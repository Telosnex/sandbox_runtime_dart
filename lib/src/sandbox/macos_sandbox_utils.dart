// Ported from sandbox-runtime src/sandbox/macos-sandbox-utils.ts @ 0bbebed.
// ignore_for_file: prefer_adjacent_string_concatenation
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments
// ignore_for_file: doc_directive_unknown, slash_for_doc_comments, curly_braces_in_flow_control_structures
// ignore_for_file: prefer_interpolation_to_compose_strings, non_constant_identifier_names

import 'dart:convert';
import 'dart:math' as math;

import 'package:path/path.dart' as path;

import '../node/child_process.dart';
import '../node/errno.dart' show errorMessage;
import '../node/process.dart' as process;
import '../utils/debug.dart';
import '../utils/shell_quote.dart';
import '../utils/which.dart';
import 'java_proxy_agent.dart';
import 'path_entries.dart' show PathListKind, literalReadings;
import 'sandbox_config.dart' show IgnoreViolationsConfig;
import 'credential_mask_files.dart' show MaskedFileBind;
import 'sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'glob_pattern.dart' show denyGlobRegex, escapeRegexLiteral, globToRegex;
import 'sandbox_utils.dart';
import 'sandbox_violation_store.dart';

class MacOSSandboxParams {
  String command;

  ///
  /// Attribution key for this invocation: the string encoded into the
  /// seatbelt log tag and the proxy username, and reported as the
  /// violation's `command`. Defaults to `command`. Set it when the string
  /// you execute differs from the one you will later look violations up by
  /// (e.g. you wrap an assembled `source snapshot && eval '<cmd>'` but query
  /// `getViolationsForCommand('<cmd>')`).
  ///
  String? commandId;
  bool needsNetworkRestriction;
  // TELOSNEX DEVIATION: Direct IP access still enforces Unix-socket policy.
  bool directNetwork;
  int? httpProxyPort;
  int? socksProxyPort;

  /// Per-session proxy auth token; embedded in proxy env URLs.
  String? proxyAuthToken;

  /// Path to the TLS-termination CA cert; injected as trust env vars.
  String? caCertPath;

  /// Path to the JVM proxy agent jar; injected via JAVA_TOOL_OPTIONS.
  String? javaAgentJarPath;
  List<String>? allowUnixSockets;
  bool? allowAllUnixSockets;
  bool? allowLocalBinding;
  List<String>? allowMachLookup;
  FsReadRestrictionConfig? readConfig;
  FsWriteRestrictionConfig? writeConfig;

  /// Environment variable names to unset for the sandboxed child (env -u)
  List<String>? unsetEnvVars;

  /// Environment variables to set for the sandboxed child (env NAME=VALUE)
  Map<String, String>? setEnvVars;

  ///
  /// Whole-file credential masks. SBPL cannot redirect reads, so on macOS
  /// these degrade to read-deny on realPath until the DYLD interposer
  /// lands. fakePath is unused here.
  ///
  List<MaskedFileBind>? maskedFileBinds;

  ///
  /// Masked files that degraded to a read-deny because their extract
  /// pattern matched nothing under `onExtractNoMatch: 'deny'`. Denied as
  /// literals, like [maskedFileBinds]: each is a file the library opened,
  /// not a spelling to match.
  ///
  List<String>? degradeToDenyPaths;
  IgnoreViolationsConfig? ignoreViolations;
  bool? allowPty;
  bool? allowGitConfig;

  ///
  /// Directories to emit as `safe.directory` via `GIT_CONFIG_*` env
  /// vars — see [buildPosixGitSafeDirEnv].
  ///
  List<String>? gitSafeDirectories;
  bool? enableWeakerNetworkIsolation;
  bool? allowAppleEvents;
  String? binShell;

  // TELOSNEX DEVIATION: Per-command TMPDIR and control of the legacy fallback.
  String? temporaryDirectory;
  bool? skipDefaultTmpdir;

  MacOSSandboxParams({
    required this.command,
    this.commandId,
    required this.needsNetworkRestriction,
    // TELOSNEX DEVIATION: Keep direct IP distinct from unrestricted networking.
    this.directNetwork = false,
    this.httpProxyPort,
    this.socksProxyPort,
    this.proxyAuthToken,
    this.caCertPath,
    this.javaAgentJarPath,
    this.allowUnixSockets,
    this.allowAllUnixSockets,
    this.allowLocalBinding,
    this.allowMachLookup,
    required this.readConfig,
    required this.writeConfig,
    this.unsetEnvVars,
    this.setEnvVars,
    this.maskedFileBinds,
    this.degradeToDenyPaths,
    this.ignoreViolations,
    this.allowPty,
    this.allowGitConfig,
    this.gitSafeDirectories,
    this.enableWeakerNetworkIsolation,
    this.allowAppleEvents,
    this.binShell,
    // TELOSNEX DEVIATION: Accept the command's choice from the manager.
    this.temporaryDirectory,
    this.skipDefaultTmpdir,
  });
}

/// The mandatory write denies (no filesystem scanning). Each name appears
/// twice: once as the path in the cwd, and once as a pattern for the same
/// name anywhere beneath it, which macOS matches via a regex.
///
/// Both are anchored at the cwd, and the cwd is a name on disk that may
/// contain `[`, `*` or `?`. So the first is a literal entry, and the second
/// carries the cwd as its anchor — only the `**/<name>` tail is pattern.
/// Compiled as one glob, a cwd like `a[b/c]d` would turn into a character
/// class and every one of these denies would match nothing.
// TELOSNEX DEVIATION: Reuse the cwd's rules at each explicit root.
List<PathEntry> macGetMandatoryDenyEntries([bool allowGitConfig = false]) =>
    _macGetRootMandatoryDenyEntries(process.cwd(), allowGitConfig);

List<PathEntry> _macGetRootMandatoryDenyEntries(
  String root,
  bool allowGitConfig,
) {
  final cwd = normalizePathForSandbox(root, literal: true);
  final entries = <PathEntry>[];
  PathEntry literal(String relativePath) => _toLiteralPathEntry(
    path.normalize(
      path.isAbsolute(relativePath)
          ? relativePath
          : path.join(cwd, relativePath),
    ),
  );
  PathEntry beneathCwd(String pattern) => _anchoredGlobEntry(cwd, pattern);

  // Dangerous files - static paths in CWD + glob patterns for subtree
  for (final fileName in DANGEROUS_FILES) {
    entries.add(literal(fileName));
    entries.add(beneathCwd('**/$fileName'));
  }

  // Dangerous directories
  for (final dirName in getDangerousDirectories()) {
    entries.add(literal(dirName));
    entries.add(beneathCwd('**/$dirName/**'));
  }

  // Git hooks are always blocked for security
  entries.add(literal('.git/hooks'));
  entries.add(beneathCwd('**/.git/hooks/**'));

  // Git config - conditionally blocked based on allowGitConfig setting
  if (!allowGitConfig) {
    entries.add(literal('.git/config'));
    entries.add(beneathCwd('**/.git/config'));
  }
  return entries;
}

class SandboxViolationEvent {
  String line;
  String? command;
  String? encodedCommand;
  DateTime timestamp;
  SandboxViolationEvent({
    required this.line,
    this.command,
    this.encodedCommand,
    required this.timestamp,
  });
}

typedef SandboxViolationCallback =
    void Function(SandboxViolationEvent violation);

final String _sessionSuffix =
    '_${math.Random().nextInt(1 << 32).toRadixString(36)}_SBX';

///
/// Generate a unique log tag for sandbox monitoring
/// @param command - The command being executed (will be base64 encoded)
///
String _generateLogTag(String command) =>
    'CMD64_${encodeSandboxedCommand(command)}_END_$_sessionSuffix';

///
/// SBPL path filter for a normalized entry: `regex` for glob patterns,
/// `subpath` (the path and everything beneath it) otherwise.
///
String _pathFilter(PathEntry entry) => entry.glob
    ? '(regex ${_escapePath(_globRegex(entry as _GlobPathEntry))})'
    : '(subpath ${_escapePath(entry.path)})';

///
/// Compiles `entry`'s pattern with one of the shared string compilers in
/// `sandbox-utils.ts`. An entry anchored at a directory
/// (`anchor`) keeps that directory as a literal — it is a name on disk
/// and may itself contain `[`, `*` or `?` — so only the tail below it goes
/// through the compiler, and the anchor is spliced back in escaped. Every
/// compiler there returns '^…$'.
///
/// This is the whole difference between the entry-taking wrappers here and
/// the string-taking compilers they call: those see a spelling in which
/// every character is glob syntax, which is right for what a caller wrote
/// as a pattern and wrong for a name on disk.
///
String _anchorRegex(_GlobPathEntry entry, String Function(String) compile) {
  final anchor = entry.anchor;
  if (anchor == null) return compile(entry.path);
  final pattern = entry.path.substring(anchor.length);
  return '^${escapeRegexLiteral(anchor)}${compile(pattern).substring(1)}';
}

/// The regex for a glob entry: [globToRegex], anchor respected.
String _globRegex(_GlobPathEntry entry) => _anchorRegex(entry, globToRegex);

/// The regex for a glob entry used in a DENY rule: [denyGlobRegex],
/// anchor respected. That is [globToRegex] plus an optional `/…` tail,
/// so the deny covers everything beneath each match the way `subpath` does
/// for literals. Callers strip a trailing `/**` before the pattern gets here
/// ([removeTrailingGlobSuffix]), so `**/secrets/**` arrives as `**/secrets`
/// and, matched exactly, would deny only the directory vnode while
/// `secrets/key` stayed readable. This is what the Linux backend already
/// does (a deny masks the whole subtree). Only ever widens a deny.
String _denyGlobEntryRegex(_GlobPathEntry entry) =>
    _anchorRegex(entry, denyGlobRegex);

/// [pathFilter] for deny rules: globs get [denyGlobEntryRegex].
String _denyPathFilter(PathEntry entry) => entry.glob
    ? '(regex ${_escapePath(_denyGlobEntryRegex(entry as _GlobPathEntry))})'
    : '(subpath ${_escapePath(entry.path)})';

///
/// A concrete path shaped like the ones `entry` matches (every glob segment
/// replaced by a literal `x`), used to test whether a deny regex covers the
/// region an allow / write root points at. An anchored glob's anchor, and a
/// literal entry's whole path, are names on disk and stay as they are.
///
String _entrySamplePath(PathEntry entry) {
  if (!entry.glob) return entry.path;
  final anchor = (entry as _GlobPathEntry).anchor ?? '';
  final tail = entry.path
      .substring(anchor.length)
      .replaceAll(RegExp(r'\[[^\]]*\]|[*?]+'), 'x');
  return '$anchor$tail';
}

///
/// Narrow `filter` so it no longer matches anything covered by `carveOuts`
/// (each an SBPL path filter). Used to re-emit a deny after the allows it
/// would otherwise clobber, minus exactly the allow entries it overlaps —
/// a deny minus carve-outs never matches anything the un-carved deny did
/// not, so this stays deny-only.
///
String _carveFilter(String filter, List<String> carveOuts) {
  // Dedupe: the project dir is routinely both an allowRead entry and a
  // write root.
  final unique = carveOuts.toSet().toList();
  if (unique.isEmpty) return filter;
  final nots = unique.map((c) => '(require-not $c)').join(' ');
  return '(require-all $filter $nots)';
}

///
/// One denyOnly / allowWithinDeny / allowWrite entry after normalization.
/// Whether `path` is a pattern or a name on disk is decided once, by
/// whoever produced the spelling — a caller's pattern or a path the library
/// resolved — and is never re-derived from the characters in `path`: a
/// resolved name may itself contain `[`, `*` or `?`.
///
sealed class PathEntry {
  final String path;
  final bool glob;
  const PathEntry(this.path, this.glob);
}

class _LiteralPathEntry extends PathEntry {
  const _LiteralPathEntry(String path) : super(path, false);
}

/// The [PathEntry] members that carry a pattern.
class _GlobPathEntry extends PathEntry {
  /// Set when this glob is anchored at a directory that is a name on
  /// disk (the cwd, for the mandatory `**\/<name>` patterns, or an
  /// existing one that holds glob characters): the prefix of
  /// `path` that is a literal path rather than part of the pattern.
  final String? anchor;
  const _GlobPathEntry(String path, {this.anchor}) : super(path, true);
}

/// A pattern the library joined onto a literal directory of its own.
_GlobPathEntry _anchoredGlobEntry(String anchor, String pattern) =>
    _GlobPathEntry(path.join(anchor, pattern), anchor: anchor);

///
/// A spelling that came from the caller's config: `*`, `?` and `[…]` in
/// what the caller wrote are read as glob syntax here. The decision is
/// made on that raw spelling, because resolving a relative or `~` path can
/// splice in a cwd or home directory whose own name contains those
/// characters — read back, they would turn the caller's `secrets` into a
/// pattern that never matches the directory it was resolved to.
/// [alsoReadAs] gives the readings this one leaves out.
///
PathEntry _toPathEntry(String pathPattern) => containsGlobChars(pathPattern)
    ? _GlobPathEntry(normalizePathForSandbox(pathPattern))
    : _LiteralPathEntry(normalizePathForSandbox(pathPattern, literal: true));

///
/// A path the library itself produced: joined onto the cwd, or resolved to
/// a file it opened. It names one file or directory, so it compiles to a
/// `subpath` filter whatever characters it contains — sniffed as a pattern,
/// a component like `a[b` would become a character class and the filter
/// would no longer match the path it was built from (the rule would be
/// inert). Never use this for a spelling the caller did not mark literal.
///
PathEntry _toLiteralPathEntry(String literalPath) =>
    _LiteralPathEntry(normalizePathForSandbox(literalPath, literal: true));

///
/// The readings a caller's spellings have beside [toPathEntry]'s; see
/// [literalReadings].
///
List<PathEntry> _alsoReadAs(List<String>? spellings, PathListKind kind) =>
    (spellings ?? const <String>[]).expand((spelling) {
      final values = literalReadings(spelling, kind);
      return values.map<PathEntry>((reading) {
        if (reading.glob) {
          return _GlobPathEntry(reading.path, anchor: reading.anchor);
        }
        return _LiteralPathEntry(reading.path);
      });
    }).toList();

/// One of the caller's lists as entries, in every reading each has.
List<PathEntry> _callerEntries(
  PathListKind kind,
  List<String>? spellings,
  List<String>? literalPaths,
) => [
  ...(spellings ?? const <String>[]).map(_toPathEntry),
  ..._alsoReadAs(spellings, kind),
  ...(literalPaths ?? const <String>[]).map(_toLiteralPathEntry),
];

/// Does a subtree-extended deny glob regex cover `entry`'s region?
bool _denyGlobCovers(RegExp denyRegex, PathEntry entry) =>
    denyRegex.hasMatch(_entrySamplePath(entry));

/// Is `entry`'s region strictly inside the literal directory `dir`?
bool _isStrictlyUnder(PathEntry entry, String dir) =>
    isStrictlyUnder(_entrySamplePath(entry), dir);

///
/// The read config with every entry normalized once, shared by the read
/// section ([generateReadRules]) and the trailing unlink re-denies
/// ([generateReadDenyUnlinkRules]) so both reason about the same
/// spellings.
///
class _ResolvedReadConfig {
  final List<PathEntry> denies;

  /// Those of `denies` whose only exceptions are `ownAllows`.
  final Set<PathEntry> credentialDenies;
  final List<PathEntry> allows;

  /// Those of `allows` the library adds for files of its own.
  final List<PathEntry> ownAllows;
  final List<PathEntry> writeRoots;
  const _ResolvedReadConfig({
    required this.denies,
    required this.credentialDenies,
    required this.allows,
    required this.ownAllows,
    required this.writeRoots,
  });
}

///
/// A read entry under both spellings of its path: as written, and with the
/// links on the way resolved. A deny is resolved to its end. An allow is a
/// name, so its last component stays as written. Of a pattern, the directory
/// it starts from is what is resolved. The root is never a second spelling.
///
List<PathEntry> _inBothSpellings(PathListKind kind, PathEntry entry) {
  String resolved(String p) =>
      pathSpellings(p).length > 1 ? pathSpellings(p)[1] : p;
  final base = _entryBaseDir(entry);
  final canonical = kind == 'deny' || entry.glob
      ? resolved(base)
      : nameLocation(base, resolved);
  // Nor among the devices: a rule on a name blanked with a link to /dev/null
  // would be one on /dev/null for every command.
  if (canonical == base || canonical == '/' || isAtOrUnder(canonical, '/dev'))
    return [entry];
  if (entry.glob) {
    return [
      entry,
      _GlobPathEntry(
        canonical + entry.path.substring(base.length),
        anchor: canonical,
      ),
    ];
  }
  return [entry, _LiteralPathEntry(canonical)];
}

_ResolvedReadConfig _resolveReadConfig(
  FsReadRestrictionConfig config,
  List<PathEntry> writeRoots,

  ///
  /// Read denies the library resolved itself — the masked credential files,
  /// which macOS degrades to a deny. Already literal: each names the file
  /// that was found, not a pattern to match.
  ///
  List<PathEntry> libraryDenies,
) {
  final credentialDenies = [
    ..._callerEntries('deny', config.credentialDenyOnly, null),
    ...libraryDenies,
  ].expand((entry) => _inBothSpellings('deny', entry)).toList();
  final ordinaryDenies = _callerEntries(
    'deny',
    config.denyOnly
        .where((p) => !(config.credentialDenyOnly?.contains(p) ?? false))
        .toList(),
    config.literalDenyOnly,
  ).expand((entry) => _inBothSpellings('deny', entry)).toList();
  return _ResolvedReadConfig(
    denies: [...ordinaryDenies, ...credentialDenies],
    credentialDenies: credentialDenies.toSet(),
    ownAllows: (config.ownAllowWithinDeny ?? const <String>[])
        .map(_toLiteralPathEntry)
        .expand((e) => _inBothSpellings('allow', e))
        .toList(),
    // Non-glob spellings arrive slash-free from normalizePathForSandbox —
    // the nested-deny re-emit matches by `path + '/'` prefix, which a
    // preserved trailing slash would defeat ('<dir>//').
    allows: _callerEntries(
      'allow',
      config.allowWithinDeny,
      config.literalAllowWithinDeny,
    ).expand((e) => _inBothSpellings('allow', e)).toList(),
    writeRoots: [...writeRoots],
  );
}

/// The denies that must land AFTER the allowWithinDeny allows, because
/// Seatbelt is last-match-wins and the allow block would otherwise re-open
/// them. Each comes back as the SBPL filter to emit:
///
/// - A literal deny nested inside a literal allow (`~/proj/secrets` under
///   `~/proj`), re-emitted as-is.
/// - Every glob deny, minus (`require-not`) each allow entry the glob's own
///   regex covers. A leaf-shaped glob (`**/.env`, `/**/*.key`) covers no
///   directory allow, so it comes back whole and beats the directory allows
///   it lands inside — the fix for globs being silently re-allowed. A
///   region-shaped glob (`~/**/*` with allowRead carve-outs) covers its
///   carve-outs, so they are subtracted and its behavior is unchanged. A
///   glob that covers a specific FILE allow (a user carve-out, or the
///   TLS-termination trust bundle sandbox-manager adds to allowWithinDeny,
///   which a `/**/*.crt` deny would otherwise sever) keeps that one file
///   readable without any allow being emitted after the denies.
/// - Every credential deny, literal or glob, minus the library's own files
///   that it covers.
///
/// Every filter here is a deny or a narrower deny: nothing this function
/// produces can make a path readable that is not readable today. Keep it
/// that way — the moment an `(allow file-read* …)` is appended after this
/// block, every deny above it has to be re-audited against it.
///
/// The coverage test (denyGlobCovers) fails closed by construction: every
/// carve-out is an entry the allow block above already allows, so an
/// unnecessary carve-out only reproduces today's behavior for that entry,
/// and a missed one (e.g. a glob allow whose sample path the deny regex
/// happens not to match) leaves the deny wider — never opens anything.
({
  List<String> filters,

  /// Some emitted glob deny matches "/" itself (a `/*`-shaped pattern).
  bool coversRoot,
})
_lateReadDenyFilters(_ResolvedReadConfig resolved) {
  final filters = <String>[];
  var coversRoot = false;
  final literalAllowDirs = resolved.allows
      .where((a) => !a.glob)
      .map((a) => a.path)
      .toList();
  for (final deny in resolved.denies) {
    final credential = resolved.credentialDenies.contains(deny);
    if (!deny.glob) {
      if (credential) {
        final carveOuts = resolved.ownAllows
            .where((a) => isAtOrUnder(a.path, deny.path))
            .map(_pathFilter)
            .toList();
        filters.add(_carveFilter(_denyPathFilter(deny), carveOuts));
      } else if (literalAllowDirs.any((a) => _isStrictlyUnder(deny, a))) {
        filters.add(_denyPathFilter(deny));
      }
      continue;
    }
    final glob = deny as _GlobPathEntry;
    final denyRegex = RegExp(_denyGlobEntryRegex(glob));
    if (denyRegex.hasMatch('/')) coversRoot = true;
    final source = credential ? resolved.ownAllows : resolved.allows;
    final carveOuts = source
        .where((a) => _denyGlobCovers(denyRegex, a))
        .map(_pathFilter)
        .toList();
    filters.add(_carveFilter(_denyPathFilter(deny), carveOuts));
  }
  return (filters: filters, coversRoot: coversRoot);
}

/// Directory that bounds where a glob can match: its static prefix, or "/"
/// for a root-anchored pattern like `/**/*.key`.
String _globBaseDir(String normalizedGlob) {
  final staticPrefix = normalizedGlob.split(RegExp(r'[*?\[\]]')).first;
  if (staticPrefix.isEmpty || staticPrefix == '/') return '/';
  return staticPrefix.endsWith('/')
      ? staticPrefix.substring(0, staticPrefix.length - 1)
      : path.dirname(staticPrefix);
}

///
/// Directory that bounds where `entry` can match: the anchor the library
/// set, the static prefix of a pattern, or the path itself when it names
/// one file or directory.
///
String _entryBaseDir(PathEntry entry) {
  if (!entry.glob) return entry.path;
  final glob = entry as _GlobPathEntry;
  return glob.anchor ?? _globBaseDir(entry.path);
}

/// Trailing `(deny file-write-unlink …)` for read-denied paths that the
/// write section may have re-opened. Emitted at the very end of the profile.
///
/// generateReadRules() blocks moving a read-denied path (and its ancestors)
/// out from under its deny, but then re-allows file-write-unlink /
/// file-write-create for every allowWrite root so `rm` works inside the
/// project (#171). Any read-denied path INSIDE a write root is therefore
/// movable again: `mv .env x; cat x`, or `mv secrets s2; cat s2/key`,
/// defeats both glob and literal denies. This re-denies unlink (rename
/// source / rm) — not create, so new files can still be made; a new `.env`
/// is still read-denied by name — for:
///
/// - every glob deny whose region intersects a write root, minus the allow
///   entries and write roots the glob itself covers (a region glob like
///   `~/**/*` must not re-block `rm` inside carve-outs it was already
///   subtracting; a leaf glob like `**/.env` covers none of them);
/// - every literal deny strictly below a write root, minus any allow entry
///   or write root nested strictly inside it;
/// - the literal ancestor directories of each of those (for a glob, its
///   static-prefix directory and that directory's ancestors) that sit
///   strictly below a write root — the directory vnodes only, so `rm` of
///   unrelated siblings still works but the enclosing directory cannot be
///   renamed out from under the deny. Ancestors at or above a write root
///   are left alone: the deny above already covers them, and re-denying the
///   root itself would block unrelated `rm`s.
///
/// A literal deny not below any write root needs nothing: the read
/// section's move-blocking deny still holds for it. Deny-only, like the
/// rest of this file's read handling.
///
/// A credential deny is emitted wherever it lies and with nothing subtracted,
/// and a write root among its ancestors is kept in place with them.
List<String> _generateReadDenyUnlinkRules(
  _ResolvedReadConfig resolved,
  String logTag,
) {
  final denies = resolved.denies;
  final credentialDenies = resolved.credentialDenies;
  final writeRoots = resolved.writeRoots;
  if (writeRoots.isEmpty) return [];
  final writeRootRegexes = writeRoots
      .where((w) => w.glob)
      .map((w) => RegExp(_globRegex(w as _GlobPathEntry)))
      .toList();
  final literalWriteRoots = writeRoots
      .where((w) => !w.glob)
      .map((w) => w.path)
      .toList();
  bool strictlyBelowWriteRoot(String p) =>
      literalWriteRoots.any((w) => _isStrictlyUnder(_LiteralPathEntry(p), w)) ||
      writeRootRegexes.any((re) => re.hasMatch(p));
  final filters = <String>{};
  void protectDirs(List<String> dirs, bool withWriteRoots) {
    for (final dir in dirs) {
      if (strictlyBelowWriteRoot(dir) ||
          (withWriteRoots && literalWriteRoots.contains(dir))) {
        filters.add('(literal ${_escapePath(dir)})');
      }
    }
  }

  for (final deny in denies) {
    final credential = credentialDenies.contains(deny);
    final exceptions = credential
        ? <PathEntry>[]
        : [...resolved.allows, ...writeRoots];
    if (deny.glob) {
      final baseDir = _entryBaseDir(deny);
      final intersects =
          writeRootRegexes.isNotEmpty ||
          literalWriteRoots.any(
            (w) =>
                baseDir == w ||
                _isStrictlyUnder(_LiteralPathEntry(baseDir), w) ||
                _isStrictlyUnder(_LiteralPathEntry(w), baseDir),
          );
      if (!intersects) continue;
      final regex = RegExp(_denyGlobEntryRegex(deny as _GlobPathEntry));
      final carveOuts = exceptions
          .where((e) => _denyGlobCovers(regex, e))
          .map(_pathFilter)
          .toList();
      filters.add(_carveFilter(_denyPathFilter(deny), carveOuts));
      if (baseDir != '/')
        protectDirs([baseDir, ..._getAncestorDirectories(baseDir)], credential);
    } else {
      if (!credential && !strictlyBelowWriteRoot(deny.path)) continue;
      final carveOuts = exceptions
          .where((e) => _isStrictlyUnder(e, deny.path))
          .map(_pathFilter)
          .toList();
      filters.add(_carveFilter(_denyPathFilter(deny), carveOuts));
      protectDirs(_getAncestorDirectories(deny.path), credential);
    }
  }
  return _renderRule('deny', ['file-write-unlink'], filters, logTag);
}

///
/// Render one SBPL rule applying `action` for each of `operations` to any
/// path matching one of `filters`, reporting `logTag` on a match. Emits
/// nothing for an empty filter set: a rule with no filter would match every
/// path.
///
List<String> _renderRule(
  String action,
  List<String> operations,
  Set<String> filters,
  String logTag,
) {
  if (filters.isEmpty) return [];
  return [
    '($action ${operations.join(' ')}',
    ...filters.map((f) => '  $f'),
    '  (with message "$logTag"))',
  ];
}

///
/// Get all ancestor directories for a path, up to (but not including) root
/// Example: /private/tmp/test/file.txt -> ["/private/tmp/test", "/private/tmp", "/private"]
///
List<String> _getAncestorDirectories(String pathStr) {
  final ancestors = <String>[];
  var currentPath = path.dirname(pathStr);

  // Walk up the directory tree until we reach root
  while (currentPath != '/' && currentPath != '.') {
    ancestors.add(currentPath);
    final parentPath = path.dirname(currentPath);
    // Break if we've reached the top (path.dirname returns the same path for root)
    if (parentPath == currentPath) break;
    currentPath = parentPath;
  }
  return ancestors;
}

///
/// sandbox-exec rejects a string literal longer than 1025 bytes ("Error
/// reading string"); the regexes built below stay well under that, since
/// one oversized string invalidates the whole profile.
///
const int _SBPL_STRING_MAX_BYTES = 900;

///
/// Below this many names, one regex is not shorter than the literal filters
/// it would replace.
///
const int _MIN_DENY_GROUP_SIZE = 4;

///
/// Literal deny paths of the shape `<dir>/<name>/<leaf>` that share `dir` and
/// the same set of leaves, e.g. git's per-worktree registry
/// `<gitdir>/worktrees/<name>/{commondir,config.worktree}` for every
/// registered worktree.
///
class _LiteralDenyGroup {
  final String dir;
  List<String> names;
  final List<String> leaves;
  _LiteralDenyGroup({
    required this.dir,
    required this.names,
    required this.leaves,
  });
}

///
/// Fold literal deny paths into {@link LiteralDenyGroup}s. Each group renders
/// as one anchored regex per chunk of names instead of one `subpath` filter
/// per path, so a directory with many same-shaped children costs bytes and
/// profile compile time proportional to the names, not to the repeated
/// absolute prefix (sandbox-exec compiles a few thousand path filters in
/// seconds; a few dozen regexes in milliseconds). Globs, paths that do not
/// fit a group of at least {@link MIN_DENY_GROUP_SIZE} names, and names too
/// long for one regex are returned in `rest` unchanged.
({List<_LiteralDenyGroup> groups, List<PathEntry> rest}) _groupLiteralDenyPaths(
  List<PathEntry> entries,
) {
  final byDir = <String, Map<String, Set<String>>>{};
  for (final entry in entries) {
    if (entry.glob) continue;
    final entryPath = entry.path;
    final parent = path.dirname(entryPath);
    final dir = path.dirname(parent);
    if (dir == parent || parent == entryPath || dir == '/') continue;
    final names = byDir.putIfAbsent(dir, () => <String, Set<String>>{});
    final leaves = names.putIfAbsent(path.basename(parent), () => <String>{});
    leaves.add(path.basename(entryPath));
  }
  final grouped = <String>{};
  final groups = <_LiteralDenyGroup>[];
  for (final pair in byDir.entries) {
    final bySignature = <String, _LiteralDenyGroup>{};
    for (final pair2 in pair.value.entries) {
      final leaves = pair2.value.toList()..sort();
      final signature = leaves.join('\u0000');
      final group = bySignature.putIfAbsent(
        signature,
        () => _LiteralDenyGroup(dir: pair.key, names: [], leaves: leaves),
      );
      group.names.add(pair2.key);
    }
    for (final group in bySignature.values) {
      final fixedLength =
          _regexLength(_groupRegexPrefix(group)) +
          _regexLength(_groupDenyTail(group));
      group.names = group.names
          .where(
            (name) =>
                fixedLength + _regexLength(escapeRegexLiteral(name)) <=
                _SBPL_STRING_MAX_BYTES,
          )
          .toList();
      if (group.names.length < _MIN_DENY_GROUP_SIZE) continue;
      groups.add(group);
      for (final name in group.names) {
        for (final leaf in group.leaves)
          grouped.add(path.join(group.dir, name, leaf));
      }
    }
  }
  return (
    groups: groups,
    rest: entries.where((e) => !grouped.contains(e.path)).toList(),
  );
}

/// Bytes a regex fragment occupies inside an SBPL string literal.
int _regexLength(String fragment) =>
    utf8.encode(_escapePath(fragment)).length - 2;
String _groupRegexPrefix(_LiteralDenyGroup group) =>
    '^${escapeRegexLiteral(group.dir)}/(';
String _groupDenyTail(_LiteralDenyGroup group) =>
    ')/(${group.leaves.map(escapeRegexLiteral).join('|')})(/.*)?' + r'$';

///
/// Regex filters for a {@link LiteralDenyGroup}, chunked so no regex exceeds
/// {@link SBPL_STRING_MAX_BYTES}. `deny` matches each `<dir>/<name>/<leaf>`
/// and everything beneath it (the `subpath` semantics of a literal deny);
/// `pins` match each `<dir>/<name>` directory itself, the move-blocking
/// literal a per-path deny would have added for its parent.
({List<String> deny, List<String> pins}) _literalDenyGroupFilters(
  _LiteralDenyGroup group,
) {
  final prefix = _groupRegexPrefix(group);
  final denyTail = _groupDenyTail(group);
  final fixedLength = _regexLength(prefix) + _regexLength(denyTail);
  final chunks = <List<String>>[];
  var chunk = <String>[];
  var chunkLength = 0;
  for (final name in group.names.map(escapeRegexLiteral)) {
    final nameLength = _regexLength(name) + (chunk.isEmpty ? 0 : 1);
    if (chunk.isNotEmpty &&
        fixedLength + chunkLength + nameLength > _SBPL_STRING_MAX_BYTES) {
      chunks.add(chunk);
      chunk = <String>[];
      chunkLength = 0;
    }
    chunk.add(name);
    chunkLength += chunk.length == 1 ? _regexLength(name) : nameLength;
  }
  chunks.add(chunk);
  final alternations = chunks.map((names) => names.join('|'));
  return (
    deny: alternations
        .map((names) => '(regex ${_escapePath('$prefix$names$denyTail')})')
        .toList(),
    pins: alternations.map((names) {
      final regex = '$prefix$names)' + r'$';
      return '(regex ${_escapePath(regex)})';
    }).toList(),
  );
}

///
/// Generate deny rules for file movement (file-write-unlink) and creation
/// (file-write-create) to protect paths. This prevents bypassing read or write
/// restrictions by moving files/directories, and prevents replacing a
/// not-yet-existing protected path (or one of its ancestors) with an
/// attacker-controlled symlink.
///
/// Emitted as a single rule whose filters are the union over all patterns:
/// protected paths commonly share most of their ancestors, and each distinct
/// filter both costs argv bytes and adds to sandbox-exec's compile time.
///
/// @param entries - Normalized entries to protect (literals and globs)
/// @param logTag - Log tag for sandbox violations
/// @returns Array of sandbox profile rule lines
///
List<String> _generateMoveBlockingRules(
  List<PathEntry> entries,
  String logTag,
) => _renderRule(
  'deny',
  ['file-write-unlink', 'file-write-create'],
  _moveBlockingFilters(entries),
  logTag,
);

///
/// The filters [generateMoveBlockingRules] emits, for normalized entries.
///
Set<String> _moveBlockingFilters(List<PathEntry> entries) {
  final filters = <String>{};
  for (final entry in entries) {
    // Block moving/renaming the denied path itself (or files matching the
    // pattern, and anything beneath them)
    filters.add(_denyPathFilter(entry));
    final baseDir = _entryBaseDir(entry);
    if (entry.glob) {
      // For glob patterns, block moves of the directory the pattern is
      // bounded by, then of its ancestors
      if (baseDir == '/') continue;
      filters.add('(literal ${_escapePath(baseDir)})');
    }
    // Block moves of ancestor directories
    for (final ancestor in _getAncestorDirectories(baseDir))
      filters.add('(literal ${_escapePath(ancestor)})');
  }
  return filters;
}

///
/// Generate filesystem read rules for sandbox profile
///
/// Supports two layers:
/// 1. denyOnly: deny reads from these paths (broad regions like /Users)
/// 2. allowWithinDeny: re-allow reads within denied regions (like CWD)
///    allowWithinDeny takes precedence over denyOnly.
///
/// In Seatbelt profiles, later rules take precedence, so we emit:
///   (allow file-read*)        ← default: allow everything
///   (deny file-read* ...)     ← deny everything in denyOnly
///   (allow file-read* ...)    ← re-allow allowWithinDeny
///   (deny file-read* ...)     ← re-emit the denies the allows would clobber:
///                               literal denies nested in an allow, and every
///                               glob deny minus the allows it covers
///                               (see lateReadDenyFilters)
///   (allow file-read* (literal "/"))  ← only if a deny covers "/" itself
///
/// REVIEW INVARIANT: after the allowWithinDeny block, this function only
/// ever adds denies (or narrows one with require-not). The one exception is
/// the pre-existing literal-"/" re-allow, which matches exactly one vnode.
/// Do not append another `(allow file-read* …)` layer here — every deny
/// above it would then need re-auditing for re-open bypasses.
///
List<String> _generateReadRules(_ResolvedReadConfig? resolved, String logTag) {
  if (resolved == null) return ['(allow file-read*)'];
  // Start by allowing everything
  final rules = <String>['(allow file-read*)'];
  final deniesRoot = resolved.denies.any((d) => d.path == '/');
  // Then deny specific paths
  rules.addAll(
    _renderRule(
      'deny',
      ['file-read*'],
      resolved.denies.map(_denyPathFilter).toSet(),
      logTag,
    ),
  );
  // Re-allow specific paths within denied regions (allowWithinDeny takes precedence)
  rules.addAll(
    _renderRule(
      'allow',
      ['file-read*'],
      resolved.allows.map(_pathFilter).toSet(),
      logTag,
    ),
  );
  // Denies the allow block would otherwise win over (last-match-wins) land
  // here, after it. Must stay ahead of the file-read-metadata allow below.
  final late = _lateReadDenyFilters(resolved);
  rules.addAll(
    _renderRule('deny', ['file-read*'], late.filters.toSet(), logTag),
  );
  // (subpath "/") — or a re-emitted `/*`-shaped glob — denies the root inode
  // itself; no allowWithinDeny entry covers "/", so dyld aborts before exec
  // (#190). Re-allow the literal root, after the re-emitted denies so a
  // glob landing later can't take it away again. This exposes `ls /` dirent
  // names but no subtree contents.
  if (deniesRoot || late.coversRoot)
    rules.add('(allow file-read* (literal "/"))');
  // Allow stat/lstat on all directories so that realpath() can traverse
  // path components within denied regions. Without this, C realpath() fails
  // when resolving symlinks because it needs to lstat every intermediate
  // directory (e.g. /Users, /Users/chris) even if only a subdirectory like
  // ~/.local is in allowWithinDeny. This only allows metadata reads on
  // directories — not listing contents (readdir) or reading files.
  if (resolved.denies.isNotEmpty)
    rules.addAll(['(allow file-read-metadata', '  (vnode-type DIRECTORY))']);
  // Block file movement to prevent bypass via mv/rename
  rules.addAll(_generateMoveBlockingRules(resolved.denies, logTag));
  // Re-allow file-write-unlink / file-write-create for paths that are explicitly
  // write-allowed. The move-blocking rules above emit broad
  // (deny file-write-unlink (subpath "/Users")) to prevent bypassing read
  // restrictions by moving files out of denied regions.
  // However, in macOS Seatbelt, a specific (deny file-write-unlink) is not overridden
  // by a later (allow file-write*) wildcard — the specific operation deny wins.
  // This means file deletions are blocked even in write-allowed directories like
  // the project directory. We fix this by explicitly re-allowing file-write-unlink
  // and file-write-create for write-allowed paths after the move-blocking deny rules.
  //
  // Note: denyWithinAllow paths are not excluded here because the write section's
  // generateMoveBlockingRules() runs later in the profile and re-denies
  // file-write-unlink for those paths (Seatbelt uses last-match-wins). This
  // depends on read rules being emitted before write rules in generateSandboxProfile().
  //
  // This re-allow also re-opens rename/rm of read-denied paths that sit
  // INSIDE a write root; generateReadDenyUnlinkRules(), emitted at the end
  // of the profile, takes those back.
  rules.addAll(
    _renderRule(
      'allow',
      ['file-write-unlink', 'file-write-create'],
      resolved.writeRoots.map(_pathFilter).toSet(),
      logTag,
    ),
  );
  return rules;
}

///
/// What a write config allows, as entries. Decided once per profile and
/// handed to the read and the write section, so the two see the same answer.
///
List<PathEntry> _writeRootEntries(FsWriteRestrictionConfig? config) =>
    _callerEntries('allow', config?.allowOnly, config?.literalAllowOnly);

///
/// Generate filesystem write rules for sandbox profile
///
List<String> _generateWriteRules(
  FsWriteRestrictionConfig? config,
  String logTag,
  bool allowGitConfig,
  List<PathEntry> writeRoots,
) {
  if (config == null) return ['(allow file-write*)'];
  final rules = <String>[];
  // Generate allow rules
  rules.addAll(
    _renderRule(
      'allow',
      ['file-write*'],
      writeRoots.map(_pathFilter).toSet(),
      logTag,
    ),
  );
  // Combine user-specified and mandatory deny patterns (no ripgrep needed on
  // macOS). The caller's spellings are patterns when they read as patterns;
  // the mandatory entries carry their own literal/glob split.
  // TELOSNEX DEVIATION: Replace the cwd only when the command supplies roots.
  final mandatoryDenyRoots = config.mandatoryDenyRoots;
  final denyEntries = <PathEntry>[
    ...(config.denyWithinAllow).map(_toPathEntry),
    ...(config.literalDenyWithinAllow ?? const <String>[]).map(
      _toLiteralPathEntry,
    ),
    // TELOSNEX DEVIATION: Feed explicit-root entries into the same deny/pin rules.
    if (mandatoryDenyRoots == null)
      ...macGetMandatoryDenyEntries(allowGitConfig)
    else
      for (final root in mandatoryDenyRoots)
        ..._macGetRootMandatoryDenyEntries(root, allowGitConfig),
  ];
  denyEntries.addAll(_alsoReadAs(config.denyWithinAllow, 'deny'));
  final grouped = _groupLiteralDenyPaths(denyEntries);
  final groups = grouped.groups;
  final ungrouped = grouped.rest;
  final groupFilters = groups.map(_literalDenyGroupFilters).toList();
  final denyFilters = <String>{};
  for (final filters in groupFilters) denyFilters.addAll(filters.deny);
  for (final entry in ungrouped) denyFilters.add(_denyPathFilter(entry));
  rules.addAll(_renderRule('deny', ['file-write*'], denyFilters, logTag));
  // Block file movement to prevent bypass via mv/rename. A grouped path
  // contributes its regex, the pin for its parent directory, and the
  // literals for the group directory and its ancestors — the same set a
  // per-path filter would add.
  final moveFilters = _moveBlockingFilters(ungrouped);
  for (var i = 0; i < groupFilters.length; i++) {
    moveFilters.addAll(groupFilters[i].deny);
    moveFilters.addAll(groupFilters[i].pins);
    final dir = groups[i].dir;
    for (final ancestor in [dir, ..._getAncestorDirectories(dir)])
      moveFilters.add('(literal ${_escapePath(ancestor)})');
  }
  rules.addAll(
    _renderRule(
      'deny',
      ['file-write-unlink', 'file-write-create'],
      moveFilters,
      logTag,
    ),
  );
  return rules;
}

///
/// Generate complete sandbox profile
///
String _generateSandboxProfile({
  required FsReadRestrictionConfig? readConfig,

  /// Library-resolved read denies; see {@link resolveReadConfig}.
  required List<PathEntry> libraryDenyEntries,
  required FsWriteRestrictionConfig? writeConfig,
  int? httpProxyPort,
  int? socksProxyPort,
  required bool needsNetworkRestriction,
  // TELOSNEX DEVIATION: Keep Unix-socket rules when opting out of the proxy.
  required bool directNetwork,
  List<String>? allowUnixSockets,
  bool? allowAllUnixSockets,
  bool? allowLocalBinding,
  List<String>? allowMachLookup,
  bool? allowPty,
  bool allowGitConfig = false,
  bool enableWeakerNetworkIsolation = false,
  bool allowAppleEvents = false,
  required String logTag,
}) {
  final profile = <String>[
    '(version 1)',
    '(deny default (with message "$logTag"))',
    '',
    '; LogTag: $logTag',
    '',
    '; Essential permissions - based on Chrome sandbox policy',
    '; Process permissions',
    '(allow process-exec)',
    '(allow process-fork)',
    '(allow process-info* (target same-sandbox))',
    '(allow signal (target same-sandbox))',
    '(allow mach-priv-task-port (target same-sandbox))',
    '',
    '; User preferences',
    '(allow user-preference-read)',
    '',
    '; Mach IPC - specific services only (no wildcard)',
    '(allow mach-lookup',
    '  (global-name "com.apple.audio.systemsoundserver")',
    '  (global-name "com.apple.distributed_notifications@Uv3")',
    '  (global-name "com.apple.FontObjectsServer")',
    '  (global-name "com.apple.fonts")',
    '  (global-name "com.apple.logd")',
    '  (global-name "com.apple.lsd.mapdb")',
    '  (global-name "com.apple.PowerManagement.control")',
    '  (global-name "com.apple.system.logger")',
    '  (global-name "com.apple.system.notification_center")',
    '  (global-name "com.apple.system.opendirectoryd.libinfo")',
    '  (global-name "com.apple.system.opendirectoryd.membership")',
    '  (global-name "com.apple.bsd.dirhelper")',
    '  (global-name "com.apple.securityd.xpc")',
    '  (global-name "com.apple.coreservices.launchservicesd")',
    ')',
    '',
    if (enableWeakerNetworkIsolation) ...[
      '; trustd.agent - needed for Go TLS certificate verification (weaker network isolation)',
      '(allow mach-lookup (global-name "com.apple.trustd.agent"))',
    ],
    if (allowAppleEvents) ...[
      '; Apple Events - opt-in; needed for open/osascript to talk to other apps (appleeventsd)',
      '(allow appleevent-send)',
      '(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))',
      '; Launch Services open requests need the lsopen operation plus, on',
      '; macOS 14/15, coreservicesd and the quarantine resolver - without',
      '; these open fails with -10822 kLSServerCommunicationErr or -54',
      '(allow lsopen)',
      '(allow mach-lookup (global-name "com.apple.CoreServices.coreservicesd"))',
      '(allow mach-lookup (global-name "com.apple.coreservices.quarantine-resolver"))',
    ],
    if (allowMachLookup != null && allowMachLookup.isNotEmpty) ...[
      '; User-specified XPC/Mach services',
      ...allowMachLookup.map(
        (name) => name.endsWith('*')
            ? '(allow mach-lookup (global-name-prefix ${_escapePath(name.substring(0, name.length - 1))}))'
            : '(allow mach-lookup (global-name ${_escapePath(name)}))',
      ),
    ],
    '',
    '; POSIX IPC - shared memory',
    '(allow ipc-posix-shm)',
    '',
    '; POSIX IPC - semaphores for Python multiprocessing',
    '(allow ipc-posix-sem)',
    '',
    '; IOKit - specific operations only',
    '(allow iokit-open',
    '  (iokit-registry-entry-class "IOSurfaceRootUserClient")',
    '  (iokit-registry-entry-class "RootDomainUserClient")',
    '  (iokit-user-client-class "IOSurfaceSendRight")',
    ')',
    '',
    '; IOKit properties',
    '(allow iokit-get-properties)',
    '',
    "; Specific safe system-sockets, doesn't allow network access",
    '(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))',
    '',
    '; sysctl - specific sysctls only',
    '(allow sysctl-read',
    '  (sysctl-name "hw.activecpu")',
    '  (sysctl-name "hw.busfrequency_compat")',
    '  (sysctl-name "hw.byteorder")',
    '  (sysctl-name "hw.cacheconfig")',
    '  (sysctl-name "hw.cachelinesize_compat")',
    '  (sysctl-name "hw.cpufamily")',
    '  (sysctl-name "hw.cpufrequency")',
    '  (sysctl-name "hw.cpufrequency_compat")',
    '  (sysctl-name "hw.cputype")',
    '  (sysctl-name "hw.l1dcachesize_compat")',
    '  (sysctl-name "hw.l1icachesize_compat")',
    '  (sysctl-name "hw.l2cachesize_compat")',
    '  (sysctl-name "hw.l3cachesize_compat")',
    '  (sysctl-name "hw.logicalcpu")',
    '  (sysctl-name "hw.logicalcpu_max")',
    '  (sysctl-name "hw.machine")',
    '  (sysctl-name "hw.memsize")',
    '  (sysctl-name "hw.ncpu")',
    '  (sysctl-name "hw.nperflevels")',
    '  (sysctl-name "hw.packages")',
    '  (sysctl-name "hw.pagesize_compat")',
    '  (sysctl-name "hw.pagesize")',
    '  (sysctl-name "hw.physicalcpu")',
    '  (sysctl-name "hw.physicalcpu_max")',
    '  (sysctl-name "hw.tbfrequency_compat")',
    '  (sysctl-name "hw.vectorunit")',
    '  (sysctl-name "kern.argmax")',
    '  (sysctl-name "kern.bootargs")',
    '  (sysctl-name "kern.hostname")',
    '  (sysctl-name "kern.maxfiles")',
    '  (sysctl-name "kern.maxfilesperproc")',
    '  (sysctl-name "kern.maxproc")',
    '  (sysctl-name "kern.ngroups")',
    '  (sysctl-name "kern.osproductversion")',
    '  (sysctl-name "kern.osrelease")',
    '  (sysctl-name "kern.ostype")',
    '  (sysctl-name "kern.osvariant_status")',
    '  (sysctl-name "kern.osversion")',
    '  (sysctl-name "kern.secure_kernel")',
    '  (sysctl-name "kern.tcsm_available")',
    '  (sysctl-name "kern.tcsm_enable")',
    '  (sysctl-name "kern.usrstack64")',
    '  (sysctl-name "kern.version")',
    '  (sysctl-name "kern.willshutdown")',
    '  (sysctl-name "machdep.cpu.brand_string")',
    '  (sysctl-name "machdep.ptrauth_enabled")',
    '  (sysctl-name "security.mac.lockdown_mode_state")',
    '  (sysctl-name "sysctl.proc_cputype")',
    '  (sysctl-name "vm.loadavg")',
    '  (sysctl-name-prefix "hw.optional.arm")',
    '  (sysctl-name-prefix "hw.optional.arm.")',
    '  (sysctl-name-prefix "hw.optional.armv8_")',
    '  (sysctl-name-prefix "hw.perflevel")',
    '  (sysctl-name-prefix "kern.proc.all")',
    '  (sysctl-name-prefix "kern.proc.pgrp.")',
    '  (sysctl-name-prefix "kern.proc.pid.")',
    '  (sysctl-name-prefix "machdep.cpu.")',
    '  (sysctl-name-prefix "net.routetable.")',
    ')',
    '',
    '; V8 thread calculations',
    '(allow sysctl-write',
    '  (sysctl-name "kern.tcsm_enable")',
    ')',
    '',
    '; Distributed notifications',
    '(allow distributed-notification-post)',
    '',
    '; Specific mach-lookup permissions for security operations',
    '(allow mach-lookup (global-name "com.apple.SecurityServer"))',
    '',
    '; File I/O on device files',
    '(allow file-ioctl (literal "/dev/null"))',
    '(allow file-ioctl (literal "/dev/zero"))',
    '(allow file-ioctl (literal "/dev/random"))',
    '(allow file-ioctl (literal "/dev/urandom"))',
    '(allow file-ioctl (literal "/dev/dtracehelper"))',
    '(allow file-ioctl (literal "/dev/tty"))',
    '',
    '(allow file-ioctl file-read-data file-write-data',
    '  (require-all',
    '    (literal "/dev/null")',
    '    (vnode-type CHARACTER-DEVICE)',
    '  )',
    ')',
    '',
  ];

  // Network rules
  profile.add('; Network');
  // TELOSNEX DEVIATION: Only the upstream unrestricted mode allows network*.
  if (!needsNetworkRestriction && !directNetwork) {
    profile.add('(allow network*)');
  } else {
    // Allow local binding if requested.
    //
    // bind/inbound use (local ip "*:*") instead of "localhost:*" because modern
    // runtimes (Java, etc.) create IPv6 dual-stack sockets by default; binding
    // such a socket to 127.0.0.1 is represented in the kernel as
    // ::ffff:127.0.0.1, which Seatbelt's "localhost" filter does not match.
    // Seatbelt only accepts "localhost" or "*" as the host token, so "*:*" is
    // the only way to admit the IPv4-mapped form. bind/inbound are local
    // operations (no remote endpoint), so wildcarding them does not grant
    // egress.
    //
    // outbound uses (remote ip "localhost:*") so the egress allowlist remains
    // enforced when allowLocalBinding is set (#225, #88). A (local ip ...)
    // filter on network-outbound is evaluated against the source address,
    // which for an unbound socket is INADDR_ANY (0.0.0.0 / ::) at connect()
    // time — Seatbelt's "localhost" matches the any-address, so any
    // (local ip ...) host value admits every outbound connection. (remote ip
    // "localhost:*") matches connect() to 127.0.0.1 and ::1 but not
    // ::ffff:127.0.0.1; runtimes that connect to loopback via dual-stack
    // sockets need to use AF_INET (see JAVA_TOOL_OPTIONS injection below).
    // TELOSNEX DEVIATION: Permit IP endpoints, not Unix socket paths.
    if (directNetwork) {
      profile.add('(allow network-bind (local ip "*:*"))');
      profile.add('(allow network-inbound (local ip "*:*"))');
      profile.add('(allow network-outbound (remote ip "*:*"))');
      // macOS's system resolver connects to mDNSResponder over Unix IPC.
      // Match that endpoint exactly, outbound only; no extra bind grant.
      profile.add(
        '(allow network-outbound (remote unix-socket (literal "/private/var/run/mDNSResponder")))',
      );
    } else if (allowLocalBinding == true) {
      profile.add('(allow network-bind (local ip "*:*"))');
      profile.add('(allow network-inbound (local ip "*:*"))');
      profile.add('(allow network-outbound (remote ip "localhost:*"))');
    }
    // Unix domain sockets for local IPC (SSH agent, Docker, Gradle, etc.)
    // Three separate operations must be allowed:
    // 1. system-socket: socket(AF_UNIX, ...) syscall — creates the socket fd (no path context)
    // 2. network-bind: bind() to a local Unix socket path
    // 3. network-outbound: connect() to a remote Unix socket path
    // Note: (subpath ...) and (path-regex ...) are path-based filters that can only match
    // bind/connect operations — socket() creation has no path, so it requires system-socket.
    if (allowAllUnixSockets == true) {
      // Allow creating AF_UNIX sockets and all Unix socket paths
      profile.add('(allow system-socket (socket-domain AF_UNIX))');
      profile.add(
        '(allow network-bind (local unix-socket (path-regex #"^/")))',
      );
      profile.add(
        '(allow network-outbound (remote unix-socket (path-regex #"^/")))',
      );
    } else if (allowUnixSockets != null && allowUnixSockets.isNotEmpty) {
      // Allow creating AF_UNIX sockets (required for any Unix socket use)
      profile.add('(allow system-socket (socket-domain AF_UNIX))');
      // Allow specific Unix socket paths
      for (final socketPath in allowUnixSockets) {
        final normalizedPath = normalizePathForSandbox(socketPath);
        profile.add(
          '(allow network-bind (local unix-socket (subpath ${_escapePath(normalizedPath)})))',
        );
        profile.add(
          '(allow network-outbound (remote unix-socket (subpath ${_escapePath(normalizedPath)})))',
        );
      }
    }
    // If both allowAllUnixSockets and allowUnixSockets are false/undefined/empty, Unix sockets are blocked by default
    // TELOSNEX DEVIATION: Direct IP mode allows only the DNS exception above by default.
    // Allow localhost TCP operations for the HTTP proxy
    if (httpProxyPort != null) {
      profile.add('(allow network-bind (local ip "localhost:$httpProxyPort"))');
      profile.add(
        '(allow network-inbound (local ip "localhost:$httpProxyPort"))',
      );
      profile.add(
        '(allow network-outbound (remote ip "localhost:$httpProxyPort"))',
      );
    }
    // Allow localhost TCP operations for the SOCKS proxy. Skip when it's
    // the same port as the HTTP proxy (the mux serves both on one port);
    // SBPL accepts duplicate allow clauses but there's no need to emit them.
    if (socksProxyPort != null && socksProxyPort != httpProxyPort) {
      profile.add(
        '(allow network-bind (local ip "localhost:$socksProxyPort"))',
      );
      profile.add(
        '(allow network-inbound (local ip "localhost:$socksProxyPort"))',
      );
      profile.add(
        '(allow network-outbound (remote ip "localhost:$socksProxyPort"))',
      );
    }
  }
  profile.add('');
  final writeRoots = _writeRootEntries(writeConfig);
  // Read rules
  // Pass write-allowed paths so that move-blocking deny rules in the read section
  // can be overridden for paths where file deletion should be permitted.
  final resolvedRead = readConfig != null || libraryDenyEntries.isNotEmpty
      ? _resolveReadConfig(
          readConfig ?? FsReadRestrictionConfig(denyOnly: []),
          writeRoots,
          libraryDenyEntries,
        )
      : null;
  profile.add('; File read');
  profile.addAll(_generateReadRules(resolvedRead, logTag));
  profile.add('');
  // Write rules
  profile.add('; File write');
  profile.addAll(
    _generateWriteRules(writeConfig, logTag, allowGitConfig, writeRoots),
  );
  // Read-denied paths inside write roots: the read section's unlink/create
  // re-allow for write roots (and the write section's file-write* allows)
  // must not leave them renameable. Last in the profile so nothing above
  // can re-open them.
  if (resolvedRead != null) {
    final unlinkRules = _generateReadDenyUnlinkRules(resolvedRead, logTag);
    if (unlinkRules.isNotEmpty) {
      profile.add('');
      profile.add(
        '; File read: keep read-denied paths inside write roots in place',
      );
      profile.addAll(unlinkRules);
    }
  }
  // Pseudo-terminal (pty) support
  if (allowPty == true) {
    profile.addAll([
      '',
      '; Pseudo-terminal (pty) support',
      '(allow pseudo-tty)',
      '(allow file-ioctl',
      '  (literal "/dev/ptmx")',
      '  (regex #"^/dev/ttys")',
      ')',
      '(allow file-read* file-write*',
      '  (literal "/dev/ptmx")',
      '  (regex #"^/dev/ttys")',
      ')',
    ]);
  }
  return profile.join('\n');
}

///
/// Escape path for sandbox profile using JSON.stringify for proper escaping
///
String _escapePath(String pathStr) => jsonEncode(pathStr);

///
/// Wrap command with macOS sandbox
///
String wrapCommandWithSandboxMacOS(MacOSSandboxParams params) {
  final command = params.command;
  final commandId = params.commandId;
  final needsNetworkRestriction = params.needsNetworkRestriction;
  final httpProxyPort = params.httpProxyPort;
  final socksProxyPort = params.socksProxyPort;
  final proxyAuthToken = params.proxyAuthToken;
  final caCertPath = params.caCertPath;
  final javaAgentJarPath = params.javaAgentJarPath;
  final allowUnixSockets = params.allowUnixSockets;
  final allowAllUnixSockets = params.allowAllUnixSockets;
  final allowLocalBinding = params.allowLocalBinding;
  final allowMachLookup = params.allowMachLookup;
  final readConfig = params.readConfig;
  final writeConfig = params.writeConfig;
  final unsetEnvVars = params.unsetEnvVars;
  final setEnvVars = params.setEnvVars;
  final maskedFileBinds = params.maskedFileBinds;
  final degradeToDenyPaths = params.degradeToDenyPaths;
  final allowPty = params.allowPty;
  final allowGitConfig = params.allowGitConfig ?? false;
  final gitSafeDirectories = params.gitSafeDirectories;
  final enableWeakerNetworkIsolation =
      params.enableWeakerNetworkIsolation ?? false;
  final allowAppleEvents = params.allowAppleEvents ?? false;
  final binShell = params.binShell;
  // TELOSNEX DEVIATION: Use a private TMPDIR independent of proxying.
  final temporaryDirectory = params.temporaryDirectory;

  // SBPL cannot redirect a read to different bytes, so whole-file masking
  // degrades to read-deny on macOS: the sandboxed process gets EPERM
  // instead of the sentinel. The DYLD interposer (a later step) lifts
  // this. The paths go to generateReadRules() as LITERAL denies — each is
  // a credential file the library located, not a spelling the caller wrote
  // — and the existing (deny file-read* …) rule is emitted unchanged.
  final maskedDenyPaths =
      maskedFileBinds?.map((b) => b.realPath).toList() ?? [];
  if (maskedDenyPaths.isNotEmpty) {
    logForDebugging(
      '[Sandbox macOS] file mask degrades to deny on macOS until the interposer lands',
    );
  }
  final libraryDenyEntries = [
    ...maskedDenyPaths,
    ...(degradeToDenyPaths ?? const <String>[]),
  ].map(_toLiteralPathEntry).toList();
  // A masked file whose extract pattern stopped matching is denied the
  // same way: the library opened both, so both are literals.

  // Determine if we have restrictions to apply
  // Read: denyOnly pattern - empty array means no restrictions
  // Write: allowOnly pattern - undefined means no restrictions, any config means restrictions
  final hasReadRestrictions =
      (readConfig != null &&
          (readConfig.denyOnly.isNotEmpty ||
              (readConfig.literalDenyOnly?.length ?? 0) > 0)) ||
      libraryDenyEntries.isNotEmpty;
  final hasWriteRestrictions = writeConfig != null;
  final hasEnvRestrictions =
      (unsetEnvVars != null && unsetEnvVars.isNotEmpty) ||
      (setEnvVars != null && setEnvVars.isNotEmpty);
  final hasGitConfig = (gitSafeDirectories?.length ?? 0) > 0;
  // No sandboxing needed
  // TELOSNEX DEVIATION: Explicit direct IP mode still applies Unix-socket rules.
  if (!needsNetworkRestriction &&
      !params.directNetwork &&
      !hasReadRestrictions &&
      !hasWriteRestrictions &&
      !hasEnvRestrictions &&
      !hasGitConfig) {
    // TELOSNEX DEVIATION: Set TMPDIR even for unrestricted commands, without
    // imposing a sandbox that upstream would not have imposed.
    return temporaryDirectory == null
        ? command
        : quote([
            'env',
            'TMPDIR=$temporaryDirectory',
            binShell != null && binShell.isNotEmpty ? binShell : 'bash',
            '-c',
            command,
          ]);
  }

  // Both correlation carriers (seatbelt log tag, proxy username) encode
  // the attribution key, which is the caller's commandId when the
  // executed string differs from the one violations are looked up by.
  final attributionCommand = attributionKeyFor(command, commandId);
  final logTag = _generateLogTag(attributionCommand);
  final profile = _generateSandboxProfile(
    readConfig: readConfig,
    libraryDenyEntries: libraryDenyEntries,
    writeConfig: writeConfig,
    httpProxyPort: httpProxyPort,
    socksProxyPort: socksProxyPort,
    needsNetworkRestriction: needsNetworkRestriction,
    // TELOSNEX DEVIATION: Pass through direct IP mode to the profile.
    directNetwork: params.directNetwork,
    allowUnixSockets: allowUnixSockets,
    allowAllUnixSockets: allowAllUnixSockets,
    allowLocalBinding: allowLocalBinding,
    allowMachLookup: allowMachLookup,
    allowPty: allowPty,
    allowGitConfig: allowGitConfig,
    enableWeakerNetworkIsolation: enableWeakerNetworkIsolation,
    allowAppleEvents: allowAppleEvents,
    logTag: logTag,
  );

  // Generate proxy environment variables using shared utility
  final proxyEnvArgs = generateProxyEnvVars(
    httpProxyPort,
    socksProxyPort,
    caCertPath,
    proxyAuthToken,
    // TELOSNEX DEVIATION: Don't set the legacy shared TMPDIR when opted out
    // or when the command has its own temp directory.
    writeConfig == null ||
        params.skipDefaultTmpdir == true ||
        temporaryDirectory != null,
    encodeSandboxedCommand(attributionCommand),
  );
  // TELOSNEX DEVIATION: The explicit TMPDIR takes precedence over proxy defaults
  // and credential env overlays, just as the upstream TMPDIR did.
  if (temporaryDirectory != null)
    proxyEnvArgs.add('TMPDIR=$temporaryDirectory');
  // JAVA_TOOL_OPTIONS carries two things for JVMs in the sandbox:
  //
  // - The proxy agent jar (see java-proxy-agent.ts): JVMs ignore the proxy
  //   env vars above, so the agent translates them into system properties
  //   plus an Authenticator for the proxy credential at JVM start.
  // - -Djava.net.preferIPv4Stack=true whenever the profile lets the child
  //   reach loopback at all (the proxy ports, or allowLocalBinding's
  //   localhost:*): Seatbelt's (remote ip "localhost:N") filter matches
  //   127.0.0.1 and ::1 but not the IPv4-mapped IPv6 form ::ffff:127.0.0.1.
  //   Modern Java defaults to AF_INET6 dual-stack sockets, so a Java client
  //   connecting to 127.0.0.1 reaches the kernel as ::ffff:127.0.0.1 and is
  //   denied ("Operation not permitted") — including its connect to the
  //   proxy the agent just pointed it at. Forcing the IPv4 stack makes Java
  //   open AF_INET sockets so loopback connect matches the filter.
  //
  // Both are composed with any inherited JAVA_TOOL_OPTIONS unless that var
  // is on the credential-deny list, in which case the inherited value is
  // dropped so the deny holds.
  final loopbackReachable =
      needsNetworkRestriction &&
      (allowLocalBinding == true ||
          httpProxyPort != null ||
          socksProxyPort != null);
  final javaToolOptions = buildJavaToolOptions(
    agentJarPath: javaAgentJarPath,
    flags: loopbackReachable ? ['-Djava.net.preferIPv4Stack=true'] : [],
    unsetEnvVars: unsetEnvVars,
    inherited: process.env['JAVA_TOOL_OPTIONS'],
  );
  if (javaToolOptions != null)
    proxyEnvArgs.add('JAVA_TOOL_OPTIONS=$javaToolOptions');

  // safe.directory (dubious-ownership) — buildPosixGitSafeDirEnv composes
  // against the child's actual starting env (process.env inherited under
  // sandbox-exec, unsetEnvVars dropped, setEnvVars overlaid) so an ambient
  // GIT_CONFIG_COUNT is continued, not clobbered.
  if (gitSafeDirectories != null && gitSafeDirectories.isNotEmpty) {
    final gitCfg = buildPosixGitSafeDirEnv(
      safeDirs: gitSafeDirectories,
      unsetEnvVars: unsetEnvVars ?? const <String>[],
      setEnvVars: setEnvVars ?? const <String, String>{},
    );
    for (final entry in gitCfg.entries)
      proxyEnvArgs.add('${entry.key}=${entry.value}');
  }

  // Use the user's shell (zsh, bash, etc.) to ensure aliases/snapshots work
  // Resolve the full path to the shell binary
  final shellName = (binShell == null || binShell.isEmpty) ? 'bash' : binShell;
  final shell = whichSync(shellName);
  if (shell == null) throw StateError("Shell '$shellName' not found in PATH");
  // Drop denied credential env vars from the inherited environment. The -u
  // flags must precede the VAR=VALUE assignments so SRT's own proxy plumbing
  // vars survive even if a caller lists one of them as a denied credential.
  final unsetEnvArgs = (unsetEnvVars ?? const <String>[]).expand(
    (name) => ['-u', name],
  );
  // Masked credentials override the inherited real value with a sentinel.
  // Placed before the proxy plumbing assignments for the same precedence
  // reason as the -u flags.
  final setEnvArgs = (setEnvVars ?? const <String, String>{}).entries.map(
    (e) => '${e.key}=${e.value}',
  );
  // Use `env` command to set environment variables - each VAR=value is a separate
  // argument that quote() escapes properly, avoiding shell quoting issues
  final wrappedCommand = quote([
    'env',
    ...unsetEnvArgs,
    ...setEnvArgs,
    ...proxyEnvArgs,
    '/usr/bin/sandbox-exec',
    '-p',
    profile,
    shell,
    '-c',
    command,
  ]);
  final readSummary = hasReadRestrictions ? 'denyAllExcept' : 'none';
  final writeSummary = writeConfig != null ? 'denyAllExcept' : 'none';
  logForDebugging(
    '[Sandbox macOS] Applied restrictions - network: ${(httpProxyPort ?? 0) != 0 || (socksProxyPort ?? 0) != 0}, read: $readSummary, write: $writeSummary',
  );
  return wrappedCommand;
}

///
/// Start monitoring macOS system logs for sandbox violations
/// Look for sandbox-related kernel deny events ending in {logTag}
///
void Function() Function(
  SandboxViolationCallback callback,
  IgnoreViolationsConfig? ignoreViolations,
  String Function(String decodedKey) resolveCommandText,
)
startMacOSSandboxLogMonitor = _startMacOSSandboxLogMonitor;

void Function() _startMacOSSandboxLogMonitor(
  SandboxViolationCallback callback,
  IgnoreViolationsConfig? ignoreViolations,

  ///
  /// Map a decoded attribution key to the command text it represents, before
  /// ignoreViolations matching and before the event's `command` is set. Only
  /// the manager holds the registry that can do that, so it is required
  /// rather than defaulted: a caller with no registry passes
  /// sanitizeUnregisteredCommandKey, which treats the key as the untrusted
  /// bytes it arrived as.
  ///
  String Function(String decodedKey) resolveCommandText,
) {
  // Pre-compile regex patterns for better performance
  final cmdExtractRegex = RegExp(r'CMD64_(.+?)_END');
  final sandboxExtractRegex = RegExp(r'Sandbox:\s+(.+)$');
  // Stream and filter kernel logs for all sandbox violations
  // We can't filter by specific logTag since it's dynamic per command
  final logProcess = spawn('log', [
    'stream',
    '--predicate',
    '(eventMessage ENDSWITH "$_sessionSuffix")',
    '--style',
    'compact',
  ]);
  logProcess.stdout?.listen((data) {
    final lines = utf8.decode(data).split('\n');
    // Get violation and command lines
    String? firstOrNull(Iterable<String> values) =>
        values.isEmpty ? null : values.first;
    final violationLine = firstOrNull(
      lines.where((line) => line.contains('Sandbox:') && line.contains('deny')),
    );
    final commandLine = firstOrNull(
      lines.where((line) => line.startsWith('CMD64_')),
    );
    if (violationLine == null) return;
    // Extract violation details
    final sandboxMatch = sandboxExtractRegex.firstMatch(violationLine);
    final violationDetails = sandboxMatch?.group(1);
    if (violationDetails == null || violationDetails.isEmpty) return;
    // Try to get command
    String? command;
    String? encodedCommand;
    if (commandLine != null) {
      encodedCommand = cmdExtractRegex.firstMatch(commandLine)?.group(1);
      if (encodedCommand != null && encodedCommand.isNotEmpty) {
        try {
          command = resolveCommandText(decodeSandboxedCommand(encodedCommand));
        } catch (_) {
          // Failed to decode, continue without command.
        }
      }
    }
    // Always filter out noisey violations
    if (violationDetails.contains('mDNSResponder') ||
        violationDetails.contains('mach-lookup com.apple.diagnosticd') ||
        violationDetails.contains('mach-lookup com.apple.analyticsd'))
      return;
    // Check if we should ignore this violation
    if (shouldIgnoreViolation(violationDetails, command, ignoreViolations))
      return;
    // Not ignored - report the violation
    callback(
      SandboxViolationEvent(
        line: violationDetails,
        command: command,
        encodedCommand: encodedCommand,
        timestamp:
            DateTime.now(), // We could parse the timestamp from the log but this feels more reliable
      ),
    );
  });
  logProcess.stderr?.listen((data) {
    logForDebugging(
      '[Sandbox Monitor] Log stream stderr: ${utf8.decode(data)}',
    );
  });

  logProcess.on('error', (Object error) {
    logForDebugging(
      '[Sandbox Monitor] Failed to start log stream: ${errorMessage(error)}',
    );
  });

  logProcess.on('exit', (int? code) {
    logForDebugging('[Sandbox Monitor] Log stream exited with code: $code');
  });
  return () {
    logForDebugging('[Sandbox Monitor] Stopping log monitor');
    logProcess.kill('SIGTERM');
  };
}
