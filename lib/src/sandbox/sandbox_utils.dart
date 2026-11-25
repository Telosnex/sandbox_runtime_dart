// Ported from sandbox-runtime src/sandbox/sandbox-utils.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments
// ignore_for_file: slash_for_doc_comments, non_constant_identifier_names
// ignore_for_file: avoid_dynamic_calls, curly_braces_in_flow_control_structures
// ignore_for_file: doc_directive_unknown

import 'dart:convert';

import 'package:path/path.dart' as path;

import '../node/abort.dart';
import '../node/buffer.dart';
import '../node/errno.dart';
import '../node/fs.dart' as fs;
import '../node/generators.dart';
import '../node/os.dart' show homedir;
import '../node/path.dart' as node_path;
import '../node/process.dart' as process;
import '../utils/debug.dart';
import '../utils/platform.dart' show getPlatform;
import '../utils/real_path.dart' show realPathOf;
import 'glob_pattern.dart';
import 'sandbox_config.dart'
    show FilesystemPathEntry, FilesystemPathLiteral, FilesystemPathSpelling;

/// Dangerous files that should be protected from writes.
/// These files can be used for code execution or data exfiltration.
const List<String> DANGEROUS_FILES = [
  '.gitconfig',
  '.gitmodules',
  '.bashrc',
  '.bash_profile',
  '.zshrc',
  '.zprofile',
  '.profile',
  '.ripgreprc',
  '.mcp.json',
];

/// Dangerous directories that should be protected from writes.
/// These directories contain sensitive configuration or executable files.
const List<String> DANGEROUS_DIRECTORIES = ['.git', '.vscode', '.idea'];

/// Get the list of dangerous directories to deny writes to.
/// Excludes .git since we need it writable for git operations -
/// instead we block specific paths within .git (hooks and config).
List<String> getDangerousDirectories() => [
  ...DANGEROUS_DIRECTORIES.where((directory) => directory != '.git'),
  '.claude/commands',
  '.claude/agents',
];

/// Normalizes a path for case-insensitive comparison.
/// This prevents bypassing security checks using mixed-case paths on case-insensitive
/// filesystems (macOS/Windows) like `.cLauDe/Settings.locaL.json`.
///
/// We always normalize to lowercase regardless of platform for consistent security.
/// @param path The path to normalize
/// @returns The lowercase path for safe comparison
String normalizeCaseForComparison(String pathStr) => pathStr.toLowerCase();

/// `p` is `dir` itself or lies beneath it, by path segment ('/xy' is not under
/// '/x'); root-aware, since '/' + '/' is a prefix of nothing.
bool isAtOrUnder(String p, String dir) =>
    p == dir || p.startsWith(dir == '/' ? '/' : '$dir/');

/// `p` lies strictly beneath `dir` (isAtOrUnder, excluding `dir` itself).
bool isStrictlyUnder(String p, String dir) => p != dir && isAtOrUnder(p, dir);

/// The proper ancestors of an absolute POSIX path, nearest first, ending at '/'.
Iterable<String> properAncestors(String absolutePath) sync* {
  for (
    var slash = absolutePath.lastIndexOf('/');
    slash > 0;
    slash = absolutePath.lastIndexOf('/', slash - 1)
  ) {
    yield absolutePath.substring(0, slash);
  }
  if (absolutePath != '/') yield '/';
}

/// The spellings that name `candidatePath` for a mount comparison: as spelled,
/// plus with every symlink resolved when that differs. A path that cannot be
/// resolved (dangling, vanished) is named by its spelling alone.
List<String> pathSpellings(String candidatePath) {
  try {
    final resolved = realPathOf(candidatePath);
    if (resolved != candidatePath) return [candidatePath, resolved];
  } catch (_) {
    // Dangling or vanished: only the spelling names it.
  }
  return [candidatePath];
}

/// Where the name `p` lives: its parent directories as `canonicalOf` resolves
/// them, its last component as written. An allowRead entry is read so: one
/// that is a symlink names the link, and nothing the link points at.
String nameLocation(String p, String Function(String dir) canonicalOf) {
  if (p == '/') return p;
  final parent = canonicalOf(path.dirname(p));
  return '${parent == '/' ? '' : parent}/${path.basename(p)}';
}

/// `process.cwd()`, or undefined where that throws: it has been removed.
String? workingDirectory() {
  try {
    return process.cwd();
  } catch (_) {
    return null;
  }
}

/// An fs error that means the name resolves to no file — it is missing, or
/// the path cannot name one at all — as opposed to one that means a file is
/// there but could not be looked at (EACCES, EPERM, EIO, anything
/// unrecognised).
bool isAbsenceErrno(Object? err) {
  final code = err is NodeError
      ? err.code
      : err is Map && err['code'] is String
      ? err['code'] as String
      : null;
  return code == 'ENOENT' ||
      code == 'ENOTDIR' ||
      code == 'ELOOP' ||
      code == 'ENAMETOOLONG';
}

///
/// Check if a path pattern contains glob characters
///
bool containsGlobChars(String pathPattern) =>
    pathPattern.contains('*') ||
    pathPattern.contains('?') ||
    pathPattern.contains('[') ||
    pathPattern.contains(']');

/// Windows-specific glob-char check. `[` and `]` are NOT
/// metachars here — they are legal in Win32 filenames, so a
/// literal `C:\app\[prod].env` must route to the literal-path
/// branch, not glob expansion (where it would match nothing and
/// be silently dropped). Only `*` and `?` trigger expansion.
bool containsGlobCharsWin(String p) => p.contains('*') || p.contains('?');

/// Platform-appropriate glob-char check.
bool containsGlobCharsForPlatform(String p) =>
    getPlatform() == 'windows' ? containsGlobCharsWin(p) : containsGlobChars(p);

/// The path of an entry that is not a spelling. Throws unless the entry is
/// `{ path: string, literal: true }`: a config built in code skips the
/// schema, and reading `{ path }` either way would be a guess about a deny.
String markedLiteralPath(FilesystemPathEntry entry) {
  if (entry is FilesystemPathLiteral && entry.path.isNotEmpty)
    return entry.path;
  throw ArgumentError(
    'A filesystem path entry must be a path, or { path, literal: true }; '
    'got ${jsonEncode(entry.toString())}',
  );
}

/// Strip the Win32 `\\?\` extended-path prefix so the residue is
/// a conventional absolute path (drive-letter or UNC) with no `?`
/// for the glob-char check to misclassify. `\\?\UNC\srv\share\f`
/// → `\\srv\share\f`; `\\?\C:\f` → `C:\f`; anything else → input.
/// The UNC marker is matched case-insensitively (Windows accepts
/// `\\?\unc\…` in any casing; a case-sensitive check would fall
/// through to the 4-char strip and yield a cwd-relative residue).
String stripExtendedPathPrefix(String p) {
  if (RegExp(r'^\\\\\?\\unc\\', caseSensitive: false).hasMatch(p)) {
    return r'\\' + p.substring(8);
  }
  if (p.startsWith(r'\\?\')) return p.substring(4);
  return p;
}

/// True for a Windows UNC path in any spelling — `\\server\share\…`,
/// extended-length `\\?\UNC\server\share\…`, device-namespace
/// `\\.\UNC\server\share\…` (all any casing, either separator).
/// Delegates path-form normalization to
/// `path.win32.toNamespacedPath` — every UNC spelling canonicalizes
/// to `\\?\UNC\…` — so the check is "namespaced form starts with
/// `\\?\UNC\` (or `\\.\UNC\`)". Drive-local forms (`C:\…`,
/// `\\?\C:\…`), other device paths (`\\.\pipe\…`), relative paths
/// (resolved against a local cwd), and server-only `\\srv` (no
/// share) are all false.
///
/// The broker uses this to skip `stat`/`realpath` on UNC **literals**
/// (see {@link normalizePathForSandbox}): any such call is an SMB
/// request carrying the **real user's** NTLM credentials to whatever
/// host the path names — a forced-auth / path-encoded-exfil channel
/// if the path is model-influenced. Literals pass through raw
/// (resolution failures surface at `srt-win` stamp/grant time); a
/// UNC **glob** still walks the share with real-user credentials —
/// the user consented by naming their own share in the config.
/// Defense-in-depth: the primary embedder already gates
/// model-provided cwd/paths upstream.
bool isUncPath(String p) {
  // Dart: no path.win32 shim; this is win32.toNamespacedPath for a regular UNC path.
  final regular = RegExp(
    r'^[\\/]{2}([^\\/?.][^\\/]*)[\\/]+([^\\/]+)',
  ).firstMatch(p);
  final ns = regular != null
      ? r'\\?\UNC\' + p.substring(2).replaceAll('/', r'\')
      : p;
  // Already-namespaced input passes through `toNamespacedPath`
  // verbatim (casing and separators preserved), so match the UNC
  // marker case-insensitively with either separator. `[?.]` also
  // catches the device-namespace `\\.\UNC\…` form — that is a real
  // network access, not a local device.
  return RegExp(
    r'^[\\/]{2}[?.][\\/]unc[\\/]',
    caseSensitive: false,
  ).hasMatch(ns);
}

/// Remove trailing /** glob suffix from a path pattern
/// Used to normalize path patterns since /** just means "directory and everything under it"
String removeTrailingGlobSuffix(String pathPattern) {
  final stripped = pathPattern.replaceFirst(RegExp(r'/\*\*$'), '');
  return stripped.isEmpty ? '/' : stripped;
}

/// Check if a symlink resolution crosses expected path boundaries.
///
/// When resolving symlinks for sandbox path normalization, we need to ensure
/// the resolved path doesn't unexpectedly broaden the scope. This function
/// returns true if the resolved path is an ancestor of the original path
/// or resolves to a system root, which would indicate the symlink points
/// outside expected boundaries.
///
/// @param originalPath - The original path before symlink resolution
/// @param resolvedPath - The path after fs.realpathSync() resolution
/// @returns true if the resolved path is outside expected boundaries
bool isSymlinkOutsideBoundary(String originalPath, String resolvedPath) {
  final normalizedOriginal = path.normalize(originalPath);
  final normalizedResolved = path.normalize(resolvedPath);
  // Same path after normalization - OK
  if (normalizedResolved == normalizedOriginal) return false;
  // Handle macOS /tmp -> /private/tmp canonical resolution
  // This is a legitimate system symlink that should be allowed
  // /tmp/claude -> /private/tmp/claude is OK
  // /var/folders/... -> /private/var/folders/... is OK
  if (normalizedOriginal.startsWith('/tmp/') &&
      normalizedResolved == '/private$normalizedOriginal')
    return false;
  if (normalizedOriginal.startsWith('/var/') &&
      normalizedResolved == '/private$normalizedOriginal')
    return false;
  // If resolved path is "/" it's outside expected boundaries
  if (normalizedResolved == '/') return true;
  // If resolved path is very short (single component like /tmp, /usr, /var),
  // it's likely outside expected boundaries
  final resolvedParts = normalizedResolved
      .split('/')
      .where((p) => p.isNotEmpty);
  if (resolvedParts.length <= 1) return true;
  // If original path starts with resolved path, the resolved path is an ancestor
  // e.g., /tmp/claude -> /tmp means the symlink points to a broader scope
  if (normalizedOriginal.startsWith('$normalizedResolved/')) return true;
  // Also check the canonical form of the original path for macOS
  // e.g., /tmp/claude should also be checked as /private/tmp/claude
  var canonicalOriginal = normalizedOriginal;
  if (normalizedOriginal.startsWith('/tmp/')) {
    canonicalOriginal = '/private$normalizedOriginal';
  } else if (normalizedOriginal.startsWith('/var/')) {
    canonicalOriginal = '/private$normalizedOriginal';
  }
  if (canonicalOriginal != normalizedOriginal &&
      canonicalOriginal.startsWith('$normalizedResolved/'))
    return true;
  // STRICT CHECK: Only allow resolutions that stay within the expected path tree
  // The resolved path must either:
  // 1. Start with the original path (deeper/same) - already covered by returning false below
  // 2. Start with the canonical original (deeper/same under canonical form)
  // 3. BE the canonical form of the original (e.g., /tmp/x -> /private/tmp/x)
  // Any other resolution (e.g., /tmp/claude -> /Users/dworken) is outside expected bounds
  final resolvedStartsWithOriginal = normalizedResolved.startsWith(
    '$normalizedOriginal/',
  );
  final resolvedStartsWithCanonical =
      canonicalOriginal != normalizedOriginal &&
      normalizedResolved.startsWith('$canonicalOriginal/');
  final resolvedIsCanonical =
      canonicalOriginal != normalizedOriginal &&
      normalizedResolved == canonicalOriginal;
  // If resolved path is not within expected tree, it's outside boundary
  if (!resolvedIsCanonical &&
      !resolvedStartsWithOriginal &&
      !resolvedStartsWithCanonical)
    return true;
  // Allow resolution to same directory level or deeper within expected tree
  return false;
}

/// Expand a leading `~` to the home directory. Handles bare `~`,
/// `~/…`, and (on Windows only) the `~\…` form so callers don't each
/// open-code the variants. `~\` is gated to Windows because `\` is a
/// valid POSIX filename byte — `~\foo` is a legal relative filename
/// on Linux/macOS and must NOT tilde-expand there.
String expandTilde(String p) {
  if (p == '~') return homedir();
  if (p.startsWith('~/') ||
      (process.platform == 'win32' && p.startsWith(r'~\'))) {
    return homedir() + p.substring(1);
  }
  return p;
}

/// Expand Windows-style `%USERPROFILE%` / `%HOMEDRIVE%` / `%HOMEPATH%`
/// references to the real user's home directory. Case-insensitive;
/// idempotent. Applied by {@link normalizePathForSandbox}'s Windows
/// pre-processing so every filesystem-config path field
/// (`allowRead`/`allowWrite`/`denyRead`/`denyWrite`) accepts these
/// forms uniformly.
///
/// `%HOMEPATH%` is drive-RELATIVE (`\Users\name`) and `%HOMEDRIVE%` is
/// the drive-only (`C:`) — the split matches how cmd.exe defines them,
/// so `%HOMEDRIVE%%HOMEPATH%` composes to the full home path.
String expandWindowsEnvRefs(String p) {
  final home = homedir();
  final driveMatch = RegExp(r'^[A-Za-z]:').firstMatch(home);
  final drive = driveMatch == null ? '' : home.substring(0, 2);
  final homePath = drive.isNotEmpty ? home.substring(2) : home;
  return p
      .replaceAll(RegExp(r'%USERPROFILE%', caseSensitive: false), home)
      .replaceAll(RegExp(r'%HOMEDRIVE%', caseSensitive: false), drive)
      .replaceAll(RegExp(r'%HOMEPATH%', caseSensitive: false), homePath);
}

/// Runs of `/` collapsed to one and `/./` components dropped, leaving the rest
/// of the spelling (a trailing `/` or `/.`, a `..`) to the caller. POSIX only.
String collapseInteriorSpellings(String pathPattern) => pathPattern
    .replaceAll(RegExp(r'/{2,}'), '/')
    .replaceAll(RegExp(r'/\.(?=/)'), '');

/// Says so when a `..` reaches a backend unfolded — realpath could not resolve
/// the path (absent, or unreadable), and folding `..` lexically here could aim
/// the rule past a symlink at a file the kernel would never reach. Debug-only
/// (`SRT_DEBUG`), so a rule that matches nothing is silent by default. Called
/// at every return of {@link normalizePathForSandbox} that can carry one, glob
/// spellings included.
String _warnIfParentRefUnfolded(String normalizedPath) {
  if (getPlatform() != 'windows' &&
      RegExp(r'(?:^|/)\.\.(?:/|$)').hasMatch(normalizedPath)) {
    logForDebugging(
      '[Sandbox] "$normalizedPath" could not be resolved and still contains '
      'a ".." component, so a rule spelled this way may not match.',
      level: 'warn',
    );
  }
  return normalizedPath;
}

/// Normalize a path for use in sandbox configurations
/// Handles:
/// - Tilde (~) expansion for home directory
/// - Relative paths (./foo, ../foo, etc.) converted to absolute
/// - POSIX: '//' runs, '/./' components and a trailing '/' or '/.' collapsed
/// - Symlinks are resolved to their real paths for non-glob patterns
/// - Glob patterns preserve wildcards after path normalization
///
/// Returns the absolute path with symlinks resolved (or normalized glob pattern)
///
/// `opts.literal` marks a path that names one file or directory rather
/// than matching several: one the library computed itself, one the caller
/// marked literal, a caller spelling that carried no glob character —
/// resolving such a spelling can splice in a cwd or home directory whose own
/// name does — or the name a spelling with glob characters also is (see
/// path-entries.ts). The glob branches are skipped for it, so a component
/// like `a[b` is resolved and later compiled as the name it is. Without it,
/// a spelling with `*`, `?` or `[…]` in it keeps the character sniffing, its
/// pattern reading. The interior collapse below is not one of the glob
/// branches: `//` and `/./` are dead spellings either way.
String normalizePathForSandbox(String pathPattern, {bool literal = false}) {
  bool isGlobSpelling(String p) => !literal && containsGlobCharsForPlatform(p);
  // Windows pre-processing: expand `%USERPROFILE%` / `%HOMEDRIVE%` /
  // `%HOMEPATH%`, strip the `\\?\` / `\\?\UNC\` extended prefix (its
  // `?` is a literal, not a glob char), and uppercase the drive
  // letter so `c:\…` and `C:\…` normalize identically.
  if (getPlatform() == 'windows') {
    pathPattern = stripExtendedPathPrefix(expandWindowsEnvRefs(pathPattern));
    if (RegExp(r'^[a-z]:').hasMatch(pathPattern)) {
      pathPattern = pathPattern[0].toUpperCase() + pathPattern.substring(1);
    }
    // UNC literal: return as-is (separators normalised only) — no
    // stat/realpath. A UNC *glob* falls through to the glob walk
    // below (user-trusted share). See {@link isUncPath}.
    if (isUncPath(pathPattern) && !isGlobSpelling(pathPattern)) {
      return path.Context(style: path.Style.windows).normalize(pathPattern);
    }
  }
  // POSIX: strip trailing slashes from non-glob spellings before any
  // resolution. Consumers on the Linux and macOS paths compare spellings by
  // exact match and `path + '/'` prefixes — which a preserved slash silently
  // defeats ('<dir>//') — and the realpath-acceptance checks below treat a
  // slash-only difference as a mismatch. A Seatbelt `subpath` filter is the
  // one place the two spellings really are interchangeable: a `literal`
  // filter and a glob regex ending '/$' match nothing when the slash is
  // there, and a bwrap bind tolerates it only for a directory (a slashed
  // file path fails ENOTDIR at mount). Glob spellings are left untouched: a
  // slash after a glob segment is semantic ('/x/*/' compiles to a different
  // regex than '/x/*'). That regex matches nothing, which an allow may
  // harmlessly be — so an allow keeps the spelling, while the same spelling
  // as a deny is rejected at config validation (see sandbox-config.ts). On
  // Windows a trailing separator is the directory marker for absent deny
  // targets (srt#404) and must survive.
  if (getPlatform() != 'windows' &&
      pathPattern.endsWith('/') &&
      !isGlobSpelling(pathPattern)) {
    pathPattern = pathPattern.replaceFirst(RegExp(r'/+$'), '');
    if (pathPattern.isEmpty) pathPattern = '/';
  }
  var normalizedPath = expandTilde(pathPattern);
  // A pattern with no tilde to expand and no root is resolved against the
  // working directory; path.resolve covers './', '../', '.' and a bare
  // relative name alike.
  if (normalizedPath == pathPattern && !path.isAbsolute(pathPattern)) {
    normalizedPath = path.normalize(path.join(process.cwd(), pathPattern));
  }
  // POSIX: collapse the interior spellings realpath would have removed, on the
  // EXPANDED path — the trailing strip above runs before expansion and only
  // ever touches a trailing run, and tilde expansion can put a run back
  // (HOME='/home/u/' turns '~/x' into '/home/u//x'). Glob spellings need it
  // for the same reason: '~/.aws//*.pem' compiles to a regex holding '//'.
  //
  // It matters on macOS: Seatbelt compares the kernel's canonical path, so a
  // filter spelled with '//' or '/./' matches nothing, silently — which for a
  // deny is exactly the absent-target case the deny exists for. bwrap
  // tolerates the spelling, and the Linux backend rebuilds its destinations
  // with path.dirname/join, so that argv was already right.
  //
  // Lexical only, and deliberately not path.normalize/path.resolve, which
  // also fold '..'. An absolute spelling's '..' is left to realPathOf below:
  // that folds it in text too, and answers only for a path that is there, so
  // one that is not keeps its '..' as written. A relative one was already
  // folded lexically by the path.resolve above (pre-existing).
  if (getPlatform() != 'windows') {
    normalizedPath = collapseInteriorSpellings(normalizedPath);
  }
  // For glob patterns, resolve symlinks for the directory portion only
  if (isGlobSpelling(normalizedPath)) {
    // Extract the static directory prefix before glob characters
    // (on Windows, `[`/`]` are literal so only split on `*`/`?`).
    final splitRe = getPlatform() == 'windows'
        ? RegExp(r'[*?]')
        : RegExp(r'[*?[\]]');
    final staticPrefix = normalizedPath.split(splitRe).first;
    if (staticPrefix.isNotEmpty && staticPrefix != '/') {
      // Get the directory containing the glob pattern
      // If staticPrefix ends with /, remove it to get the directory
      final baseDir = staticPrefix.endsWith('/')
          ? staticPrefix.substring(0, staticPrefix.length - 1)
          : path.dirname(staticPrefix);
      try {
        // Try to resolve symlinks for the base directory
        final resolvedBaseDir = realPathOf(baseDir);
        // Validate that resolution stays within expected boundaries
        if (!isSymlinkOutsideBoundary(baseDir, resolvedBaseDir)) {
          // Reconstruct the pattern with the resolved directory
          final patternSuffix = normalizedPath.substring(baseDir.length);
          return _warnIfParentRefUnfolded('$resolvedBaseDir$patternSuffix');
        }
        // If resolution would broaden scope, keep original pattern
      } catch (_) {
        // If directory doesn't exist or can't be resolved, keep the original pattern
      }
    }
    return _warnIfParentRefUnfolded(normalizedPath);
  }
  // A trailing '/' or '/.' is not semantic outside a glob, and the empty
  // string is not the filesystem root: an empty HOME makes expandTilde('~')
  // empty, and '' || '/' would turn `allowWrite: ['~']` into a whole-
  // filesystem grant.
  if (getPlatform() != 'windows' && normalizedPath.isNotEmpty) {
    normalizedPath = normalizedPath.replaceFirst(RegExp(r'/\.$'), '');
    normalizedPath = normalizedPath.replaceFirst(RegExp(r'/+$'), '');
    if (normalizedPath.isEmpty) normalizedPath = '/';
  }
  // Resolve symlinks to real paths to avoid bwrap issues
  // Validate that the resolution stays within expected boundaries
  try {
    final resolvedPath = realPathOf(normalizedPath);
    // A symlink pointing outside the expected boundaries (e.g. to a parent
    // directory) keeps the original path.
    if (!isSymlinkOutsideBoundary(normalizedPath, resolvedPath)) {
      normalizedPath = resolvedPath;
    }
  } catch (_) {
    // Absent, or unreadable: keep the normalized spelling.
  }
  return _warnIfParentRefUnfolded(normalizedPath);
}

// TELOSNEX DEVIATION: Keep the device/stdio exceptions when a command omits
// the shared temp and home convenience directories.
const List<String> SANDBOX_DEVICE_WRITE_PATHS = [
  '/dev/stdout',
  '/dev/stderr',
  '/dev/null',
  '/dev/tty',
  '/dev/dtracehelper',
  '/dev/autofs_nowait',
];

/// What the sandbox itself needs writable: the child's stdio and the TMPDIR it
/// is handed (generateProxyEnvVars). Kept whatever is read-denied.
const List<String> _SANDBOX_OWN_WRITE_PATHS = [
  // TELOSNEX DEVIATION: Reuse the device exceptions in the upstream defaults.
  ...SANDBOX_DEVICE_WRITE_PATHS,
  '/tmp/claude',
  '/private/tmp/claude',
];

/// Directories under the home directory made writable as a convenience the
/// caller never asked for. Every entry is subject to the read-rule check in
/// {@link getDefaultWritePaths}.
const List<String> _HOME_CONVENIENCE_WRITE_DIRS = [
  '.npm/_logs',
  '.claude/debug',
];

/// Get recommended system paths that should be writable for commands to work properly
///
/// WARNING: These default paths are intentionally broad for compatibility but may
/// allow access to files from other processes. In highly security-sensitive
/// environments, you should configure more restrictive write paths.
///
/// With no argument this is the whole list. Given the read rules of a
/// filesystem policy, a home convenience directory (~/.npm/_logs,
/// ~/.claude/debug) is left out when a `denyRead` entry names it or a
/// directory above it: kept, it would be bound back over that deny on Linux
/// (readable and writable again) and stay writable on macOS, so the explicit
/// denyRead wins over the implicit write allow. It is kept when an `allowRead`
/// entry beneath that deny re-opens it, because the caller has already made it
/// readable. A caller who wants it writable regardless lists it in
/// `allowWrite`. What the sandbox itself needs (stdio, /tmp/claude) is never
/// left out.
///
/// Pass the entries as configured, not expanded. `dir/**` counts as `dir`,
/// and a glob covers a directory when it matches that directory or one above
/// it; nothing is listed from disk. On Linux, where the backend expands globs
/// against the disk, two things follow: a glob that matches nothing there
/// still counts (which only ever drops a convenience path), and a glob whose
/// match is a symlink to one of these directories is not seen. A glob
/// `allowRead` entry is not counted as re-opening anything.
///
/// An entry marked `{ path, literal: true }` is a name whatever it holds. A
/// spelling is read by its characters alone: the name it also is when that
/// exists on disk is for the caller to add as a marked entry.
List<String> getDefaultWritePaths({
  List<FilesystemPathEntry>? denyRead,
  List<FilesystemPathEntry>? allowRead,
}) {
  final home = homedir();
  final keptDirs = denyRead == null || denyRead.isEmpty
      ? _HOME_CONVENIENCE_WRITE_DIRS
      : _homeDirsNotReadDenied(home, denyRead, allowRead ?? const []);
  return [
    ..._SANDBOX_OWN_WRITE_PATHS,
    ...keptDirs.map((rel) => path.join(home, rel)),
  ];
}

/// The {@link HOME_CONVENIENCE_WRITE_DIRS} no `denyRead` entry covers, or
/// that an `allowRead` entry beneath the covering deny re-opens.
List<String> _homeDirsNotReadDenied(
  String home,
  List<FilesystemPathEntry> denyRead,
  List<FilesystemPathEntry> allowRead,
) {
  // Rules are compared as normalizePathForSandbox spells them, and on macOS
  // that resolves /tmp and /var to /private/... for a path that exists. A
  // convenience directory may not exist yet, so its second spelling is built
  // from the home directory, which does.
  final homes = <String>{home, normalizePathForSandbox(home, literal: true)};
  final denies = denyRead.map(_readRuleCovers).toList();
  final reopened = allowRead
      .map((entry) {
        if (entry is FilesystemPathLiteral) return markedLiteralPath(entry);
        final spelling = (entry as FilesystemPathSpelling).path;
        final stripped = removeTrailingGlobSuffix(spelling);
        return containsGlobCharsForPlatform(stripped) ? null : stripped;
      })
      .whereType<String>()
      .map((entry) => normalizePathForSandbox(entry, literal: true))
      .toList();
  return _HOME_CONVENIENCE_WRITE_DIRS.where((rel) {
    final spellings = homes.map((home) => path.join(home, rel)).toList();
    return !denies.any(
      (denyCovers) =>
          spellings.any(denyCovers) &&
          !reopened.any(
            (allow) =>
                denyCovers(allow) &&
                spellings.any((s) => isAtOrUnder(s, allow)),
          ),
    );
  }).toList();
}

/// Whether a read rule covers a path: the path is the rule's own or lies
/// beneath it. `dir/**` is `dir`, and a glob covers whatever
/// {@link denyGlobRegex} matches.
///
/// Pattern or name is decided on what the caller wrote, before the spelling
/// is resolved: `*`, `?` and `[…]` there are the syntax it asked for, while
/// resolving splices in a cwd or home directory that may carry those
/// characters in its own name. A spelling without them is normalized as the
/// name it is, and so is an entry marked literal, whatever it holds.
bool Function(String p) _readRuleCovers(FilesystemPathEntry entry) {
  if (entry is FilesystemPathLiteral) {
    final rule = normalizePathForSandbox(
      markedLiteralPath(entry),
      literal: true,
    );
    return (p) => isAtOrUnder(p, rule);
  }
  final spelling = (entry as FilesystemPathSpelling).path;
  final stripped = removeTrailingGlobSuffix(spelling);
  if (containsGlobCharsForPlatform(stripped)) {
    final regex = _compiledDenyGlob(normalizePathForSandbox(stripped));
    // Too large to compile. What it covers cannot be told, so it covers.
    return regex == null ? (_) => true : (p) => regex.hasMatch(p);
  }
  final rule = normalizePathForSandbox(stripped, literal: true);
  return (p) => isAtOrUnder(p, rule);
}

/**
 * {@link denyGlobRegex} compiled, or null for a pattern too large to compile.
 * Kept by the normalized pattern, which is all it depends on: these rules are
 * read for a getter that callers ask once a path. What is asked of the disk
 * on the way to the normalized pattern is asked every time.
 */
RegExp? _compiledDenyGlob(String normalizedGlob) {
  var regex = _compiledDenyGlobs[normalizedGlob];
  if (!_compiledDenyGlobs.containsKey(normalizedGlob)) {
    _denyGlobCompiles++;
    try {
      regex = RegExp(denyGlobRegex(normalizedGlob));
      // V8 finds a pattern too large only when it first runs it.
      regex.hasMatch('');
    } catch (_) {
      regex = null;
    }
    _compiledDenyGlobChars += normalizedGlob.length;
    if (_compiledDenyGlobChars > _MAX_COMPILED_DENY_GLOB_CHARS) {
      _compiledDenyGlobs.clear();
      _compiledDenyGlobChars = normalizedGlob.length;
    }
    _compiledDenyGlobs[normalizedGlob] = regex;
  }
  return regex;
}

final _compiledDenyGlobs = <String, RegExp?>{};
var _compiledDenyGlobChars = 0;
var _denyGlobCompiles = 0;
/** Past this much pattern text all that is kept is let go, to begin again. */
const _MAX_COMPILED_DENY_GLOB_CHARS = 1 << 20;

/// Dart: how many read-rule globs {@link _compiledDenyGlob} has compiled.
/// Tests check that a rule is compiled once without timing it.
int get denyGlobCompilesForTesting => _denyGlobCompiles;

/**
 * Generate proxy environment variables for sandboxed processes
 */
/// Per-tool trust-store env vars set to the TLS-termination CA cert path so
/// HTTPS clients in the sandboxed child accept proxy-minted certs.
const List<String> CA_TRUST_VARS = [
  'NODE_EXTRA_CA_CERTS',
  'SSL_CERT_FILE',
  'CURL_CA_BUNDLE',
  'REQUESTS_CA_BUNDLE',
  'PIP_CERT',
  'GIT_SSL_CAINFO',
  'AWS_CA_BUNDLE',
  'CARGO_HTTP_CAINFO',
  'DENO_CERT',
  // gcloud ignores SSL_CERT_FILE/REQUESTS_CA_BUNDLE; this is its dedicated
  // override (maps to core/custom_ca_certs_file).
  'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE',
  // Nix-built binaries are patched to read this instead of SSL_CERT_FILE, and
  // it's typically pre-set to the Nix system bundle in the parent env, so we
  // must override it explicitly.
  'NIX_SSL_CERT_FILE',
];

List<String> generateProxyEnvVars([
  int? httpProxyPort,
  int? socksProxyPort,
  String? caCertPath,
  String? proxyAuthToken,
  bool? skipTmpdir,
  String? encodedCommand,
]) {
  // When the proxy requires auth, embed the credential in the URL so clients
  // send Proxy-Authorization automatically. Only the sandbox child sees this
  // env, so the token never reaches host processes.
  //
  // The username carries the per-command encodedCommand so the proxy can
  // attribute denials to a specific invocation (see
  // SandboxViolationStore). Standard base64 is percent-encoded in the URL so
  // `+/=` survive userinfo parsing; clients URL-decode before building the
  // Basic header / RFC 1929 frame, so the proxy receives the raw base64.
  final userRaw = proxyUsernameFor(encodedCommand);
  final userPct = userRaw == PROXY_AUTH_USER
      ? userRaw
      : Uri.encodeComponent(userRaw);
  final auth = proxyAuthToken != null && proxyAuthToken.isNotEmpty
      ? '$userPct:$proxyAuthToken@'
      : '';
  final envVars = <String>['SANDBOX_RUNTIME=1'];
  // TMPDIR is overridden so temp-file writers land in a path the FS sandbox
  // allows (getDefaultWritePaths). When filesystem policy is disabled
  // (writeConfig === undefined → skipTmpdir), the host TMPDIR is already
  // writable and /tmp/claude may not exist, so leave it untouched.
  // CLAUDE_CODE_TMPDIR is the current name; CLAUDE_TMPDIR is kept for
  // backwards compatibility (#141).
  if (skipTmpdir != true) {
    final currentTmpdir = process.env['CLAUDE_CODE_TMPDIR'] ?? '';
    final legacyTmpdir = process.env['CLAUDE_TMPDIR'] ?? '';
    final tmpdir = currentTmpdir.isNotEmpty
        ? currentTmpdir
        : legacyTmpdir.isNotEmpty
        ? legacyTmpdir
        : '/tmp/claude';
    envVars.add('TMPDIR=$tmpdir');
  }
  // When TLS termination is configured, the child only ever sees proxy-minted
  // certs signed by the configured CA. Point the common per-tool trust-store
  // env vars at it so HTTPS clients accept those certs.
  if (caCertPath != null && caCertPath.isNotEmpty) {
    for (final variable in CA_TRUST_VARS) {
      envVars.add('$variable=$caCertPath');
    }
  }
  // If no proxy ports provided, return minimal env vars
  if ((httpProxyPort == null || httpProxyPort == 0) &&
      (socksProxyPort == null || socksProxyPort == 0))
    return envVars;

  // Always set NO_PROXY to exclude localhost and private networks from
  // proxying. *.local is intentionally absent: under network restriction the
  // child has no usable resolver/routes (bwrap --unshare-net on Linux,
  // loopback-only under seatbelt), so a NO_PROXY match makes the client try
  // direct getaddrinfo() and fail. Routing .local hostnames through the proxy
  // lets the parent resolve them (e.g. Kubernetes *.svc.cluster.local).
  final noProxyAddresses = <String>[
    'localhost',
    '127.0.0.1',
    '::1',
    '169.254.0.0/16', // Link-local
    '10.0.0.0/8', // Private network
    '172.16.0.0/12', // Private network
    '192.168.0.0/16', // Private network
  ].join(',');
  envVars.add('NO_PROXY=$noProxyAddresses');
  envVars.add('no_proxy=$noProxyAddresses');
  if (httpProxyPort != null && httpProxyPort != 0) {
    final proxyUrl = 'http://${auth}localhost:$httpProxyPort';
    envVars.add('HTTP_PROXY=$proxyUrl');
    envVars.add('HTTPS_PROXY=$proxyUrl');
    // Lowercase versions for compatibility with some tools
    envVars.add('http_proxy=$proxyUrl');
    envVars.add('https_proxy=$proxyUrl');
    if (proxyAuthToken != null && proxyAuthToken.isNotEmpty) {
      // Pre-send Basic so git never gets a 407 and never invokes a
      // credential helper for the proxy URL (Windows GCM intercepts the
      // challenge and the URL-embedded password doesn't survive it).
      envVars.add("GIT_CONFIG_PARAMETERS='http.proxyAuthMethod=basic'");
    }
  }
  // The URL to advertise to clients that need a general-purpose,
  // CONNECT-capable proxy. The mux serves HTTP CONNECT and SOCKS on the same
  // advertised port, so http:// works for everyone: clients that only speak
  // CONNECT get a URL they understand, and anything that actually speaks
  // SOCKS to it still reaches the SOCKS handler. Falls back to socks5h://
  // only when no HTTP proxy port exists, which no current caller configures.
  final connectProxyUrl = httpProxyPort != null && httpProxyPort != 0
      ? 'http://${auth}localhost:$httpProxyPort'
      : 'socks5h://${auth}localhost:$socksProxyPort';
  envVars.add('ALL_PROXY=$connectProxyUrl');
  envVars.add('all_proxy=$connectProxyUrl');
  // ALL_PROXY: prefer the HTTP proxy URL over SOCKS. httpx (and similar
  // Python clients) eagerly import `socksio` at client construction when
  // ALL_PROXY is a socks5h:// URL and crash with ImportError in envs that
  // lack the package — before any bytes hit the wire, so the mux's
  // protocol sniffing can't help.
  //
  // gRPC-based tools. gRPC C-core (every google-cloud-* Python client, and
  // grpc-js) only understands HTTP CONNECT proxies. Given a socks5h:// URL it
  // logs "'socks5h' scheme not supported in proxy URI", ignores the var, and
  // resolves the target directly via c-ares — which the sandbox blocks, so
  // the client dies with "address lookup failed / Could not contact DNS
  // servers" instead of falling back to https_proxy. Not gated on
  // socksProxyPort: the value no longer depends on it, and a gRPC client in
  // an HTTP-only sandbox needs this var just as much.
  envVars.add('GRPC_PROXY=$connectProxyUrl');
  envVars.add('grpc_proxy=$connectProxyUrl');
  if (socksProxyPort != null && socksProxyPort != 0) {
    // Configure Git to use SSH through the proxy so DNS resolution happens outside the sandbox.
    // ControlMaster/ControlPath are disabled because SSH connection multiplexing breaks inside
    // the sandbox: the mux socket path from the user's ssh config (typically under ~/.ssh) is
    // not an allowed Unix socket path, and OpenSSH treats a mux listener bind failure as fatal
    // even with ControlMaster=auto — it exits right after authentication, before running the
    // git command. Command-line options take precedence over ssh_config, so this neutralizes
    // any user ControlMaster setup. ControlPath=none is needed in addition to ControlMaster=no:
    // with ControlMaster=no alone, ssh still tries to connect to an existing mux socket at the
    // configured ControlPath.
    const sshMuxOverride = '-o ControlMaster=no -o ControlPath=none';
    final platform = getPlatform();
    if (platform == 'macos' &&
        proxyAuthToken != null &&
        proxyAuthToken.isNotEmpty &&
        httpProxyPort == socksProxyPort) {
      // macOS, and the SOCKS listener is the library's own, which serves both
      // protocols on one port and wants the token: BSD nc has no SOCKS
      // authentication to give it, and is refused. So an HTTP CONNECT with
      // the credential, as on Linux, from what macOS ships. The script
      // travels in a variable of its own: that keeps the token out of the
      // arguments of ssh and of what it starts, and the script out of git's
      // `sh -c`, ssh's % expansion and `$SHELL -c` (the user's shell, be it
      // fish or tcsh), which see plain and single-quoted words only.
      final basic = Buffer.from('$userRaw:$proxyAuthToken').toString('base64');
      envVars.addAll([
        'SRT_SSH_PROXY_COMMAND=${sshConnectScript(socksProxyPort, basic)}',
        "GIT_SSH_COMMAND=ssh $sshMuxOverride -o ProxyCommand=\"/bin/sh -c '"
            r'''eval \"\${SRT_SSH_PROXY_COMMAND:?unset, but GIT_SSH_COMMAND needs it}\"' sh '%h' %p"''',
      ]);
    } else if (platform == 'macos') {
      // A SOCKS listener that wants no token of ours, an external one
      // included: BSD nc's SOCKS5 support (-X 5 -x).
      envVars.add(
        "GIT_SSH_COMMAND=ssh $sshMuxOverride -o ProxyCommand='nc -X 5 -x "
        "localhost:$socksProxyPort %h %p'",
      );
    } else if (platform == 'linux' && httpProxyPort != null) {
      // Linux: use socat HTTP CONNECT via the HTTP proxy bridge.
      // socat is already a required Linux sandbox dependency, and PROXY: is
      // portable across all socat versions (unlike SOCKS5-CONNECT which needs >= 1.8.0).
      final socatAuth = proxyAuthToken != null && proxyAuthToken.isNotEmpty
          ? ',proxyauth=$userRaw:$proxyAuthToken'
          : '';
      envVars.add(
        "GIT_SSH_COMMAND=ssh $sshMuxOverride -o ProxyCommand='socat - "
        "PROXY:localhost:%h:%p,proxyport=$httpProxyPort$socatAuth'",
      );
    }
    // FTP proxy support (use socks5h for DNS resolution through proxy).
    // Deliberately not connectProxyUrl: given an http:// ftp_proxy, curl does
    // not CONNECT-tunnel by default, it gateways the transfer as
    // `GET ftp://host/path HTTP/1.1` to the proxy — which the mux does not
    // implement, and an env var can't ask curl for --proxytunnel. socks5h is
    // transparent at the TCP layer, so it is the value that works here.
    envVars.add('FTP_PROXY=socks5h://${auth}localhost:$socksProxyPort');
    envVars.add('ftp_proxy=socks5h://${auth}localhost:$socksProxyPort');
    // rsync proxy support — RSYNC_PROXY is host:port only, no userinfo. With
    // proxy auth on, rsync via this var fails at the CONNECT (407); use SSH
    // transport or wrap with proxychains instead.
    envVars.add('RSYNC_PROXY=localhost:$socksProxyPort');
    // Database tools NOTE: Most database clients don't have built-in proxy support
    // You typically need to use SSH tunneling or a SOCKS wrapper like tsocks/proxychains

    // Docker CLI uses HTTP for the API
    // This makes Docker use the HTTP proxy for registry operations
    final dockerPort = httpProxyPort != null && httpProxyPort != 0
        ? httpProxyPort
        : socksProxyPort;
    envVars.add('DOCKER_HTTP_PROXY=http://${auth}localhost:$dockerPort');
    envVars.add('DOCKER_HTTPS_PROXY=http://${auth}localhost:$dockerPort');
    // Google Cloud SDK - has specific proxy settings.
    // proxy/type names the protocol the *proxy* speaks, not the traffic it
    // tunnels. Our HTTP CONNECT proxy carries TLS to Google APIs, so the
    // correct value is "http" (gcloud only accepts http, http_no_tunnel,
    // socks4, socks5; "https" is rejected at startup).
    if (httpProxyPort != null && httpProxyPort != 0) {
      envVars.addAll([
        'CLOUDSDK_PROXY_TYPE=http',
        'CLOUDSDK_PROXY_ADDRESS=localhost',
        'CLOUDSDK_PROXY_PORT=$httpProxyPort',
      ]);
      if (proxyAuthToken != null && proxyAuthToken.isNotEmpty) {
        envVars.add('CLOUDSDK_PROXY_USERNAME=$userRaw');
        envVars.add('CLOUDSDK_PROXY_PASSWORD=$proxyAuthToken');
      }
    }
    // kubectl, the AWS CLI, the Azure CLI, Terraform and gRPC read the
    // standard vars already emitted; nothing tool-specific is needed.
  }
  // Do not set HTTP_PROXY/HTTPS_PROXY to SOCKS URLs in the SOCKS-only path:
  // most HTTP clients reject socks*:// in those vars. ALL_PROXY (above)
  // already carries the route for clients that read it.
  return envVars;
}

/// A POSIX sh script for an ssh ProxyCommand (`$1` host, `$2` port): an HTTP
/// CONNECT through the proxy on 127.0.0.1:`proxyPort` with the Basic
/// credential `basic`, then stdin and stdout relayed by `nc`.
///
/// The host comes from a git URL, which a repository chooses. It is never
/// script text or printf's format, and one that could end the request line is
/// refused before anything is sent.
///
/// The response head is read here, so a refusal is one line on stderr, with
/// the status line's own words. The pipeline runs in the background (hence
/// stdin as fd 3) so that this shell can close its own copy of stdout: held,
/// it would keep an end of file from ssh.
///
/// `nc` is the one macOS ships, by path: it leaves when the network side
/// ends, which is how ssh learns of it. Current OpenBSD and Debian ones stay
/// until their stdin ends too, and ssh would wait.
String sshConnectScript(
  int proxyPort,
  String basic, [
  String nc = '/usr/bin/nc',
]) =>
    'LC_ALL=C; no() { printf "sandbox proxy: %s\\n" "\$*" >&2; exit 1; }; '
    'case \$1 in ""|*[!A-Za-z0-9._:-]*) no bad host;; *:*) set -- "[\$1]" "\$2";; esac; '
    'case \$2 in ""|*[!0-9]*) no bad port;; esac; '
    'exec 3<&0; '
    '{ printf "CONNECT %s HTTP/1.1\\r\\nHost: %s\\r\\nProxy-Authorization: Basic $basic\\r\\n\\r\\n" "\$1:\$2" "\$1:\$2"; exec /bin/cat <&3; } | '
    '$nc 127.0.0.1 $proxyPort | '
    '{ read -r v why; while read -r v; do case \$v in ""|?) break;; esac; done; '
    'case \$why in "200 "*) exec /bin/cat;; esac; '
    'why=\${why%?}; no "\$1:\$2: \${why:-no answer}"; } & '
    'exec >&-; wait \$!';

/// `safe.directory` entries above this count collapse to a single
/// `safe.directory=*`. Keeps `GIT_CONFIG_COUNT` (and the argv it rides
/// on) bounded when the safe-dir set is wide.
const int _SAFE_DIRECTORY_WILDCARD_THRESHOLD = 8;

/// Build the `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_<n>` /
/// `GIT_CONFIG_VALUE_<n>` env-var set for the sandboxed child.
///
/// Emits:
///   - `safe.directory=<dir>` for each entry in `safeDirs` (or one
///     `safe.directory=*` when the list is long) — inside the sandbox
///     the working tree is owned by a different user (Windows: the
///     real user vs `srt-sandbox`; Linux: unmapped uid under
///     `bwrap --unshare-user`), so git refuses with "detected dubious
///     ownership" without it.
///   - `http.schannelUseSSLCAInfo=true` and
///     `http.schannelCheckRevoke=false` when `schannelCa` (Windows
///     only) — makes git's schannel backend honor `GIT_SSL_CAINFO`
///     without `-c http.sslBackend=openssl`. Revocation is disabled
///     because CryptoAPI CRL/OCSP fetches ignore proxy env and would
///     be WFP-fenced.
///   - `http.sslBackend=openssl` when `opensslBackend` — for a child
///     whose token Schannel refuses (the write-restricted token).
///
/// Composes with an existing `GIT_CONFIG_COUNT` in `baseEnv` by
/// continuing its numbering; the returned `GIT_CONFIG_COUNT` is the
/// new total. `baseEnv` should reflect what the child will actually
/// see: on Windows the two-hop launch means the broker's own
/// `process.env` never reaches the child, so `baseEnv` is the caller
/// overlay (`WindowsSandboxParams.setEnvVars`); on Linux/macOS the
/// child inherits `process.env`, so callers use
/// {@link buildPosixGitSafeDirEnv} (which folds in `process.env`,
/// `unsetEnvVars`, and `setEnvVars`).
///
/// Paths are emitted with forward slashes so the value survives
/// msys2's env conversion untouched and native git accepts it (a
/// no-op on POSIX paths).
Map<String, String> buildGitConfigEnv({
  required List<String> safeDirs,

  /// Windows-only schannel knobs; default false.
  bool schannelCa = false,

  /// Windows-only: select git's OpenSSL TLS backend; default false.
  bool opensslBackend = false,
  Map<String, String?>? baseEnv,
}) {
  // An explicit `GIT_CONFIG_COUNT=0` in baseEnv is an opt-out ("no
  // env-level git config") — respect it rather than overwriting.
  if (baseEnv?['GIT_CONFIG_COUNT'] == '0') return {};
  final rawCount = baseEnv?['GIT_CONFIG_COUNT'] ?? '';
  final parsed =
      int.tryParse(
        RegExp(r'^\s*([+-]?\d+)').firstMatch(rawCount)?.group(1) ?? '',
      ) ??
      0;
  final start = parsed >= 0 ? parsed : 0;
  var n = start;
  final out = <String, String>{};
  void emit(String key, String value) {
    out['GIT_CONFIG_KEY_$n'] = key;
    out['GIT_CONFIG_VALUE_$n'] = value;
    n++;
  }

  final dirs = <String>{};
  for (final directory in safeDirs) {
    if (directory.isEmpty) continue;
    final fwd = directory.replaceAll('\\', '/');
    final stripped = fwd.replaceFirst(RegExp(r'/+$'), '');
    // Don't strip the trailing slash off a bare root: `C:`
    // is drive-relative-cwd (git wants `C:/`), and `` is
    // git's list-reset sentinel for safe.directory (would
    // wipe preceding entries) — POSIX `/` must stay `/`.
    if (stripped.isEmpty || RegExp(r'^[A-Za-z]:$').hasMatch(stripped)) {
      dirs.add('$stripped/');
    } else {
      dirs.add(stripped);
    }
  }
  if (dirs.length > _SAFE_DIRECTORY_WILDCARD_THRESHOLD) {
    emit('safe.directory', '*');
  } else {
    // git matches safe.directory against the REPO TOP-LEVEL exactly,
    // so a workspace root doesn't cover a nested repo. Emit both the
    // exact path and the `<dir>/*` glob (git ≥2.46) so any repo
    // at-or-under a granted dir is trusted. Roots keep their trailing
    // `/`; don't double it in the glob (`//*` never wildmatches).
    for (final directory in dirs) {
      emit('safe.directory', directory);
      emit(
        'safe.directory',
        directory.endsWith('/') ? '$directory*' : '$directory/*',
      );
    }
  }
  if (schannelCa) {
    emit('http.schannelUseSSLCAInfo', 'true');
    emit('http.schannelCheckRevoke', 'false');
  }
  if (opensslBackend) {
    emit('http.sslBackend', 'openssl');
  }
  if (n == start) return {};
  out['GIT_CONFIG_COUNT'] = '$n';
  return out;
}

/// POSIX-side wrapper over {@link buildGitConfigEnv} that constructs
/// the correct `baseEnv` for a Linux/macOS sandbox: the child inherits
/// `process.env` under bwrap/sandbox-exec, then `unsetEnvVars` are
/// dropped and `setEnvVars` overlaid — so numbering must continue from
/// whatever `GIT_CONFIG_COUNT` survives that. Shared by
/// `wrapCommandWithSandbox{Linux,MacOS}`.
Map<String, String> buildPosixGitSafeDirEnv({
  required List<String> safeDirs,
  List<String> unsetEnvVars = const [],
  Map<String, String> setEnvVars = const {},
}) {
  final baseEnv = <String, String?>{
    'GIT_CONFIG_COUNT': process.env['GIT_CONFIG_COUNT'],
  };
  for (final key in unsetEnvVars) {
    baseEnv.remove(key);
  }
  baseEnv.addAll(setEnvVars);
  return buildGitConfigEnv(safeDirs: safeDirs, baseEnv: baseEnv);
}

/// How much of an attribution key rides the carriers. A key is cut to this
/// many characters before encoding, so two commands that share this much of
/// a prefix share a key.
const int SANDBOXED_COMMAND_KEY_LENGTH = 100;

/// The attribution key for an invocation: the caller's `commandId`, or the
/// command itself when there is no usable id.
String attributionKeyFor(String command, String? commandId) {
  // Falsy, not `=== undefined`: every carrier drops an empty attribution, and
  // a JavaScript caller's `null` would throw in encodeSandboxedCommand.
  return commandId == null || commandId.isEmpty ? command : commandId;
}

/// Encode a command for sandbox monitoring
/// Truncates to SANDBOXED_COMMAND_KEY_LENGTH chars and base64 encodes to
/// avoid parsing issues
String encodeSandboxedCommand(String command) => Buffer.from(
  command.substring(
    0,
    command.length < SANDBOXED_COMMAND_KEY_LENGTH
        ? command.length
        : SANDBOXED_COMMAND_KEY_LENGTH,
  ),
).toString('base64');

/// Decode a base64-encoded command from sandbox monitoring
String decodeSandboxedCommand(String encodedCommand) =>
    Buffer.from(encodedCommand, 'base64').toString('utf8');

/// Base proxy username; the auth token is the credential, this is a label.
const String PROXY_AUTH_USER = 'srt';

/// RFC 1929 caps a SOCKS5 username at 255 bytes.
const int _MAX_PROXY_USERNAME_BYTES = 255;

/// The longest encodedCommand a carrier this process mints can hold: what is
/// left of the username budget after `srt.`. Every carrier is bounded far more
/// loosely than that (an HTTP proxy header budget is kilobytes), so a longer
/// attribution field was not minted here and is stored by nobody.
const int MAX_ENCODED_COMMAND_BYTES = _MAX_PROXY_USERNAME_BYTES - 4;

/// Build the proxy username for a sandboxed command: `srt.<encodedCommand>`
/// so the proxy can attribute a denial to the invocation that triggered it,
/// or bare `srt` when there is nothing to attribute. A multibyte command whose
/// 100-code-unit truncation still base64s past the username budget would fail
/// the SOCKS handshake, so fall back to bare `srt` (attribution is lost,
/// connectivity is not).
String proxyUsernameFor(String? encodedCommand) {
  if (encodedCommand == null || encodedCommand.isEmpty) return PROXY_AUTH_USER;
  final user = '$PROXY_AUTH_USER.$encodedCommand';
  return Buffer.byteLength(user) <= _MAX_PROXY_USERNAME_BYTES
      ? user
      : PROXY_AUTH_USER;
}

/// Inverse of {@link proxyUsernameFor}: extract the encodedCommand suffix
/// from `srt.<encodedCommand>`, or undefined for bare `srt` / anything else.
/// The username is presented by the client inside the sandbox. A forged
/// suffix cannot authenticate (the token does that), but it decides which
/// invocation a denial is attributed to in the violation report and which
/// registered network allow list applies to the connection: see
/// `SandboxManager.registerCommandNetworkLists` for what that asks of an id. A
/// suffix past {@link MAX_ENCODED_COMMAND_BYTES} is longer than this process
/// can mint, so it is dropped rather than stored: the denial is still
/// recorded, unattributed, and no registered list applies.
String? encodedCommandFromProxyUser(String? username) {
  if (username == null || !username.startsWith('$PROXY_AUTH_USER.'))
    return null;
  final suffix = username.substring(PROXY_AUTH_USER.length + 1);
  if (suffix.isEmpty || Buffer.byteLength(suffix) > MAX_ENCODED_COMMAND_BYTES) {
    return null;
  }
  return suffix;
}

class ExpandGlobOptions {
  const ExpandGlobOptions({this.caseInsensitive = false, this.anchor});

  /// Match case-insensitively. Set this on Windows where the
  /// pattern's static prefix may differ in case from what
  /// `readdirSync` returns. Default: false (Linux/macOS callers
  /// don't need it).
  final bool caseInsensitive;

  /// A directory the pattern is walked beneath, taken as the name it is: a
  /// leading run of `globPath` that exists on disk and may itself hold `[`,
  /// `*` or `?`. Only what follows it is pattern. The glob dialect has no
  /// escape, so this is the one way to say where such a name ends. A
  /// `TypeError` is thrown for one that is empty or the root, or that
  /// `globPath` does not start with, up to a separator.
  final String? anchor;
}

/// What the walk reads of a listed entry.
class _GlobWalkEntry {
  const _GlobWalkEntry({
    required this.name,
    required this.isDirectory,
    required this.isSymbolicLink,
  });
  final String name;
  final bool Function() isDirectory;
  final bool Function() isSymbolicLink;
}

/// What listing a real directory gave, its entries with their types or the
///  error that has it denied whole: a second position, or a second pattern,
///  reads the same answer.
typedef GlobWalkListings = Map<String, Object>;

class GlobWalkOptions extends ExpandGlobOptions {
  const GlobWalkOptions({
    super.caseInsensitive = false,
    super.anchor,
    this.withDirectoryForm = false,
    this.followSymlinkedDirectories = false,
    this.listings,
  });
  final bool withDirectoryForm;
  final bool followSymlinkedDirectories;

  /// Handed to every walk of one configuration, so that patterns with a
  /// base in common list each directory once between them.
  final GlobWalkListings? listings;
}

/// Work that can be left between two steps and taken up again.
typedef Steps<T> = Iterable<Step<T>>;

/// Runs `steps` to the end, on the spot.
T finish<T>(Steps<T> steps) {
  for (final step in steps) {
    switch (step) {
      case Pause<T>():
        break;
      case Done<T>(:final value):
        return value;
    }
  }
  throw StateError('Steps ended without Done');
}

/// How long {@link finishInTurns} works before it lets others have a turn.
const int _TURN_MS = 10;

/// Runs `steps` to the end, letting the event loop have a turn every
/// {@link TURN_MS}: a walk of a large tree takes seconds, and a caller whose
/// thread is held that long can neither draw nor hear that it should stop.
/// Rejects with `signal`'s reason once that is aborted, however far it got.
Future<T> finishInTurns<T>(Steps<T> steps, [AbortSignal? signal]) async {
  void throwIfAborted() {
    if (signal?.aborted == true) throw signal!.reason ?? AbortError();
  }

  throwIfAborted();
  final iterator = steps.iterator;
  final stopwatch = Stopwatch()..start();
  for (;;) {
    if (!iterator.moveNext()) throw StateError('Steps ended without Done');
    final step = iterator.current;
    if (step case Done<T>(:final value)) {
      throwIfAborted();
      return value;
    }
    if (stopwatch.elapsedMilliseconds >= _TURN_MS) {
      await Future<void>.delayed(Duration.zero);
      throwIfAborted();
      stopwatch
        ..reset()
        ..start();
    }
  }
}

/// What one recursive walk of a glob's base directory found; see {@link walkGlobPattern}.
class GlobWalk {
  /// Where the walk started, with symlinks resolved (the spelling itself
  ///  when it could not be resolved); '' when the pattern had no literal
  ///  directory to start from.
  String baseLocation = '';

  /// Absolute paths matching the pattern, as spelled from the pattern's base.
  ///  One found by listing through a symlinked directory is reported where it
  ///  really lives instead.
  final List<String> matches = [];

  /// With `withDirectoryForm`: directories (a symlink to one included)
  ///  matching the pattern without its trailing `/**`.
  final List<String> directoryMatches = [];

  /// Every visited entry that is a symbolic link, by full path.
  final Set<String> symlinks = {};

  /// Symbolic links whose target is there but could not be looked at, so
  ///  `realOf` has no entry for them. Unreadable now is not absent: a deny
  ///  expansion must cover such a link rather than drop it.
  final Set<String> uninspectableLinks = {};

  /// Directories the walk could not list (any error but absence) under a
  ///  name it reached them by, each named once, and entries that may be one
  ///  for all it could learn. What the pattern matches beneath one can be
  ///  missing from `matches`; a deny expansion must cover them whole.
  final List<String> unlisted = [];

  /// Where an entry of `matches`, `directoryMatches` or `unlisted` really
  ///  lives, for each one that is a symlink or is spelled through one above
  ///  the walk. A symlink that does not resolve has no entry, and neither has
  ///  what was found through a symlinked directory, which is reported where
  ///  it really lives to begin with.
  final Map<String, String> realOf = {};
}

/// Expand a glob pattern into the concrete paths matching it.
///
/// Used on Linux (where bubblewrap doesn't support glob patterns
/// natively) and Windows (point-in-time expansion before `srt-win
/// acl stamp`). A symlink is a match in its own right and is not
/// descended into; {@link walkGlobPattern} is the read-deny expansion's
/// richer view of the same walk.
///
/// @param globPath - A path pattern containing glob characters (e.g., ~/test/*.env)
/// @returns Array of absolute paths matching the glob pattern
List<String> expandGlobPattern(
  String globPath, {
  bool caseInsensitive = false,
  String? anchor,
}) => walkGlobPattern(
  globPath,
  caseInsensitive: caseInsensitive,
  anchor: anchor,
).matches;

/// A pattern as an automaton that takes a path one name at a time, which is
/// how a walk meets it. A position is a state of it: a place in the pattern
/// where a path component can start.
///
/// What the pattern matches beneath a directory depends on the directory's
/// spelling only through the positions that spelling leads to, so the walk
/// lists a real directory once per position however many names lead to it,
/// and lists no directory that has none (`proj/*.pem` lists `proj` alone).
/// Beneath `**/.env` every spelling has the same positions; beneath
/// `**/secrets/*.pem` a directory named `secrets` has one more.
///
/// {@link globToRegex} lets two things span a path separator, and each is a
/// choice between two readings that do not:
///
/// - a `**` written against other text: `X**Y` is `X*Y`, or `X*` / `**` / `*Y`;
///   and `X**` before a separator is `X` run into what follows, or
///   `X*` / `**` / what follows;
/// - a bracket expression that can match `/`, such as `[+-9]`: the expression
///   without the `/`, or a separator.
///
/// A choice is a branch from the position it is met at, and the readings
/// after it are shared, so the automaton grows with the pattern's length and
/// not with the number of combinations.
///
/// `splits` is false for a pattern this cannot be done for: one of thousands
/// of components, more than a path has. Its positions say nothing, so every
/// directory is listed, an entry is matched by its whole spelling, and
/// [walkGlobPattern] does not list such a pattern through symlinks.
class _GlobPositions {
  const _GlobPositions({
    required this.splits,
    required this.start,
    required this.next,
    required this.matches,
    required this.matchesDirectoryForm,
  });
  final bool splits;

  /// The positions beneath the root directory.
  final List<int> start;
  final List<int> Function(List<int>, String) next;

  /// Whether the entry `name` of a directory with `positions` matches the
  ///  pattern. Decided from the positions and the name alone, so the walk
  ///  never matches anything against a spelling, which grows with every link
  ///  it goes through. Only a pattern that does not split reads `spelled`,
  ///  the entry's whole path, and that one is not listed through links.
  final bool Function(List<int>, String, String) matches;

  /// The same for the pattern without its trailing `/**`; never true for a
  ///  pattern that has none.
  final bool Function(List<int>, String, String) matchesDirectoryForm;
}

RegExp _globRegExp(String source, String flags) => RegExp(
  source,
  caseSensitive: !flags.contains('i'),
  dotAll: flags.contains('s'),
);

_GlobPositions _globPositions(String normalizedPattern, String flags) {
  final regex = _globRegExp(globToRegex(normalizedPattern), flags);
  final directoryForm = removeTrailingGlobSuffix(normalizedPattern);
  final directoryRegex = directoryForm != normalizedPattern
      ? _globRegExp(globToRegex(directoryForm), flags)
      : null;
  final unsplit = _GlobPositions(
    splits: false,
    start: const [0],
    next: (_, __) => const [0],
    matches: (_, __, spelled) => regex.hasMatch(spelled),
    matchesDirectoryForm: (_, __, spelled) =>
        directoryRegex?.hasMatch(spelled) == true,
  );
  // A `**`: any name leaves it where it is, and what follows it (`then`) can
  // start at once. With nothing after it, every name beneath it matches.
  // A component: one name, matched by one of these. `to` is the position
  // after it, undefined where the pattern ends, which is a match.
  final states = <Object>[];
  final star = globTokenToRegex(const GlobTokenSimple(GlobTokenKind.Star));

  /// The automaton of one pattern, as the position it starts at.
  int build(List<GlobToken> pieces) {
    final sources = pieces.map(globTokenToRegex).toList();
    final memo = <String, int>{};
    int globstar(int? then) {
      states.add(_Globstar(then));
      return states.length - 1;
    }

    /// The position of a component that starts at `pieces[i]`, after a
    /// `[^/]*` when `lead`.
    int componentAt(int i, bool lead) {
      final key = '$i${lead ? '*' : ''}';
      final known = memo[key];
      if (known != null) return known;
      if (!lead &&
          i < pieces.length &&
          pieces[i].kind == GlobTokenKind.GlobstarSlash) {
        final id = globstar(null);
        memo[key] = id;
        (states[id] as _Globstar).then = componentAt(i + 1, false);
        return id;
      }
      if (!lead &&
          i == pieces.length - 1 &&
          pieces[i].kind == GlobTokenKind.Globstar) {
        final id = globstar(null);
        memo[key] = id;
        return id;
      }
      final component = _GlobComponent();
      states.add(component);
      final id = states.length - 1;
      memo[key] = id;
      void endsWith(String source, int? to) =>
          component.edges.add(_GlobEdge(_globRegExp('^$source\$', flags), to));
      var source = lead ? star : '';
      for (var j = i; ; j++) {
        final piece = j < pieces.length ? pieces[j] : null;
        if (piece == null) {
          endsWith(source, null);
          break;
        }
        if (piece.kind == GlobTokenKind.Separator) {
          endsWith(source, componentAt(j + 1, false));
          break;
        }
        if (piece.kind == GlobTokenKind.Globstar) {
          // Spanning separators: `X*` / `**` / `*Y`. Or not: `X*Y`.
          endsWith('$source$star', globstar(componentAt(j + 1, true)));
          source += star;
        } else if (piece.kind == GlobTokenKind.GlobstarSlash) {
          // Spanning: `X*` / `**` / what follows. Or X run into it.
          endsWith('$source$star', globstar(componentAt(j + 1, false)));
        } else if (piece is GlobTokenSet && piece.matchesSeparator) {
          endsWith(source, componentAt(j + 1, false));
          source += '(?!/)${sources[j]}';
        } else {
          source += sources[j];
        }
      }
      return id;
    }

    return componentAt(0, false);
  }

  late List<int> starts;
  late int firstOfDirectoryForm;
  try {
    starts = [build(parseGlob(normalizedPattern))];
    firstOfDirectoryForm = states.length;
    if (directoryRegex != null) starts.add(build(parseGlob(directoryForm)));
  } catch (_) {
    // More components than the build can nest.
    return unsplit;
  }
  void open(Set<int> into, int? position) {
    var p = position;
    while (p != null && !into.contains(p)) {
      into.add(p);
      final state = states[p];
      p = state is _Globstar ? state.then : null;
    }
  }

  List<int> sorted(Set<int> positions) => positions.toList()..sort();
  bool endsAt(List<int> positions, String name, bool directory) =>
      positions.any((p) {
        if ((p >= firstOfDirectoryForm) != directory) return false;
        final state = states[p];
        return state is _Globstar
            ? state.then == null
            : (state as _GlobComponent).edges.any(
                (edge) => edge.to == null && edge.regex.hasMatch(name),
              );
      });
  final start = <int>{};
  for (final position in starts) {
    open(start, position);
  }
  return _GlobPositions(
    splits: true,
    start: sorted(start),
    next: (positions, name) {
      final next = <int>{};
      for (final position in positions) {
        final state = states[position];
        if (state is _Globstar) {
          open(next, position);
        } else {
          for (final edge in (state as _GlobComponent).edges) {
            if (edge.to != null && edge.regex.hasMatch(name))
              open(next, edge.to);
          }
        }
      }
      return sorted(next);
    },
    matches: (positions, name, _) => endsAt(positions, name, false),
    matchesDirectoryForm: (positions, name, _) => endsAt(positions, name, true),
  );
}

class _Globstar {
  _Globstar(this.then);
  int? then;
}

class _GlobComponent {
  final List<_GlobEdge> edges = [];
}

class _GlobEdge {
  const _GlobEdge(this.regex, this.to);
  final RegExp regex;
  final int? to;
}

/// The literal directory a glob's walk starts from: the static prefix before
/// the pattern's first glob character, without its last path component when
/// that component is not a directory of its own. Split at its separators it
/// is the pattern's own leading components, the empty one of a doubled
/// separator ('C:/a//*.pem': 'C:/a/') included: the walk consumes them one by
/// one, and a base with one more or one fewer matches nothing. A drive root
/// comes back as 'C:', the root of a UNC share as '//server/share'. '/', and
/// '' for a pattern with a wildcard in its first path component, are what
/// {@link globBaseDirIsRoot} refuses.
///
/// @param normalizedPattern - a pattern already through
/// {@link normalizePathForSandbox} (and, on Windows, {@link toForwardSlashes}),
/// or the tail of one that is walked beneath an anchor
String globPatternBaseDir(String normalizedPattern) {
  final staticPrefix = normalizedPattern.split(RegExp(r'[*?[\]]')).first;
  if (staticPrefix.isEmpty) return '';
  // The pattern is spelled with '/' on every host. Windows' own dirname keeps
  // the separator of a root it returns ('C:/'), which no component stands for.
  return staticPrefix.endsWith('/')
      ? staticPrefix.substring(0, staticPrefix.length - 1)
      : node_path.dirname(staticPrefix);
}

/// Whether a base from {@link globPatternBaseDir} is one no walk starts from:
/// nothing at all, or the root, '/', from which a walk (`/**/*.pem`) would
/// list every filesystem the machine has mounted. A drive root ('C:') and the
/// root of a UNC share ('//server/share') are bases like any other: each is
/// one volume, which the entry names itself. Refused, every such pattern
/// would go unenforced.
bool globBaseDirIsRoot(String baseDir) => baseDir.isEmpty || baseDir == '/';

/// Normalize to `/` separators so {@link globToRegex} (which treats `/` as the
/// segment boundary) and the static-prefix split work on Windows paths. Gated
/// to win32: `\` is a valid filename byte on POSIX, so rewriting it there
/// would change the path (e.g. a Linux directory literally named `app\creds`).
String toForwardSlashes(String s) =>
    process.platform == 'win32' ? s.replaceAll('\\', '/') : s;

/// The walk behind {@link expandGlobPattern}: one listing of the pattern's
/// static prefix, filtered by `globPath` and, with `withDirectoryForm`, by
/// `globPath` without its trailing `/**`, with the symlinks seen recorded.
/// With `followSymlinkedDirectories` it also lists through a symlinked
/// directory and reports every match where it really lives.
GlobWalk walkGlobPattern(
  String globPath, {
  bool caseInsensitive = false,
  String? anchor,
  bool withDirectoryForm = false,
  bool followSymlinkedDirectories = false,
  GlobWalkListings? listings,
}) => finish(
  walkGlobPatternSteps(
    globPath,
    caseInsensitive: caseInsensitive,
    anchor: anchor,
    withDirectoryForm: withDirectoryForm,
    followSymlinkedDirectories: followSymlinkedDirectories,
    listings: listings,
  ),
);

/// {@link walkGlobPattern}, a step to a directory.
Steps<GlobWalk> walkGlobPatternSteps(
  String globPath, {
  bool caseInsensitive = false,
  String? anchor,
  bool withDirectoryForm = false,
  bool followSymlinkedDirectories = false,
  GlobWalkListings? listings,
}) sync* {
  final walk = GlobWalk();
  // Beneath an anchor the pattern is the tail alone, so no character of the
  // anchor is compiled; the walk starts at the anchor plus the tail's base.
  final walkAnchor = anchor == null ? null : toForwardSlashes(anchor);
  final normalizedPattern = walkAnchor == null
      ? toForwardSlashes(normalizePathForSandbox(globPath))
      : toForwardSlashes(globPath).substring(walkAnchor.length);
  // The tail is cut by length, so a wrong anchor would walk another directory
  // and hand back its matches. Thrown, not skipped: a skipped deny is lost.
  if (walkAnchor != null &&
      (!RegExp(r'[^/]').hasMatch(walkAnchor) ||
          !toForwardSlashes(globPath).startsWith(walkAnchor) ||
          !(walkAnchor.endsWith('/') ||
              RegExp(r'^(\/|$)').hasMatch(normalizedPattern)))) {
    throw ArgumentError(
      'Glob pattern $globPath does not lie beneath the anchor $anchor',
    );
  }
  final patternBaseDir = globPatternBaseDir(normalizedPattern);
  final baseDirBelowAnchor = patternBaseDir == '/' ? '' : patternBaseDir;
  final baseDir = walkAnchor == null
      ? patternBaseDir
      : '$walkAnchor$baseDirBelowAnchor';
  if (globBaseDirIsRoot(baseDir)) {
    logForDebugging(
      '[Sandbox] Glob pattern has no literal directory below the root to start from, skipping: $globPath',
      level: 'warn',
    );
    yield Done(walk);
    return;
  }
  // `s`: a name may hold a line terminator, which `.` alone does not match.
  final flags = caseInsensitive ? 'is' : 's';
  final positions = _globPositions(normalizedPattern, flags);
  if (followSymlinkedDirectories && !positions.splits) {
    logForDebugging(
      '[Sandbox] Glob pattern $globPath cannot be followed one path component at a time, so it is matched against real paths only and not through symlinked directories',
      level: 'warn',
    );
  }
  // A search of (directory, position): each real directory is listed once
  // for each position a spelling of it leads to. The names for one directory
  // are as many as the routes the links offer (n directories linking to each
  // other: about e*n!), and the sets of positions a tree can lead to are as
  // many as the subsets of them, while the positions are as many as the
  // pattern has, whatever the tree holds. So the work is the size of the tree
  // times the length of the pattern. One readdir per directory rather than
  // readdirSync's `recursive` option, so an unreadable subtree costs only
  // itself, not the whole pattern. A directory that is not there is not a
  // case of its own: the listing below tells an absent directory from one
  // that must be denied whole.
  //
  // Nothing here grows with the links a tree holds. An entry is matched from
  // its directory's positions and its own name, never against a spelling, and
  // a directory reached through a link is carried, and what it holds is
  // reported, by its real path, so no path gets longer than a real one.
  final records = <String, _DirectoryRecord>{};
  final cachedListings = listings ?? <String, Object>{};
  final pending = <_WalkFrame>[];
  String? codeOf(Object? error) => error is NodeError ? error.code : null;

  /// A filesystem call on a real path and, when that fails, on a shorter name
  /// for it. The real path crosses no link, so a long chain of them cannot fail
  /// the call (ELOOP) and nothing can lead it elsewhere. It can still fail for
  /// a reason that is not the object's: a path too long to name, a busy host,
  /// a runtime whose call does not take the name. So the short name is asked
  /// after every failure. But it crosses links a sandboxed command can repoint,
  /// at an empty directory or at nothing, so what it says is only ever ADDED to
  /// what the real path said:
  /// - a real path that failed with anything but `absent` or ENAMETOOLONG says
  ///   that something is there and was not read. `unread` is called, and the
  ///   caller covers that whole whatever the short name answers;
  /// - of two failures the one thrown is the one that is not `absent`, so
  ///   "could not be read" never comes out as "is not there".
  T onRealPath<T>(
    String real,
    String short,
    T Function(String) call,
    bool Function(Object) absent,
    void Function() unread,
  ) {
    try {
      return call(real);
    } catch (first) {
      if (short == real) rethrow;
      late T answer;
      try {
        answer = call(short);
      } catch (second) {
        throw absent(first) ? (!absent(second) ? second : first) : first;
      }
      if (!absent(first) && codeOf(first) != 'ENAMETOOLONG') {
        logForDebugging(
          '[Sandbox] $real could not be read for glob pattern $globPath, so it is covered whole, whatever $short leads to: $first',
          level: 'warn',
        );
        unread();
      }
      return answer;
    }
  }

  final linkTargets = <String, _LinkTarget>{};
  _LinkTarget linkTargetOf(String linkPath, String realLinkPath) {
    final cached = linkTargets[realLinkPath];
    if (cached != null) return cached;
    late _LinkTarget target;
    try {
      var unread = false;
      final found = onRealPath(
        realLinkPath,
        linkPath,
        (p) => _FoundLinkTarget(
          isDirectory: fs.statSync(p).isDirectory(),
          real: realPathOf(p),
          unread: false,
        ),
        isAbsenceErrno,
        () => unread = true,
      );
      target = _FoundLinkTarget(
        isDirectory: found.isDirectory,
        real: found.real,
        unread: unread,
      );
    } catch (error) {
      target = isAbsenceErrno(error)
          ? const _AbsentLinkTarget()
          : const _UninspectableLinkTarget();
    }
    linkTargets[realLinkPath] = target;
    return target;
  }

  /// An entry of the directory `real`, listed under the name `listedAs`, with
  ///  its type. Some file systems list names without one (some NFS and FUSE
  ///  mounts, XFS with ftype=0). Every `is…()` of such an entry answers false,
  ///  and taken at its word a directory would be passed over with all the
  ///  pattern matches beneath it. So it is asked for, at the cost of one call;
  /// an entry that was listed with a type costs none.
  _GlobWalkEntry withType(fs.Dirent entry, String listedAs, String real) {
    if (entry.isFile() ||
        entry.isDirectory() ||
        entry.isSymbolicLink() ||
        entry.isFIFO() ||
        entry.isSocket() ||
        entry.isCharacterDevice() ||
        entry.isBlockDevice()) {
      return _GlobWalkEntry(
        name: entry.name,
        isDirectory: entry.isDirectory,
        isSymbolicLink: entry.isSymbolicLink,
      );
    }
    final name = entry.name;
    final spelled = path.join(listedAs, name);
    var type = 'other';
    try {
      final stats = fs.lstatSync(spelled);
      if (stats.isDirectory()) {
        type = 'directory';
      } else if (stats.isSymbolicLink()) {
        type = 'link';
      }
    } catch (_) {
      try {
        // Where it leads can still tell: only a link leads away from its place.
        final isDirectory = fs.statSync(spelled).isDirectory();
        if (realPathOf(spelled) != path.join(real, name)) {
          type = 'link';
        } else if (isDirectory) {
          type = 'directory';
        }
      } catch (error) {
        // Only links make a circle. One that is not there is gone since it was
        // listed, which leaves its name to be matched: kept, that denies no
        // less than a listing made a moment later. Any other may be a
        // directory, and is taken for one whose listing has failed: it is not
        // gone into, and is denied whole where the pattern reaches beneath it.
        final code = codeOf(error);
        if (code == 'ELOOP') {
          type = 'link';
        } else if (code != 'ENOENT') {
          type = 'directory';
          cachedListings[path.join(real, name)] = error is Error
              ? error
              : NodeException(error.toString());
        }
      }
    }
    return _GlobWalkEntry(
      name: name,
      isDirectory: () => type == 'directory',
      isSymbolicLink: () => type == 'link',
    );
  }

  // The base as the filesystem is asked about it: a drive root gets back its
  // separator, since 'C:' on its own names the drive's current directory.
  // The positions are still reached from the base without one.
  final baseSpelling = RegExp(r'^[A-Za-z]:$').hasMatch(baseDir)
      ? '$baseDir/'
      : baseDir;
  var baseReal = baseSpelling;
  try {
    baseReal = realPathOf(baseSpelling);
  } catch (_) {
    // Not there, or a component of it cannot be resolved: list the spelling.
  }
  walk.baseLocation = baseReal;
  final initialPositions = (walkAnchor == null ? baseDir : baseDirBelowAnchor)
      .split('/')
      .fold<List<int>>(positions.start, positions.next);
  pending.add(
    _WalkFrame(
      dir: baseSpelling,
      real: baseReal,
      short: baseSpelling.length < baseReal.length ? baseSpelling : baseReal,
      positions: initialPositions,
    ),
  );
  while (pending.isNotEmpty) {
    final frame = pending.removeLast();
    final dir = frame.dir;
    final real = frame.real;
    final record = records.putIfAbsent(real, _DirectoryRecord.new);
    // What a position finds beneath a directory does not depend on the
    // others it came with, so only the ones new to this directory are taken.
    final fresh = frame.positions
        .where((p) => !record.listedFor.contains(p))
        .toList();
    if (fresh.isEmpty) continue;
    yield Pause<GlobWalk>();
    // Once. What one pattern denies is denied for the whole configuration, so
    // what the short name listed is kept for the next pattern like any other.
    void denyWhole() {
      if (record.unlisted) return;
      record.unlisted = true;
      walk.unlisted.add(dir);
      if (real != dir) walk.realOf[dir] = real;
    }

    late List<_GlobWalkEntry> entries;
    try {
      final known = cachedListings[real];
      if (known is Error) throw known;
      entries = known is List<_GlobWalkEntry>
          ? known
          : onRealPath(
              real,
              frame.short,
              (p) => fs
                  .readdirSync(p, withFileTypes: true)
                  .map((entry) => withType(entry, p, real))
                  .toList(),
              (error) => codeOf(error) == 'ENOENT',
              denyWhole,
            );
      cachedListings[real] = entries;
    } catch (error) {
      final errorCode = codeOf(error);
      logForDebugging(
        '[Sandbox] Error listing $dir for glob pattern $globPath: $error',
        level: errorCode == 'ENOENT' ? 'info' : 'warn',
      );
      if (errorCode != 'ENOENT') {
        // Kept, or every pattern would try the directory again: one that
        // would have cleared meanwhile hides more. An absence is not kept. It
        // is the one answer that denies nothing, so each pattern asks, under
        // each name. Nor is anything kept in a walk's own map: there a second
        // name for the directory still gets its try (see `listedFor`).
        if (listings != null) {
          cachedListings[real] = error is Error
              ? error
              : NodeException(error.toString());
        }
        denyWhole();
      }
      continue;
    }
    record.listedFor.addAll(fresh);
    for (final entry in entries) {
      // Nearly every entry of a large tree: a plain file the pattern does not
      // match, which nothing below records. A pattern that splits is matched
      // by name, so no path need be spelled to find that out.
      if (positions.splits &&
          !entry.isDirectory() &&
          !entry.isSymbolicLink() &&
          !positions.matches(fresh, entry.name, '')) {
        continue;
      }
      final fullPath = path.join(dir, entry.name);
      final realPath = path.join(real, entry.name);
      // A pattern that does not split is matched by its whole spelling, and
      // beneath an anchor that is the spelling from the anchor on. It is never
      // listed through a link, so every path it sees starts with the anchor.
      final spelled = toForwardSlashes(fullPath);
      final candidate = walkAnchor != null && spelled.startsWith(walkAnchor)
          ? spelled.substring(walkAnchor.length)
          : spelled;
      final isMatch = positions.matches(fresh, entry.name, candidate);
      if (isMatch) walk.matches.add(fullPath);
      if (entry.isDirectory()) {
        final beneath = positions.next(fresh, entry.name);
        final isDirectoryMatch =
            withDirectoryForm &&
            positions.matchesDirectoryForm(fresh, entry.name, candidate);
        if (isDirectoryMatch) walk.directoryMatches.add(fullPath);
        if ((isMatch || isDirectoryMatch) && realPath != fullPath) {
          walk.realOf[fullPath] = realPath;
        }
        if (beneath.isNotEmpty) {
          pending.add(
            _WalkFrame(
              dir: fullPath,
              real: realPath,
              short: path.join(frame.short, entry.name),
              positions: beneath,
            ),
          );
        }
        continue;
      }
      if (!entry.isSymbolicLink()) {
        if (isMatch && realPath != fullPath) walk.realOf[fullPath] = realPath;
        continue;
      }
      walk.symlinks.add(fullPath);
      // Only the read-deny expansion lists through a symlinked directory: it
      // has to cover what the pattern reaches by every name. The allowRead
      // expansion and the Windows ACL stamp take the link itself and stop
      // there, as the allow bind and the ACL they feed do — Windows does not
      // follow reparse points at all.
      if (!followSymlinkedDirectories) continue;
      final isDirectoryFormCandidate =
          withDirectoryForm &&
          positions.matchesDirectoryForm(fresh, entry.name, candidate);
      // A pattern that does not split is not listed through a link: no two
      // names for a directory can be told apart, so none but its own is
      // listed. A link that is itself a match still denies what it leads to.
      final beneath = positions.splits
          ? positions.next(fresh, entry.name)
          : <int>[];
      if (!isMatch && !isDirectoryFormCandidate && beneath.isEmpty) continue;
      final shortPath = path.join(frame.short, entry.name);
      final target = linkTargetOf(shortPath, realPath);
      if (target is _AbsentLinkTarget) continue;
      final unread =
          target is _UninspectableLinkTarget ||
          (target as _FoundLinkTarget).unread;
      if (unread) {
        // Where it leads is unknown, or known from the short name alone, so it
        // gets no real location — but it is still a match, and a deny
        // expansion covers it under its own spelling.
        walk.uninspectableLinks.add(fullPath);
        if (isDirectoryFormCandidate) walk.directoryMatches.add(fullPath);
      }
      // Nothing is listed through a link that leads nobody knows where.
      if (target is _UninspectableLinkTarget) continue;
      final found = target as _FoundLinkTarget;
      // Where the short name alone says it leads is denied besides: for the
      // root, as for any link to it, the directory that holds the link.
      if (unread &&
          (isMatch || (isDirectoryFormCandidate && found.isDirectory))) {
        walk.matches.add(found.real == '/' ? real : found.real);
      }
      if (isMatch && !unread) walk.realOf[fullPath] = found.real;
      if (!found.isDirectory) continue;
      if (isDirectoryFormCandidate && !unread) {
        walk.directoryMatches.add(fullPath);
        walk.realOf[fullPath] = found.real;
      }
      if (beneath.isEmpty) continue;
      // A link that leads up — to this directory or above it, or to the
      // walk's base or above it — is not listed through: beneath it is a tree
      // the pattern was never aimed at (`/`, a home directory).
      if (isAtOrUnder(real, found.real) || isAtOrUnder(baseReal, found.real)) {
        logForDebugging(
          '[Sandbox] Not following symlink $fullPath -> ${found.real} for glob pattern $globPath: it leads back up the tree',
        );
        continue;
      }
      // The one line that names the link: matches are reported by real path.
      logForDebugging(
        '[Sandbox] Following symlink $fullPath -> ${found.real} for glob pattern $globPath',
      );
      pending.add(
        _WalkFrame(
          dir: found.real,
          real: found.real,
          short: shortPath.length < found.real.length ? shortPath : found.real,
          positions: beneath,
        ),
      );
    }
  }
  yield Done(walk);
}

class _WalkFrame {
  const _WalkFrame({
    required this.dir,
    required this.real,
    required this.short,
    required this.positions,
  });

  /// The directory as spelled from the pattern's base, or `real` for one
  ///  reached through a link.
  final String dir;

  /// `dir` with every symlink resolved.
  final String real;

  /// The shortest name known for the directory, which a filesystem call
  ///  falls back on: through a link it can be short enough to name where a
  ///  real path near PATH_MAX is not.
  final String short;
  final List<int> positions;
}

/// What the walk knows about one real directory, whatever the names that
/// lead to it. A listing failure is not recorded against its positions: it
/// can belong to the name the listing was tried under (a real path too long
/// to name) while the directory is there under another, and letting that
/// name answer for the others would drop every match beneath it.
class _DirectoryRecord {
  /// The positions it has been listed for, each of them successfully.
  final Set<int> listedFor = {};

  /// Whether it is already in `walk.unlisted`, which names it once.
  bool unlisted = false;
}

/// Where a symlink leads and whether that is a directory. 'absent' when
///  nothing is there to descend into; 'uninspectable' when something is and
///  it could not be looked at, which is not the same thing: a same-uid
///  command can make a target unsearchable and undo that from inside the
///  next sandbox, so a deny must still cover the link. `unread` when only the
///  short name said where it leads: both, see {@link onRealPath}.
sealed class _LinkTarget {
  const _LinkTarget();
}

final class _FoundLinkTarget extends _LinkTarget {
  const _FoundLinkTarget({
    required this.real,
    required this.isDirectory,
    required this.unread,
  });
  final String real;
  final bool isDirectory;
  final bool unread;
}

final class _AbsentLinkTarget extends _LinkTarget {
  const _AbsentLinkTarget();
}

final class _UninspectableLinkTarget extends _LinkTarget {
  const _UninspectableLinkTarget();
}
