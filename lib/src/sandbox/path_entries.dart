/**
 * How an entry of `denyRead`, `allowRead`, `allowWrite` or `denyWrite` is
 * read: as the pattern its characters spell, as the path they name, or both.
 *
 * An entry with `*`, `?`, `[` or `]` is a pattern. A directory may hold those
 * in its own name (`[WIP] project`), so such an entry is ALSO read as what it
 * names wherever the part that holds the characters exists on disk. An entry
 * marked `{ path, literal: true }` is the name and nothing else.
 *
 * The decision is made by the functions here only, for each stage that
 * needs it (the manager and the wrapper's fold on Linux, the profile builder
 * on macOS, `expandWindowsFsPaths` on Windows). One wrap may ask about an
 * entry more than once, and the disk may change in between.
 */

// Ported from sandbox-runtime src/sandbox/path-entries.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments, dangling_library_doc_comments
// ignore_for_file: constant_identifier_names

import 'package:path/path.dart' as path;

import '../node/fs.dart' as fs;
import '../node/generators.dart';
import '../node/path.dart' as node_path;
import '../node/process.dart' as process;
import '../utils/platform.dart';
import 'sandbox_config.dart';
import 'sandbox_schemas.dart';
import 'sandbox_utils.dart';

/**
 * Which way a list cuts. A deny takes every reading that may hold, since one
 * more can only deny more; an allow takes one only for a path that is there
 * exactly as spelled.
 */
/// The allowed values are `'allow'` and `'deny'`.
typedef PathListKind = String;

/** One reading of an entry, shaped as the macOS builder's `PathEntry`. */
sealed class PathReading {
  const PathReading();

  bool get glob;
  String get path;
  String? get anchor;
}

/** The entry is the name of this path. */
class PathNameReading extends PathReading {
  const PathNameReading(this.path);

  @override
  final String path;
  @override
  bool get glob => false;
  @override
  String? get anchor => null;

  @override
  bool operator ==(Object other) =>
      other is PathNameReading && other.path == path;

  @override
  int get hashCode => Object.hash(false, path);

  @override
  String toString() => 'PathNameReading(glob: false, path: $path)';
}

/**
 * The entry is a pattern beneath `anchor`, a directory taken as the name it
 * is: `path` is `anchor` plus the tail, and only the tail is pattern.
 */
class PathGlobReading extends PathReading {
  const PathGlobReading({required this.path, required this.anchor});

  @override
  final String path;
  @override
  final String anchor;
  @override
  bool get glob => true;

  @override
  bool operator ==(Object other) =>
      other is PathGlobReading && other.path == path && other.anchor == anchor;

  @override
  int get hashCode => Object.hash(true, path, anchor);

  @override
  String toString() =>
      'PathGlobReading(glob: true, path: $path, anchor: $anchor)';
}

/**
 * The spellings and the marked paths of a list, apart. Throws on an entry
 * that is neither; see [markedLiteralPath].
 */
({List<String> spelled, List<String> marked}) splitPathEntries(
  List<FilesystemPathEntry>? entries,
) {
  final spelled = <String>[];
  final marked = <String>[];
  for (final entry in entries ?? const <FilesystemPathEntry>[]) {
    if (entry is FilesystemPathSpelling) {
      spelled.add(entry.path);
    } else {
      marked.add(markedLiteralPath(entry));
    }
  }
  return (spelled: spelled, marked: marked);
}

/** The spellings among the entries of a list: what may be a pattern. */
List<String> spelledOf(List<FilesystemPathEntry>? entries) =>
    splitPathEntries(entries).spelled;

/**
 * Whether two lists hold the same entries, in any order. Entries are told
 * apart by value: a marked entry is a new object after every clone of the
 * config, and `/x` is not `{ path: '/x' }`.
 */
bool samePathEntries(List<FilesystemPathEntry> a, List<FilesystemPathEntry> b) {
  String key(FilesystemPathEntry entry) => switch (entry) {
    FilesystemPathSpelling(:final path) => 's:$path',
    FilesystemPathLiteral() => 'l:${markedLiteralPath(entry)}',
  };
  if (a.length != b.length) return false;
  final keys = a.map(key).toSet();
  return b.every((entry) => keys.contains(key(entry)));
}

/**
 * The spelling made absolute as [normalizePathForSandbox] does for a
 * pattern: no symlink resolved, a trailing separator kept. Undefined for a
 * Windows UNC path, which is never probed (see [isUncPath]).
 */
String? _spelledAbsolute(String spelling) {
  final onWindows = getPlatform() == 'windows';
  var spelled = spelling;
  if (onWindows) {
    spelled = stripExtendedPathPrefix(expandWindowsEnvRefs(spelled));
    if (isUncPath(spelled)) return null;
  }
  final expanded = expandTilde(spelled);
  final absolute = expanded == spelled && !path.isAbsolute(spelled)
      ? node_path.resolve(process.cwd(), spelled)
      : expanded;
  return onWindows
      ? toForwardSlashes(absolute)
      : collapseInteriorSpellings(absolute);
}

/**
 * Whether something may be at `p`, for a deny. A symbolic link counts,
 * dangling or not, and so does a path that cannot be looked at: otherwise a
 * command running as the same user could switch the deny off by making a
 * parent unsearchable, and undo that inside the next sandbox.
 */
bool _mayBeThere(String p) {
  try {
    fs.lstatSync(p);
    return true;
  } catch (err) {
    return !isAbsenceErrno(err);
  }
}

/**
 * Whether `p` is there and is not a symbolic link, for an allow. Whoever can
 * write the directory that holds `p` can plant a link of that name, and the
 * allow would open what it points at. What cannot be looked at is not there.
 */
bool _isThereUnlinked(String p) {
  try {
    return !fs.lstatSync(p).isSymbolicLink();
  } catch (_) {
    return false;
  }
}

/** Whether a pattern can be walked beneath `p`, under the rule of `kind`. */
bool _isDirectoryFor(PathListKind kind, String p) {
  try {
    return kind == 'allow'
        ? fs.lstatSync(p).isDirectory()
        : fs.statSync(p).isDirectory();
  } catch (err) {
    return kind == 'deny' && !isAbsenceErrno(err);
  }
}

/// The readings a caller's spelling has BESIDE the one its characters give
/// it. Empty for a spelling that is no pattern, and for a pattern none of
/// whose glob characters are part of a name on disk: that costs one `lstat`.
///
/// A trailing `/**` is set aside first. Of the components that hold glob
/// characters, the leading ones that exist on disk as spelled are names:
///
/// - When all of them exist, the entry is also the NAME it spells. What
///   follows the last of them need not exist.
/// - When a pattern follows an existing one, the entry is also that pattern
///   BENEATH the directory. There is one such reading per existing component,
///   the longest first, so creating or removing a directory adds or removes a
///   reading and never turns one into another.
///
/// Whether a spelling is a pattern is decided on what the caller wrote
/// (`isPattern`); which components hold glob characters, by
/// [containsGlobChars] on every platform, since those are what the
/// pattern compiler and the walk take for syntax.
///
/// A component exists for a deny as [mayBeThere] has it. For an allow
/// no component from the first with glob characters on may be a symbolic
/// link or beyond looking at: a name to its end, a pattern up to its first
/// pattern component, from where the walk of an allow goes through no link.
List<PathReading> literalReadings(
  String spelling,
  PathListKind kind, {
  bool Function(String spelling)? isPattern,
}) {
  isPattern ??= containsGlobCharsForPlatform;
  var stripped = removeTrailingGlobSuffix(spelling);
  if (!isPattern(stripped)) {
    // Where `[` and `]` are no pattern syntax (Windows), `<dir>/**` is a
    // pattern by its `/**` alone, and the walk still reads the brackets as a
    // class: the `/**` stays on, as a pattern beneath the directory.
    if (stripped == spelling || !containsGlobChars(stripped)) return [];
    stripped = spelling;
  }
  final spelled = _spelledAbsolute(stripped);
  if (spelled == null) return [];

  final parts = spelled.split('/');
  final globAt = <int>[
    for (var i = 0; i < parts.length; i++)
      if (containsGlobChars(parts[i])) i,
  ];
  if (globAt.isEmpty) return [];
  final first = globAt.first;
  final last = globAt.last;
  String prefix(int i) =>
      parts.take(i + 1).join('/').isEmpty ? '/' : parts.take(i + 1).join('/');

  final isThere = kind == 'deny' ? _mayBeThere : _isThereUnlinked;
  var reach = first - 1;
  while (reach < last && isThere(prefix(reach + 1))) {
    reach++;
  }
  if (reach < first) return [];

  final readings = <PathReading>[];
  if (reach == last &&
      (kind == 'deny' || _restIsUnlinked(last, parts.length - 1, prefix))) {
    readings.add(
      PathNameReading(normalizePathForSandbox(stripped, literal: true)),
    );
  }

  // The tail keeps a trailing separator, which makes a pattern match nothing
  // (`/x/*/`): stripped, an allow spelled so would match every child. The
  // `/**` set aside above goes back on, for the walk's directory form.
  final setAside = stripped == spelling ? '' : '/**';
  for (var n = globAt.length - 2; n >= 0; n--) {
    final at = globAt[n];
    if (at > reach) continue;
    // As far as the directory's own name goes on: up to the next component
    // with glob characters, or to where the disk ends.
    final next = globAt[n + 1];
    var end = next - 1 < reach ? next - 1 : reach;
    while (end >= at && !_isDirectoryFor(kind, prefix(end))) {
      end--;
    }
    if (end < at) continue;
    // The walk resolves what the tail spells before its first pattern
    // component: a link there would have an allow list what it points at.
    if (kind == 'allow' && !_restIsUnlinked(end, next - 1, prefix)) {
      continue;
    }
    final anchor = normalizePathForSandbox(prefix(end), literal: true);
    readings.add(
      PathGlobReading(
        anchor: anchor,
        path: anchor + spelled.substring(prefix(end).length) + setAside,
      ),
    );
  }
  return readings;
}

/**
 * Whether no component after `from`, up to `to`, is a symbolic link or
 * beyond looking at. What is not there yet is neither.
 */
bool _restIsUnlinked(int from, int to, String Function(int) prefix) {
  for (var i = from + 1; i <= to; i++) {
    try {
      if (fs.lstatSync(prefix(i)).isSymbolicLink()) return false;
    } catch (err) {
      return isAbsenceErrno(err);
    }
  }
  return true;
}

/** Whether a spelling that reads as a pattern is also the name of a path. */
bool hasNameReading(String spelling, PathListKind kind) =>
    literalReadings(spelling, kind).any((reading) => !reading.glob);

/**
 * What a Linux read entry resolves to: what `expandGlob` returns for the
 * pattern, then what the entry's other readings add. `name` is the entry as
 * a name, in the caller's spelling.
 */
Steps<List<String>> withOtherReadings(
  String spelling,
  String name,
  PathListKind kind,
  Steps<List<String>> Function(String pattern, [String? anchor]) expandGlob,
) sync* {
  final expansion = Box<List<String>>();
  yield* yieldStar(expandGlob(spelling), expansion);
  final seen = expansion.value.toSet();
  final added = <String>[];
  for (final reading in literalReadings(spelling, kind)) {
    final found = <String>[];
    if (reading.glob) {
      final matches = Box<List<String>>();
      yield* yieldStar(expandGlob(reading.path, reading.anchor), matches);
      found.addAll(matches.value);
    } else {
      found.add(name);
    }
    for (final p in found) {
      if (seen.contains(p)) continue;
      seen.add(p);
      added.add(p);
    }
  }
  yield Done([...expansion.value, ...added]);
  return;
}

/**
 * The read rules `getDefaultWritePaths()` is given: the entries, the
 * credential denies, and the name each spelling also is, as a marked path.
 */
({List<FilesystemPathEntry> denyRead, List<FilesystemPathEntry>? allowRead})
readRulesOf(
  List<FilesystemPathEntry> denyRead,
  List<FilesystemPathEntry>? allowRead,
  List<String> credentialDenies,
) {
  List<FilesystemPathEntry> withNames(
    List<FilesystemPathEntry> entries,
    PathListKind kind,
  ) => [
    ...entries,
    ...spelledOf(entries).expand(
      (spelling) => literalReadings(spelling, kind).expand(
        (reading) => reading.glob
            ? const <FilesystemPathEntry>[]
            : <FilesystemPathEntry>[FilesystemPathLiteral(reading.path)],
      ),
    ),
  ];

  return (
    denyRead: withNames([
      ...denyRead,
      ...credentialDenies.map(FilesystemPathSpelling.new),
    ], 'deny'),
    allowRead: allowRead == null ? null : withNames(allowRead, 'allow'),
  );
}

Map<String, List<String>> _nonEmptyLists(Map<String, List<String>> lists) => {
  for (final entry in lists.entries)
    if (entry.value.isNotEmpty) entry.key: entry.value,
};

/**
 * The `literal…` lists of a read config: the marked entries of the two read
 * lists. A key is present only when its list is not empty.
 */
Map<String, List<String>> literalReadLists(
  List<FilesystemPathEntry>? denyRead,
  List<FilesystemPathEntry>? allowRead,
) => _nonEmptyLists({
  'literalDenyOnly': splitPathEntries(denyRead).marked,
  'literalAllowWithinDeny': splitPathEntries(allowRead).marked,
});

/** The `literal…` lists of a write config; see [literalReadLists]. */
Map<String, List<String>> literalWriteLists(
  List<FilesystemPathEntry>? allowWrite,
  List<FilesystemPathEntry>? denyWrite,
) => _nonEmptyLists({
  'literalAllowOnly': splitPathEntries(allowWrite).marked,
  'literalDenyWithinAllow': splitPathEntries(denyWrite).marked,
});

/**
 * Every path a write config allows, whichever list it came in on. Whoever
 * asks "may the command write here" asks this, not `allowOnly` alone: a
 * path the caller marked literal is in `literalAllowOnly` and nowhere else.
 */
List<String> writeRootsOf(
  ({List<String> allowOnly, List<String>? literalAllowOnly}) config,
) => [...config.allowOnly, ...(config.literalAllowOnly ?? const <String>[])];

/**
 * The paths bound back over a read deny: the read allows and the write
 * allows, the marked ones among them. A deny glob's matches are collapsed
 * against these, and one left out loses the matches beneath it their mask.
 */
List<String> reExposedBy(
  List<String> expandedAllowRead,
  List<FilesystemPathEntry>? allowRead,
  FsWriteRestrictionConfig writeConfig,
) => [
  ...expandedAllowRead,
  ...splitPathEntries(allowRead).marked,
  ...writeRootsOf((
    allowOnly: writeConfig.allowOnly,
    literalAllowOnly: writeConfig.literalAllowOnly,
  )),
];

/**
 * A read config for a backend to which every path is a name (Linux): the
 * literal lists folded into the lists they are more entries of, and gone as
 * keys, so that whatever reads `denyOnly` has read them all.
 */
FsReadRestrictionConfig? readNamesOf(FsReadRestrictionConfig? config) {
  if (config == null) return config;
  final literalDenyOnly = config.literalDenyOnly;
  final literalAllowWithinDeny = config.literalAllowWithinDeny;
  return FsReadRestrictionConfig(
    denyOnly: [...config.denyOnly, ...(literalDenyOnly ?? const <String>[])],
    allowWithinDeny:
        config.allowWithinDeny != null || literalAllowWithinDeny != null
        ? [
            ...(config.allowWithinDeny ?? const <String>[]),
            ...(literalAllowWithinDeny ?? const <String>[]),
          ]
        : null,
    credentialDenyOnly: config.credentialDenyOnly,
    ownAllowWithinDeny: config.ownAllowWithinDeny,
    unlistableDenyDirs: config.unlistableDenyDirs,
  );
}

/// The same for a write config; see [readNamesOf]. A string of
/// `allowOnly` that holds glob characters is kept only when it is also the
/// name of a path (see [literalReadings]). Any other is a pattern and
/// no name: resolving a name folds a `..` by the text, so `/home/*/../.ssh`
/// would make `/home/.ssh` writable where nothing is named `*`.
FsWriteRestrictionConfig? writeNamesOf(FsWriteRestrictionConfig? config) {
  if (config == null) return config;
  final literalAllowOnly = config.literalAllowOnly;
  final literalDenyWithinAllow = config.literalDenyWithinAllow;
  return FsWriteRestrictionConfig(
    allowOnly: writeRootsOf((
      allowOnly: config.allowOnly
          .where((p) => !containsGlobChars(p) || hasNameReading(p, 'allow'))
          .toList(),
      literalAllowOnly: literalAllowOnly,
    )),
    denyWithinAllow: [
      ...config.denyWithinAllow,
      ...(literalDenyWithinAllow ?? const <String>[]),
    ],
    // TELOSNEX DEVIATION: Roots are already literal; keep them in Linux's fold.
    mandatoryDenyRoots: config.mandatoryDenyRoots,
  );
}
