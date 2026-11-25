// Ported from sandbox-runtime src/sandbox/linux-sandbox-utils.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments, constant_identifier_names
// ignore_for_file: doc_directive_unknown, non_constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: prefer_interpolation_to_compose_strings
// ignore_for_file: prefer_adjacent_string_concatenation, unintended_html_in_doc_comment

import 'package:path/path.dart' as path;

import '../node/abort.dart';
import '../node/buffer.dart';
import '../node/child_process.dart' as child_process;
import '../node/child_process.dart' show spawn, spawnSync;
import '../node/crypto.dart' show randomBytes;
import '../node/errno.dart';
import '../node/fs.dart' as fs;
import '../node/os.dart' show endianness, tmpdir;
import '../node/process.dart' as process;
import '../utils/shell_quote.dart' show quote;
import '../utils/debug.dart' show logForDebugging;
import '../utils/real_path.dart' show realPathOf, wayTo;
import '../utils/which.dart' show whichSync;
import '../utils/ripgrep.dart' show ripGrep, RipgrepError, RipgrepConfig;
import 'java_proxy_agent.dart' show buildJavaToolOptions;
import 'path_entries.dart' show readNamesOf, writeNamesOf;
import 'sandbox_utils.dart'
    show
        generateProxyEnvVars,
        buildPosixGitSafeDirEnv,
        normalizePathForSandbox,
        normalizeCaseForComparison,
        isSymlinkOutsideBoundary,
        encodeSandboxedCommand,
        attributionKeyFor,
        DANGEROUS_FILES,
        isAbsenceErrno,
        isAtOrUnder,
        isStrictlyUnder,
        properAncestors,
        nameLocation,
        getDangerousDirectories,
        workingDirectory;
import 'credential_mask_files.dart' show MaskedFileBind;
import 'sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'generate_seccomp_filter.dart' show getApplySeccompBinaryPath;
import 'sandbox_config.dart' show SeccompConfig;

class LinuxNetworkBridgeContext {
  final String httpSocketPath;
  final String socksSocketPath;
  final child_process.NodeChildProcess httpBridgeProcess;
  final child_process.NodeChildProcess socksBridgeProcess;
  final int httpProxyPort;
  final int socksProxyPort;

  const LinuxNetworkBridgeContext({
    required this.httpSocketPath,
    required this.socksSocketPath,
    required this.httpBridgeProcess,
    required this.socksBridgeProcess,
    required this.httpProxyPort,
    required this.socksProxyPort,
  });
}

class LinuxSandboxParams {
  final String command;

  /** Attribution key encoded for violation correlation; defaults to
   *  `command`. See MacOSSandboxParams.commandId. */
  final String? commandId;
  final bool needsNetworkRestriction;
  final String? httpSocketPath;
  final String? socksSocketPath;
  final int? httpProxyPort;
  final int? socksProxyPort;

  /** Per-session proxy auth token; embedded in proxy env URLs. */
  final String? proxyAuthToken;

  /** Path to the TLS-termination CA cert; injected as trust env vars. */
  final String? caCertPath;

  /** Path to the JVM proxy agent jar; injected via JAVA_TOOL_OPTIONS. */
  final String? javaAgentJarPath;
  final FsReadRestrictionConfig? readConfig;
  final FsWriteRestrictionConfig? writeConfig;

  /** Environment variable names to unset inside the sandbox (bwrap --unsetenv) */
  final List<String>? unsetEnvVars;

  /** Environment variables to set inside the sandbox (bwrap --setenv NAME VALUE) */
  final Map<String, String>? setEnvVars;

  /**
   * Whole-file credential masks: bind fakePath (sentinel content) over
   * realPath read-only so the sandbox reads the sentinel.
   */
  final List<MaskedFileBind>? maskedFileBinds;

  /**
   * Host directory holding the fake files. Ro-bound over itself so the
   * sandbox cannot write the bind sources even if allowWrite covers it.
   */
  final String? maskedFileStoreDir;
  final bool? enableWeakerNestedSandbox;
  /** Lets the command undo the write denies: see {@link NESTED_USERNS_ENV}. */
  final bool? allowNestedUserNamespaces;
  final bool? allowAllUnixSockets;
  final String? binShell;
  final RipgrepConfig? ripgrepConfig;

  /** Maximum directory depth to search for dangerous files (default: 3) */
  final int? mandatoryDenySearchDepth;

  /** Allow writes to .git/config files (default: false) */
  final bool? allowGitConfig;

  /**
   * Directories to emit as `safe.directory` via `GIT_CONFIG_*` env
   * vars (see {@link buildPosixGitSafeDirEnv}). Under `--unshare-user`
   * the repo owner's uid is unmapped inside the sandbox, so git
   * refuses with "detected dubious ownership" without this.
   */
  final List<String>? gitSafeDirectories;

  /** Custom seccomp binary paths */
  final SeccompConfig? seccompConfig;

  /** Absolute path to the bwrap binary (default: resolve "bwrap" via PATH) */
  final String? bwrapPath;

  /** Absolute path to the socat binary (default: resolve "socat" via PATH) */
  final String? socatPath;

  /**
   * Filesystem unix socket bound by the Linux violation monitor. When set,
   * the socket is bind-mounted into the sandbox and apply-seccomp is told
   * (via SRT_OBSERVE_SOCK) to install a USER_NOTIF observation filter and
   * stream observed write-intent paths over that socket as newline JSON.
   */
  final String? observeSocketPath;

  /** Abort signal to cancel the ripgrep scan */
  final AbortSignal? abortSignal;

  // TELOSNEX DEVIATION: Per-command TMPDIR and control of the legacy fallback.
  final String? temporaryDirectory;
  final bool? skipDefaultTmpdir;
  // TELOSNEX DEVIATION: an embedder can own mount-point cleanup on exit.
  final bool registerProcessHandlers;

  const LinuxSandboxParams({
    required this.command,
    this.commandId,
    required this.needsNetworkRestriction,
    this.httpSocketPath,
    this.socksSocketPath,
    this.httpProxyPort,
    this.socksProxyPort,
    this.proxyAuthToken,
    this.caCertPath,
    this.javaAgentJarPath,
    this.readConfig,
    this.writeConfig,
    this.unsetEnvVars,
    this.setEnvVars,
    this.maskedFileBinds,
    this.maskedFileStoreDir,
    this.enableWeakerNestedSandbox,
    this.allowNestedUserNamespaces,
    this.allowAllUnixSockets,
    this.binShell,
    this.ripgrepConfig,
    this.mandatoryDenySearchDepth,
    this.allowGitConfig,
    this.gitSafeDirectories,
    this.seccompConfig,
    this.bwrapPath,
    this.socatPath,
    this.observeSocketPath,
    this.abortSignal,
    // TELOSNEX DEVIATION: Accept the command's choice from the manager.
    this.temporaryDirectory,
    this.skipDefaultTmpdir,
    // TELOSNEX DEVIATION: standalone wraps retain upstream exit cleanup.
    this.registerProcessHandlers = true,
  });
}

/** Default max depth for searching dangerous files */
const _DEFAULT_MANDATORY_DENY_SEARCH_DEPTH = 3;

/**
 * Find if any component of the path is a symlink within the allowed write paths.
 * Returns the symlink path if found, or null if no symlinks.
 *
 * This is used to detect and block symlink replacement attacks where an attacker
 * could delete a symlink and create a real directory with malicious content.
 */
String? _findSymlinkInPath(String targetPath, List<String> allowedWritePaths) {
  final parts = targetPath.split(path.separator);
  var currentPath = '';

  for (final part in parts) {
    if (part.isEmpty) continue; // Skip empty parts (leading /)
    final nextPath = currentPath + path.separator + part;

    try {
      final stats = fs.lstatSync(nextPath);
      if (stats.isSymbolicLink()) {
        // Check if this symlink is within an allowed write path
        final isWithinAllowedPath = allowedWritePaths.any(
          (allowedPath) => isAtOrUnder(nextPath, allowedPath),
        );
        if (isWithinAllowedPath) {
          return nextPath;
        }
      }
    } catch (_) {
      // Path doesn't exist - no symlink issue here
      break;
    }
    currentPath = nextPath;
  }

  return null;
}

/** As many missing names as one way is followed up from again. */
const _MAX_MISSING_NAMES_PASSED = 40;

/**
 * Canonicalize a deny path through symlinks before any mask or bind is
 * computed (resolve-before-mask). Deny paths regularly contain symlinked
 * ancestors — the common dotfiles setup symlinks .claude (or the parent of
 * .mcp.json) to a real directory — and masking the raw symlink with
 * `--ro-bind /dev/null <symlink>` makes bwrap abort at startup: "Is a
 * directory" for relative link targets, ENOENT for absolute ones.
 *
 * Resolution: realpath when the full path exists; otherwise canonicalize the
 * deepest existing ancestor and re-join the missing components.
 *
 * A dangling symlink along the way is followed as the kernel follows it, name
 * by name, to the first name that is not there. What lies beyond that name is
 * undecided, since whoever makes it decides where the way goes on. So the
 * answer ends with it, and with the name that follows it if one does, which
 * makes a directory of it: the caller's placeholder on the first missing
 * component then keeps the whole way from coming about.
 *
 * A way that goes up again at once from the missing name is let pass by a
 * directory put there as a placeholder. So that name goes to `alsoDenied`, to
 * be denied for itself, and the way is followed on from where it would lead.
 *
 * A directory on the way that cannot be searched is the answer itself: what
 * lies in it cannot be told, and denied whole it keeps its place and its mode.
 *
 * Returns null when the path cannot be canonicalized (a symlink cycle, a name
 * that is no text). Callers fail closed on it.
 *
 * Unlike normalizePathForSandbox, this intentionally applies no
 * isSymlinkOutsideBoundary check: that check exists so allow paths can't
 * silently widen write access through a symlink, but a deny path only ever
 * removes access, and the mask must land on the inode that writes through
 * the symlink actually reach.
 */
String? _resolveSymlinkedDenyPath(
  String targetPath, [
  List<String>? alsoDenied,
]) {
  try {
    return realPathOf(targetPath);
  } catch (_) {
    // Some component is missing or dangling — canonicalize manually below.
  }

  // Find the deepest ancestor that fully resolves, collecting the missing
  // suffix components (leaf first, so unshift keeps them in path order).
  var ancestor = targetPath;
  final remainder = <String>[];
  String? resolvedAncestor;
  while (resolvedAncestor == null) {
    final parent = path.dirname(ancestor);
    if (parent == ancestor) {
      return null; // reached the root without resolving anything
    }
    remainder.insert(0, path.basename(ancestor));
    ancestor = parent;
    try {
      resolvedAncestor = realPathOf(ancestor);
    } catch (_) {
      // Keep walking up.
    }
  }

  // The first missing component may be a dangling symlink (lstat succeeds,
  // realpath fails); otherwise the remainder is genuinely non-existent and
  // the re-joined path is final.
  final rejoined = path.normalize(
    path.joinAll([resolvedAncestor, ...remainder]),
  );
  try {
    fs.readlinkSync(path.join(resolvedAncestor, remainder[0]));
  } catch (_) {
    return rejoined; // Not a symlink — nothing left to resolve.
  }
  Object? why = 'it goes up from too many names that are not there';
  try {
    var onward = rejoined;
    for (var i = 0; i < _MAX_MISSING_NAMES_PASSED; i++) {
      final way = wayTo(onward);
      final real = way.real;
      final rest = way.rest;
      final notThere = way.notThere;
      if (notThere is NodeError && notThere.code == 'EACCES') {
        return real.isNotEmpty ? real : '/';
      }
      final names = rest.where((name) => name != '' && name != '.').toList();
      if (names.length < 2 || names[1] != '..') {
        final result = [real, ...names.take(2)].join('/');
        return result.isNotEmpty ? result : '/';
      }
      alsoDenied?.add('$real/${names[0]}');
      onward = [real, ...names.skip(2)].join('/');
    }
  } catch (err) {
    why = err;
  }
  // Said by the pass that acts on it, not by the one that gathers.
  if (alsoDenied == null) {
    logForDebugging(
      '[Sandbox Linux] Where a write to $targetPath would land cannot be settled: $why. The link on the way is masked instead, which can keep the sandbox from starting.',
      level: 'warn',
    );
  }
  return null;
}

/**
 * The first existing component of the path that is not a directory, if there
 * is one. Nothing can be created below it for as long as it is there: a git
 * worktree's `.git` is a file, so there is no `.git/hooks`.
 */
String? _fileOnTheWay(String targetPath) {
  final parts = targetPath.split(path.separator);
  var currentPath = '';

  for (final part in parts) {
    if (part.isEmpty) continue; // Skip empty parts (leading /)
    final nextPath = currentPath + path.separator + part;
    try {
      if (!fs.statSync(nextPath).isDirectory()) return nextPath;
    } catch (_) {
      // Path doesn't exist — stop checking
      break;
    }
    currentPath = nextPath;
  }

  return null;
}

/**
 * Find the first non-existent path component.
 * E.g., for "/existing/parent/nonexistent/child/file.txt" where /existing/parent exists,
 * returns "/existing/parent/nonexistent"
 *
 * This is used to block creation of non-existent deny paths by mounting /dev/null
 * at the first missing component, preventing mkdir from creating the parent directories.
 */
String _findFirstNonExistentComponent(String targetPath) {
  final parts = targetPath.split(path.separator);
  var currentPath = '';

  for (final part in parts) {
    if (part.isEmpty) continue; // Skip empty parts (leading /)
    final nextPath = currentPath + path.separator + part;
    if (!fs.existsSync(nextPath)) {
      return nextPath;
    }
    currentPath = nextPath;
  }

  return targetPath; // Shouldn't reach here if called correctly
}

/** What the placeholder for an absent deny path is mounted on. */
abstract final class _MountPointKind {
  /** A file made on the host for it, which /dev/null goes on. */
  static const File = 'file';
  /** A directory made on the host for it, which an empty one goes on. */
  static const Directory = 'directory';
  /** The file above the path, which goes on itself. Nothing is made. */
  static const Held = 'held';
  /** None can be made. Nothing is mounted; what lies above is still pinned. */
  static const Unmakeable = 'unmakeable';
}

/** The kinds that are made on the host. */
typedef _MadeMountPointKind = String; // 'file' | 'directory'

/** open(2)'s O_PATH on x86-64 and arm64; node:fs does not name it. Where the
 * bit means something else the open is an ordinary one or fails, and a failure
 * keeps the placeholder. */
const _O_PATH = 2097152;
/** statfs(2)'s type for 9p, which is how WSL 2 mounts a Windows drive. */
const _V9FS_MAGIC = 0x01021997;

/**
 * The kind of mount point that can be made at `dest`, an absent path whose
 * parent is there: `wanted`, a directory where only a file is refused, or
 * unmakeable. bubblewrap makes it on the host as this user, before the command
 * runs, and exits if it cannot.
 *
 * Unmakeable only where the refusal is not this user's to lift, so that the
 * command cannot create `dest` either; `wanted` on any doubt (see
 * mountPointFor).
 */
String _makeableMountPoint(String dest, _MadeMountPointKind wanted) {
  /** The errno `attempt` is refused with. Any other failure is a doubt. */
  String? refusalOf(void Function() attempt) {
    try {
      attempt();
      return null;
    } catch (err) {
      final code = err is NodeError ? err.code : null;
      if (code == 'EACCES' || code == 'EPERM' || code == 'EROFS') return code;
      rethrow;
    }
  }

  int? fd;
  try {
    // One descriptor answers every question, through /proc: a command still
    // running could put another directory at the path between two of them.
    // Its link differs from the path when a symlink was followed on the way.
    fd = fs.openSync(
      path.dirname(dest),
      _O_PATH | fs.constants.O_NOFOLLOW | fs.constants.O_DIRECTORY,
    );
    final parent = '/proc/self/fd/$fd';
    if (fs.readlinkSync(parent) != path.dirname(dest)) return wanted;
    final stat = fs.fstatSync(fd);
    final uid = stat.uid;
    final mode = stat.mode;
    // What the kernel asks of a directory before it creates anything in it.
    final refusal = refusalOf(
      () => fs.accessSync(parent, fs.constants.W_OK | fs.constants.X_OK),
    );

    if (fs.statfsSync(parent).type != _V9FS_MAGIC) {
      // EACCES is the word of the mode or an ACL, which the owner can change,
      // and bubblewrap's user namespace overrides it for the owner. A
      // read-only file system (EROFS) and an immutable directory (EPERM)
      // refuse whoever asks from in there.
      return refusal == null ||
              (refusal == 'EACCES' && uid == process.geteuid?.call())
          ? wanted
          : _MountPointKind.Unmakeable;
    }

    // On a Windows drive the Windows ACL decides, and nothing on this side
    // tells it: every directory there is this user's, with a mode that lets it
    // write, also one that takes subfolders and no files. So the mount point
    // is made here instead of by bubblewrap, which finds it there.
    if (refusal == null) {
      final entry = '$parent/${path.basename(dest)}';
      if (wanted == _MountPointKind.File &&
          refusalOf(() => fs.closeSync(fs.openSync(entry, 'wx', 292))) ==
              null) {
        return _MountPointKind.File;
      }
      if (refusalOf(() => fs.mkdirSync(entry)) == null) {
        return _MountPointKind.Directory;
      }
    }
    // The name may be refused for a reason that passes. The folder is beyond
    // this user when it may not even be given the mode it has.
    return refusalOf(() => fs.chmodSync(parent, mode & 4095)) == null
        ? wanted
        : _MountPointKind.Unmakeable;
  } catch (_) {
    return wanted;
  } finally {
    if (fd != null) fs.closeSync(fd);
  }
}

/** What the `.git` of a directory is, and so what is denied there. */
abstract final class _DotGitKind {
  /** A repository: its hooks and config are denied. */
  static const Directory = 'directory';
  /**
   * The pointer of a worktree or a submodule ("gitdir: /path/..."). There are
   * no .git/hooks for as long as it is a file, so the file is denied, which
   * keeps it one.
   */
  static const File = 'file';
  /** Nothing is denied: a mount at .git would keep `git init` from making it. */
  static const Absent = 'absent';
}

String _dotGitKindAt(String dotGitPath) {
  try {
    return fs.statSync(dotGitPath).isDirectory()
        ? _DotGitKind.Directory
        : _DotGitKind.File;
  } catch (_) {
    return _DotGitKind.Absent;
  }
}

/**
 * The part of the mandatory deny set that follows from the cwd alone: the
 * dangerous files and directories resolved against it, plus `.git/hooks` and
 * (unless the caller allows git config) `.git/config`, or a `.git` that is a
 * file.
 * {@link linuxGetMandatoryDenyPaths} adds the nested matches its ripgrep scan
 * finds on top of these. Split out so a consumer that must not scan — the
 * violation monitor, which needs the same denies to judge a write bwrap
 * refuses — reads the same definition rather than a copy of it.
 */
// TELOSNEX DEVIATION: Reuse the cwd's static deny set at each explicit root.
List<String> linuxGetCwdMandatoryDenyPaths([bool allowGitConfig = false]) =>
    _linuxGetRootMandatoryDenyPaths(process.cwd(), allowGitConfig);

List<String> _linuxGetRootMandatoryDenyPaths(String cwd, bool allowGitConfig) {
  // Note: Settings files are added at the callsite in sandbox-manager.ts
  final denyPaths = [
    // Dangerous files in CWD
    ...DANGEROUS_FILES.map((f) => path.normalize(path.join(cwd, f))),
    // Dangerous directories in CWD
    ...getDangerousDirectories().map((d) => path.normalize(path.join(cwd, d))),
  ];

  // Only the cwd's own: a .git file below it is git's to rewrite and remove
  // (a checkout that recurses into submodules does).
  final dotGitPath = path.normalize(path.join(cwd, '.git'));
  final dotGit = _dotGitKindAt(dotGitPath);

  if (dotGit == _DotGitKind.File) {
    denyPaths.add(dotGitPath);
  }
  if (dotGit == _DotGitKind.Directory) {
    // Git hooks always blocked for security
    denyPaths.add(path.normalize(path.join(cwd, '.git/hooks')));

    // Git config conditionally blocked based on allowGitConfig setting
    if (!allowGitConfig) {
      denyPaths.add(path.normalize(path.join(cwd, '.git/config')));
    }
  }

  return denyPaths;
}

/**
 * The directories below `cwd`, down to `maxDepth`, that ripgrep said it could
 * not read, that this process cannot read either, and whose mode is this
 * user's to change. What is in one is not known, so the caller denies it whole.
 * Exported for testing.
 */
List<String> unreadableDirectories(String stderr, String cwd, int maxDepth) {
  final found = <String>[];
  final tried = <String>{};
  for (final line in stderr.split('\n')) {
    // How a message is worded depends on ripgrep's version and on how many
    // threads it has, so what stands before each ": " is tried.
    final said = line.startsWith('rg: ') ? line.substring(4) : line;
    for (
      var cut = said.indexOf(': ');
      cut != -1;
      cut = said.indexOf(': ', cut + 1)
    ) {
      for (
        var dir = path.normalize(path.join(cwd, said.substring(0, cut)));
        dir.startsWith(cwd + path.separator) && !tried.contains(dir);
        dir = path.dirname(dir)
      ) {
        tried.add(dir);
        try {
          // THREAT: the text is only a hint. A name can hold a newline and a
          // whole message of its own, and a bind of `link/x` would bring what
          // the link leads to INTO the sandbox. So: a directory, with no link
          // on the way to it, that cannot be read from here. And this user's:
          // nobody else's mode can be given back from inside, and there can
          // be thousands of those (`/home`), each of them a mount.
          final stat = fs.lstatSync(dir);
          if (!stat.isDirectory() ||
              stat.uid != process.getuid?.call() ||
              realPathOf(dir) != dir) {
            break;
          }
        } catch (error) {
          // What cannot be looked at, because what holds it cannot be
          // searched, is stood in for by the directory above it.
          if (error is NodeError && error.code == 'EACCES') continue;
          break;
        }
        try {
          fs.accessSync(dir, fs.constants.R_OK | fs.constants.X_OK);
        } catch (_) {
          if (path.relative(dir, from: cwd).split(path.separator).length <=
              maxDepth) {
            found.add(dir);
          }
        }
        break;
      }
    }
  }
  return found;
}

/**
 * Get mandatory deny paths using ripgrep (Linux only).
 * Uses a SINGLE ripgrep call with multiple glob patterns for efficiency.
 * With --max-depth limiting, this is fast enough to run on each command without memoization.
 */
Future<List<String>> _linuxGetMandatoryDenyPaths([
  RipgrepConfig? ripgrepConfig,
  int maxDepth = _DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  bool allowGitConfig = false,
  AbortSignal? abortSignal,
  // TELOSNEX DEVIATION: Run the same scan at an explicit root when supplied.
  String? root,
]) async {
  ripgrepConfig ??= RipgrepConfig(command: 'rg');
  // TELOSNEX DEVIATION: Use the explicit root when provided, not the cwd.
  final cwd = root ?? process.cwd();
  // Use provided signal or create a fallback controller
  final fallbackController = AbortController();
  final signal = abortSignal ?? fallbackController.signal;
  final dangerousDirectories = getDangerousDirectories();

  // TELOSNEX DEVIATION: The static denies and the scan use the same root.
  final denyPaths = _linuxGetRootMandatoryDenyPaths(cwd, allowGitConfig);

  // Build iglob args for all patterns in one ripgrep call
  final iglobArgs = <String>[];
  for (final fileName in DANGEROUS_FILES) {
    iglobArgs.addAll(['--iglob', fileName]);
  }
  for (final dirName in dangerousDirectories) {
    iglobArgs.addAll(['--iglob', '**/$dirName/**']);
  }
  // Git hooks always blocked in nested repos. A repository is known by its
  // HEAD, so that its hooks are denied before there are any.
  iglobArgs.addAll(['--iglob', '**/.git/hooks/**', '--iglob', '**/.git/HEAD']);

  // Git config conditionally blocked in nested repos
  if (!allowGitConfig) {
    iglobArgs.addAll(['--iglob', '**/.git/config']);
  }

  // Single ripgrep call to find all dangerous paths in subdirectories
  // Limit depth for performance - deeply nested dangerous files are rare
  // and the security benefit doesn't justify the traversal cost
  //
  // ripgrep lists files, and its depth is the file's. `sub/.vscode/x` and
  // `sub/.git/config` lie at `maxDepth`; `sub/.git/hooks/pre-commit`, of the
  // same directory, one level further down.
  var matches = <String>[];
  try {
    matches = await ripGrep(
      [
        '--files',
        '--hidden',
        // INVARIANT: no file decides what is listed. An ignore file that names
        // a directory hides all beneath it, and a configuration file can add
        // any flag; both are files in or above the tree.
        '--no-ignore',
        '--no-config',
        // Into a pipe ripgrep writes by the block, and killed it drops the
        // block: it would have listed nothing.
        '--line-buffered',
        '--max-depth',
        '${maxDepth + 1}',
        ...iglobArgs,
        '-g',
        '!**/node_modules/**',
      ],
      cwd,
      signal,
      ripgrepConfig,
    );
  } catch (error) {
    // Stopped, it found nothing: the caller must not be handed a command
    // without the denies it would have found.
    signal.throwIfAborted();
    // INVARIANT: what ripgrep listed counts, however it ended. It exits 2 if
    // there was a directory it could not read, having listed the rest, and is
    // killed after ten seconds. What it had not come to by then is not denied.
    if (error is RipgrepError) {
      matches = error.listed;
      // A read-only bind also keeps the command from giving the mode back.
      denyPaths.addAll(unreadableDirectories(error.stderr, cwd, maxDepth));
    }
    logForDebugging('[Sandbox] ripgrep scan failed: $error', level: 'warn');
  }

  // The names a match can lie under, by path component.
  final directoryNames = [
    ...dangerousDirectories,
    '.git/hooks',
    '.git/config',
    '.git/HEAD',
  ].map((name) => normalizeCaseForComparison(name).split('/')).toList();
  for (final match in matches) {
    final segments = path
        .relative(path.normalize(path.join(cwd, match)), from: cwd)
        .split(path.separator);
    final lower = segments.map(normalizeCaseForComparison).toList();
    // Where the dangerous name begins and how long it is: the first of
    // `directoryNames` on the way down, else the file itself.
    var at = segments.length - 1;
    var length = 1;
    // How deep the directory holding the name, `at`, may lie. One level less
    // for `directoryNames`, all alike: each costs mounts that keep what holds
    // it from being renamed or removed, and bwrap's start grows with them.
    var deepest = maxDepth - 1;
    search:
    for (var i = 0; i < lower.length; i++) {
      for (final name in directoryNames) {
        // Dart: an index past the end throws, where JS reads undefined.
        if (name.indexed.every(
          (c) => i + c.$1 < lower.length && lower[i + c.$1] == c.$2,
        )) {
          at = i;
          length = name.length;
          deepest = maxDepth - 2;
          break search;
        }
      }
    }
    if (at > deepest) continue;
    final found = segments.sublist(0, at + length);
    if (lower[at] == '.git' && at + 1 < lower.length && lower[at + 1] == 'head')
      found[at + 1] = 'hooks';
    denyPaths.add(path.normalize(path.joinAll([cwd, ...found])));
  }

  return {...denyPaths}.toList();
}

// Track mount points created by bwrap for non-existent deny paths.
// When bwrap does --ro-bind /dev/null /nonexistent/path, it creates an empty
// file on the host as a mount point. These persist after bwrap exits and must
// be cleaned up explicitly.
final Set<String> _bwrapMountPoints = {};

// The source of the empty-directory mount points: at most one at a time, made
// on first use, reused while a sandbox is running, and removed with the mount
// points — never before, because a live bind's source must stay.
// generateFilesystemArgs pins it read-only inside every sandbox that uses it.
String? _emptyMountSourceDir;

String _ensureEmptyMountSourceDir() {
  if (_emptyMountSourceDir != null) {
    // Revalidated, not trusted: the path is under the system temp dir, which
    // sandboxed commands commonly can write, and bwrap resolves a bind source
    // on the HOST, so a directory swapped for a symlink between two wraps
    // would publish whatever it points at. Anything that is not our own
    // private empty directory is left where it is: it is not ours to delete.
    try {
      final stat = fs.lstatSync(_emptyMountSourceDir!);
      if (stat.isDirectory() &&
          stat.uid == process.getuid?.call() &&
          (stat.mode & int.parse('077', radix: 8)) == 0 &&
          fs.readdirSync(_emptyMountSourceDir!).isEmpty) {
        return _emptyMountSourceDir!;
      }
    } catch (_) {
      // Gone, or no longer inspectable: make a new one below.
    }
    logForDebugging(
      '[Sandbox Linux] Not reusing the empty-directory mount source, it is gone or no longer our own empty directory: $_emptyMountSourceDir',
    );
  }
  _emptyMountSourceDir = fs.mkdtempSync(path.join(tmpdir(), 'claude-empty-'));
  // mkdtemp asks for 0700 but the umask applies, so under `umask 0200` the
  // directory lands on 0500. Set the mode here rather than let the check
  // above reject the directory this call has just made.
  fs.chmodSync(_emptyMountSourceDir!, int.parse('700', radix: 8));
  return _emptyMountSourceDir!;
}

const int CAP_SETFCAP = 31;

// This process's bounding set unioned with its inheritable set, read once —
// see processHasBoundingCapability for why those two. Only prctl(CAPBSET_DROP)
// and capset move them and this library calls neither, and without the memo
// the read is a synchronous open of /proc/self/status on the path of every
// wrapped command. Only a successful read is stored, so a transient failure
// does not latch "no capabilities" for the life of the process.
BigInt? _boundingCapabilities;
bool _capabilityReadFailureLogged = false;

/**
 * Whether this process holds `cap` in its bounding or inheritable set (Linux).
 *
 * bwrap is reached by execve, and for a euid-0 caller the kernel recomputes
 * the new permitted set from the bounding and inheritable sets, discarding
 * what the caller itself had permitted. Those two sets are therefore what
 * decides which capabilities bwrap holds when it writes its uid map; CapPrm
 * and CapEff do not, and for any process itself reached by exec as root they
 * merely repeat the union.
 */
bool processHasBoundingCapability(int cap) {
  var bits = _boundingCapabilities;
  if (bits == null) {
    var failure = 'has no CapBnd or CapInh line';
    try {
      bits = boundingCapabilitiesFromStatus(
        fs.readFileSync('/proc/self/status', 'utf8') as String,
      );
      _boundingCapabilities = bits;
    } catch (e) {
      failure = 'could not be read ($e)';
    }
    if (bits == null) {
      if (!_capabilityReadFailureLogged) {
        _capabilityReadFailureLogged = true;
        logForDebugging(
          '[Sandbox Linux] /proc/self/status $failure - assuming this process holds no capabilities',
          level: 'warn',
        );
      }
      return false;
    }
  }
  return ((bits >> cap) & BigInt.one) == BigInt.one;
}

/**
 * The capability set an execve gives a euid-0 caller's child, parsed out of a
 * `/proc/<pid>/status`: CapBnd unioned with CapInh. `undefined` when either
 * line is absent. CapPrm and CapEff are deliberately not consulted — see
 * processHasBoundingCapability.
 */
BigInt? boundingCapabilitiesFromStatus(String status) {
  final bounding = RegExp(
    r'^CapBnd:\s*([0-9a-fA-F]+)\s*$',
    multiLine: true,
  ).firstMatch(status);
  final inheritable = RegExp(
    r'^CapInh:\s*([0-9a-fA-F]+)\s*$',
    multiLine: true,
  ).firstMatch(status);
  return bounding != null && inheritable != null
      ? BigInt.parse(bounding[1]!, radix: 16) |
            BigInt.parse(inheritable[1]!, radix: 16)
      : null;
}

/**
 * The bwrap capability list. Always `--cap-drop ALL`, which for a non-root
 * caller is bwrap's default anyway. `--cap-add CAP_SETFCAP` for the whole
 * bwrap invocation — the outer shell and the two socat relays hold it too —
 * when the caller is uid 0, the seccomp helper is in use and the capability
 * survives into bwrap: the helper's nested user namespace maps uid 0, which
 * Linux 5.12 and the distribution kernels that backported it allow only from
 * a creator holding CAP_SETFCAP. Under the helper a uid-0 caller's command
 * therefore has a full set inside that nested namespace, which is
 * identity-mapped to the caller's uid 0, and the filesystem policy there
 * rests on the helper's namespaces filter refusing the calls that change a
 * mount tree: the nested namespace's locked mount copies refuse the unmount
 * of any one of them, not the whole tree being moved aside. Without the
 * helper (`allowAllUnixSockets`, or no usable helper binary) the command runs
 * in bwrap's own namespaces and `--cap-drop ALL` is what stops it unmounting
 * a deny.
 *
 * Pure: `hasSetfcap` is decided by the caller, which is also where the
 * missing-capability case is reported once per process.
 */
List<String> capabilityArgs({
  required int? euid,
  required bool hasSetfcap,
  required bool usesSeccompHelper,
}) {
  final args = ['--cap-drop', 'ALL'];
  if (euid != 0) return args;
  if (!hasSetfcap) return args;
  if (usesSeccompHelper) args.addAll(['--cap-add', 'CAP_SETFCAP']);
  return args;
}

// Latch for the predicted case: once per process, not once per command.
var _setfcapMissingLogged = false;

// A uid-0 caller whose bounding set lacks CAP_SETFCAP cannot sandbox
// anything: bwrap's own --unshare-user writes a uid map containing uid 0, and
// so does the seccomp helper's nested namespace, and a kernel that enforces
// the requirement refuses both unless the namespace's creator held the
// capability. allowAllUnixSockets does not avoid it — it only drops the
// helper, not bwrap's own user namespace. Worded for both the predicted case
// (the debug warning on the path of a wrapped command) and the confirmed one
// (checkLinuxDependencies, after bubblewrap has actually refused).
const String CAP_SETFCAP_MISSING_MESSAGE =
    "running as uid 0 without CAP_SETFCAP in this process's capability bounding set - on " +
    'kernels that enforce the CAP_SETFCAP requirement for mapping uid 0 into a user namespace ' +
    '(Linux 5.12 and distribution backports) every sandboxed command fails while writing a uid ' +
    'map ("Operation not permitted"). Grant CAP_SETFCAP to this process, or run as a non-root user';

/**
 * Linux's per-argument cap, MAX_ARG_STRLEN: 32 pages, so 128 KiB on most
 * kernels and up to 2 MiB with 64 KiB pages. The page size is AT_PAGESZ in
 * /proc/self/auxv (pairs of native words); 4 KiB, the smallest, if unreadable.
 */
int? _linuxMaxArgStrlen;
int _maxArgStrlen() {
  if (_linuxMaxArgStrlen == null) {
    const AT_PAGESZ = 6;
    var pageSize = 4096;
    try {
      final auxv = fs.readFileSync('/proc/self/auxv') as Buffer;
      final wordBytes = RegExp(r'64|s390x').hasMatch(process.arch) ? 8 : 4;
      // Buffer reads at most 6 bytes as a number; no value needed here is wider.
      final low = wordBytes < 6 ? wordBytes : 6;
      int word(int at) => endianness() == 'BE'
          ? auxv.readUIntBE(at + wordBytes - low, low)
          : auxv.readUIntLE(at, low);
      for (var at = 0; at + 2 * wordBytes <= auxv.length; at += 2 * wordBytes) {
        if (word(at) == AT_PAGESZ) {
          pageSize = word(at + wordBytes);
          break;
        }
      }
    } catch (_) {
      // No /proc: the smallest page size only moves a profile to the file
      // sooner than it had to.
    }
    _linuxMaxArgStrlen = 32 * pageSize;
  }
  return _linuxMaxArgStrlen!;
}

/**
 * Room left below the cap when deciding whether the profile stays on the
 * command line: the embedder may put a prefix of its own (`exec`, `cd x &&`,
 * an assignment) in the same argument.
 */
const _ARG_HEADROOM_BYTES = 4096;

/** bwrap's cap on parsed words, the command line and `--args` file together. */
const _BWRAP_MAX_ARGS = 9000;

/**
 * The fd the `--args` file is opened on: a single digit, since dash rejects
 * multi-digit redirections, and high, since embedders hand the command low
 * fds of their own (an extra stdio pipe, a helper as `/proc/self/fd/3`).
 */
const _BWRAP_ARGS_FD = 9;

/**
 * Linux's O_TMPFILE, which neither Node nor Bun exposes in `fs.constants`:
 * the asm-generic __O_TMPFILE, the value on every architecture they build
 * for Linux, together with the O_DIRECTORY the flag is defined to carry — a
 * kernel or filesystem that does not know it therefore fails the open on the
 * directory rather than creating a named file.
 */
final _O_TMPFILE = int.parse('20000000', radix: 8) | fs.constants.O_DIRECTORY;

/**
 * The `--args` profiles this process holds open.
 *
 * A profile is an unnamed file (O_TMPFILE): written at wrap time, kept open
 * here, and opened again by the string bwrap runs through
 * `/proc/<pid>/fd/<n>`, which is a fresh read-only description of the same
 * inode at offset 0. Nothing is named at any point, so there is nothing for
 * anyone to substitute between the wrap and the execution — not a sandbox
 * that renames an ancestor of tmpdir, not a sandbox another process of the
 * same user launched with tmpdir writable. Every sandbox this library starts
 * has its own PID namespace and a fresh /proc, so none of them can reach
 * /proc/<this pid> either.
 *
 * Fds close when the sandboxes of a batch are cleaned up, and fd numbers are
 * reused: a string kept past its cleanup and run later opens whatever the
 * number means by then — nothing (the redirection fails and the command does
 * not run), something bwrap refuses, or another profile of this process,
 * never one from outside it.
 */
final Set<int> _bwrapArgsFds = {};

/** Where the string bwrap runs opens the profile held on `fd`. */
String _bwrapArgsProfilePath(int fd) {
  return '/proc/${process.pid}/fd/$fd';
}

/**
 * Writes `mountWords` NUL-separated to an unnamed file and returns the fd it
 * stays open on. Throws when no directory takes an O_TMPFILE file, or when
 * the profile cannot be opened again through /proc: there is no named-file
 * fallback, and before any of this an over-long profile failed with E2BIG
 * anyway. The check is this process's own open; a child's can still be
 * refused (a process made non-dumpable owns its /proc entries as root), and
 * the string then fails in the redirection and runs no command.
 */
int _openBwrapArgsProfile(List<String> mountWords) {
  final contents = mountWords.map((word) => word + '\x00').join('');
  final failures = <String>[];
  for (final dir in {tmpdir(), '/dev/shm'}) {
    int fd;
    try {
      fd = fs.openSync(
        dir,
        _O_TMPFILE | fs.constants.O_RDWR,
        int.parse('600', radix: 8),
      );
    } catch (error) {
      failures.add('$dir: ${_errorText(error)}');
      continue;
    }
    try {
      fs.writeFileSync(fd, contents);
      // Read-only from here: this process is done writing it.
      fs.fchmodSync(fd, int.parse('400', radix: 8));
      // The string opens this path. Fail now, where the caller is told why,
      // rather than when the command runs.
      fs.closeSync(
        fs.openSync(_bwrapArgsProfilePath(fd), fs.constants.O_RDONLY),
      );
    } catch (error) {
      failures.add('$dir: ${_errorText(error)}');
      fs.closeSync(fd);
      continue;
    }
    _bwrapArgsFds.add(fd);
    return fd;
  }
  throw NodeException(
    'no unnamed file could be opened for it (${failures.join('; ')})',
  );
}

void _closeBwrapArgsProfile(int fd) {
  _bwrapArgsFds.remove(fd);
  try {
    fs.closeSync(fd);
  } catch (_) {
    // Already closed: nothing left to release.
  }
}

String _errorText(Object? error) {
  return errorMessage(error);
}

/**
 * Why a bubblewrap profile could not be run. Allowed values:
 * 'too_many_arguments' | 'nul_in_path' | 'args_file_unavailable' |
 * 'command_too_long'.
 */
typedef LinuxSandboxProfileErrorCode = String;

/** More arguments than bubblewrap parses, on the line or through a file. */
/** A mount path holds a NUL byte, which no carrier of arguments can hold. */
/**
 * No unnamed file could be opened to carry the mounts: passing (this
 * process is out of descriptors) or lasting (no directory on this host
 * takes one). The error on `.cause` names each directory tried and what it
 * said.
 */
/** The line does not fit one shell argument even with the mounts in a file. */

/**
 * Thrown when a Linux bubblewrap profile cannot be run on this host: what the
 * configuration expands to, with the mandatory denies of the working
 * directory, is past a limit, or, for `command_too_long` and `nul_in_path`,
 * what the caller passed in is. The command was not run and no
 * profile file stays open, so do not run the per-command cleanup
 * (`cleanupAfterCommand()`, `cleanupBwrapMountPoints()`) for a wrap that
 * threw: it would release a second time, and a sandbox still running would
 * lose its mount points. Branch on `.code`, never on `.message`, which
 * carries the sizes of the moment. Other wrap-time failures (a shell that is
 * not on PATH, a bridge socket that is gone) are plain Errors.
 */
class LinuxSandboxProfileError extends Error {
  LinuxSandboxProfileError(this.code, this.message, [Object? cause])
    : name = 'LinuxSandboxProfileError' {
    if (cause != null) {
      // Non-enumerable, as a native `cause` is. Once the compile target is
      // ES2022 this is `super(message, { cause })`.
      this.cause = cause;
    }
  }

  final LinuxSandboxProfileErrorCode code;
  Object? cause;
  String message;
  String name;

  @override
  String toString() => 'LinuxSandboxProfileError: $message';
}

/**
 * Thrown by the wrap when the host changed its working directory while the
 * mandatory denies were looked for. Nothing has been handed out or left on
 * the host by then. `SandboxManager` starts the wrap over.
 */
class WorkingDirectoryChanged extends Error {
  WorkingDirectoryChanged()
    : message =
          'The working directory changed while the command was being wrapped',
      name = 'WorkingDirectoryChanged';

  String message;
  String name;

  @override
  String toString() => 'WorkingDirectoryChanged: $message';
}

/**
 * The shell string that runs bwrap with `bwrapArgs`, which the caller runs
 * as one argument of `sh -c`. When that would not fit the kernel's
 * per-argument cap, the words in `mounts` (a slice of `bwrapArgs`) go to an
 * unnamed file this process holds open (see `bwrapArgsFds`) and bwrap reads
 * them through `--args` at the same position; the string opens that file
 * again through /proc. Every other word, the per-command environment and the
 * command among them, stays on the line. The result stays a simple command,
 * so a prefix (`exec`, `timeout 30`) or a suffix (`&& next`) still composes.
 * Throws {@link LinuxSandboxProfileError} when the profile cannot run.
 */
String _renderBwrapInvocation(
  String bwrapBinary,
  List<String> bwrapArgs,
  ({int start, int end, int mandatoryDenyArgs}) mounts,
) {
  // Whose the arguments are and what lowers each share: the mandatory denies
  // follow from what the working directory holds, not from the configuration.
  String shares() =>
      '${mounts.mandatoryDenyArgs} of its arguments are built-in write protection, in no list of the configuration: shell and tool settings and each git repository\'s hooks and config, in and below the working directory, and the directories holding them. For fewer, run from a directory with fewer repositories in it, or allow writing to fewer of them; a lower mandatoryDenySearchDepth leaves the deeper ones unprotected. The other ${bwrapArgs.length - mounts.mandatoryDenyArgs} are what the configuration expands to: each path takes about three arguments, each environment variable two';
  if (bwrapArgs.length > _BWRAP_MAX_ARGS) {
    throw LinuxSandboxProfileError(
      'too_many_arguments',
      'Sandbox profile has ${bwrapArgs.length} bwrap arguments and bwrap accepts at most $_BWRAP_MAX_ARGS (about ${_BWRAP_MAX_ARGS ~/ 3} mounts). ${shares()}',
    );
  }
  final mountWords = bwrapArgs.sublist(mounts.start, mounts.end);
  // A command line ends at a NUL and bwrap splits an args file on one, so the
  // word is cut short on the line and becomes several options in the file.
  if (mountWords.any((word) => word.contains('\x00'))) {
    throw LinuxSandboxProfileError(
      'nul_in_path',
      'Sandbox profile contains a path with a NUL byte, which neither a command line nor a file of bwrap arguments can carry',
    );
  }
  final inline = quote([bwrapBinary, ...bwrapArgs]);
  final inlineBytes = Buffer.byteLength(inline, 'utf8');
  final limit = _maxArgStrlen() - 1;
  if (inlineBytes <= limit - _ARG_HEADROOM_BYTES) {
    return inline;
  }

  final tooLong =
      'Sandbox profile is too long for the command line ($inlineBytes bytes; past ${limit - _ARG_HEADROOM_BYTES} it goes through a file)';
  // `--args <fd>` are two more words.
  if (bwrapArgs.length + 2 > _BWRAP_MAX_ARGS) {
    throw LinuxSandboxProfileError(
      'too_many_arguments',
      '$tooLong and, passed through a file, would exceed the $_BWRAP_MAX_ARGS arguments bwrap accepts. ${shares()}',
    );
  }
  int argsFd;
  try {
    argsFd = _openBwrapArgsProfile(mountWords);
  } catch (error) {
    throw LinuxSandboxProfileError(
      'args_file_unavailable',
      '$tooLong and cannot be passed through a file: ${_errorText(error)}',
      error,
    );
  }
  // /bin/sh opens the profile on the fd and execs bwrap, which reads it to
  // EOF and closes it before running the command.
  final viaArgsFile = quote([
    '/bin/sh',
    '-c',
    'exec $_BWRAP_ARGS_FD<"\$1" && shift && exec "\$@"',
    'srt-args',
    _bwrapArgsProfilePath(argsFd),
    bwrapBinary,
    ...bwrapArgs.sublist(0, mounts.start),
    '--args',
    '$_BWRAP_ARGS_FD',
    ...bwrapArgs.sublist(mounts.end),
  ]);
  final viaArgsFileBytes = Buffer.byteLength(viaArgsFile, 'utf8');
  if (viaArgsFileBytes > limit) {
    _closeBwrapArgsProfile(argsFd);
    throw LinuxSandboxProfileError(
      'command_too_long',
      'Sandboxed command is too long for one shell argument even with the mounts passed through a file ($viaArgsFileBytes bytes; the limit here is $limit)',
    );
  }
  logForDebugging(
    '[Sandbox Linux] bwrap mounts moved to an unnamed file, read through ${_bwrapArgsProfilePath(argsFd)} on bwrap\'s fd $_BWRAP_ARGS_FD: the command line would be $inlineBytes bytes as one argument',
  );
  return viaArgsFile;
}

// Number of wrapped commands that have been generated but whose cleanup has
// not yet run. cleanupBwrapMountPoints() defers file deletion while this is
// positive, because deleting a mount point file on the host while another
// bwrap instance is still running detaches that instance's bind mount and
// the deny rule stops applying inside it.
var _activeSandboxCount = 0;

// Forced cleanups so far. One zeroes the count under a wrap still in flight,
// which from then on has nothing in it to give back.
var _forcedCleanups = 0;

var _exitHandlerRegistered = false;

/**
 * Register cleanup handler for bwrap mount points
 */
void _registerExitCleanupHandler() {
  if (_exitHandlerRegistered) {
    return;
  }

  process.on('exit', () {
    cleanupBwrapMountPoints(force: true);
  });

  _exitHandlerRegistered = true;
}

/**
 * Clean up mount point files created by bwrap for non-existent deny paths.
 *
 * When protecting non-existent deny paths, bwrap creates empty files on the
 * host filesystem as mount points for --ro-bind. These files persist after
 * bwrap exits. This function removes them.
 *
 * This should be called after each sandboxed command completes to prevent
 * ghost dotfiles (e.g. .bashrc, .gitconfig) from appearing in the working
 * directory. It is also called automatically on process exit as a safety net.
 *
 * Each call decrements the active-sandbox counter that was incremented by
 * wrapCommandWithSandboxLinux(). File deletion is deferred until the counter
 * reaches zero. Deleting a mount point file on the host while another bwrap
 * instance is still running detaches that instance's bind mount (the dentry
 * is unhashed, so path lookup no longer finds the mount) and the deny rule
 * stops applying inside that sandbox.
 *
 * Pass `{ force: true }` to delete unconditionally — used by the process-exit
 * handler and reset() where deferral is not meaningful.
 *
 * Also closes the `--args` profiles the wraps of this batch opened.
 */
void cleanupBwrapMountPoints({bool? force}) {
  if (!(force ?? false)) {
    if (_activeSandboxCount > 0) {
      _activeSandboxCount--;
    }
    if (_activeSandboxCount > 0) {
      logForDebugging(
        '[Sandbox Linux] Deferring mount point cleanup — $_activeSandboxCount sandbox(es) still active',
      );
      return;
    }
  } else {
    _activeSandboxCount = 0;
    _forcedCleanups++;
  }

  // Deepest first: a sandbox wrapped while another's directory mount point is
  // there gets its own inside it, and a directory goes only when it is empty.
  // Dart: List.sort is not stable, so ties keep their order by index.
  final deepestFirst =
      ([..._bwrapMountPoints.indexed]..sort((a, b) {
            final d = b.$2.length - a.$2.length;
            return d != 0 ? d : a.$1 - b.$1;
          }))
          .map((e) => e.$2);
  for (final mountPoint in deepestFirst) {
    try {
      // Only remove if it's still the empty file/directory bwrap created.
      // If something else has written real content, leave it alone.
      final stat = fs.statSync(mountPoint);
      if (stat.isFile() && stat.size == 0) {
        fs.unlinkSync(mountPoint);
        logForDebugging(
          '[Sandbox Linux] Cleaned up bwrap mount point (file): $mountPoint',
        );
      } else if (stat.isDirectory()) {
        // Empty directory mount points are created for intermediate
        // components (Fix 2). Only remove if still empty.
        final entries = fs.readdirSync(mountPoint);
        if (entries.isEmpty) {
          fs.rmdirSync(mountPoint);
          logForDebugging(
            '[Sandbox Linux] Cleaned up bwrap mount point (dir): $mountPoint',
          );
        }
      }
    } catch (_) {
      // Ignore cleanup errors — the file may have already been removed
    }
  }
  _bwrapMountPoints.clear();
  if (_emptyMountSourceDir != null) {
    try {
      // rmdirSync, not a recursive remove: it neither follows a symlink nor
      // descends, so a path that is no longer our empty directory is left
      // exactly as found.
      fs.rmdirSync(_emptyMountSourceDir!);
      logForDebugging(
        '[Sandbox Linux] Cleaned up the empty-directory mount source: $_emptyMountSourceDir',
      );
      _emptyMountSourceDir = null;
    } catch (err) {
      final code = err is NodeError ? err.code : null;
      if (code == 'ENOTEMPTY') {
        logForDebugging(
          '[Sandbox Linux] Left the empty-directory mount source behind, something has written into it: $_emptyMountSourceDir',
        );
      }
      // Forget the path only when there is nothing left to remove. ENOTEMPTY,
      // EACCES and EBUSY (a forced cleanup while a live sandbox still pins the
      // source) leave it ours to try again; the revalidation on next use
      // decides whether it can be reused.
      if (code == 'ENOENT' || code == 'ENOTDIR') {
        _emptyMountSourceDir = null;
      }
    }
  }

  for (final argsFd in [..._bwrapArgsFds]) {
    _closeBwrapArgsProfile(argsFd);
  }
}

/**
 * Detailed status of Linux sandbox dependencies
 */
class LinuxDependencyStatus {
  final bool hasBwrap;
  final bool hasSocat;
  final bool hasSeccompApply;

  const LinuxDependencyStatus({
    required this.hasBwrap,
    required this.hasSocat,
    required this.hasSeccompApply,
  });
}

/**
 * Result of checking sandbox dependencies
 */
class SandboxDependencyCheck {
  final List<String> warnings;
  final List<String> errors;

  /** Windows: the error in `errors` that asks for the install to be re-run. */
  final String? reinstallRequired;
  /**
   * Windows: the error in `errors` that says the installed loopback mode
   * is not the configured `network.allowLocalBinding`.
   */
  final String? loopbackMismatch;

  const SandboxDependencyCheck({
    required this.warnings,
    required this.errors,
    this.reinstallRequired,
    this.loopbackMismatch,
  });
}

/**
 * Options for Linux dependency checks. Explicit binary paths, when set,
 * are checked directly instead of resolving via PATH.
 */
class LinuxDependencyOptions {
  final SeccompConfig? seccompConfig;
  final String? bwrapPath;
  final String? socatPath;

  const LinuxDependencyOptions({
    this.seccompConfig,
    this.bwrapPath,
    this.socatPath,
  });
}

bool _isExecutable(String p) {
  try {
    fs.accessSync(p, fs.constants.X_OK);
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * Get detailed status of Linux sandbox dependencies
 */
LinuxDependencyStatus getLinuxDependencyStatus({
  SeccompConfig? seccompConfig,
  String? bwrapPath,
  String? socatPath,
}) {
  // argv0 mode: apply-seccomp is compiled into the caller's binary — skip
  // the on-disk lookup and trust that applyPath resolves inside bwrap.
  return LinuxDependencyStatus(
    hasBwrap: bwrapPath != null && bwrapPath.isNotEmpty
        ? _isExecutable(bwrapPath)
        : whichSync('bwrap') != null,
    hasSocat: socatPath != null && socatPath.isNotEmpty
        ? _isExecutable(socatPath)
        : whichSync('socat') != null,
    hasSeccompApply:
        seccompConfig?.argv0 != null && seccompConfig!.argv0!.isNotEmpty
        ? true
        : getApplySeccompBinaryPath(seccompConfig?.applyPath) != null,
  );
}

/**
 * Check sandbox dependencies and return structured result
 */
SandboxDependencyCheck checkLinuxDependencies({
  SeccompConfig? seccompConfig,
  String? bwrapPath,
  String? socatPath,
}) {
  final errors = <String>[];
  final warnings = <String>[];

  // An explicit override is a directive, not a hint — if it doesn't exist,
  // surface that rather than silently falling back to PATH.
  String? usableBwrap;
  if (bwrapPath != null && bwrapPath.isNotEmpty) {
    if (_isExecutable(bwrapPath))
      usableBwrap = bwrapPath;
    else
      errors.add('bubblewrap (bwrap) not executable at $bwrapPath');
  } else {
    usableBwrap = whichSync('bwrap');
    if (usableBwrap == null) errors.add('bubblewrap (bwrap) not installed');
  }

  if (socatPath != null && socatPath.isNotEmpty) {
    if (!_isExecutable(socatPath))
      errors.add('socat not executable at $socatPath');
  } else if (whichSync('socat') == null) {
    errors.add('socat not installed');
  }

  if (!(seccompConfig?.argv0 != null && seccompConfig!.argv0!.isNotEmpty) &&
      getApplySeccompBinaryPath(seccompConfig?.applyPath) == null) {
    warnings.add('seccomp not available - unix socket access not restricted');
  }

  final uid0Error = uid0SandboxError(
    euid: process.geteuid?.call(),
    hasSetfcap: processHasBoundingCapability(CAP_SETFCAP),
    bwrap: usableBwrap,
  );
  if (uid0Error != null) errors.add(uid0Error);

  final outdated = _outdatedBwrapWarning(usableBwrap);
  if (outdated != null) warnings.add(outdated);

  return SandboxDependencyCheck(warnings: warnings, errors: errors);
}

/**
 * The oldest bubblewrap on which everything this library does holds. Mount
 * plans start on 0.4.0 and later, but before 0.5.0 `ensure_file()` takes
 * only a regular file as a file bind's mount point, so a mask on a fifo,
 * socket or device node blocks or fails.
 */
const String OLDEST_FULLY_SUPPORTED_BWRAP_VERSION = '0.5.0';

// Keyed by path, so a caller that passes an explicit bwrapPath is not
// answered for another binary. A probe that got no answer is kept too, as
// null: it can block for the whole timeout, and callers ask several times
// during one start-up.
// INVARIANT: the version decides a warning and nothing else. No mount plan may
// rest on it: one slow start would then decide for the life of the process.
final _bwrapVersions = <String, String?>{};

/** The version `bwrap --version` reports, or null when it could not be asked. */
String? _probeBwrapVersion(String bwrap) {
  if (_bwrapVersions.containsKey(bwrap)) return _bwrapVersions[bwrap];

  final probe = spawnSync(
    bwrap,
    ['--version'],
    {
      'timeout': 5000,
      'stdio': ['ignore', 'pipe', 'ignore'],
      'encoding': 'utf8',
    },
  );
  final version = probe.error == null && probe.status == 0
      ? (RegExp(r'\d+(?:\.\d+)*')
            .firstMatch((probe.stdout as String?) ?? '')?[0])
      : null;
  _bwrapVersions[bwrap] = version;
  return version;
}

/** Negative when `a` is the older version. A missing or unreadable component
 * counts as 0, so '0.5' and '0.5.0' compare equal. */
int _compareVersions(String a, String b) {
  List<int> partsOf(String version) => version.split('.').map((part) {
    // Dart: int.tryParse takes no leading digits of '5a' as parseInt does.
    final parsed = int.tryParse(
      RegExp(r'^\s*[+-]?\d+').firstMatch(part)?[0]?.trim() ?? '',
    );
    return parsed ?? 0;
  }).toList();
  final left = partsOf(a);
  final right = partsOf(b);
  for (
    var i = 0;
    i < (left.length > right.length ? left.length : right.length);
    i++
  ) {
    final difference =
        (i < left.length ? left[i] : 0) - (i < right.length ? right[i] : 0);
    if (difference != 0) return difference;
  }
  return 0;
}

/**
 * A warning naming a bubblewrap older than
 * OLDEST_FULLY_SUPPORTED_BWRAP_VERSION, and what that costs. Not an error:
 * the sandbox starts and enforces on it. A version that could not be asked
 * for is not reported: a guess would be noise on every run.
 */
String? _outdatedBwrapWarning(String? bwrap) {
  if (bwrap == null) return null;
  final version = _probeBwrapVersion(bwrap);
  if (version == null ||
      _compareVersions(version, OLDEST_FULLY_SUPPORTED_BWRAP_VERSION) >= 0) {
    return null;
  }
  return 'bubblewrap $version at $bwrap is older than ' +
      '$OLDEST_FULLY_SUPPORTED_BWRAP_VERSION: a denyRead entry or credential ' +
      'mask naming a path that is not a regular file (a fifo, socket or device ' +
      'node) cannot be applied on it. Everything else is unaffected';
}

/**
 * Predict, then confirm. The prediction — uid 0 with no CAP_SETFCAP to hand
 * to bwrap — is exact about the capability but not about the kernel, so ask
 * bubblewrap itself before failing the caller's initialize(). An error, not a
 * warning: if it holds, every sandboxed command fails.
 *
 * `bwrap === null` skips the probe: a missing or unusable bubblewrap is
 * already its own dependency error, and a second one about capabilities would
 * only misdirect.
 */
String? uid0SandboxError({
  required int? euid,
  required bool hasSetfcap,
  required String? bwrap,
}) {
  if (euid != 0 || hasSetfcap || bwrap == null) return null;
  final refusal = _probeUid0UserNamespace(bwrap);
  if (refusal == null) return null;
  return refusal == ''
      ? CAP_SETFCAP_MISSING_MESSAGE
      : '$CAP_SETFCAP_MISSING_MESSAGE (bubblewrap: $refusal)';
}

// One probe result per bwrap binary: whether a uid-0 map is refused is a
// property of the kernel and the binary, not of the moment. Keyed by path so
// a caller that passes an explicit bwrapPath is not answered for another one.
final _uid0UserNamespaceProbes = <String, String?>{};

/**
 * Run `bwrap --unshare-user --dev-bind / / true` once and report whether this
 * kernel actually refuses to map uid 0. `null` means it does not, so there is
 * nothing to report; otherwise bubblewrap's own first stderr line, or the
 * empty string when the probe could not be run at all and the prediction
 * stands unaided.
 */
String? _probeUid0UserNamespace(String bwrap) {
  if (_uid0UserNamespaceProbes.containsKey(bwrap)) {
    return _uid0UserNamespaceProbes[bwrap];
  }

  final probe = spawnSync(
    bwrap,
    ['--unshare-user', '--dev-bind', '/', '/', 'true'],
    {
      'timeout': 5000,
      'stdio': ['ignore', 'ignore', 'pipe'],
      'encoding': 'utf8',
    },
  );
  final refusal = probe.error == null && probe.status == 0
      ? null
      : (((probe.stderr as String?) ?? '')
                .split('\n')
                .map((line) => line.trim())
                .where((line) => line.isNotEmpty)
                .map(
                  (line) => line.length > 200 ? line.substring(0, 200) : line,
                )
                .firstOrNull ??
            '');
  _uid0UserNamespaceProbes[bwrap] = refusal;
  return refusal;
}

/**
 * Initialize the Linux network bridge for sandbox networking
 *
 * ARCHITECTURE NOTE:
 * Linux network sandboxing uses bwrap --unshare-net which creates a completely isolated
 * network namespace with NO network access. To enable network access, we:
 *
 * 1. Host side: Run socat bridges that listen on Unix sockets and forward to host proxy servers
 *    - HTTP bridge: Unix socket -> host HTTP proxy (for HTTP/HTTPS traffic)
 *    - SOCKS bridge: Unix socket -> host SOCKS5 proxy (for SSH/git traffic)
 *
 * 2. Sandbox side: Bind the Unix sockets into the isolated namespace and run socat listeners
 *    - HTTP listener on port 3128 -> HTTP Unix socket -> host HTTP proxy
 *    - SOCKS listener on port 1080 -> SOCKS Unix socket -> host SOCKS5 proxy
 *
 * 3. Configure environment:
 *    - HTTP_PROXY=http://localhost:3128 for HTTP/HTTPS tools
 *    - GIT_SSH_COMMAND with socat for SSH through SOCKS5
 *
 * LIMITATION: Unlike macOS sandbox which can enforce domain-based allowlists at the kernel level,
 * Linux's --unshare-net provides only all-or-nothing network isolation. Domain filtering happens
 * at the host proxy level, not the sandbox boundary. This means network restrictions on Linux
 * depend on the proxy's filtering capabilities.
 *
 * DEPENDENCIES: Requires bwrap (bubblewrap) and socat
 */
Future<LinuxNetworkBridgeContext> initializeLinuxNetworkBridge(
  int httpProxyPort,
  int socksProxyPort, [
  String? socatPath,
]) async {
  final socat = socatPath ?? 'socat';
  final socketId = randomBytes(8).toString('hex');
  final httpSocketPath = path.join(tmpdir(), 'claude-http-$socketId.sock');
  // Only allocated when ports differ; in the mux case the SOCKS side
  // reuses httpSocketPath.
  final socksSocketPath = path.join(tmpdir(), 'claude-socks-$socketId.sock');

  // Start HTTP bridge
  final httpSocatArgs = [
    'UNIX-LISTEN:$httpSocketPath,fork,reuseaddr',
    'TCP:localhost:$httpProxyPort,keepalive,keepidle=10,keepintvl=5,keepcnt=3',
  ];

  logForDebugging('Starting HTTP bridge: $socat ${httpSocatArgs.join(' ')}');

  final httpBridgeProcess = spawn(socat, httpSocatArgs, {'stdio': 'ignore'});

  // Add error and exit handlers to monitor bridge health. These must be
  // registered before the !pid check: when spawn fails (e.g. socat is
  // missing or not executable), the ChildProcess emits an asynchronous
  // 'error' event, and throwing first would leave that event without a
  // listener — surfacing as an uncaughtException instead of the rejection
  // below.
  httpBridgeProcess.on('error', (Object? err) {
    logForDebugging('HTTP bridge process error: $err', level: 'error');
  });
  httpBridgeProcess.on('exit', (Object? code, Object? signal) {
    logForDebugging(
      'HTTP bridge process exited with code $code, signal $signal',
      level: code == 0 ? 'info' : 'error',
    );
  });

  if (httpBridgeProcess.pid == null || httpBridgeProcess.pid == 0) {
    throw NodeException('Failed to start HTTP bridge process');
  }

  // SOCKS bridge: when the host serves both protocols on one port (the mux),
  // a second socat to the same TCP target is redundant — reuse the HTTP
  // bridge's process and socket path. Downstream consumers
  // (LinuxNetworkBridgeContext, in-sandbox socat, cleanup) treat duplicate
  // refs idempotently. A separate bridge is only spawned when the ports
  // differ (external proxy override).
  child_process.NodeChildProcess socksBridgeProcess;
  String socksSockPath;
  if (socksProxyPort == httpProxyPort) {
    socksBridgeProcess = httpBridgeProcess;
    socksSockPath = httpSocketPath;
  } else {
    socksSockPath = socksSocketPath;
    final socksSocatArgs = [
      'UNIX-LISTEN:$socksSocketPath,fork,reuseaddr',
      'TCP:localhost:$socksProxyPort,keepalive,keepidle=10,keepintvl=5,keepcnt=3',
    ];

    logForDebugging(
      'Starting SOCKS bridge: $socat ${socksSocatArgs.join(' ')}',
    );

    socksBridgeProcess = spawn(socat, socksSocatArgs, {'stdio': 'ignore'});

    // Add error and exit handlers to monitor bridge health — registered
    // before the !pid check for the same reason as the HTTP bridge above.
    socksBridgeProcess.on('error', (Object? err) {
      logForDebugging('SOCKS bridge process error: $err', level: 'error');
    });
    socksBridgeProcess.on('exit', (Object? code, Object? signal) {
      logForDebugging(
        'SOCKS bridge process exited with code $code, signal $signal',
        level: code == 0 ? 'info' : 'error',
      );
    });

    if (socksBridgeProcess.pid == null || socksBridgeProcess.pid == 0) {
      // Clean up HTTP bridge
      if (httpBridgeProcess.pid != null && httpBridgeProcess.pid != 0) {
        try {
          process.kill(httpBridgeProcess.pid!, 'SIGTERM');
        } catch (_) {
          // Ignore errors
        }
      }
      throw NodeException('Failed to start SOCKS bridge process');
    }
  }

  // Wait for both sockets to be ready
  const maxAttempts = 5;
  for (var i = 0; i < maxAttempts; i++) {
    if (httpBridgeProcess.pid == null ||
        httpBridgeProcess.pid == 0 ||
        httpBridgeProcess.killed ||
        socksBridgeProcess.pid == null ||
        socksBridgeProcess.pid == 0 ||
        socksBridgeProcess.killed) {
      throw NodeException('Linux bridge process died unexpectedly');
    }

    try {
      // fs already imported
      if (fs.existsSync(httpSocketPath) && fs.existsSync(socksSockPath)) {
        logForDebugging('Linux bridges ready after ${i + 1} attempts');
        break;
      }
    } catch (err) {
      logForDebugging(
        'Error checking sockets (attempt ${i + 1}): $err',
        level: 'error',
      );
    }

    if (i == maxAttempts - 1) {
      // Clean up both processes
      if (httpBridgeProcess.pid != null && httpBridgeProcess.pid != 0) {
        try {
          process.kill(httpBridgeProcess.pid!, 'SIGTERM');
        } catch (_) {
          // Ignore errors
        }
      }
      if (socksBridgeProcess.pid != null && socksBridgeProcess.pid != 0) {
        try {
          process.kill(socksBridgeProcess.pid!, 'SIGTERM');
        } catch (_) {
          // Ignore errors
        }
      }
      throw NodeException(
        'Failed to create bridge sockets after $maxAttempts attempts',
      );
    }

    await Future<void>.delayed(Duration(milliseconds: i * 100));
  }

  return LinuxNetworkBridgeContext(
    httpSocketPath: httpSocketPath,
    socksSocketPath: socksSockPath,
    httpBridgeProcess: httpBridgeProcess,
    socksBridgeProcess: socksBridgeProcess,
    httpProxyPort: httpProxyPort,
    socksProxyPort: socksProxyPort,
  );
}

/**
 * Read by the seccomp helper, never by this process. The write denies are
 * read-only binds, and a bind protects a path only in the mount namespace it
 * was made in. Creating a user namespace takes no capability and gives a full
 * set over a private copy of the mount tree, from which the binds can be
 * detached all at once; a directory opened beforehand then reaches the denied
 * names. So by default the helper refuses the calls with a seccomp filter and
 * sets user.max_user_namespaces to zero in the namespace it made. `1` lifts
 * both. A wrap with no helper gives bubblewrap --disable-userns instead.
 */
const _NESTED_USERNS_ENV = 'SRT_ALLOW_NESTED_USERNS';

/**
 * The assignment the helper's command line starts with, so that the variable
 * holds what the configuration says: the wrap reaches the helper through a
 * shell, whose start-up files (BASH_ENV) could set it after bubblewrap cleared
 * it, and an assignment before a command is made after those.
 */
String _helperEnvironmentPrefix(bool allowNestedUserNamespaces) {
  return '$_NESTED_USERNS_ENV=${allowNestedUserNamespaces ? '1' : '0'} ';
}

// Keyed by path, like the uid-0 probe. Only an answer is kept: a probe that
// failed is made again the next time.
final _disableUsernsProbes = <String, bool>{};

/**
 * Whether this bubblewrap lists --disable-userns (0.8.0 and later) and can
 * honour it: a setuid bubblewrap refuses the option outright.
 */
bool bwrapCanDisableUserns(String bwrap) {
  final cached = _disableUsernsProbes[bwrap];
  if (cached != null) return cached;
  var can = false;
  try {
    if ((fs.statSync(bwrap).mode & 2048) == 0) {
      final help = spawnSync(
        bwrap,
        ['--help'],
        {
          'timeout': 5000,
          'stdio': ['ignore', 'pipe', 'pipe'],
          'encoding': 'utf8',
        },
      );
      final text = '${help.stdout ?? ''}${help.stderr ?? ''}';
      if (help.error != null || text.trim().isEmpty) return false;
      can = text.contains('--disable-userns');
    }
  } catch (_) {
    return false;
  }
  _disableUsernsProbes[bwrap] = can;
  return can;
}

var _noUsernsLimitLogged = false;

/**
 * Resolve how to invoke apply-seccomp: either a standalone binary path, or a
 * multicall-binary prefix that dispatches on the ARGV0 env var.
 *
 * Returns a shell-ready string ending in a trailing space — callers append
 * quote([shell, '-c', cmd]). Returns undefined when seccomp is
 * unavailable (no argv0, no binary found).
 *
 * When argv0 is set, applyPath is used verbatim (no existence check); the
 * caller is responsible for ensuring it resolves inside the bwrap namespace.
 */
String? _resolveApplySeccompPrefix(String? applyPath, String? argv0) {
  if (argv0 != null && argv0.isNotEmpty) {
    if (applyPath == null || applyPath.isEmpty) {
      throw NodeException(
        'seccompConfig.argv0 requires seccompConfig.applyPath',
      );
    }
    return 'ARGV0=${quote([argv0])} ${quote([applyPath])} ';
  }
  final binary = getApplySeccompBinaryPath(applyPath);
  return binary != null && binary.isNotEmpty ? '${quote([binary])} ' : null;
}

/**
 * Shell lines that return once both relays listen, given their process ids in
 * `$_srt_http` and `$_srt_socks`. The relays are started in the background,
 * and a command that connects at once got there first: its first connection
 * was refused.
 *
 * The network namespace counts its TCP sockets in use, and a listening one
 * counts from the moment it listens. The namespace is new and only the two
 * relays make a socket in it before the command runs, one each, so two in
 * use are the two relays listening. Not `/proc/net/tcp`, which names the
 * ports: one read of it walks the host's whole connection table (5 ms on a
 * machine with 256 GB).
 *
 * It gives up, and the command starts as it did before, when a relay has
 * exited, when a file cannot be read, and after 0.3 s by `/proc/uptime`,
 * which counts in hundredths (the `1` in front keeps a leading zero from
 * being read as octal).
 *
 * INVARIANT: these lines start no program. They run before the seccomp
 * filter is on, so anything found on `PATH` here would run without it. That
 * is why they poll without a pause: `sleep` is a program in all three
 * shells.
 *
 * No `!`: shell-quote would put a backslash before it that the shell keeps.
 * No `%1`: dash resolves no job outside an interactive shell.
 */
const _RELAYS_LISTEN = [
  r'_srt_since=',
  r'while [ -r /proc/net/sockstat ] && kill -0 "$_srt_http" "$_srt_socks" 2>/dev/null; do',
  r'  _srt_up=0',
  r'  for _srt_counts in /proc/net/sockstat /proc/net/sockstat6; do',
  r'    [ -r "$_srt_counts" ] || continue',
  r'    while read -r _srt_kind _srt_skip _srt_inuse _srt_skip; do',
  r'      case "$_srt_kind" in TCP: | TCP6:) _srt_up=$((_srt_up + _srt_inuse)); break ;; esac',
  r'    done < "$_srt_counts"',
  r'  done',
  r'  [ "$_srt_up" -lt 2 ] || break',
  r'  read -r _srt_now _srt_skip 2>/dev/null < /proc/uptime || break',
  r'  _srt_now=1${_srt_now%.*}${_srt_now#*.}',
  r'  [ "$((_srt_now - ${_srt_since:=$_srt_now}))" -lt 30 ] || break',
  r'done',
  r'unset _srt_since _srt_now _srt_up _srt_counts _srt_kind _srt_skip _srt_inuse _srt_http _srt_socks',
];

/**
 * Build the command that runs inside the sandbox.
 * Sets up HTTP proxy on port 3128 and SOCKS proxy on port 1080
 */
String _buildSandboxCommand(
  String httpSocketPath,
  String socksSocketPath,
  String userCommand,
  String? applySeccompPrefix, [
  String? shell,
  String? socatPath,
]) {
  // Default to bash for backward compatibility
  final shellPath = shell != null && shell.isNotEmpty ? shell : 'bash';
  // Host filesystem is bind-mounted into the sandbox, so an explicit
  // socatPath resolves to the same binary inside bwrap.
  final socat = quote([socatPath ?? 'socat']);
  // socat's own backlog is 5. A connection that finds the queue full is
  // dropped, and tried again after 1 s, then 2 s, 4 s and so on: of a package
  // installer's burst, some wait for a minute. The kernel caps the number.
  const listen = 'fork,reuseaddr,backlog=4096';
  // Which family a plain TCP-LISTEN takes is socat's choice, and differs by
  // version. One that takes IPv6 exits at once on a kernel that has none, and
  // nothing listens; one that takes IPv4 refuses a client to which `localhost`
  // is ::1 and that tries no second address. So the family is named: IPv6 with
  // IPv4 mapped in, which serves both, and IPv4 alone where that fails.
  String relay(int port, String socketPath) =>
      '{ $socat TCP6-LISTEN:$port,ipv6only=0,$listen UNIX-CONNECT:$socketPath || ' +
      'exec $socat TCP4-LISTEN:$port,$listen UNIX-CONNECT:$socketPath; } >/dev/null 2>&1 &';
  final socatCommands = [
    relay(3128, httpSocketPath),
    r'_srt_http=$!',
    relay(1080, socksSocketPath),
    r'_srt_socks=$!',
    // The trap saves the status the script is exiting with and exits with
    // it. A bare `exit` inside an EXIT trap is not portable: bash and dash
    // keep the script's status, zsh takes the status of the trap's own last
    // command (the kill), so under zsh a failing command reported 0. Single
    // quotes, so $? and $rc are read when the trap runs, not when it is set.
    r"trap 'rc=$?; kill %1 %2 2>/dev/null; exit $rc' EXIT",
    ..._RELAYS_LISTEN,
  ];

  // apply-seccomp runs after socat so socat can still create Unix sockets.
  if (applySeccompPrefix != null && applySeccompPrefix.isNotEmpty) {
    final applySeccompCmd =
        applySeccompPrefix + quote([shellPath, '-c', userCommand]);
    final innerScript = [...socatCommands, applySeccompCmd].join('\n');
    return '$shellPath -c ${quote([innerScript])}';
  } else {
    final innerScript = [
      ...socatCommands,
      'eval ${quote([userCommand])}',
    ].join('\n');
    return '$shellPath -c ${quote([innerScript])}';
  }
}

/**
 * The three classes an fs errno from a path lookup falls into, enumerated
 * once because each leads somewhere different: ABSENCE, where the name
 * resolves to no file and every consumer already treats the path as absent
 * (isAbsenceErrno, in sandbox-utils.ts, where the glob walk classifies the
 * same failures); TRANSIENT, a busy, unlucky or re-exporting host rather
 * than a fact about the path, worth asking once more before the failure is
 * taken for an answer; and SETTLED, a file that is there and cannot be
 * looked at, and will not become readable while this wrap runs. Every code
 * neither predicate names is settled, because nothing says it clears.
 */
bool _isTransientErrno(Object? err) {
  final code = err is NodeError ? err.code : null;
  return code == 'EIO' ||
      code == 'ESTALE' ||
      code == 'EMFILE' ||
      code == 'ENFILE' ||
      code == 'EAGAIN';
}

/**
 * `attempt`, asked a second time when the first failure was transient and
 * rethrown otherwise. Two caveats come with the second ask: a same-tick retry
 * cannot clear descriptor exhaustion (EMFILE, ENFILE), so for those it is
 * best effort. And on a soft-mounted network filesystem that is down, a
 * transient-class errno arrives only after the mount's own timeout, so the
 * retry can double that stall — a hard mount never returns at all, so the
 * retry never runs there.
 */
T _retryingTransient<T>(T Function() attempt) {
  try {
    return attempt();
  } catch (err) {
    if (!_isTransientErrno(err)) rethrow;
  }
  return attempt();
}

/** The top-level directories this wrap leaves to the kernel and to the
 * caller's own remounts. A cover must never take one — --proc and --dev
 * replace two of them after the pins are spliced in, and /sys is kernel
 * state — and the '/' read-deny expansion must not hide one either. */
const _KERNEL_TOP_LEVEL_DIRS = ['/proc', '/dev', '/sys'];

/**
 * A self-bind ("pin") for every directory between a seed (where a deny bind,
 * file mask or read-deny tmpfs lands) and the allowed write root covering it,
 * shallow-first, which makes each one a mountpoint the kernel refuses to
 * rename or remove. A directory that is not there is skipped: bwrap cannot
 * bind a missing source and there is nothing to rename. One that exists but
 * cannot be inspected is still pinned, and if bwrap cannot bind it either the
 * sandbox does not start, which is where the deny loop lands too.
 *
 * Pins are read-only and spliced in beneath every other mount, so that one
 * landing on top of an allowed write root cannot make it read-only; a write
 * root needs no pin of its own there, its allow bind already being a live
 * mountpoint.
 *
 * A '/' write root defeats that: its own recursive `--bind / /` is one of the
 * mounts above the pins and buries them, leaving those directories renamable.
 * Under one the pins therefore go AFTER the allow binds and take every
 * ancestor, the other allowed write roots included, stopping below the
 * top-level directory D on the chain; a writable `--bind D D` — the cover —
 * takes D itself and buries them again. Lookups enter the cover and never meet
 * a pin, so no filesystem boundary lands inside D, while the kernel's rename
 * and rmdir checks scan mounts by dentry and still find one. The only new
 * boundary is at D. /proc, /dev and /sys are never covered, and a seed under
 * one of them gets no pins.
 */
List<String> _ancestorPinArgs(
  Iterable<String> seeds,
  ({
    bool rootIsWriteRoot,
    bool Function(String dir) isWithinAllowedWrite,
    bool Function(String dir) isAllowedWriteRoot,
  })
  writeRoots,
) {
  final rootIsWriteRoot = writeRoots.rootIsWriteRoot;
  final pinDirs = <String>{};
  final coverDirs = <String>{};
  // Verdicts are seed-independent: a visited ancestor's chain is done.
  final visited = <String>{};
  for (final seed in seeds) {
    if (rootIsWriteRoot &&
        _KERNEL_TOP_LEVEL_DIRS.any((dir) => isAtOrUnder(seed, dir))) {
      continue;
    }
    for (
      var dir = path.dirname(seed);
      dir != '/' &&
          !visited.contains(dir) &&
          writeRoots.isWithinAllowedWrite(dir);
      dir = path.dirname(dir)
    ) {
      visited.add(dir);
      if (rootIsWriteRoot) {
        if (path.dirname(dir) == '/') {
          coverDirs.add(dir);
          continue;
        }
      } else if (writeRoots.isAllowedWriteRoot(dir)) {
        continue;
      }
      try {
        fs.statSync(dir);
      } catch (err) {
        if (isAbsenceErrno(err)) continue;
      }
      pinDirs.add(dir);
    }
  }
  final covers = [...coverDirs];
  if (covers.isNotEmpty) {
    logForDebugging(
      '[Sandbox Linux] Covering the pinned ancestors under: ${covers.join(', ')}',
    );
  }
  return [
    // Dart: List.sort is not stable, so ties keep their order by index.
    ...([...pinDirs.indexed]..sort((a, b) {
          final d = a.$2.split('/').length - b.$2.split('/').length;
          return d != 0 ? d : a.$1 - b.$1;
        }))
        .expand((e) => ['--ro-bind', e.$2, e.$2]),
    ...covers.expand((dir) => ['--bind', dir, dir]),
  ];
}

/** A restore the tmpfs pass emitted: the mount's source and its destination
 * in the sandbox. Both are needed later — the destination says where the
 * path is visible, the source says which inode was vetted for it. */
typedef _RestoredMount = ({String source, String dest});

/**
 * Mount a tmpfs over a read-denied directory, then restore the allowed write
 * paths and allowRead paths the tmpfs just wiped. Returns the mounts it
 * re-bound, writable and read-only, which is what a later pass re-emits when
 * a denyWrite bind re-exposes this directory.
 */
({List<_RestoredMount> restoredWrites, List<_RestoredMount> restoredReads})
_pushReadDenyDirMounts(
  List<String> args,
  ({
    /** Where the tmpfs lands, and the destination bwrap is handed for it:
     *  a read deny is mounted where its path resolves (readDenyMountOf's
     *  landing in the caller), never on a symlink. */
    String landing,
    List<String> allowedWritePaths,
    List<String> readAllowPaths,
    /** Where a path resolves to, and whether that is a resolution at all:
     * an unresolved answer is the spelling itself, which must never become a
     * mount source (canonicalLocationOf in the caller). */
    ({String canonical, bool resolved}) Function(String p) resolve,
    /** What the read section hides at or around a resolved target, other
     * than this tmpfs and the denies above it (readDenialAround bound to
     * this unit's landing in the caller). */
    String? Function(String target) readDenialAround,
    /** Where a path's name lives (nameLocationOf in the caller). */
    String Function(String p) nameLocation,
  })
  unit,
) {
  final landing = unit.landing;
  final allowedWritePaths = unit.allowedWritePaths;
  final readAllowPaths = unit.readAllowPaths;
  args.addAll(['--tmpfs', landing]);

  // How to bind allowed path `p` back, if it is a carve-out of this unit:
  // its name must live inside the denied directory, and so must what it
  // resolves to. Parent directories may be symlinks (/lib/x is a carve-out
  // of a tmpfs on /usr, where /lib is a link to /usr/lib). A path that is
  // itself a symlink INTO the directory is not a carve-out: it names the
  // link, which this tmpfs did not hide, and re-allows nothing the link
  // points at, or a link planted at an allowed path (docs -> ~/.ssh) would
  // cancel the deny of its target.
  //
  // The mount goes back at the NAME (the entry re-allows the name it is, and
  // an entry whose last component is a symlink is ENOENT inside the sandbox
  // if restored only at its target), from the RESOLVED source: that is the
  // path both containment checks were made against, and naming it leaves
  // bwrap nothing to re-resolve at mount time.
  _RestoredMount? restorePlacementOf(String p) {
    final dest = unit.nameLocation(p);
    if (!isAtOrUnder(dest, landing)) return null;
    final (canonical: source, resolved: resolved) = unit.resolve(p);
    if (!resolved) {
      logForDebugging(
        '[Sandbox Linux] Not restoring $p over denyRead tmpfs $landing: nothing there resolves (absent, dangling or unreadable), so the only source available is the name itself',
        level: 'warn',
      );
      return null;
    }
    if (!isAtOrUnder(source, landing)) {
      logForDebugging(
        '[Sandbox Linux] Not restoring $p over denyRead tmpfs $landing: it resolves outside it, to $source',
        level: 'warn',
      );
      return null;
    }
    // Restoring at the name from a DIFFERENT path is a second mount of the
    // target's inode, which nothing landing on the target's own path covers,
    // so such a restore is dropped whenever the read section hides anything
    // at, inside or around that target: the deny wins, and the follow-up that
    // gives the carve-out back has to bind the target at the target.
    if (source != dest) {
      final denied = unit.readDenialAround(source);
      if (denied != null) {
        logForDebugging(
          '[Sandbox Linux] Not restoring $p over denyRead tmpfs $landing: it resolves to $source, and the read section denies or masks $denied',
          level: 'warn',
        );
        return null;
      }
    }
    return (source: source, dest: dest);
  }

  // tmpfs wiped any earlier write binds under this path — restore them.
  final restoredWrites = <_RestoredMount>[];
  for (final writePath in allowedWritePaths) {
    final placement = restorePlacementOf(writePath);
    if (placement == null) continue;
    args.addAll(['--bind', placement.source, placement.dest]);
    restoredWrites.add(placement);
    logForDebugging(
      '[Sandbox Linux] Re-bound write path wiped by denyRead tmpfs: $writePath',
    );
  }

  // Re-allow specific paths within the denied directory (allowRead overrides denyRead).
  // After mounting tmpfs over the denied dir, bind back the allowed subdirectories
  // so they are readable again.
  final restoredReads = <_RestoredMount>[];
  for (final allowPath in readAllowPaths) {
    final placement = restorePlacementOf(allowPath);
    if (placement == null) continue;
    // Skip only if a write path was re-bound just above AND covers
    // allowPath. A write path that's an ancestor of the deny dir isn't
    // re-bound (it wasn't wiped), so allowPath under it still needs
    // its own ro-bind here.
    if (restoredWrites.any((w) => isAtOrUnder(placement.dest, w.dest)))
      continue;
    // Bind the allowed path back over the tmpfs so it's readable
    args.addAll(['--ro-bind', placement.source, placement.dest]);
    restoredReads.add(placement);
    logForDebugging(
      '[Sandbox Linux] Re-allowed read access within denied region: $allowPath',
    );
  }
  return (restoredWrites: restoredWrites, restoredReads: restoredReads);
}

// Dart: a typedef cannot be local, so the two shapes the function below
// declares for itself stand here.
typedef _ReadDenyMount = ({
  /** Where the mount goes. */
  String landing,

  /** As the entry resolved, before the landing rules below. */
  String named,
  bool isDirectory,

  /** The landing is not where the entry names: nothing beneath it can
   *  be vouched for, so nothing is bound back over it. */
  bool isStandIn,
});
typedef _ReadDenyPlanEntry = ({
  String normalizedPath,
  _ReadDenyMount? mount,
  bool liftedFile,
  bool isCredential,
});

// Dart: the union below is one record; when `usable` is false the lists are
// empty and unread. Upstream's `usable: false` member is documented:
/**
 * The derivation threw, or needed a canonical location it could not
 * look at. A failure must not read as "no read-deny tmpfs", so
 * every covering directory is vetoed instead.
 */
typedef _StubSkipVetoInputs = ({
  /** The derivation held; the arrays below describe this wrap. */
  bool usable,

  /**
   * allowWrite paths in their recorded and realpath-canonical
   * spellings (mountForms). The canonical form is not reused from
   * the allow loop's earlier resolution, deliberately: canonicalForm
   * resolves after the (unbounded) mandatory-deny scan, so it sees
   * an allow path whose symlink target changed during that window —
   * the fail-closed direction, since a link now pointing into a
   * covering deny dir must veto the skip. The guard's veto compares
   * deny dests (always canonical) against allow paths, so it keeps
   * both domains.
   */
  List<String> allowedWritePathsBothForms,

  /**
   * Where the denyRead loop below would mount a tmpfs, read off the
   * same readDenyPlan() walk that loop takes its own answers from,
   * keeping only the entries that are directories (the loop skips
   * the ones that mount nothing and gives a file entry a read-only
   * /dev/null mask instead), in raw and canonical spellings. It
   * over-predicts: the loop also
   * skips an entry whose landing an earlier tmpfs already hides.
   * That direction is the safe one, since every veto below turns a
   * predicted tmpfs into a KEPT placeholder. A read-denied tmpfs at
   * or under a covering deny dir is the TRIGGER for the
   * post-denyWrite re-application, and a deny bind whose dest sits
   * under one can be dropped by the emission filter — both facts
   * feed the guard.
   */
  List<String> prospectiveReadDenyTmpfsDirsBothForms,
});

/**
 * Generate filesystem bind mount arguments for bwrap
 */
Future<({List<String> args, int mandatoryDenyArgs})> _generateFilesystemArgs(
  FsReadRestrictionConfig? readConfig,
  FsWriteRestrictionConfig? writeConfig,
  List<MaskedFileBind>? maskedFileBinds,
  String? maskedFileStoreDir, [
  RipgrepConfig? ripgrepConfig,
  int mandatoryDenySearchDepth = _DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  bool allowGitConfig = false,
  AbortSignal? abortSignal,
  // TELOSNEX DEVIATION: use the embedder's exit-handler preference.
  bool registerProcessHandlers = true,
]) async {
  ripgrepConfig ??= RipgrepConfig(command: 'rg');
  final args = <String>[];
  final startedIn = workingDirectory();
  // fs already imported

  // Collect normalized allowed write paths. Populated in the writeConfig
  // block, read again in the denyRead loop to re-bind writes under tmpfs.
  final allowedWritePaths = <String>[];
  // denyWrite binds are buffered and emitted after denyRead processing so that
  // a denyRead tmpfs over an ancestor directory doesn't wipe them out.
  final denyWriteArgs = <String>[];
  // Where the mandatory denies' binds begin in it: after the configuration's.
  // Dart: int has no Infinity; the largest int stands in for it.
  var mandatoryDenyArgsStart = 0x7fffffffffffffff;
  // Directories that a deny entry re-binds read-only inside the sandbox
  // (--ro-bind <dir> <dir>), keyed by resolved dest, with every raw
  // (pre-resolution) spelling each was reached through. A non-existent deny
  // path whose deepest existing ancestor lies within one of these is already
  // uncreatable, and must not get a /dev/null stub: bwrap would have to
  // creat() the mount point inside that read-only mount and abort ("Can't
  // create file at <path>: Read-only file system"). An EXISTING deny path
  // strictly beneath one is likewise already unwritable and its own
  // --ro-bind <p> <p> is skipped as redundant. The spellings matter
  // because the re-application passes record a deny bind's raw spelling
  // beside its resolved dest, so the stub-skip guard tests a covering
  // directory in its canonical form AND every recorded spelling.
  final readOnlyDenyDirSpellings = <String, Set<String>>{};
  // Resolved dests that at least one deny entry reaches through a symlink.
  // Asked of the dest, not of the entry in hand: the deny loop deduplicates
  // on the dest, so which spelling it sees is the caller's ordering.
  final symlinkedDenySpellingDests = <String>{};
  // dest → the pre-resolution deny path it came from. A bind at the resolved
  // dest also re-exposes whatever the symlinked spelling leads to, so the
  // re-application passes below compare a read deny's landing against both
  // spellings. Landings and allowed write paths are canonical, so the extra
  // spelling can only match more of them, never fewer.
  final denyWriteRawDests = <String, String>{};
  // Placeholder dests where no mount point can be made (see mountPointFor).
  // Planned like the others, so that their ancestors are pinned and counted
  // alike, and left out at emission.
  final unmakeableDenyDests = <String>{};
  // The shared empty directory this call's placeholders bind from, resolved at
  // most once per wrap: resolving again mid-wrap (the cached path having been
  // tampered with in between) would leave the binds already emitted pointing
  // at a directory this same call has just judged not ours.
  String? emptySource;
  // Where a mount given `p` lands: `p` fully resolved, every symlink on the
  // way and not one hop. One resolution per path per wrap, so every predicate
  // below sees the same answer, and none before the mandatory-deny scan's
  // await: that scan can run arbitrarily long, and a realpath taken ahead of
  // it would miss a symlink retargeted meanwhile.
  final canonicalFormCache = <String, String>{};
  // Paths whose canonical location could not be LOOKED AT — a settled errno,
  // or a transient one that outlived the retry — so the recorded spelling
  // stands in for it. That is a guess, and the
  // stub-skip prediction below refuses to conclude anything from a guess made
  // about its own inputs. Plain absence is not a guess: nothing is there to
  // resolve, and every consumer already treats such a path as absent (a
  // dangling symlink under '/' is ordinary, and counting it would keep every
  // deny placeholder on the whole host).
  final canonicalFormGuesses = <String>{};
  // Paths canonicalForm answered with the spelling it was given because
  // nothing could be resolved. A mount SOURCE must never be one of them:
  // bwrap would resolve whatever sits at that name at mount time, after the
  // containment checks ran against the name itself.
  final canonicalFormUnresolved = <String>{};
  String canonicalForm(String p) {
    var canonical = canonicalFormCache[p];
    if (canonical == null) {
      try {
        canonical = _retryingTransient(() => realPathOf(p));
      } catch (err) {
        canonical = p; // vanished or unresolvable: the recorded form stands
        canonicalFormUnresolved.add(p);
        if (!isAbsenceErrno(err)) {
          canonicalFormGuesses.add(p);
          logForDebugging(
            '[Sandbox Linux] Where $p really is cannot be told, so what is mounted for it is mounted on this spelling, which bubblewrap may refuse: $err',
            level: 'warn',
          );
        }
      }
      canonicalFormCache[p] = canonical!;
    }
    return canonical;
  }

  /** Where `p` resolves to, beside whether anything was resolved at all.
   * Answered together because the answer is the spelling itself when nothing
   * was, and a mount source must never be one of those. */
  ({String canonical, bool resolved}) canonicalLocationOf(String p) => (
    canonical: canonicalForm(p),
    resolved: !canonicalFormUnresolved.contains(p),
  );
  /** `p` as recorded, plus its canonical location when that differs. */
  List<String> mountForms(String p) {
    final canonical = canonicalForm(p);
    return canonical == p ? [p] : [p, canonical];
  }

  // Where the name `p` lives: its parent directories resolved, its last
  // component as written. This, not what `p` resolves to, decides which read
  // deny an allowRead entry is an exception to: an entry that is a symlink
  // names the link, and re-allows nothing the link points at.
  String nameLocationOf(String p) => nameLocation(p, canonicalForm);
  // Whether a canonical path lies inside the write allowlist, and so
  // whether it is stubbed and pinned at all: a path outside it is left
  // read-only by the initial --ro-bind / /. allowedWritePaths entries are
  // canonical (the allow loop drops a symlink-spelled one) and recorded with
  // trailing slashes stripped.
  //
  // Containment is root-aware (isAtOrUnder) because '/' is a legal allowOnly
  // entry that the allow loop binds writable: an `allowedPath + '/'` prefix
  // test spells it '//' and matches nothing, so every deny no other allow
  // entry covers would be judged outside the allowlist and silently lose its
  // bind over a writable root. The ancestor pins are the one consumer that
  // treats a '/' write root specially: see ancestorPinArgs.
  bool isWithinAnyAllowedWritePath(String candidatePath) => allowedWritePaths
      .any((allowedPath) => isAtOrUnder(candidatePath, allowedPath));
  // Whether an existing deny path gets its own --ro-bind: it lies inside the
  // write allowlist, or an allowed write path lies beneath it, whose --bind
  // the deny's then covers. The deny pre-pass and the deny loop's --ro-bind
  // gate MUST share it: the pre-pass is only sound if it records exactly the
  // directories the loop re-binds read-only (a recorded directory that is
  // never re-bound read-only would suppress stubs unsafely; a re-bound
  // directory missing from the record only costs an abort).
  bool meetsAnyAllowedWritePath(String candidatePath) =>
      isWithinAnyAllowedWritePath(candidatePath) ||
      allowedWritePaths.any(
        (allowedPath) => isStrictlyUnder(allowedPath, candidatePath),
      );
  bool isAllowedWriteRoot(String candidatePath) =>
      allowedWritePaths.contains(candidatePath);
  // Resolves symlinks, so computed on first use, which is after the
  // mandatory-deny scan.
  List<String>? readAllowPathsMemo;
  List<String> readAllowPaths() =>
      (readAllowPathsMemo ??= (readConfig?.allowWithinDeny ?? <String>[])
          .map((p) => normalizePathForSandbox(p, literal: true))
          .toList());
  List<String>? ownReadAllowPathsMemo;
  List<String> ownReadAllowPaths() =>
      (ownReadAllowPathsMemo ??= (readConfig?.ownAllowWithinDeny ?? <String>[])
          .map((p) => normalizePathForSandbox(p, literal: true))
          .toList());
  // The denyOnly entries that are credential denies, as they are spelled
  // there, and what may be an exception to a read deny of either kind.
  final credentialDenies = <String>{...?readConfig?.credentialDenyOnly};
  List<String> readExceptionsTo(bool isCredential) =>
      isCredential ? ownReadAllowPaths() : readAllowPaths();
  // What the read section mounts for one denyRead entry: a tmpfs (directory)
  // or a /dev/null mask (anything else) on the entry itself; nothing when it
  // is not there; and, when it cannot be inspected, a tmpfs on the deepest
  // directory above it that can. That hides more than was asked, never less:
  // a same-uid command can make a parent unsearchable (chmod 000) and undo it
  // again from inside the next sandbox, so "unreadable now" is not "absent".
  // This is the widest blast radius a transient failure has, hence the retry:
  // one unlucky EIO turns a file deny into a stand-in over its whole
  // directory, and every carve-out beneath that is then refused.
  ({String path, bool isDirectory, bool isStandIn})? readDenyTargetOf(
    String entry,
  ) {
    for (var candidate = entry; ; candidate = path.dirname(candidate)) {
      if (candidate == '/' && candidate != entry) return null;
      try {
        final stats = _retryingTransient(() => fs.statSync(candidate));
        return (
          path: candidate,
          isDirectory: stats.isDirectory(),
          isStandIn: candidate != entry,
        );
      } catch (err) {
        if (isAbsenceErrno(err) || candidate == '/') return null;
      }
    }
  }

  // Where that mount lands, which is where the entry really is: one mount
  // then covers every spelling of that place; the real contents are hidden
  // wherever they are reachable, even when the route that named them is
  // itself inside an earlier tmpfs; and no mount is ever asked to land on a
  // symlink, which bubblewrap refuses outright from 0.12 on ("Can't mount on
  // symlink destination").
  //
  // '/' is never a landing. Only a symlink to the root resolves there (a '/'
  // entry itself is expanded into the root's children), and a --tmpfs /
  // would wipe every mount placed before it while the pivot promoted it,
  // booting the command on an empty tree. The directory holding the link
  // stands in for it, on the same rule as an entry that cannot be inspected,
  // and `undefined` means nothing at all is mounted for this entry.
  _ReadDenyMount? readDenyMountOf(String entry) {
    final target = readDenyTargetOf(entry);
    if (target == null) return null;
    final landing = canonicalForm(target.path);
    if (landing != '/') {
      return (
        landing: landing,
        named: target.path,
        isDirectory: target.isDirectory,
        isStandIn: target.isStandIn,
      );
    }
    final holder = canonicalForm(path.dirname(target.path));
    if (holder == '/') return null;
    return (
      landing: holder,
      named: target.path,
      isDirectory: true,
      isStandIn: true,
    );
  }

  // The directories and files the read section denies, as configured. A '/'
  // entry is expanded into the root's children, because --tmpfs / would wipe
  // every prior mount (ro-bind /, write binds, deny binds). /proc and /dev are
  // skipped (the caller remounts them after this function returns) and so is
  // /sys (kernel interface; the host's is already read-only via ro-bind). A
  // child an allowRead entry covers (its name is the child, or an ancestor
  // of where the child lands) is skipped too: the deny is synthetic and the
  // allow is the caller's, and a tmpfs at the child's canonical location
  // (/bin lands at /usr/bin) would only be restored over again. An entry
  // that is a symlink to the child covers nothing: its name lives elsewhere. /etc/ssh/ssh_config.d is
  // always hidden when there is a read policy: ssh is strict about config
  // file ownership and permissions, which can look wrong inside the sandbox
  // ("Bad owner or permissions" under OrbStack). Throws if '/' cannot be
  // listed, a transient failure having been retried once. Computed on first
  // use, like readAllowPaths.
  List<String>? readDenyEntriesMemo;
  List<String> readDenyEntries() {
    if (readDenyEntriesMemo != null) return readDenyEntriesMemo!;
    if (readConfig == null) return [];
    final entries = <String>[];
    for (final p in readConfig.denyOnly) {
      if (normalizePathForSandbox(p, literal: true) != '/') {
        entries.add(p);
        continue;
      }
      // The only call here that throws, and the list is memoised on success
      // alone, so the retry belongs to it rather than to one of its callers:
      // the stub-skip derivation catches a throw and gives up on the
      // prediction, and the denyRead loop below does not catch one at all.
      final children = _retryingTransient(
        () => fs.readdirSync('/', withFileTypes: false),
      );
      final isCredential = credentialDenies.contains(p);
      for (final childEntry in children) {
        final child = childEntry.name;
        if (_KERNEL_TOP_LEVEL_DIRS.contains('/$child')) continue;
        final childLocation = canonicalForm('/' + child);
        final covered = readExceptionsTo(isCredential).any(
          (allowPath) => isAtOrUnder(childLocation, nameLocationOf(allowPath)),
        );
        if (covered) {
          logForDebugging(
            '[Sandbox Linux] Root deny expansion skips /$child: covered by allowRead',
          );
          continue;
        }
        entries.add('/' + child);
        if (isCredential) credentialDenies.add('/' + child);
      }
    }
    if (fs.existsSync('/etc/ssh/ssh_config.d')) {
      entries.add('/etc/ssh/ssh_config.d');
    }
    readDenyEntriesMemo = entries;
    return entries;
  }

  // Shallow-first by canonical depth, so a tmpfs over a directory lands
  // before the tmpfs or /dev/null mask on anything inside it however either
  // was spelled. That order is what lets a unit restore its write and
  // allowRead paths unconditionally: nothing emitted so far can lie inside
  // one. Sorted by spelling, a symlink-spelled entry could mount first inside
  // a directory listed after it, whose restores would then bury it.
  int canonicalDepth(String p) => canonicalForm(p).split('/').length;
  // What every denyRead entry mounts and where: ONE walk, whose answers the
  // deny loop, the locations the carve-out gate below reads, and the
  // stub-skip prediction all take, so none of them can disagree about where
  // a deny lands. `mount` is undefined where nothing is mounted at all;
  // `liftedFile` marks a file deny an allowRead entry naming that very file
  // cancels — the entry mounts nothing in that case either. Lazy and
  // memoised like readDenyEntries(): it resolves symlinks, so it must not run
  // before the mandatory-deny scan's await.
  List<_ReadDenyPlanEntry>? readDenyPlanMemo;
  List<_ReadDenyPlanEntry> readDenyPlan() => (readDenyPlanMemo ??=
      // Dart: List.sort is not stable, so ties keep their order by index.
      ([
            ...readDenyEntries()
                .map(
                  (p) => (
                    normalizedPath: normalizePathForSandbox(p, literal: true),
                    isCredential: credentialDenies.contains(p),
                  ),
                )
                .indexed,
          ]..sort((a, b) {
            final d =
                canonicalDepth(a.$2.normalizedPath) -
                canonicalDepth(b.$2.normalizedPath);
            return d != 0 ? d : a.$1 - b.$1;
          }))
          .map((e) => e.$2)
          .map((e) {
            final (:normalizedPath, :isCredential) = e;
            final mount = readDenyMountOf(normalizedPath);
            return (
              normalizedPath: normalizedPath,
              mount: mount,
              isCredential: isCredential,
              liftedFile:
                  mount != null &&
                  !mount.isDirectory &&
                  readExceptionsTo(isCredential).any(
                    (allowPath) => nameLocationOf(allowPath) == mount.landing,
                  ),
            );
          })
          .toList());
  // Where the ancestor pins are spliced in once every mount is known:
  // beneath the allow binds, or after them under a '/' write root that would
  // otherwise bury them (see ancestorPinArgs).
  int ancestorPinInsertAt;

  // Determine initial root mount based on write restrictions
  if (writeConfig != null) {
    // Write restrictions: Start with read-only root, then allow writes to specific paths
    args.addAll(['--ro-bind', '/', '/']);
    final beneathAllowBinds = args.length;

    // Allow writes to specific paths
    for (final pathPattern in writeConfig.allowOnly) {
      // Every path here is a name, and normalizePathForSandbox strips a
      // name's trailing slash; the strip below stays as a guard. Allow paths
      // are recorded slash-free because every
      // downstream comparison — the deny loop's within-allowlist gate,
      // findSymlinkInPath's mask scoping, the emission filter's re-expose
      // check, the denyRead re-bind and its allowRead skip, and the stub-skip
      // vetoes — matches by `allowedPath + '/'` prefix, which '<dir>//'
      // silently defeats. bwrap binds 'dir' and 'dir/' identically, so
      // normalizing the recorded spelling fixes every consumer at once
      // instead of per-predicate. ('/' itself is kept; the empty spelling an
      // empty $HOME expands '~' to is NOT the root, and falls out at the
      // existence check below.)
      final normalized = normalizePathForSandbox(pathPattern, literal: true);
      final stripped = normalized.replaceFirst(RegExp(r'/+$'), '');
      final normalizedPath = normalized == ''
          ? ''
          : (stripped.isEmpty ? '/' : stripped);

      logForDebugging(
        '[Sandbox Linux] Processing write path: $pathPattern -> $normalizedPath',
      );

      // Skip /dev/* paths since --dev /dev already handles them
      if (normalizedPath.startsWith('/dev/')) {
        logForDebugging('[Sandbox Linux] Skipping /dev path: $normalizedPath');
        continue;
      }

      if (!fs.existsSync(normalizedPath)) {
        logForDebugging(
          '[Sandbox Linux] Skipping non-existent write path: $normalizedPath',
        );
        continue;
      }

      // Check if path is a symlink pointing outside expected boundaries
      // bwrap follows symlinks, so --bind on a symlink makes the target writable
      // This could unexpectedly expose paths the user didn't intend to allow
      try {
        final resolvedPath = realPathOf(normalizedPath);
        // Trim trailing slashes before comparing: realpathSync never returns
        // a trailing slash, but normalizedPath may have one, which would cause
        // a false mismatch and incorrectly treat the path as a symlink.
        final normalizedForComparison = normalizedPath.replaceFirst(
          RegExp(r'/+$'),
          '',
        );
        if (resolvedPath != normalizedForComparison &&
            isSymlinkOutsideBoundary(normalizedPath, resolvedPath)) {
          logForDebugging(
            '[Sandbox Linux] Skipping symlink write path pointing outside expected location: $pathPattern -> $resolvedPath',
          );
          continue;
        }
      } catch (_) {
        // realpathSync failed - path might not exist or be accessible, skip it
        logForDebugging(
          '[Sandbox Linux] Skipping write path that could not be resolved: $normalizedPath',
        );
        continue;
      }

      args.addAll(['--bind', normalizedPath, normalizedPath]);
      allowedWritePaths.add(normalizedPath);
    }
    ancestorPinInsertAt = isAllowedWriteRoot('/')
        ? args.length
        : beneathAllowBinds;

    // Inputs for the covering-directory vetoes, computed at most once and
    // only when a deny path (absent or existing) lies strictly beneath a
    // recorded read-only deny dir — commands with no such covering directory
    // skip the extra stat/realpath/readdir syscalls entirely. Lazy
    // evaluation also means the derivation runs from inside the deny loop,
    // AFTER the (unbounded) mandatory-deny ripgrep await below, keeping the
    // snapshot as close as possible to the denyRead loop that later acts on
    // the real filesystem.
    _StubSkipVetoInputs? stubSkipVetoInputs;
    _StubSkipVetoInputs getStubSkipVetoInputs() {
      if (stubSkipVetoInputs != null) {
        return stubSkipVetoInputs!;
      }
      _StubSkipVetoInputs unusable(String cause) {
        logForDebugging(
          '[Sandbox Linux] Read-deny prediction unusable ($cause); keeping every deny placeholder, which refuses to start wherever a covering deny directory is read-only: bubblewrap cannot create a placeholder\'s mount point there',
          level: 'warn',
        );
        return (
          usable: false,
          allowedWritePathsBothForms: const <String>[],
          prospectiveReadDenyTmpfsDirsBothForms: const <String>[],
        );
      }

      // Single-shot: readDenyEntries() owns the retry for the one thing that
      // throws here, its listing of '/'. A guess would survive a retry
      // anyway, being a settled verdict about a path that cannot be looked at.
      try {
        final allowedWritePathsBothForms = allowedWritePaths
            .expand(mountForms)
            .toList();
        final prospectiveReadDenyTmpfsDirsBothForms = readDenyPlan().expand((
          e,
        ) {
          final mount = e.mount;
          if (!(mount?.isDirectory ?? false)) return <String>[];
          // The tmpfs hides its landing, and the spelling the entry
          // resolved to when that differs. '/' is never a landing, and
          // must not enter the prediction as a spelling either (a link
          // to the root resolves there, and its holder is the landing):
          // every covering directory lies under '/', so predicting a
          // tmpfs there would veto every skip on the whole host.
          return {
            ...mountForms(mount!.named),
            mount.landing,
          }.where((form) => form != '/').toList();
        }).toList();
        // Every canonicalForm call site runs inside this derivation or after
        // the deny loop that triggers it, so a guess recorded by now was made
        // about the derivation's own inputs. A future caller that resolves
        // earlier can only add guesses here, which vetoes more skips, never
        // fewer.
        stubSkipVetoInputs = canonicalFormGuesses.isNotEmpty
            ? unusable(
                'no canonical location for ${[...canonicalFormGuesses].join(', ')}',
              )
            : (
                usable: true,
                allowedWritePathsBothForms: allowedWritePathsBothForms,
                prospectiveReadDenyTmpfsDirsBothForms:
                    prospectiveReadDenyTmpfsDirsBothForms,
              );
      } catch (err) {
        stubSkipVetoInputs = unusable('deriving it threw: $err');
      }
      return stubSkipVetoInputs!;
    }

    // Deny writes within allowed paths (user-specified + mandatory denies)
    final configuredDenyPaths = writeConfig.denyWithinAllow;
    // TELOSNEX DEVIATION: Resolve explicit roots as literal directories before
    // scanning. They replace the cwd; each uses the same mount and pin plan.
    final mandatoryDenyRoots = writeConfig.mandatoryDenyRoots
        ?.map((root) => normalizePathForSandbox(root, literal: true))
        .toSet();
    final denyPaths = [
      ...configuredDenyPaths,
      for (final root in mandatoryDenyRoots ?? const <String?>{null})
        ...(await _linuxGetMandatoryDenyPaths(
          ripgrepConfig,
          mandatoryDenySearchDepth,
          allowGitConfig,
          abortSignal,
          root,
        )),
    ];
    // INVARIANT: one plan, one working directory. A relative entry is resolved
    // against it on both sides of the await above, the only one here.
    if (workingDirectory() != startedIn) throw WorkingDirectoryChanged();

    // Duplicate deny entries must be collapsed: a duplicate
    // --ro-bind /dev/null <dest> hits a char device on the second pass and
    // bwrap's ensure_file() falls through to creat() on a read-only mount.
    final seenDenyWrite = <String>{};
    // Every directory a deny path lies beneath, there or not.
    final denyPathAncestors = <String>{};
    // PRE-PASS (order-independent): record the directories the loop below
    // re-binds read-only, BEFORE any stub decision, so the read-only
    // conclusion does not depend on where an enclosing directory appears in
    // the caller's denyWrite ordering. It applies the loop's own resolution,
    // the same symlink re-check, and the same meetsAnyAllowedWritePath
    // gate as the --ro-bind emission, and it records every raw spelling each
    // directory is reached through. A recorded directory is EVIDENCE for
    // skipping a stub only if it also passes the guard's vetoes below (no
    // read-deny tmpfs contains it in any spelling; no allowed write path is
    // both beneath it and under such a tmpfs), which exclude every way its
    // subtree could be writable in the sandbox. Keep the two passes in lockstep: a
    // directory recorded here is either re-bound read-only by the loop or
    // skipped because a recorded directory above it survived the vetoes and
    // is bound in its place, so every record still stands for a bind that
    // lands — unless a symlink appears in its path between the two passes,
    // where the loop masks that component and emits no bind for the
    // directory (the re-check below); an emitted one missing from the record
    // only costs a spurious abort.
    for (var preIndex = 0; preIndex < denyPaths.length; preIndex++) {
      final pathPattern = denyPaths[preIndex];
      final rawPath = normalizePathForSandbox(pathPattern, literal: true);
      if (rawPath.startsWith('/dev/')) {
        continue;
      }
      final resolvedPath = _resolveSymlinkedDenyPath(rawPath, denyPaths);
      if (resolvedPath == null || resolvedPath.startsWith('/dev/')) {
        continue;
      }
      for (final above in properAncestors(resolvedPath)) {
        denyPathAncestors.add(above);
      }
      // Same defense-in-depth re-check as the loop: there the --ro-bind is
      // replaced by a symlink mask, so such a directory must not be recorded
      // as re-bound here.
      if (_findSymlinkInPath(resolvedPath, allowedWritePaths) != null) {
        continue;
      }
      if (resolvedPath != rawPath) {
        symlinkedDenySpellingDests.add(resolvedPath);
      }
      var isDirectory = false;
      try {
        isDirectory = fs.statSync(resolvedPath).isDirectory();
      } catch (_) {
        continue; // absent (or vanished): not a read-only re-bound directory
      }
      if (!isDirectory) {
        continue;
      }
      if (meetsAnyAllowedWritePath(resolvedPath)) {
        // Keep every spelling this dest is reached through (the
        // re-application passes record the first-seen raw spelling beside
        // the dest, which this pass cannot assume): the guard below treats
        // the directory as unsafe if a read-deny tmpfs contains ANY of them.
        var spellings = readOnlyDenyDirSpellings[resolvedPath];
        if (spellings == null) {
          spellings = <String>{};
          readOnlyDenyDirSpellings[resolvedPath] = spellings;
        }
        spellings.add(rawPath);
      }
    }
    // Per-covering-dir veto verdict, computed once per recorded directory
    // (the inputs never change during the deny loop) instead of per absent
    // deny entry.
    // INVARIANT: a stub, or an existing deny path's own bind, is skipped
    // only under a recorded covering deny directory that was judged against
    // a prediction that could be derived, that no read-deny tmpfs contains
    // (it, or any spelling it was reached through), and beneath which no
    // allowed write path sits that a read-deny tmpfs also covers. '/' is the
    // exception: it contains every allowed write path, so
    // coveredBySafeReadOnlyDenyDir judges a vetoed '/' against the candidate
    // instead — see the branch there.
    // The skip rests on the emission order: nothing host-backed and writable
    // lands after the buffered read-only binds, so a covering bind is the
    // last word on its subtree unless a tmpfs above it drops that bind at
    // emission. Where a veto could apply, keep the stub: the pre-existing
    // abort is preferable to a silently creatable deny path.
    final coveringDirUnsafeVerdicts = <String, bool>{};
    bool coveringDirIsUnsafe(String denyDir) {
      final cached = coveringDirUnsafeVerdicts[denyDir];
      if (cached != null) {
        return cached;
      }
      final vetoInputs = getStubSkipVetoInputs();
      final unsafe =
          // (0) the prediction of what the denyRead loop will mount is
          //     unusable, so no veto below can be trusted to fire. Veto
          //     everything rather than nothing: a prediction that failed is no
          //     evidence that this directory is reliably read-only.
          !vetoInputs.usable ||
          // (i) an allowed write path both strictly beneath the dir and at or
          //     under a prospective read-deny tmpfs. Re-applying that tmpfs
          //     after the dir's read-only bind is the one pass that mounts
          //     anything inside such a path at all, and it restores read-only,
          //     so this names no live re-opening route today and no
          //     configuration is known that needs it. It is the only veto that
          //     speaks about a writable path under the dir: should a pass after
          //     the deny binds ever restore one writable again, the skip fails
          //     closed here.
          vetoInputs.allowedWritePathsBothForms.any(
            (writePath) =>
                isStrictlyUnder(writePath, denyDir) &&
                vetoInputs.prospectiveReadDenyTmpfsDirsBothForms.any(
                  (tmpfsDir) => isAtOrUnder(writePath, tmpfsDir),
                ),
          ) ||
          // (ii) a read-deny tmpfs CONTAINING the dir: its own --ro-bind is
          //     dropped as hidden-by-the-tmpfs at emission, and a tmpfs above
          //     it restores allowed paths around it — either way the dir's own
          //     bind is not the last word on that subtree. A tmpfs containing
          //     only a raw spelling it was reached through counts too; that
          //     over-predicts, which only keeps a stub.
          vetoInputs.prospectiveReadDenyTmpfsDirsBothForms.any(
            (tmpfsDir) => [
              denyDir,
              ...(readOnlyDenyDirSpellings[denyDir] ?? <String>{}),
            ].any((spelling) => isAtOrUnder(spelling, tmpfsDir)),
          );
      coveringDirUnsafeVerdicts[denyDir] = unsafe;
      return unsafe;
    }

    // Materialized once: the pre-pass above fully populates the map and the
    // deny loop never mutates it.
    final readOnlyDenyDirs = [...readOnlyDenyDirSpellings.keys];
    // The allowed write paths with no recorded directory above them.
    // INVARIANT: one strictly beneath a recorded directory is never writable,
    // whatever the vetoes say of that directory's own bind. Emitted, that bind
    // (or the one above that it is skipped for) covers the path; dropped as
    // hidden by a read-deny tmpfs, that tmpfs has wiped the path's allow bind,
    // and the emission filter puts a read-only bind on every write path a unit
    // restored beneath the dropped dest. No writable mount follows either.
    final uncoveredWritePaths = allowedWritePaths
        .where(
          (allowedPath) => !readOnlyDenyDirs.any(
            (denyDir) => isStrictlyUnder(allowedPath, denyDir),
          ),
        )
        .toList();
    // Is `candidate` already unwritable in the sandbox: strictly under a
    // recorded read-only deny directory that survives every
    // coveringDirIsUnsafe veto? Strictly, because a deny equal to a recorded
    // directory IS that covering bind and must be emitted (an absent path
    // never equals one). Stops at the first vetoed covering directory.
    bool coveredBySafeReadOnlyDenyDir(String candidate) {
      var covered = false;
      for (final denyDir in readOnlyDenyDirs) {
        if (!isStrictlyUnder(candidate, denyDir)) continue;
        if (coveringDirIsUnsafe(denyDir)) {
          if (denyDir == '/') {
            // A vetoed '/' does not disqualify an inner recorded directory:
            // everything lies beneath it, so it would veto every skip and
            // stub each absent mandatory-deny path of a write-denied cwd
            // after that cwd's own bind — the startup abort. Its descendants
            // are decided by their own recorded directories.
            //
            // It does still COVER a candidate outside every predicted
            // read-deny tmpfs. Its own --ro-bind / / holds the whole tree
            // read-only from where it is emitted, burying the allow loop's
            // binds, and the only writable surface after it is a re-applied
            // tmpfs itself: the re-application passes no allowed write
            // paths, so everything it restores comes back read-only. An
            // allowed write path beneath the root is therefore not a vector
            // here, and vetoing on one only brings the abort back for
            // `allowOnly: ['/', <dir>]`. An underivable prediction proves
            // nothing and keeps the stub. Without this branch, `allowOnly:
            // ['/']` with `denyWithinAllow: ['/']` stubs each absent cwd
            // dotfile on the read-only root it just mounted — the startup
            // abort — whenever anything vetoes '/', which an unusable
            // prediction or an allowed write path under a read-deny tmpfs
            // does. The branch is strictly stricter than covering on the
            // root's own bind, and it is what decides those two cases.
            final vetoInputs = getStubSkipVetoInputs();
            if (vetoInputs.usable &&
                !vetoInputs.prospectiveReadDenyTmpfsDirsBothForms.any(
                  (tmpfsDir) => isAtOrUnder(candidate, tmpfsDir),
                )) {
              covered = true;
            }
            continue;
          }
          return false;
        }
        covered = true;
      }
      return covered;
    }

    // The placeholder dests decided so far.
    final decidedMountPoints = <String>{};
    String? decidedMountPointOver(String p) => [
      p,
      ...properAncestors(p),
    ].where((at) => decidedMountPoints.contains(at)).firstOrNull;
    /**
     * The placeholder an absent deny path adds to the plan: where, which is
     * its first missing component or the file above it, and on what kind of
     * mount point. Undefined where the path adds nothing.
     *
     * INVARIANT: a placeholder is left out only where the sandboxed command
     * cannot create the path either; each branch says why it cannot. On any
     * doubt the placeholder stays: at worst bubblewrap cannot make its mount
     * point and nothing starts, which loses no deny.
     */
    ({String dest, String kind})? mountPointFor(String absentPath) {
      ({String dest, String kind})? none(String why) {
        logForDebugging(
          '[Sandbox Linux] No placeholder for non-existent deny path $absentPath: $why',
        );
        return null;
      }

      // One mount point per destination. Deny paths are deduplicated on the
      // deny path, but a placeholder lands on the first MISSING component, so
      // two denies can share one: denyWrite '<cwd>/.claude' together with the
      // mandatory '<cwd>/.claude/commands', in a project with no `.claude/`.
      // Asked of the record, not of the host, where the component may be
      // there by now (see makeableMountPoint).
      final decided = decidedMountPointOver(absentPath);
      if (decided != null) return none('decided with $decided');

      // Read-only in the sandbox, where bwrap could not creat() a mount point
      // either. No allowed write path holds it, which leaves it to the initial
      // --ro-bind / /, or only covered ones do (see uncoveredWritePaths); or a
      // recorded deny directory covers it and survives the
      // coveringDirIsUnsafe vetoes (see the INVARIANT at its definition). The
      // pre-pass has recorded every such directory, wherever it appears in
      // denyPaths; recorded directories exist, so one that covers the path is
      // at or above its deepest existing ancestor.
      if (!uncoveredWritePaths.any(
            (allowedPath) => isAtOrUnder(absentPath, allowedPath),
          ) ||
          coveredBySafeReadOnlyDenyDir(absentPath)) {
        return none('it is read-only there');
      }
      // Nothing can be created under a file (a git worktree's .git is one),
      // for as long as the file is there. So it is kept there, where the
      // command may write the directory that holds it. Where it may write the
      // file alone, that stays where it is and writable. It is not tracked
      // for removal: it is the caller's own, or another sandbox's mount point.
      // Asked of what lies above the path, not of the path: another sandbox's
      // bubblewrap may have made a mount point at it since it was found
      // absent, and a file there is no reason to leave it unbound.
      final file = _fileOnTheWay(path.dirname(absentPath));
      if (file != null) {
        if (seenDenyWrite.contains(file)) return none('$file is denied itself');
        if (!uncoveredWritePaths.any(
          (allowedPath) => isAtOrUnder(path.dirname(file), allowedPath),
        )) {
          return none('$file is a file, in a directory that is read-only');
        }
        seenDenyWrite.add(file);
        decidedMountPoints.add(file);
        return (dest: file, kind: _MountPointKind.Held);
      }

      // A component with a deny path beneath it is covered by an empty
      // read-only directory, which blocks creating it and everything below it
      // exactly as /dev/null does and stays traversable; as a file it breaks
      // tools that expect a directory there. Whatever the order of denyPaths.
      final dest = _findFirstNonExistentComponent(absentPath);
      decidedMountPoints.add(dest);
      final kind = _makeableMountPoint(
        dest,
        denyPathAncestors.contains(dest)
            ? _MountPointKind.Directory
            : _MountPointKind.File,
      );
      if (kind == _MountPointKind.Unmakeable) {
        // The directories above it are pinned all the same: a command that
        // may write one of THEM could otherwise move the refusing one aside.
        unmakeableDenyDests.add(dest);
      } else {
        // INVARIANT: only a path found absent here is tracked, for
        // cleanupBwrapMountPoints() to remove. An existing file that looks
        // like a mount point may be the caller's own, or that of another
        // process's sandbox still running, whose deny goes with it.
        _bwrapMountPoints.add(dest);
        // TELOSNEX DEVIATION: still track the placeholder for explicit
        // cleanup, but leave exit alone when the embedder owns shutdown.
        if (registerProcessHandlers) _registerExitCleanupHandler();
      }
      return (dest: dest, kind: kind);
    }

    /** What goes on it. The empty directory is made when first asked for. */
    String mountSourceFor(({String dest, String kind}) placeholder) {
      final (:dest, :kind) = placeholder;
      switch (kind) {
        case _MountPointKind.Held:
          return dest;
        case _MountPointKind.Directory:
          return emptySource ??= _ensureEmptyMountSourceDir();
        case _MountPointKind.File:
          return '/dev/null';
        case _MountPointKind.Unmakeable:
          // Never mounted: unmakeableDenyDests keeps it out of what is emitted.
          return '/dev/null';
        default:
          throw StateError('Unknown mount point kind: $kind');
      }
    }

    for (final (index, pathPattern) in denyPaths.indexed) {
      if (index == configuredDenyPaths.length) {
        mandatoryDenyArgsStart = denyWriteArgs.length;
      }
      final rawPath = normalizePathForSandbox(pathPattern, literal: true);

      // Skip /dev/* paths since --dev /dev already handles them
      if (rawPath.startsWith('/dev/')) {
        continue;
      }

      // Resolve-before-mask: normalizePathForSandbox keeps the raw symlink
      // path whenever resolution crosses isSymlinkOutsideBoundary (the
      // common dotfiles case), so canonicalize here. Every mask/bind below
      // must be computed against the resolved path — bwrap dest-resolves
      // symlinks, so a mask on the raw path either aborts startup (dir
      // symlink) or lands on the target inode anyway (file symlink). Writes
      // through the original symlinked path resolve to the same denied
      // target inside the mount namespace.
      final normalizedPath = _resolveSymlinkedDenyPath(rawPath);
      if (normalizedPath == null) {
        // Unresolvable: a symlink cycle, or a chain past the ELOOP bound.
        // Fail closed. Dropping the deny here would sandbox the command with
        // the path unprotected, so instead mask the symlink component and let
        // bwrap refuse to start. When no component is a symlink inside an
        // allowed write path there is nothing to protect: the path is already
        // read-only from the initial --ro-bind / /.
        final unresolvableSymlink = _findSymlinkInPath(
          rawPath,
          allowedWritePaths,
        );
        if (unresolvableSymlink != null &&
            unresolvableSymlink.isNotEmpty &&
            !seenDenyWrite.contains(unresolvableSymlink)) {
          seenDenyWrite.add(unresolvableSymlink);
          denyWriteArgs.addAll(['--ro-bind', '/dev/null', unresolvableSymlink]);
          denyWriteRawDests[unresolvableSymlink] = rawPath;
        }
        logForDebugging(
          '[Sandbox Linux] Deny path could not be resolved through symlinks, failing closed: $rawPath',
        );
        continue;
      }
      if (normalizedPath != rawPath) {
        logForDebugging(
          '[Sandbox Linux] Resolved symlinked deny path: $rawPath -> $normalizedPath',
        );
      }

      // Re-check after resolution: a deny path can only now land in /dev (e.g.
      // a symlink into it), where --dev /dev has already replaced the tree and
      // a bind would either miss or fight the new devtmpfs.
      if (normalizedPath.startsWith('/dev/')) {
        continue;
      }

      // Dedup post-resolution: distinct spellings (tilde vs absolute, via
      // symlink vs direct) converge to the same real path here.
      if (seenDenyWrite.contains(normalizedPath)) continue;
      seenDenyWrite.add(normalizedPath);

      // Defense-in-depth: the resolved path should be symlink-free for its
      // existing prefix, but the tree may change between resolution and this
      // check. A hit still fails closed — bwrap refuses to start rather than
      // sandboxing with an unprotected deny path.
      final symlinkInPath = _findSymlinkInPath(
        normalizedPath,
        allowedWritePaths,
      );
      if (symlinkInPath != null && symlinkInPath.isNotEmpty) {
        if (!seenDenyWrite.contains(symlinkInPath)) {
          seenDenyWrite.add(symlinkInPath);
          denyWriteArgs.addAll(['--ro-bind', '/dev/null', symlinkInPath]);
          denyWriteRawDests[symlinkInPath] = rawPath;
        }
        logForDebugging(
          '[Sandbox Linux] Mounted /dev/null at symlink $symlinkInPath to prevent symlink replacement attack',
        );
        continue;
      }

      // Handle non-existent paths by mounting /dev/null to block creation.
      // Without this, a sandboxed process could mkdir+write a denied path that
      // doesn't exist yet, bypassing the deny rule entirely.
      if (decidedMountPointOver(normalizedPath) != null ||
          !fs.existsSync(normalizedPath)) {
        final placeholder = mountPointFor(normalizedPath);
        if (placeholder != null) {
          final (:dest, :kind) = placeholder;
          final source = mountSourceFor(placeholder);
          denyWriteArgs.addAll(['--ro-bind', source, dest]);
          // The first of the denies that share the destination. The record is
          // purely additive: it only gives the tmpfs and mask comparisons
          // below a second spelling to test, and `dest` itself is always
          // tested.
          denyWriteRawDests[dest] = rawPath;
          logForDebugging(
            kind == _MountPointKind.Unmakeable
                ? '[Sandbox Linux] No mount point at $dest, which neither bubblewrap nor the command can create, for $normalizedPath'
                : '[Sandbox Linux] Mounted $source at $dest to block creation of $normalizedPath',
          );
        }
        continue;
      }

      // Only add deny binding if this path is within an allowed write path or
      // holds one. Otherwise all of it is already read-only from the initial
      // --ro-bind / /
      if (meetsAnyAllowedWritePath(normalizedPath)) {
        // Already unwritable under a read-only denied directory (the
        // existing-path twin of the stub skip above). Veto (ii) keeps the
        // covering bind through the emission filter; a dest ANY deny entry
        // reaches through a symlink keeps its own bind, so that the plan does
        // not depend on which spelling of it the loop sees first.
        if (!symlinkedDenySpellingDests.contains(normalizedPath) &&
            coveredBySafeReadOnlyDenyDir(normalizedPath)) {
          logForDebugging(
            '[Sandbox Linux] Skipping deny path already under read-only denied directory: $normalizedPath',
          );
          continue;
        }
        // A deny's read-only bind is emitted after every allow bind, so an
        // allowed write path beneath it comes back read-only instead of
        // stopping the sandbox from starting. Say so: the config asked for
        // both and only the deny takes effect.
        for (final buried in allowedWritePaths) {
          if (isStrictlyUnder(buried, normalizedPath)) {
            logForDebugging(
              '[Sandbox Linux] Write deny $normalizedPath covers allowed write path $buried; $buried will be read-only',
              level: 'warn',
            );
          }
        }
        denyWriteArgs.addAll(['--ro-bind', normalizedPath, normalizedPath]);
        denyWriteRawDests[normalizedPath] = rawPath;
      } else {
        logForDebugging(
          '[Sandbox Linux] Skipping deny path not within allowed paths: $normalizedPath',
        );
      }
    }
  } else {
    // No write restrictions: Allow all writes
    args.addAll(['--bind', '/', '/']);
    // Recording '/' makes isWithinAnyAllowedWritePath and isAllowedWriteRoot
    // say so, which is the '/'-write-root shape ancestorPinArgs treats
    // specially. Nothing is ever restored for it: no read-deny tmpfs lands
    // at '/'.
    allowedWritePaths.add('/');
    ancestorPinInsertAt = args.length;
  }
  // denyWriteArgs is emitted after the denyRead loop below.

  // Handle read restrictions by mounting tmpfs over denied paths.
  // Non-glob spellings arrive slash-free from normalizePathForSandbox — the
  // comparisons below (hidden-by-tmpfs prefixes, the exact-match allowRead
  // skip, pushReadDenyDirMounts' re-bind checks) depend on that.

  // The read-deny mounts emitted so far, in emission order: directories
  // masked by --tmpfs with what their restore loops re-bound, and files
  // masked by --ro-bind <source> <dest> (/dev/null for read-deny, the
  // sentinel fake for a credential mask). `landing` is where each mount sits
  // in the sandbox. Every later decision reads these records: the ancestor
  // pins, the deny-bind emission filter and the re-application passes.
  final readDenyTmpfsUnits =
      <
        ({
          String landing,
          List<_RestoredMount> restoredWrites,
          List<_RestoredMount> restoredReads,
        })
      >[];
  final fileMasks = <({String source, String landing})>[];

  // Replay the tmpfs units in order (bwrap is last-mount-wins): is `location`
  // beneath a unit's tmpfs and not brought back by a restore since? A restore
  // counts only where it lands. One reached through a symlink puts the
  // target's inode at the NAME; the target's own path is still under the
  // tmpfs, and asking there must not answer "brought back".
  // `broughtBackBy`: 'writes' | 'writes and reads'.
  bool isHiddenByTmpfs(String location, String broughtBackBy) {
    bool broughtBack(List<_RestoredMount> restored) =>
        restored.any((r) => isAtOrUnder(location, r.dest));
    var hidden = false;
    for (final unit in readDenyTmpfsUnits) {
      if (isAtOrUnder(location, unit.landing)) {
        hidden = true;
      }
      if (broughtBack(unit.restoredWrites) ||
          (broughtBackBy == 'writes and reads' &&
              broughtBack(unit.restoredReads))) {
        hidden = false;
      }
    }
    return hidden;
  }

  // Entries a glob expansion produced for a directory it could not list.
  // What the pattern matches beneath an allowed path in there was never
  // found, so binding that path back over the tmpfs would show every one of
  // those matches unmasked.
  final unlistableDenyDirs = <String>{...?readConfig?.unlistableDenyDirs};

  // The credential masks, one fake per landing. Where two entries name one
  // file ('~/.netrc' and its absolute form), the last is kept: it is the
  // mask bubblewrap would leave in force there.
  final credentialMaskFakes = <String, String>{};
  for (final MaskedFileBind(:realPath, :fakePath)
      in maskedFileBinds ?? const <MaskedFileBind>[]) {
    credentialMaskFakes[canonicalForm(realPath)] = fakePath;
  }
  // Destinations a file mask has been placed at, or will be: one mount per
  // destination. A second file mount lands on what the first put there, a
  // character device for a /dev/null mask, which bubblewrap before 0.5.0
  // does not take as a mount point: it refuses to start ("Can't create file
  // at <dest>: Permission denied"). Seeded with the credential landings,
  // which are emitted after this loop and win where both name one file.
  final fileMaskLandings = <String>{...credentialMaskFakes.keys};

  // Every location the read section hides, each one where its mount lands:
  // one per entry that mounts something — a directory's tmpfs, the stand-in
  // tmpfs of an entry that could not be inspected or that resolves to '/', a
  // file's /dev/null mask — and one per masked credential file. An entry that
  // mounts nothing hides nothing, and must not cost a carve-out; a stand-in
  // hides where it lands, which is above the entry that asked for it. A
  // landing the loop below then skips as already hidden stays in this list:
  // it refuses a carve-out the mounts alone would have allowed, which is the
  // safe direction and one comparison fewer.
  final readDeniedLocations = [
    ...readDenyPlan().expand(
      (e) => e.mount == null || e.liftedFile ? <String>[] : [e.mount!.landing],
    ),
    ...credentialMaskFakes.keys,
  ];
  // What the read section hides at, inside, or around `target`, ignoring the
  // tmpfs landing at `landing` and every deny above it — those are what a
  // carve-out restored into that tmpfs is the exception to. Everything else
  // that overlaps the target wins over the carve-out. Both sides are resolved
  // locations: every read deny mounts where its entry resolves, and `target`
  // is what the carve-out resolves to, so no spelling has to be guessed at.
  // Returns the offending location, for the debug line.
  String? readDenialAround(String target, String landing) => readDeniedLocations
      .where(
        (denied) =>
            !isAtOrUnder(landing, denied) &&
            (isAtOrUnder(denied, target) || isAtOrUnder(target, denied)),
      )
      .firstOrNull;

  // What a tmpfs unit binds back. A path whose name lives at or beneath the
  // landing of a credential deny is bound back by no unit, the library's own
  // files apart. A path above such a landing is, and the credential deny,
  // being deeper, is mounted after it.
  final credentialLandings = readDenyPlan()
      .expand(
        (e) =>
            e.mount != null && e.isCredential ? [e.mount!.landing] : <String>[],
      )
      .toList();
  final leftOut = <String>{};
  bool outsideCredentials(String p) {
    final landing = credentialLandings
        .where((at) => isAtOrUnder(nameLocationOf(p), at))
        .firstOrNull;
    if (landing != null && !leftOut.contains(p)) {
      leftOut.add(p);
      logForDebugging(
        '[Sandbox Linux] $p is at or beneath the credential deny $landing: not bound back',
        level: 'warn',
      );
    }
    return landing == null;
  }

  final restorableReadPaths = readAllowPaths()
      .where((p) => ownReadAllowPaths().contains(p) || outsideCredentials(p))
      .toList();
  final restorableWritePaths = allowedWritePaths
      .where(outsideCredentials)
      .toList();

  for (final (:normalizedPath, :mount, :liftedFile, isCredential: _)
      in readDenyPlan()) {
    if (mount == null) {
      logForDebugging(
        '[Sandbox Linux] Read deny path mounts nothing this wrap can place (absent, or uninspectable, or a link to \'/\' with nothing but \'/\' holding it): $normalizedPath',
      );
      continue;
    }
    final (:landing, :isDirectory, :isStandIn, named: _) = mount;
    // One mount per location. A tmpfs emitted so far already hides this
    // place, and nothing bound back over it shows the host there again, so a
    // mount here would be created inside that tmpfs and change nothing. This
    // also collapses two spellings of one directory, and the entries a
    // collapsed read-deny glob leaves beneath a directory it already denies.
    if (isHiddenByTmpfs(landing, 'writes and reads')) {
      logForDebugging(
        '[Sandbox Linux] Skipping read deny already hidden by a denyRead tmpfs: $landing',
      );
      continue;
    }

    if (isDirectory) {
      // A stand-in for an entry this wrap cannot vouch for hides everything
      // beneath it: nothing under it can be vouched for either. So does a
      // directory a glob expansion could not enumerate.
      if (isStandIn) {
        logForDebugging(
          '[Sandbox Linux] Read deny path $normalizedPath cannot be mounted where it names; hiding $landing instead',
          level: 'warn',
        );
      }
      final unlistable =
          unlistableDenyDirs.contains(normalizedPath) ||
          unlistableDenyDirs.contains(landing);
      if (unlistable) {
        logForDebugging(
          '[Sandbox Linux] Read-denied directory could not be listed when the glob was expanded; restoring nothing beneath it: $landing',
          level: 'warn',
        );
      }
      final restoresNothing = isStandIn || unlistable;
      final restored = _pushReadDenyDirMounts(args, (
        landing: landing,
        allowedWritePaths: restoresNothing ? [] : restorableWritePaths,
        readAllowPaths: restoresNothing ? [] : restorableReadPaths,
        resolve: canonicalLocationOf,
        readDenialAround: (restoreTarget) =>
            readDenialAround(restoreTarget, landing),
        nameLocation: nameLocationOf,
      ));
      readDenyTmpfsUnits.add((
        landing: landing,
        restoredWrites: restored.restoredWrites,
        restoredReads: restored.restoredReads,
      ));
    } else {
      // For files, only an exact allowRead match overrides the deny: an
      // entry that names this very file, through whatever symlinked
      // directories. One that is a symlink to it names the link and lifts
      // nothing, or a link planted at an allowRead path would cancel the deny
      // of the file it points at. A directory allowRead does not un-deny a
      // file specifically listed in denyRead — otherwise denyRead: ['.env']
      // + allowRead: ['.'] silently drops the .env deny.
      if (liftedFile) {
        logForDebugging(
          '[Sandbox Linux] Skipping read deny for re-allowed path: $normalizedPath',
        );
        continue;
      }
      // One mask per destination (see fileMaskLandings): spellings of one
      // file converge here, and each would otherwise mount over the last.
      if (fileMaskLandings.contains(landing)) {
        logForDebugging(
          '[Sandbox Linux] Skipping read deny at a destination a file mask already covers: $normalizedPath -> $landing',
        );
        continue;
      }
      fileMaskLandings.add(landing);
      // For files, bind /dev/null instead of tmpfs, where the path resolves
      // like every other read-deny mount.
      args.addAll(['--ro-bind', '/dev/null', landing]);
      fileMasks.add((source: '/dev/null', landing: landing));
    }
  }

  // Whole-file credential masks: same bind shape as a file read-deny,
  // at the same place — where the path really resolves, which is what
  // covers a credential dotfile that is a symlink into a dotfile manager's
  // directory (~/.netrc, ~/.npmrc). realPath was already normalized
  // (tilde-expanded, realpath'd) by the caller. The fake's parent dir is
  // explicitly ro-bound at the end of this function, so the bind source is
  // never writable from inside the sandbox.
  for (final MapEntry(key: landing, value: fakePath)
      in credentialMaskFakes.entries) {
    args.addAll(['--ro-bind', fakePath, landing]);
    fileMasks.add((source: fakePath, landing: landing));
  }

  // Ancestor pinning: the directories between a deny bind, file mask or
  // read-deny tmpfs and its covering allowed write root carry no mount, so
  // rename(2) on one moves the mount along with it and the path can be
  // recreated unprotected (mv .git aside; mkdir .git; write .git/hooks/x),
  // or, for a read-denied path, is simply not found by the next command's
  // wrap and left readable under its new name. ancestorPinArgs says what is
  // pinned and where. Seeds are landings because the walk takes dirname() of
  // each: a symlink spelling would pin the chain of the link, not of where
  // the mount sits. Deny binds, tmpfs units and masks are emitted later and
  // land on top of both pins and covers.
  final pinArgs = _ancestorPinArgs(
    [
      ...denyWriteRawDests.keys,
      ...fileMasks.map((mask) => mask.landing),
      ...readDenyTmpfsUnits.map((unit) => unit.landing),
    ],
    (
      rootIsWriteRoot: isAllowedWriteRoot('/'),
      isWithinAllowedWrite: isWithinAnyAllowedWritePath,
      isAllowedWriteRoot: isAllowedWriteRoot,
    ),
  );
  args.insertAll(ancestorPinInsertAt, pinArgs);
  // What the mandatory denies cost, for the refusal of a profile with too many
  // arguments: the pins above them here, their own binds as they are emitted.
  final pinned = <String>{...pinArgs};
  final mandatoryDenyPins = <String>{};
  for (var i = mandatoryDenyArgsStart; i < denyWriteArgs.length; i += 3) {
    for (
      var dir = path.dirname(denyWriteArgs[i + 2]);
      dir != '/' && !mandatoryDenyPins.contains(dir);
      dir = path.dirname(dir)
    ) {
      if (pinned.contains(dir)) mandatoryDenyPins.add(dir);
    }
  }
  var mandatoryDenyArgs = 3 * mandatoryDenyPins.length;

  // Emitting denyWrite last means these ro-binds layer on top of any write
  // paths the denyRead loop just re-bound. Before this ordering, tmpfs over
  // an ancestor of cwd would wipe the .git/hooks protection. But skip any
  // dest already masked by denyRead:
  //
  // - file masks: --ro-bind <host> <host> for denyWrite would undo
  //   --ro-bind /dev/null <host> from denyRead, which landed first.
  // - tmpfs dirs: a dest at or under a denyRead tmpfs is already hidden, and
  //   re-binding the host path on top of the tmpfs would expose the real
  //   (read-denied) contents read-only. Writes inside the tmpfs never reach
  //   the host, so the write-deny stays enforced without the bind. Exception:
  //   if an allowed write path at-or-under that tmpfs covers the dest, the
  //   denyRead loop re-bound it (the .git/hooks case) and the write-deny bind
  //   is still required on top.
  // Both are decided by where the mask or tmpfs landed against the deny's
  // canonical dest, which is where its bind lands.
  final emittedDenyWriteDests = <String>[];
  // Write paths already restored read-only by a dropped deny bind, so two
  // denies covering the same path emit one --ro-bind.
  final restoredReadOnlyWritePaths = <String>{};
  for (var i = 0; i < denyWriteArgs.length; i += 3) {
    final dest = denyWriteArgs[i + 2];
    if (unmakeableDenyDests.contains(dest)) continue;
    final rawDest = denyWriteRawDests[dest] ?? dest;
    // A mask's landing, not its dest: the landing is where the mask's bind
    // actually sits, and this deny's dest is canonical, so the two are
    // comparable as written.
    if (fileMasks.any((mask) => mask.landing == dest)) continue;
    if (isHiddenByTmpfs(dest, 'writes')) {
      logForDebugging(
        '[Sandbox Linux] Skipping denyWrite bind already hidden by denyRead tmpfs: $dest',
      );
      // The tmpfs hides this dest but not a write path one of the units
      // restored writable beneath it: that path is inside this write deny, so
      // restore it read-only, where the unit left it. Emitting the dest's own
      // bind instead would expose the read-denied directory around it.
      // uncoveredWritePaths counts on this restore.
      for (final unit in readDenyTmpfsUnits) {
        for (final writeMount in unit.restoredWrites) {
          final writePath = writeMount.dest;
          if (!isAtOrUnder(writePath, dest) &&
              !isAtOrUnder(writePath, rawDest)) {
            continue;
          }
          // A masked file needs no restore: its mask already holds it
          // unreadable and unwritable. A read-only bind of the real file here
          // would land ABOVE that mask, and the re-application below would
          // then have to put the mask back over a bind this loop only just
          // emitted — so skipping saves both that bind and its emitted-dest
          // entry. A masked file strictly BENEATH a restored directory is the
          // other case and stays: recording that directory is what puts its
          // mask back on top. Masks and restores are both keyed by where they
          // land, so one comparison answers for every spelling.
          if (fileMasks.any((mask) => mask.landing == writePath)) {
            logForDebugging(
              '[Sandbox Linux] Leaving a masked file to its mask inside dropped denyWrite bind $dest: $writePath',
            );
            continue;
          }
          if (restoredReadOnlyWritePaths.contains(writePath)) continue;
          restoredReadOnlyWritePaths.add(writePath);
          args.addAll(['--ro-bind', writeMount.source, writePath]);
          // Like a deny bind, this one lands above whatever the read section
          // mounted inside the write path, so the re-application passes below
          // have to see it and put those mounts back.
          emittedDenyWriteDests.add(writePath);
          logForDebugging(
            '[Sandbox Linux] Restoring write path read-only inside dropped denyWrite bind $dest: $writePath',
          );
        }
      }
      continue;
    }
    args.addAll([denyWriteArgs[i], denyWriteArgs[i + 1], dest]);
    if (i >= mandatoryDenyArgsStart) mandatoryDenyArgs += 3;
    emittedDenyWriteDests.add(dest);
    // The tmpfs / mask re-application passes below ask "does this bind sit
    // above a read-denied path?". A bind at the resolved dest also re-exposes
    // anything under the symlinked spelling, so record both.
    if (rawDest != dest) emittedDenyWriteDests.add(rawDest);
  }

  // The inverse stacking problem: a denyWrite ro-bind whose dest strictly
  // contains a read-denied dir re-exposes that dir's real contents (the bind
  // landed after the tmpfs). Re-apply the tmpfs on top, with the allowRead
  // re-binds the denyRead loop emitted. A bind of '/' itself (allowOnly and
  // denyWithinAllow both naming it) contains every one of them, so
  // containment is root-aware. An allowed write path beneath such a tmpfs
  // lies inside the emitted deny dest too, so the deny wins: it comes back
  // read-only, visible as it was after the first pass but not writable.
  // Deeper units and masks under the same dest follow in the same order as
  // the first pass, so nothing restored here stays on top of one.
  for (final unit in readDenyTmpfsUnits) {
    final reExposingDest = emittedDenyWriteDests
        .where((dest) => isStrictlyUnder(unit.landing, dest))
        .firstOrNull;
    if (reExposingDest != null) {
      logForDebugging(
        '[Sandbox Linux] Re-applying denyRead tmpfs re-exposed by denyWrite bind: ${unit.landing}',
      );
      // Name the paths that lose their write access here, and to which deny.
      if (unit.restoredWrites.isNotEmpty) {
        logForDebugging(
          '[Sandbox Linux] Restoring write paths read-only inside denyWrite bind $reExposingDest: ${unit.restoredWrites.map((w) => w.dest).join(', ')}',
        );
      }
      // The recorded pairs go back as they are: each restore returns to where
      // the first pass put it, from the source it vetted then. Write paths
      // come back read-only, being inside the deny that re-exposed the tmpfs.
      // The tmpfs goes back at the unit's landing, which is the destination
      // the first pass gave bwrap for it.
      args.addAll(['--tmpfs', unit.landing]);
      for (final restored in [...unit.restoredWrites, ...unit.restoredReads]) {
        args.addAll(['--ro-bind', restored.source, restored.dest]);
      }
    }
  }
  // Same problem for masked files: the mask landed before the denyWrite
  // ancestor bind, so the real file is back. Re-apply the mask with its
  // original source (/dev/null for read-deny, the fake for credential mask).
  for (final mask in fileMasks) {
    if (emittedDenyWriteDests.any((dest) => isAtOrUnder(mask.landing, dest))) {
      logForDebugging(
        '[Sandbox Linux] Re-applying file mask re-exposed by denyWrite bind: ${mask.landing}',
      );
      args.addAll(['--ro-bind', mask.source, mask.landing]);
    }
  }

  // INVARIANT: the fake-file store directory must never be writable from
  // inside the sandbox. If it were, a sandboxed process could plant a
  // symlink at a fake path and a later host-side write() would follow it,
  // or replace a fake's content so the bind exposes attacker bytes. Emit
  // last so it overlays any earlier --bind that covers the store dir
  // (e.g. allowWrite: ['/tmp'] when the store is under os.tmpdir()).
  if (maskedFileStoreDir != null) {
    args.addAll(['--ro-bind', maskedFileStoreDir, maskedFileStoreDir]);
  }

  // INVARIANT, for the same reason: the empty directory the placeholders above
  // bind from must never be writable from inside the sandbox. It lives under
  // the system temp dir, so a caller's allowWrite or a host $TMPDIR under a
  // default write path makes it writable — and a placeholder binds it onto a
  // DENIED destination, so a write to the source lands at the deny. Emit last,
  // like the store, to overlay any earlier --bind that covers it. A same-uid
  // process on the host can still swap the source between wrap and run, which
  // is outside what this library defends against.
  if (emptySource != null) {
    args.addAll(['--ro-bind', emptySource!, emptySource!]);
  }

  return (args: args, mandatoryDenyArgs: mandatoryDenyArgs);
}

/**
 * Wrap a command with sandbox restrictions on Linux
 *
 * UNIX SOCKET BLOCKING (APPLY-SECCOMP):
 * This implementation uses a custom apply-seccomp binary to block Unix domain socket
 * creation for user commands while allowing network infrastructure:
 *
 * The two stages are described in README.md, "Unix Socket Restrictions
 * (Linux)".
 *
 * This solves the conflict between:
 * - Security: Blocking arbitrary Unix socket creation in user commands
 * - Functionality: Network sandboxing requires socat to call socket(AF_UNIX, ...) for bridge connections
 *
 * The seccomp-bpf filter blocks socket(AF_UNIX, ...) syscalls, preventing:
 * - Creating new Unix domain socket file descriptors
 *
 * It also blocks socket(AF_VSOCK, ...): the network namespace does not fence
 * VM sockets, so one would reach out of the sandbox past the proxies.
 *
 * Security limitations:
 * - Does NOT block operations (bind, connect, sendto, etc.) on inherited Unix socket FDs
 * - Does NOT prevent passing Unix socket FDs via SCM_RIGHTS
 * - For most sandboxing use cases, blocking socket creation is sufficient
 *
 * The filter allows:
 * - All TCP/UDP sockets (AF_INET, AF_INET6) for normal network operations
 * - All other syscalls
 *
 * PLATFORM NOTE:
 * The allowUnixSockets configuration is not path-based on Linux (unlike macOS)
 * because seccomp-bpf cannot inspect user-space memory to read socket paths.
 *
 * Requirements for seccomp filtering:
 * - Pre-built apply-seccomp binaries are included for x64 and ARM64
 * - Pre-generated BPF filters are included for x64 and ARM64
 * - Other architectures are not currently supported (no apply-seccomp binary available)
 * - To use sandboxing without Unix socket blocking on unsupported architectures,
 *   set allowAllUnixSockets: true in your configuration
 * Dependencies are checked by checkLinuxDependencies() before enabling the sandbox.
 *
 * CALLER OBLIGATION: the euid and capability decisions behind the returned
 * string are made here, in the process that builds it, so the string must be
 * run by a process with the same euid and the same capability bounding and
 * inheritable sets.
 */
Future<String> wrapCommandWithSandboxLinux(LinuxSandboxParams params) async {
  final command = params.command;
  final commandId = params.commandId;
  final needsNetworkRestriction = params.needsNetworkRestriction;
  final httpSocketPath = params.httpSocketPath;
  final socksSocketPath = params.socksSocketPath;
  final httpProxyPort = params.httpProxyPort;
  final socksProxyPort = params.socksProxyPort;
  final proxyAuthToken = params.proxyAuthToken;
  final caCertPath = params.caCertPath;
  final javaAgentJarPath = params.javaAgentJarPath;
  final unsetEnvVars = params.unsetEnvVars;
  final setEnvVars = params.setEnvVars;
  final maskedFileBinds = params.maskedFileBinds;
  final maskedFileStoreDir = params.maskedFileStoreDir;
  final enableWeakerNestedSandbox = params.enableWeakerNestedSandbox;
  final allowNestedUserNamespaces = params.allowNestedUserNamespaces;
  final allowAllUnixSockets = params.allowAllUnixSockets;
  final binShell = params.binShell;
  // TELOSNEX DEVIATION: Use a private TMPDIR independent of proxying.
  final temporaryDirectory = params.temporaryDirectory;
  final ripgrepConfig = params.ripgrepConfig ?? RipgrepConfig(command: 'rg');
  final mandatoryDenySearchDepth =
      params.mandatoryDenySearchDepth ?? _DEFAULT_MANDATORY_DENY_SEARCH_DEPTH;
  final allowGitConfig = params.allowGitConfig ?? false;
  final gitSafeDirectories = params.gitSafeDirectories;
  final seccompConfig = params.seccompConfig;
  final bwrapPath = params.bwrapPath;
  final socatPath = params.socatPath;
  final observeSocketPath = params.observeSocketPath;
  final abortSignal = params.abortSignal;
  // bubblewrap takes no patterns, so every path here is a name. The literal
  // lists are folded into the lists they belong to, once, so that nothing
  // below can read a list and miss them; a pattern in `allowOnly` that is no
  // name is dropped by the fold (see writeNamesOf).
  final readConfig = readNamesOf(params.readConfig);
  final writeConfig = writeNamesOf(params.writeConfig);

  // Determine if we have restrictions to apply
  // Read: denyOnly pattern - empty array means no restrictions
  // Write: allowOnly pattern - undefined means no restrictions, any config means restrictions
  final hasReadRestrictions =
      (readConfig != null && readConfig.denyOnly.isNotEmpty) ||
      (maskedFileBinds != null && maskedFileBinds.isNotEmpty);
  final hasWriteRestrictions = writeConfig != null;
  final hasEnvRestrictions =
      (unsetEnvVars != null && unsetEnvVars.isNotEmpty) ||
      (setEnvVars != null && setEnvVars.keys.isNotEmpty);
  final hasGitConfig = (gitSafeDirectories?.length ?? 0) > 0;

  // Check if we need any sandboxing
  if (!needsNetworkRestriction &&
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

  // Mark this sandbox invocation as active. cleanupBwrapMountPoints() will
  // defer file deletion until this (and every other concurrent) invocation
  // has been cleaned up. The matching decrement happens in
  // cleanupBwrapMountPoints(), which the caller must invoke after the
  // spawned command exits. If wrapping fails below, the catch block
  // decrements so the count does not leak.
  _activeSandboxCount++;
  final countedAfter = _forcedCleanups;

  // One encoded key for both carriers below (SRT_ENCODED_CMD for the seccomp
  // observer, the proxy username for network denies), so a violation seen
  // through either resolves to the same registry entry. macOS derives its log
  // tag from a single key the same way.
  final attributionKey = encodeSandboxedCommand(
    attributionKeyFor(command, commandId),
  );

  final bwrapArgs = <String>['--new-session', '--die-with-parent'];
  String? applySeccompPrefix;

  try {
    // ========== SECCOMP FILTER (Unix Socket Blocking) ==========
    // apply-seccomp wraps the workload and applies the baked-in BPF filter
    // that blocks socket(AF_UNIX, ...). Skipped when allowAllUnixSockets is true.
    if (!(allowAllUnixSockets ?? false)) {
      applySeccompPrefix = _resolveApplySeccompPrefix(
        seccompConfig?.applyPath,
        seccompConfig?.argv0,
      );

      if (applySeccompPrefix == null || applySeccompPrefix.isEmpty) {
        logForDebugging(
          '[Sandbox Linux] apply-seccomp binary not available - unix socket blocking disabled. ' + 'Install @anthropic-ai/sandbox-runtime globally for full protection.',
          level: 'warn',
        );
      } else {
        applySeccompPrefix =
            _helperEnvironmentPrefix(allowNestedUserNamespaces == true) +
            applySeccompPrefix;
        logForDebugging(
          '[Sandbox Linux] Applying seccomp filter for Unix socket blocking',
        );
      }
    } else {
      logForDebugging(
        '[Sandbox Linux] Skipping seccomp filter - allowAllUnixSockets is enabled',
      );
    }

    // ========== VIOLATION OBSERVATION (best-effort) ==========
    // Only meaningful when apply-seccomp will run — it is the binary that
    // installs the USER_NOTIF filter and ships the listener fd.
    if (observeSocketPath != null &&
        observeSocketPath.isNotEmpty &&
        applySeccompPrefix != null &&
        applySeccompPrefix.isNotEmpty) {
      if (fs.existsSync(observeSocketPath)) {
        bwrapArgs.addAll(['--bind', observeSocketPath, observeSocketPath]);
        bwrapArgs.addAll(['--setenv', 'SRT_OBSERVE_SOCK', observeSocketPath]);
        // Tag events with the encoded command so the violation store can
        // associate them with this invocation (parity with macOS log tag).
        bwrapArgs.addAll(['--setenv', 'SRT_ENCODED_CMD', attributionKey]);
      } else {
        logForDebugging(
          '[Sandbox Linux] observe socket missing — supervisor not running; ' +
              'continuing without violation monitoring',
        );
      }
    }

    // ========== ENV RESTRICTIONS ==========
    // Drop denied credential env vars from the inherited environment. Emitted
    // before the proxy --setenv flags below: bwrap applies env operations in
    // argument order, so SRT's own proxy plumbing vars survive even if a
    // caller lists one of them as a denied credential.
    if (hasEnvRestrictions) {
      for (final name in unsetEnvVars ?? const <String>[]) {
        bwrapArgs.addAll(['--unsetenv', name]);
      }
      // Masked credentials override the inherited real value with a
      // sentinel; bwrap --setenv replaces any inherited value of NAME.
      for (final MapEntry(key: name, :value)
          in (setEnvVars ?? const <String, String>{}).entries) {
        bwrapArgs.addAll(['--setenv', name, value]);
      }
    }

    // ========== GIT CONFIG (safe.directory) ==========
    // Under `--unshare-user` the repo owner's uid is unmapped so git
    // sees dubious ownership. `buildPosixGitSafeDirEnv` composes
    // against the child's actual starting env (process.env inherited,
    // unsetEnvVars dropped, setEnvVars overlaid) so an ambient
    // GIT_CONFIG_COUNT is continued, not clobbered.
    if (gitSafeDirectories != null && gitSafeDirectories.isNotEmpty) {
      final gitCfg = buildPosixGitSafeDirEnv(
        safeDirs: gitSafeDirectories,
        unsetEnvVars: unsetEnvVars ?? const [],
        setEnvVars: setEnvVars ?? const {},
      );
      for (final MapEntry(key: name, :value) in gitCfg.entries) {
        bwrapArgs.addAll(['--setenv', name, value]);
      }
    }

    // ========== NETWORK RESTRICTIONS ==========
    if (needsNetworkRestriction) {
      // Always unshare network namespace to isolate network access
      // This removes all network interfaces, effectively blocking all network
      bwrapArgs.add('--unshare-net');

      // If proxy sockets are provided, bind them into the sandbox to allow
      // filtered network access through the proxy. If not provided, network
      // is completely blocked (empty allowedDomains = block all)
      if (httpSocketPath != null &&
          httpSocketPath.isNotEmpty &&
          socksSocketPath != null &&
          socksSocketPath.isNotEmpty) {
        // Verify socket files still exist before trying to bind them
        if (!fs.existsSync(httpSocketPath)) {
          throw NodeException(
            'Linux HTTP bridge socket does not exist: $httpSocketPath. ' + 'The bridge process may have died. Try reinitializing the sandbox.',
          );
        }
        if (!fs.existsSync(socksSocketPath)) {
          throw NodeException(
            'Linux SOCKS bridge socket does not exist: $socksSocketPath. ' + 'The bridge process may have died. Try reinitializing the sandbox.',
          );
        }

        // Bind both sockets into the sandbox
        bwrapArgs.addAll(['--bind', httpSocketPath, httpSocketPath]);
        // When the mux serves both protocols, socksSocketPath is the same
        // file as httpSocketPath; bwrap rejects a duplicate --bind of the
        // same source→target.
        if (socksSocketPath != httpSocketPath) {
          bwrapArgs.addAll(['--bind', socksSocketPath, socksSocketPath]);
        }

        // Add proxy environment variables
        // HTTP_PROXY points to the socat listener inside the sandbox (port 3128)
        // which forwards to the Unix socket that bridges to the host's proxy server
        final proxyEnv = generateProxyEnvVars(
          3128, // Internal HTTP listener port
          1080, // Internal SOCKS listener port
          caCertPath,
          proxyAuthToken,
          // TELOSNEX DEVIATION: Don't set the legacy shared TMPDIR when opted out
          // or when the command has its own temp directory.
          writeConfig == null ||
              params.skipDefaultTmpdir == true ||
              temporaryDirectory != null,
          attributionKey,
        );
        bwrapArgs.addAll(
          proxyEnv.expand((String env) {
            final firstEq = env.indexOf('=');
            final key = env.substring(0, firstEq);
            final value = env.substring(firstEq + 1);
            return ['--setenv', key, value];
          }),
        );

        // JVMs ignore the proxy env vars above; the agent jar translates
        // them into system properties + an Authenticator at JVM start
        // (see java-proxy-agent.ts). Composed against the inherited value
        // so a caller's own JAVA_TOOL_OPTIONS survives.
        final javaToolOptions = buildJavaToolOptions(
          agentJarPath: javaAgentJarPath,
          unsetEnvVars: unsetEnvVars,
          inherited: process.env['JAVA_TOOL_OPTIONS'],
        );
        if (javaToolOptions != null) {
          bwrapArgs.addAll(['--setenv', 'JAVA_TOOL_OPTIONS', javaToolOptions]);
        }

        // Add host proxy port environment variables for debugging/transparency
        // These show which host ports the Unix socket bridges connect to
        if (httpProxyPort != null) {
          bwrapArgs.addAll([
            '--setenv',
            'CLAUDE_CODE_HOST_HTTP_PROXY_PORT',
            '$httpProxyPort',
          ]);
        }
        if (socksProxyPort != null) {
          bwrapArgs.addAll([
            '--setenv',
            'CLAUDE_CODE_HOST_SOCKS_PROXY_PORT',
            '$socksProxyPort',
          ]);
        }
      }
      // If no sockets provided, network is completely blocked (--unshare-net without proxy)
    }

    // TELOSNEX DEVIATION: Set the command's TMPDIR whether or not proxy or
    // network isolation is active. Like the old proxy TMPDIR, it wins over
    // credential env overlays.
    if (temporaryDirectory != null) {
      bwrapArgs.addAll(['--setenv', 'TMPDIR', temporaryDirectory]);
    }

    // ========== FILESYSTEM RESTRICTIONS ==========
    final (args: fsArgs, :mandatoryDenyArgs) = await _generateFilesystemArgs(
      readConfig,
      writeConfig,
      maskedFileBinds,
      maskedFileStoreDir,
      ripgrepConfig,
      mandatoryDenySearchDepth,
      allowGitConfig,
      abortSignal,
      // TELOSNEX DEVIATION: carry the opt-out through to mount planning.
      params.registerProcessHandlers,
    );
    final mountsStart = bwrapArgs.length;
    bwrapArgs.addAll(fsArgs);
    final mounts = (
      start: mountsStart,
      end: bwrapArgs.length,
      mandatoryDenyArgs: mandatoryDenyArgs,
    );

    // Always bind /dev
    bwrapArgs.addAll(['--dev', '/dev']);

    // ========== PID NAMESPACE ISOLATION ==========
    // IMPORTANT: These must come AFTER filesystem binds for nested bwrap to work
    // By default, always unshare PID namespace and mount fresh /proc.
    // If we don't have --unshare-pid, it is possible to escape the sandbox.
    // If we don't have --proc, it is possible to read host /proc and leak information about code running
    // outside the sandbox. But, --proc is not available when running in unprivileged docker containers
    // so we support running without it if explicitly requested.
    bwrapArgs.add('--unshare-pid');
    // --unshare-user in both modes: bwrap only auto-creates a userns when
    // EUID != 0. A root parent in an unprivileged container (Docker's
    // default: EUID=0 without CAP_SYS_ADMIN) would otherwise try a direct
    // clone and EPERM.
    final euid = process.geteuid?.call();
    final hasSetfcap = processHasBoundingCapability(CAP_SETFCAP);
    if (euid == 0 && !hasSetfcap && !_setfcapMissingLogged) {
      _setfcapMissingLogged = true;
      logForDebugging(
        '[Sandbox Linux] $CAP_SETFCAP_MISSING_MESSAGE',
        level: 'warn',
      );
    }
    bwrapArgs.addAll([
      '--unshare-user',
      ...capabilityArgs(
        euid: euid,
        hasSetfcap: hasSetfcap,
        usesSeccompHelper: applySeccompPrefix != null,
      ),
    ]);
    if (!(enableWeakerNestedSandbox ?? false)) {
      // Mount fresh /proc if PID namespace is isolated (secure mode).
      bwrapArgs.addAll(['--proc', '/proc']);
    } else {
      // --bind /proc /proc: apply-seccomp's nested-userns path writes
      // /proc/self/setgroups and uid_map. Without --proc above, the
      // --ro-bind / / leaves /proc read-only and those writes EROFS; a
      // fresh proc mount is what an unprivileged container refuses.
      bwrapArgs.addAll(['--bind', '/proc', '/proc']);
    }

    // The caller's environment decides nothing about the command's namespaces:
    // the variable is cleared after every other environment operation, which
    // bubblewrap applies in argument order, and helperEnvironmentPrefix sets it.
    bwrapArgs.addAll(['--unsetenv', _NESTED_USERNS_ENV]);

    // With no helper to refuse user namespaces, bubblewrap is asked to. Never
    // beside the helper, which makes one of its own, and not under
    // enableWeakerNestedSandbox: bubblewrap does it by writing a sysctl, and
    // dies on the read-only /proc/sys of an unprivileged container.
    if (applySeccompPrefix == null && allowNestedUserNamespaces != true) {
      final bwrap = enableWeakerNestedSandbox == true
          ? null
          : (bwrapPath ?? whichSync('bwrap'));
      if (bwrap != null && bwrapCanDisableUserns(bwrap)) {
        bwrapArgs.add('--disable-userns');
      } else if (!_noUsernsLimitLogged) {
        _noUsernsLimitLogged = true;
        logForDebugging(
          '[Sandbox Linux] no seccomp helper in use, and bubblewrap cannot disable user namespaces ' +
              '(needs 0.8.0 or later, not setuid, and no enableWeakerNestedSandbox) - ' +
              'a sandboxed command that creates one can undo the write denies',
          level: 'warn',
        );
      }
    }

    // apply-seccomp obtains CAP_SYS_ADMIN for its nested PID+mount unshare
    // by creating a nested user namespace. This requires the host to permit
    // capability-bearing unprivileged user namespaces (the same requirement
    // bwrap itself has when not installed setuid). See README for the
    // Ubuntu 24.04 sysctl if AppArmor restricts this.

    // ========== COMMAND ==========
    // Use the user's shell (zsh, bash, etc.) to ensure aliases/snapshots work
    // Resolve the full path to the shell binary since bwrap doesn't use $PATH
    final shellName = binShell != null && binShell.isNotEmpty
        ? binShell
        : 'bash';
    final shell = whichSync(shellName);
    if (shell == null || shell.isEmpty) {
      throw NodeException("Shell '$shellName' not found in PATH");
    }
    bwrapArgs.addAll(['--', shell, '-c']);

    // With network restrictions, route the command through buildSandboxCommand
    // so socat starts before seccomp is applied. Otherwise invoke apply-seccomp
    // directly if we have a binary.
    if (needsNetworkRestriction &&
        httpSocketPath != null &&
        httpSocketPath.isNotEmpty &&
        socksSocketPath != null &&
        socksSocketPath.isNotEmpty) {
      final sandboxCommand = _buildSandboxCommand(
        httpSocketPath,
        socksSocketPath,
        command,
        applySeccompPrefix,
        shell,
        socatPath,
      );
      bwrapArgs.add(sandboxCommand);
    } else if (applySeccompPrefix != null && applySeccompPrefix.isNotEmpty) {
      final applySeccompCmd =
          applySeccompPrefix + quote([shell, '-c', command]);
      bwrapArgs.add(applySeccompCmd);
    } else {
      bwrapArgs.add(command);
    }

    final wrappedCommand = _renderBwrapInvocation(
      bwrapPath ?? 'bwrap',
      bwrapArgs,
      mounts,
    );

    final restrictions = <String>[];
    if (needsNetworkRestriction) restrictions.add('network');
    if (hasReadRestrictions || hasWriteRestrictions)
      restrictions.add('filesystem');
    if (hasEnvRestrictions) restrictions.add('env');
    if (applySeccompPrefix != null && applySeccompPrefix.isNotEmpty)
      restrictions.add('seccomp(unix-block)');

    logForDebugging(
      '[Sandbox Linux] Wrapped command with bwrap (${restrictions.join(', ')} restrictions)',
    );

    // INVARIANT: a wrap that hands out a command is in the count when it does,
    // whatever a forced cleanup did meanwhile: its caller gives one back.
    if (_forcedCleanups != countedAfter) _activeSandboxCount++;
    return wrappedCommand;
  } catch (error) {
    // Undo the activeSandboxCount increment — the caller won't call
    // cleanupBwrapMountPoints() for a wrap that threw. A command that ended
    // meanwhile deferred its removal to this wrap, so it runs here. After a
    // forced cleanup the count is of other sandboxes only: one taken from it
    // has their mount points removed while they run.
    if (_forcedCleanups == countedAfter) cleanupBwrapMountPoints();
    rethrow;
  }
}
