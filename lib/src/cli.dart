// Ported from sandbox-runtime src/cli.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments, constant_identifier_names, non_constant_identifier_names, prefer_interpolation_to_compose_strings
import 'dart:convert';
import 'dart:async';
import 'dart:typed_data';

import 'utils/shell_quote.dart' show quote;
import 'node/commander.dart' show Command, InvalidArgumentError;
import 'index.dart' show SandboxManager;
import 'sandbox/sandbox_config.dart'
    show SandboxRuntimeConfig, SrtWinConfig, WindowsConfig;
import 'node/child_process.dart' show spawn;
import 'utils/debug.dart' show logForDebugging;
import 'utils/config_loader.dart'
    show
        loadConfig,
        loadConfigFromString,
        LoadConfigResultOk,
        LoadConfigResultUnreadable,
        LoadConfigResultInvalid;
import 'node/readline.dart' as readline;
import 'node/fs.dart' as fs;
import 'node/net.dart' as net;
import 'package:path/path.dart' as path;
import 'node/stream_promises.dart' show finished;
import 'node/os.dart' as os;
import 'node/abort.dart' show AbortController;
import 'node/console.dart' as console;
import 'node/emitted_http.dart' show runsOnBun;
import 'node/errno.dart' show NodeError, NodeException, errorMessage;
import 'node/globals.dart';
import 'node/process.dart' as process;
import 'node/stream.dart' as stream;
import 'sandbox/sandbox_config.dart' show NetworkConfig, FilesystemConfig;
import 'sandbox/windows_sandbox_utils.dart' as windows_sandbox_utils;
import 'proxy_cli.dart' as proxy_cli;

// Dart has no JSON import: package.json's version, kept equal to pubspec.yaml.
const _pkg = (version: '1.0.0');

/**
 * Get default config path
 */
String _getDefaultConfigPath() {
  return path.join(os.homedir(), '.srt-settings.json');
}

/**
 * The version `--version` reports, from the package's own manifest, which
 * sits one directory above both src/cli.ts and dist/cli.js. A static import
 * rather than a runtime require, so a single-file build (`bun build
 * --compile`) embeds it instead of looking for a package.json beside the
 * binary. There is still no fallback: a plausible-looking wrong version is
 * worse than failing, because the README pins behaviour to specific releases.
 */
String _getPackageVersion() {
  return _pkg.version;
}

/**
 * How long a command that ignores SIGTERM gets before SIGKILL.
 */
const _KILL_GRACE_MS = 2000;

/**
 * Exit rather than run under the built-in defaults, naming what that would
 * cost. The defaults are not a weaker version of any settings file — they
 * are a different config, so falling back to them drops rules rather than
 * relaxing them.
 */
Never _refuseSettings(String reason, String lost) {
  console.error('Error: $reason');
  console.error(
    'Refusing to run with the built-in defaults, which would drop $lost.',
  );
  process.exit(1);
}

/**
 * What a fall-back to the built-in defaults costs when the file is there.
 */
const _FILE_RULES =
    "this file's rules (its denyRead, allowRead and credential entries included)";

/**
 * Create a minimal default config if no config file exists
 */
SandboxRuntimeConfig _getDefaultConfig() {
  return const SandboxRuntimeConfig(
    network: NetworkConfig(allowedDomains: [], deniedDomains: []),
    filesystem: FilesystemConfig(
      denyRead: [],
      allowRead: [],
      allowWrite: [],
      denyWrite: [],
    ),
  );
}

/**
 * A readable stream over the control fd. A pipe or socket is read through a
 * libuv stream handle, driven by the event loop: fs.createReadStream would
 * park a threadpool thread in a blocking read(2) that process.exit() then
 * waits for, so srt would outlive the wrapped command until the parent
 * closed the fd. Anything else keeps the fs stream, which is right for a
 * regular file (its reads never block) and leaves a tty with the old wait.
 * Under Bun, net.Socket({ fd }) reads nothing, and Bun's fs stream does not
 * hold exit, so the fs stream serves every fd kind there.
 *
 * A libuv handle switches the fd's open file description to non-blocking
 * mode, from the moment srt opens it and for good (Node restores only fds
 * 0-2 at exit). A parent that shares that description (a shell
 * `exec 3<fifo`, a Python pass_fds of an fd it keeps using) then sees
 * EAGAIN on its own blocking reads, so hand srt a dedicated pipe end.
 */
stream.Readable _openControlFd(int fd) {
  // fstat succeeds on descriptors srt can never read a byte from — one
  // opened write-only, the write end of a pipe — and a reader over those
  // fails only once the command is already running. A zero-length readv(2)
  // asks the kernel whether a read is permitted at all without performing
  // one: EBADF for those, 0 for every readable kind, on both node and bun,
  // without blocking on an empty pipe or consuming a byte of a full one.
  fs.readvSync(fd, [Uint8List(0)]);
  final stat = fs.fstatSync(fd);
  if (!runsOnBun() && (stat.isFIFO() || stat.isSocket())) {
    try {
      return net.NodeSocket(fd: fd, readable: true, writable: false).unref();
    } catch (err) {
      final code = err is NodeError ? err.code : null;
      if (code != 'ERR_INVALID_FD_TYPE') {
        // ERR_INVALID_FD_TYPE is the only refusal that leaves the fd
        // untouched (a datagram or seqpacket socket, which the fs stream
        // still reads, one read(2) per datagram). Every other failure comes
        // out of uv_pipe_open, which has already switched the fd to
        // non-blocking mode: an fs stream over it would read EAGAIN
        // forever, so no fallback is left to take.
        throw NodeException(
          'could not be adopted as a stream (${code ?? '$err'})',
        );
      }
      logForDebugging(
        'Control fd $fd is not a stream socket (${errorMessage(err)}); reading it through fs',
      );
    }
  }
  return fs.createReadStream('', fd: fd);
}

/**
 * Parse --control-fd: an integer descriptor number >= 3.
 */
num _parseControlFd(String value) {
  // Number() alone would also take '0x10', '3e0' and ' 5 '.
  if (!RegExp(r'^\d+$').hasMatch(value) || Number(value) < 3) {
    throw InvalidArgumentError(
      'must be an integer file descriptor >= 3 (0-2 are stdin, stdout and stderr).',
    );
  }
  return Number(value);
}

/**
 * stdio for the sandboxed command: the three standard streams, plus
 * /dev/null over the control fd's slot, so nothing inside the sandbox can
 * read the channel that carries the policy confining it.
 *
 * The displacement is what matters on Linux. On macOS libuv spawns through
 * posix_spawn with POSIX_SPAWN_CLOEXEC_DEFAULT, which already keeps every
 * descriptor the caller did not list out of the child.
 */
List<Object> _sandboxedStdio(int? controlFd) {
  // Each entry is 'inherit', 'ignore' or a descriptor number.
  final stdio = <Object>['inherit', 'inherit', 'inherit'];
  if (controlFd == null) {
    return stdio;
  }
  // 'ignore' past fd 2 leaves a slot as it is rather than closing it, so the
  // control fd's slot needs a descriptor of its own to displace it with.
  while (stdio.length < controlFd) {
    stdio.add('ignore');
  }
  // Only close-on-exec keeps an inherited descriptor out of an exec'd
  // command, and uv_disable_stdio_inheritance() stops at the first closed
  // number above 15, so `--control-fd 20` with 16-19 closed leaves the
  // channel live in the sandbox. Displacing the slot covers every kind of
  // descriptor, which re-opening the fd privately does not: a unix socket
  // cannot be re-opened through /proc/self/fd at all (ENXIO).
  stdio.add(fs.openSync('/dev/null', 'r'));
  return stdio;
}

// Dart: the arguments come from bin/srt.dart (Node's process.argv.slice(2)).
Future<void> _main(List<String> argv) async {
  final program = Command();

  program
      .name('srt')
      .description(
        'Run commands in a sandbox with network and filesystem restrictions',
      )
      .version(_getPackageVersion());

  // ── Windows install/uninstall ─────────────────────────────────
  // Self-elevating one-shot install (one UAC prompt). Also
  // available programmatically as installWindowsSandbox().
  program
      .command('windows-install')
      .description(
        'Windows: provision the `srt-sandbox` user account + install WFP '
        'filters (one UAC prompt), then make your user profile readable '
        'to sandboxed commands, except for credential stores (no '
        'elevation; minutes on a large profile the first time). No '
        'logout needed. Run it again after upgrading sandbox-runtime '
        'when a command asks for it, or to bring the profile read grant '
        'up to date: it upgrades the existing install in place.',
      )
      .option('--sublayer-guid <guid>', 'WFP sublayer GUID')
      .option(
        '--proxy-port-range <lo-hi>',
        'loopback PERMIT port range (e.g. 60080-60089)',
      )
      .option(
        '--allow-loopback',
        'let sandboxed commands connect to any localhost port (default: '
            'off); must match network.allowLocalBinding',
      )
      .option(
        '--sandbox-user <name>',
        'name for the sandbox user account (default: srt-sandbox)',
      )
      .option('--force', 'replace an existing install with different config')
      .option(
        '--profile-exclude <path>',
        'a path inside your profile to keep unreadable in addition to the '
            'built-in exclusions (repeatable)',
        null,
        <String>[],
        (v, acc) => [...(acc as List<String>), v],
      )
      .option(
        '--profile-include <path>',
        'a directory inside your profile to make readable in addition to '
            'the built-in list of per-user tool directories (repeatable)',
        null,
        <String>[],
        (v, acc) => [...(acc as List<String>), v],
      )
      .option(
        '--skip-profile-grant',
        'install the account and the filters only; sandboxed commands '
            'then read nothing in your profile (use this on a computer other '
            'people have accounts on)',
      )
      .action((args) async {
        final o = args[0] as Map<String, Object?>;
        final installWindowsSandboxAsync =
            windows_sandbox_utils.installWindowsSandboxAsync;
        final resolveSrtWin = windows_sandbox_utils.resolveSrtWin;
        final VENDORED_SRT_WIN_EXE = windows_sandbox_utils.VENDORED_SRT_WIN_EXE;
        final WINDOWS_ALLOW_LOOPBACK_EFFECT =
            windows_sandbox_utils.WINDOWS_ALLOW_LOOPBACK_EFFECT;
        final range = o['proxyPortRange'] is String
            ? (() {
                final parts = (o['proxyPortRange'] as String)
                    .split('-')
                    .map(Number)
                    .toList();
                return (parts[0].toInt(), parts[1].toInt());
              })()
            : null;
        try {
          final r = await installWindowsSandboxAsync(
            sublayerGuid: o['sublayerGuid'] as String?,
            proxyPortRange: range,
            allowLoopback: o['allowLoopback'] == true,
            sandboxUser: o['sandboxUser'] as String?,
            force: o['force'] == true,
            skipProfileGrant: o['skipProfileGrant'] == true,
            profileExclude: o['profileExclude'] as List<String>,
            profileInclude: o['profileInclude'] as List<String>,
            // One line on what is about to become readable, and how to
            // skip or undo it, before the grant is applied.
            onProfileGrantStart: (notice) => console.error(notice),
            onProfileGrantProgress: (line) => console.error(line),
            // Our own CLI opts into the packaged exe explicitly —
            // there is no ambient vendor fallback.
            srtWin: resolveSrtWin(SrtWinConfig(path: VENDORED_SRT_WIN_EXE)),
          );
          if (r.cancelled == true) {
            console.error(
              'Install cancelled at the UAC prompt. Nothing changed.',
            );
            process.exit(2);
          }
          console.log(
            'Installed.\n'
                    '  sandbox user: ${r.user.provisioned ? 'provisioned' : 'MISSING'}' +
                (r.user.sid != null ? ' (${r.user.sid})' : '') +
                '\n'
                    '  WFP:   ${r.wfp.state}, ${r.wfp.filters} filters' +
                (r.wfp.portRange != null
                    ? ', port range ${r.wfp.portRange!.$1}-${r.wfp.portRange!.$2}'
                    : '') +
                '\n'
                    '  profile read grant: ' +
                (switch (r.profileGrant) {
                  windows_sandbox_utils.WindowsInstallProfileGrantApplied(
                    :final result,
                  ) =>
                    'applied to ${result.profile} '
                        '(${result.granted} directories, '
                        '${result.denied} excluded, '
                        '${result.skipped.length} skipped)',
                  windows_sandbox_utils.WindowsInstallProfileGrantSkipped(
                    :final reason,
                  ) =>
                    'NOT applied — $reason',
                  null => 'NOT applied — unknown',
                }) +
                '\n\n'
                    'No logout needed — the WFP filter keys on the dedicated '
                    "`srt-sandbox` user's SID, so your network is unaffected." +
                (r.wfp.allowLoopback == true
                    ? '\n\n$WINDOWS_ALLOW_LOOPBACK_EFFECT'
                    : ''),
          );
        } catch (e) {
          console.error('Error: ${errorMessage(e)}');
          process.exit(1);
        }
      });

  program
      .command('windows-uninstall')
      .description(
        'Windows: remove WFP filters + the `srt-sandbox` account (one UAC prompt).',
      )
      .option('--sublayer-guid <guid>', 'WFP sublayer GUID')
      .action((args) async {
        final o = args[0] as Map<String, Object?>;
        final uninstallWindowsSandbox =
            windows_sandbox_utils.uninstallWindowsSandbox;
        final resolveSrtWin = windows_sandbox_utils.resolveSrtWin;
        final VENDORED_SRT_WIN_EXE = windows_sandbox_utils.VENDORED_SRT_WIN_EXE;
        try {
          final r = uninstallWindowsSandbox(
            sublayerGuid: o['sublayerGuid'] as String?,
            srtWin: resolveSrtWin(SrtWinConfig(path: VENDORED_SRT_WIN_EXE)),
          );
          if (r.cancelled == true) {
            console.error('Uninstall cancelled at the UAC prompt.');
            process.exit(2);
          }
          console.log('WFP filters and `srt-sandbox` account removed.');
        } catch (e) {
          console.error('Error: ${errorMessage(e)}');
          process.exit(1);
        }
      });

  program
      .command('proxy')
      .description(
        'Run only the HTTP proxy, deciding every request through an external decider on inherited fds.',
      )
      .allowUnknownOption()
      .helpOption(false)
      .argument('[args...]')
      .action((a) async {
        final args = (a[0] as List).cast<String>();
        final runProxyCli = proxy_cli.runProxyCli;
        await runProxyCli(args);
      });

  // Default command - run command in sandbox
  program
      .argument('[command...]', 'command to run in the sandbox')
      .option('-d, --debug', 'enable debug logging')
      .option(
        '-s, --settings <path>',
        'path to config file (default: ~/.srt-settings.json)',
      )
      .option(
        '-c <command>',
        'run command string directly (like sh -c), no escaping applied',
      )
      .option(
        '--control-fd <fd>',
        'read config updates from an inherited file descriptor >= 3 (JSON lines '
            'protocol; give srt a dedicated read-only end — see the README)',
        _parseControlFd,
      )
      .allowUnknownOption()
      .action((a) async {
        final commandArgs = (a[0] as List).cast<String>();
        final options = (
          debug: (a[1] as Map)['debug'] as bool?,
          settings: (a[1] as Map)['settings'] as String?,
          c: (a[1] as Map)['c'] as String?,
          controlFd: ((a[1] as Map)['controlFd'] as num?)?.toInt(),
        );
        try {
          // Enable debug logging if requested. logForDebugging() reads
          // SRT_DEBUG (not DEBUG, to avoid clashing with the npm `debug`
          // package and other tools) — keep this in sync with utils/debug.ts.
          if (options.debug == true) {
            process.env['SRT_DEBUG'] = 'true';
          }

          // Load config from file
          final configPath = (options.settings?.isNotEmpty ?? false)
              ? options.settings!
              : _getDefaultConfigPath();
          final loaded = loadConfig(configPath);
          SandboxRuntimeConfig runtimeConfig;
          switch (loaded.kind) {
            case 'ok':
              runtimeConfig = (loaded as LoadConfigResultOk).config;
            case 'missing':
              // A settings file that is not there is the documented way to
              // ask for the built-in defaults. One the caller named with
              // --settings is not: those are rules it asked to have applied.
              if (options.settings?.isNotEmpty ?? false) {
                _refuseSettings(
                  '$configPath does not exist.',
                  'the rules --settings asked for',
                );
              }
              logForDebugging(
                'No config found at $configPath, using default config',
              );
              runtimeConfig = _getDefaultConfig();
            case 'empty':
              // A file truncated to nothing is exactly the case where
              // falling back would drop rules that were in force yesterday.
              _refuseSettings(
                '$configPath is empty. Delete it, or put a config in it.',
                _FILE_RULES,
              );
            case 'unreadable':
            case 'invalid':
              _refuseSettings(
                loaded is LoadConfigResultUnreadable
                    ? loaded.reason
                    : (loaded as LoadConfigResultInvalid).reason,
                _FILE_RULES,
              );
            default:
              throw StateError('unreachable: ${loaded.kind}');
          }

          // Windows: srtWin.path is required (no ambient vendor
          // fallback). When the user's config doesn't set it, this
          // CLI opts into the packaged exe explicitly — that's our
          // code making the choice, not a library default.
          if (process.platform == 'win32' &&
              runtimeConfig.windows?.srtWin?.path == null) {
            final VENDORED_SRT_WIN_EXE =
                windows_sandbox_utils.VENDORED_SRT_WIN_EXE;
            final w = runtimeConfig.windows;
            runtimeConfig = SandboxRuntimeConfig(
              network: runtimeConfig.network,
              filesystem: runtimeConfig.filesystem,
              credentials: runtimeConfig.credentials,
              ignoreViolations: runtimeConfig.ignoreViolations,
              enableWeakerNestedSandbox:
                  runtimeConfig.enableWeakerNestedSandbox,
              allowNestedUserNamespaces:
                  runtimeConfig.allowNestedUserNamespaces,
              enableWeakerNetworkIsolation:
                  runtimeConfig.enableWeakerNetworkIsolation,
              allowAppleEvents: runtimeConfig.allowAppleEvents,
              ripgrep: runtimeConfig.ripgrep,
              mandatoryDenySearchDepth: runtimeConfig.mandatoryDenySearchDepth,
              allowPty: runtimeConfig.allowPty,
              seccomp: runtimeConfig.seccomp,
              bwrapPath: runtimeConfig.bwrapPath,
              socatPath: runtimeConfig.socatPath,
              javaAgentJarPath: runtimeConfig.javaAgentJarPath,
              windows: WindowsConfig(
                backend: w?.backend,
                sandboxUser: w?.sandboxUser,
                sublayerGuid: w?.sublayerGuid,
                wfpSublayerGuid: w?.wfpSublayerGuid,
                proxyPortRange: w?.proxyPortRange,
                srtWin: SrtWinConfig(path: VENDORED_SRT_WIN_EXE),
              ),
              git: runtimeConfig.git,
            );
          }

          // The wrapped command, once it exists: a control channel that
          // dies before it delivers anything takes it down with it.
          ({bool Function([Object signal]) kill})? child;
          var controlChannelFailed = false;
          var receivedAnyLine = false;
          var controlErrorReported = false;
          final controlFd = options.controlFd;

          void onControlError(Object err) {
            // Attached both to the stream and to the reader: the stream is
            // live from the moment the fd is opened, which is before the
            // reader exists, and readline re-emits an input error on the
            // reader as well. The channel is gone after the first error
            // either way, so it is reported once.
            if (controlErrorReported) {
              return;
            }
            controlErrorReported = true;
            if (receivedAnyLine) {
              // The channel did deliver. The config last applied stays in
              // force, so the command keeps running under it.
              console.error(
                'Error reading control fd $controlFd: ${errorMessage(err)}. The control channel is closed; no further updates will be applied.',
              );
              return;
            }
            // Nothing ever came through: this is the descriptor that would
            // not open, found one step later. The caller is sending updates
            // into a channel srt cannot read.
            console.error(
              'Error: control fd $controlFd failed before delivering an update: ${errorMessage(err)}. Refusing to run the command without the control channel it asks for.',
            );
            controlChannelFailed = true;
            if (child == null) {
              process.exit(1);
            }
            child.kill('SIGTERM');
            // The child's own exit is what exits srt; this covers a command
            // that ignores SIGTERM.
            setTimeout(() => child?.kill('SIGKILL'), _KILL_GRACE_MS).unref();
          }

          // Open and check the control fd before anything is built: a
          // refusal here has no proxy or Linux bridge to unwind, and
          // process.exit() cannot wait for the async reset() that would.
          stream.Readable? controlStream;
          if (controlFd != null) {
            try {
              controlStream = _openControlFd(controlFd);
            } catch (err) {
              // Same rule as an explicit --settings that will not load: a
              // caller that asked for a control channel gets an error, not
              // a run whose updates — including the ones that tighten the
              // sandbox — quietly go nowhere.
              console.error(
                'Error: --control-fd $controlFd is not usable: '
                '${errorMessage(err)}. '
                'Refusing to run the command without the control channel it asks for.',
              );
              process.exit(1);
            }
            controlStream.on('error', onControlError);
          }

          // Until there is a child to pass an interrupt on to, it stops the
          // run. The library's own handlers, which initialize() installs, only
          // clean up: left to them the command would be run all the same.
          final interrupted = AbortController();
          void interrupt(String signal) =>
              interrupted.abort(StateError('interrupted by $signal'));
          process.once('SIGINT', interrupt);
          process.once('SIGTERM', interrupt);
          void aboutToSpawn() {
            interrupted.signal.throwIfAborted();
            process.off('SIGINT', interrupt);
            process.off('SIGTERM', interrupt);
          }

          // Initialize sandbox with config
          logForDebugging('Initializing sandbox...');
          try {
            await SandboxManager.initialize(runtimeConfig);
          } catch (err) {
            // The library's own handler resets on the same signal, which
            // cancels initialize(): the interrupt is the reason to report.
            interrupted.signal.throwIfAborted();
            rethrow;
          }

          // Read config updates only now. The stream has been waiting
          // unread, so nothing the caller wrote meanwhile is lost, and an
          // update applied before initialize() would have been overwritten
          // by it.
          readline.Interface? controlReader;
          if (controlStream != null) {
            controlReader = readline.createInterface(
              input: controlStream,
              crlfDelay: double.infinity,
            );

            controlReader.on('line', (String line) {
              receivedAnyLine = true;
              final newConfig = loadConfigFromString(line);
              if (newConfig != null) {
                logForDebugging(
                  'Config updated from control fd: ${jsonEncode(newConfig)}',
                );
                SandboxManager.updateConfig(newConfig);
              } else if (line.trim().isNotEmpty) {
                // The caller has to learn its update was dropped whether
                // or not it runs srt with --debug; the line itself stays
                // in the debug log rather than on the terminal.
                console.error(
                  'Invalid config on control fd $controlFd: ignored, previous config still in force',
                );
                logForDebugging(
                  'Invalid config on control fd (ignored): $line',
                );
              }
            });

            controlReader.on('error', onControlError);

            // End of input just means the writer closed its end. The
            // command keeps running under the config last applied.
            logForDebugging('Listening for config updates on fd $controlFd');
          }

          // Cleanup control reader on exit
          process.on('exit', () {
            controlReader?.close();
          });

          // Determine command string based on mode
          String command;
          if (options.c?.isNotEmpty ?? false) {
            // -c mode: use command string directly, no escaping
            command = options.c!;
            logForDebugging('Command string mode (-c): $command');
          } else if (commandArgs.isNotEmpty) {
            // Default mode: argv-style invocation. The result is later
            // executed via `bash -c <command>`, so each arg must be
            // shell-quoted to survive that re-parse — a plain join(' ')
            // splits arguments containing whitespace (#157).
            command = quote(commandArgs);
            logForDebugging('Original command: $command');
          } else {
            console.error(
              'Error: No command specified. Use -c <command> or provide command arguments.',
            );
            process.exit(1);
          }

          logForDebugging(
            const JsonEncoder.withIndent(
              '  ',
            ).convert(SandboxManager.getNetworkRestrictionConfig()),
          );

          void onCommandExit(int? code, String? signal) {
            // Clean up bwrap mount point artifacts before exiting.
            // On Linux, bwrap creates empty files on the host when protecting
            // non-existent deny paths. This removes them.
            SandboxManager.cleanupAfterCommand();

            if (controlChannelFailed) {
              // srt killed the command over a dead control channel, so the
              // status it died with is not the run's result.
              process.exit(1);
            }

            if (signal != null) {
              if (signal == 'SIGINT' || signal == 'SIGTERM') {
                process.exit(0);
              } else {
                console.error('Process killed by signal: $signal');
                process.exit(1);
              }
            }
            process.exit(code ?? 0);
          }

          // Wrap the command with sandbox restrictions. On Windows
          // the wrapper returns an argv array that MUST be spawned
          // with {shell:false} — that's the boundary keeping the
          // command bytes off the host shell. On other platforms
          // we keep the existing shell-string path.
          if (process.platform == 'win32' &&
              SandboxManager.getWindowsBackend?.call()?.backend == 'mxc') {
            // The MXC SDK starts the command itself; there is no argv.
            final spawnSandboxed = SandboxManager.spawnSandboxed;
            if (spawnSandboxed == null) {
              throw NodeException('spawnSandboxed() is not available');
            }
            aboutToSpawn();
            final proc = await spawnSandboxed(command);
            // MXC has no signals: any kill ends the whole tree. Remember
            // which signal asked, so the exit reads as it does elsewhere.
            String? killedBy;
            child = (
              kill: ([Object signal = 'SIGTERM']) {
                killedBy = signal is String ? signal : 'SIGTERM';
                proc.kill();
                return true;
              },
            );
            proc.stdout?.pipe(process.stdout, end: false);
            proc.stderr?.pipe(process.stderr, end: false);
            final stdin = proc.stdin;
            if (stdin != null) {
              // The command may exit without reading its input.
              stdin.on('error', () {});
              process.stdin.pipe(stdin);
            }
            // Exit only once the command's output has been read to the
            // end and written out: a pipe on Windows is asynchronous,
            // and process.exit() would drop what is still queued.
            final drained = Future.wait(
              [proc.stdout, proc.stderr].map(
                (s) => s != null
                    ? finished(s).catchError((Object _) {})
                    : Future<void>.value(),
              ),
            );
            Future<void> flushed(process.WriteStream out) {
              final completer = Completer<void>();
              out.write('', () => completer.complete());
              return completer.future;
            }

            unawaited(
              proc
                  .wait()
                  .then((result) async {
                    await drained;
                    await Future.wait([
                      flushed(process.stdout),
                      flushed(process.stderr),
                    ]);
                    onCommandExit(result.exitCode, killedBy);
                  })
                  .catchError((Object error) {
                    console.error(
                      'Failed to execute command: ${errorMessage(error)}',
                    );
                    process.exit(1);
                  }),
            );
          } else if (process.platform == 'win32') {
            // env carries the proxy vars the sandboxed child must inherit.
            final (:argv, :env) = await SandboxManager.wrapWithSandboxArgv(
              command,
            );
            // No slot to displace: libuv passes only the stdio array's
            // entries to the child as CRT descriptors, so the control fd
            // is not among them (an inheritable HANDLE still reaches the
            // child, but unnamed — nothing there can find it).
            aboutToSpawn();
            final spawned = spawn(argv[0], argv.sublist(1), {
              'shell': false,
              'stdio': 'inherit',
              'env': env,
            });
            child = (kill: spawned.kill);
            spawned.on('exit', onCommandExit);
            spawned.on('error', (Object error) {
              console.error(
                'Failed to execute command: ${errorMessage(error)}',
              );
              process.exit(1);
            });
          } else {
            // The wrap can take seconds over a large tree.
            final sandboxedCommand = await SandboxManager.wrapWithSandbox(
              command,
              null,
              null,
              interrupted.signal,
            );
            aboutToSpawn();
            final spawned = spawn(sandboxedCommand, const [], {
              'shell': true,
              'stdio': _sandboxedStdio(controlFd),
            });
            child = (kill: spawned.kill);
            spawned.on('exit', onCommandExit);
            spawned.on('error', (Object error) {
              console.error(
                'Failed to execute command: ${errorMessage(error)}',
              );
              process.exit(1);
            });
          }

          // Handle cleanup on interrupt
          process.on('SIGINT', () {
            child?.kill('SIGINT');
          });

          process.on('SIGTERM', () {
            child?.kill('SIGTERM');
          });
        } catch (error) {
          console.error('Error: ${errorMessage(error)}');
          process.exit(1);
        }
      });

  await program.parse(argv);
}

/// The `srt` entry (upstream runs `main()` when cli.js loads).
Future<void> main(List<String> argv) async {
  try {
    await _main(argv);
  } catch (error) {
    console.error('Fatal error:', error);
    process.exit(1);
  }
}
