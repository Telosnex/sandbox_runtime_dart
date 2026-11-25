// TELOSNEX DEVIATION: Per-command write grants and TMPDIR have no upstream
// counterpart (PORT_WORKLOG.md, "Deviations from upstream").
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/sandbox_runtime.dart' hide Platform;
import 'package:sandbox_runtime/src/node/errno.dart' show NodeError;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart'
    show PartialSandboxRuntimeConfig;
import 'package:sandbox_runtime/src/utils/shell_quote.dart' show quote;
import 'package:sandbox_runtime/src/utils/which.dart' show whichSync;
import 'package:test/test.dart';

import '../helpers/bwrap_namespace.dart'
    show bwrapCanNamespace, bwrapCanNamespaceNetwork;

void main() {
  final platformSkip =
      Platform.isMacOS ||
          (Platform.isLinux &&
              whichSync('rg') != null &&
              whichSync('bwrap') != null &&
              bwrapCanNamespace())
      ? false
      : 'requires macOS or Linux with working bubblewrap and ripgrep';
  final proxySkip =
      platformSkip == false &&
          Platform.isLinux &&
          (whichSync('socat') == null || !bwrapCanNamespaceNetwork())
      ? 'requires socat and a working network namespace'
      : platformSkip;
  const filesystem = FilesystemConfig(
    denyRead: [],
    allowWrite: [],
    denyWrite: [],
  );
  const network = NetworkConfig(allowedDomains: [], deniedDomains: []);
  const shell = '/bin/bash';
  final savedCwd = Directory.current.path;
  late Directory fixtures;
  late String temporaryDirectory;
  late String hostTmpdir;
  late String home;
  late String other;
  late Map<String, String> env;
  late List<File> sharedProbes;
  Directory? createdSharedDir;

  setUp(() {
    // The network initializer binds a Unix socket under TMPDIR. macOS's
    // default system temp path can make it exceed the socket length limit.
    fixtures = Directory('/tmp').createTempSync('srt-command-tmp-');
    final base = fixtures.resolveSymbolicLinksSync();
    String make(String name) =>
        (Directory(path.join(base, name))..createSync()).path;
    temporaryDirectory = make("tmp [a] 'literal'");
    // With a spelling-based macOS rule, [a] as a glob would admit this dir.
    other = make("tmp a 'literal'");
    hostTmpdir = make('host-tmp');
    home = make('home');
    final work = make('work');
    Directory.current = work;
    env = {...Platform.environment, 'HOME': home, 'TMPDIR': hostTmpdir}
      ..remove('CLAUDE_CODE_TMPDIR')
      ..remove('CLAUDE_TMPDIR');
    process.setEnvForTesting(env);
    sharedProbes = [];
    createdSharedDir = null;
  });

  tearDown(() async {
    await SandboxManager.reset();
    process.setEnvForTesting(null);
    Directory.current = savedCwd;
    for (final file in sharedProbes) {
      if (file.existsSync()) file.deleteSync();
    }
    final sharedDir = createdSharedDir;
    if (sharedDir != null && sharedDir.listSync().isEmpty) {
      sharedDir.deleteSync();
    }
    fixtures.deleteSync(recursive: true);
  });

  void makeSharedProbePaths() {
    for (final dir in [
      Directory('/tmp/claude'),
      Directory(path.join(home, '.npm', '_logs')),
      Directory(path.join(home, '.claude', 'debug')),
    ]) {
      final exists = dir.existsSync();
      if (!exists) dir.createSync(recursive: true);
      if (dir.path == '/tmp/claude' && !exists) createdSharedDir = dir;
      sharedProbes.add(File(path.join(dir.path, path.basename(fixtures.path))));
    }
  }

  Future<String> run(
    String command, [
    PartialSandboxRuntimeConfig? customConfig,
  ]) async {
    final wrapped = await SandboxManager.wrapWithSandboxArgv(
      command,
      shell,
      customConfig,
    );
    try {
      final result = await Process.run(
        wrapped.argv.first,
        wrapped.argv.skip(1).toList(),
        environment: {
          for (final MapEntry(:key, :value) in wrapped.env.entries)
            if (value != null) key: value,
        },
        includeParentEnvironment: false,
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      return (result.stdout as String).trimRight();
    } finally {
      SandboxManager.cleanupAfterCommand();
    }
  }

  const printTmpdir = r'printf "%s\n" "$TMPDIR"';
  const writeTmp = r'printf yes > "$TMPDIR/x"';

  test(
    'only the command temp directory is writable when defaults are omitted',
    () async {
      makeSharedProbePaths();
      env['CLAUDE_CODE_TMPDIR'] = '/tmp/claude';
      final output = await run(
        [
          'set -e',
          printTmpdir,
          writeTmp,
          'printf yes > /dev/null',
          for (final probe in [...sharedProbes.map((f) => f.path), '$other/x'])
            'if printf bad > ${quote([probe])}; then exit 1; fi',
        ].join('\n'),
        PartialSandboxRuntimeConfig(
          filesystem: filesystem,
          omitDefaultWritablePaths: true,
          temporaryDirectory: temporaryDirectory,
        ),
      );
      expect(output, temporaryDirectory);
      expect(File('$temporaryDirectory/x').readAsStringSync(), 'yes');
      for (final file in [...sharedProbes, File('$other/x')]) {
        expect(file.existsSync(), isFalse, reason: file.path);
      }
    },
    skip: platformSkip,
  );

  test(
    'with no options, the upstream write and TMPDIR defaults still apply',
    () async {
      makeSharedProbePaths();
      final output = await run(
        [
          'set -e',
          printTmpdir,
          for (final file in sharedProbes) 'printf yes > ${quote([file.path])}',
        ].join('\n'),
      );
      // With no network proxy Linux inherits the host TMPDIR; macOS sets it.
      expect(output, Platform.isMacOS ? '/tmp/claude' : hostTmpdir);
      for (final file in sharedProbes) {
        expect(file.readAsStringSync(), 'yes', reason: file.path);
      }
    },
    skip: platformSkip,
  );

  test('omitting the defaults alone does not set the legacy TMPDIR', () async {
    env['CLAUDE_CODE_TMPDIR'] = '/tmp/claude';
    expect(
      await run(
        printTmpdir,
        const PartialSandboxRuntimeConfig(omitDefaultWritablePaths: true),
      ),
      hostTmpdir,
    );
  }, skip: platformSkip);

  test(
    'exports TMPDIR when the network is restricted but has no proxy',
    () async {
      final output = await run(
        'set -e\n$printTmpdir\n$writeTmp',
        PartialSandboxRuntimeConfig(
          network: network,
          omitDefaultWritablePaths: true,
          temporaryDirectory: temporaryDirectory,
        ),
      );
      expect(output, temporaryDirectory);
      expect(File('$temporaryDirectory/x').readAsStringSync(), 'yes');
    },
    skip: proxySkip,
  );

  test(
    'exports TMPDIR with a proxy, and preserves the proxy default when omitted',
    () async {
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(network: network, filesystem: filesystem),
      );
      const requireProxy = r'test -n "$CLAUDE_CODE_HOST_HTTP_PROXY_PORT"';
      final checkProxy = Platform.isLinux ? '$requireProxy\n' : '';
      expect(await run('set -e\n$checkProxy$printTmpdir'), '/tmp/claude');
      final output = await run(
        'set -e\n$checkProxy$printTmpdir\n$writeTmp',
        PartialSandboxRuntimeConfig(
          omitDefaultWritablePaths: true,
          temporaryDirectory: temporaryDirectory,
        ),
      );
      expect(output, temporaryDirectory);
      expect(File('$temporaryDirectory/x').readAsStringSync(), 'yes');
    },
    skip: proxySkip,
  );

  test('exports TMPDIR without sandboxing an unrestricted command', () async {
    const unrestricted = FilesystemConfig(
      disabled: true,
      denyRead: [],
      allowWrite: [],
      denyWrite: [],
    );
    final output = await run(
      'set -e\n$printTmpdir\n$writeTmp\nprintf yes > ${quote(['$other/x'])}',
      PartialSandboxRuntimeConfig(
        filesystem: unrestricted,
        omitDefaultWritablePaths: true,
        temporaryDirectory: temporaryDirectory,
      ),
    );
    expect(output, temporaryDirectory);
    expect(File('$temporaryDirectory/x').readAsStringSync(), 'yes');
    expect(File('$other/x').readAsStringSync(), 'yes');
  }, skip: platformSkip);

  test(
    'rejects a temp directory that does not exist instead of creating it',
    () async {
      final missing = '$temporaryDirectory/missing';
      await expectLater(
        SandboxManager.wrapWithSandboxArgv(
          ':',
          shell,
          PartialSandboxRuntimeConfig(temporaryDirectory: missing),
        ),
        throwsA(isA<NodeError>().having((e) => e.code, 'code', 'ENOENT')),
      );
      expect(Directory(missing).existsSync(), isFalse);
    },
    skip: platformSkip,
  );
}
