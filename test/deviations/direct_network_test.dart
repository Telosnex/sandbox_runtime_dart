// No upstream counterpart: tests per-command direct network
// (PORT_WORKLOG.md, "Deviations from upstream").
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/sandbox_runtime.dart' hide Platform;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart'
    show getApplySeccompBinaryPath;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show FilesystemPathLiteral;
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart'
    show PartialSandboxRuntimeConfig;
import 'package:sandbox_runtime/src/utils/shell_quote.dart' show quote;
import 'package:sandbox_runtime/src/utils/which.dart' show whichSync;
import 'package:test/test.dart';

import '../helpers/bwrap_namespace.dart' show bwrapCanNamespaceNetwork;

void main() {
  test('Windows rejects direct network, including the MXC spawn API', () async {
    process.setPlatformForTesting('win32');
    addTearDown(() => process.setPlatformForTesting(null));
    const config = PartialSandboxRuntimeConfig(directNetwork: true);
    final unsupported = throwsA(
      isA<WindowsSandboxError>()
          .having((e) => e.code, 'code', 'backend_unsupported')
          .having((e) => e.message, 'message', contains('directNetwork')),
    );
    await expectLater(
      SandboxManager.wrapWithSandbox('exit', null, config),
      unsupported,
    );
    await expectLater(
      SandboxManager.wrapWithSandboxArgv('exit', null, config),
      unsupported,
    );
    await expectLater(
      SandboxManager.spawnSandboxed!(
        'exit',
        const SpawnSandboxedOptions(customConfig: config),
      ),
      unsupported,
    );
  });

  group('one session with direct and proxied commands', skip: _liveSkip(), () {
    const shell = '/bin/bash';
    final curl = whichSync('curl');
    const curlArgs = [
      '--disable',
      '--noproxy',
      '*',
      '--connect-timeout',
      '4',
      '--max-time',
      '8',
      '--silent',
      '--show-error',
      '--fail',
    ];
    const proxyVars = ['HTTP_PROXY', 'ALL_PROXY', 'GIT_SSH_COMMAND'];
    late Directory fixtures;
    late String allowed;
    late String blocked;
    late String secret;

    setUpAll(() async {
      fixtures = await Directory.systemTemp.createTemp('srt-direct-');
      final base = fixtures.resolveSymbolicLinksSync();
      allowed = (Directory(path.join(base, 'allowed'))..createSync()).path;
      blocked = path.join(base, 'blocked.txt');
      secret = path.join(base, 'secret.txt');
      File(secret).writeAsStringSync('private');
      await SandboxManager.initialize(
        SandboxRuntimeConfig(
          network: const NetworkConfig(allowedDomains: [], deniedDomains: []),
          filesystem: FilesystemConfig(
            allowWrite: [FilesystemPathLiteral(allowed)],
            denyWrite: [],
            denyRead: [FilesystemPathLiteral(secret)],
          ),
        ),
        (_) async => false,
      );
      expect(SandboxManager.getProxyPort(), isNotNull);
    });

    tearDownAll(() async {
      await SandboxManager.reset();
      await fixtures.delete(recursive: true);
    });

    Future<ProcessResult> run(String command, bool? directNetwork) async {
      final wrapped = await SandboxManager.wrapWithSandboxArgv(
        command,
        shell,
        PartialSandboxRuntimeConfig(directNetwork: directNetwork),
      );
      try {
        if (Platform.isLinux) {
          final script = wrapped.argv[2];
          if (directNetwork == true) {
            expect(script, isNot(contains('--unshare-net')));
            expect(script, isNot(contains('UNIX-CONNECT:')));
          } else {
            expect(script, contains('--unshare-net'));
            expect(script, contains('UNIX-CONNECT:'));
          }
        }
        return await Process.run(
          wrapped.argv.first,
          wrapped.argv.skip(1).toList(),
          includeParentEnvironment: false,
          environment: {
            for (final MapEntry(:key, :value) in wrapped.env.entries)
              if (value != null && !proxyVars.contains(key)) key: value,
          },
        );
      } finally {
        SandboxManager.cleanupAfterCommand();
      }
    }

    test(
      'concurrent commands retain their own network mode and file policy',
      () async {
        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        addTearDown(() => server.close(force: true));
        server.listen((request) async {
          request.response.writeln('host loopback reached');
          await request.response.close();
        });
        final localhost = 'http://127.0.0.1:${server.port}/';
        final command = [
          // Emit names but never print credentials embedded in the values.
          for (final key in proxyVars)
            'if printenv $key >/dev/null; then echo $key=present; fi',
          'if ${quote([curl!, ...curlArgs, localhost])}; then echo tcp=ok; else echo tcp=blocked; fi',
          'if printf denied > ${quote([blocked])}; then exit 91; fi',
          'if cat ${quote([secret])} >/dev/null; then exit 92; fi',
          'printf write-ok > ${quote([path.join(allowed, 'probe.txt')])}',
        ].join('\n');
        const modes = [true, null, false];
        final results = await Future.wait([
          for (final mode in modes) run(command, mode),
        ]);
        for (final (i, result) in results.indexed) {
          final direct = modes[i] == true;
          expect(
            result.exitCode,
            0,
            reason: '${result.stdout}\n${result.stderr}',
          );
          expect(result.stdout, contains(direct ? 'tcp=ok' : 'tcp=blocked'));
          for (final token in [
            'host loopback reached',
            ...proxyVars.map((key) => '$key=present'),
          ]) {
            final shouldAppear = direct == (token == 'host loopback reached');
            expect(
              result.stdout,
              shouldAppear ? contains(token) : isNot(contains(token)),
            );
          }
        }
        expect(File(blocked).existsSync(), isFalse);
        expect(
          File(path.join(allowed, 'probe.txt')).readAsStringSync(),
          'write-ok',
        );
      },
    );

    test('reaches an external HTTPS host without the proxy', () async {
      final args = [
        ...curlArgs,
        'https://example.com/',
        '--output',
        '/dev/null',
      ];
      final host = await Process.run(curl!, args);
      if (host.exitCode != 0) {
        markTestSkipped(
          'Host cannot reach example.com directly: ${host.stderr}',
        );
        return;
      }
      final result = await run(quote([curl, ...args]), true);
      expect(result.exitCode, 0, reason: '${result.stderr}');
    });

    test(
      'keeps the upstream Linux Unix-socket filter',
      () async {
        final result = await run(
          quote([
            'python3',
            '-c',
            '''import errno, socket
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()
except OSError as e:
    assert e.errno == errno.EPERM, e
else:
    raise AssertionError('AF_UNIX socket was allowed')''',
          ]),
          true,
        );
        expect(result.exitCode, 0, reason: '${result.stderr}');
      },
      skip:
          Platform.isLinux &&
              whichSync('python3') != null &&
              getApplySeccompBinaryPath() != null
          ? false
          : 'requires Linux with Python and apply-seccomp',
    );
  });
}

Object _liveSkip() {
  if (!Platform.isMacOS && !Platform.isLinux) return 'requires macOS or Linux';
  for (final name in [
    'curl',
    'rg',
    if (Platform.isLinux) ...['bwrap', 'socat'],
  ]) {
    if (whichSync(name) == null) return 'requires $name';
  }
  if (Platform.isLinux && !bwrapCanNamespaceNetwork()) {
    return 'bwrap cannot create network namespaces';
  }
  return false;
}
