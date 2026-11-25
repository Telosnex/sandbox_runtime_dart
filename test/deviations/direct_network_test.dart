// No upstream counterpart: tests per-command direct network
// (PORT_WORKLOG.md, "Deviations from upstream").
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/sandbox_runtime.dart' hide Platform;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart'
    show getApplySeccompBinaryPath;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show FilesystemPathLiteral, TlsTerminateConfig;
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart'
    show PartialSandboxRuntimeConfig;
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show CA_TRUST_VARS;
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

    SandboxRuntimeConfig sessionConfig([
      NetworkConfig network = const NetworkConfig(
        allowedDomains: [],
        deniedDomains: [],
        tlsTerminate: TlsTerminateConfig(),
      ),
    ]) => SandboxRuntimeConfig(
      network: network,
      filesystem: FilesystemConfig(
        allowWrite: [FilesystemPathLiteral(allowed)],
        denyWrite: [],
        denyRead: [FilesystemPathLiteral(secret)],
      ),
    );

    setUpAll(() async {
      fixtures = await Directory.systemTemp.createTemp('srt-direct-');
      final base = fixtures.resolveSymbolicLinksSync();
      allowed = (Directory(path.join(base, 'allowed'))..createSync()).path;
      blocked = path.join(base, 'blocked.txt');
      secret = path.join(base, 'secret.txt');
      File(secret).writeAsStringSync('private');
      await SandboxManager.initialize(sessionConfig(), (_) async => false);
      expect(SandboxManager.getProxyPort(), isNotNull);
    });

    tearDownAll(() async {
      await SandboxManager.reset();
      await fixtures.delete(recursive: true);
    });

    Map<String, String> launchEnvironment(
      Map<String, String?> env, {
      bool omitInheritedTrust = false,
    }) => {
      for (final MapEntry(:key, :value) in env.entries)
        if (value != null &&
            !proxyVars.contains(key) &&
            !(omitInheritedTrust && CA_TRUST_VARS.contains(key)))
          key: value,
    };

    Future<ProcessResult> run(
      String command,
      bool? directNetwork, {
      bool omitInheritedTrust = false,
    }) async {
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
          environment: launchEnvironment(
            wrapped.env,
            omitInheritedTrust: omitInheritedTrust,
          ),
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

    test('injects proxy CA variables only into proxied commands', () async {
      final ca = SandboxManager.getMitmCA();
      expect(ca, isNotNull, reason: 'the session must have a proxy CA');
      final command = [
        for (final key in CA_TRUST_VARS)
          'if printenv $key >/dev/null; then echo $key; fi',
      ].join('\n');
      final direct = await run(command, true, omitInheritedTrust: true);
      final proxied = await run(command, null, omitInheritedTrust: true);
      expect(direct.exitCode, 0, reason: '${direct.stderr}');
      expect(direct.stdout, isEmpty);
      expect(proxied.exitCode, 0, reason: '${proxied.stderr}');
      expect((proxied.stdout as String).trim().split('\n'), CA_TRUST_VARS);
    });

    test('reaches an external HTTPS host without the proxy', () async {
      const hostname = 'example.com';
      final args = [
        ...curlArgs,
        'https://$hostname/',
        '--output',
        '/dev/null',
        '--verbose',
      ];
      // Keep the same inherited trust settings as the sandboxed curl. Use the
      // same server IP as well: separate DNS lookups or Happy Eyeballs races
      // can otherwise send the two requests to different CDN edges/chains.
      final host = await Process.run(
        curl!,
        [...args, '--write-out', '%{remote_ip}'],
        includeParentEnvironment: false,
        environment: launchEnvironment(process.env),
      );
      if (host.exitCode != 0) {
        markTestSkipped('Host cannot reach $hostname directly: ${host.stderr}');
        return;
      }
      final peer = InternetAddress(host.stdout as String);
      final resolve = peer.type == InternetAddressType.IPv6
          ? '$hostname:443:[${peer.address}]'
          : '$hostname:443:${peer.address}';
      final result = await run(
        quote([curl, ...args, '--resolve', resolve]),
        true,
      );
      expect(
        result.exitCode,
        0,
        reason: 'Host curl:\n${host.stderr}\nSandbox curl:\n${result.stderr}',
      );
    });

    test(
      'direct mode verifies TLS through the macOS system trust store',
      skip: Platform.isMacOS ? false : 'macOS only',
      () async {
        // A CA file with one unrelated root makes Apple's curl fall back to
        // the system trust store, as it does on hosts where /etc/ssl/cert.pem
        // lacks a site's root. That fallback uses TrustEvaluationAgent.
        const hostname = 'example.com';
        final bundle = File('/etc/ssl/cert.pem').readAsStringSync();
        final start = bundle.indexOf('-----BEGIN CERTIFICATE-----');
        const end = '-----END CERTIFICATE-----';
        final one = File(path.join(fixtures.path, 'one-root.pem'))
          ..writeAsStringSync(
            '${bundle.substring(start, bundle.indexOf(end, start) + end.length)}\n',
          );
        final args = [
          '/usr/bin/curl',
          ...curlArgs,
          '--cacert',
          one.path,
          'https://$hostname/',
          '--output',
          '/dev/null',
        ];
        final host = await Process.run(args.first, args.sublist(1));
        if (host.exitCode != 0) {
          markTestSkipped('Host cannot verify $hostname: ${host.stderr}');
          return;
        }
        final result = await run(quote(args), true);
        expect(result.exitCode, 0, reason: '${result.stderr}');
      },
    );

    test(
      'direct mode can resolve an external hostname via the macOS resolver',
      () async {
        const resolver = '/usr/bin/dscacheutil';
        const args = ['-q', 'host', '-a', 'name', 'example.com'];
        final address = RegExp(r'^ip(?:v6)?_address: ', multiLine: true);
        final host = await Process.run(resolver, args);
        if (host.exitCode != 0 || !address.hasMatch(host.stdout as String)) {
          markTestSkipped('Host cannot resolve example.com: ${host.stderr}');
          return;
        }
        final result = await run(quote([resolver, ...args]), true);
        expect(result.exitCode, 0, reason: '${result.stderr}');
        expect(result.stdout, matches(address));
      },
      skip: Platform.isMacOS ? false : 'requires the macOS resolver',
    );

    // TELOSNEX DEVIATION: Direct IP must not imply Unix-socket access.
    for (final mode in ['default', 'unrelated', 'specific', 'all']) {
      test('direct mode respects macOS Unix-socket policy ($mode)', () async {
        // The socket is outside the sandbox's filesystem allow list.
        final base = fixtures.resolveSymbolicLinksSync();
        final socketPath = path.join(base, 'peer.sock');
        final listener = await ServerSocket.bind(
          InternetAddress(socketPath, type: InternetAddressType.unix),
          0,
        );
        addTearDown(listener.close);
        const marker = 'host Unix peer reached';
        listener.listen((client) async {
          client.writeln(marker);
          await client.close();
        });

        const nc = '/usr/bin/nc';
        final args = ['-d', '-w', '2', '-U', socketPath];
        final host = await Process.run(nc, args);
        expect(host.exitCode, 0, reason: '${host.stderr}');
        expect(host.stdout, contains(marker));

        SandboxManager.updateConfig(
          sessionConfig(
            NetworkConfig(
              allowedDomains: [],
              deniedDomains: [],
              tlsTerminate: const TlsTerminateConfig(),
              allowUnixSockets: switch (mode) {
                'specific' => [socketPath],
                'unrelated' => [path.join(base, 'other.sock')],
                _ => null,
              },
              allowAllUnixSockets: mode == 'all' ? true : null,
            ),
          ),
        );
        addTearDown(() => SandboxManager.updateConfig(sessionConfig()));

        final result = await run(quote([nc, ...args]), true);
        if (mode == 'specific' || mode == 'all') {
          expect(result.exitCode, 0, reason: '${result.stderr}');
          expect(result.stdout, contains(marker));
        } else {
          expect(
            result.exitCode,
            1,
            reason: '${result.stdout}\n${result.stderr}',
          );
          expect(result.stdout, isNot(contains(marker)));
        }
      }, skip: Platform.isMacOS ? false : 'requires macOS Seatbelt');
    }

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
