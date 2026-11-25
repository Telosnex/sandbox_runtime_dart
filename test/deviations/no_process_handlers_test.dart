// No upstream counterpart: tests the TELOSNEX DEVIATION in
// sandbox_manager.dart and linux_sandbox_utils.dart (PORT_WORKLOG.md,
// "Deviations from upstream").

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:sandbox_runtime/sandbox_runtime.dart' hide Platform;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show FilesystemPathLiteral, RipgrepConfig;
import 'package:test/test.dart';

const _config = SandboxRuntimeConfig(
  network: NetworkConfig(allowedDomains: [], deniedDomains: []),
  filesystem: FilesystemConfig(denyRead: [], allowWrite: [], denyWrite: []),
);
const _optOut = SandboxInitializeOptions(registerProcessHandlers: false);
const _events = ['SIGINT', 'SIGTERM', 'exit'];
const _childTimeout = Duration(seconds: 15);

const _childScript = '''
import 'dart:io';

import 'package:sandbox_runtime/sandbox_runtime.dart';
import 'package:sandbox_runtime/src/node/process.dart' as process;

Future<void> main(List<String> args) async {
  const config = SandboxRuntimeConfig(
    network: NetworkConfig(allowedDomains: [], deniedDomains: []),
    filesystem: FilesystemConfig(denyRead: [], allowWrite: [], denyWrite: []),
  );
  if (args.contains('opt-out')) {
    await SandboxManager.initialize(
      config, null, false,
      const SandboxInitializeOptions(registerProcessHandlers: false),
    );
  } else {
    await SandboxManager.initialize(config);
  }
  if (SandboxManager.getProxyPort() == null) {
    throw StateError('Proxy was not started');
  }
  const events = ['SIGINT', 'SIGTERM', 'exit'];
  stdout.writeln(events.map(process.listenerCount).join(','));
  await stdout.flush();
  // Stay alive until the manager handles the signal by resetting the proxy.
  // With no handler, SIGTERM kills this process before it can exit normally.
  while (SandboxManager.getProxyPort() != null) {
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
  // The upstream SIGINT watcher is still registered after SIGTERM.
  exit(0);
}
''';

Future<void> _checkSigterm({required bool optOut}) async {
  final directory = await Directory.systemTemp.createTemp('srt_signals_');
  addTearDown(() => directory.delete(recursive: true));
  final script = File.fromUri(directory.uri.resolve('child.dart'));
  await script.writeAsString(_childScript);
  final packages = (await Isolate.packageConfig)!.toFilePath();
  final child = await Process.start(Platform.resolvedExecutable, [
    '--packages=$packages',
    script.path,
    if (optOut) 'opt-out',
  ]);
  final errors = child.stderr.transform(utf8.decoder).join();
  final lines = StreamIterator(
    child.stdout.transform(utf8.decoder).transform(const LineSplitter()),
  );
  addTearDown(() async {
    child.kill(ProcessSignal.sigkill);
    await child.exitCode;
    await lines.cancel();
    await child.stdin.close();
  });

  if (!await lines.moveNext().timeout(_childTimeout)) {
    fail('Child exited before initialization: ${await errors}');
  }
  expect(lines.current, optOut ? '0,0,0' : '1,1,1');
  expect(child.kill(ProcessSignal.sigterm), isTrue);
  final status = await child.exitCode.timeout(_childTimeout);
  expect(
    status,
    optOut ? -ProcessSignal.sigterm.signalNumber : 0,
    reason: await errors,
  );
}

void main() {
  group('process cleanup handlers', skip: !Platform.isMacOS, () {
    test('opt-out leaves SIGTERM at its default action', () async {
      await _checkSigterm(optOut: true);
    });

    test('by default SIGTERM is handled and resets the sandbox', () async {
      await _checkSigterm(optOut: false);
    });

    test(
      'explicit reset closes the proxy without registering handlers',
      () async {
        addTearDown(SandboxManager.reset);
        await SandboxManager.initialize(_config, null, false, _optOut);
        expect(_events.map(process.listenerCount), [0, 0, 0]);
        final port = SandboxManager.getProxyPort()!;
        final socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
        socket.destroy();

        await SandboxManager.reset();

        expect(SandboxManager.getProxyPort(), isNull);
        expect(_events.map(process.listenerCount), [0, 0, 0]);
        await expectLater(
          Socket.connect(InternetAddress.loopbackIPv4, port),
          throwsA(isA<SocketException>()),
        );
      },
    );

    test('planning a Linux mount point does not install an exit hook', () async {
      final directory = await Directory.systemTemp.createTemp('srt_mount_');
      addTearDown(() => directory.delete(recursive: true));
      addTearDown(SandboxManager.reset);
      final root = await directory.resolveSymbolicLinks();
      final mountPoint = File('$root/missing.txt');
      await SandboxManager.initialize(
        SandboxRuntimeConfig(
          network: const NetworkConfig(
            allowedDomains: [],
            deniedDomains: [],
            allowAllUnixSockets: true,
          ),
          filesystem: FilesystemConfig(
            denyRead: [],
            allowWrite: [FilesystemPathLiteral(root)],
            denyWrite: [FilesystemPathLiteral(mountPoint.path)],
          ),
          bwrapPath: '/usr/bin/true',
          ripgrep: const RipgrepConfig(command: '/usr/bin/true'),
          mandatoryDenySearchDepth: 0,
          enableWeakerNestedSandbox: true,
        ),
        null,
        false,
        _optOut,
      );
      // Exercise Linux's planner on macOS without running a sandboxed command.
      process.setPlatformForTesting('linux');
      addTearDown(() => process.setPlatformForTesting(null));
      final command = await SandboxManager.wrapWithSandbox('true', '/bin/sh');
      expect(command, contains(mountPoint.path));
      expect(_events.map(process.listenerCount), [0, 0, 0]);

      await mountPoint.writeAsString(''); // What bwrap would leave behind.
      SandboxManager.cleanupAfterCommand();
      expect(await mountPoint.exists(), isFalse);
    });
  });
}
