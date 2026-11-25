// TELOSNEX DEVIATION: exercise the Dart-only process launcher and its fd,
// stdio, exit status and process-group contract.
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:sandbox_runtime/sandbox_runtime.dart' show spawnSafe;
import 'package:test/test.dart';

const _timeout = Duration(seconds: 5);
final _libc = DynamicLibrary.process();

void main() {
  group('spawnSafe', skip: !Platform.isMacOS && !Platform.isLinux, () {
    test('child does not inherit a non-CLOEXEC parent descriptor', () async {
      final open = _libc
          .lookupFunction<
            Int32 Function(Pointer<Utf8>, Int32, VarArgs<(Int32,)>),
            int Function(Pointer<Utf8>, int, int)
          >('open');
      final close = _libc
          .lookupFunction<Int32 Function(Int32), int Function(int)>('close');
      final fcntl = _libc
          .lookupFunction<
            Int32 Function(Int32, Int32, VarArgs<(Int32,)>),
            int Function(int, int, int)
          >('fcntl');
      final path = '/dev/null'.toNativeUtf8();
      final source = open(path, 0, 0);
      malloc.free(path);
      expect(source, greaterThanOrEqualTo(0));
      addTearDown(() => close(source));
      final fd = fcntl(source, 0, 75); // F_DUPFD (not F_DUPFD_CLOEXEC)
      expect(fd, greaterThanOrEqualTo(75));
      addTearDown(() => close(fd));
      expect(fcntl(fd, 1, 0), 0); // F_GETFD: FD_CLOEXEC is clear.

      final child = await spawnSafe(
        Platform.isMacOS
            ? [
                '/bin/sh',
                '-c',
                // Prove fd 3 was just opened during the glob, not inherited.
                r'printf "%s\n" /dev/fd/*; [ ! -e /dev/fd/3 ]',
              ]
            : ['/bin/ls', '-1', '/proc/self/fd'],
      );
      final stdout = _text(child.stdout);
      final stderr = _text(child.stderr);
      expect(await child.exitCode.timeout(_timeout), 0, reason: await stderr);
      // Descriptor 3 belongs to the directory listing itself.
      expect((await stdout).trim().split('\n').map((s) => s.split('/').last), [
        '0',
        '1',
        '2',
        '3',
      ]);
    });

    test('buffers stdout and stderr and reports exact exit status', () async {
      // dart:io's global child reaper must not steal the status of a short
      // child launched by spawnSafe (macOS kqueue / Linux helper relay).
      final reaper = await Process.start('/bin/sleep', ['60']);
      addTearDown(() async {
        reaper.kill();
        await reaper.exitCode.timeout(_timeout);
      });
      final child = await spawnSafe(
        ['/bin/sh', '-c', 'printf %s "\$SRT_TEST"; printf error >&2; exit 47'],
        environment: {'SRT_TEST': 'from environment'},
      );
      expect(await child.exitCode.timeout(_timeout), 47);
      // The child exited before either public stream was listened to.
      expect(await _text(child.stdout), 'from environment');
      expect(await _text(child.stderr), 'error');
    });

    test(
      'redirects stdin through an IOSink and closes it on request',
      () async {
        final child = await spawnSafe(['/bin/cat']);
        addTearDown(() => child.kill(ProcessSignal.sigkill));
        final stdout = child.stdout
            .expand((bytes) => bytes)
            .toList()
            .timeout(_timeout);
        final stderr = _text(child.stderr);
        // Larger than a pipe's buffer, so blocking writes could hang this test.
        final input = Uint8List.fromList(
          List.generate(256 * 1024, (i) => i % 251),
        );
        child.stdin.add(input);
        await child.stdin.close().timeout(_timeout);
        expect(await child.exitCode.timeout(_timeout), 0, reason: await stderr);
        expect(await stdout, input);
      },
    );

    test(
      'setsid makes the child a group leader and group kill ends its grandchild',
      () async {
        final child = await spawnSafe([
          '/bin/sh',
          '-c',
          r'''
/bin/sleep 600 &
background=$!
printf '%s %s\n' "$$" "$background"
wait "$background"
''',
        ], newSession: true);
        addTearDown(() => child.killGroup(ProcessSignal.sigkill));
        final stderr = _text(child.stderr);
        final line = await child.stdout
            .transform(utf8.decoder)
            .transform(const LineSplitter())
            .first
            .timeout(_timeout);
        final [leader, grandchild] = line.split(' ').map(int.parse).toList();
        addTearDown(() {
          if (grandchild > 1) {
            Process.killPid(grandchild, ProcessSignal.sigkill);
          }
        });
        expect(leader, child.pid);
        final getsid = _libc
            .lookupFunction<Int32 Function(Int32), int Function(int)>('getsid');
        final getpgid = _libc
            .lookupFunction<Int32 Function(Int32), int Function(int)>(
              'getpgid',
            );
        expect(getsid(leader), leader);
        expect(getpgid(leader), leader);
        expect(getpgid(grandchild), leader);
        expect(await _live(grandchild), isTrue);

        expect(child.killGroup(ProcessSignal.sigkill), isTrue);
        expect(
          await child.exitCode.timeout(_timeout),
          -ProcessSignal.sigkill.signalNumber,
        );
        await stderr; // Prove even the inherited stderr pipe closed.
        final elapsed = Stopwatch()..start();
        while (await _live(grandchild)) {
          if (elapsed.elapsed >= _timeout) {
            fail('Grandchild $grandchild is still alive');
          }
          await Future<void>.delayed(const Duration(milliseconds: 20));
        }
      },
    );

    test('signals the child PID without requiring its own group', () async {
      final child = await spawnSafe(['/bin/sleep', '60']);
      addTearDown(() => child.kill(ProcessSignal.sigkill));
      expect(child.killGroup, throwsStateError);
      expect(child.kill(ProcessSignal.sigterm), isTrue);
      expect(
        await child.exitCode.timeout(_timeout),
        -ProcessSignal.sigterm.signalNumber,
      );
      expect(await _text(child.stdout), isEmpty);
      expect(await _text(child.stderr), isEmpty);
    });

    test(
      'uses an explicit Linux helper path and does not silently fall back',
      skip: !Platform.isLinux,
      () async {
        final config = Platform.packageConfig!;
        final cfg = config.startsWith('file:')
            ? Uri.parse(config)
            : Uri.file(config);
        final data =
            jsonDecode(File.fromUri(cfg).readAsStringSync())
                as Map<String, dynamic>;
        final packages = (data['packages'] as List<dynamic>)
            .cast<Map<String, dynamic>>();
        final package = packages.singleWhere(
          (entry) => entry['name'] == 'sandbox_runtime',
        );
        final root = cfg.resolve(package['rootUri'] as String);
        final arch = Abi.current() == Abi.linuxArm64 ? 'arm64' : 'x64';
        final helper = root
            .resolve('vendor/spawn-helper/$arch/srt-spawn')
            .toFilePath();
        final child = await spawnSafe([
          '/bin/echo',
          'explicit helper',
        ], helperPath: helper);
        expect(await _text(child.stdout), 'explicit helper\n');
        expect(await _text(child.stderr), isEmpty);
        expect(await child.exitCode.timeout(_timeout), 0);
        await expectLater(
          spawnSafe(['/bin/true'], helperPath: '$helper.missing'),
          throwsA(
            predicate((Object error) => error.toString().contains('ENOENT')),
          ),
        );
      },
    );
  });
}

Future<String> _text(Stream<List<int>> stream) =>
    utf8.decoder.bind(stream).join().timeout(_timeout);

Future<bool> _live(int pid) async {
  final result = await Process.run('/bin/ps', ['-o', 'state=', '-p', '$pid']);
  final state = (result.stdout as String).trim();
  return state.isNotEmpty && !state.startsWith('Z');
}
