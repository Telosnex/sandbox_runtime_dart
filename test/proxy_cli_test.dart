// Ported from sandbox-runtime test/proxy-cli.test.ts @ 0bbebed.
library;

// ignore_for_file: no_leading_underscores_for_local_identifiers, constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_interpolation_to_compose_strings
import 'dart:async';
import 'dart:convert';
import 'dart:io' as io;
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/child_process.dart';
import 'package:sandbox_runtime/src/node/fs.dart';
import 'package:sandbox_runtime/src/node/globals.dart' as globals;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/node/stream.dart' show Writable;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/decider_client.dart'
    show encodeFrame;
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:test/test.dart';

import 'helpers/emitted_connections.dart' show canServeEmittedConnections;

// Dart: process.execPath is the Dart VM, and the entry is bin/srt_proxy.dart.
final ENTRY = '${io.Directory.current.path}/bin/srt_proxy.dart';
final String _execPath = io.Platform.resolvedExecutable;
final String? TASKSET = io.Platform.isLinux
    ? ([
        '/usr/bin/taskset',
        '/bin/taskset',
      ].cast<String?>().firstWhere((p) => existsSync(p!), orElse: () => null))
    : null;

/** The first CPU this process may run on (Linux). */
final FIRST_CPU =
    RegExp(r'^Cpus_allowed_list:\s*(\d+)', multiLine: true)
        .firstMatch(
          io.Platform.isLinux
              ? readFileSync('/proc/self/status', 'utf8') as String
              : '',
        )
        ?.group(1) ??
    '0';
final HELLO =
    readFileSync(
          '${io.Directory.current.path}/test/fixtures/srt-proxy-hello.json',
          'utf8',
        )
        as String;

typedef Proc = ({
  ChildProcess child,
  Future<int?> exited,
  String Function() stderr,
});

Proc run(List<String> args, [Map<String, String>? env]) {
  final child = spawn(
    _execPath,
    [ENTRY, ...args],
    {
      'stdio': ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'],
      'env': env == null ? null : {...process.env, ...env},
    },
  );
  var stderr = '';
  // TELOSNEX DEVIATION: 'exit' can come before the last stderr bytes are
  // read. Wait for the end of stderr too, so that a test sees all of it.
  final stderrDone = Completer<void>();
  child.stderr!.listen(
    (d) => stderr += utf8.decode(d, allowMalformed: true),
    onDone: stderrDone.complete,
  );
  final exitedCompleter = Completer<int?>();
  child.once('exit', (code, _) {
    unawaited(
      stderrDone.future.then((_) {
        if (!exitedCompleter.isCompleted) {
          exitedCompleter.complete(code as int?);
        }
      }),
    );
  });
  return (child: child, exited: exitedCompleter.future, stderr: () => stderr);
}

/** The loopback port a proxy started with `--listen 127.0.0.1:0` serves. */
Future<int> servingPort(Proc p) {
  final completer = Completer<int>();
  final t = globals.setInterval(() {
    final m = RegExp(r'serving 127\.0\.0\.1:(\d+)').firstMatch(p.stderr());
    if (m != null && !completer.isCompleted) {
      completer.complete(int.parse(m.group(1)!));
    }
  }, 20);
  unawaited(
    p.exited.then((code) {
      globals.clearInterval(t);
      if (!completer.isCompleted) {
        completer.completeError(Exception('exited $code: ${p.stderr()}'));
      }
    }),
  );
  return completer.future.whenComplete(() => globals.clearInterval(t));
}

Future<void> main() async {
  /** Whether this host can bind the IPv6 loopback address. */
  final HAS_IPV6_LOOPBACK = await () {
    final resolved = Completer<bool>();
    final s = net.createServer();
    s.once('error', (_) {
      if (!resolved.isCompleted) resolved.complete(false);
    });
    s.listen(
      0,
      '::1',
      () => s.close(() {
        if (!resolved.isCompleted) resolved.complete(true);
      }),
    );
    return resolved.future;
  }();

  group('srt-proxy entry', () {
    test('without a decider it refuses to start (exit 2)', () async {
      final p = run(['--listen', '127.0.0.1:0']);
      expect(await p.exited, 2);
      expect(p.stderr(), contains('a decider is required'));
    });

    test(
      'with SRT_PROXY_REPORT_RSS_MS set, reports its resident set size on stderr',
      () async {
        final p = run(
          ['--listen', '127.0.0.1:0', '--decider-fd', '3'],
          {'SRT_PROXY_REPORT_RSS_MS': '20'},
        );
        try {
          final sizes = await () {
            final completer = Completer<List<int>>();
            final t = globals.setInterval(() {
              final found = RegExp(
                r'^srt-proxy rss (\d+)$',
                multiLine: true,
              ).allMatches(p.stderr()).toList();
              if (found.length >= 2 && !completer.isCompleted) {
                completer.complete(
                  found.map((m) => int.parse(m.group(1)!)).toList(),
                );
              }
            }, 20);
            unawaited(
              p.exited.then((code) {
                globals.clearInterval(t);
                if (!completer.isCompleted) {
                  completer.completeError(
                    Exception('exited $code: ${p.stderr()}'),
                  );
                }
              }),
            );
            return completer.future.whenComplete(
              () => globals.clearInterval(t),
            );
          }();
          for (final n in sizes) {
            expect(n, greaterThan(0));
          }
        } finally {
          p.child.kill();
          await p.exited;
        }
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );

    test(
      'speaks the pinned hello first, serves after the decider answers, and stops when the lifeline ends',
      () async {
        final p = run([
          '--listen',
          '127.0.0.1:0',
          '--decider-fd',
          '3',
          '--lifeline-fd',
          '4',
          '--strip-response-header',
          'set-cookie',
        ]);
        final decider = p.child.stdio[3]! as net.NodeSocket;
        final lifeline = p.child.stdio[4]! as Writable;
        final firstCompleter = Completer<Uint8List>();
        decider.once(
          'data',
          (Object? c) =>
              firstCompleter.complete(Uint8List.fromList(c as List<int>)),
        );
        final first = await firstCompleter.future;
        expect(
          ByteData.sublistView(first).getUint32(0, Endian.big),
          first.length - 4,
        );
        expect(utf8.decode(first.sublist(4)), HELLO);
        decider.write(
          encodeFrame({
            't': 'hello',
            'proto': 1,
            'allowedDomains': ['allowed.test:443'],
            'deniedDomains': [],
          }),
        );
        final port = await servingPort(p);
        // A host outside the decider's list is refused before it is asked.
        final reply = await () {
          final completer = Completer<String>();
          late final net.NodeSocket c;
          c = net.connect(
            port,
            '127.0.0.1',
            () => c.write(
              'CONNECT other.test:443 HTTP/1.1\r\nHost: other.test:443\r\n\r\n',
            ),
          );
          var out = '';
          c.on('data', (Object? d) => out += utf8.decode(d as List<int>));
          c.on('close', (_) {
            if (!completer.isCompleted) completer.complete(out);
          });
          c.on('error', (_) {
            if (!completer.isCompleted) completer.complete(out);
          });
          return completer.future;
        }();
        expect(reply, startsWith('HTTP/1.1 403'));
        lifeline.end();
        expect(await p.exited, 0);
        expect(p.stderr(), contains('lifeline closed'));
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );

    test(
      'a decider that stops reading stops the proxy, and the request in hand is refused',
      () async {
        final p = run([
          '--listen',
          '127.0.0.1:0',
          '--decider-in',
          '3',
          '--decider-out',
          '4',
        ]);
        try {
          final toProxy = p.child.stdio[3]! as net.NodeSocket;
          final fromProxy = p.child.stdio[4]! as net.NodeSocket;
          final gotData = Completer<void>();
          fromProxy.once('data', (_) => gotData.complete());
          await gotData.future;
          toProxy.write(
            encodeFrame({
              't': 'hello',
              'proto': 1,
              'allowedDomains': ['allowed.test:80'],
              'deniedDomains': [],
            }),
          );
          final port = await servingPort(p);
          // The decider's reading end goes away while its writing end stays
          // open, so the proxy learns of it only by failing to write a frame.
          final closedCompleter = Completer<void>();
          fromProxy.once('close', (_) => closedCompleter.complete());
          fromProxy.destroy();
          await closedCompleter.future;
          final reply = await () {
            final completer = Completer<String>();
            late final net.NodeSocket c;
            c = net.connect(
              port,
              '127.0.0.1',
              () => c.write(
                'GET http://allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n',
              ),
            );
            var out = '';
            c.on('data', (Object? d) => out += utf8.decode(d as List<int>));
            c.on('close', (_) {
              if (!completer.isCompleted) completer.complete(out);
            });
            c.on('error', (_) {
              if (!completer.isCompleted) completer.complete(out);
            });
            return completer.future;
          }();
          expect(reply, startsWith('HTTP/1.1 503'));
          globals.Timeout? timer;
          final code = await Future.any<Object?>([
            p.exited,
            () {
              final resolved = Completer<String>();
              timer = globals.setTimeout(
                () => resolved.complete('still running'),
                3000,
              );
              return resolved.future;
            }(),
          ]);
          globals.clearTimeout(timer);
          expect(p.stderr(), contains('stopped (decider: write error'));
          expect(code, 0);
        } finally {
          p.child.kill('SIGKILL');
        }
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );

    // Each form runs twice. Pinned to one CPU, reads of descriptors that sit
    // idle (the lifeline, the decider between frames) must not starve the
    // writes to the decider: Bun sizes its thread pool by CPUs. Pinning needs
    // Linux and taskset; elsewhere those cases show as skipped, and the
    // unpinned ones do not cover the starvation. A handed listening socket
    // needs a runtime that serves emitted connections; elsewhere all four
    // show as skipped.
    for (final pin in [false, true]) {
      final pinned1 = pin ? ', pinned to one CPU' : '';
      for (final (_form, deciderArgs) in <(String, List<String>)>[
        ('on two streams', ['--decider-in', '4', '--decider-out', '5']),
        ('on one socket', ['--decider-fd', '4']),
      ]) {
        test(
          'the descriptor forms$pinned1: a handed listening socket, the decider $_form, the CA on its own',
          () async {
            // The host's side of the handover: a listening socket it made, passed
            // as a descriptor, and closed here once the proxy has its copy.
            final listener = net.createServer();
            final listening = Completer<void>();
            listener.listen(0, '127.0.0.1', () => listening.complete());
            await listening.future;
            final port = (listener.address() as net.NodeAddress).port;
            final fd = listener.handleFd;
            final ca = generateCa();
            final argv = [
              _execPath,
              ENTRY,
              '--listen-fd',
              '3',
              ...deciderArgs,
              '--lifeline-fd',
              '6',
              '--ca-fd',
              '7',
            ];
            final pinned = pin ? [TASKSET!, '-c', FIRST_CPU, ...argv] : argv;
            final child = spawn(pinned[0], pinned.sublist(1), {
              // Include timeout/handshake diagnostics if a hosted runner's
              // connection closes before its expected HTTP response.
              'env': {...process.env, 'SRT_DEBUG': '1'},
              'stdio': [
                'ignore',
                'ignore',
                'pipe',
                fd,
                'pipe',
                'pipe',
                'pipe',
                'pipe',
              ],
            });
            // A failed response assertion must still release the descriptor
            // sockets and child; otherwise they keep the test runner alive.
            addTearDown(() {
              child.kill('SIGKILL');
              for (final stream in child.stdio) {
                if (stream is net.NodeSocket) stream.destroy();
              }
              listener.close();
            });
            listener.close();
            var stderr = '';
            // TELOSNEX DEVIATION: wait for the end of stderr as well as
            // 'exit', as in run().
            final stderrDone = Completer<void>();
            child.stderr!.listen(
              (d) => stderr += utf8.decode(d, allowMalformed: true),
              onDone: stderrDone.complete,
            );
            final exitedCompleter = Completer<int?>();
            child.once('exit', (code, _) {
              unawaited(
                stderrDone.future.then((_) {
                  if (!exitedCompleter.isCompleted) {
                    exitedCompleter.complete(code as int?);
                  }
                }),
              );
            });
            final exited = exitedCompleter.future;
            // The extra stdio entries are the parent's ends of socket pairs.
            final io_ = child.stdio.cast<net.NodeSocket?>();
            final (toProxy, lifeline, caStream) = (io_[4]!, io_[6]!, io_[7]!);
            final fromProxy = deciderArgs.contains('--decider-fd')
                ? toProxy
                : io_[5]!;
            caStream.end(ca.keyPem + ca.certPem);
            // The decider: answer the hello, then deny every request.
            final asked = <Map<String, Object?>>[];
            var buf = Uint8List(0);
            fromProxy.on('data', (Object? chunk) {
              buf = Uint8List.fromList([...buf, ...(chunk as List<int>)]);
              while (buf.length >= 4 &&
                  buf.length >=
                      4 + ByteData.sublistView(buf).getUint32(0, Endian.big)) {
                final n = ByteData.sublistView(buf).getUint32(0, Endian.big);
                final f =
                    jsonDecode(utf8.decode(buf.sublist(4, 4 + n)))
                        as Map<String, Object?>;
                buf = Uint8List.fromList(buf.sublist(4 + n));
                if (f['t'] == 'hello') {
                  toProxy.write(
                    encodeFrame({
                      't': 'hello',
                      'proto': 1,
                      'allowedDomains': ['allowed.test:443'],
                      'deniedDomains': [],
                    }),
                  );
                  continue;
                }
                asked.add(f);
                toProxy.write(
                  encodeFrame({
                    't': 'verdict',
                    'id': f['id'] as int,
                    'action': 'deny',
                    'status': 403,
                    'reason': 'denied by the test decider',
                  }),
                );
              }
            });
            await () {
              final completer = Completer<void>();
              final t = globals.setInterval(() {
                if (stderr.contains('serving fd 3') && !completer.isCompleted) {
                  completer.complete();
                }
              }, 20);
              unawaited(
                exited.then((code) {
                  globals.clearInterval(t);
                  if (!completer.isCompleted) {
                    completer.completeError(Exception('exited $code: $stderr'));
                  }
                }),
              );
              return completer.future.whenComplete(
                () => globals.clearInterval(t),
              );
            }();
            // A tunnel to the allowed host, terminated with a leaf of the handed CA,
            // and a request the decider denies.
            final clientEvents = <String>[];
            final reply = await () {
              final completer = Completer<String>();
              late final net.NodeSocket c;
              c = net.connect(
                port,
                '127.0.0.1',
                () => c.write(
                  'CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n',
                ),
              );
              c.on('error', (Object e) {
                if (!completer.isCompleted) completer.completeError(e);
              });
              var head = '';
              void onData(Object? x) {
                head += latin1.decode(x as List<int>);
                if (!head.contains('\r\n\r\n')) return;
                clientEvents.add(
                  'CONNECT response: ${head.split('\r\n').first}',
                );
                c.off('data', onData);
                final t = tls.connect({
                  'socket': c,
                  'ca': ca.certPem,
                  'servername': 'allowed.test',
                  'ALPNProtocols': ['http/1.1'],
                });
                var out = '';
                t.on('secureConnect', (_) {
                  clientEvents.add('secureConnect');
                  // Dart regression: application data must still be read
                  // when it arrives after the final TLS handshake packet.
                  globals.setTimeout(() {
                    final accepted = t.write(
                      'GET /x HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n',
                    );
                    clientEvents.add('request write: $accepted');
                  }, 50);
                });
                t.on('data', (Object? y) => out += utf8.decode(y as List<int>));
                t.on('close', (_) {
                  clientEvents.add(
                    'TLS close: read=${t.bytesRead}, written=${t.bytesWritten}, queued=${t.writableLength}',
                  );
                  if (!completer.isCompleted) completer.complete(out);
                });
                t.on('error', (Object e) {
                  if (!completer.isCompleted) completer.completeError(e);
                });
              }

              c.on('data', onData);
              return completer.future;
            }();
            expect(
              reply,
              startsWith('HTTP/1.1 403'),
              reason:
                  '$stderr\nClient events: $clientEvents\nDecider requests: $asked',
            );
            expect(reply, contains('denied by the test decider'));
            expect(asked, hasLength(1));
            expect(asked[0], containsPair('t', 'req'));
            expect(asked[0], containsPair('host', 'allowed.test'));
            expect(asked[0], containsPair('path', '/x'));
            lifeline.end();
            expect(await exited, 0);
            expect(stderr, contains('lifeline closed'));
          },
          timeout: const Timeout(Duration(milliseconds: 20000)),
          skip: !canServeEmittedConnections || (pin && TASKSET == null)
              ? true
              : null,
        );
      }
    }
  });

  /**
   * Runs the entry to completion with only stdin, stdout and stderr open, and
   * returns what it wrote as bytes (one character per byte).
   */
  ({int? status, String stdout, String stderr}) runToExit(
    List<String> args, {
    Map<String, String>? env,
    String? cwd,
  }) {
    final r = spawnSync(
      _execPath,
      [ENTRY, ...args],
      {
        'stdio': ['ignore', 'pipe', 'pipe'],
        'env': ?env,
        'cwd': ?cwd,
      },
    );
    return (
      status: r.status,
      stdout: (r.stdout as Buffer).toString('latin1'),
      stderr: (r.stderr as Buffer).toString('latin1'),
    );
  }

  group('srt-proxy --version', () {
    // Dart: package.json is pubspec.yaml here.
    final version = RegExp(r'^version:\s*(\S+)', multiLine: true)
        .firstMatch(
          readFileSync('${io.Directory.current.path}/pubspec.yaml', 'utf8')
              as String,
        )!
        .group(1)!;
    final LINE = 'srt-proxy $version\n';

    test('prints one line, the name and the package version, and exits 0', () {
      expect(
        version,
        matches(RegExp(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')),
      );
      expect(runToExit(['--version']), (status: 0, stdout: LINE, stderr: ''));
    });

    test('needs nothing from the environment or the working directory', () {
      expect(runToExit(['--version'], env: {}, cwd: '/'), (
        status: 0,
        stdout: LINE,
        stderr: '',
      ));
    });

    // Descriptors 3 to 6 are closed in the child: starting on them fails, so
    // the same answer shows that none of them was opened or read.
    // Dart: 100 to 103 stand in for 3 to 6, which the Dart VM itself opens
    // on Linux (a pipe, an eventpoll and a timerfd).
    const CLOSED_FDS = [
      '--listen-fd',
      '100',
      '--decider-fd',
      '101',
      '--lifeline-fd',
      '102',
      '--ca-fd',
      '103',
    ];

    test('opens no descriptor another option names', () {
      expect(runToExit(CLOSED_FDS).status, isNot(0));
      for (final args in [
        [...CLOSED_FDS, '--version'],
        ['--version', ...CLOSED_FDS],
      ]) {
        expect(runToExit(args), (status: 0, stdout: LINE, stderr: ''));
      }
    });

    for (final (_name, args) in <(String, List<String>)>[
      (
        'after an option that does not exist',
        ['--no-such-option', '--version'],
      ),
      (
        'before an option that does not exist',
        ['--version', '--no-such-option'],
      ),
      ('where another option expects its value', ['--listen-fd', '--version']),
      (
        'after an address that would be refused',
        ['--decider-fd', '3', '--listen', '0.0.0.0:0', '--version'],
      ),
      ('with --help', ['--help', '--version']),
      ('given twice', ['--version', '--version']),
    ]) {
      test('wins over the rest of the command line: $_name', () {
        expect(runToExit(args), (status: 0, stdout: LINE, stderr: ''));
      });
    }

    test('is listed by --help', () {
      final help = runToExit(['--help']);
      expect(help.status, 0);
      expect(help.stderr, '');
      expect(help.stdout, startsWith('Usage: srt-proxy [options]'));
      expect(
        help.stdout,
        matches(RegExp(r'^ {2}--version {2,}\S', multiLine: true)),
      );
    });
  });

  /** Resolves with stderr once it matches `re`; rejects if the proxy exits first. */
  Future<String> stderrMatching(Proc p, RegExp re) {
    final completer = Completer<String>();
    void check() {
      if (re.hasMatch(p.stderr()) && !completer.isCompleted) {
        completer.complete(p.stderr());
      }
    }

    p.child.stderr!.listen((_) => check());
    unawaited(
      p.exited.then((code) {
        if (completer.isCompleted) return;
        if (re.hasMatch(p.stderr())) {
          completer.complete(p.stderr());
        } else {
          completer.completeError(Exception('exited $code: ${p.stderr()}'));
        }
      }),
    );
    check();
    return completer.future;
  }

  group('srt-proxy --listen address', () {
    const DECIDER = ['--decider-fd', '3'];

    for (final addr in ['0.0.0.0:0', ':0', '[::]:0', '192.0.2.1:0']) {
      test(
        '$addr is refused without --listen-any-interface (exit 2)',
        () async {
          final p = run(['--listen', addr, ...DECIDER]);
          expect(await p.exited, 2);
          expect(p.stderr(), contains('is not a loopback address'));
          expect(p.stderr(), contains('--listen-any-interface'));
          expect(p.stderr(), isNot(contains('serving')));
        },
      );
    }

    test(
      'a bare port is refused with a message about the expected form (exit 2)',
      () async {
        final p = run(['--listen', '8080', ...DECIDER]);
        expect(await p.exited, 2);
        expect(p.stderr(), contains('--listen needs <host:port>'));
      },
    );

    Future<String> starts(List<String> args, RegExp serving) async {
      final p = run([...args, ...DECIDER]);
      final decider = p.child.stdio[3]! as net.NodeSocket;
      decider.once(
        'data',
        (_) => decider.write(
          encodeFrame({
            't': 'hello',
            'proto': 1,
            'allowedDomains': [],
            'deniedDomains': [],
          }),
        ),
      );
      try {
        return await stderrMatching(p, serving);
      } finally {
        p.child.kill('SIGKILL');
        await p.exited;
      }
    }

    test('127.0.0.1:0 starts without the flag and without a warning', () async {
      final err = await starts([
        '--listen',
        '127.0.0.1:0',
      ], RegExp(r'serving 127\.0\.0\.1:\d+'));
      expect(err, isNot(contains('warning')));
    });

    test('[::1]:0 starts without the flag', () async {
      final err = await starts([
        '--listen',
        '[::1]:0',
      ], RegExp(r'serving ::1:\d+'));
      expect(err, isNot(contains('warning')));
    }, skip: !HAS_IPV6_LOOPBACK ? true : null);

    test(
      '0.0.0.0:0 starts with --listen-any-interface and warns that the listener is exposed',
      () async {
        final err = await starts([
          '--listen',
          '0.0.0.0:0',
          '--listen-any-interface',
        ], RegExp(r'serving 0\.0\.0\.0:\d+'));
        expect(
          err,
          contains(
            'warning: --listen-any-interface: the listener on 0.0.0.0:0 is reachable from other hosts and is unauthenticated',
          ),
        );
      },
    );
  });
}
