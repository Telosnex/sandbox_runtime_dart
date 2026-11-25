// Ported from sandbox-runtime src/proxy-cli.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments
/**
 * `srt proxy` argument handling, shared by the `srt` CLI and the
 * standalone proxy entry (proxy-main.ts). Kept free of anything that needs
 * files next to the bundle (vendor/, or package.json read at run time), so
 * it compiles into a single executable. The package manifest is a static
 * import, which a bundler embeds.
 */
library;

import 'dart:convert';

import 'node/commander.dart' show Command;
import 'node/console.dart' as console;
import 'node/errno.dart' show errorMessage;
import 'node/globals.dart';
import 'node/net.dart' show NodeAddress, isIPv4, isIPv6;
import 'node/process.dart' as process;
import 'sandbox/proxy_only.dart'
    show
        ProxyListen,
        ProxyListenFd,
        ProxyListenHostPort,
        ProxyOnlyOptions,
        openFdStreams,
        readPemFromFd,
        startProxyOnly;

// Dart has no JSON import: package.json's version, kept equal to pubspec.yaml.
const _pkg = (version: '1.0.0');

Future<void> runProxyCli(List<String> argv) async {
  // `--version` anywhere on the command line prints one line and does nothing
  // else: no other option is parsed, so no descriptor is opened, nothing is
  // read or bound, and the process ends once the line is written.
  if (argv.contains('--version')) {
    process.stdout.write('srt-proxy ${_pkg.version}\n');
    return;
  }
  final program = Command('srt-proxy')
      .description(
        'Run only the HTTP proxy, deciding every request through an external decider on inherited fds.',
      )
      .option(
        '--listen-fd <fd>',
        'accept connections on this inherited listening socket',
        (v) => parseInt(v, 10),
      )
      .option(
        '--listen <host:port>',
        'listen on this loopback address instead (development); a non-loopback address needs --listen-any-interface',
      )
      .option(
        '--listen-any-interface',
        'let --listen bind a non-loopback address: the listener is unauthenticated and reachable from other hosts',
      )
      .option(
        '--decider-fd <fd>',
        'bidirectional decider stream (a socket)',
        (v) => parseInt(v, 10),
      )
      .option(
        '--decider-in <fd>',
        'decider -> proxy stream (with --decider-out)',
        (v) => parseInt(v, 10),
      )
      .option(
        '--decider-out <fd>',
        'proxy -> decider stream (with --decider-in)',
        (v) => parseInt(v, 10),
      )
      .option(
        '--lifeline-fd <fd>',
        'shut down when this stream ends',
        (v) => parseInt(v, 10),
      )
      .option(
        '--ca-fd <fd>',
        'read the TLS-termination CA (key and certificate PEM) from this fd',
        (v) => parseInt(v, 10),
      )
      .option(
        '--strip-response-header <name...>',
        'response headers never passed back',
      )
      .option(
        '--plaintext-header-set',
        'let allow verdicts set headers on plain-HTTP requests (cleartext)',
      )
      .option('-d, --debug', 'enable debug logging')
      .option(
        '--version',
        'print "srt-proxy <version>" and exit; every other option is ignored',
      )
      .exitOverride((err) {
        process.exit(err.exitCode == 0 ? 0 : 2);
      });
  await program.parse(argv);
  final o = program.opts();
  if (o['debug'] == true) process.env['SRT_DEBUG'] = 'true';
  // Diagnostics: with SRT_PROXY_REPORT_RSS_MS set to a positive integer N,
  // report the resident set size on stderr every N ms, for hosts that cannot
  // read another process's memory use.
  final rssEvery = Number(process.env['SRT_PROXY_REPORT_RSS_MS']);
  if (NumberIsInteger(rssEvery) && rssEvery > 0) {
    setInterval(() {
      process.stderr.write('srt-proxy rss ${process.memoryUsage().rss}\n');
    }, rssEvery.toInt()).unref();
  }
  Never fail(String msg) {
    console.error('srt proxy: $msg');
    process.exit(2);
  }

  final inFd = (o['deciderFd'] ?? o['deciderIn']) as num?;
  final outFd = (o['deciderFd'] ?? o['deciderOut']) as num?;
  if (inFd == null || outFd == null) {
    fail(
      'a decider is required (--decider-fd, or --decider-in and --decider-out)',
    );
  }
  ProxyListen listen;
  final listenFd = o['listenFd'];
  if (listenFd is num && NumberIsInteger(listenFd) && listenFd >= 0) {
    listen = ProxyListenFd(fd: listenFd.toInt());
  } else if (o['listen'] is String) {
    final oListen = o['listen'] as String;
    final i = oListen.lastIndexOf(':');
    final rawHost = i < 0 ? '' : oListen.substring(0, i);
    final host = RegExp(r'^\[.*\]$').hasMatch(rawHost)
        ? rawHost.substring(1, rawHost.length - 1)
        : rawHost;
    final portText = oListen.substring(i + 1);
    final port = Number(portText);
    if (i < 0 || !RegExp(r'^\d+$').hasMatch(portText) || port > 65535) {
      fail(
        '--listen needs <host:port> with a port from 0 to 65535 (got ${jsonEncode(oListen)})',
      );
    }
    if (!isLoopbackHost(host)) {
      // The listener has no authentication of its own: an empty host binds
      // every interface, so only an explicit flag may leave loopback.
      if (o['listenAnyInterface'] != true) {
        fail(
          '--listen ${jsonEncode(oListen)} is not a loopback address (127.0.0.0/8, [::1] or localhost); pass --listen-any-interface to bind it anyway',
        );
      }
      console.error(
        'srt proxy: warning: --listen-any-interface: the listener on $oListen is reachable from other hosts and is unauthenticated',
      );
    }
    listen = ProxyListenHostPort(host: host, port: port.toInt());
  } else {
    fail('--listen-fd (or --listen for development) is required');
  }
  try {
    final p = startProxyOnly(
      ProxyOnlyOptions(
        listen: listen,
        decider: inFd == outFd
            ? openFdStreams(inFd.toInt())
            : (
                input: openFdStreams(inFd.toInt(), writable: false).input,
                // Dart: write-only, as Bun's writer is: a peer that closed is
                // learnt of by a failed write, not by an EOF read.
                output: openFdStreams(outFd.toInt(), readable: false).output,
              ),
        caPem: o['caFd'] is num
            ? readPemFromFd((o['caFd'] as num).toInt())
            : null,
        lifeline: o['lifelineFd'] is num
            ? openFdStreams((o['lifelineFd'] as num).toInt()).input
            : null,
        stripResponseHeaders: (o['stripResponseHeader'] as List?)
            ?.cast<String>(),
        plaintextHeaderSet: o['plaintextHeaderSet'] == true,
        onClosed: (why) {
          console.error('srt proxy: stopped ($why)');
          process.exit(why.startsWith('start failed') ? 1 : 0);
        },
      ),
    );
    process.once('SIGTERM', () => p.close('SIGTERM'));
    await p.ready;
    final a = listen is ProxyListenFd ? null : p.listener.address();
    console.error(
      'srt proxy: serving ${a != null && a is! String ? '${(a as NodeAddress).address}:${a.port}' : 'fd ${(listen as ProxyListenFd).fd}'}',
    );
  } catch (e) {
    fail(errorMessage(e));
  }
}

/** Whether a `--listen` host can only be reached from this machine. */
bool isLoopbackHost(String host) {
  if (host.toLowerCase() == 'localhost') return true;
  if (isIPv4(host)) return host.startsWith('127.');
  return isIPv6(host) &&
      RegExp(r'^(0{1,4}:){7}0{0,3}1$|^::0{0,3}1$').hasMatch(host);
}
