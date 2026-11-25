// No upstream counterpart: tests per-command mandatory deny roots
// (PORT_WORKLOG.md, "Deviations from upstream").
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/sandbox_runtime.dart' hide Platform;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show cleanupBwrapMountPoints;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show FilesystemPathLiteral;
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart'
    show PartialSandboxRuntimeConfig;
import 'package:sandbox_runtime/src/utils/shell_quote.dart' show quote;
import 'package:sandbox_runtime/src/utils/which.dart' show whichSync;
import 'package:test/test.dart';

import '../helpers/bwrap_argv.dart' show lastMountAt, mountsOf;
import '../helpers/bwrap_namespace.dart' show bwrapCanNamespace;

void main() {
  final policySkip =
      Platform.isMacOS ||
          (Platform.isLinux &&
              whichSync('bwrap') != null &&
              whichSync('rg') != null)
      ? false
      : 'requires macOS or Linux with bubblewrap and ripgrep';
  final liveSkip = policySkip != false
      ? policySkip
      : Platform.isLinux && !bwrapCanNamespace()
      ? 'bwrap cannot create namespaces'
      : false;
  late Directory fixtures;
  late String cwd;
  late String a;
  late String b;
  final savedCwd = Directory.current.path;
  const shell = '/bin/bash';
  const gitEnv = 'GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1';

  setUp(() {
    fixtures = Directory.systemTemp.createTempSync('srt-roots-');
    final base = fixtures.resolveSymbolicLinksSync();
    cwd = (Directory(path.join(base, 'cwd'))..createSync()).path;
    a = (Directory(path.join(base, 'a[literal]'))..createSync()).path;
    b = (Directory(path.join(base, 'b'))..createSync()).path;
    Directory.current = cwd;
  });

  tearDown(() {
    Directory.current = savedCwd;
    if (Platform.isLinux) cleanupBwrapMountPoints(force: true);
    fixtures.deleteSync(recursive: true);
  });

  Future<({List<String> argv, Map<String, String?> env})> wrap(
    String command, [
    List<String>? roots,
  ]) => SandboxManager.wrapWithSandboxArgv(
    command,
    shell,
    PartialSandboxRuntimeConfig(
      filesystem: FilesystemConfig(
        allowWrite: [
          for (final dir in [a, b, cwd]) FilesystemPathLiteral(dir),
        ],
        denyWrite: [],
        denyRead: [],
      ),
      mandatoryDenyRoots: roots,
    ),
    null,
    a,
  );

  Future<void> runProbe(String command, List<String> roots) async {
    final wrapped = await wrap(command, roots);
    final result = await Process.run(
      wrapped.argv.first,
      wrapped.argv.skip(1).toList(),
      environment: {
        for (final MapEntry(:key, :value) in wrapped.env.entries)
          if (value != null) key: value,
      },
      workingDirectory: a,
    );
    expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
    expect(result.stdout, contains('PROBE_DONE'));
  }

  String checkBlocked(String operation) =>
      'if $operation; then echo ${quote(['unexpected success: $operation'])} >&2; exit 1; fi';

  test('omitting roots still generates the process cwd write policy', () async {
    File(path.join(cwd, '.bashrc')).writeAsStringSync('');
    final omitted = await wrap(':');
    final explicitCwd = await wrap(':', [cwd]);
    final noRoots = await wrap(':', []);
    if (Platform.isMacOS) {
      // Same command => same log tag, so compare the entire wrapped profile.
      expect(omitted.argv, explicitCwd.argv);
      expect(omitted.argv[2], contains('$cwd/.bashrc'));
      expect(noRoots.argv[2], isNot(contains('$cwd/.bashrc')));
    } else {
      // Compare generated mounts as a multiset: ripgrep's order can vary.
      expect(
        mountsOf(omitted.argv[2]),
        unorderedEquals(mountsOf(explicitCwd.argv[2])),
      );
      final bashrc = '$cwd/.bashrc';
      expect(lastMountAt(omitted.argv[2], bashrc), '--ro-bind $bashrc $bashrc');
      expect(lastMountAt(noRoots.argv[2], bashrc), isNull);
    }
  }, skip: policySkip);

  test(
    'protects two roots without blocking ordinary writes or git commits',
    () async {
      for (final repo in [a, b]) {
        final result = Process.runSync(shell, [
          '-c',
          '$gitEnv git -c init.defaultBranch=main init --template= -q ${quote([repo])}',
        ]);
        expect(result.exitCode, 0, reason: '${result.stderr}');
        Directory(path.join(repo, '.git', 'hooks')).createSync();
      }
      Directory(path.join(a, 'src')).createSync();
      final bArg = quote([b]);
      final cwdArg = quote([cwd]);

      await runProbe(
        [
          'set -e',
          checkBlocked('printf blocked > .git/hooks/x'),
          checkBlocked('printf blocked > $bArg/.bashrc'),
          checkBlocked('mv $bArg/.git $bArg/.git-moved'),
          'printf ordinary > src/x',
          'printf ordinary > $bArg/allowed.txt',
          'export $gitEnv',
          'git add src/x',
          'git -c user.name=Test -c user.email=test@example.com -c commit.gpgsign=false commit -qm test',
          // The command's roots replace, rather than add to, the process cwd.
          'printf ordinary > $cwdArg/.bashrc',
          'echo PROBE_DONE',
        ].join('\n'),
        [a, b],
      );

      expect(File(path.join(a, '.git', 'hooks', 'x')).existsSync(), isFalse);
      expect(Directory(path.join(b, '.git')).existsSync(), isTrue);
      expect(File(path.join(a, 'src', 'x')).readAsStringSync(), 'ordinary');
      expect(
        File(path.join(a, '.git', 'refs', 'heads', 'main')).existsSync(),
        isTrue,
      );
    },
    skip: liveSkip != false
        ? liveSkip
        : (whichSync('git') == null ? 'requires git' : false),
  );

  test(
    "keeps the platform's nested protection and Linux scan bounds",
    () async {
      const nested = 'child/.bashrc';
      const excluded = ['node_modules/pkg/.bashrc', 'd1/d2/d3/.bashrc'];
      for (final relative in [nested, ...excluded]) {
        final file = File(path.join(a, relative));
        file.parent.createSync(recursive: true);
        file.writeAsStringSync('');
      }

      await runProbe(
        [
          'set -e',
          checkBlocked('printf blocked > $nested'),
          for (final relative in excluded)
            if (Platform.isLinux)
              'printf allowed > $relative'
            else
              checkBlocked('printf blocked > $relative'),
          'echo PROBE_DONE',
        ].join('\n'),
        [a, b],
      );
    },
    skip: liveSkip,
  );
}
