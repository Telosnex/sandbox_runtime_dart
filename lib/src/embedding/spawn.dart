// TELOSNEX DEVIATION: upstream leaves process launch to Node; export a Dart
// Process-compatible launcher so embedders can exclude inherited descriptors.
import 'dart:async';
import 'dart:io';

import '../node/child_process.dart' as node;
import '../node/errno.dart';
import '../node/events.dart' as events;

/// Starts [argv] literally, without a shell, on macOS or Linux. This does not
/// apply a sandbox by itself: pass the `argv` and `env` from
/// `SandboxManager.wrapWithSandboxArgv` to run a wrapped command.
/// [environment] replaces the parent environment when supplied; null values
/// are omitted. Use an absolute executable path for unambiguous resolution.
///
/// The executable starts with only descriptors 0 (stdin), 1 (stdout), and 2
/// (stderr), all piped. macOS uses `POSIX_SPAWN_CLOEXEC_DEFAULT`. Linux uses
/// `srt-spawn`, which closes descriptors with `close_range` (or enumerates
/// `/proc/self/fd` within the single-threaded helper if unavailable). The
/// helper also relays the exact exit status even when Dart reaps its process.
/// Linux requires the helper; this API never uses the helper-less fallback.
///
/// On Linux [helperPath] overrides helper discovery, even if that path fails.
/// Otherwise the launcher checks `SRT_SPAWN_HELPER` in the **parent**
/// environment and then `vendor/spawn-helper/<arch>/srt-spawn` at the
/// `sandbox_runtime` root from the Dart package config. Bundled/AOT apps can
/// supply the absolute path to their own trusted copy (build it with
/// `dart run tool/build_spawn_helper.dart`). [helperPath] is ignored on macOS.
///
/// Set [newSession] to make the child the leader of a new session and process
/// group before it runs. This enables [SafeProcess.killGroup]. On Linux this
/// option requires a helper built from this version of the package.
///
/// Output is buffered until listened to. Consume or cancel both output
/// streams promptly to avoid retaining unbounded output. Close stdin when
/// the child should receive EOF. Other platforms throw [UnsupportedError].
Future<SafeProcess> spawnSafe(
  List<String> argv, {
  Map<String, String?>? environment,
  String? workingDirectory,
  bool newSession = false,
  String? helperPath,
}) async {
  if (!Platform.isMacOS && !Platform.isLinux) {
    throw UnsupportedError('spawnSafe is only supported on macOS and Linux');
  }
  if (argv.isEmpty || argv.first.isEmpty || argv.any(_containsNul)) {
    throw ArgumentError.value(
      argv,
      'argv',
      'Expected a nonempty executable and no NUL bytes',
    );
  }
  if (workingDirectory != null && _containsNul(workingDirectory)) {
    throw ArgumentError.value(
      workingDirectory,
      'workingDirectory',
      'Contains a NUL byte',
    );
  }
  if (Platform.isLinux &&
      helperPath != null &&
      (helperPath.isEmpty || _containsNul(helperPath))) {
    throw ArgumentError.value(
      helperPath,
      'helperPath',
      'Expected a path with no NUL bytes',
    );
  }
  if (environment != null) {
    for (final entry in environment.entries) {
      final key = entry.key, value = entry.value;
      if (key.isEmpty ||
          key.contains('=') ||
          _containsNul(key) ||
          (value != null && _containsNul(value))) {
        throw ArgumentError('Invalid environment variable name or value');
      }
    }
  }
  final child = node.spawnForEmbedding(
    argv.first,
    argv.sublist(1),
    {'cwd': workingDirectory, 'env': environment},
    newSession: newSession,
    helperPath: helperPath,
  );
  if (child.pid == null) {
    throw (await events.once(child, 'error')).single!;
  }
  return SafeProcess._(child, newSession);
}

bool _containsNul(String value) => value.contains('\u0000');

/// A [Process] from [spawnSafe], with optional process-group signaling.
final class SafeProcess implements Process {
  SafeProcess._(this._child, this._newSession)
    // Attach both listeners synchronously: the Node shim's broadcast streams
    // would otherwise discard data that arrives before the caller listens.
    : stdout = _buffer(_child.stdout!),
      stderr = _buffer(_child.stderr!),
      stdin = node.embeddingStdin(_child.stdin!) {
    final exit = Completer<int>();
    exitCode = exit.future;
    _child.on('error', (Object error) {
      if (!exit.isCompleted) exit.completeError(error);
    });
    _child.once('exit', (int? code, String? signal) {
      _child.stdin!.end();
      if (!exit.isCompleted) {
        exit.complete(
          code ?? -(int.tryParse(signal!) ?? node.signalNumber(signal)),
        );
      }
    });
  }

  final node.ChildProcess _child;
  final bool _newSession;

  @override
  int get pid => _child.pid!;

  @override
  late final Future<int> exitCode;

  @override
  final IOSink stdin;

  @override
  final Stream<List<int>> stdout;

  @override
  final Stream<List<int>> stderr;

  @override
  bool kill([ProcessSignal signal = ProcessSignal.sigterm]) =>
      _child.kill(signal.signalNumber);

  /// Sends [signal] to the group whose ID is [pid]. Returns false if the
  /// group could not be signaled; throws [StateError] without `newSession`.
  ///
  /// This does not wait for exit or reach descendants that leave the group.
  /// It can be used after the leader exits while its descendants are still
  /// in the group; do not use a stale handle after the group's lifetime.
  bool killGroup([ProcessSignal signal = ProcessSignal.sigterm]) {
    if (!_newSession) throw StateError('killGroup requires newSession');
    if (pid <= 1) return false;
    try {
      return node.killPid(-pid, signal.signalNumber);
    } on NodeError {
      return false;
    }
  }
}

Stream<List<int>> _buffer(Stream<List<int>> source) {
  final controller = StreamController<List<int>>();
  final subscription = source.listen(
    controller.add,
    onError: controller.addError,
    onDone: controller.close,
  );
  controller.onCancel = subscription.cancel;
  return controller.stream;
}
