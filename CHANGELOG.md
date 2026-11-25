## 1.0.0

Based on Anthropic Sandbox Runtime v0.0.83 (`0bbebed`). From this release, the
package version is independent of the upstream version. The upstream version
is in the README and in each changelog entry.

New opt-in options for Dart apps that embed the sandbox. Each one differs from
upstream; without it, behavior is the same as upstream. `PORT_WORKLOG.md`
lists the details.

- `PartialSandboxRuntimeConfig.mandatoryDenyRoots`: apply the built-in
  protected paths to given folders, not only the process working directory.
- `spawnSafe` / `SafeProcess`: start a process that inherits only file
  descriptors 0, 1 and 2, optionally in a new session. Requires `srt-spawn`
  on Linux.
- `PartialSandboxRuntimeConfig.temporaryDirectory` and
  `omitDefaultWritablePaths`: a caller-owned temporary folder per command,
  without the shared default write paths.
- `SandboxInitializeOptions.registerProcessHandlers`: set to `false` to skip
  the SIGINT, SIGTERM and exit cleanup handlers. The embedder then calls
  `cleanupAfterCommand` and `reset`.
- `PartialSandboxRuntimeConfig.directNetwork`: direct IP network for one
  command on macOS and Linux, with the filesystem policy unchanged. Unix
  sockets keep the proxy-mode rules. On macOS, system TLS trust services are
  allowed. Windows rejects it.

## 0.0.85

- Shorten the package description, add a runnable sandbox example, and fix analyzer lints.

## 0.0.84

- Fix `execFileSync`/`spawnSync` on macOS sometimes failing with `ECHILD` when
  the child exited quickly. The child now starts suspended until its exit
  watch is registered.

## 0.0.83

- Port Anthropic Sandbox Runtime v0.0.83 to Dart.
- Support macOS and Linux sandbox backends and an injectable Windows MXC SDK adapter.
- Add public-repository CI, pub.dev publication and daily upstream checks.
