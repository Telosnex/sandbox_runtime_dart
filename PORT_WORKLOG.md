# Port worklog

Upstream: https://github.com/anthropics/sandbox-runtime, checked out at
`~/dev/sandbox-runtime`. Port baseline: v0.0.83, commit `0bbebed` (synced 2026-11-14 from v0.0.79, `24eb39e`).

## Sync to v0.0.83 (2026-11-14)

The port follows upstream `0bbebed` (v0.0.83). Six agents synced it on the
branches `port/sync-{paths,linux,proxy,front,win,cli}`, merged in
`port/sync-all`. Every header names `0bbebed`.

- New upstream files ported: `glob-pattern.ts`, `mxc-sandbox-utils.ts`, and
  their tests, and the new Linux, proxy and path tests.
- **Windows.** srt-win stays unsupported: `windows_sandbox_utils.dart` ports
  the pure helpers, and functions that run srt-win throw. The **MXC backend
  is ported in full**. Rule 3 for `@microsoft/mxc-sdk`, an optional peer of
  upstream: the port depends on no MXC package. `isMxcSdkInstalled()` is
  false and `loadMxcSdk()` throws; an embedder passes `windowsMxcSdk` to
  `initialize()`. Telosnex passes an adapter over `mxc_sdk_dart`. The MXC
  boundary tests skip with the Windows reason; the tests through a fake SDK
  run everywhere.
- Shims: `fs` (native realpath, byte paths, `statfsSync`, spy variables),
  `process` (cwd through libc `getcwd`, stdio streams), `path` (resolve
  reads the cwd only for a relative path), new `util` (`isDeepStrictEqual`)
  and `stream_promises` (`finished`), `commander` (repeatable options,
  defaults), `http` (a read no longer asks for more bytes than are
  buffered, which had cut throughput to about 1 MB/s), `structured_clone`
  (new config fields).
- `pointycastle` ^4.0.0, which Telosnex resolves.
- The Linux VM needs `kernel.apparmor_restrict_unprivileged_userns=0` (as
  upstream CI sets) and, on Ubuntu 26.04, the `bwrap-userns-restrict`
  AppArmor profile unloaded, for the tests that run the seccomp helper
  inside bwrap. Before the sync, the helper lookup depended on the cwd, so
  those tests ran without the helper and passed.

New skips (title and body kept):
- `linux_nested_userns_test`: two cases cast `'yes'` and `1` to a boolean
  option; Dart types reject them at compile time.
- `read_deny_glob_test`: one case depends on Bun resolving `/proc/self/cwd`
  beneath an unsearchable folder; libc `realpath` and Node return EACCES.
- `tunnel_ends_test` (from `test/fixtures/tunnel-ends.mjs`): five cases, three
  runs each, need TLS `close_notify`, which `dart:io` does not send.
- `tls_terminate_destroy_soon_test`: a destroy after a finished end cannot
  discard the native socket queue of `dart:io`.
- One case needs an unref'd socket; Dart has no unref.

Suspected upstream bugs, ported as they are:
- `spawnSandboxed()` joins per-command `allowWrite` with session
  `denyWrite` without ranking. MXC lets the most specific path win, so a
  per-command write grant beneath a session write deny overrides the deny.
- `cli.ts`: the MXC branch removes the signal handlers before it awaits
  `spawnSandboxed()`, and adds the forwarding handlers after. A signal during
  the await has no handler.

## Deviations from upstream

Each one is marked `TELOSNEX DEVIATION` in the code and has a test in
`test/deviations/`.

- `mxc_sandbox_utils.dart`, `buildMxcRequest`: upstream sends every
  `denyWrite` path as an MXC denied path, which also blocks reads. Here an
  existing `denyWrite` path outside every `denyRead` is a read-only path:
  MXC then blocks writes, renames into it and deletes, and keeps reads
  (tested on Windows 11 26H2, 2026-11-14). A denied `.git/config` breaks
  git. A missing path stays denied, because a read-only path does not stop
  its creation. Telosnex may propose this upstream.

- `spawnSafe` / `SafeProcess`: upstream leaves spawning to Node. Dart
  embedders can spawn wrapped or plain argv with piped stdio and only fds
  0, 1, and 2 at exec, with exact exit status. macOS uses the port's
  `POSIX_SPAWN_CLOEXEC_DEFAULT`; Linux requires `srt-spawn` for the fd and
  status guarantees and accepts an explicit `helperPath` for app bundles
  before normal discovery. Opt-in `newSession` sets up a process group
  before exec so apps can stop a command and its group. Existing
  Node-shaped shim callers are unchanged. Telosnex may propose the public
  launch contract upstream.

## State (2026-10-13, after the test fidelity pass)

`main` builds and passes from a clean clone on macOS (524 pass, 38 skip) and
on the Ubuntu ARM64 VM (444 pass, 111 skip, most of them macOS-only or
pending ports). No agent is running, and there is no other worktree or branch.

### Test fidelity pass (done)

Every ported test file now has all upstream titles in order and every
upstream comment (`test/port/fidelity_test.dart` checks both in
`dart test`; see below). What changed beyond comments:

- `config_validation_test` was rebuilt from upstream statement for
  statement. Its full assertions caught a validator bug: zod `.strict()`
  reports one `unrecognized_keys` issue at the object's path naming every
  unknown key; the Dart credentials/awsPairs/sigv4 parsers reported one
  issue per key at the key's path. Fixed and checked against upstream's
  compiled schema.
- `path_canonicalization_test` runs `normalizeWithHome` in a child process
  again. That caught a shim bug: `os.homedir()` threw on an empty HOME,
  where Node returns ''.
- `java_proxy_agent_test`: the `agent inside a JVM` group runs against a
  real JVM (7 tests, including the challenging proxy on the node:http shim).
  `vendor/java-proxy-agent-src` is vendored and
  `tool/build_java_proxy_agent.dart` builds the jar.
- `test/helpers/spawn.dart` ports upstream's `spawnAsync`.
- `resolved_address_guard_test`, `mux_proxy_test`: pending bodies and each
  group's setup are kept as upstream text in comments.
- `which_node_test` runs as upstream's script, in one test.
- The Seatbelt differential test moved to `test/differential/`.
- Every `pending port:` skip names the `src/` path.

Still open:

- `emitted_connection.dart` keeps upstream's declarations, but four bodies
  live in `node/emitted_http.dart`. Move them back when the proxies are
  ported (header says PARTIAL).
- Validator: zod runs a `superRefine` on a dirty object (for example, one
  with only unknown keys), but not on an aborted one (a child failed its
  type). The Dart validators stop at any new issue, so the credentials
  refinement's issues are missing when an object also has unknown keys.
  Only the issue list differs; `success` is the same.
- `test/fixtures/srt-proxy-hello.json` is not copied yet; its test
  (proxy-cli) is not ported.
- `tool/refresh_mozilla_roots.dart`, `test/node/`, `test/differential/`
  have no upstream counterpart and carry no `Ported from` header. That is
  intended.
- `aws_sigv4_test` has one extra test: upstream's describe-level
  `expect(vectors.length).toBe(22)`, moved into a test as the convention
  says.

The audit runs in `dart test` (`test/port/fidelity_test.dart`); by hand:
`dart run tool/audit/comments.dart` (every upstream
comment line of 12+ characters must appear after normalizing `{@link X}`
and `**\/`) and `dart run tool/audit/titles.dart all`. `tool/audit/README.md` lists the
expected output.

### Linux VM

- VM "Ubuntu 26.04 ARM64" (Parallels). Dart is at `/opt/dart/dart-sdk/bin`
  (not on `PATH`). gcc, libseccomp-dev, bubblewrap, socat and ripgrep are
  installed.
- `prlctl exec VM bash -c '...'` passes only the first word to `bash -c`; the
  rest runs in an outer shell. Put the commands in a script under `~` (shared
  as `/media/psf/Home`) and run `prlctl exec VM /bin/bash <script>`.
  Long-running commands can fail inside prlctl; run them with `nohup ... &`
  and poll an output file.
- To test: `git clone /media/psf/Home/dev/sandbox-runtime-dart /root/srt-dart`,
  then `dart pub get`, `dart run tool/build_seccomp.dart` and `dart test`.

### Port: DONE, final audits (2026-10-14)

main runs the whole suite green on macOS (+2486) and on Linux, as an
unprivileged user (four chunks: 467, 798, 734, 1040; ~/.srt-vm/linux_test
now runs tests as `parallels`, caps runs, passes args intact). All 20 test
batches are ported; no `pending` tags remain. Skips that stay, with reasons
in place: TLS 1.2-capped clients (dart:io has no max version), npm-install
own-files cases, root-only and macOS-nc cases, Windows sandboxing.
Audits clean at abd9549: comments (all lib files but Windows bodies), stubcheck (all src/), titles (two intended differences, allow-listed in test/port), format, analyze. Linux and macOS green. Next: Telosnex integration.
Upstream/deployment notes: ~/dev/srt-wt/FINDINGS.md.

### Wave 1 phase A: nearly DONE (2026-10-14)

Main 3b7769d has every src/ module ported and reviewed except where noted:
shims (stream/net/http/tls/fd_io, web/https, sys incl. the Linux spawn
helper vendor/spawn-helper-src/srt-spawn.c), linux_sandbox_utils,
sandbox_manager, http/tls/socks/proxy-only/parent/mux/emitted, filter,
body-substitution, decider, credentials, mitm, cli/proxy-cli/proxy-main,
config toJson. Open: shim-stream review fixes in flight (Agent defaults
maxSockets Infinity/keepAlive false, fd_io nonblocking writes + CLOEXEC
accept, early 400 on an invalid request line); then untag the mux_proxy_test
TLS-first-byte case. Known gaps: servername '' cannot disable SNI (dart:io);
https SNICallback gets '' (dart:io does not report the client's name).
Next: phase B, the ~100 unported upstream test files.

### (historical) Wave 1 restart: STATE (2026-10-13 late; rate-limit suspension)

Agents are gone (new run); worktrees and branches are the state. Main =
3da14cd: shim-web, shim-sys to e5ded96, impl-linux-small, impl-mitm-ca,
impl-socks, impl-cred, helpers, config_loader, index+fd. Unmerged:
- port/shim-stream 56c175e (+ dirty net.dart): stream.dart done; NodeSocket
  is a Duplex; http.dart compiles. Left: IncomingMessage extends Readable
  (+unpipe), closeAllConnections, unshift/flowing bug (mux test),
  NodeSocket.parser per the positional kOn* contract, setDefaultEncoding,
  listen({fd}), Socket({fd,readable,writable}).unref(), isIPv4/isIPv6,
  ClientRequest servername/auth/reusedSocket + https.Agent options,
  fs.createReadStream({fd}) (approved edit in fs.dart), https server TLS
  hook for shim-web, drop emitted_http.dart from http_test.
- port/shim-sys ca7c0ce: macOS green; Linux: VM's waitpid(-1) reaper steals
  posix_spawn children's status (even under `dart test` alone). Decision:
  (b) a tiny helper that is our child and reports the real child's wait
  status over a pipe, built like the seccomp helper; until then skip the 4-5
  Linux child_process tests with that reason so ca7c0ce can merge.
- Waiting only on shim-stream (reviewed, MERGE when deps land):
  impl-http 7f0b01a, impl-tls db1cf6d, impl-filter 64bc71b; impl-manager
  805d68f (needs closeAllConnections); impl-front c0de812 (needs
  Socket({fd}), createReadStream, isIPv4); impl-proxy-only 4a67c99 (mux
  test: unshift bug + rmSync from ca7c0ce).
- impl-linux 6caa80c: full port, un-skips done; not reviewed.
- impl-decider cfb2b21: analyzes clean; not reviewed (rev ran on e6535dd,
  result lost); no decider tests until phase B.
Decisions this round: parser kOn* slots called positionally with Node's
arity; structuredClone in node/structured_clone.dart (impl-manager);
commander/globals/readline shims (impl-front); RipgrepConfig stays two
types with boundary conversions (as upstream).

### Wave 1: PAUSED after first attempt (2026-10-13). Read before restarting

All 16 phase A agents stopped within about 30 minutes with partial work,
and each said so (none claimed done falsely). Several wrote "simplified"
code instead of a port (http_proxy basic CONNECT, socks5 state machine,
decider_client partial): do not merge that; it gets redone. Causes:
- Task size: one agent per 1,000-3,600-line file. Agents said the work
  "exceeds available task window". Wave 0 worked because each task was small.
- reasoning_effort was not set, so agents inherited /root's (low).
- Shim chain: stream.dart is barely started and NodeSocket/IncomingMessage
  do not extend it yet, so every proxy port is blocked behind it.
Restart (user direction): agents are now more capable subinstances; run
them at low effort, one agent per file as before, concise reports. Brief
addendum at the end of WAVE1_BRIEF.md: no stopping for stubs, no
simplified logic, read long files in ranges and commit per chunk. Branch state at pause: see `git log main..port/<name>` in each
worktree; gate PASS of port/shim-sys e568f3f + port/shim-web 96abefc
(unreviewed, not merged; shim-sys signs with an openssl subprocess, which
Rule 3 does not allow).

### Wave 1 plan (first attempt)

Brief: ~/dev/srt-wt/WAVE1_BRIEF.md; review brief: ~/dev/srt-wt/REVIEW1_BRIEF.md.
Each agent has worktree ~/dev/srt-wt/<name>, branch port/<name>. /root
reviews each finished branch with a read-only reviewer, then merges through
~/dev/srt-wt/gate. Ported tests whose module is a stub merge with
`@Tags(['pending'])` (Rule 1a); the implementer removes the tag.

Phase A (shims, helpers, implementations), owners:
- shim-stream: node/{stream,net,http,tls,events,dns}.dart. NodeSocket
  extends Duplex; IncomingMessage extends Readable; ServerResponse,
  ClientRequest extend Writable. Proxy shim requests go here.
- shim-web: node/{fetch,url,console}.dart, new node/https.dart.
- shim-sys: node/{crypto,fs,os,process,child_process,buffer,errno,abort}
  .dart, new node/zlib.dart, utils/which.dart spy point. Spy-point requests.
- helpers: test/helpers/*.
- impl-linux: linux_sandbox_utils (+ un-skips in seccomp_filter_test,
  path_canonicalization_test).
- impl-linux-small: linux_violation_monitor, read_deny_glob, own_files.
- impl-manager: sandbox_manager, utils/config_loader (+ java_proxy_agent_test
  un-skip).
- impl-front: new src/index.dart, src/cli.dart, src/proxy_main.dart,
  proxy_cli.dart, lib/sandbox_runtime.dart, bin/srt.dart,
  bin/srt_proxy.dart, new node/fd.dart (control-fd CLOEXEC).
- impl-http: http_proxy (+ resolved_address_guard_test un-skips).
- impl-tls: tls_terminate_proxy, mitm_leaf.
- impl-mitm-ca: mitm_ca, node/forge.dart.
- impl-socks: socks_proxy, new node/socks5_server.dart.
- impl-proxy-only: proxy_only, parent_proxy, mux_proxy,
  emitted_connection, node/emitted_http.dart (+ mux_proxy_test un-skips).
- impl-filter: request_filter, body_substitution.
- impl-decider: decider_client.
- impl-cred: credential_{sentinel,decode,mask_env,mask_files,aws_pairs}
  (+ macos_literal_deny_brackets_test un-skips).

Phase B (test porters, about 23 agents) starts when helpers and the
https/crypto/zlib declarations are on main. Not ported: winsrt tests.

### Wave 0: DONE (2026-10-13, retry)

Merged to main as a67c74b (gate PASS: 0 analyzer errors, 0 warnings;
macOS 521 pass; Linux 444 pass). Every remaining module has a stub
(or, for the three PARTIAL files, its missing exports as stubs) that
passes `tool/audit/stubcheck.dart` and an independent review: exports in
order, public members, upstream doc comments verbatim, exact types per
"Types for the remaining modules". Shim declarations: node/stream.dart,
node/fetch.dart (Headers implemented), node/console.dart, url.URL and
fileURLToPath; bodies throw until wave 1. Spy points in fs, which,
process, console.

How it ran, for next time: 10 leaf agents (system prompt forbids
agent_create; fork_turns none; brief ~/dev/srt-wt/WAVE0_BRIEF.md), one
read-only reviewer per group after its gate passed
(~/dev/srt-wt/REVIEW_BRIEF.md). Reviewers rejected 8 of 10 first
submissions; every defect was real (reworded or misplaced docs, `{@link}`
rewritten in /** */ blocks, missing allowed-value comments, wrong
optionality, a record or sealed class where the table says Object, a
static-dispatch `pipe` extension). One round of fixes each. Decisions made
during the wave are in the type table (unions of primitive and object,
`Partial<T>`, optional positionals before an options object).

### HANDOFF (historical): wave 0 first attempt aborted (2026-10-13, evening)

The first parallel attempt (wave 0: API stubs) failed and was stopped. The
chat that ran it is being reset, so this section is the only record.

What happened:
- 8 stub agents + 1 helpers agent were spawned with `fork_turns: none`.
  Their work was thin (stubs missing most upstream doc comments, types
  erased to `Object`) and most reported partial work as done.
- stub-front spawned a runaway tree of ~300 relay agents ("send", "relay",
  "to-root", ~12 levels). Cause: a Telosnex agent-team bug, children
  inherited only `agent_create` under tool search, so they could not see
  `agent_send_msg`/`agent_wait` and spawned relays instead.
- ~02:35 UTC, 179 requests failed with HTTP 403 from the ChatGPT Codex
  WebSocket backend (the children ran on GPT models); every one was
  reported as "completed without text response", not failed.
- All agents were interrupted. No agent work reached `main` (still
  0b55ba5 before this note).

Telosnex fixes: DONE and on Telosnex main as 5f7b62bccf (linear, no merge
commit; not pushed). Three fixes, each with tests (red, then green):
1. tool_search: one agent_* tool loaded (searched, in history, or inherited)
   loads all five, like web_search/web_get/cite. Children therefore always
   get all team tools.
2. A nested run that ends with no answer after a request error is `failed`,
   with the error as its report.
3. Status JSON says `activity: idle` (not `working`) for finished agents.

Cleanup: DONE. All wave 0 worktrees and port/* branches were deleted; their
work was rejected and is gone. The Telosnex worktree and branch are deleted.

Kept infrastructure (works, outside the repo):
- ~/dev/srt-wt/new <name>: worktree + branch port/<name> from main.
- ~/dev/srt-wt/sandbox-runtime: symlink so ../sandbox-runtime resolves in
  worktrees.
- ~/.srt-vm/linux_test <dir> [args]: queued Linux VM run (flock; verified).
- ~/dev/srt-wt/gate <branch>...: merge to a scratch worktree and run
  format/analyze/tests on macOS and Linux (written, never run yet).
- ~/dev/srt-wt/exports, ~/dev/srt-wt/tools/stubcheck.dart: stub gate
  (exports by name, upstream doc comments verbatim, no Object erasure).
- ~/dev/srt-wt/WAVE0_BRIEF.md: the stub brief, now with the stubcheck gate.
stubcheck now lives in the repo: `tool/audit/stubcheck.dart` (the copy in
~/dev/srt-wt/tools and ~/dev/srt-wt/exports are retired).

### Parallel setup (from wave 0, 2026-10-13)

- Every agent works in its own git worktree on its own branch, never in the
  main checkout: `~/dev/srt-wt/new <name>` creates `~/dev/srt-wt/<name>` on
  branch `port/<name>` from main. `../sandbox-runtime` resolves there too.
  Commit only on that branch; /root merges.
- Linux: `~/.srt-vm/linux_test <worktree dir> [dart test args]` runs the
  working copy on the VM, queued (one run at a time), and prints the log's
  path. Never call prlctl directly.
- Each agent owns a disjoint set of files. Needing a change in a file you do
  not own (most often a signature in another module): message /root.
- Done means: `dart analyze` clean for your files, `dart test test/port`
  passes, your files' tests pass on macOS and Linux, and an independent
  reviewer agent has read the upstream file and the Dart file in full and
  signed off.

### Coordination rules learned (keep them)

- One writer per file. Agents must not spawn sub-agents for files they own: a
  recursive spawn tree once had about 10 agents overwriting
  `macos_sandbox_utils.dart`.
- A shared shim that others import (net.dart) is developed in its own git
  worktree, then rebased and merged with `--ff-only`.
- /root commits `PORT_WORKLOG.md`; agents edit their rows but do not commit it.
- `git add` explicit paths only. The repo root must be this directory
  (`git rev-parse --show-toplevel`).
- Commit as soon as a file analyzes clean. An untracked file that a committed
  file imports breaks every other checkout (this happened with the seccomp
  port).
- An agent that reports no progress for 30 minutes is stuck: check file
  modification times, then interrupt it.
- Never `git commit --amend`, `reset`, `rebase` or `stash` in a shared
  checkout: an agent's amend once folded its file into another agent's
  commit (history was split back into one commit per file afterwards).
- Check an agent's report against `dart test test/port` and its diff:
  in the fidelity pass, half the agents reported done with work missing,
  and one replaced an upstream comment with an invented one.
- `tool/audit/ts2dart.dart` may be used ONLY for the initial skeleton of a
  TEST file, never for lib/ or tool/ code. The porter must still read the
  upstream file and the Dart file in full to confirm the port is correct.
  Put this in every porting task.
- Author: James O'Leary <jpohhhh@gmail.com>.

### Remaining source (about 19,000 of 27,700 upstream lines)

- Linux: linux-sandbox-utils (3,653), linux-violation-monitor, read-deny-glob,
  own-files. The seccomp helper builds and works on the VM.
- Proxies: http-proxy, tls-terminate-proxy, socks-proxy (needs a SOCKS5 server
  shim), proxy-only, decider-client, request-filter, the rest of
  parent-proxy, mux-proxy and emitted-connection.
- mitm-ca, mitm-leaf (forge/tls shims are ready).
- Credentials: credential-sentinel, -decode, -mask-env, -mask-files,
  -aws-pairs, body-substitution.
- windows-sandbox-utils: NOT PORTED, by decision (see below).
- sandbox-manager (3,144), then index, cli, proxy-cli, proxy-main,
  config-loader.
- Tests: most of upstream's ~66,000 test lines, mostly sandbox-manager driven.
  The queue is under "Related upstream tests not ported in this batch".
- Vendor: java-proxy-agent is done; srt-win is not vendored (Windows is
  skipped). CI.

Founder decisions (2026-10-13): the Linux sandbox and sandbox-manager come
before the proxy stack. Windows is skipped (decided 2026-10-13): Telosnex ADR
D6 rejects srt-win's model (a separate Windows user account, machine-wide
firewall filters, an administrator install step), and Telosnex uses the Codex
restricted-token fork on Windows instead.

What skipping means in practice:
- `src/sandbox/windows-sandbox-utils.ts` (2,457 lines), `vendor/srt-win-src`
  and `vendor/srt-win/build.ts` are not ported or vendored.
- sandbox-manager, index and cli import it. Port those files whole; where
  they call into it, use a STUB `lib/src/sandbox/windows_sandbox_utils.dart`
  (header `STUB: pending port of src/sandbox/windows-sandbox-utils.ts`)
  whose functions throw `UnsupportedError('Windows is not supported by this
  port')`, so the Windows branches stay in upstream's shape and fail loudly.
  On Windows, the manager's platform check should report "not supported".
- `test/sandbox/winsrt.test.ts` and `winsrt-paths.property.test.ts`: not
  ported; listed here as the gap. Tests elsewhere that are Windows-only keep
  upstream's bodies as comments with `skip: 'Windows not supported by this
  port'`.
- Config keys that only Windows reads (`windows.*`) still validate, as
  upstream's schema does.

**Telosnex follow-ups (outside this repo):** update
`docs/design/ADR_tool_execution_sandbox.md` to use this port; wire
`cli_command` to it; fix file descriptors that Telosnex leaks into spawned
commands (they bypass the sandbox, because it checks access only at open).

## Rule 1: one-to-one with upstream

The goal is to keep porting upstream changes for years. So a reader must be
able to put an upstream file next to its Dart file and diff them by eye.

- **Files.** `src/<dir>/<kebab-name>.ts` becomes `lib/src/<dir>/<snake_name>.dart`.
  Only `-` changes to `_`. Do not merge, split, or move files.
  `test/<dir>/<name>.test.ts` becomes `test/<dir>/<snake_name>_test.dart`.
  `test/helpers/*.ts` becomes `test/helpers/*.dart` (`test/helpers/platform.dart`
  is ported; use its `isLinux`/`isMacOS`/`isWindows` for `describe.if`).
  A `.` in a test name other than the extension becomes `_`
  (`glob-walk.property.test.ts` is `glob_walk_property_test.dart`).
  `vendor/<helper>/build.ts` becomes `tool/build_<helper>.dart`.
- **Names.** Every function, class, constant, type, field, and parameter keeps
  its upstream name. Only casing changes where Dart requires it:
  `SCREAMING_CASE` stays `SCREAMING_CASE` (ignore the lint per file).
  Exported TS names stay public in Dart; unexported names get a `_` prefix.
- **Order.** Declarations appear in the same order as upstream.
- **Comments.** Keep every upstream comment, edited only where it names a
  Node API that the Dart code does not use.
- **Tests.** Port every `it`/`test`/`describe` with the same title, in the same
  order. A test that cannot be ported stays as a `skip:` test with the reason.
- **Standalone Node tests.** A standalone `test/<dir>/<name>.mjs` is kept as a
  separate `test/<dir>/<name>_test.dart` file, with `-` changed to `_`; do not
  fold it into a sibling `*.test.ts` suite.
- **No improvements.** Port bugs too. Note a suspected bug here instead.
- **Each Dart file starts with:**
  `// Ported from sandbox-runtime src/<path>.ts @ <commit>.`

## Rule 1a: who ports a test file

Upstream test files are named for a behaviour, not a source file. So:

- A test file is always ported whole, as one Dart file named after it.
- From wave 1 (2026-10-13) on, test files are ported by their own agents,
  in parallel with the source they exercise: every remaining module has a
  stub with its full API (wave 0), so a test compiles before the code
  exists. A test whose module is still a stub keeps its full body and runs;
  it fails with UnimplementedError until the implementation lands, and that
  failure is the implementer's to-do list. Do not skip it.
- Such a file carries `@Tags(['pending'])` (before `library;`), so it can
  merge to main while its module is a stub: `dart_test.yaml` skips the tag
  by default, and `dart test -P impl <file>` runs it. The implementer whose
  port makes the file pass removes the tag. Never use the tag for a file
  that passes.
- A test that needs Windows gets `skip: 'Windows not supported by this
  port'`.

## Rule 1b: partial files

A file may be created before its owner ports it, to supply declarations that
another file needs:

- **Stub:** declarations only, bodies `throw UnimplementedError('pending port
  of src/<path>.ts')`, header `// STUB: pending port of src/<path>.ts @ <commit>.`
- **Partial:** some declarations ported faithfully (with their upstream
  comments, in upstream order relative to each other), the rest absent.
  Header `// PARTIAL: ported <names>; pending port of the rest of
  src/<path>.ts @ <commit>.` Allowed only when /root approves it.

The agent that later ports the whole file replaces either kind, keeping any
faithful declarations that are already there.

## Rule 2: Node API shims

Upstream leans on Node behavior: error codes, `BlockList`, `isIP`, `rawHeaders`.
Dart equivalents behave differently. All such shims live in `lib/src/node/`
(no upstream counterpart), so that ported files read like the original.
A ported file never reimplements a Node API inline.

There is one shim file per Node module, named for the module, so a ported
file imports the shim that matches upstream's import (`import * as fs from
'node:fs'` becomes `import '../node/fs.dart' as fs;`). Add to the module's
file; do not make a per-consumer file such as `fs_<consumer>.dart`.

| Node | Dart shim (`lib/src/node/`) |
|------|-----------------------------|
| `err.code` (`ENOENT`, ...) | `errno.dart`: `NodeError { code, syscall, path }`; errno-to-code tables for macOS and Linux |
| `fs` | `fs.dart`: `lstatSync`, `statSync`, `existsSync`, `readdirSync` (Dirent), `readlinkSync`, `realpathSync`; libc keeps the errno; test-only `statIdentitySync` and `fsCallObserver` |
| `os` | `os.dart`: `homedir`, `tmpdir`, `networkInterfaces` (getifaddrs) |
| `process` | `process.dart`: `platform`, `arch`, `env`, `cwd()`, overridable in tests |
| `child_process` | `child_process.dart`: `spawn` (long-running), `execSync`, `exec` |
| `crypto` | `crypto.dart`: `createHash`, `createHmac` (sha256) |
| `buffer` | `buffer.dart`: `Buffer.from`, `Buffer.byteLength`, `toString` |
| `url` | `url.dart`: WHATWG host parsing, `URLSearchParams` |
| `net`, `dns`, `tls`, `http` | `net.dart` (`isIP`, `BlockList`, `Socket`, `Server`, `connect`, `createServer`), `dns.dart`, `tls.dart` (`connect`, `TLSSocket` client and server, `createSecureContext`, `checkServerIdentity`), `http.dart` (raw HTTP/1.1; `Server` extends `net.Server`; `IncomingHttpHeaders`) |
| `node-forge` | `forge.dart`, with `mozilla_roots.dart` (generated) |
| `events` | `events.dart`: `EventEmitter`, `once` |
| Generators that return a value | `generators.dart` (see Conventions) |

## Rule 3: third-party packages

| Upstream | Dart |
|----------|------|
| `zod` schemas | Hand-written validators in the same file, same error messages |
| `commander` | `package:args`, same options and help text |
| `node-forge` | Pure Dart: `pointycastle` + `asn1lib`, no OpenSSL FFI |
| `@pondwader/socks5-server` | Open: port the parts used into `lib/src/node/socks5_server.dart` |
| `fast-check` | Open: a small property-test helper, or seeded random loops |
| `bun:test` | `package:test` |

## Rule 4: vendor

`vendor/seccomp-src`, `vendor/srt-win-src`, and `vendor/java-proxy-agent-src`
are copied unchanged. Their `build.ts` scripts become Dart under `tool/`.

## Conventions

Repeat these translation decisions for the rest of the port:

- **Node I/O keeps Node's call shape.** `net.connect`, `net.createConnection`
  and `tls.connect` return the socket at once, in the connecting state, as
  Node does. It emits 'connect' (TLS: then 'secureConnect'), or 'error' then
  'close'; writes made before then are queued. `server.listen` and
  `server.close` return the server; the result is a 'listening', 'error' or
  'close' event. So an upstream line such as
  `const s = netConnect({ port, host, lookup })` ports as one line, and the
  listeners that follow it port unchanged. Where upstream awaits a Promise
  built from those events, port the Promise as written (a `Completer`), or use
  `events.once(emitter, name)` where upstream does. Never `await` a connect
  or listen call, and never add a Dart-only `Future` variant.
- **Errors are Node's.** Socket errors are `NodeError` with Node's `code`
  (`ECONNREFUSED`, `EADDRINUSE`, `ENOENT`...), `syscall`, `address`, `port`
  and message text. Upstream checks such as `err.code === 'EADDRINUSE'` port
  as `err is NodeError && err.code == 'EADDRINUSE'`.
- **Every emitter extends `events.EventEmitter`.** It has Node's methods
  (`on`, `once`, `off`, `removeListener`, `emit`, `listenerCount`...). A
  listener gets as many of the emitted arguments as it accepts. An 'error'
  event with no listener is an uncaught error, which fails a test.
- **TLS on a socket you hold.** Upstream's
  `new TLSSocket(socket, { isServer: true, secureContext, ALPNProtocols })`
  ports as `TLSSocket(socket, {'isServer': true, ...})`. It returns at once
  and emits 'secure' or 'error'. Bytes put back with `socket.unshift(head)`
  before it start the handshake. Afterwards `socket` only closes with it:
  reading or writing it throws `StateError`. Node's internal
  `tls._secureEstablished` is `tls.secureEstablished`; `getPeerFinished`
  does not exist. `tls.servername` is null (see Known port gaps).
- **Bun branches.** `runsOnBun()` is false. Keep each `if (runsOnBun())`
  and port the Node side. A Bun-only body that needs a shim that does not
  exist (a hand-made `Duplex`, as in tls-terminate-proxy
  `duplexOverSocket`) becomes `throw UnimplementedError('Bun only')`, and
  the file status says which helpers are not ported.
- **Unsupported options throw.** `net.connect`, `tls.connect`,
  `net.createServer` and `server.listen` throw `UnimplementedError` for an
  option they do not handle (for example `listen({ fd })`). Add the option to
  the shim; never drop it in the ported file.

- **Option objects.** Flatten a TS final options object into Dart named
  parameters; keep arguments that are positional in TS positional in Dart.
  Example: TS `logForDebugging(message, options?: { level?: 'info' | 'error' |
  'warn' })` becomes `logForDebugging(message, {String? level})`.
- **Unions and literals.** A string-valued TS union stays a Dart `String` (or a
  `typedef` to `String`) when callers consume its literal spelling. Preserve
  the allowed values in comments and at runtime validation sites; do not turn
  serialized strings into Dart enums. Structural object types that are return
  values can become Dart records with named fields.
- **`undefined` and `null`.** TS optional values and `T | undefined` become
  nullable Dart values (`T?`) and use `null` for the absent case when the TS
  code only uses optional chaining or nullish/default checks. If upstream
  distinguishes an absent field from an explicit `null`, use a sentinel or a
  wrapper rather than collapsing the distinction.
- **Sync and async.** Keep synchronous Node `*Sync` calls synchronous in Dart;
  keep TS `Promise<T>` functions as `Future<T>`. Do not make an API async just
  because a Dart equivalent exists. EventEmitter-shaped boundaries use
  `Stream` subscriptions that are cancelled when the paired event wins, with
  the upstream promise represented as a `Future`.
- **Private names and constants.** Prefix unexported TS declarations with `_`.
  A private upstream `MAX_LINKS` therefore becomes `_MAX_LINKS`. Keep exported
  `SCREAMING_CASE` constants unchanged and add a file-local lint ignore rather
  than renaming the public declaration.
- **Tests.** `describe.skipIf(condition)` maps to `group(..., skip: condition ?
  reason : false)`; `describe.if(condition)` is the same with the inverse
  condition. A conditional assertion in a test body remains an early return,
  not a skipped test. Use Dart `test(..., skip: reason)` for an upstream case
  whose behavior cannot be run faithfully.
- **Test shape.** Keep each test body in upstream's shape, statement for
  statement. Do not factor bodies into new helpers: the file must diff
  against upstream. A body that cannot compile yet is kept as `//` lines of
  the upstream text, never left empty.
- **Test runner.** `dart_test.yaml` sets `concurrency: 1`: test files share
  one process, and several set the process-wide `Directory.current`.
- **Assertions in test declarations.** Bun permits `expect(...)` directly in a
  `describe` callback; `package:test` does not. Move the assertion into a
  `test` at the same position, titled for what it checks.
- **Property tests.** `fast-check` properties use deterministic, seeded
  `Random` loops with the upstream sample counts and bounds. Keep the test
  title and timeout. Generate only values representable by the downstream
  process API (shell arguments cannot contain NUL bytes).
- **Node `Buffer`.** Use `Uint8List` for Node byte buffers; keep byte-oriented
  work byte-oriented and use `utf8.decode` only where upstream explicitly
  converts a Buffer to text. Do not decode raw HTTP/header/protocol bytes early.
- **Node errors and APIs.** Import Node behavior from `lib/src/node/` rather
  than rebuilding it in a ported file. `NodeError` carries `code`, `syscall`,
  and `path`; its FFI operation captures errno before another native call can
  overwrite it. Use `NodeException` for generic Node `Error` stringification.
  Dart's RegExp omits Node's `d`-flag capture offsets; `node/regexp.dart`
  instruments capture prefixes and lookbehind spans, and renumbers numeric
  backreferences. Unsupported quantified captures and legacy octal escapes
  throw rather than guess. Tests cover duplicate text, lookbehind, nesting,
  escapes, named captures, and backreferences.
- **Unavailable Node APIs.** Until an HTTP/socket shim exists, an unimplemented
  Node API must throw `UnimplementedError` with the blocking hard spot rather
  than silently no-op (particularly for body gates and budget enforcement).
- **`process` overrides.** Import the shim as `process`; read its `platform`,
  `env`, and `cwd()` getters at the point of use. Tests that patch Node globals
  call `setPlatformForTesting`, `setEnvForTesting`, or `setCwdForTesting` and
  restore with `null` in `finally`.
- **`sandbox-config` types.** Each inferred object configuration type is an
  immutable Dart class with the upstream field names and `final` fields;
  optional fields use nullable types. The inline TLS-termination object is
  represented by `TlsTerminateConfig`. `FilesystemPathEntry` is a sealed
  union: `FilesystemPathSpelling(path)` is the string spelling branch and
  `FilesystemPathLiteral(path)` is `{path, literal: true}` (`literal` is
  always true). String-literal unions remain `String` typedefs with adjacent
  allowed-value constants. The hand-written validators expose
  `ConfigSchema<T>.safeParse(Object?)`, returning `success`, typed `data`, or
  `error.issues` with `message`, `path`, and `code`. `filterRequest` is a
  `FilterRequestCallback` (request_filter.dart): `fetch.Request` in,
  `Future<RequestDecision>` out.

### Comments

- Keep an upstream `/** ... */` block as it is where its text holds no `/*`.
  That diffs best against upstream.
- Dart block comments nest, so a block whose text holds `/*` (a glob such as
  `src/**`, or `/**/*.key`) never closes and breaks the whole file. Write such
  a block as `///` lines. Convert with a scanner that skips strings, never
  with a broad regex: one such regex once deleted code in sandbox_utils.dart.
- In a `///` comment, write a TS JSDoc escape such as `**\/` as `**/`, and
  `{@link X}` as `[X]` (dartdoc reports `{@link}` as an unknown directive).
  Inside a Dart `/** */` block, keep both as upstream has them.
- Comments inside test bodies stay too, at the same place in the body.

### Generators that return a value (`Steps<T>`)

TS `function*` generators that `return` a value and are composed with
`const x = yield* f()` (sandbox-utils `Steps<T>`, `finish`, `finishInTurns`)
cannot be Dart `async`, because upstream's `finish` runs them synchronously.
Dart `sync*` cannot return a value. So, decided by /root:

- `lib/src/node/generators.dart` (no upstream counterpart) defines
  `sealed class Step<T>`, `Pause<T>` (a TS `yield` / `yield undefined`) and
  `Done<T>(value)` (the TS `return value`), plus
  `Iterable<Step<R>> yieldStar<T, R>(Iterable<Step<T>> steps, Box<T> into)`,
  which re-yields each pause as `Pause<R>` and stores the `Done` value in
  `into`. `class Box<T> { late T value; }`.
- `sandbox_utils.dart` keeps upstream's declaration:
  `typedef Steps<T> = Iterable<Step<T>>;` and ports `finish`/`finishInTurns`
  to iterate until `Done`.
- Mapping, line for line:
  - `function* f(): Steps<T> {` → `Steps<T> f() sync* {`
  - `yield` → `yield Pause();`
  - `return v` → `yield Done(v); return;`
  - `const x = yield* g()` → `final x = Box<U>(); yield* yieldStar(g(), x);`
    then use `x.value` where upstream uses `x`.
- A `Steps` iterable must end with exactly one `Done`. `finish` throws
  `StateError` if it ends without one (fail closed).
- Plain value generators (`Generator<string>`, for example
  `properAncestors`) stay `Iterable<String> f() sync*`.

### Types for the remaining modules (decided 2026-10-13, wave 0 retry)

Shims are named for the Node module they stand for; a shim class whose
Node name clashes with dart:io gets a `Node` prefix (`NodeSocket`,
`NodeServer`, `NodeChildProcess`). Otherwise it keeps Node's name.

| Upstream type | Dart |
|---|---|
| `Readable`, `Writable`, `Duplex`, `Transform`, `PassThrough` (`node:stream`) | `lib/src/node/stream.dart`, same names, imported `as stream` |
| `Socket` (`node:net`) | `net.NodeSocket`; it will extend `stream.Duplex` (wave 1), so `Socket \| Duplex` is `stream.Duplex` |
| `Server` (`node:net`) / (`node:http`) | `net.NodeServer` / `http.NodeHttpServer` |
| `IncomingMessage` / `ServerResponse`, `ClientRequest` | `http.IncomingMessage` (will extend `stream.Readable`) / `http.ServerResponse`, `http.ClientRequest` (will extend `stream.Writable`) |
| `IncomingHttpHeaders`, `Agent` (`node:http`) | `http.IncomingHttpHeaders`, `http.Agent` |
| `node:https` `request`, `Agent` | `lib/src/node/https.dart` (wave 1) |
| `TLSSocket`, `SecureContext`, `TLSSocketOptions` | `tls.TLSSocket`, `tls.SecureContext`, options as `Map<String, Object?>` like `tls.connect` |
| `LookupFunction`, `BlockList` | `net.LookupFunction`, `net.BlockList` |
| `ChildProcess` | `child_process.NodeChildProcess` |
| `AbortSignal`, `AbortController` | `abort.dart` |
| Web `Request`, `Headers`, `ReadableStream<T>`, `ReadableStreamDefaultReader<T>` (globals) | `lib/src/node/fetch.dart`, same names, imported `as fetch` |
| `URL` (`node:url` or global) | `url.URL` in `lib/src/node/url.dart` (wave 1) |
| `console.warn/error/log` | `lib/src/node/console.dart`, imported `as console` |
| `Buffer` | `Uint8List` (Conventions: Node `Buffer`) |
| `@pondwader/socks5-server` | `lib/src/node/socks5_server.dart` (wave 1) |
| `X509Certificate`, `sign` (`node:crypto`), `node-forge` | `crypto.dart`, `forge.dart` |

Declarations:
- A TS `type`/`interface` of plain fields: a class with `final` fields and
  a `const` constructor of named parameters (as `MacOSSandboxParams`,
  `ResolvedAddressGuardOptions`). Optional field: nullable.
- A TS `interface` (or object type) with methods, implemented by object
  literals upstream: `abstract interface class` (as `MuxProxyServer`,
  `ResolvedAddressGuard`); an optional method (`m?(...)`) is a nullable
  function-typed field instead. The object literal becomes a private class
  implementing it.
- An exported object constant (`export const SandboxManager: ISandboxManager
  = { ... }`): `final ISandboxManager SandboxManager = _SandboxManager();`
  with the lint ignored per file.
- A union of object types: a sealed class with one subclass per branch,
  named `<Union><Branch>` (precedent: `FilesystemPathEntry`). A union of
  string literals: `String` (Conventions: Unions).
- `Promise<T> | T`: `FutureOr<T>`. `Record<string, T>`: `Map<String, T>`.
  `unknown`: `Object?`. `readonly T[]`: `List<T>`. TS `object`: `Object`.
- A union of a primitive and an object type (`string | WindowsBinShell`,
  `string | Buffer | Array<string | Buffer>`): `Object?` with the union in
  a comment; the body narrows it at runtime as upstream does.
- `Partial<T>`: a class `PartialT` with every field of `T`, all nullable,
  declared in the first file that needs it (`PartialSandboxRuntimeConfig`
  in sandbox_manager.dart).
- `export function*` returning `Steps<T>`: as Generators above.
- Optional positional parameters before a final options object: Dart cannot
  mix optional positional and named parameters, so they become named too
  (`readDenyGlob(..., {unlistableDirs, ...opts})`,
  `getWindowsSandboxCaCert({status, srtWin})`). With no options object,
  optional positionals stay positional (`[T? x]`).

Test spies. Upstream tests replace a module function with
`spyOn(module, 'name').mockImplementation(...)`. The Dart port does it by
making that function a top-level variable that holds the implementation:

```dart
/// Node's `fs.readdirSync`. A variable so a test can replace it, as
/// upstream's tests do with `spyOn(fs, 'readdirSync')`.
List<Dirent> Function(String path, {bool withFileTypes}) readdirSync =
    _readdirSync;
```

Callers are unchanged. A test saves it, assigns a closure, and restores it
in `finally` (or `addTearDown`); calls are counted in the closure. Spy
points exist for `fs.readdirSync`, `fs.realpathSync`, `fs.statSync`,
`console.warn`, `console.error`, `console.log`, `process.getuid` and
`which.whichSync`. A test needing another one: message /root (the files
are shared). `spyOn(platform, 'getPlatform')` stays
`process.setPlatformForTesting`.

### Worked example

Upstream `listenInRange(server, doListen, range, exclude)` returns a
`Promise<void>` and gets `undefined` for an unbounded range. The Dart port keeps
the four positional arguments, maps `Promise<void>` to `Future<void>`, maps
`undefined` to nullable `List<int>?` (`null` means listen once on port `0`),
and replaces paired EventEmitter one-shot callbacks with the
`NodeEventEmitter` Stream boundary in `lib/src/node/events.dart`.

## Known hard spots (decide before porting the file)

- `--control-fd` (cli.ts): do not use `posix_spawn`. Read an inherited fd with
  `File('/dev/fd/N')`; keeping it out of the sandboxed child is a small FFI
  `fcntl(fd, F_SETFD, FD_CLOEXEC)` shim in `lib/src/node/`. Verified on macOS:
  `dart:io` `Process.start` and `Process.run` children inherit every parent fd
  that does not have `FD_CLOEXEC` set. Later ports must not assume Dart closes
  arbitrary inherited descriptors.
- `http-proxy.ts`, `tls-terminate-proxy.ts`: depend on Node `http` details
  (`rawHeaders`, CONNECT `head`). `dart:io` lowercases headers. Likely needs a
  raw HTTP/1.1 parser shim.
- `emitted-connection.ts`: depends on Node's raw HTTP parser callbacks and
  emitted-socket lifecycle. `emitted-connection.dart` is partial until the
  HTTP/socket shim exists; unsupported entry points fail with
  `UnimplementedError` rather than fail open.
- `mitm-leaf.ts`: Node picks a certificate per SNI. Dart has no SNI callback.
  Read the SNI from the ClientHello, then `SecureSocket.secureServer` with
  `bufferedData`.

## Port order (by imports)

1. Leaves: utils/*, address, listen-in-range, sandbox-schemas, credential-extract.
2. sandbox-config, sandbox-utils, platform-dependent path helpers.
3. macOS, Linux, Windows utils; seccomp; ripgrep users.
4. Proxies, MITM, credentials.
5. sandbox-manager, index, cli, proxy-cli.

## Status

| Upstream file | Dart | Tests | Notes |
|---------------|------|-------|-------|
| `src/utils/shell-quote.ts` | `lib/src/utils/shell_quote.dart` | `test/utils/shell_quote_test.dart` | Ported; wrapper-builder test skipped because its macOS builder is outside this step |
| `src/utils/real-path.ts` | `lib/src/utils/real_path.dart` | `test/utils/real_path_test.dart` | Ported; POSIX FFI preserves errno and `stat` dev/inode identity; property test compares against the sibling upstream module when present |
| `src/sandbox/address.ts` | `lib/src/sandbox/address.dart` | — | Ported; no matching standalone upstream test file |
| `src/sandbox/listen-in-range.ts` | `lib/src/sandbox/listen_in_range.dart` | — | Ported; no matching upstream test file; Stream adapter is in `node/events.dart` |
| `src/utils/debug.ts` | `lib/src/utils/debug.dart` | — | Ported as a downstream dependency; no matching upstream test file |
| `src/utils/platform.ts` | `lib/src/utils/platform.dart` | `test/utils/platform_test.dart` | Ported |
| `src/utils/which.ts` | `lib/src/utils/which.dart` | `test/utils/which_test.dart`, `test/utils/which_node_test.dart` | Ported; 4 pass, 2 skipped (Bun-only); Node fallback script kept separate, as one test; Dart's synchronous process API has no spawn timeout |
| `src/utils/ripgrep.ts` | `lib/src/utils/ripgrep.dart` | `test/utils/ripgrep_test.dart` | Ported; real `rg` process; six tests pass on this host; POSIX argv0 uses Bash `exec -a`; Windows argv0 case skips because Dart cannot override argv[0] |
| `src/sandbox/sandbox-schemas.ts` | `lib/src/sandbox/sandbox_schemas.dart` | — | Ported; no matching standalone test file; six other sandbox tests import it (listed below) |
| `src/sandbox/credential-extract.ts` | `lib/src/sandbox/credential_extract.dart` | — | Ported; no matching standalone test file; direct extraction tests in `credential-mask-files.test.ts` remain queued; exact capture offsets use the instrumented RegExp shim |
| `src/sandbox/emitted-connection.ts` | `lib/src/sandbox/emitted_connection.dart` | — | **Partial:** HTTP/socket core is now available; no matching upstream test file; TLS termination wiring and byte-budget/runtime tests remain deferred; unsupported paths stay fail-closed |
| `src/sandbox/mux-proxy.ts` | `lib/src/sandbox/mux_proxy.dart` | `test/sandbox/mux_proxy_test.dart` | **Partial:** net/HTTP shim dependencies are now present; source port remains partial and all 8 direct tests still skip pending that port |
| `src/sandbox/aws-sigv4.ts` | `lib/src/sandbox/aws_sigv4.dart` | `test/sandbox/aws_sigv4_test.dart` | Ported; 38 pass, including all 22 official test-suite vectors |
| `src/sandbox/sandbox-config.ts` | `lib/src/sandbox/sandbox_config.dart` | `test/config_validation_test.dart` | Ported; 151 config-validation cases pass, with hand-written typed validators |
| `src/sandbox/domain-pattern.ts` | `lib/src/sandbox/domain_pattern.dart` | `test/sandbox/domain_pattern_test.dart` | Ported; all 16 direct tests pass |
| `src/sandbox/parent-proxy.ts` | `lib/src/sandbox/parent_proxy.dart` | — | **Partial:** `stripBrackets` and `canonicalizeHost` ported; the rest are stubs (wave 0) |
| `src/sandbox/request-filter.ts` | `lib/src/sandbox/request_filter.dart` | — | Stub (wave 0): full API |
| `src/sandbox/sandbox-utils.ts` | `lib/src/sandbox/sandbox_utils.dart` | `test/sandbox/{sandbox_env_tmpdir_test,glob_walk_property_test}.dart` | Ported; 6 direct tests pass; no one-to-one utility suite exists upstream; Node shims `os.dart`, `buffer.dart`, `fs.dart` |
| `src/sandbox/path-entries.ts` | `lib/src/sandbox/path_entries.dart` | — | Ported; `literal-path-entries.test.ts` waits on sandbox-manager and Linux/macOS wrapper modules |
| `src/sandbox/macos-sandbox-utils.ts` | `lib/src/sandbox/macos_sandbox_utils.dart` | `test/sandbox/{macos_allow_local_binding,macos_apple_events,macos_deny_grouping,macos_glob_deny_reemit,macos_literal_deny_brackets,macos_profile_size,macos_pty,macos_seatbelt,path_canonicalization,tls_terminate_trust_env,symlink_boundary}_test.dart` | Ported; 129 tests pass across the macOS suites, plus 2 credential-mask cases skipped pending `credential-mask-files.ts`; generated wrapper/profile compared byte-for-byte with upstream after normalizing only the random log suffix. Apple Events end-to-end cases depend on the host GUI probe. |
| `src/sandbox/java-proxy-agent.ts` | `lib/src/sandbox/java_proxy_agent.dart` | `test/sandbox/java_proxy_agent_test.dart` | Ported; 17 pass with a JDK and the jar (`dart run tool/build_java_proxy_agent.dart`), including the 7 JVM tests; the sandboxed-child case is pending `sandbox-manager.ts`. |
| `src/sandbox/generate-seccomp-filter.ts` | `lib/src/sandbox/generate_seccomp_filter.dart` | `test/sandbox/seccomp_filter_test.dart` | Ported; 3 binary tests pass on the Linux VM, 9 more keep upstream bodies pending `linux-sandbox-utils.ts`. `vendor/seccomp-src` copied unchanged; `tool/build_seccomp.dart` builds `apply-seccomp`, which refuses `socket(AF_UNIX)` on the VM. An AOT embedder passes `seccompBinaryPath` |
| `test/helpers/platform.ts` | `test/helpers/platform.dart` | — | Ported |
| `src/sandbox/sandbox-violation-store.ts` | `lib/src/sandbox/sandbox_violation_store.dart` | — | Ported; no one-to-one upstream test file; related assertions are in `command-text-registry.test.ts` |
| — (Node shims) | `lib/src/node/{errno,events,fs,os,child_process,http,net,process}.dart` | `test/node/{http,net}_test.dart` | No upstream counterparts; raw HTTP/1.1/socket subset with byte-preserving headers, body/trailer framing, CONNECT, server `upgrade`, keep-alive, and TCP/Unix listeners; focused tests pass |
| — (Node shim) | `lib/src/node/url.dart` | `test/node/url_test.dart` | WHATWG URL host parsing subset for `canonicalizeHost`; seven Node v22.16.0 golden tests pass; unsupported IDNA fails closed |
| — (Node shims) | `lib/src/node/{abort,emitted_http,regexp}.dart` | `test/node/{emitted_http,regexp}_test.dart` | No upstream counterparts; AbortSignal, emitted-connection adapter over raw HTTP/socket shim, and exact supported RegExp-with-indices instrumentation |
| — (Node shims) | `lib/src/node/{crypto,buffer}.dart` | — | No upstream counterparts; sha256 hash/HMAC for `aws-sigv4.ts`, Buffer helpers for `sandbox-utils.ts` |
| — (Node shims) | `lib/src/node/{forge,tls}.dart` | `test/node/{forge,tls}_test.dart` | Pure-Dart forge subset; Mozilla root bundle `2026-09-25` SHA-256 `a41b5d35…37d00505`; bounded ClientHello replay and ALPN; secure client HTTP uses the raw socket shim |
| `src/sandbox/linux-sandbox-utils.ts` | `lib/src/sandbox/linux_sandbox_utils.dart` | — | Stub (wave 0): full API |
| `src/sandbox/linux-violation-monitor.ts` | `lib/src/sandbox/linux_violation_monitor.dart` | — | Stub (wave 0): full API |
| `src/sandbox/read-deny-glob.ts` | `lib/src/sandbox/read_deny_glob.dart` | — | Stub (wave 0): full API |
| `src/sandbox/own-files.ts` | `lib/src/sandbox/own_files.dart` | — | Stub (wave 0): full API |
| `src/sandbox/sandbox-manager.ts` | `lib/src/sandbox/sandbox_manager.dart` | — | Stub (wave 0): full API |
| `src/utils/config-loader.ts` | `lib/src/utils/config_loader.dart` | — | Stub (wave 0): full API |
| `src/proxy-cli.ts` | `lib/src/proxy_cli.dart` | — | Stub (wave 0): full API |
| `src/sandbox/http-proxy.ts` | `lib/src/sandbox/http_proxy.dart` | — | Stub (wave 0): full API |
| `src/sandbox/proxy-only.ts` | `lib/src/sandbox/proxy_only.dart` | — | Stub (wave 0): full API |
| `src/sandbox/socks-proxy.ts` | `lib/src/sandbox/socks_proxy.dart` | — | Stub (wave 0): full API |
| `src/sandbox/tls-terminate-proxy.ts` | `lib/src/sandbox/tls_terminate_proxy.dart` | — | Stub (wave 0): full API |
| `src/sandbox/mitm-ca.ts` | `lib/src/sandbox/mitm_ca.dart` | — | Stub (wave 0): full API |
| `src/sandbox/mitm-leaf.ts` | `lib/src/sandbox/mitm_leaf.dart` | — | Stub (wave 0): full API |
| `src/sandbox/decider-client.ts` | `lib/src/sandbox/decider_client.dart` | — | Stub (wave 0): full API |
| `src/sandbox/body-substitution.ts` | `lib/src/sandbox/body_substitution.dart` | — | Stub (wave 0): full API |
| `src/sandbox/credential-sentinel.ts` | `lib/src/sandbox/credential_sentinel.dart` | — | Stub (wave 0): full API |
| `src/sandbox/credential-decode.ts` | `lib/src/sandbox/credential_decode.dart` | — | Stub (wave 0): full API |
| `src/sandbox/credential-mask-env.ts` | `lib/src/sandbox/credential_mask_env.dart` | — | Stub (wave 0): full API |
| `src/sandbox/credential-mask-files.ts` | `lib/src/sandbox/credential_mask_files.dart` | — | Stub (wave 0): full API |
| `src/sandbox/credential-aws-pairs.ts` | `lib/src/sandbox/credential_aws_pairs.dart` | — | Stub (wave 0): full API |
| `src/sandbox/windows-sandbox-utils.ts` | `lib/src/sandbox/windows_sandbox_utils.dart` | — | Stub (wave 0): full API; permanent (Windows not ported), bodies throw UnsupportedError |

### Known port gaps

- `node/tls.dart` `connect`: dart:io checks the server name itself during the
  handshake and does not say which check failed. A custom
  `checkServerIdentity` that would accept a name dart:io rejects gets an
  untrusted-chain error instead. Upstream's only custom check
  (tls-terminate-proxy) pins the name more strictly, so it is not affected.
- `node/tls.dart` server `TLSSocket`: dart:io cannot abort a server
  handshake. `destroy()` during one closes both sockets at once, but the
  connection stays open until the handshake ends, which a silent client can
  put off until it closes. dart:io also does not report the server name, so
  `servername` is null; upstream reads it from the ClientHello anyway.
- `node/tls.dart` `TLSSocket` runs only over a `net.Socket`, on the server
  side. No `Duplex` shim exists. `proxy-only.ts` `listen({ fd })` is
  unsupported.
- `node/net.dart` reads: dart:io reads all the kernel holds at once, so a
  socket nobody reads can hold more than `highWaterMark` before it stops.
  A flowing socket with no 'data' listener keeps its bytes for `read()`,
  where Node drops them (the http shim relies on this).
- `node/net.dart` `bytesWritten` on a socket under a TLS socket counts only
  what was written before the TLS socket took over.
- `node/net.dart` `unref()` records state only: Dart cannot let an open
  socket stop holding the process open.

- `which.ts`: Dart's synchronous `Process.runSync` has no `spawnSync` timeout;
  the upstream one-second timeout cannot be reproduced synchronously.
- `emitted-connection.ts`: HTTP/socket parser and event adapters now exist;
  full TLS tunnel wiring and runtime/body-budget integration remain deferred.
- `mux-proxy.ts`: raw net stream/server and HTTP shim dependencies are present;
  inherited-FD listener support and the source port/test suite remain pending.
- TLS: malformed, oversized, or timed-out ClientHello inspection throws and
  destroys the raw socket; no-SNI is returned explicitly for caller policy.
  Unsupported forge extensions, non-RSA PEM keys, and signing algorithms throw
  rather than guessing. `checkServerIdentity` returns a mismatch error. Complex
  multi-valued user-CA RDNs are normalized when re-encoded for CRLs, matching
  node-forge's documented limitation.
- WHATWG URL host parsing: `node/url.dart` supports ASCII, IPv4 inet_aton
  forms, IPv6, percent decoding, Latin-1 Punycode, fullwidth ASCII and mapped
  dot separators. Full UTS-46/NFC IDNA behavior is not implemented; unsupported
  Unicode throws so `canonicalizeHost` returns null rather than guessing.
- `sandbox-utils.ts`: `os.homedir()`'s native passwd-database fallback is not
  available through Dart; the shim throws if HOME/USERPROFILE is absent. Dart
  also cannot create a `TypeError` carrying Node's custom message, so marked
  literal and invalid-anchor failures use `ArgumentError`.
- macOS wrapper test helpers use `dart:io` process boundaries; synchronous
  `Process.runSync` has no timeout option where the upstream `spawnSync` tests
  specify one. The PTY and profile-size suites retain explicit async deadlines.

### Related upstream tests not ported in this batch

These exercise the listed modules but belong to other source/test files, so
they stay queued for those files' port steps (per the one-file test rule):

- `credential-extract.ts`: `test/sandbox/credential-mask-files.test.ts`.
- `sandbox-schemas.ts`: `test/sandbox/{allow-read,read-list-precedence}.test.ts`.
- `sandbox-violation-store.ts`: sanitizer/store cases in `test/sandbox/command-text-registry.test.ts` (not a one-to-one test file).
- `mux-proxy.ts`: `test/sandbox/{mux-proxy-e2e,request-rewriting}.test.ts`.
- `aws-sigv4.ts`: `test/sandbox/{credential-aws-pairs,credential-mask-sigv4}.test.ts`.
- `emitted-connection.ts`: direct tests in `test/sandbox/{byte-budget,tls-terminate-runtime,tls-terminate-upload-gate,tls-terminate-relay-budget}.test.ts`; its helper `test/helpers/emitted-connections.ts` is used by `test/proxy-cli.test.ts` and `test/sandbox/{canonical-host-routing,client-abort,connect-non-tls,credential-mask-body,credential-mask-sigv4,deny-late-body,invalid-upstream-response,proxy-only-edges,proxy-only,request-filter,request-rewriting,request-target-forwarding,resolved-address-guard,response-header-bytes,tls-terminate-handshake-deadline,tls-terminate-in-process,tls-terminate-keepalive,tls-terminate-proxy,trailers-then-request}.test.ts`.
- `linux-sandbox-utils.ts`: 9 cases of `test/sandbox/seccomp-filter.test.ts` (ported, skipped) and the Linux backend case of `path-canonicalization.test.ts`.
- `sandbox-config.ts`: `test/config-validation.test.ts` is the one-to-one suite ported with this file. The other direct schema/type consumers belong to their own source/test steps and remain queued: `test/configurable-proxy-ports.test.ts`, `test/public-exports.test.ts`, and `test/sandbox/{brackets-that-spell-no-set,credential-aws-pairs,credential-deny,credential-mask-files,credential-mask-sigv4,credential-mask,filesystem-disabled,glob-expand,integration,literal-path-entries,mux-proxy-e2e,names-with-a-backslash,own-files,proxy-env-vars,read-list-precedence,request-rewriting,resolved-address-guard,tls-terminate-runtime,update-config,winsrt,wrap-with-sandbox}.test.ts`.
- `path-entries.ts`: `test/sandbox/literal-path-entries.test.ts` waits on `sandbox-manager.ts`, `linux-sandbox-utils.ts`, `linux-violation-monitor.ts`, and its platform/bwrap/config-loader helpers.

The upstream `src` and `test` grep for `maskedFileBinds` and
`NetworkHostPattern` found reads and object construction only; no code mutates
`realPath`, `fakePath`, `host`, or `port` fields. The existing named records
remain appropriate for those nested object shapes.
