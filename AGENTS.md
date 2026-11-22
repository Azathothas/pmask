# pmask: repository guide

`pmask` redacts `/proc` metadata (`cmdline`, `environ`, `comm`) for a Linux process tree while each program keeps its real `argv` and `envp`.
`pmask` provides process-level confidential execution on hosts without a TEE or hypervisor.
The repository builds three interfaces: a Rust library, a CLI (`pmask`), and a daemon (`pmaskd`).

## Map

| path | role |
|---|---|
| `src/mask.rs` | public session API: `Mask` builder, `Prepared`, `MaskedChild`, fork plumbing |
| `src/tracer.rs` | tracee table, exec lifecycle, seizer/waiter loop, session-end policies, counters |
| `src/execimg.rs` | exec-entry swap, exec-completion rebuild, presentation block placement, window relocation |
| `src/presetmm.rs` | `prctl(PR_SET_MM, PR_SET_MM_MAP)`: read `/proc/<pid>/stat`, encode the struct, rewrite `AT_EXECFN` |
| `src/inject.rs`, `src/remote.rs` | syscall-site discovery, remote syscall injection, tracee memory access |
| `src/arch.rs` | x86-64, aarch64, and i386 register layouts and syscall numbers |
| `src/selfmask.rs` | supervisor metadata redaction and argv restoration |
| `src/seccomp.rs` | opt-in seccomp filters for `--watch-rename` and `--exec-once` |
| `src/rexec.rs` | program images for `--rexec`: sealed memfd, hugetlb, temporary file, `--exec-once` cache |
| `src/crypto.rs` | per-session XChaCha20-Poly1305 sealing and `memfd_secret` key storage for `--encrypt-memory` |
| `src/testhooks.rs` | test-only `PMASK_FAULT_*` and `PMASK_PROBE_*` switches behind `--features test-hooks` |
| `src/userns.rs`, `src/isolate.rs` | namespaces for `--unshare` and `--isolate` |
| `src/scope.rs` | transient systemd scope prefix |
| `src/daemon.rs` | `pmaskd` protocol, server, client, env-file parser |
| `src/mem.rs` | locked, wipe-on-drop buffers (`mlock`, `MADV_DONTDUMP`, `PR_SET_DUMPABLE`) |
| `src/secret.rs` | secret sources (`file:`, `env:`, `agent:`, `stdin`, `literal:`) and descriptor delivery |
| `src/store.rs` | encrypted secret store (Argon2id, XChaCha20-Poly1305, mode 0600 file) |
| `src/lease.rs` | leases: TTL, use count, revocation, idle lock, hash-chained audit |
| `src/agent.rs` | secret agent: holds the unlocked store in one process and answers over a socket |
| `src/subcmd.rs` | `store`, `agent`, `get`, `read`, `probe`, `doctor` |
| `src/caps.rs` | host capability probes, one row per mechanism |
| `src/run.rs` | mode selection: redaction, secret delivery, isolation |
| `src/cli.rs`, `src/main.rs` | `pmask` CLI (local and `--daemon` client modes) |
| `src/bin/pmaskd.rs` | `pmaskd` argument parsing and startup |
| `src/bin/testcases.rs`, `src/bin/tc/*.rs` | probe dispatcher and probe subcommands |
| `src/bin/protocases.rs` | raw protocol client for the daemon negative suite |
| `tests/` | test suites (`tests/run.sh` is the native gate) |
| `tests/qa.sh`, `tests/qa.d/` | QA dispatcher and numbered fragments, one per closed issue |
| `scripts/` | CI guards (rename, completions, notices, static link, artefacts) and `verify.sh` |
| `vm/` | QEMU micro-VM harness (`run.sh`), shared helpers (`common.sh`), debug runner (`debug.sh`) |
| `measurements/` | speed and zapper comparison harnesses and one-off probes |
| `evidence/` | raw measurement logs by batch (`evidence/stealth/` holds detection-audit re-measurements) |
| `docs/` | design, threat model, deployment, integration, audits, research, release notes |
| `docs/COMMENT-AUDIT.md`, `docs/ISSUE-CLOSURE.md` | corrected source comments and per-issue fix, test, and evidence records |
| `docs/DETECTION-AUDIT.md`, `docs/REDTEAM-RESULTS.md` | detection-audit and red-team findings with fixes and evidence |
| `docs/INTEGRATION.md` | binary and library contract, feature flags, and packaging guide |
| `man/`, `completions/` | manual pages and shell completions |
| `contrib/` | systemd units, `tmpfiles.d`, and `sysusers.d` (excluded from the crate) |
| `fuzz/` | store header parser fuzz target |

## Invariants

1. **Tracer thread equals forking thread.** `PTRACE_SEIZE` binds the child to the thread that forked it. Ptrace calls from any other thread return `ESRCH`. `Mask::spawn_prepared` forks inside the tracer thread on purpose. Do not collapse this into a shared loop.
2. **Session serialization.** One session owns the calling process's `waitpid(-1)` domain. `SESSION: Mutex<()>` serializes sessions in one process. `pmaskd` runs one job at a time unless `--jobs N` gives each job a worker process.
3. **Strict guards on opt-in seccomp filters.** An unserviced `RET_TRACE` stop makes trapped syscalls return `ENOSYS` in an unsupervised descendant. `pmask` installs no default exec filter and guards its two opt-in filters tightly:
   - `--exec-once` installs an `execve`/`execveat` watch filter only when `PTRACE_O_EXITKILL` is active and `--on-exit` is not `detach`. Otherwise the tracee stays syscall-supervised.
   - `--watch-rename` traps `prctl(PR_SET_NAME)` plus `open`, `openat`, `openat2`, and `creat` (and write syscalls under `--watch-rename=strict`). `pmask` refuses `--watch-rename` with `--detach` or `--on-exit detach` in both the CLI and the library API.
4. **Zero-exposure redaction on first exec.** `pmask` swaps pointers at the true syscall-entry stop for every process's first native ELF exec. Scripts (`#!`), `vfork` children, and settled re-execs take the post-exec path unless `--strict-exec` refuses them. `pmask` refuses 32-bit images before execution unless `--allow-foreign` is set. Every new spawn path must choose its path explicitly.
5. **Tracee state machine.** Transitions follow `Slow -> (entry swap) -> Swapped -> (completion) -> Run`, with `Script` and `Foreign` as the other entry outcomes. Failed execs restore the original inline arrays and return to `Slow`. Non-`Run` states stay syscall-supervised (`PTRACE_SYSCALL`). Every error path must leave a tracee resumed or dead, never stopped and forgotten. Route every resume through `Tracer::resume`.
6. **Exit semantics.** `pmask` passes the supervised master's exit status through untouched in local and daemon modes. When a signal kills the master, `pmask` re-raises that signal. The session-end policy (`detach` default, `wait`, or `kill`) governs remaining descendants.
7. **0BSD license and minimal dependencies.** The redaction engine depends only on `libc`. The secret subsystem adds `zeroize`, `argon2`, and `chacha20poly1305`. Do not add another dependency without a recorded decision. Static musl builds must keep working because `vm/run.sh` depends on them.
8. **Exact argv byte forwarding.** The CLI parses `args_os()`, not `args()`. Non-UTF-8 arguments must reach the supervised program unchanged. Only the presentation label decodes text lossily.
9. **Tracee-relative path resolution.** ELF detection and `--exec-once` open `/proc/<pid>/cwd/<path>` for relative paths and `/proc/<pid>/root<path>` for absolute paths. Path helpers rewrite `/proc/self/` and `/proc/thread-self/` to `/proc/<pid>/`. After a `chdir()` inside the tree, tracer and tracee cwds differ.
10. **POSIX `sh` scripts.** `vm/*.sh` and `tests/*.sh` must use POSIX `sh` only. Do not use brace expansion, `[[`, or `local`. Debian and Ubuntu run `/bin/sh` as `dash`, and the micro-VM runs busybox `ash`.
11. **`SO_PEERCRED` daemon authorization.** `pmaskd` accepts its own uid and root by default, and widens access only via `--allow-uid`. The socket uses mode 0600 by default, and the client verifies the server's peer uid. `pmaskd` pins the accepted peer with a `SO_PEERPIDFD` pidfd when available, or `/proc` pid and start time otherwise, and fails closed if neither succeeds. Never accept a request before verifying peer identity.
12. **Supervisor `/proc` hygiene.** `pmask` copies its argv, zeroes the kernel-served argv block, and only then parses options and forks. Non-plain modes zeroize `original_argv` right after the plain-mode check. `pmaskd` hardens itself before loading `--env-file`, builds the job environment, and masks itself. Do not reorder these steps.
13. **Visible degradation.** Emit a stderr warning at default verbosity and increment a summary counter on every fallback or failure. Silent fallbacks are defects.
14. **Test-only fault and probe hooks.** All `PMASK_FAULT_*` and `PMASK_PROBE_*` hooks live behind `--features test-hooks` (`src/testhooks.rs`) and compile out of release builds. Fault hooks: `PMASK_FAULT_POKE`, `PMASK_FAULT_NOVDSO`, `PMASK_FAULT_REFUSE_MAP`, `PMASK_FAULT_NOWINDOW`, `PMASK_FAULT_CLOSE`, `PMASK_FAULT_REXEC_FAIL`, `PMASK_FAULT_REXEC_DISK`, `PMASK_FAULT_REXEC_NO_PROC`, `PMASK_FAULT_PEERPIDFD`, and `PMASK_FAULT_WATCH`. Probe hooks: `PMASK_PROBE_AUDIT`, `PMASK_PROBE_LANDLOCK_ABI`, `PMASK_PROBE_MEMFD_SECRET`, `PMASK_PROBE_MEMLOCK`, `PMASK_PROBE_PEERPIDFD`, `PMASK_PROBE_PROC_HIDDEN`, `PMASK_PROBE_PTRACE`, and `PMASK_PROBE_USERNS`.

## Build and verify

```sh
cargo build --locked --release                       # pmask and pmaskd
cargo build --locked --release --bins --features testbins  # also the probes
cargo clippy --all-targets -- -D warnings            # zero-warning policy
cargo fmt --all -- --check                           # formatting
cargo test --locked --lib                            # ptrace-free unit tests
sh scripts/check-rename.sh                           # the retired project name
sh scripts/check-completions.sh                      # completion tables against the parser
python3 scripts/notices.py --check                   # THIRD_PARTY_NOTICES.md is current
mandoc -T lint -W error man/pmask.1 man/pmaskd.8     # man pages
sh tests/run.sh                                      # native gate (needs ptrace)
sh vm/run.sh                                         # micro-VM gate (works anywhere)
```

`scripts/verify.sh` runs the build, lints, guards, and `tests/run.sh`.
`scripts/verify.sh --vm` adds `vm/run.sh`.

`tests/run.sh` requires a host that permits ptrace with `kernel.yama.ptrace_scope` set to `0`.
Many sandboxes and dev containers block ptrace with seccomp.
Use `vm/run.sh` as the canonical gate in those environments.
`vm/run.sh` boots a pinned kernel and a static busybox initramfs under QEMU.
The micro-VM runs the staged suites twice (root and uid 1000) and exits 0 only when both passes report `FINAL: ALL-PASS`.

Every detection suite follows four verification steps:

1. Run the workload without `pmask` and confirm the observer detects the markers (negative control).
2. Run the workload under `pmask` and require zero sightings.
3. Verify the masked processes stay alive under the label (liveness check).
4. Verify stdio, exit codes, argv and env fidelity, and signal delivery.

Undecidable test cases print `SKIP <name> (<reason>)` instead of `PASS`.

## Conventions

- Write commits with an imperative subject line and explain the reason in the body.
- Keep the retired project name out of the tree. `scripts/check-rename.sh` enforces this rule, allowing only release notes that describe the rename.
- Keep the repository lean. Place new documentation under `docs/` and link each file from `docs/README.md`. Place release notes in `docs/releases/`.
- Place every host-behavior claim next to its measurement. Include kernel version, uid, capability set, and exact command with every number.
- The release workflow builds static musl binaries for x86-64 and ARM64, checksums them, attests them, and marks tags containing `-` as prereleases. `docs/releases/<tag>.md` must exist and contain the exact heading `## Breaking`.
