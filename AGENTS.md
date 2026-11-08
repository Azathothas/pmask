# pmask: repository guide

`pmask` redacts the `/proc` metadata (cmdline, environ, comm) of an
entire Linux process tree while every program keeps its real
`argv`/`envp`. It is confidential execution at the process level, for
machines with no TEE and no hypervisor. Three faces: a library, a CLI
(`pmask`) and a daemon (`pmaskd`).

## Map

| path | role |
|---|---|
| `src/mask.rs` | public session API: `Mask` builder, `Prepared`, `MaskedChild`, fork plumbing |
| `src/tracer.rs` | tracee table, exec lifecycle, seizer/waiter loop, session end policies, counters |
| `src/execimg.rs` | exec-entry swap, exec-completion rebuild, redaction block placement, window relocation |
| `src/presetmm.rs` | `prctl(PR_SET_MM, PR_SET_MM_MAP)`: reading `/proc/<pid>/stat`, encoding the struct, rewriting `AT_EXECFN` |
| `src/inject.rs`, `src/remote.rs` | syscall-site discovery, remote syscall injection, tracee memory access |
| `src/arch.rs` | x86-64, aarch64 and i386 register layouts and syscall numbers |
| `src/selfmask.rs` | the supervisor's own metadata treatment |
| `src/seccomp.rs` | the opt-in `prctl(PR_SET_NAME)` watch filter |
| `src/rexec.rs` | program images for `--rexec`: sealed memfd, hugetlb, temporary file, `--exec-once` cache |
| `src/userns.rs`, `src/isolate.rs` | namespaces for `--unshare` and `--isolate` |
| `src/scope.rs` | the transient systemd scope prefix |
| `src/daemon.rs` | `pmaskd` protocol, server, client, env-file parser |
| `src/mem.rs` | locked, wipe-on-drop buffers (`mlock`, `MADV_DONTDUMP`, `PR_SET_DUMPABLE`) |
| `src/secret.rs` | secret sources (`file:`, `env:`, `agent:`, `stdin`, `literal:`) and descriptor delivery |
| `src/store.rs` | the encrypted secret store (Argon2id, ChaCha20-Poly1305, 0600 file) |
| `src/lease.rs` | leases: TTL and use count, revocation, the idle lock, the hash-chained audit |
| `src/agent.rs` | the secret agent: one process holds the unlocked store and answers over a socket |
| `src/subcmd.rs` | `store`, `agent`, `get`, `read`, `probe`, `doctor` |
| `src/caps.rs` | what this host allows, one row per mechanism |
| `src/run.rs` | mode selection: redaction, secret delivery, isolation |
| `src/cli.rs`, `src/main.rs` | `pmask` (local and `--daemon` client modes) |
| `src/bin/pmaskd.rs` | `pmaskd` argument parsing and startup |
| `src/bin/testcases.rs`, `src/bin/tc/*.rs` | probe dispatcher and probe subcommands |
| `src/bin/protocases.rs` | raw protocol client for the daemon negative suite |
| `tests/` | the suites; `run.sh` is the native gate |
| `vm/` | QEMU micro-VM harness (`run.sh`), shared parts (`common.sh`), debug runner (`debug.sh`) |
| `measurements/` | speed and zapper comparison harnesses, and the one-off probes |
| `docs/` | design, threat model, deployment, research, release notes |
| `man/`, `completions/` | manual pages and shell completions |
| `contrib/` | systemd units, `tmpfiles.d` and `sysusers.d`, excluded from the crate |
| `fuzz/` | the store header parser target |

## Invariants

1. **Tracer thread = forking thread.** `PTRACE_SEIZE` binds the child to
   the *thread* that forked it; ptrace ops from any other thread of the
   tracer return `ESRCH`. `Mask::spawn_prepared` forks inside the tracer
   thread on purpose. Do not "simplify" this into a shared loop.
2. **Session serialization.** A session owns the calling process's
   `waitpid(-1)` domain; sessions are serialized through
   `SESSION: Mutex<()>`. No concurrent sessions in one process. The
   daemon runs one job at a time unless `--jobs N` gives each job a
   worker process.
3. **No exec-shaped seccomp filter.** An unserviced `RET_TRACE` stop
   makes `execve` return `ENOSYS` in a descendant that is not being
   supervised; that is measured and it is why the filter stays out. The
   only filter in the tree matches `prctl(PR_SET_NAME)` and is opt-in
   (`--watch-rename`).
4. **Zero-exposure redaction for every process's first exec** (swap at
   the true syscall-entry stop). Scripts (`#!`), a `vfork` child, re-execs
   of a settled process and 32-bit images take the post-exec path; a
   32-bit image is refused loudly and not redacted. Any new spawn path
   must pick one of these explicitly.
5. **State machine**: `Slow → (entry swap) → Swapped → (completion) →
   Run`, with `Script` and `Foreign` as the other entry outcomes and
   failed execs restoring the original inline arrays and settling to
   `Slow`. Every error path must leave a resumed-or-dead tracee behind,
   never a stopped-and-forgotten one; every resume goes through
   `Tracer::resume`.
6. **Exit semantics**: the supervised master's exit status (including
   signal deaths, re-raised by the CLI) passes through untouched, in
   local mode and through the daemon. What happens to the rest of the
   tree is the session-end policy (`detach` default, `wait`, `kill`).
7. **0BSD, few dependencies.** The redaction engine needs only `libc`;
   the secret side adds `zeroize`, `argon2` and `chacha20poly1305`. No
   other dependency without a recorded decision. Static musl builds must
   keep working (`vm/run.sh` depends on it).
8. **argv bytes are forwarded exactly.** The CLI parses `args_os()`, not
   `args()`: a non-UTF-8 argument must reach the supervised program
   unchanged. Only the *label* is decoded as text, lossily.
9. **Paths are resolved against the tracee, not the tracer.** ELF
   detection opens `/proc/<pid>/cwd/<path>` (relative) or
   `/proc/<pid>/root<path>` (absolute). After a `chdir()` inside the
   tree the two cwds differ, and opening the tracer's copy silently
   drops the zero-exposure path.
10. **`vm/*.sh` and `tests/*.sh` are POSIX sh.** No brace expansion, no
    `[[`, no `local`: `/bin/sh` is dash on Debian/Ubuntu and busybox ash
    in the VM, where brace expansion creates one literal directory and
    the gate fails before boot.
11. **The daemon's authorisation is `SO_PEERCRED`.** Own uid and root by
    default, `--allow-uid` to widen, socket mode 0600, and the client
    checks the peer uid of the socket it connected to. The identity
    established at `accept` is pinned: a pidfd from `SO_PEERPIDFD` where
    the kernel offers one, otherwise the peer's pid and start time from
    `/proc`, which is best effort. Never accept a request before checking
    it.
12. **Secrets never enter the supervisor's own `/proc`.** `pmask` copies
    its argv, zeroes the kernel-served block, and only then parses
    options and forks; `pmaskd` builds the job environment, then masks
    itself. Do not reorder either.
13. **Every degradation is visible.** A warning at the default verbosity
    plus a count in the session summary. A silent fallback is a defect,
    not a graceful path.
14. **Fault hooks stay test-only.** `PMASK_FAULT_POKE`,
    `PMASK_FAULT_NOVDSO`, `PMASK_FAULT_REFUSE_MAP`,
    `PMASK_FAULT_NOWINDOW`, `PMASK_FAULT_CLOSE`,
    `PMASK_FAULT_REXEC_FAIL`, `PMASK_FAULT_REXEC_DISK`,
    `PMASK_FAULT_REXEC_NO_PROC`, `PMASK_FAULT_PEERPIDFD` and
    `PMASK_FAULT_WATCH` are read once, so the suites can drive the
    failure paths. They change no production behaviour.

## Build and verify

```sh
cargo build --locked --release                       # pmask and pmaskd
cargo build --locked --release --bins --features testbins  # also the probes
cargo clippy --all-targets -- -D warnings            # zero-warning policy
cargo fmt --all -- --check                           # formatting
cargo test --locked --lib                            # ptrace-free unit tests
sh tests/run.sh                                      # native gate (needs ptrace)
sh vm/run.sh                                         # micro-VM gate (works anywhere)
```

`tests/run.sh` needs a host where ptrace is permitted and
`kernel.yama.ptrace_scope` is 0. Many sandboxes, including the usual dev
container, seccomp-ban ptrace entirely; `vm/run.sh` exists for exactly
that case and is the canonical gate. It boots a pinned kernel and a
static busybox initramfs under QEMU, runs the staged suites twice (root
and uid 1000), and exits 0 only when both passes report
`FINAL: ALL-PASS`.

Suite design (why a pass means something): every detection suite runs its
battery *without* `pmask` first and requires the observer to detect the
markers (negative control), then requires zero sightings under the mask,
then requires the processes to be *alive* under the label (liveness, so
"zero sightings" cannot be vacuous), then checks function (stdio, exit
codes, argv/env fidelity, signals). A case that cannot be decided prints
`SKIP <name> (<reason>)`, never a pass.

## Conventions

- Commits: plain imperative subject, reason in the body.
- The old project name must not appear in the tree. `scripts/check-rename.sh`
  enforces it; the only allowed exception is the release notes that
  describe the rename.
- Keep the repo lean. New docs go under `docs/` and are linked from
  `docs/README.md`. Release notes live in `docs/releases/`.
- A claim about what a host does goes next to the measurement. A number
  carries its kernel, uid, capability set and command.
- The release workflow builds x86-64 and ARM64 static musl binaries,
  checksums them, attests them, and publishes a prerelease for a tag with
  a suffix. `docs/releases/<tag>.md` must exist and contain `## Breaking`.
