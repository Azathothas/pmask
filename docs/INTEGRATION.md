# Integrating pmask

This guide explains how to run a payload under `pmask` or reuse its memory-hygiene components. It defines the binary contract, the library contract, feature flags, and packaging limits.

## Use the binary, not the library, for a supervisor

The `pmask` library owns the calling process's `waitpid(-1)` domain and holds a process-wide session lock. That design fits a dedicated launcher, not a process that already reaps its own children (such as a service manager running a `waitid(P_PIDFD)` loop). A project with its own child reaper must launch the `pmask` binary as a separate process.

### Binary contract

- Invoke `pmask -q --label LABEL [options] -- COMMAND [ARGS...]`.
- `pmask` returns the payload's exit status. If the payload dies from a signal, `pmask` re-raises that signal so the caller sees `128 + signal`.
- Exit code `255` indicates a `pmask` usage error or policy refusal. Because a payload can also exit `255`, inspect the `pmask: ` stderr prefix or check whether `--report-file` was written.
- On the local mask path, `pmask` forwards `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGTERM`, `SIGUSR1`, `SIGUSR2`, and `SIGWINCH` to the payload. Runner-path runs (`--secret`, `--isolate`, `--no-redact`, `--hide-pid`, `--encrypt-memory`, or report-only runs) do not install this signal proxy. If `pmask` dies, `PTRACE_O_EXITKILL` kills the tree instead. Send signals directly to the payload pid when direct delivery is required.
- Pass `--on-exit kill` from a service manager so descendants cannot outlive the session. The default `detach` policy leaves surviving descendants running untraced.
- Pass `--report-file PATH` or `--report-fd N` to write one JSON object after the payload exits. Every local path produces a report. `--daemon` jobs refuse reports (exit `255`). Avoid `--report=json` when fd 1 carries job logs, because the payload shares stdout.
- Pass `--args-from-fd N` to keep command-line arguments out of the supervisor's `argv`. Pass `--secret NAME=file:PATH` or `agent:NAME` to deliver secrets over sealed descriptors. `literal:` and `env:` put values in plain sight, trigger a warning, and are refused in non-redacting modes unless `--allow-argv-secret` is set.
- Run `pmask probe` for a capability preflight. Run `pmask doctor --require=redact,exact` to exit `0` (active), `3` (degraded), or `4` (unavailable). Hosts that block `ptrace` fall back to `mode=plain`, delivering secrets without redacting `/proc`.
- `--strict-exec` refuses exec shapes that cannot be redacted at syscall entry: `#!` scripts, `vfork` children, entry-redaction fallbacks, and settled re-execs. It also refuses `--detach`. Refused execs die with `SIGKILL` (exit `137`) and print `pmask: refused:` even under `-q`.
- `--hide-pid` requires `/proc` mounted with `hidepid=invisible` or `hidepid=ptraceable` and refuses weaker mounts. On `hidepid=ptraceable`, an existing dentry returns `EPERM`, distinguishing a hidden pid from a missing one. `cgroup.procs`, `cgroup.threads`, `kill(0)`, `pidfd_open`, `getpriority`, `sched_getaffinity`, `prlimit`, and root still see the pid. Because the tracer re-injects `PR_SET_DUMPABLE=0` at every traced exec, `--hide-pid` refuses `--no-follow`, `--detach`, and `--exec-once`. Descendants detached by `--on-exit detach` stay hidden only until their next exec resets `PR_SET_DUMPABLE`.
- `--encrypt-memory` encrypts the supervisor's at-rest `argv` and `environ` copies with XChaCha20-Poly1305 under a per-session key in `memfd_secret` memory when available (falling back to `mlock`-protected heap and reporting the tier). The payload's separate redaction block stays anonymous and `MADV_DONTDUMP` on every host to avoid a `/secretmem` VMA fingerprint. Payload heap and stack remain unencrypted.
- `--no-dumpable`, `--hide-pid`, and default `--secret` sessions in redaction mode make `/proc/<pid>/mem` unreadable to same-uid readers. Do not combine them with a same-uid tool that must inspect `/proc/<pid>/mem` (such as a seccomp user-notification handler).
- `--isolate` creates namespaces only and does not redact `/proc`. Combine `--redact --isolate=LIST` for both.
- `--exec-once` with `--on-exit wait` or `--on-exit kill` (and without `--no-exit-kill`) installs a seccomp filter trapping only `execve`/`execveat` so the tracee runs freely between execs. With `--on-exit detach`, the tracee remains syscall-supervised so detached survivors never hit an unserviced filter. `--exec-once --detach` warns that the cache is unused after the first exec. `--exec-once` is refused with `--no-dumpable`, `--hide-pid`, `--stealth` (on non-`hidepid` hosts), and default non-dumpable `--secret` sessions.
- `--watch-rename` traps `prctl(PR_SET_NAME)` plus `open`/`openat`/`openat2`/`creat` targeting `/proc/.../comm` (with lexical path normalization), and `--watch-rename=strict` also traps write syscalls (`write`, `writev`, `pwrite64`, `pwritev`, `pwritev2`). Because a seccomp filter cannot be removed, `--watch-rename` refuses `--detach` and `--on-exit detach` and defaults to `WaitTree` in the CLI.
- `pmask` zeroes `literal:` and `env:` secrets in supervisor memory immediately after loading them into protected buffers. The kernel audit log and caller shell copies remain and trigger a pre-run warning.

## Use the library for memory hygiene

`pmask::mem::SecBuf` is a dump-excluded, zeroize-on-drop buffer that prefers `memfd_secret` and falls back to `mlock`-protected heap. `SecBuf::is_locked()` and the report's `hardening` field report the achieved tier, including unlocked fallbacks. `SealedFd` creates read-only sealed memfds. `secret::Delivery` installs sealed descriptors at fd 3, 4, ... and sets `PMASK_SECRET_<NAME>`. `store::Store` provides an Argon2id and XChaCha20-Poly1305 encrypted file store with explicit policy checks.

### Library contract

- `Mask::prepare` copies `argv` and the environment. Call `snapshot_argv()` before `mask_self()` because `std::env::args()` reads the zeroed kernel `argv` pointers after self-masking.
- Every session owns `waitpid(-1)` and serializes on a process-wide mutex. Never run two sessions concurrently inside one process.
- Release builds ignore all `PMASK_FAULT_*` and `PMASK_PROBE_*` environment variables. Those hooks compile only with `--features test-hooks`. `PMASK_NO_SELFMASK` is a documented debug escape, not a test hook.
- Policy switches on `Mask` include `Mask::hide_pid`, `Mask::encrypt_memory`, `Mask::allow_foreign`, `Mask::supervisor_non_dumpable`, `Mask::strict_exec`, and `Mask::watch_rename_strict`. `hide_pid` and `encrypt_memory` are opt-in and never default. `hide_pid` makes the payload non-dumpable (`PR_SET_DUMPABLE=0`), whereas `encrypt_memory` hardens only the supervisor and the separate anonymous redaction block, leaving the payload dumpable. Call `Mask::payload_is_dumpable()` to query the resulting payload dumpability.
- `Mask::validate` enforces safety refusals directly in the library API and returns `InvalidInput` for invalid combinations:
  - `exec_once` with `no_dumpable` or `hide_pid`.
  - `watch_rename` (including `watch_rename_strict`) with `detach_after_exec(true)` or `SessionEnd::Detach`.
  - `strict_exec` with `detach_after_exec(true)`.
  - `hide_pid` with `follow_tree(false)` or `detach_after_exec(true)`.
- The library writes diagnostics to stderr unless `Mask::quiet()` is set. Library callers that require silent stderr must enable `quiet()`.

## Feature flags

- `testbins`: builds `pmask-testcases` and `pmask-protocases`.
- `test-hooks`: enables `PMASK_FAULT_*` and `PMASK_PROBE_*` overrides. Test gates build with `--features testbins,test-hooks`. Release builds enable neither.

## Packaging

The crate uses the `0BSD` license and is not published to crates.io. Pin a release tag or commit from GitHub:

```toml
pmask = { git = "https://github.com/Azathothas/pmask", tag = "v0.1.0" }
```

Alternatively, vendor the source tree. The GitHub release workflow builds static musl binaries for `x86_64` and `aarch64`. `src/arch.rs` supports `x86_64`, `aarch64`, and the `i686` test probe. Porting to another architecture requires implementing register layouts and syscall tables in `src/arch.rs`, `src/inject.rs`, and `src/seccomp.rs`.

## What pmask is not

`pmask` is not a sandbox, a TEE, or a boundary against hostile code. `pmask` hides process metadata from other local accounts and, with `--no-dumpable` or `--hide-pid`, from the same uid. Root, `CAP_SYS_PTRACE`, the kernel, eBPF, and the audit log still observe execution. `pmask` does not encrypt payload memory. `pmask` does not hide pid existence except under `--hide-pid` on a `hidepid=invisible` or `hidepid=ptraceable` mount, where `cgroup.procs`, `kill(0)`, `pidfd_open`, `getpriority`, `sched_getaffinity`, `prlimit`, and root still see the pid.
