# Integrating pmask

This page is for a project that wants to run a payload under pmask, or
reuse one of its memory-hygiene pieces.  It states the contract, the
limits, and the two integration shapes.

## Use the binary, not the library, for a supervisor

The library owns the calling process's `waitpid(-1)` domain and a
process-wide session lock.  That is correct for a dedicated launcher and
wrong inside a process that already reaps its own children, such as a
service manager with its own `waitid(P_PIDFD)` loop.  A project with its
own reaper should start the `pmask` binary as a separate process.

The binary contract:

- `pmask -q --label LABEL [options] -- COMMAND [ARGS...]`
- The exit status is the payload's.  A signal death is re-raised, so the
  caller sees `128 + signal`.
- `255` is pmask's usage or policy refusal.  A payload can also exit
  255 by itself, so the status alone does not distinguish the two; the
  stderr prefix (`pmask: ...`) and the absence of a report do.  Use
  `--report-file` when a caller must tell a refused run from a payload
  status.
- On the local mask path, SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1,
  SIGUSR2 and SIGWINCH are forwarded to the payload.  A runner-path run
  (`--secret`, `--isolate`, or a report-only run) does not install the
  proxy; if pmask dies, `PTRACE_O_EXITKILL` kills the tree instead.  Send
  the signal to the payload pid when the caller must reach it directly.
- `--on-exit kill` is the right policy for a service manager: the tree
  does not outlive the session.  The default `detach` leaves descendants
  running and untraced.
- `--report-file PATH` or `--report-fd N` writes one JSON object after
  the payload exits.  Every local path produces one, including plain
  redaction.  A `--daemon` job refuses the report because the daemon
  owns the run.  Do not use `--report=json` when fd 1 is the job log;
  the payload shares it.
- `--args-from-fd N` keeps the command line out of the supervisor's
  argv.  `--secret NAME=file:PATH` or `agent:NAME` delivers a value on a
  sealed descriptor.  `literal:` and `env:` are the sources that put the
  value in plain sight; the run warns and, in a mode that cannot redact,
  refuses them.
- `pmask probe` is the capability preflight.  `pmask doctor
  --require=redact,exact` exits 0, 3 or 4.  A host that denies ptrace
  runs `mode=plain`; the binary still delivers secrets and masks its own
  entry, but it does not redact the payload.
- `--hide-pid` needs `/proc` mounted with `hidepid=invisible` or
  `hidepid=ptraceable`.  It refuses on a weaker mount.  On
  `hidepid=ptraceable` a dentry that already exists answers `EPERM`, so
  the denial is distinguishable from a missing pid.  `kill(0)`,
  `pidfd_open` and root still see the pid.  The flag is re-injected at
  every traced exec, so `--no-follow` and `--detach` are refused: they
  take a process off that path, and an exec resets `PR_SET_DUMPABLE`.
  A descendant left running by the default `--on-exit detach` keeps the
  flag only until its next exec resets it.
- `--encrypt-memory` seals the supervisor's at-rest copies and keeps
  the payload's redaction block out of a core dump.  The block is
  anonymous and `MADV_DONTDUMP` on every host; a `memfd_secret` block
  would leave a `/secretmem` VMA in the payload, which is a tool
  fingerprint.  The session key uses `memfd_secret` when the host offers
  it.  It does not encrypt the payload's heap or stack.  A host without
  `memfd_secret` runs with the key in mlock'ed heap and the run says so.
- `--no-dumpable` and `--hide-pid` make `/proc/<pid>/mem` unreadable to
  a same-uid reader.  A tool that reads a task's memory through
  `/proc/<pid>/mem` (a seccomp user-notification hold, for example) must
  not combine its reader with those flags.
- `--isolate` is namespace-only; it does not redact.  Use `--redact
  --isolate=LIST` to compose.
- `--exec-once` with `--on-exit wait` or `--on-exit kill` (and without
  `--no-exit-kill`, whose survivors would keep a filter no tracer
  services) installs a seccomp filter that traps only
  `execve`/`execveat`, so the tracee runs free between execs.  With the
  default `--on-exit detach` the tracee is syscall-supervised instead,
  because a detached tracee would keep a filter with no tracer to
  service it.  `--exec-once --detach` warns that
  the cache is not applied: the tracee is released after its first exec
  and a later exec runs from its real path.
- `--watch-rename` and `--detach` are refused together.  The rename
  filter cannot be removed, and a detached tracee would answer a later
  `prctl(PR_SET_NAME)` with `ENOSYS` because no tracer services the
  filter.
- A `literal:` or `env:` secret is zeroed in the supervisor as soon as
  it is loaded into the protected buffer.  The remaining copy is the one
  the kernel and the caller's shell already hold; the run warns about it
  before it starts.

## Use the library for memory hygiene

`pmask::mem::SecBuf` is a dump-excluded, zeroize-on-drop buffer that
prefers `memfd_secret` and falls back to heap with a best-effort
`mlock`.  `is_locked()` and the report's `hardening` name the tier the
host actually gave, including an unlocked fallback.  `SealedFd`
builds a read-only sealed memfd.  `secret::Delivery` installs a set of
sealed descriptors at 3, 4, ... and sets `PMASK_SECRET_<NAME>`.
`store::Store` is an XChaCha20-Poly1305, Argon2id file store with an
explicit policy.

The library contract:

- `Mask::prepare` copies argv and the environment.  Call
  `snapshot_argv()` before `mask_self()`: `std::env::args()` reads the
  saved argv pointers, so after the self-mask it returns empty strings
  (or label suffixes), not the original arguments.
- A session owns `waitpid(-1)` and serializes on a process-wide lock.
  Do not run two sessions in one process.
- The release build reads no `PMASK_FAULT_*` or `PMASK_PROBE_*`
  variable.  Those are compiled in only with the `test-hooks` feature.
  `PMASK_NO_SELFMASK` is a documented debugging escape and is not a test
  hook.
- `Mask::hide_pid`, `Mask::encrypt_memory`, `Mask::allow_foreign` and
  `Mask::supervisor_non_dumpable` are the new policy switches.  The
  first two are opt-in and never default.  `hide_pid` also makes the
  payload non-dumpable (`PR_SET_DUMPABLE=0`); `encrypt_memory` hardens
  the supervisor and the block and leaves the payload dumpable.
  `Mask::payload_is_dumpable()` reports that distinction.
- The library writes diagnostics to stderr unless `quiet` is set.  A
  library caller that must not write to stderr sets it.

## Feature flags

- `testbins` builds `pmask-testcases` and `pmask-protocases`.
- `test-hooks` enables the fault and probe overrides.  The project's own
  gate builds with `testbins,test-hooks`; a release build uses neither.

## Packaging

The crate is `0BSD` and its dependencies are on the podcrates allow
list.  It is not published to crates.io.  A consumer pins a tag or a
commit:

```toml
pmask = { git = "https://github.com/Azathothas/pmask", tag = "v0.1.0-beta.5" }
```

or vendors the tree.  The release workflow builds static musl binaries
for `x86_64` and `aarch64`; the source has `arch.rs` support for those
two plus the i686 test probe.  A build for another architecture needs a
port of `arch.rs`, `inject.rs` and `seccomp.rs`, not a `cfg` change.

## What pmask is not

It is not a boundary against hostile code, a TEE, or a replacement for a
sandbox.  It hides process metadata from other local accounts and, with
`--no-dumpable`/`--hide-pid`, from the same uid.  Root, `CAP_SYS_PTRACE`,
the kernel, eBPF and the audit log see the exec.  It does not encrypt the
payload's memory.  It does not hide that a pid exists unless
`--hide-pid` is used on a suitable `/proc`, and even then `kill(0)` and
root still see it.
