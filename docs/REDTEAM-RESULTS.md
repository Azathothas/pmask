# Team red: beta.5 review results (`v0.1.0`)

The tables below record the evidence for the red-team review fixes carried from PR #63 into `v0.1.0`.
Every row names the automated check that verifies the fix.
The gate counts at the bottom come directly from recorded gate output, not estimates.

## What changed, and why it matters to an observer

| review issue | before | after (`v0.1.0`) | check |
|---|---|---|---|
| 001 carrier (#64) | A same-uid `rename` over `/dev/shm/.pmask-rexec-*` ran attacker bytes under the label. The cache keyed only mtime and size. | `pmask` prefers `$XDG_RUNTIME_DIR` for the carrier and checks `verify_carrier` (`dev`, `ino`, `ctime`, and bytes) against the cached descriptor before reuse. A mismatch kills the exec. `Cache` keys `dev`, `ino`, and `ctime`. A warning reports `seal()` failure. A double-forked reaper cleans fds and stdio and unlinks the carrier on `Image::drop` or `SIGKILL`. Residual TOCTOU when `$XDG_RUNTIME_DIR` is unset is documented. | `src/rexec.rs::carrier_tests` (5 cases), `tests/redteam.sh` (note: `tests/qa.d/64.sh` tests `--encrypt-memory`, not issue #64) |
| 002 fast path (#65) | `--no-dumpable` broke entry writes, made seccomp installation return `EIO`, and ran the later exec from disk with exit 0. | Both the CLI (`src/main.rs`) and library (`src/mask.rs`) refuse `--exec-once` with `--no-dumpable`, `--hide-pid`, `--stealth` on non-`hidepid` hosts, and default non-dumpable `--secret` sessions before fork. `install_exec_filter` runs before `PR_SET_DUMPABLE=0`. | `tests/qa.d/65.sh`, `tests/options.sh` O39 |
| 003 window (#66) | Scripts, `vfork` children, and `--no-dumpable` execs exposed real argv for 0.4 to 1.6 ms. `--detach` left the real argv permanently. | `--strict-exec` refuses `#!` scripts, `vfork` children, entry-redaction fallbacks (`write_mem`, scratch, overflow), settled re-exec bypasses, and `--detach`. Docs state the default trade and residual window. | `tests/qa.d/66.sh` |
| 004 same-uid (#67) | The secret fd and payload memory stayed readable by default. The supervisor kept image fds 200 and 210 open. | `--secret` sessions default to `--no-dumpable` and a non-dumpable supervisor (`--allow-dumpable` opts out). `close_parent_image_fds` closes supervisor fds 200 and 210 after fork, including under `--exec-once`. Daemon jobs stay non-dumpable. Non-secret default dumpability remains a documented trade. | `tests/qa.d/67.sh`, `tests/options.sh` O27, `tests/daemon.sh` d7b/d8 |
| 005 load window (#68) | The secret holder stayed dumpable while a blocking source fed the value. | `harden_self()` (`PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0`) runs before secret, passphrase, or `--env-file` load in `src/run.rs`, `src/bin/pmaskd.rs`, `src/subcmd.rs`, and `src/agent.rs`, with a visible warning on failure. | `tests/qa.d/68.sh` |
| 006 self exec (#69) | `execv("/proc/self/exe")` under `--exec-once` cached and executed the `pmask` binary. | `tracee_open_path`, `path_is_elf`, and `elf_is_32` rewrite `/proc/self/` and `/proc/thread-self/` to `/proc/{pid}/` before the cache key resolves. | `tests/qa.d/69.sh`, `tests/redteam.sh` R4 |
| 007 report (#70) | A dumpable supervisor let the payload append to the report. The audit fd reason matched the `pmask` substring. | `ReportSink` stages reports in `O_TMPFILE` or a 0600 temp file with `Drop` cleanup and links after the tree exits. `src/run.rs` preserves `supervisor_non_dumpable(true)`. Reports default to `WaitTree`, and `--audit` plus stdout `--report=json` is refused. `fd_is_residue` checks `/memfd:`, `(deleted)`, and `.pmask-rexec-`. | `tests/qa.d/70.sh`, `tests/redteam.sh` R6 |
| 008 comm write (#71) | `write(2)` to `/proc/self/comm` changed `comm` under `--watch-rename`. | `--watch-rename` traps `prctl(PR_SET_NAME)` plus `open`, `openat`, `openat2`, and `creat` with lexical path normalization. `--watch-rename=strict` traps write syscalls. `aarch64` `NT_ARM_SYSTEM_CALL` denial is fixed, and non-dumpable `EACCES` prints a visible warning. | `tests/qa.d/71.sh`, `tests/redteam.sh` R7 |
| 009 orphan filter (#72) | Default detach left an unremovable seccomp filter with no tracer and caused `ENOSYS`. | `--watch-rename` defaults to `WaitTree` in the CLI and refuses `--on-exit detach` in both the CLI and `Mask` library API. | `tests/qa.d/72.sh` |
| 010 hide-pid (#73) | Docs claimed family-wide blindness even though cgroupfs and syscalls still exposed the pid. | `README.md`, help text, runtime notices, and `docs/THREAT-MODEL.md` document the kernel boundary for cgroupfs (`cgroup.procs`, `cgroup.threads`) and non-`/proc` syscalls (`getpriority`, `sched_getaffinity`, `prlimit`). | `tests/qa.d/73.sh` |
| 011 no-exact (#74) | The entry swap shortened the kernel window and repeated the decoy string. | `--no-exact` skips the entry transform and preserves original `arg_lo..arg_hi` and `env_lo..env_hi`. Completion fills `cmdline` with spaces plus one NUL and writes complete non-repeating decoy `environ` entries. | `tests/qa.d/74.sh`, `tests/redteam.sh` R2 |
| 012 exact shape (#75) | `env_start` equalled `arg_end + argc`, `start_stack` equalled `arg_start`, the block replaced `[stack]`, and `--encrypt-memory` marked `[stack]` with `dd`. | Exact mode writes the presentation block inside `[stack]` with `arg_end == env_start`, a plausible decoy `environ`, `start_stack < arg_start`, and the real `[stack]` VMA intact. `--encrypt-memory` marks the separate anonymous block `MADV_DONTDUMP`, not `[stack]`. | `tests/qa.d/75.sh`, `tests/qa.d/64.sh`, `tests/redteam.sh` R1 |
| 013 rexec (#76) | A failed `--rexec` placement printed one line and ran the on-disk binary with exit 0. | `--rexec` fails closed with exit 126 (or 127 when the source is missing) and prints an actionable `RLIMIT_NOFILE` error unless `--rexec-allow-disk` is given. | `tests/qa.d/76.sh`, `tests/options.sh` O32 |
| 014 plain (#77) | The supervisor `cmdline` showed an all-NUL run under `--no-redact`. | Plain mode restores caller argv via `restore_own_argv` when no plain-sight secret is present. Non-plain modes zeroize `original_argv` immediately. | `tests/qa.d/77.sh`, `tests/redteam.sh` R3 |

## The detector rules from the b-team issues

| rule | before | after (`v0.1.0`) |
|---|---|---|
| `arg_end - arg_start == len(cmdline)` | Fired. | Still holds by construction. Because `env_start == arg_end` and `env_start != env_end` now hold, the paired empty-environment rule no longer fires. |
| `start_stack == arg_start` | Fired. | No longer holds. `start_stack` keeps the kernel's initial stack pointer (`start_stack < arg_start`). |
| `[stack]` is a 16 kB anonymous block without `gd` | Fired. | No longer holds. The real 132 kB `[stack]` VMA keeps `gd`, and the presentation block sits inside it. |
| `AT_EXECFN` served as the label while `getauxval` returned the real path | Fired. | In exact mode, `patch_stack_execfn` rewrites stack `AT_EXECFN` and `pres_bytes` fixes the trailing NUL so both copies match the label (`tests/qa.d/43.sh`, `R1-inprocess-auxv`). Under `--no-exact`, both copies stay the real path. |
| `environ` length 0 | Fired. | No longer holds. The environment window holds a complete decoy with a non-zero span. |
| `write(2)` to `/proc/self/comm` | Fired. | Refused by the opt-in `--watch-rename` filter. `--watch-rename=strict` also covers aliases. |
| A symlink to `/proc/<pid>/comm` opened for write | Fired. | Refused by `--watch-rename=strict`. The default `--watch-rename` filter still allows symlink aliases, as documented in `README.md` and `--help`. |
| `Seccomp: 2` on any process of the tree | Fired only when a filter was active (not in default mode). | Unchanged and unmaskable because the field is kernel state. `--stealth` installs the rename filter, so `--stealth` carries the field too. |

## What still fires, and is now stated

- `comm` and `cmdline` show the label while `exe` and `maps` show the real binary unless `--rexec` or `--no-dumpable` runs. `docs/THREAT-MODEL.md` documents this design boundary.
- `#!` scripts, `vfork` children, and later execs that skip the entry path expose real argv for the measured window unless `--strict-exec` runs.
- Root and callers with `CAP_SYS_PTRACE` read every mode. A same-uid peer reads a dumpable payload's memory, and kernel audit or eBPF sensors see the real image at exec time.
- `Seccomp: 2` and `NoNewPrivs: 1` appear on every run that installs the rename filter, including `--stealth`. One `awk` scan over `/proc/*/status` detects those fields. Because those fields are kernel state, no flag hides them, and `docs/THREAT-MODEL.md` records the per-mode values.
- The supervisor `exe` names the `pmask` binary in every mode unless `--no-dumpable` blocks same-uid reads. A label `comm` paired with a `pmask` `exe` stays visible in default modes.
- Without `--keep-env`, the payload environment is a fixed 110-byte decoy. The fixed content and small size act as a signature, so use `--keep-env` when a plausible inherited environment is required.
- `--exec-once` creates a readable named carrier file. The carrier is authenticated and fail-closed, but a same-uid process can still read its bytes before removal.

## Gate

The micro-VM gate runs `tests/run.sh` as root and as uid 1000.
The counts below come directly from the recorded beta.5 review run:

```
gate: 720 PASS, 0 FAIL, 32 SKIP (root and uid 1000; the count is
read from vm/cache/vm-output.log for this tree, which stages
`redteam` and `blueteam` among the eleven suites it copies)
```

Native suites that need a full host (`qa.d`, `store`, `isolation`, `lease`, `secrets`, `compare`, `conformance`, `regressions`) skip inside the VM by design.
Those native suites are not included in the VM count above.
On a host that denies ptrace, run `PMASK_VM_FRAGS="71 72" sh vm/run.sh` to stage specific fragments with `qa.sh` inside the guest.
The subset run prints a `NOTE` naming the subset so a partial run never appears as full coverage.
The `native-suites` CI job runs `tests/qa.sh` on a ptrace-enabled runner to decide fragments 65 through 77.
The CI step requires a `QA: PASS` summary line with at least one decided case so skipped runs cannot pass as coverage.

Invariants that do not require ptrace also run as Rust unit tests.
`src/execimg.rs` unit tests check argv and environ window geometry.
`src/tracer.rs` unit tests check descriptor classification and `comm`-path resolution.
