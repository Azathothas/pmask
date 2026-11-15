# Team red: beta.5 review results

This is the evidence record for the fixes applied to the PR #63 tree.
Every row names the check that decides it.  The numbers at the bottom are
read from the gate output, not estimated.

## What changed, and why it matters to an observer

| review issue | before | after | check |
|---|---|---|---|
| 001 carrier | a same-uid `rename` over `/dev/shm/.pmask-rexec-*` ran attacker bytes under the label; the cache keyed mtime and size | the carrier is preferred in `$XDG_RUNTIME_DIR`, its dev/ino and bytes are compared with the cached descriptor before reuse, its status change time is compared with the one taken when the bytes were written (an in-place rewrite keeps device, inode and length), and a mismatch kills the exec; a double-forked reaper unlinks it after SIGKILL | `src/rexec.rs` `carrier_tests` (5 cases; no shell case covers this, R4 belongs to 006) |
| 002 fast path | `--no-dumpable` made the entry writes fail, the seccomp install answer `EIO`, and the later exec ran the on-disk file on exit 0 | the combination is refused before the fork; the filter is installed before the completion dumpable injection | `qa.d/65.sh`, `options.sh` O39 |
| 003 window | scripts, vfork children and every `--no-dumpable` exec exposed the real argv for 0.4 to 1.6 ms; `--detach` left it permanently | `--strict-exec` refuses the shapes that cannot be redacted at entry; the default and the residual are documented | `qa.d/66.sh` |
| 004 same-uid | the secret fd and the payload memory were readable by default; the supervisor kept image fds 200/210 | a delivered secret makes the payload non-dumpable by default (`--allow-dumpable` opts out); the supervisor closes the image descriptors after the fork; daemon jobs are non-dumpable | `qa.d/67.sh`, `options.sh` O27, `daemon.sh` d7b/d8 |
| 005 load window | the holder was dumpable while a blocking source fed the value | `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` run before the first read in the CLI, `pmaskd --env-file` and the passphrase resolver | `qa.d/68.sh` |
| 006 self exec | `execv("/proc/self/exe")` under `--exec-once` cached and ran the pmask binary | `/proc/self` and `/proc/thread-self` rewrite to the tracee pid before the cache key resolves | `qa.d/69.sh`, `redteam.sh` R4 |
| 007 report | a dumpable supervisor let the payload append to the report; the audit fd reason was a `pmask` substring | the report is staged in `O_TMPFILE` or a 0600 name and linked after the tree; report runs wait and keep the supervisor non-dumpable; audit fd rows match memfd/deleted targets | `qa.d/70.sh`, `redteam.sh` R6 |
| 008 comm write | `write(2)` to `/proc/self/comm` changed the name under `--watch-rename` | the filter traps the open family and refuses a write-mode open; `--watch-rename=strict` also checks the descriptor target on write | `qa.d/71.sh`, `redteam.sh` R7 |
| 009 orphan filter | the default detach left the unremovable filter with no tracer and `ENOSYS` | a watch-rename run waits by default; an explicit detach is refused | `qa.d/72.sh` |
| 010 hide-pid | the docs claimed a family-wide blindness; cgroupfs and syscalls still named the pid | README, help, tool message and threat model name the channels | `qa.d/73.sh` |
| 011 no-exact | the entry swap shortened the kernel window and the decoy repeated | the entry transform is skipped, the original extent survives, and the completion writes the label plus a unique complete decoy | `qa.d/74.sh`, `redteam.sh` R2 |
| 012 exact shape | `env_start = arg_end + argc`, `start_stack = arg_start`, the block became `[stack]`, and `--encrypt-memory` marked it `dd` | the presentation is written into the kernel-copied stack region, `arg_end == env_start`, the environment span is non-zero, and `start_stack` and the real `[stack]` VMA are untouched | `qa.d/75.sh`, `redteam.sh` R1 |
| 013 rexec | a failed placement printed one line and ran the on-disk program on exit 0 | the run exits 126 (127 when the source is missing) unless `--rexec-allow-disk` was given; the message names `RLIMIT_NOFILE` | `qa.d/76.sh`, `options.sh` O32 |
| 014 plain | the supervisor's `cmdline` was an all-NUL run under `--no-redact` | the caller's argv block is restored when no plain-sight secret is present | `qa.d/77.sh`, `redteam.sh` R3 |

## The detector rules from the b-team issues

| rule | before | after |
|---|---|---|
| `arg_end - arg_start == len(cmdline)` | fired | still true by construction, but `env_start == arg_end` and `env_start != env_end` now hold, so the paired "empty environment" form of the rule does not |
| `start_stack == arg_start` | fired | no longer holds; `start_stack` is the kernel's initial stack pointer |
| `[stack]` is a 16 kB anonymous block without `gd` | fired | the real 132 kB `[stack]` VMA keeps `gd`; the presentation sits inside it |
| `AT_EXECFN` served as the label while `getauxval` returned the real path | fired | both copies are rewritten at the completion stop; they agree |
| `environ` length 0 | fired | the window is a complete decoy with a non-zero span |
| `write(2)` to `/proc/self/comm` | fired | refused by the opt-in filter (strict also covers aliases) |

## What still fires, and is now stated

- `comm`/`cmdline` name the label while `exe` and `maps` name the real
  binary unless `--rexec` or `--no-dumpable` is used.  This is the
  design's boundary, and `docs/THREAT-MODEL.md` says so.
- A `#!` script, a vfork child and a later exec that cannot take the
  entry path still expose the real argv for the measured window unless
  `--strict-exec` is used.
- Root and anything with `CAP_SYS_PTRACE` read everything.  A same-uid
  peer reads a dumpable payload's memory, and the audit/eBPF channels
  still see the real exec image at exec time.
- `--exec-once` leaves a readable named carrier; it is now
  authenticated and fails closed, but a same-uid process can still read
  the bytes before it is removed.

## Gate

The micro-VM gate runs `tests/run.sh` as root and as uid 1000.  The
counts are copied from the run that produced this tree:

```
gate: 684 PASS, 0 FAIL, 32 SKIP (root and uid 1000; the count is
read from vm/cache/vm-output.log for this tree)
```

The native suites that need a full host (`qa.d`, `store`, `isolation`,
`lease`, `secrets`, `compare`, `conformance`, `regressions`) are skipped
inside the VM by design, so the count above does not include them.  The
fragments for 65-77 are decided by the `native-suites` job, whose
"per-issue QA fragments" step runs `tests/qa.sh` on the runner with
ptrace enabled; that step requires a `QA: PASS` summary line with at
least one decided case, so a batch of skips cannot read as coverage.

Where an invariant does not need ptrace it is also a unit test, so a
host that refuses `PTRACE_TRACEME` still decides it: the argv/environ
window geometry is `src/execimg.rs`'s tests, and the descriptor
classification and the comm-path resolution are `src/tracer.rs`'s.
