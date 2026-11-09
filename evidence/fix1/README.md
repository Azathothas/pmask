# Evidence: fix1 (issues 4, 5, 15, 16, 17, 33, 60)

Every log here is raw command output. Measurement host: Debian 13
container, kernel `6.12.113+deb13-amd64`, uid 1000 unless a line says
otherwise. User namespaces work (`unshare -Urn true` exits 0), native
ptrace works, tracefs/eBPF are blocked by the container.

Two binaries are compared throughout:

- **fixed**: `target/release/pmask` built from this branch at the commit
  named in each report section.
- **baseline**: the `qa-base` build of `fa46e62` (plus PR #37), saved
  before any change and used through `TESTBIN_DIR=/tmp/prefix`.  For
  issue 60 that binary predates the `evilrename` testcase, so
  `/tmp/basebin` pairs the baseline `pmask` with the current
  `testcases`; the mismatch is the probe, not the library.

## Layout

| path | what it is |
|---|---|
| `<issue>/repro.log` | the defect and the fix, side by side |
| `<issue>/qa-fixed.log` | `tests/qa.d/<issue>.sh` against the fixed build |
| `<issue>/qa-baseline.log` | the same fragment against the baseline |
| `gate-run.log` | `sh tests/run.sh` (full native gate) |
| `gate-qa-dispatch.log` | `sh tests/qa.sh` (all fragments) |
| `suite-*.log` | the targeted suites re-run after the last commit |

## Verdicts

| issue | fixed fragment | baseline fragment |
|---|---|---|
| 4 | 21 PASS, exit 0 | 20 PASS / 1 FAIL, exit 1 |
| 5 | 7 PASS, exit 0 | 3 PASS / 4 FAIL, exit 4 |
| 15 | 5 PASS, exit 0 | 3 PASS / 2 FAIL, exit 2 |
| 16 | 5 PASS, exit 0 | 3 PASS / 2 FAIL, exit 2 |
| 17 | 5 PASS, exit 0 | 3 PASS / 2 FAIL, exit 2 |
| 33 | 7 PASS, exit 0 | 3 PASS / 4 FAIL, exit 4 |
| 60 | 12 PASS, exit 0 | 10 PASS / 2 FAIL, exit 2 |

`gate-run.log` ends `FINAL: ALL-PASS`; `gate-qa-dispatch.log` ends
`QA: PASS cases=7`.

## What could not be reproduced natively

**Issue 4's original symptom.** On this kernel the baseline binary also
redacts correctly under `--unshare`, so the "no redaction at all" output
in the issue report does not come back here. The mechanism the issue
names is nonetheless visible and was confirmed with a standalone C probe:
the child's own `raise(SIGSTOP)` is delivered as a plain group-stop
(`0x137f`, sig 19, event 0) rather than as the handshake, and the kernel
on this host happens to deliver it. The fix removes the dependence on
that: the tracer stops the seized child with `PTRACE_INTERRUPT` and
takes the `PTRACE_EVENT_STOP`/SIGTRAP stop as the handshake. Fragment
`qa4-handshake-is-tracer-interrupt` asserts the mechanism through the
verbose line, so it fails on the baseline (1 FAIL) and passes on the
fixed build even where the outcome case cannot discriminate. The
Alpine 6.12.115 VM in the issue report is where the outcome differs;
`vm/run.sh` was not run (it is the shared, slow gate and the lead asked
for it to be scheduled, not taken).

**Issue 4 also depends on a pid-namespace init's self-stop being
discarded.** That is kernel-version behaviour. `strace` cannot attach
inside this container (`PTRACE_SEIZE` returns EPERM under the
container's seccomp policy), so the ordered-handshake proof is the
verbose line plus the C probe, not a syscall trace.
