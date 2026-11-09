# Issue 35: the gate is not root-safe

Date: 2026-11-09T10:55:26Z  host: Linux 6.12.113+deb13-amd64 x86_64  uid: 1000

## The defect, measured before the fix

`sudo sh tests/run.sh`: 18 FAIL lines.

```
FAIL i21-environ-refused-with-no-dumpable (readable)
FAIL i22-maps-refused-with-no-dumpable (masked=[2757] control=[2757])
FAIL i23-smaps-refused-with-no-dumpable (masked=[22901] control=[22901])
FAIL i24-fd-and-fdinfo-refused-with-no-dumpable (control fd=[3] fdinfo=[3])
FAIL i25-exe-refused-with-no-dumpable (control=[/workspace/wt/fix5/tests/testcases])
FAIL i26-cwd-and-root-refused-with-no-dumpable (control cwd=[/workspace/wt/fix5/tests] root=[/])
FAIL i27-ns-refused-with-no-dumpable (control=[pid:[4026532664]])
FAIL i28-auxv-refused-with-no-dumpable (masked=[368] control=[368])
FAIL i29-syscall-refused-with-no-dumpable (masked=[57] control=[57])
FAIL i30-io-refused-with-no-dumpable (masked=[94] control=[94])
FAIL i31-mem-refused-with-no-dumpable (opened)
FAIL i32-pidfd-getfd-refused-with-no-dumpable (masked=[ok] control=[ok])
FAIL i33-process-vm-readv-refused-with-no-dumpable (masked=[ok bytes=8] control=[ok bytes=8])
FAIL i34-process-vm-writev-refused-with-no-dumpable (masked=[ok bytes=8] control=[ok bytes=8])
FAIL i36-kcmp-refused-with-no-dumpable (masked=[ok result=0] control=[ok result=0])
FAIL d5-agent-refuses-mem-maps-smaps-environ (1 of 4 refused)
FAIL holder-environ-refused: a same-uid peer read the holder's environ while it held a secret
FAIL nodumpable-refuses: a same-uid peer read /proc/1345642/environ with --no-dumpable set
################ FINAL: FAILURES
```

## The fix

`tests/lib.sh` gained the shared decision, so every suite uses one rule:

- `cap_has_sys_ptrace CAPHEX` — CAP_SYS_PTRACE is bit 19, the high bit of
  the fifth hex digit from the right of `CapEff`. It is decoded as a hex
  digit, not by arithmetic: a 64-bit `CapEff` overflows a shell integer.
- `root_peer_observer` — true when `id -u` is 0 **and** that bit is set.
  It sets `ROOT_PEER_REASON` with the explanation the suites print.
  Deliberately not "uid is 0": a root that dropped CAP_SYS_PTRACE is
  still a dumpable-limited observer and those cases must keep running.
- `kill_owned PID START` — SIGKILL a process only when the uid and the
  `/proc/<pid>/stat` start time still match what the suite recorded, so a
  cleanup cannot hit a recycled pid.

Applied to the same-uid refusal cases, which print `SKIP <name>: <reason>`:

| suite | cases |
| --- | --- |
| `tests/isolation.sh` | i21–i36 (16 cases) |
| `tests/conformance.sh` | `holder-environ-refused`, `nodumpable-refuses` |
| `tests/lease.sh` | `d5-agent-refuses-mem-maps-smaps-environ` (not in the issue, but the same class, and it blocked `FINAL: ALL-PASS`) |

## Control-payload leak (found by the b-team audit)

`tests/isolation.sh` started an unmasked control with
`testcases sleeper PMKISO-$$` and never killed it: `cleanup` only called
`kill_comm mkiso`, and the control's comm is `testcases`, so the scoped
kill never matched. The orphan then made `edge.sh e6-supervisor-selfmask`
fail on the next run.

Fixed in two places, both scoped:

- `cleanup` calls `kill_owned` for the control's pid and start time;
- the matrix kills and reaps the control as soon as its last case has run,
  and fails `i19-matrix-control-payload-stopped` if the kill did not take.

`i37-no-pmkiso-process-survives-the-matrix` asserts the property directly:
`$(sightings PMKISO-$$)` must be 0 at the end of the suite.

The reap is a bounded poll, never a bare `wait`: the payload is a
`sleeper`, so `wait` on a kill that did not fire would hang the gate
forever instead of failing it. That was found by planting the defect and
observing the hang, and is the reason the loop exists.

## Commands and verdicts

| command | exit | verdict |
| --- | --- | --- |
| `sudo sh tests/run.sh` before the fix | 1 | `################ FINAL: FAILURES`, 18 FAIL lines (`root-run-before.log`) |
| `sudo sh tests/run.sh` after the fix | 0 | `################ FINAL: ALL-PASS`, 0 FAIL lines (`root-run-after.log`) |
| `sh tests/isolation.sh` (uid 1000) | 0 | `== VERDICT: FAIL=0 ==`, 88 PASS, 0 SKIP, 0 stray `PMKISO-` (`isolation-as-uid1000.log`) |
| `sudo sh tests/isolation.sh` | 0 | `== VERDICT: FAIL=0 ==`, 16 SKIPs with the reason above (`isolation-as-root.log`) |
| `sudo sh tests/conformance.sh` | 0 | `CONFORMANCE: PASS pass=18 fail=0 skip=6` (`conformance-as-root.log`) |
| `sudo sh tests/lease.sh` | 0 | `SKIP d5-agent-refuses-mem-maps-smaps-environ: uid 0 with CAP_SYS_PTRACE...` |
| `sh tests/qa.d/35.sh` | 0 | `QA35: PASS`, 21 cases |
| plant: control kill disabled | 1 | `FAIL i19-matrix-control-payload-stopped (pid ... survived its kill)`, `FAIL i37-no-pmkiso-process-survives-the-matrix (1 process(es) still carry PMKISO-...)` (`plant-no-control-kill.log`) |

## One cross-talk observation, not a defect in this change

A single `sh tests/isolation.sh` run reported
`FAIL i15-refused-env-secret-leaves-no-process (2 sightings)` while
another agent's worktree was running its own `isolation.sh`: the marker
`MK-ISO-ENVSECRET` is a fixed literal shared by every checkout, so
`sightings` counts the other run's process. Re-running immediately gave
`FAIL=0`. This is the documented fixed-label cross-talk in
`/workspace/meta/ISSUE-MAP.md`, not a regression from this change, and it
is the reason the full gate was run only when the other agents were
quiet.
