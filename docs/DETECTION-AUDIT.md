# Detection audit follow-up

The `v0.1.0` repository carries the fixes for the independent detection audit of `v0.1.0-beta.3`.
The audit lives in the `pmask-beta3-detection-audit` archive, with numbered findings in `FINDINGS.md`.
The table below maps each finding to its fix and the test that verifies it.

The re-measurement archive is `evidence/stealth/`.
The archive stores the raw case records, the compact matrix, the hidden-pid run, and the launch-window logs.

## Findings and fixes

| finding | fix | test |
|---|---|---|
| 1-3: the hidden-pid family names the non-dumpable supervisor on a `hidepid=invisible` host | The supervisor scrubs its at-rest argv and environment copies after the fork and stays dumpable. `--no-dumpable` still pins the supervisor non-dumpable. `--stealth` reads the `/proc` policy and selects the trade that avoids a hidden pid. | `tests/qa.d/62.sh` |
| 9: `--no-exact` leaves a NUL run | In `v0.1.0` (#74), `--no-exact` keeps the original `arg_lo..arg_hi` and `env_lo..env_hi` extents. `pmask` pads `cmdline` with spaces and one final NUL and fills `environ` with complete non-repeating decoy entries or `--keep-env` variables. | `tests/qa.d/40.sh`, `tests/qa.d/41.sh`, `tests/qa.d/74.sh`, `tests/core.sh` K15/K15b |
| 12: `--exec-once` leaves `exe` naming the real binary | With `--on-exit wait` or `kill` and without `--no-exit-kill`, a seccomp exec filter traps later execs of a settled tracee and redirects them to the cached image. With the default `--on-exit detach`, the tracee stays syscall-supervised instead because a detached tracee would keep an unserviced filter. In `v0.1.0` (#64, #65, #69), `pmask` verifies carrier integrity, refuses incompatible non-dumpable modes, and rewrites `/proc/self/` paths. | `tests/qa.d/45.sh`, `tests/qa.d/61.sh`, `tests/qa.d/65.sh`, `tests/qa.d/69.sh` |
| 16: `--keep-env=NAME` leaves a NUL-padded window | `pmask` moves the kernel environment window onto a compact kept-only span in the redaction block. | `tests/qa.d/16.sh`, `tests/qa.d/41.sh` |
| 19: a 32-bit image runs unredacted | `pmask` refuses the 32-bit exec with `SIGKILL` before the image runs. `--allow-foreign` restores the unredacted run, and the summary counts it. | `tests/qa.d/49.sh` |
| 21: the same-uid memory read is open | `--stealth` applies `--no-dumpable` on a `hidepid=0` host. On `hidepid=invisible` or `hidepid=ptraceable`, `--stealth` keeps the tree dumpable and prints that the read stays open. In `v0.1.0` (#67), `--secret` sessions also default to `--no-dumpable` unless `--allow-dumpable` is passed. | `tests/qa.d/62.sh`, `tests/qa.d/67.sh` |
| 22: the network identity is not hidden | The threat model documents this limit. `--isolate=net` gives the payload a private network namespace. | `tests/qa.d/19.sh` |
| 14-15: `--isolate` does not redact and `--isolate=none` reads as if `/proc` is unchanged | An `--isolate` run prints a notice stating that it applies namespaces only. `README.md` states that `--isolate=none` still redacts. | `tests/isolation.sh` |
| 18: a self-renaming payload changes `comm` | `--stealth` enables `--watch-rename`, while the default keeps rename watching opt-in. In `v0.1.0` (#71, #72), `--watch-rename` also traps `open`, `openat`, `openat2`, and `creat`, `--watch-rename=strict` traps write syscalls, and `--on-exit detach` is refused. | `tests/qa.d/62.sh`, `tests/qa.d/71.sh`, `tests/qa.d/72.sh` |
| 20: the launch window | The launch window is documented and measured with no claim of closure. `--rexec` changes the off-label `comm` to a memfd name. In `v0.1.0` (#66), `--strict-exec` refuses shapes that cannot redact at entry. | `evidence/stealth/window-*.txt`, `tests/qa.d/66.sh` |
| 29: an `env:` secret is briefly in the supervisor's environment | The warning remains active. Using `file:`, `stdin`, or `--args-from-fd` avoids the environment copy. | `tests/qa.d/59.sh` |

## The new surface

`--stealth` implements the composition described in audit recommendation 9.3.
The flag combines `--rexec`, `--watch-rename`, and `--no-dumpable` unless the host `/proc` mount uses `hidepid=invisible` or `hidepid=ptraceable`.
`pmask` prints the trade it selected before the payload runs.
On a `hidepid=0` host, `--stealth` closes the same-uid memory read.
On a `hidepid=invisible` or `hidepid=ptraceable` host, `--stealth` keeps the tree visible to hidden-pid sweepers, leaves the memory read open, and states that trade.

`pmask probe` reports a `proc hidepid policy` row.
`pmask doctor --require=hidepid` exits with code 3 when the policy is `invisible`, `ptraceable`, or unknown.
A CI job can use that exit code to reject a host whose trade does not match its requirement.

`--allow-foreign` is the explicit opt-in for a 32-bit image.
Because `pmask` does not redact 32-bit images, the default configuration refuses them.
The summary line `foreign-refused` counts refusals, and `foreign-arch` counts runs that enabled the opt-in.

## Round 2 audit (0.1.0-beta.5 final)

The second audit round re-measured the `0.1.0-beta.5` tree against both a same-uid observer and root.
`evidence/round2/README.md` holds the raw record, with the exact command and log path for every row.
The audit measured nine cases and skipped none:

| case | measured result |
|---|---|
| default redaction | `cmdline`, `comm`, `environ`, and `AT_EXECFN` are the label. `exe`, `maps`, and payload memory name the real binary. |
| `--no-dumpable` | Six `EACCES` paths appear for the same uid. Root still reads all six. `stat` fields 48-51 are zero. |
| `--stealth` (`hidepid=0`) | Output prints the trade line. `comm` keeps the label after a rename. Six paths return `EACCES`. Only root sees the `/memfd:` `exe`. |
| `--encrypt-memory` | The supervisor holds `/secretmem` for the key. The payload block has no `/secretmem` VMA. The literal secret is absent from the holder's 6.1 MB of readable memory. The payload canary remains present. |
| `--exec-once --on-exit wait` | `ONE TWO` is preserved. `Seccomp_filters` rises by one. The later exec uses the `.pmask-rexec-` carrier. |
| `--watch-rename` | `comm` keeps the label while the control becomes `other`. One filter is installed. |
| `--hide-pid` | Readers see `ENOENT` on `hidepid=invisible` and `EPERM` on an instantiated inode under `hidepid=ptraceable`. `kill(0)` and root still see the pid. |
| secret source scrub | The holder memory contains no `literal:` value. A plain process holding the same value shows four hits. |
| `--report-file` (default path) | Output is one JSON object with `"mode": "redact"`. |

The round 2 audit contradicted five documentation claims, and `0.1.0-beta.5` corrected all five.
First, the `--stealth` row omitted `hidepid=ptraceable`.
Second, the memfd row omitted the `--exec-once` carrier.
Third, the supervisor row omitted `auxv`.
Fourth, the seccomp row claimed an absolute `Seccomp_filters: 2`.
Fifth, the `--no-dumpable` row counted five refusals instead of six.
The audit also found the secret source remaining in the holder heap.
`pmask` now zeroes that buffer at load, verified by `tests/qa.d/64.sh`.

Round 2 also closed six code defects that round 1 did not reach.
The fixes resolved the fast-exec double entry and a 32-bit completion path that only warned.
A third fix ensured completion paths that skip filter installation mark the tracee properly.
Another fix prevented a report-only run from selecting plain mode on a no-ptrace host.
The final two fixes replaced `MFD_CLOEXEC` with `O_CLOEXEC` on `memfd_secret(2)` and aligned `payload_dumpable` with the applied mask.
Matching tests live in `tests/qa.d/9.sh`, `45.sh`, `49.sh`, `62.sh`, `63.sh`, `64.sh`, `tests/options.sh`, and `tests/qa.sh`.

## Updates in v0.1.0

After `0.1.0-beta.5`, the `v0.1.0` hardening pass closed the follow-up findings recorded in `docs/REDTEAM-RESULTS.md` and `docs/ISSUE-CLOSURE.md` (#40, #43, #64–#77).
Exact mode now places the presentation block inside `[stack]` with `arg_end == env_start`, a plausible decoy `environ`, and `start_stack < arg_start`.
The real `[stack]` VMA stays intact, and stack `AT_EXECFN` matches `/proc/<pid>/auxv`.
`--no-exact` preserves original argv and environment spans with spaces, one NUL, and non-repeating decoy entries.
`--rexec` fails closed with exit 126 or 127 unless `--rexec-allow-disk` is given.
`--secret` sessions default to `--no-dumpable` and harden the supervisor before loading secret sources.

## Remaining limits

The launch window stays open in default mode, though `--strict-exec` refuses shapes that cannot redact at entry.
A same-uid observer can read payload memory in default non-secret mode.
Root and processes with `CAP_SYS_PTRACE` read every mode.
Network identity stays unchanged unless `--isolate=net` runs.
`pmask` refuses 32-bit images by default rather than redacting them.
The supervisor `exe` names the `pmask` binary because `--rexec` relocates only the payload `exe` to a memfd.
Hosts with `CAP_BPF` or `CAP_AUDIT_CONTROL` observe the exec at the syscall boundary.
`--no-dumpable` remains a `/proc` fingerprint and acts as a hidden pid on `hidepid=invisible` hosts.
`--hide-pid` does not hide pids from cgroupfs (`cgroup.procs`, `cgroup.threads`) or non-`/proc` syscalls (`getpriority`, `sched_getaffinity`, `prlimit`).
