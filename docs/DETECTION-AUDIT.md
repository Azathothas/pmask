# Detection audit follow-up

This tree carries the fixes for the independent detection audit of
`v0.1.0-beta.3`. The audit is the `pmask-beta3-detection-audit` archive.
Its findings are numbered in `FINDINGS.md`; this page maps each one to
the change and the test that pins it.

The re-measurement is `evidence/stealth/`. It carries the raw case
records, the compact matrix, the hidden-pid run and the launch-window
logs.

## Findings and fixes

| finding | fix | test |
|---|---|---|
| 1-3: the hidden-pid family names the non-dumpable supervisor on a `hidepid=invisible` host | the supervisor scrubs its at-rest argv and environment copies after the fork and stays dumpable. `--no-dumpable` still pins it non-dumpable. `--stealth` reads the `/proc` policy and picks the trade that avoids a hidden pid. | `tests/qa.d/62.sh` |
| 9: `--no-exact` leaves a NUL run | the argv window is the label padded with spaces and one final NUL. The environment window gets a fixed decoy, or the `--keep-env` variables. | `tests/qa.d/40.sh`, `tests/qa.d/41.sh`, `tests/core.sh` K15/K15b |
| 12: `--exec-once` leaves `exe` naming the real binary | with `--on-exit wait` or `kill` (and without `--no-exit-kill`), a seccomp exec filter traps the settled tracee's later exec and redirects it to the cached image.  With the default `--on-exit detach` the tracee is syscall-supervised instead, because a detached tracee would keep a filter with no tracer. | `tests/qa.d/45.sh`, `tests/qa.d/61.sh` |
| 16: `--keep-env=NAME` leaves a NUL-padded window | the kernel's environment window is moved onto a compact kept-only span in the redaction block. | `tests/qa.d/16.sh`, `tests/qa.d/41.sh` |
| 19: a 32-bit image runs unredacted | the exec is refused before the image runs. `--allow-foreign` restores the old unredacted run and the summary counts it. | `tests/qa.d/49.sh` |
| 21: the same-uid memory read is open | `--stealth` applies `--no-dumpable` on a `hidepid=0` host. On `hidepid=invisible` or `hidepid=ptraceable` it keeps the tree dumpable and prints that the read stays open. | `tests/qa.d/62.sh` |
| 22: the network identity is not hidden | documented. `--isolate=net` gives the payload a private network namespace. | `tests/qa.d/19.sh` |
| 14-15: `--isolate` does not redact and `--isolate=none` reads as if `/proc` is unchanged | the isolate run now prints the note that it is namespace-only; the README says `--isolate=none` still redacts. | `tests/isolation.sh` |
| 18: a self-renaming payload changes `comm` | `--stealth` enables `--watch-rename`. The default keeps the old opt-in behaviour. | `tests/qa.d/62.sh` |
| 20: the launch window | documented and measured. No claim of closure. `--rexec` changes the off-label `comm` to a memfd name. | `evidence/stealth/window-*.txt` |
| 29: an `env:` secret is briefly in the supervisor's environment | the warning remains. A `file:`, `stdin` or `--args-from-fd` source avoids the environment copy. | `tests/qa.d/59.sh` |

## The new surface

`--stealth` is the composition the audit's recommendation 9.3 describes:
`--rexec`, `--watch-rename`, and `--no-dumpable` unless the host's
`/proc` uses `hidepid=invisible` or `hidepid=ptraceable`. It prints the
trade it chose. On a `hidepid=0` host it closes the same-uid memory
read. On a `hidepid=invisible` or `hidepid=ptraceable` host it keeps the
tree visible to the hidden-pid sweepers and leaves the memory read open,
and it says so.

`pmask probe` has a `proc hidepid policy` row. `--require=hidepid` fails
with exit 3 when the policy is `invisible` or `ptraceable` (and on an
unknown policy), so a CI job can refuse a host where the trade is not
the one it wanted.

`--allow-foreign` is the explicit opt-in for a 32-bit image. A 32-bit
image is not redacted, so the default refuses it. The summary line
`foreign-refused` counts the refusals and `foreign-arch` counts the
runs that took the opt-in.

## Round 2 audit (0.1.0-beta.5 final)

The second round re-measured the fixed tree against a same-uid observer and
root.  The raw record is `evidence/round2/README.md`; every row there names the
command and the log it came from.  Nine cases were measured, none skipped:

| case | measured result |
|---|---|
| default redaction | `cmdline`, `comm`, `environ` and `AT_EXECFN` are the label; `exe`, `maps` and the payload's memory name the real binary |
| `--no-dumpable` | six `EACCES` paths for the same uid; root still reads all six; stat fields 48-51 are zero |
| `--stealth` (hidepid=0) | the trade line; `comm` keeps the label after a rename; six `EACCES`; only root sees the `/memfd:` exe |
| `--encrypt-memory` | supervisor has `/secretmem` for the key; the payload block has none; the literal secret is absent from the holder's 6.1 MB of readable memory; the payload canary is present |
| `--exec-once --on-exit wait` | `ONE TWO` preserved; `Seccomp_filters` rises by one; the later exec uses the `.pmask-rexec-` carrier |
| `--watch-rename` | `comm` stays the label; the control becomes `other`; one filter |
| `--hide-pid` | `ENOENT` on `hidepid=invisible`, `EPERM` on an instantiated inode under `hidepid=ptraceable`; `kill(0)` and root still see the pid |
| secret source scrub | the holder's memory has no `literal:` value; a plain process holding the same value shows four hits |
| `--report-file` (default path) | one JSON object, `"mode": "redact"` |

The audit contradicted five documentation claims, all corrected: the
`--stealth` row omitted `hidepid=ptraceable`; the memfd row omitted the
`--exec-once` carrier; the supervisor row omitted `auxv`; the seccomp row
claimed an absolute `Seccomp_filters: 2`; and the `--no-dumpable` row counted
five refusals instead of six.  It also found the secret source left in the
holder's heap, which is now zeroed at load and tested by `tests/qa.d/64.sh`.

Round 2 also closed code defects the first round did not reach: the fast-exec
double entry, a completion that skipped the filter install without marking
the tracee, a 32-bit completion that only warned, a report-only run that
could select plain mode on a no-ptrace host, `MFD_CLOEXEC` on
`memfd_secret(2)`, and a `payload_dumpable` that followed the request rather
than the mask.  The matching tests are in `tests/qa.d/9.sh`, `45.sh`,
`49.sh`, `62.sh`, `63.sh`, `64.sh`, `tests/options.sh` and `tests/qa.sh`.

## Remaining limits

The launch window is unchanged. A same-uid observer can read the payload
memory in the default mode. Root reads every mode. The network identity
is unchanged unless `--isolate=net` is used. A 32-bit image is refused,
not redacted. The supervisor's `exe` names the pmask binary; `--rexec`
moves the payload's `exe` to a memfd, not the supervisor's. A host with
`CAP_BPF` or `CAP_AUDIT_CONTROL` sees the exec at the syscall boundary.
`--no-dumpable` is still a fingerprint, and on `hidepid=invisible` it is
still a hidden pid.
