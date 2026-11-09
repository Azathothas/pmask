# Issue 58: the detector family that does not see pmask

Host: Debian 13, `6.12.113+deb13-amd64`, x86_64, LXC container, uid 1000
with passwordless sudo. Research note: `docs/research/bteam-detectors.md`.
QA fragment: `tests/qa.d/58.sh`.

## Result

The hidden-pid family is blind to pmask for a structural reason: pmask
hides no pid. A masked payload is present in every existence view
(`getdents64`, `readdir`, `stat`, `kill(0)`), exactly like an unmasked one.

| tool | how obtained | result |
| --- | --- | --- |
| `unhide` 20240510 | Debian `.deb`, extracted to `/tmp` | `sys`/`checkkill`/`checkgetprio`/`proc`: no pmask pid, exit 0 |
| `chkproc` 0.58b | Debian `.deb`, extracted | payload and supervisor never named |
| `rkhunter` 1.4.6 | Debian `.deb`, extracted | `hidden_procs [ None found ]`, with and without a mask |
| `strace` | installed | control attaches; masked payload and supervisor refuse `PTRACE_SEIZE` |
| `sandfly-processdecloak` | not obtained | no Debian package; SKIP |
| `pspy` | not obtained | no Debian package; SKIP |
| `zapper` | not obtained | no Debian package; SKIP |
| `lsrootkit` | not obtained | no Debian package; SKIP |

Nothing was installed system-wide and nothing was fetched from an upstream
release; see `install-notes.log`.

## The bulk count is a host artefact

`chkproc`'s "process(es) hidden from readdir(3)" is 43-51 **with no pmask
process running** (`measure.log`). The cause is 23 threads of one container
process that its `ps -edf` parse does not list. The pid set is stable and
never contains the supervisor or the payload (`setdiff.log`,
`hidden-control.txt`, `hidden-masked.txt`). The QA case asserts the pid set,
not the count.

## Fragments

* `no-tools-run.log` — `sh tests/qa.d/58.sh` with nothing installed:
  4 PASS, 6 SKIP (each naming `command not found`), exit 0.
* `qa-tools-run.log` — the same with `PMASK_QA_TOOLS` and
  `PMASK_QA_RKHUNTER_CONF` pointing at the extracted binaries:
  8 PASS, 4 SKIP, exit 0.

## What was not measured

`unhide brute` and `quick` did not finish within a 10-minute limit on this
container, so they are not in the measured set. The four unobtained tools
are covered structurally in the note, not by a run.
