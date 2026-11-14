# Stealth re-measurement after the beta.4 fixes

Date: 2026-11-10, read from the evaluation host.
Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86_64, 8 vCPU.
Observer: uid 1000 for the same-uid rows, uid 0 for the root rows.
Harness: the `pmask-beta3-detection-audit` case runner and payloads, with
the slow sweepers (`chkproc`, `rkhunter`, `lsrootkit`) removed from the
per-case battery. The hidden-pid rows use `unhide-noroot checkkill` in a
private mount namespace with `hidepid=invisible`, because the host's own
`/proc` is `hidepid=0`.

The raw case records are `results.jsonl`. The compact table is
`matrix.tsv`. The launch-window logs are `window-default.txt`,
`window-rexec.txt` and `window-stealth.txt`. The hidden-pid runs are
`hidepid-unhide.txt`. The beta.5 opt-in features are measured by
`hide-pid.log` and `encrypt-memory.log`; the `memfd_secret` row is a
SKIP on this host because the kernel does not offer the syscall, and the
fallback is reported as `block_secretmem=false`.

## What changed

| audit finding | before | after |
|---|---|---|
| 1-3: the supervisor is a hidden pid under `hidepid=invisible` | the supervisor was non-dumpable for the session, so `unhide` and `chkproc` named it | the supervisor scrubs its at-rest argv and environment copies and stays dumpable. `--no-dumpable` still pins it non-dumpable. `--stealth` chooses the best trade for the host. |
| 9: `--no-exact` leaves a NUL run | `cmdline` was the label plus one NUL per argument slot and `environ` was an all-NUL block | `cmdline` is the label padded with spaces and one final NUL, and `environ` is a fixed decoy environment. The payload's real argv and environment still come from the hidden block. |
| 12: `--exec-once` leaves `exe` naming the real binary | a settled tracee was resumed with `PTRACE_CONT`, so its later exec ran from disk and `exe` was `/usr/bin/sleep` | a settled tracee is syscall-supervised while `--exec-once` is active, so the later exec is redirected to the cached image. `exe` is the guarded temporary file. |
| 16: `--keep-env=NAME` leaves a NUL-padded window | the kernel's environment window kept its original extent, with the kept variable inside a NUL run | the window is moved onto a compact kept-only span in the redaction block. `environ` is exactly the kept variables. |
| 19: a 32-bit image runs unredacted | the run warned and ran the image with its real argv, environ and `comm` | the exec is refused before the image runs. `--allow-foreign` restores the old unredacted run and the summary counts it. |
| 21: the same-uid memory read is open | readable in every mode except `--no-dumpable` | `--stealth` applies `--no-dumpable` on a `hidepid=0` host, so the read is refused. On `hidepid=invisible` it keeps the tree dumpable and prints that the read stays open, because a non-dumpable process would be a hidden pid. |
| 22: the network identity is not hidden | `ss`, `lsof` and `/proc/net/tcp` give the real pid, uid, inode and fd | unchanged by the mask. `--isolate=net` puts the payload in a private network namespace. The README now says so. |

## The hidden-pid result

`hidepid-unhide.txt` is the direct measurement. Inside a private mount
namespace with `hidepid=invisible`, `unhide-noroot checkkill` names no
pmask pid for the default run and no pid for the `--stealth` run. It
names the supervisor and two tree processes for `--no-dumpable`, which is
the negative control: the sweeper can still fire, and the default is not
silently invisible.

## The content matrix

`matrix.tsv` is the per-case record. The rows that decide the comparison:

| launcher | comm | cmdline | environ | exe | same-uid mem |
|---|---|---|---|---|---|
| plain control | `payload` | real argv | 382 bytes | real binary | 2 hits |
| pmask default | `lblM1` | `lblM1` | 0 | real binary | 3 hits |
| pmask `--no-exact` | `lblM2` | `lblM2` plus spaces | 15-byte decoy | real binary | 3 hits |
| pmask `--no-dumpable` | `lblM3` | `lblM3` | `EACCES` | `EACCES` | refused |
| pmask `--rexec` | `lblM4` | `lblM4` | 0 | `/memfd:lblM4 (deleted)` | 3 hits |
| pmask `--keep-env=KEEP` | `lblM11` | `lblM11` | 19 bytes, `KEEP=...` | real binary | 3 hits |
| pmask `--exec-once` | `lblM18` | `lblM18` | 0 | `/dev/shm/.pmask-rexec-lblM18-...` | 1 hit |
| pmask 32-bit | none | none | none | none | refused |
| zapper | `payload` | `payload` plus NUL run | 382 bytes | real binary | 2 hits |
| mimic | `apache2` | `/usr/sbin/apache2 -k start` | 382 bytes | real binary | 2 hits |
| `exec -a` | `payload` | `fake-worker` plus real argv | 431 bytes | real binary | 2 hits |
| setproctitle | `worker` | `worker` plus NUL run | 386 bytes | `/usr/bin/python3.13` | 2 hits |

The pmask rows are the only ones that combine the label in `comm` and
`cmdline`, a zero or compact `environ`, and a tracer that refuses a
second attach. `--rexec` is the only row that also moves `exe` off the
real binary. `--no-dumpable` is the only row that closes the same-uid
memory read, and it is the row that creates the `EACCES` fingerprint and
the `hidepid` interaction. `--stealth` is the composition that picks one
of those two trades for the host.

The launch window is not closed by any of these. `window-default.txt`
measures a median 457 us for a script payload and 537 us for an ELF on
this host. `window-rexec.txt` and `window-stealth.txt` are the same
range, and the off-label `comm` in those runs is `memfd:<label>`, not the
real binary name. A tight same-uid poller can still catch the interpreter
name for a script payload. The window is a property of ptrace and is
documented, not claimed closed.

## Reproduction

The case runner is the audit archive's `harness/scripts/harness.py`.
The fast runner used here is a small Python wrapper that imports it and
replaces the detector list. The exact command for one case:

```sh
cd pmask-beta3-detection-audit
sudo python3 harness/scripts/harness.py --out out --only M1,M2,M11,M18
```

The hidden-pid check:

```sh
sudo unshare -m -p --fork --mount-proc sh -c '
  mount -o remount,hidepid=invisible /proc
  setpriv --reuid=1000 --regid=1000 --clear-groups -- pmask -q -l hid -- /bin/sleep 10 &
  sleep 0.7
  setpriv --reuid=1000 --regid=1000 --clear-groups -- unhide-noroot checkkill
'
```

The launch window:

```sh
cd pmask-beta3-detection-audit/harness/scripts
PMASK_BIN=/path/to/pmask WINDOW_ROUNDS=2 WINDOW_N=40 sh launch-window.sh
```

## Limits

The host's `/proc` is `hidepid=0`, so the default rows do not show the
`hidepid=invisible` interaction. The hidden-pid rows use the private
namespace described above. The `chkproc` binary scans four million pids
on this host and did not finish inside the per-case budget, so the
hidden-pid evidence uses `unhide checkkill`, which is the same
`kill(0)` view and is fast. The `--stealth` memory row is measured on
`hidepid=0`; the `hidepid=invisible` trade is a printed warning, not a
refusal. Root can read every mode, as the threat model says.
