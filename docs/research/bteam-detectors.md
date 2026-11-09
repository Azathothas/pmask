# The detector family that does not see pmask

Scope: the rootkit / hidden-pid checkers, measured against this build where
the tool could be obtained from a trusted source, and decided
structurally where it could not. Host: Debian 13,
`6.12.113+deb13-amd64`, x86_64, LXC container, uid 1000 with passwordless
sudo. Raw output: `evidence/bteam5/58/`. QA fragment: `tests/qa.d/58.sh`.

## The structural reason the family is blind

Every tool in this family compares two views of the pid space:

* a raw `getdents64` over `/proc` against a cooked `readdir`;
* a `ps` table against a direct `/proc/<pid>` path;
* a syscall that requires the pid to exist (`kill(pid, 0)`,
  `getpriority`, `sched_getaffinity`) against a listing.

pmask hides no pid. It keeps the pid, the `/proc/<pid>` directory, the
parent chain, the `TracerPid` record (unless `--detach`) and the
`readdir` result. What it rewrites is the *contents* of three files:
`cmdline`, `environ` and `comm`. A checker that only asks "does this
entry exist in both views" therefore has no input from a masked process
that differs from an unmasked one, and it cannot fire.

Measured on a live masked payload (`tests/testcases procviews`, which reads
`getdents64` directly rather than through libc):

```
pid=1999609 getdents64=present readdir=present stat=present kill0=present
```

and the same four views for an unmasked canary (`d2` in the fragment), so
the equality is a property of the host, not of the mask:

```
pid=2003509 getdents64=present readdir=present stat=present kill0=present
```

The masked payload's content at that moment was `comm=[b58view]`,
`cmdline=[b58view|]`, parent `PPid=1999601` (the supervisor). A tool that
printed the hidden process's `cmdline` would print the label; none of these
tools reaches that code, because the decision never says "hidden".

## What was measured, per tool

| tool | obtained | result |
| --- | --- | --- |
| `unhide` (20240510, Debian) | extracted, not installed | `sys`, `checkkill`, `checkgetprio`, `proc`: no pmask pid in the hidden set; exit 0; no finding line |
| `chkproc` (chkrootkit 0.58b, Debian) | extracted, not installed | the payload and the supervisor are never named; the bulk count is a host artefact (below) |
| `rkhunter` 1.4.6 (Debian) | extracted, not installed | `Checking for hidden processes [ None found ]`, with and without a masked tree |
| `strace` | on the host | control attaches; a masked payload and the supervisor both refuse `PTRACE_SEIZE` |
| `sandfly-processdecloak` | not obtained | no Debian package; upstream is a GitHub release. SKIP |
| `pspy` | not obtained | no Debian package. SKIP |
| `zapper` | not obtained | no Debian package. SKIP |
| `lsrootkit` | not obtained | no Debian package. SKIP |

How the three obtained tools were fetched, and what was deliberately not
done, is in `evidence/bteam5/58/install-notes.log`: `apt-get download` from
the configured Debian archive plus `dpkg-deb -x` into a private directory.
Nothing was installed into a system path, and no upstream release tarball
was fetched.

## The bulk count is a host artefact, and that matters

`chkproc` prints a count of "process(es) hidden from readdir(3)". On this
host that number is between 43 and 51 with **no pmask process running at
all**:

```
control: no pmask, three samples      -> 47, 43, 44      (`measure.log`)
masked:  one pmask tree, three samples -> 48, 48, 51
```

The cause is this container's process tree, not pmask: 23 of the 47 named
pids are threads of one process (`Tgid != Pid`), and `chkproc`'s `ps -edf`
parse does not list them. The pid set is stable between runs
(`hidden-control.txt`, 47 entries), and neither the supervisor nor the
payload ever appears in it (`setdiff.log`):

```
supervisor in the hidden set: no
payload in the hidden set:    no
```

So the fragment asserts the pid set, not the count. A detector written
against the count alone would fire on this container with nothing masked,
which is the same false-positive shape the issue warns about.

One incidental finding, recorded because it is a real usable signal: this
host's `/proc` readdir hides a live thread id from an unprivileged reader
(`143`, `Tgid=122`), while `stat` and `kill(0)` find it. That is a
kernel/container property and has nothing to do with pmask; it is also
exactly the kind of divergence this family *is* good at, which is why the
family's silence about pmask is informative rather than accidental.

## The one member that is not blind: `strace`

`strace` is a legitimate tracer, and it fails against a masked tree for a
reason that has nothing to do with the family's views:

```
$ strace -p <unmasked canary>            -> strace: Process ... attached
$ strace -p <masked payload>             -> strace: attach: ptrace(PTRACE_SEIZE, ...): Operation not permitted
$ strace -p <pmask supervisor>           -> strace: attach: ptrace(PTRACE_SEIZE, ...): Operation not permitted
```

A pid can have one tracer. pmask's supervisor holds each tracee, and the
supervisor is non-dumpable, so a second tracer is refused. `Tgid == Pid`
separates a masked payload from a many-threaded one; `TracerPid` names a
process inside the tree rather than an external debugger. That is a
content/relationship rule, not a hidden-pid rule, and it belongs with the
other content detectors.

## `pspy` and the sampling limit

`pspy` is a poller: it reads `/proc` on an interval and prints new pids'
`cmdline`. Its output would be the label for any payload that lives longer
than the interval, so it is a weak *content* detector and not a
hidden-pid checker. It was not obtained here (no Debian package), so the
case SKIPs; the issue's own measurement (15-16 label lines over 8 ELF runs,
and 20 of 20 zero-second controls missed) is the record for it.

## `zapper` and `lsrootkit`

Neither is a checker of pmask. `zapper` is a competing masking tool: the
project already publishes the comparison
(`README.md:429-431`, `measurements/vs-zapper.sh`), and its shape differs
(zapper leaves `comm` untouched and a 164-175 byte NUL run; pmask moves the
window and empties `environ`). `lsrootkit` tests a magic-gid / magic-signal
rootkit hook; on a container its gid sweep reports the container's gid map
as findings, which is a false positive with nothing masked. Both cases SKIP
here with that reason.

`rkhunter`'s `hidden_procs` is not an implementation: it shells out to
`unhide sys`. Measured with `unhide` on `PATH` and a config file:

```
Checking for hidden processes                            [ None found ]
```

with and without a masked tree, and with an unmasked canary also present.
Without `unhide` on `PATH` and in the tool's own `PATH` under `sudo`, the
test prints `[ Skipped ]` and reports "No warnings were found", which is a
green-looking result that measured nothing. That is worth stating for a
reader who runs rkhunter from a cron job and reads only the summary line.

## Residual

* Four tools (processdecloak, pspy, zapper, lsrootkit) were not run here.
  Their rows in the issue are third-party behaviour on the evaluation host
  and remain that. Running them needs a trusted source for each; the
  fragment accepts them through `PMASK_QA_TOOLS`.
* `unhide brute`, `quick` and `procall` were attempted and did not finish
  inside a 10-minute limit on this container; only `sys`, `proc`,
  `checkkill` and `checkgetprio` are in the measured set. The modes that
  did run are the ones a hidden-pid detector would use first.
* The bulk-count baseline (43-51) is this container's. A host without
  per-thread slack in its `ps` output would show closer to zero, and then
  the *count* would also be meaningful. The pid-set assertion is portable;
  the count is not.
* `hidepid=2` is a host control, not a tool in this family: it removes the
  cross-account view and leaves the owning uid's residue set. It was not
  remounted here, because a shared container's `/proc` is not this
  worktree's to change.
* `lsrootkit` does not compile here at all in the issue's record
  (`SIGUNUSED`); that is a tool defect, and this note adds nothing to it.
