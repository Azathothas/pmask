# Issue 46: `--watch-rename` leaves a second seccomp filter and `NoNewPrivs=1`

Host: Debian 13, kernel `6.12.113+deb13-amd64`, uid 1000, LXC container.
Binary: this branch at `20716d0` + `tests/qa.d/46.sh`, `pmask 0.1.0-beta.1`.
Raw capture: `baseline.log` (`baseline.sh`, every row re-read below).

## What was measured

| row | `Seccomp` | `Seccomp_filters` | `NoNewPrivs` | `Name` | `TracerPid` |
| --- | --- | --- | --- | --- | --- |
| `--watch-rename -l proc-evid` | 2 | **2** | **1** | proc-evid | holder's tracer thread pid |
| the same payload, no flag | 2 | 1 | 0 | proc-evid | tracer pid |
| plain `/bin/sleep 5` | 2 | 1 | 0 | sleep | 0 |
| the supervisor itself | 2 | 1 | 0 | proc-evid | 0 |
| `--no-new-privs` alone | 2 | 1 | 1 | proc-evid | tracer pid |
| `--watch-rename --no-dumpable` | 2 | 2 | 1 | **other** | tracer pid |

Three repeats of the flag row all gave `filters=2 nnp=1 comm=proc-evid`, so
the pair is stable on this kernel and not a startup race.

The redirect itself: `testcases renamer` settles, calls
`prctl(PR_SET_NAME, "other")`, reports `renamer-comm=` and parks. With the
flag both `/proc/<pid>/comm` and the payload's own reading are `qa46-sec`
(the label); without it both are `other`. That control is what separates
"the observer sees the label" from "the payload never renamed itself".

## What the fragment asserts (`tests/qa.d/46.sh`)

```
PASS s1-watch-rename-filter-shape (filters=2 nnp=1 comm=qa46-label)
PASS s1b-control-without-the-flag (filters=1 nnp=0 comm=qa46-label)
PASS s1c-control-plain-process (filters=1 nnp=0 comm=sleep)
PASS s2-redirect-keeps-the-label (comm=qa46-sec, payload saw qa46-sec)
PASS s2b-control-rename-takes-effect (comm=other, payload saw other)
PASS s3-no-new-privs-alone-one-filter (filters=1 nnp=1 comm=qa46-label)
PASS s4-supervisor-row (filters=1 nnp=0 comm=qa46-label)
PASS s5-watch-rename-no-dumpable (defect #60 open: comm=other, payload=other,
                                   warning=pmask: warning: pid ...: cannot
                                   redirect a rename to the label)
== QA46: PASS
```

`s3` is the case that keeps the detection rule honest: `--no-new-privs`
alone gives `NoNewPrivs=1` with one filter, so a rule that fires on NNP
alone false-positives on the plain flag. The pair (filter count *and* NNP)
is what is flag-specific, and `comm == cmdline[0]` is what separates a
masking tool from a sandbox.

## The `--watch-rename --no-dumpable` dependency (issue #60)

`--watch-rename --no-dumpable` is a broken combination: the redirect is a
tracee memory write, and a non-dumpable tracee refuses it. Measured shape
on this branch:

```
$ pmask -l qa46nd --watch-rename --no-dumpable ./tests/testcases renamer
pmask: warning: pid 3399621: cannot redirect a rename to the label
renamer-comm=other
```

`/proc/<pid>/comm` is `other`; there is one warning per affected pid and no
nonzero exit. This is defect #60, owned by fix1. `qa/fix1` in this
repository currently has no commits beyond `qa-base` (`git log
--oneline qa/fix1` → `d2f331a`, `aaf9717`, `fa46e62`), so the fix is not
merged and the fragment asserts the current shape.

`s5` is written to accept either branch: a refusal (a payload that never
starts, with a message), a kept label (the fixed shape), or the current
`comm=other` plus the `cannot redirect a rename to the label` warning.
Anything else — a divergent `comm` with no warning — is a FAIL, because
that is a silent degradation (invariant 13). When fix1 merges, the s5 case
stays green and the branch it took is printed.

## Residual

* No code change for this issue: the filter is the documented mechanism.
  `man/pmask.1` already says `--watch-rename` implies `--no-new-privs`.
* The second filter is inherited by every process of the tree, so a
  defender counts it once per pid, not once per run.
* `Seccomp: 2` alone is common (every container runtime sets it); only
  `Seccomp_filters >= 2` is the discriminator, and `--no-new-privs`
  collapses the pair, so the rule needs both fields.
* A host that runs the payload under its own seccomp profile (Docker's
  default, systemd `SystemCallFilter=`) already has `Seccomp_filters >= 1`;
  pmask's flag adds one to whatever the sandbox installed, so the absolute
  number is not portable across hosts. The differential (same host, same
  payload, with and without the flag) is.

## Re-run, verbatim

```
$ sh tests/qa.d/46.sh
PASS s1-watch-rename-filter-shape (filters=2 nnp=1 comm=qa46-label)
PASS s1b-control-without-the-flag (filters=1 nnp=0 comm=qa46-label)
PASS s1c-control-plain-process (filters=1 nnp=0 comm=sleep)
PASS s2-redirect-keeps-the-label (comm=qa46-sec, payload saw qa46-sec)
PASS s2b-control-rename-takes-effect (comm=other, payload saw other)
PASS s3-no-new-privs-alone-one-filter (filters=1 nnp=1 comm=qa46-label)
PASS s4-supervisor-row (filters=1 nnp=0 comm=qa46-label)
PASS s5-watch-rename-no-dumpable (defect #60 open: ...)
NOTE s5 depends on issue #60 (fix1); this branch's qa/fix1 has no commits, so the open-defect shape is what was asserted here
== QA46: PASS
```
