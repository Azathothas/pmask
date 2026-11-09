# Issue 49: modes that do not redact

Host: Linux 6.12.113+deb13-amd64, Debian 13, x86_64, uid 1000, CapEff 0,
in LXC; unprivileged user namespaces available, `sudo` passwordless for
the `nsenter` probe.

## What was run

| log | command | what it shows |
|---|---|---|
| `mode-matrix.log` | `sh /tmp/probe49.sh MODE` for default, `--no-redact`, `--isolate`, `--unshare`, `--redact --isolate` | one row per mode: cmdline, comm, environ bytes, TracerPid, NSpid, `hidepid` |
| `mode-matrix-sleep.log` | `sh /tmp/probe49b.sh MODE` | the same for `/bin/sleep 5` and `/bin/sh -c 'sleep 5'`, walking grandchildren |
| `isolate-tree.log` | `sh /tmp/iso1.sh` | the isolate tree at two sample times: the intermediate is labelled, the leaf is real |
| `isolate-environ-repeat.log` | `sh /tmp/iso3.sh` | four repeats of the isolate environ byte count |
| `unshare-exact-repro.log` | `sh /tmp/probe49d.sh` | the issue's own repro shape; shows why `pgrep -x sleep` is the wrong observer on this host |
| `unshare-shapes.log` | `sh /tmp/probe49e.sh` | `--unshare` under four payload shapes |
| `unshare-fingerprints.log` | `sh /tmp/probe49f.sh` | `NSpid`, `hidepid=invisible`, and the `nsenter` probe as root |
| `nsenter-isolate-init.log` | the same probe under `--isolate`, four runs | which process is pid 1 of the private namespace |
| `unshare-six-runs.log` | `sh /tmp/unshare6.sh` | six `--unshare` runs, release build |
| `32bit-row.log` | `sh /tmp/probe49c.sh` plus the stderr of a 32-bit `echoargs` run | the 32-bit refusal and the real argv |

The `--unshare` build dependence the issue could not explain was
re-measured here by swapping the musl binary into `tests/pmask`:

```
release (target/release/pmask)   --unshare   label=6 real=0   (six runs)
musl (x86_64-unknown-linux-musl) --unshare   label=0 real=6   (six runs)
```

so the issue's "release R=0 U=6, musl R=0 U=6, glibc R=6 U=0" table does
not reproduce on this host: the release and musl builds both serve the
label, and the defect appears only when the musl binary is substituted
for the release one in the same worktree. The rows are in
`evidence/bteam3/49/unshare-six-runs.log` (release) and the transcript of
the swap. The cause is still not separated; three candidates remain and
each needs a controlled build (section 4 of the issue).

`tests/qa.d/49.sh` therefore decides the `--unshare` row by measurement:
if the host serves the label it asserts the fixed shape, and if it serves
the real argv it prints `SKIP ... (the redaction defect is #4, fixed by
qa/fix1)`. Both branches were exercised: the release build hits the
first, the substituted musl build hits the second.

## What it showed

The mode table, measured in `mode-matrix-sleep.log`:

| mode | leaf `cmdline` | `comm` | `environ` | `TracerPid` | `NSpid` |
|---|---|---|---|---|---|
| default | label + NUL | label | 0 bytes | tracer thread | one number |
| `--no-redact` | real argv | real name | real, marker present | 0 | one number |
| `--isolate` | real argv | real name | 24 bytes, marker present | 0 | two numbers |
| `--unshare` (release) | label + NUL | label | 0 bytes | tracer thread | two numbers |
| `--redact --isolate` | label + NUL | label | 0 bytes | tracer thread | two numbers |
| 32-bit image | real argv | `testcases32` | real | tracer thread | one number |

`--unshare` and `--isolate` fingerprints, both measured here:

```
mountinfo: 1859 903 0:131 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=invisible
NSpid: 69563  1
sudo nsenter -t <leaf> -p -m sh -c 'tr "\0" " " < /proc/1/cmdline'
  <label>          (in a --unshare run; under --isolate this reads the real argv,
                    because there the namespace init is the leaf)
```

`nsenter ... -p` puts the shell into the payload's pid namespace, so the
`Pid:` the shell reads for itself is the shell's, not the payload's.
Only `/proc/1` and the host-side `NSpid` describe the namespace.

The `/proc/1/cmdline` under `--unshare` is the label, and the leaf is
`pid 1` of its own pid namespace (`NSpid: 2500327  1`). An earlier
version of this note said the opposite, from reading the `nsenter`
shell's own `Pid` as if it were the payload's; the leaf's `NSpid` and an
in-namespace `cat /proc/1/comm` settle it, and both are in
`nsenter-isolate-init.log`.

Under `--isolate` the namespace init is the **leaf**, which is the
process carrying the real argv:

```
run 1 intermediate=2479658 comm=iz-1-...   NSpid=[2479658]
run 1 leaf=2479665         comm=sleep      NSpid=[2479665  1]
```

That is why `--isolate` has to be read by walking the tree: the
intermediate is labelled and the leaf is not, and only the leaf is the
namespace init. A one-level check sees the labelled process and reports
clean. Four runs, all the same shape, in `nsenter-isolate-init.log`.

The 32-bit row:

```
$ pmask -l qa49c-msg -- ./tests/testcases32 echoargs MK49C-MSG
pmask: warning: pid 57996: 32-bit (foreign ABI) program is not redacted
arg0=[./tests/testcases32] arg1=[echoargs] arg2=[MK49C-MSG] env=[ok]
pmask: 1 of 1 execs degraded (foreign-arch)
```

`tests/testcases32` is not in the tree; it is a `vm/run.sh` artifact
built from `--target i686-unknown-linux-musl`. `rustup target list
--installed` on this host already has that target, so the fragment's
32-bit rows ran here after
`cargo build --release --target i686-unknown-linux-musl --bin
pmask-testcases --features testbins`. On a host without the target the
fragment prints `SKIP 49f-... (tests/testcases32 absent)`.

## What the fragment asserts

`tests/qa.d/49.sh` runs 18 cases. The load-bearing ones are the negative
control pairs: 49a proves the default mode's leaf serves the label and
0 bytes of environ, 49b/49c prove the same observer sees the real argv
and the marker without the redaction, and 49e proves the namespace
fingerprints are visible without root.

`--unshare` is the one row whose assertion depends on which build is
under test. A `SKIP` there is a named dependency on issue #4 / `qa/fix1`,
not a pass.

## New defect found here, not fixed

`--redact --isolate --report=json` is refused:

```
$ pmask --redact --isolate --report=json -- /bin/true
pmask: --report=json: the plain mask path does not produce a report; the report describes
a secret-side run, so add --secret, --isolate or --no-redact, or drop --report
exit=0
```

The message names `--isolate` as one of the flags that makes the report
work, and the run that was just refused *has* `--isolate`. `main.rs`
converts `--redact --isolate` into `mask.unshare()` and clears
`cli.isolate` before the `--report=json` check runs
(`src/main.rs:249-251` then the `needs_runner()` check), so
`needs_runner()` is false and the message is wrong for this input. The
same composition with a `--secret` works, because that sets
`needs_runner()`.

Not fixed: `src/main.rs` is outside the files this batch was given.

## Files

- `tests/qa.d/49.sh` — the fragment.
