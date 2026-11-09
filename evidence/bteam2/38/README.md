# Issue 38: the tracer thread name

**Status: fixed.** Commit `1f9a2e7` (`fix: name the tracer thread after the
session label`).

Host for every log here: `Linux 6.12.113+deb13-amd64`, Debian 13, x86_64,
uid 1000, CapEff 0, LXC, `kernel.yama.ptrace_scope=0`. Binaries:
`target/release/pmask` from this worktree, built with
`cargo build --release --bins --features testbins`.

## Files

| file | what it is |
| --- | --- |
| `repro-38.sh` | the reproducer: one default session, its tracer task, and a host-wide sweep for the retired name |
| `repro-before.log` | that reproducer against the unmodified tree: `pmask-tracer` found, `Tgid != Pid` on the tracer |
| `repro-after.log` | the same run after the fix: the tracer comm is the label, the sweep finds nothing |
| `negative-control-old-binary.sh` | the negative control: the same observer against a pre-fix binary |
| `negative-control-old-binary.log` | its output: it *does* find the retired name, so the zero in `repro-after.log` is not a blind observer |
| `repro-runner.sh` | the runner path (`--secret`), where `spawn` runs before the self-mask |
| `repro-runner.log` | its output: three labels, one of them the retired name |

## Commands

```sh
sh evidence/bteam2/38/repro-38.sh          # repro-after.log
sh tests/qa.d/38.sh                        # the QA fragment
```

```sh
sh evidence/bteam2/38/negative-control-old-binary.sh /path/to/pre-fix/pmask
```

The pre-fix binary is built in a scratch copy of the worktree, from the
commit before the fix:

```sh
git show d2f331a:src/mask.rs > src/mask.rs
cargo build --release --bin pmask
```

It is not kept in the worktree.

## What it showed

Before (raw, `repro-before.log`):

```
supervisor=55286 payload=55289
TracerPid:	55288
Name:	pmask-tracer
Tgid:	55286
Pid:	55288
pmask-tracer sightings: 1
```

After (`repro-after.log`):

```
supervisor=60769 payload=60772
TracerPid:	60771
Name:	b2-38-proc-evid
Tgid:	60769
Pid:	60771
pmask-tracer sightings: 0
```

The `Tgid != Pid` pair survives. That is the residual, documented in
`docs/research/bteam-38-50.md`.

## Daemon path

`src/daemon.rs` and `src/bin/pmaskd.rs` contain no second thread-name site.
`pmaskd` builds every job through `daemon::run_job` -> `Mask::spawn`, which is
the same call site the CLI uses, and its other threads
(`std::thread::spawn` in `accept_loop`'s worker fork and in `agent.rs`) are
unnamed, so they carry the process's own comm, which is the label. The QA
fragment's `q38i` cases cover the daemon path end to end:

```
daemon tasks: 65499 [b2-daemon-lab]  65504 [b2-job-label]
pmask-tracer sightings=0
```

## A defect the fix found on its own second pass

The runner path (`--secret`) calls `Mask::spawn` *before* the self-mask,
because the fork has to see the real environment.  At that moment the process
still carries the pre-mask binary name.

- The first version read only the live `comm` as its fallback: with
  `--label-empty` the tracer thread was named `pmask`.
- The second added the session comm as a middle candidate but kept the live
  comm as a third: that fixed the empty-label case and left the bug for a
  session labelled with the retired string, because `pmask-tracer` is not a
  usable thread name and the next candidate was again `pmask`.
- The third drops the live comm.  `cfg.label_comm` *is* the supervisor's comm
  by construction, so nothing is lost.

Measured with `sh evidence/bteam2/38/repro-runner.sh`, filed as
`repro-runner.log`:

```
--- runner, plain label:         [b2-runner-label] [b2-runner-label]
--- runner, empty label:         [ ] [ ]
--- runner, retired-name label:  [pmask-tracer] [pmask-trace]
--- CLI, empty label:            [ ] [ ]
```

The second-version output, kept for contrast:

```
 689688 [ ]        supervisor, self-masked to the blank label
 689713 [pmask]    tracer thread, named after the pre-mask binary
```

`q38j` (empty label on the runner path), `q38k` (`--comm` wins over the label)
and the unit test `tracer_thread_name_never_uses_the_live_pre_mask_comm` pin
this; that test fails against the second version and passes against the third.

## Not covered

- The tracefs / eBPF route to the same observation is blocked in this
  container (see `/workspace/meta/ISSUE-MAP.md`); the `/proc` observer is the
  one the issue names, and it is the one measured.
- A host-wide sweep is reported beside every in-session count but is not
  asserted: a neighbour agent's unreleased build running the old binary on
  the same host is a different session and would make the fragment fail for
  the wrong reason.
