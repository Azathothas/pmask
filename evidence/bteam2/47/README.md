# Issue 47: end states

**Status: documented design, with one warning added.** Commit `2c3d850`
(`fix: warn when --detach releases a tracee untraced`). The defaults are
unchanged; no watchdog was added.

Host for every log here: `Linux 6.12.113+deb13-amd64`, Debian 13, x86_64,
uid 1000, CapEff 0, LXC, `kernel.yama.ptrace_scope=0`. Binaries:
`target/release/pmask`, `target/release/pmask-testcases`.

## Files

| file | what it is |
| --- | --- |
| `repro-47.sh` | one section per end state, plus a control for each shape that could otherwise be vacuous |
| `repro-47.log` | the output of that run |

## Commands

```sh
sh evidence/bteam2/47/repro-47.sh   # repro-47.log
sh tests/qa.d/47.sh                # the QA fragment
```

## What it showed (raw, `repro-47.log`)

```
================ --detach end state
payload=2944403
cmdline: b2-47-detach|
TracerPid:	0
comm: b2-47-detach
environ bytes: 0
================ --no-follow
pid=2963538 comm=b2-47-nofollow cmdline=b2-47-nofollow| tracer=2963537
pid=2963545 comm=sleep cmdline=/bin/sleep|5| tracer=2963537
================ --on-exit detach (orphan)
orphan pid=2967411 ppid=1 cmdline=b2-47-orphan| tracer=0
================ --on-exit kill (control)
survivors=0
================ default exit-kill: SIGKILL the supervisor
payload gone after supervisor SIGKILL
================ --no-exit-kill: SIGKILL the supervisor
payload ALIVE after supervisor SIGKILL; tracer=0 cmdline=b2-47-survive|
```

The `--no-follow` section of the log also lists `pid=2963704 comm=sleep
cmdline=sleep|480| tracer=0`: that is an unrelated process on the shared host
(another agent's), included because the reproducer's sweep is host-wide. The
two `b2-47-nofollow`/`tracer=2963537` rows are this run.

The `--detach` warning, at the release point:

```
pmask: warning: --detach released pid 3233530 untraced; a later exec in that
process is not redacted
pmask: 1 tracee(s) left detached after their exec (--detach: their later
execs are not redacted)
```

The first line is new; the second is the existing session summary. Both are
absent under `-q` and absent without `--detach`.

## Why no watchdog

Watching for the later exec of a detached process needs a tracer, and giving
up the tracer is exactly what `--detach` does. A watchdog would either
re-attach (defeating the flag) or be a promise the code cannot keep. The
release point is the last moment a truthful warning exists, so that is where
it is printed.

## Traps found while writing the fragment

- `--detach` with `sleep` left a payload from an earlier manual run on the
  host (`sleep 300`); every label in the fragment is unique to the run and
  the sweeps exclude this shell, so the fragment's counts are its own.
- The first version of `q47b` was missing its trailing `&`, so the fragment
  blocked on the pmask run instead of backgrounding it. Fixed; the fragment
  now completes in about 12 s.
