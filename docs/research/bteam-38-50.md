reproducible: yes (`sh measurements/launch-window.sh`; the commands for every other measurement are quoted in the text)

# Issues 38, 47, 48 and 50: what changed, what was measured, what remains

Four b-team findings about the *shape* of a pmask session rather than the
contents of a redacted `/proc` entry. Three are documented design or a
measurement; one was a fixable fingerprint and is fixed.

Every number in this file was produced on the host that runs this worktree:

    Linux 6.12.113+deb13-amd64, Debian 13, x86_64, uid 1000,
    CapEff 0000000000000000, nproc 8, in LXC, ptrace allowed,
    kernel.yama.ptrace_scope = 0

A number without those conditions is not a claim, so the conditions are
repeated in each section. The date is the one the machine reports: the
evidence files under `evidence/bteam2/` carry the wall clock of the run.

Tagging: `[measured]` means a command was run here and its output is quoted
or filed under `evidence/bteam2/`. `[fixed]` means a code change removed the
observation. `[residual]` means the observation is still possible and is a
documented limit, not a bug.

---

## 38. The tracer thread name — fixed

**What it was.** The tracer thread was created as `pmask-tracer`
(`src/mask.rs`, `std::thread::Builder::new().name(...)`). Thread names live in
the task directory, which the label rewrite never reaches, so
`/proc/<supervisor>/task/*/comm` named the tool on every supervised tree.
Combined with `TracerPid != 0` and `Tgid != Pid` on the named task, that pair
identified pmask exactly. `strace` and `gdb` produce neither half.

**What changed.** The thread is now named after the session label, cut to the
kernel's 15-byte `comm` limit (`TRACER_COMM_MAX`), with a fallback chain:

The candidates are the session's `comm` (which is `--comm` when given,
otherwise the label cut to 15 bytes, and a single space when that is empty)
and then the label.  The `comm` wins, because that is what every process of
the session actually shows:

| session | thread name | why |
| --- | --- | --- |
| label `proc-evid`, no `--comm` | `proc-evid` | the normal case: comm = label cut to 15 |
| 40-byte label | the first 15, cut on a UTF-8 boundary | a longer name is refused whole by `pthread_setname_np` (`ERANGE`) and the thread would keep the name it inherited |
| `-l A --comm B` | `B` | `--comm` is what the supervisor and the payload show |
| empty (`--label-empty`) | a single space | that is the session comm the operator asked for, and it is a legal thread name |
| comm contains NUL | the label | the kernel would cut the name at the NUL |
| comm contains LF or CR | the label | a line-oriented reader would see two lines |
| comm and label both `pmask-tracer` | `pmask-trace` | the retired name must never return, whatever the operator labels a session |

The *live* process comm is deliberately not a candidate.  The runner path
(`--secret`) calls `Mask::spawn` before it applies the self-mask, so at that
moment the process still carries the pre-mask binary name.  An earlier
version of this fix read it as a third fallback and produced exactly the
wrong result: a session labelled `pmask-tracer` on the runner path named its
tracer thread `pmask`.  See "The runner path" below.

The result is never empty, never contains NUL, LF or CR, and is never
`pmask-tracer`. The helper and its unit tests are
`tracer_thread_name`/`comm_prefix`/`usable_comm`/`supervisor_comm` in
`src/mask.rs`; the call site is `Mask::spawn_prepared`.

**Measured** (`evidence/bteam2/38/repro-before.log` and
`repro-after.log`, `sh evidence/bteam2/38/repro-38.sh`):

```
before:  tracer comm=pmask-tracer  Tgid=55286 Pid=55288   pmask-tracer sightings: 1
after:   tracer comm=b2-38-proc-evid Tgid=60769 Pid=60771  pmask-tracer sightings: 0
```

The negative control is `evidence/bteam2/38/negative-control-old-binary.log`:
the same observer run against the pre-fix binary prints
`retired_name_sightings=2` and a tracer `comm` of `pmask-tracer`. The observer
is not blind; the name is gone.

**Residual** `[residual]`. The thread still exists, and it is still a thread:
on the payload, `TracerPid` names a task whose `Tgid` is the supervisor's pid,
and that task has no row of its own in `readdir("/proc")` or in `ps`. Measured
after the fix (`q38b`/`q38b2` in `tests/qa.d/38.sh`):

```
TracerPid=75336  Pid=75336  Tgid=75332   (Tgid != Pid)
TracerPid=75336 absent from readdir /proc
```

A detector that asks "is the tracer a thread?" still fires. It fires at a much
higher false-positive rate than the name did, because any threaded tracer
produces it, and it no longer tells pmask from any other threaded supervisor.
Removing it would mean tracing from a separate *process*, which is what
`AGENTS.md` invariant 1 rules out: `PTRACE_SEIZE` binds a child to the thread
that forked it, so a second process cannot take over the session.

**The daemon path.** `pmaskd` runs each job through the same `Mask::spawn`, so
it is the same call site and needed no second change. Measured
(`q38i`):

```
daemon pid=65499 comm=[b2-daemon-lab]
job payload cmdline=b2-job-label|
tracer comm=[b2-job-label]  Tgid=65499  Pid=65504
daemon tasks: 65499 [b2-daemon-lab]  65504 [b2-job-label]
pmask-tracer sightings=0
```

**The runner path (`--secret`) is a different call order, and it found a
defect in the first two versions of the fix.** The runner
(`src/run.rs`, `Mode::Redact`) calls `mask.spawn` *before* it applies the
self-mask to the supervisor, because the fork must see the real environment.
At that moment the process still carries the pre-mask binary name.

- Version 1 read only the live `comm` as its fallback. With `--label-empty`
  the thread was named `pmask`.
- Version 2 added the session comm as a middle candidate but kept the live
  comm as a third. That fixed the empty-label case and left the same bug for
  a session labelled with the retired string: `pmask-tracer` is not a usable
  thread name, and the next candidate was the live `pmask`.
- Version 3 drops the live comm entirely. `cfg.label_comm` *is* the
  supervisor's comm by construction, so nothing is lost.

Measured, `sh evidence/bteam2/38/repro-runner.sh`:

```
version 2 build, --label-empty --secret T=file:... :
  689688 [ ]        <- supervisor, self-masked to the blank label
  689713 [pmask]    <- tracer thread, named after the pre-mask binary

version 3 build:
  runner, plain label:        [b2-runner-label] [b2-runner-label]
  runner, empty label:        [ ] [ ]
  runner, retired-name label: [pmask-tracer] [pmask-trace]
```

`q38j` (empty label on the runner path) and `q38k` (`--comm` wins over the
label) pin the behaviour. The unit test
`tracer_thread_name_never_uses_the_live_pre_mask_comm` fails against version 2
and passes against version 3, which is the guard that stops this returning.

**Not changed.** `src/agent.rs` and the daemon's worker `std::thread::spawn`
calls create unnamed threads. They are not tracer threads and carry no
fingerprint; they keep the process's own `comm`, which is the label. Giving
them names would add a new observable, so they are left alone.

---

## 47. End states — documented design, one warning added

The four end states are the documented behaviour of `--detach`,
`--no-follow`, `--on-exit` and `PTRACE_O_EXITKILL`. The defaults are
unchanged. Measured (`evidence/bteam2/47/repro-47.log`,
`sh evidence/bteam2/47/repro-47.sh`):

| shape | measurement |
| --- | --- |
| `--detach` payload | `cmdline b2-47-detach\|`, `TracerPid 0`, `comm b2-47-detach`, `environ` 0 bytes |
| `--no-follow` direct child | `comm b2-47-nofollow`, `cmdline b2-47-nofollow\|` |
| `--no-follow` grandchild | `comm sleep`, `cmdline /bin/sleep\|5\|`, still traced |
| `--on-exit detach` orphan | `ppid 1`, `cmdline b2-47-orphan\|`, `TracerPid 0` |
| `--on-exit kill` | 0 survivors carrying the label |
| default, `SIGKILL` to the supervisor | payload gone (`PTRACE_O_EXITKILL`) |
| `--no-exit-kill`, same signal | payload alive, `TracerPid 0`, label kept |

**What changed.** One warning, at the release point. The session summary
already counted detaches, but it prints after the run. An operator watching
the payload never learned that this process, from now on, runs its own later
execs unredacted. The release now says so:

```
pmask: warning: --detach released pid 3233530 untraced; a later exec in that
process is not redacted
```

Measured (`q47c`): the line is present at the default verbosity, absent under
`-q`, absent without `--detach`. A watchdog that watched for the later exec
would need a tracer, which is what `--detach` gives up, so the release point
is the last moment the warning can be truthful. No watchdog was added.

**Residual** `[residual]`. A detached process that execs again is a fully
real process; the label it inherited before that exec is the only clue. A
detached process that execs a setuid binary also loses the label: the kernel
refuses setuid from a traced process and permits it from a detached one. Both
are the trade `--detach` documents, and the QA fragment asserts them as
documented rather than as closed.

---

## 48. The launch window and the statistical channels — measurement

Neither channel is a defect. Both are properties of ptrace supervision, and
both are now measured reproducibly by `measurements/launch-window.sh`.

**Host.** `Linux 6.12.113+deb13-amd64`, uid 1000, CapEff 0, nproc 8, LXC.
Command: `sh measurements/launch-window.sh` with `WINDOW_ROUNDS=3`,
`WINDOW_N=60`. Raw log: `evidence/bteam2/48/launch-window.log`.

### Spawn latency

Whole-invocation wall time per launch, 60 launches per round over 3 rounds.
This is the run filed as `evidence/bteam2/48/launch-window.log`:

```
SPAWN variant=plain  mean_ms=2.4321 median_ms=2.2101 p95_ms=3.9741
SPAWN-SPREAD variant=plain round_median_min_ms=1.8096 max_ms=2.7289 spread_pct=50.8 UNSTABLE
SPAWN variant=env-i  mean_ms=2.4592 median_ms=2.2758 p95_ms=3.5580
SPAWN-SPREAD variant=env-i round_median_min_ms=2.2368 max_ms=2.4127 spread_pct=7.9 STABLE
SPAWN variant=masked mean_ms=4.7341 median_ms=4.6723 p95_ms=5.5765
SPAWN-SPREAD variant=masked round_median_min_ms=4.5190 max_ms=4.7212 spread_pct=4.5 STABLE
SPAWN-RATIO masked_over_plain=2.11 masked_over_env_i=2.05
```

The plain row is marked UNSTABLE: the three round medians differ by 50.8 %,
because this machine is shared and a neighbouring load lands on the cheapest
measurement first. The `masked` rows are stable, and the masked median is the
same figure across runs (4.67-4.87 ms over the runs made here), so the ratio
moves with the denominator rather than with pmask. An earlier quieter run of
the same harness gave `masked_over_plain = 2.73` with every row STABLE;
both runs are on this host and neither number is more "true" than the other.

**Read the ratio, not the absolute.** The `env -i` row is the control for the
wrapper class: a bare `env` costs about 1.4x plain, so the pmask-specific part
is the ratio against `env -i`, about 1.9-2.1x. The spread column exists
because this is exactly the kind of number a single median hides.

### The launch window

A C sampler polls `/proc/<pid>/comm` in a tight loop, starting the moment the
launcher's first child appears. On this host it gets one sample every
3.3-3.5 us.

The sampler is repeated three times per row, because a single `/proc` scan
can take longer than the window and report a miss. The row quotes the median
of the attempts that caught a window, with the min and the max, and the
per-attempt lines are in the log:

```
masked, script payload: attempts=3 caught=3 median_off_label_us=307.606 min=257.949 max=394.224
masked, ELF payload:    attempts=3 caught=3 median_off_label_us=388.368 min=348.686 max=647.752
plain,  script payload: label_never_seen=1   sequence=env@44435>payload.sh@603525
plain,  ELF payload:    label_never_seen=1   sequence=env@44163>payload.elf@442806
```

The sampled comm sequences, from the attempts that saw a change:

```
payload.sh > win-...                     (the exec settled late in the trace)
win-... > payload.sh > win-...           (the full double transition)
win-... > payload.elf > win-...          (ELF payload, same shape)
```

The plain rows are the control: the masked run's label never appears for a
process that is not masked, so the off-label time above is the mask's window
and not an artefact of the sampler.

**The interval is genuinely noisy.** Across the runs made here the median
ranged from about 230 us to about 450 us for the same payload, and individual
attempts ranged from 39 us to 808 us. That is the instrument as much as the
window: the sampler finds the payload by scanning `/proc`, and a scan under
load costs a large fraction of the interval it is trying to measure. The
honest statement is *"the window is a few hundred microseconds on this host,
below a millisecond poller's resolution"*, which is what the issue says and
what these numbers support. A single run does not pin it tighter than that,
and the harness does not pretend to.

**Why the sampler is C and not shell.** A shell loop costs about 2 ms per
iteration on this host (measured during development: `cat /proc/<pid>/comm`
plus a `date +%s%N` per sample), which is longer than the window. A shell
sampler reports its own startup cost. Anyone reproducing the 747 us script
window quoted in the issue needs a sub-millisecond sampler; this one is.

**Nothing was changed** for this channel. The window is inherent: the label
is applied at the exec completion stop, so between `execve` and that stop the
process carries its real `comm`. A poller below about 1 ms can see it.

### Syscall signature

Two traces, because one is impossible:

1. **Startup**, `strace -qq -o FILE` without `-f` (traces the launcher only):

```
prctl(PR_SET_MM, PR_SET_MM_MAP, ..., 0x68, 0) = 0
prctl(PR_SET_NAME, "bench")                   = 0
prctl(PR_SET_DUMPABLE, SUID_DUMP_DISABLE)     = 0
clone3(..., 88)                               = <tracer tid>
```

2. **Sustained**, `strace -p <tracer-tid>` for 6 s of a payload that execs
`/bin/true` in a loop. Attaching needs `CAP_SYS_PTRACE` because the
supervisor made itself non-dumpable; the script uses `sudo -n` and quotes the
refusal when it cannot:

```
lines=60485
PTRACE_SYSCALL=11246  PTRACE_GET_SYSCALL_INFO=10442
PTRACE_GETREGSET=6426 PTRACE_SETREGSET=5621  PTRACE_CONT=3215  PTRACE_GETEVENTMSG=1608
process_vm_readv=6427 process_vm_writev=8030
```

**A finding, not a limitation:** `strace -f` on the launcher *breaks a
session* on this kernel. With `-f`, strace seizes the forked payload itself;
pmask's own `PTRACE_SEIZE` of that child is then refused, and the run dies:

```
FAILCHECK strace_f_breaks_a_session rc=255
ptrace(PTRACE_SEIZE, ..., PTRACE_O_TRACESYSGOOD|...|PTRACE_O_EXITKILL) = -1 EPERM
pmask: session error: Operation not permitted (os error 1)
```

This is kernel behaviour, not a pmask bug: a tracee can have one tracer, and
`-f` takes it. It matters for the threat model because a *monitoring* agent
that wants the syscall signature cannot get it by tracing pmask's children
either; it has to attach to the tracer thread (needing `CAP_SYS_PTRACE`) or
observe from the kernel.

**The documented mitigation for the launcher's argv** is `--args-from-fd`
(`man/pmask.1`, `src/cli.rs`): the vector is read from a descriptor, so the
program name and its arguments never enter pmask's own `/proc/<pid>/cmdline`.
Measured (`q48e`): the launcher's cmdline is `b2q48-...|` and the payload's is
the label; the marker appears in neither, while a plain process started with
the same vector does carry it (`q48f`). The vector still reaches the payload
intact through the descriptor (`q48e3`, `argc=4`).

The window for a *script* payload is the interpreter's own command line, which
`--args-from-fd` does not cover: the kernel writes the interpreter's argv when
it execs it. That is the honest limit of the mitigation.

---

## 50. The real argv stays in the payload's memory — documented limit

**Measured** (`tests/qa.d/50.sh`, reader `evidence`-built by the fragment):

```
CONTROL   plain holdargs: HIT region=... [heap]  HIT region=... [stack]  hits=2
DEFAULT   masked payload cmdline=b2q50-d-...|
          HIT region=... [heap]  HIT region=... [stack]  hits=2
SUPERVISOR rc=3 REFUSED maps: Permission denied
NODUMPABLE rc=3 REFUSED maps: Permission denied, payload still state=S, cmdline keeps the label
```

The reader walks the readable mappings of `/proc/<pid>/maps`, reads each
through `/proc/<pid>/mem` as the same uid, and looks for a unique marker
argument. The plain row is the negative control: if it could not find its own
marker, every zero below would be a blind reader.

**Residual** `[residual]`. In the default mode the payload's memory holds its
real argv, and a same-uid observer recovers it. pmask rewrites what `/proc`
*serves*; it does not erase the payload's stack or the presentation block the
supervisor created inside the tracee. Doing so would need the payload's own
cooperation after the exec, and a program that overwrites its argv cannot
guarantee its library has finished reading it.

**The mitigation is `--no-dumpable`**, and it is a whole-tree flag: the
payload's `/proc/<pid>/mem` and `maps` refuse the same uid, the payload keeps
running, and its label is intact. The cost is the one the flag documents: a
uniform `EACCES` on every `/proc` file of the tree is itself a signature, and
core dumps and debugger attach stop working.

**Also documented, and not closable from userland:** while the redaction is
written, the real argv and environment cross the supervisor's
`process_vm_writev` buffers in plaintext. The sustained syscall trace above
counts 8030 `process_vm_writev` calls in 6 s of a busy session, so the
channel is not a one-off. A kernel-side sensor, or `CAP_SYS_PTRACE` on the
tracer thread, sees those buffers. This is the same boundary as the launch
window: pmask hides what `/proc` reports, and a kernel observer is outside
that boundary.

---

## What a reader should take from this file

- Issue 38 is fixed: the retired name is gone, and the QA fragment proves it
  against the pre-fix binary as well as the fixed one.
- Issue 47 is design plus one warning at the `--detach` release point; the
  four end states are asserted as documented, and the defaults are unchanged.
- Issue 48 is a measurement. The numbers above are this host's; a different
  host gives different ones, and the harness prints its own conditions.
- Issue 50 is a limit with a flag that closes it. The default stays
  dumpable, because the EACCES signature and the loss of debuggers are a
  worse trade for the default deployment.

Four things in this file are new findings rather than issue text:

1. `strace -f` on a pmask launcher kills the session with `EPERM` on
   `PTRACE_SEIZE`. A syscall-level monitor has to attach per thread and needs
   `CAP_SYS_PTRACE`.
2. A shell-level `/proc/<pid>/comm` poller cannot measure the launch window:
   one sample costs about 2 ms here, longer than the window. The window
   figures in the issue (747 us for a script payload) need a C sampler to
   reproduce; this harness uses one.
3. The tracer thread's name must come from the session's configured comm, not
   from the live process comm: the runner path creates the thread before the
   self-mask, and the live comm there is the pre-mask binary name. The first
   two versions of the fix got this wrong; see the runner-path section.
4. `tests/isolation.sh` leaks its own control payload, and that makes
   `tests/edge.sh` fail intermittently. It is another suite's file, so it is
   reported in `evidence/bteam2/FINDINGS.md` rather than fixed here.
