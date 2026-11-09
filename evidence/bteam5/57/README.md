# Issue 57: eBPF sensors and the process connector

Host: Debian 13, `6.12.113+deb13-amd64`, x86_64, LXC container, uid 1000
with passwordless sudo. Binary: this branch (`pmask 0.1.0-beta.1`).
Research note: `docs/research/bteam-ebpf.md`. QA fragment:
`tests/qa.d/57.sh`.

Raw logs in this directory:

| file | what it is |
| --- | --- |
| `probe.log` | every route to eBPF/tracefs/connector, uid 1000 and root |
| `refusal.log` | the same, tightened: the exact refusal lines and a `/proc` substitute |
| `why-strace-cannot-substitute.log` | the second-tracer `EPERM`, isolated with a minimal C probe |
| `probe.sh`, `refusal.sh`, `substitute-strace.sh`, `why-strace-cannot-substitute.sh` | the scripts, re-runnable |

## Result

No eBPF program was loaded and no connector event was received: the
container refuses both for root as well as uid 1000.

```
bpf(BPF_MAP_CREATE) = -1 errno=1 (Operation not permitted)     # uid 1000 and root
perf_event_open(tracepoint) = -1 errno=13 (Permission denied)  # uid 1000 and root
ls /sys/kernel/tracing -> Permission denied                    # uid 1000 and root
mount -t tracefs ... -> permission denied                      # root, in a new mount ns
echo 1 > .../sched_process_exec/enable -> Permission denied    # root
cn_proc subscribe send -> errno=111 (Connection refused)       # uid 1000 and root
```

The state that decides it: `kernel.unprivileged_bpf_disabled=2`,
`kernel.perf_event_paranoid=3`, and the container's root is `1000000` in the
initial user namespace (`/proc/self/uid_map`), so `bpf_capable()` and
`perfmon_capable()` are false there even though `CapEff` is
`000001ffffffffff` inside the namespace. `bpftool`, `bpftrace`, `perf` and
`trace-cmd` are absent; installing them would not help, because the syscall
is refused before a loader runs. The unblock is the project's own guest
(`vm/run.sh`) or a host with those permissions.

## What the QA fragment decides here

```
SKIP e1-ebpf-map-create (bpf(BPF_MAP_CREATE) refused as uid 1000: refused -1 errno=1)
SKIP e2-process-connector (subscribe refused errno=111)
PASS e3-tracer-pid-names-the-tree (payload TracerPid=816557)
PASS e3b-supervisor-has-the-tracer-task
PASS e4-control-plain-process-has-no-tracer
SKIP e5-sched-process-exec-has-no-argv (tracefs not readable: Permission denied)
PASS e6-detach-zeroes-tracerpid
== QA57: PASS
```

The three SKIPs are the eBPF/connector cases and are never counted as
passes. The four PASSes are the channel that survives without eBPF: the
payload's `TracerPid` names a task of the tree, the supervisor has a task
literally named `pmask-tracer`, a plain process has neither, and `--detach`
zeroes `TracerPid` without making the seize unrecorded.

## The substitute, and what it does not establish

`strace` reads the same kernel tracepoints through ptrace rather than bpf,
so it would show the *shape* of the tracer-syscall channel.  It cannot be
used as a substitute here, for two separate reasons, both captured in
`why-strace-cannot-substitute.log`:

1. `strace -f` attaches to every child of the process it starts, so the
   child pmask forks is already traced and pmask's `PTRACE_SEIZE` gets
   `EPERM`:

   ```
   ptrace(PTRACE_SEIZE, 1090380, NULL, PTRACE_O_TRACESYSGOOD|...|PTRACE_O_EXITKILL) = -1 EPERM
   pmask: session error: Operation not permitted (os error 1)
   ```

   A minimal C probe reproduces the same `EPERM` without pmask in the
   picture (`PTRACE_SEIZE = 0` with no other tracer, `-1 EPERM` under
   `strace -f`), so the cause is "the target already has a tracer", not
   pmask's seize call.

2. A second tracer cannot attach to a running masked payload either:
   `strace -p <payload>` returns `ptrace(PTRACE_SEIZE, ...): Operation not
   permitted`.  The only way to see the tracer-syscall channel from
   userland is to be the first tracer, which is exactly what a sensor
   is not.

What userland *can* read, and what a sensor's two channels would tell it:

```
supervisor=1090612 payload=1090619
payload TracerPid=1090616
supervisor tasks:
  1090612 b57obs
  1090616 pmask-tracer
```

The `TracerPid` join and the `pmask-tracer` task name are the load-bearing
signals on this host, not an eBPF program.

There is a separate pmask observation in item 1 worth naming: a supervisor
started under a tracer cannot start its session, and it reports
`pmask: session error: Operation not permitted (os error 1)` with exit 255.
The message names the errno and not the cause; that is in the defect list
of the final report.

## Residual

* The eBPF rows in the issue are `[measured-guest]` and remain so; this
  host could not add to them.
* The process connector's exec event carries `process_pid` and
  `process_tgid` only, read from `/usr/include/linux/cn_proc.h` on this
  host. `PROC_EVENT_COMM` carries a 16-byte comm, but it is not generated
  by an exec, so it cannot serve as an argv channel.
* `--detach` removes `TracerPid` at rest; it does not remove the
  `PTRACE_SEIZE` a sensor would have seen, nor the `pmask-tracer` task.
