# eBPF sensors and the process connector against a masked exec

Scope: what a kernel-side observer can see of a `pmask` process tree, and
what this host allows of the attempt. Host: Debian 13, kernel
`6.12.113+deb13-amd64`, x86_64, LXC container, uid 1000 with passwordless
sudo. Raw output: `evidence/bteam5/57/` (`probe.log`, `refusal.log`,
`substitute-strace.log`).

This note answers issue #57. It does not restate the project's threat
model; it records the channel-by-channel result and the blocker.

## The blocker on this host, exactly

Every route to loading a program is refused, as uid 1000 and as root:

```
$ ls /sys/kernel/tracing
ls: cannot open directory '/sys/kernel/tracing': Permission denied
$ sudo -n ls /sys/kernel/tracing
ls: cannot open directory '/sys/kernel/tracing': Permission denied
$ sudo -n sh -c 'echo 1 > /sys/kernel/tracing/events/sched/sched_process_exec/enable'
sh: 1: cannot create .../enable: Permission denied                     rc=2
$ sudo -n sh -c 'echo "p:b57 __x64_sys_execve" >> /sys/kernel/tracing/kprobe_events'
sh: 1: cannot create /sys/kernel/tracing/kprobe_events: Permission denied   rc=2
$ sudo -n unshare -m sh -c 'mkdir -p /tmp/b57t && mount -t tracefs tracefs /tmp/b57t'
mount: /tmp/b57t: permission denied.                                    rc=32
$ sudo -n mount -o remount,mode=755 /sys/kernel/tracing
mount: /sys/kernel/tracing: permission denied.                          rc=32
```

The syscall-level probes agree, with a minimal C program rather than a
tool:

```
bpf(BPF_MAP_CREATE) = -1 errno=1 (Operation not permitted)     # uid 1000
bpf(BPF_MAP_CREATE) = -1 errno=1 (Operation not permitted)     # root
perf_event_open(tracepoint) = -1 errno=13 (Permission denied)  # uid 1000
perf_event_open(tracepoint) = -1 errno=13 (Permission denied)  # root
perf_event_open(software cpu-clock) = -1 errno=13              # both
```

The state that produces it:

```
kernel.unprivileged_bpf_disabled=2          # permanent, not a sysctl to flip
kernel.perf_event_paranoid=3
/proc/self/uid_map: 0 1000000 1000 ; 1000 1000 1 ; 1001 1001001 999998999
root CapEff: 000001ffffffffff   # full set in the container's own namespace
```

`bpf_capable()` and `perfmon_capable()` test the *initial* user namespace,
and this container's root is not root there: a `mount` of an unrelated
tmpfs succeeds inside the container's namespace while a `mount -t tracefs`
is refused, so the refusal is namespace-scoped rather than capability-set
scoped. `bpftool`, `bpftrace`, `perf` and `trace-cmd` are all absent
(`command not found`), but installing them would not help: the syscall
itself answers `EPERM`/`EACCES` before any tool's loader runs. That is why
this note does not install them.

Unblocking it needs a host (or a privileged VM) where
`perf_event_open` and `bpf` are permitted in the initial user namespace and
tracefs is mounted and writable — the project's `vm/run.sh` guest is one such
place, and the guest rows in the issue were measured there.

## What each channel carries, from source

Marked `[source]` where the statement comes from the kernel's own text and
not from an event captured on this host; marked `[measured-guest]` where it
comes from the issue's guest run.

### `sched_process_exec`

`[source]` The tracepoint is defined over `struct sched_process_exec`:
`__string(filename, bprm->filename)`, `pid` and `old_pid` (the pre-exec
tid). It fires in `exec_binprm()` → `sched_exec()`, i.e. **before** the
`PTRACE_EVENT_EXEC` stop that `pmask` uses to relocate the argument
window. It therefore carries the program file name and two pids, and never
argv or envp. `[measured-guest]` In the issue's guest run all ten exec events
of a masked tree showed `filename=` empty under bpftrace 0.23.3 — the pid
and `comm` fields were populated, so the empty `filename` is a rendering
limit of that bpftrace version, not evidence the field is absent.

Consequence for a detector: at the exec boundary it can learn *that* a pid
executed and what its `comm` was at that instant, but not the command line.
The masked `comm` is the label, so the event's `comm` matches the later
`/proc/<pid>/comm`; the discriminator is the later `cmdline` being exactly
that label while the exec name differs, which requires a `/proc` read
afterwards.

### `sys_enter_execve` / `sys_enter_execveat`

`[source]` The syscall tracepoints record the raw argument vector at entry,
from `syscall_get_arguments()`. The question is whether that read happens
before or after `pmask`'s rewrite, and the answer is that it happens after:
the syscall-entry path reports to a ptrace tracer (`ptrace_report_syscall_entry`)
and only then calls `trace_sys_enter()`, which is the probe point every
`sys_enter_*` tracepoint hangs from. So a `pmask` entry-swap, which happens
at the ptrace entry stop, has already rewritten the `argv`/`envp` pointer
arrays when a `sys_enter_execve` program reads them. The tracepoint reads
the swapped array — the label and the empty strings — and not the real one.
The exceptions are the documented post-exec paths (a `#!` script, a `vfork`
child, a settled process's later exec, a 32-bit image), where the kernel
sees the real array and the redaction happens at the completion stop; there
the tracepoint sees the real arguments for the duration of the exec.

That ordering is also why the channel is weaker than it first appears for a
defender: the one tracepoint that does carry argv is the one pmask has
already edited by the time it fires. It is a `[source]` claim and it
deserves a guest re-measurement: the falsifying observation is a
`sys_enter_execve` event whose argv bytes match an unsuperceded canary for
an entry-swapped exec.

### `sys_enter_ptrace`

`[source]` Carries `request` (the `PTRACE_*` op), `pid` (the target) and the
caller's pid, which is the tracer. `pmask` seizes with `PTRACE_SEIZE` and
its option set (`PTRACE_O_TRACESYSGOOD | TRACEFORK | TRACEVFORK |
TRACECLONE | TRACEEXEC | TRACEEXIT | EXITKILL`), so the op is 0x4206. This
is the channel that identifies the supervisor even when everything else
about the tree looks like a plain program. `[measured-guest]` The issue's
guest run recorded 47 `ptrace` events with `request=16902` (0x4206) from the
tracer's pid.

### `sys_enter_process_vm_writev`

`[source]` Carries the target pid and the caller's pid. `pmask`'s
`redirect_rename` and its remote-syscall injection write into the tracee;
each write is one event. `[measured-guest]` 16 events in the issue's second
probe, each with the tracer as caller and the payload as target.

This channel is weaker as a *pmask* discriminator than it looks:
`process_vm_writev` is emitted by runtimes, JITs, debuggers and language
VMs, so a rule must scope it to a pid that also shows `sys_enter_ptrace`,
or it is a false-positive generator.

### The process connector (`cn_proc`)

`[source]` `struct proc_event` in `include/uapi/linux/cn_proc.h` (present
on this host at `/usr/include/linux/cn_proc.h`, read in full for this note)
carries for `PROC_EVENT_EXEC` exactly `process_pid` and `process_tgid`. No
argv, no comm, no filename:

```c
struct exec_proc_event {
        __kernel_pid_t process_pid;
        __kernel_pid_t process_tgid;
} exec;
```

`PROC_EVENT_COMM` is a separate event and does carry `char comm[16]` — but
it is generated by `prctl(PR_SET_NAME)` and `set_task_comm()`, which is
exactly the call `--watch-rename` intercepts, and it is not generated by an
exec. So the connector gives a listener a pid pair per exec and, in the
`COMM` variant, a 16-byte task name; nothing that can distinguish a masked
exec from a plain one.

On this host the connector is unavailable at the socket call, as uid 1000
and as root:

```
subscribe send = -1 errno=111 (Connection refused)
```

`[source]` That is `cn_proc`'s `proc_cn_mcast_ops` returning `-ESRCH`/the
connector core refusing the id because no `cn_proc` handler is registered
in this namespace; the `cn_proc` module is not loaded and cannot be loaded
from inside the container. A listener therefore has no event stream to
measure here, which is the same conclusion the issue's own container run
reached. A listener on a host with `cn_proc` must use `poll()` with a
timeout; the issue records that a blocking read could not be stopped, which
is a defect in that harness and not in the interface.

## The substitute observation that does work here

eBPF is refused, but the ptrace relation is plain `/proc` data, and it is
what the two tracer-syscall channels would tell a sensor:

```
$ pmask -q -l b57tracer ./tests/testcases sleepfor 3 &
supervisor=498776 payload=498784
supervisor TracerPid=0                    # its own tracer, detached
payload    TracerPid=498782               # the tracer thread
supervisor task names:
  498776 b57tracer
  498782 pmask-tracer
```

Two facts a sensor gets from `sys_enter_ptrace` are visible without it: the
payload's `TracerPid` names a process inside the tree, and the supervisor
has a task literally named `pmask-tracer`. Neither is visible to an eBPF
program on this host, but both are visible from userland, which is why the
eBPF row is not the load-bearing one for detecting pmask.

## What could not be measured, and what would unblock it

* No eBPF program was loaded or attached. The blocker is named above; the
  fix is a host or guest with `bpf`/`perf_event_open` allowed in the
  initial user namespace and tracefs mountable. `vm/run.sh` is that guest.
* No process-connector event was received. The blocker is `ECONNREFUSED`
  from the connector core; the fix is a host with `cn_proc` available, or
  the same guest, plus a `poll()`-driven listener.
* The `filename` rendering under bpftrace 0.23.3 is unusable; a reader on
  another version should print `str(args->filename)` and a non-empty
  control before trusting the field.
* This note's `[source]` rows are read from the kernel's tracepoint
  definitions as quoted in `docs/DESIGN.md:434-437` and from the UAPI
  headers installed on this host. They are not records captured here.

## Detection logic that follows

```
# exec boundary: needs the later /proc read, because the event has no argv
tracepoint:sched:sched_process_exec {
    flag_if(comm == later_comm(pid) && later_cmdline(pid) == comm);
}
# the tracer, from its own syscalls
tracepoint:syscalls:sys_enter_ptrace {
    if (args->request == 0x4206) flag("PTRACE_SEIZE", pid, args->pid);
}
tracepoint:syscalls:sys_enter_process_vm_writev {
    if (caller_also_seized_something) flag("string shuttle", pid, args->pid);
}
# the connector adds nothing: pid/tgid only
```

## Residual

* `--detach` removes the payload's `TracerPid` at rest, so a sensor that
  only joins on `TracerPid` loses the tree after each exec settles. The
  `sys_enter_ptrace` channel does not: the seize already happened.
* A privileged eBPF sensor can read the write to the relocated block
  through `access_remote_vm`/the page-fault path even after the window is
  moved; that is a kernel-side row, not a channel this note measured.
* This host's `perf_event_paranoid=3` also refuses `perf record` for any
  process, so the substitute for a sampler is `/proc`, not `perf`.
