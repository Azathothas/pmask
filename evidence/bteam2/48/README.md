# Issue 48: the launch window and the statistical channels

**Status: measured; no code change.** The harness is
`measurements/launch-window.sh` (new file), the numbers are in
`docs/research/bteam-38-50.md`, and `tests/qa.d/48.sh` pins the harness and
the documented mitigation.

Host: `Linux 6.12.113+deb13-amd64`, Debian 13, x86_64, uid 1000, CapEff 0,
nproc 8, LXC, `kernel.yama.ptrace_scope=0`. Compiler `cc` (gcc 14.2.0),
`strace` 6.x, passwordless `sudo` available for the tracer-thread attach.

## Files

| file | what it is |
| --- | --- |
| `repro-48.sh` | runs the harness at gate size, so this directory can be regenerated in under a minute |
| `repro-48.log` | one such run |
| `launch-window.log` | the full-length run quoted in the research note: 3 rounds of 60 launches, 6 s of sustained tracing |

## Commands

```sh
sh measurements/launch-window.sh                    # launch-window.log
WINDOW_ROUNDS=1 WINDOW_N=20 sh evidence/bteam2/48/repro-48.sh   # repro-48.log
sh tests/qa.d/48.sh                                # the QA fragment
```

## What it showed

Spawn latency, 60 launches per round over 3 rounds, whole invocation:

```
SPAWN variant=plain  mean_ms=1.8032 median_ms=1.7117 p95_ms=2.4237
SPAWN variant=env-i  mean_ms=2.5682 median_ms=2.4986 p95_ms=3.0426
SPAWN variant=masked mean_ms=4.8712 median_ms=4.6726 p95_ms=5.7500
SPAWN-RATIO masked_over_plain=2.73 masked_over_env_i=1.87
```

Launch window, a C sampler at one sample per 3.3-3.5 us:

```
WINDOW variant=masked payload=script ... off_label_total_us=457.888 sequence=payload.sh@2005208>win-...@2463096
WINDOW variant=masked payload=elf    ... off_label_total_us=424.716 sequence=win-...@3257889>payload.elf@3430694>win-...@3855410
WINDOW variant=plain  payload=script ... label_never_seen=1 sequence=env@47739>payload.sh@582633
WINDOW variant=plain  payload=elf    ... label_never_seen=1 sequence=env@47607>payload.elf@384612
```

Syscall signature, launcher startup (`strace -qq`, no `-f`):

```
prctl(PR_SET_MM, PR_SET_MM_MAP, ..., 0x68, 0) = 0
prctl(PR_SET_NAME, "bench")                   = 0
prctl(PR_SET_DUMPABLE, SUID_DUMP_DISABLE)     = 0
clone3(..., 88)                               = <tracer tid>
```

Sustained, `strace -p <tracer-tid>` for 6 s:

```
lines=58765 PTRACE_SYSCALL=10834 PTRACE_GET_SYSCALL_INFO=10060
PTRACE_GETREGSET=6191 PTRACE_SETREGSET=5418 PTRACE_CONT=3096
PTRACE_GETEVENTMSG=1548 process_vm_readv=6192 process_vm_writev=7740
```

## Two findings the issue did not name

1. **`strace -f` on a pmask launcher kills the session.**

   ```
   FAILCHECK strace_f_breaks_a_session rc=255
   ptrace(PTRACE_SEIZE, ..., PTRACE_O_TRACESYSGOOD|...|PTRACE_O_EXITKILL) = -1 EPERM
   pmask: session error: Operation not permitted (os error 1)
   ```

   With `-f` strace seizes the forked payload, so pmask's own seize of that
   child is refused. A syscall-level monitor has to attach per thread, and
   that attach needs `CAP_SYS_PTRACE` because the supervisor is non-dumpable.
   The harness tries `sudo -n` and quotes the refusal where it cannot.

2. **A shell-level `/proc/<pid>/comm` poller cannot measure the window.**
   One sample (a `cat` plus a `date +%s%N`) costs about 2 ms here, longer
   than the interval being measured. A shell sampler reports its own startup
   cost. The harness compiles a C sampler.

## Not covered

- Tracefs and eBPF are blocked in this container even for root; a
  kernel-side sensor is described from the syscall trace, not run.
- The script payload's interpreter argv (`/bin/sh /path/script.sh`) is the
  part `--args-from-fd` cannot remove, because the kernel writes it when it
  execs the interpreter. The harness measures the window but cannot close it.
