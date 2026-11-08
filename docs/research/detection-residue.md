reproducible: no (source: measured 2026-11-03 on Linux 6.12.113+deb13-amd64, Debian 13, x86_64, uid 1000, in LXC; the commands are quoted in the text)

# The residue no userland rewrite can remove

One row per interface. Each row states what the interface exposes, and the
condition under which it reveals that the published name is not the real one.
Every measurement is from this host: Linux 6.12.113+deb13-amd64, Debian 13,
x86_64, uid 1000, CapEff 0, no `hidepid`, in LXC.

Tagging: `[observed]` means a command was run here and its output is quoted.
`[inferred]` means it follows from that output or from kernel source read in
this session, without being exercised. `[reported]` means the row rests on
the source read recorded in `survey-2025/review/`, not on a measurement here.

The rewrite under test is pmask at `target/release/pmask`, run as uid
1000, plus two hand-written variants from `detection-measured.md`: an in-place
zero-fill, and a `PR_SET_MM_MAP` relocation.

---

## The table

| # | interface | what it exposes after a rewrite | condition that reveals the truth | tag |
| --- | --- | --- | --- | --- |
| 1 | pid and parent chain | the pid exists, and `stat` field 4 names its real parent | the parent's `exe` and the child's `exe` disagree with the child's `argv[0]`; a labelled child of a labelled parent makes the whole chain read `ci-runner` | `[observed]` |
| 2 | cgroup | `0::/.lxc`, unchanged by any rewrite | the cgroup of a labelled pid is compared with the cgroup of the service that should own it, or with a recorded baseline | `[observed]` |
| 3 | fds | real targets: `/tmp/residue.file`, `socket:[4879960]`, `/memfd:residue-secret (deleted)` | opening `/proc/<pid>/fd` lists paths whose names have nothing to do with the label | `[observed]` |
| 4 | sockets | the listening port appears in `/proc/net/tcp` with the owning uid and inode | the inode from `/proc/<pid>/fd` is looked up in `/proc/net/tcp`; the port and the uid are real | `[observed]` |
| 5 | start time | `stat` field 22, unchanged | a process whose `starttime` precedes the label's own creation, or whose uptime is longer than the claim | `[observed]` |
| 6 | TracerPid | 0 for an untraced process, and non-zero for a traced one | a process that is being ptraced reports the tracer's pid regardless of what it publishes about itself | `[observed]` |
| 7 | audit | `loginuid` is `4294967295` (unset) here; the kernel writes the `EXECVE` record from `mm->arg_start` at syscall exit, after the exec stop and the relocation, so it carries the label | a record written before the relocation would carry the real `argv`; the source ordering described in `../DESIGN.md` puts the write after `PTRACE_EVENT_EXEC` and before the ptrace syscall-exit stop | `[observed]` for `loginuid`, `[inferred]` for the record |
| 8 | eBPF | nothing is hidden from a kernel-side probe of `execve`, of `access_remote_vm`, or of the write itself | a uprobe or kprobe sees the real arguments at the syscall boundary and the real strings in memory | `[inferred]` |
| 9 | same-uid memory reads | the original `argv` and `environ` strings are still in `[stack]` after every rewrite measured here | `/proc/<pid>/mem` read as the same uid finds them; refused only with `PR_SET_DUMPABLE=0` | `[observed]` |
| 10 | AT_EXECFN | under pmask it is rewritten to point at the label, and that is detectable | `AT_EXECFN` points at a second label copy inside the presentation block, after the argv window | `[observed]` |
| 11 | comm versus exe | `comm` reads the label, `exe` reads the real binary | the two disagree; `exe` is a kernel dentry and cannot be written by the process | `[observed]` |
| 12 | `/proc/<pid>/environ` after a getenv-only store (#26) | a library that hides a variable from `getenv` still leaves it in the environ block | reading `/proc/<pid>/environ` directly, not the process's `getenv`, shows the value | `[reported]` |
| 13 | the Windows creation record (#28) | the PEB read and the creation record can disagree; this is not a Linux interface | a Windows observer compares the two records | `[reported]` |
| 14 | `argv[0]` and the NUL run after an in-process rewrite (#29) | a 45-line `LD_PRELOAD` hook zeroes the later arguments but leaves `argv[0]` and the original NUL run | the `cmdline` bytes and the NUL count show the untouched first string | `[reported]` |
| 15 | the `stat` span after a zero-fill (#32) | a demo wipes the cmdline and environ extent but leaves `stat` fields 48 to 51 at the original size | the byte length in `/proc/<pid>/stat` disagrees with the served `cmdline` | `[reported]` |
| 16 | per-channel detector scoring (#33) | a detector scores existence channels separately and records a dissent, so a clean cmdline is not a clean process | the channels it scores are the pid, the parent chain and the exe, not the cmdline | `[reported]` |
| 17 | an `argv[0]`-only installer (#41) | `exec -a` changes only `argv[0]`; the rest of the arguments and the environ stay | the later argv entries and the environ still name the real command | `[reported]` |
| 18 | a stopped-exec re-read (#44) | a reader that stops the process at the exec stop and re-reads the argv sees the original A-B-A window | the re-read happens before the completion stop, so the entry swap is visible | `[reported]` |
| 19 | `/proc/<pid>/task/<tid>/environ` (#47) | a protect-before-release BPF LSM leaves a tid-versus-tgid gap | the per-task environ read names a thread the process-wide read hides | `[reported]` |
| 20 | masquerade rules (#52) | a detector flags a kworker comm prefix, a bracketed cmdline, a `/memfd:` exe, or a 32-byte space and NUL run | the label must avoid those shapes; a label that copies one of them is the signal | `[reported]` |
| 21 | a patched detector in `PATH` (#54) | a detector binary replaced in `PATH` can report clean; the residue is the binary's own integrity | the process metadata agrees with the patched tool; only the tool's hash disagrees | `[reported]` |
| 22 | the Windows PEB tail (#56) | a Windows PEB rewrite leaves the tail beyond `wcslen + 1`; this is not a Linux interface | a Windows observer reads past the terminator | `[reported]` |

## 1. pid and parent chain

Measured with `/tmp/residue`, which forks a child and then relocates its own
arg span:

```
ppid=98541
child ppid=98670
```

`[observed]`. The chain is intact: `stat` field 4 points at the real parent, and
the parent's own `stat` field 4 points at the shell.

Under pmask, two processes in one tree both publish the label:

```
137071  137068 ci-runner       ci-runner
137074  137071 ci-runner       ci-runner
```

`[observed]`. What reveals the truth is `exe` on the child:
`/proc/137074/exe` reads `/usr/bin/sleep` while `comm` reads `ci-runner`.
`[observed]`

## 2. cgroup

`/proc/<pid>/cgroup` reads `0::/.lxc` for every process tested, rewritten or
not. `[observed]` The rewrite does not touch it, because it is kernel state
attached to the `css_set` and not to the `mm`.

The revealing condition is a comparison, not a value: the cgroup of a labelled
pid next to the cgroup of whatever should have started it. In a container
deployment every process shares one cgroup, so this row is weak there. On a
host with per-service slices it is strong. `[inferred]`

## 3. fds

From the relocated process, `ls -l /proc/<pid>/fd`:

```
lrwx------ 1 agent agent 64 ... 3 -> socket:[4879960]
lrwx------ 1 agent agent 64 ... 4 -> /tmp/residue.file
lrwx------ 1 agent agent 64 ... 5 -> /memfd:residue-secret (deleted)
```

`[observed]`. A memfd keeps its name. The `(deleted)` suffix does not hide it:
the name after `memfd:` is the string the creator passed.

## 4. sockets

The listening socket, found in `/proc/net/tcp` by port:

```
0: 0100007F:DDDD 00000000:0000 0A ... 1000 0 4879960 1 ...
```

`[observed]`. The uid `1000` and the inode `4879960` are both real, and the
inode matches the one in `/proc/<pid>/fd/3`. That join is the whole point: fd
listing, socket table and uid agree with each other and disagree with the
label.

## 5. start time

`stat` field 22 was `22974782` for the parent and `22974782` for the child in
the same second. `[observed]` Nothing in either rewrite changes it. It is
recorded in clock ticks since boot and it is the field that survives every
process-table forgery.

The revealing condition is a process whose claimed identity predates its own
`starttime`, or two processes claiming one identity with different start times.
`[inferred]`

## 6. TracerPid

`TracerPid` read `0` in every measured run, rewritten or not. `[observed]`
Under a tracer it would read the tracer's pid, and that field is generated by
the kernel from `task->parent` when `PT_PTRACED` is set. A process cannot set
it by writing its own memory. `[inferred]`

This matters for pmask specifically because its own architecture attaches a
tracer, so during the window in which the tracer is attached the field is
non-zero. Measured on 2026-11-07 in `tests/edge.sh` E18: a default masked
tracee reports the tracer's pid for its whole life, and a `--detach` tracee
reports 0. Exhume's `injectrules.rs` scores the first High and the second none.

## 7. audit

`/proc/<pid>/loginuid` read `4294967295` (the "unset" sentinel) for every
process tested. `[observed]` `auditd` is not installed on this host
(`auditctl` and `ausearch` are absent), so no audit record was produced or
read.

The claim that matters is `[inferred]`: the kernel writes the `EXECVE` record
from `mm->arg_start` in `__audit_syscall_exit`, after `PTRACE_EVENT_EXEC` and
before the ptrace syscall-exit stop, so a rewrite at the exec stop changes what
the record reads. pmask relocates the window at that stop, per its own
module documentation in `src/execimg.rs`: "the inline `argv[]`/`envp[]` pointer
arrays in the *old* image are rewritten to point at a label string / empty
strings in scratch space, so the kernel never copies the real command line or
environment into the new image." `[observed]` as source text, not as a
measurement of an audit record.

## 8. eBPF

`/sys/kernel/btf/vmlinux` exists on this host, so BTF is available. On
2026-11-07 `bpftool` v7.5.0 was installed, a `sched_process_exec` program was
compiled, and a load was attempted; the kernel refused every load and attach.
The commands and their output are in "The attach attempt on 2026-11-07" below.
`[observed]` for the refusal; the row's claim about what the tracepoint
carries remains `[inferred]` from the kernel source.

Three places a probe can sit, each outside userland's reach:

* a kprobe on `__x64_sys_execve` or on `begin_new_exec`, which sees the
  `linux_binprm` before and after `copy_strings`;
* a uprobe on `execve` in libc, which sees the caller's real pointers;
* a kprobe on `access_remote_vm` or on the page-fault path, which sees every
  read of the relocated block and every read of the untouched stack.

The third is the one that catches a same-uid reader, and it is also the one that
proves the residue in row 9 is reachable rather than hypothetical. `[inferred]`

### The attach attempt on 2026-11-07

The eBPF row is the one the survey's Tetragon policy would exercise. On
2026-11-07 this worktree tried to attach a `sched_process_exec` program and the
kernel refused. The host: Linux 6.12.113+deb13-amd64, x86_64, uid 0 in a
container user namespace (`/proc/self/uid_map` maps 0 to 1000000), `CapEff`
`000001ffffffffff` in that namespace, `kernel.unprivileged_bpf_disabled=2`,
`kernel.perf_event_paranoid=3`, BTF at `/sys/kernel/btf/vmlinux`.

`bpftool` v7.5.0 (libbpf v1.5) was installed with `apt-get install -y bpftool`.
A minimal tracepoint program was compiled with `clang -target bpf`:

```
$ clang -target bpf -O2 -g -c /tmp/execprobe.bpf.c -o /tmp/execprobe.bpf.o
rc=0
```

`bpftool prog list` and `bpftool prog load` were refused:

```
$ sudo bpftool prog list
Error: can't get next program: Operation not permitted
rc=255

$ sudo bpftool prog load /tmp/execprobe.bpf.o /sys/fs/bpf/execprobe
libbpf: Error in bpf_object__probe_loading():Operation not permitted(1).
Couldn't load trivial BPF program. Make sure your kernel supports BPF
(CONFIG_BPF_SYSCALL=y) and/or that RLIMIT_MEMLOCK is set to big enough value.
Error: failed to load object file
rc=255
```

The direct syscalls give the same answer:

```
bpf(BPF_MAP_CREATE, ARRAY)                 -> -1 errno=1 (Operation not permitted)
bpf(BPF_PROG_LOAD, TRACEPOINT)             -> -1 errno=1 (Operation not permitted)
perf_event_open(TRACEPOINT, config=1)      -> -1 errno=13 (Permission denied)
perf_event_open(SOFTWARE, CPU_CLOCK)       -> -1 errno=13 (Permission denied)
```

The evidence points at the user namespace. `capable()` checks the initial user
namespace, and `bpf_capable()` is `capable(CAP_BPF) || capable(CAP_SYS_ADMIN)`.
The container's root has every capability in its own namespace (`mount` of a
tmpfs and `sethostname` to the same name both succeed) but not in the initial
one (`settimeofday(NULL, NULL)` returns `EPERM`), and
`unprivileged_bpf_disabled=2` is permanent. `perf_event_open` answers `EACCES`
because `perf_event_paranoid=3`. The tracefs route is refused too:
`/sys/kernel/tracing` is not readable even as root (`ls` returns `Permission
denied`), and writing to `kprobe_events` returns `Permission denied`.

So no eBPF program was loaded or attached, and the tracepoint's fields remain
a source reading. Linux 6.12 `include/trace/events/sched.h` defines
`sched_process_exec` with `__string(filename, bprm->filename)`, `pid` and
`old_pid`, and no argv. `[observed]` as source text, not as a tracepoint
record from this host.

## 9. same-uid memory reads

This is the strongest row and the one most worth stating exactly.

After a `PR_SET_MM_MAP` relocation, `cmdline` reads 10 bytes and `environ`
reads 0. A same-uid reader opening `/proc/<pid>/mem` and scanning `[stack]`
finds:

```
b'/tmp/residue'                            at 132856
b'residue'                                 at 119368
b'CANARY_SECRET=canary-secret-value-9f3c'  at 134569
b'canary-secret-value-9f3c'                at 134583
```

`[observed]`. The full environment string, name included, is intact in stack
memory: the relocation changed where the kernel looks, not what is in memory.
The bottom two offsets are position-independent, since `argv` and `environ`
sit at the top of the stack block. The bare `residue` hit is the binary's own
`comm`, which moved between runs (123271, then 119368); treat that one offset
as illustrative only.

Same finding under pmask, on a `sleep` child with a secret environment
variable:

```
b'super-secret-token-abc123'         at 8638
b'LEAKME=super-secret-token-abc123'  at 8631
b'/bin/sleep'                        at 8204
```

`[observed]`. So the environment a pmask process was started with is
readable by any same-uid reader that scans the stack, even though
`/proc/<pid>/environ` returns zero bytes. Those four offsets are one run on one
`/bin/sleep` build; they are not stable across runs and are shown to identify
what was found, not where it always sits.

The one control that closes this: `PR_SET_DUMPABLE=0`. Measured on a process
that called it:

```
/proc/P/environ     -> Permission denied
/proc/P/mem         -> REFUSED: [Errno 13] Permission denied
/proc/P/auxv        -> Permission denied
/proc/P/maps        -> Permission denied
/proc/P/fd          -> Permission denied
```

while these stayed readable:

```
/proc/P/stat        -> 114005 (dump) S ...
/proc/P/status      -> Name: dump ... TracerPid: 0
/proc/P/cgroup      -> 0::/.lxc
/proc/P/loginuid    -> 4294967295
/proc/P/statm       -> 605 382 358 1 0 56 0
/proc/P/sched       -> dump (114005, #threads: 1)
/proc/P/comm        -> dump
/proc/P/cmdline     -> /tmp/dump
```

`[observed]` So `PR_SET_DUMPABLE=0` closes rows 3, 9 and 10 for a same-uid
reader, and leaves rows 1, 2, 5, 6 and 11 exactly as they were. That split is
the honest boundary of the mechanism.

Note the exception in that listing: `exe`, `cwd`, `root` and `ns/*` are
symlinks, and `readlink` on them returned exit 1 with `PR_SET_DUMPABLE=0`. On
a process without it, the same calls returned `/tmp/residue`, the package's
working directory, `/` and `pid:[4026532664]`. `[observed]` So `exe` moves from row 11's evidence into
the closed set only when dumpable is zero. It does not disappear from row 11
for root.

## 10. AT_EXECFN

This row is a finding, not a restatement, and it was not in the brief.

On a normal exec, `AT_EXECFN` points at the exec filename string, which the
kernel copies last onto the stack. `fs/exec.c`:

```c
	retval = copy_string_kernel(bprm->filename, bprm);
	if (retval < 0)
		return retval;
	bprm->exec = bprm->p;

	retval = copy_strings(bprm->envc, envp, bprm);
```

`[observed]` from `fs/exec.c` master. Because the filename is copied first and
the stack grows down, the string ends up at the top of the block, so
`AT_EXECFN == env_end` on every ordinary exec.

Measured on eight plain runs, including `env -i` and a run with four variables:

```
/bin/sleep        execfn-env_end=+0  in_argv=False
tail -f /dev/null execfn-env_end=+0  in_argv=False
yes >/dev/null    execfn-env_end=+0  in_argv=False
env -i            execfn-env_end=+0  in_argv=False
A=1 B=2 C=3 D=4   execfn-env_end=+0  in_argv=False
```

`[observed]` The delta is zero in all of them.

Under pmask, three runs out of three:

```
arg=[0x7f12b0a39000,0x7f12b0a3900a) env_end=0x7f12b0a3900c execfn=0x7f12b0a39000 delta=-12 inargv=True
arg=[0x7f6e1b27b000,0x7f6e1b27b00a) env_end=0x7f6e1b27b00c execfn=0x7f6e1b27b000 delta=-12 inargv=True
arg=[0x7fab6b127000,0x7fab6b12700a) env_end=0x7fab6b12700c execfn=0x7fab6b127000 delta=-12 inargv=True
```

`[observed]` in that build `AT_EXECFN` equalled `arg_start`, with `env_end` two
bytes higher and the span ten bytes wide. The current completion path places a
second label copy after the argv window and repoints `AT_EXECFN` at it:
`src/execimg.rs` sets `execfn = 1 + fl + argv.len()` from the block base, and
the presentation layout puts that copy at `env_end` (`src/execimg.rs`,
`label_presentation_len`). So `/proc/<pid>/auxv` reports the label and keeps
the `AT_EXECFN == env_end` relation a normal exec has.

The mechanism is in the repository, not guessed. `src/execimg.rs` says of
`AT_EXECFN`: "`AT_EXECFN` in `saved_auxv` is rewritten to the label in the same
call, so `/proc/<pid>/auxv` agrees with `/proc/<pid>/cmdline`." `[observed]` as
source text. The intent is consistency between `auxv` and `cmdline`, and the
measurement shows it succeeds at that and creates a different inconsistency
against `env_end`.

Why it matters: a detector that computes only `AT_EXECFN` versus `env_end` gets
a clean split on this host, 8 plain runs at `+0` and 3 pmask runs at `-12`.
`[observed]` Whether that split survives a different libc, a different
`AT_RANDOM` size, or a kernel that lays the block out differently was not
tested and is the first thing to check before relying on it. `[inferred]`

## 11. comm versus exe

Measured under pmask:

```
comm = ci-runner
exe  = /usr/bin/sleep
```

`[observed]` `comm` is writable with `PR_SET_NAME` by the process itself. `exe`
is `mm->exe_file`, a kernel reference to the `dentry` opened at exec. No
userland write reaches it, and `/proc/<pid>/exe` is served from that reference.

This is the row that survives every variant measured here, including
`PR_SET_DUMPABLE=0` for a reader with the file permissions, and it is the one
the MITRE DET0164 mutable element `AllowedArgvMismatchPatterns` exists to
discount.

## The userspace rules, as cases

C-043's Prove has a second arm that needs no BPF: the userspace rules the
survey names become `tests/edge.sh` cases. They landed as E18, E19, E21 and
E22, and the 2026-11-08 native gate ran them green.

| case | rule it runs | result |
| --- | --- | --- |
| `e18-control-untraced-scores-none` | Exhume: `TracerPid` 0 is no score | PASS |
| `e18-default-traced-scores-high` | Exhume: any non-debugger tracer is High | PASS, `TracerPid` non-zero |
| `e18-detach-untraced-scores-none` | Exhume: the same rule after `--detach` | PASS, `TracerPid` 0 |
| `e18-secret-holder-label-scores-critical` | Exhume: a traced `ssh-agent` comm is Critical | PASS |
| `e19-control-live-pid-present-in-every-view` | SPiCa: a live pid in every channel | PASS |
| `e19-control-dead-pid-absent-in-every-view` | SPiCa: a reaped pid in no channel | PASS |
| `e19-masked-present-in-every-view` | SPiCa: the masked tracee exists in every channel | PASS |
| `e19-masked-start-time-stable` | SPiCa: the kernel start time does not move | PASS |
| `e19-control-start-times-differ` | SPiCa: the start-time comparison can distinguish processes | PASS |
| `e19-masked-comm-is-label` | the process under test is really masked | PASS |
| `e19-masked-cmdline-hides-argument` | the masked cmdline is the label, not the argument | PASS |
| `e21-control-all-channels-name-the-real-argv` | kdetect (#33): the external channels agree on the real argv | PASS |
| `e21-masked-dissent-is-the-in-process-execfn` | kdetect (#33): cmdline, `stat` span and auxv name the label; the payload's own `AT_EXECFN` is the named dissent | PASS, `span=7` for the 6-byte label |
| `e22-path-resolved-check-returns-the-planted-answer` | Mao (#54): a detector resolved through `PATH` returns the planted answer | PASS |
| `e22-direct-proc-read-is-not-the-planted-answer` | Mao (#54): the direct `/proc` read is not the planted answer | PASS |

Which rules ran where:

- Exhume's `injectrules.rs` `TracerPid` scoring ran in `tests/edge.sh` E18.
  The score is High for every default tracee and Critical when the label is a
  credential holder; `--detach` brings it to none.
- SPiCa's `spica-detect` existence comparison ran in `tests/edge.sh` E19
  through `testcases procviews`, which reads the raw `getdents64` listing of
  `/proc`, the libc `readdir` listing, a direct `stat` of `/proc/<pid>` and
  `kill(pid, 0)`. The eBPF scheduler ledger, SPiCa's third channel, did not
  run because the attach was refused.
- kdetect's cross-view score ran in `tests/edge.sh` E21. The channels are the
  cmdline, the `stat` arg span, `/proc/<pid>/auxv` `AT_EXECFN` and the
  payload's own `getauxval(AT_EXECFN)`. The control run has all four name the
  real argv; under the mask the first three name the label and the fourth
  still names the real path, so the dissent is exactly that channel.
- Mao's PATH lesson ran in `tests/edge.sh` E22. A `ps` planted earlier in
  `PATH` returns the chosen answer, while the direct `/proc` read does not, so
  a PATH-resolved check is not evidence.
- The Tetragon `sched_process_exec` policy did not run, for the same reason.
- The quiet-operator recipes (survey issue #55) did not run in this pass.

The finding is a split. Exhume's rule fires on every default pmask tracee,
because the tracer is attached and `TracerPid` is not zero; `--detach` clears
it and costs tree coverage. SPiCa's existence check does not fire at all: the
pid is present in every channel, its start time is stable, and the detector
never reads `cmdline`, so the label and the hidden arguments are outside what
it compares. The residue an external observer can use is the tracer, not the
process-table existence.

The E19 control for the start-time comparison is two live processes with
different start times; it shows the comparison can distinguish a reused TGID
from the original. The case does not create a ghost entry (that needs a
kernel-side hider), so the inconsistent branch of SPiCa's truth table is not
exercised here. The two controls exercise the present and absent branches, and
the masked run asserts the consistent branch.

## 12. Environment after a getenv-only store (#26)

A library that removes a name from `getenv` still leaves the value in the
environ block. The interface is `/proc/<pid>/environ`, not the process's own
`getenv`; a same-uid reader sees the value. `[reported]`.

## 13. Windows creation record (#28)

The Windows PEB read and the creation record can disagree. This is a
Windows interface and outside a Linux tool; it is recorded so the survey
row is not mistaken for a Linux claim. `[reported]`.

## 14. `argv[0]` and the NUL run after a preload rewrite (#29)

A 45-line `LD_PRELOAD` hook that copies then zeroes the later arguments
leaves `argv[0]` and the original NUL run in place. The `cmdline` byte
length and the NUL count show the first string is untouched. `[reported]`.

## 15. The `stat` span after a zero-fill (#32)

A demo that wipes the cmdline and environ extent leaves `/proc/<pid>/stat`
fields 48 to 51 at the original size. The byte length in `stat` disagrees
with the served `cmdline`; that is the residue. `[reported]`.

## 16. Per-channel detector scoring (#33)

A detector can score existence channels separately and record a dissent.
The channels it scores are the pid, the parent chain and the exe, not the
cmdline, so a clean cmdline is not a clean process. `[reported]`.

## 17. An `argv[0]`-only installer (#41)

`exec -a` changes only `argv[0]`. The later argv entries and the environ
still name the real command. `[reported]`.

## 18. A stopped-exec re-read (#44)

A reader that stops the process at the exec stop and re-reads the argv
sees the original A-B-A window. The re-read happens before the completion
stop, so the entry swap is visible. `[reported]`.

## 19. `/proc/<pid>/task/<tid>/environ` (#47)

A protect-before-release BPF LSM leaves a tid-versus-tgid gap. The
per-task environ read names a thread the process-wide read hides.
`[reported]`.

## 20. Masquerade rules (#52)

A detector flags a kworker comm prefix, a bracketed cmdline, a `/memfd:`
exe, or a 32-byte space and NUL run. A label that copies one of those
shapes is the signal; pmask's default label does not. `[reported]`.

## 21. A patched detector in `PATH` (#54)

A detector binary replaced in `PATH` can report clean. The process
metadata agrees with the patched tool; only the tool's own hash disagrees.
The residue is the binary's integrity, not the process metadata.
`[reported]`.

## 22. The Windows PEB tail (#56)

A Windows PEB rewrite leaves the tail beyond `wcslen + 1`. This is a
Windows interface and outside a Linux tool; it is recorded so the survey
row is not mistaken for a Linux claim. `[reported]`.

## What this table does not say

It does not say a rewrite is pointless. It says the confidentiality boundary is
uid, not kernel: a same-uid reader with `PR_SET_DUMPABLE` left at its default
can recover everything from the stack, and a reader without it cannot. Rows 1,
2, 5 and 11 are outside the mechanism entirely and remain readable by any local
account.

It also does not cover: a different uid (not available here), a host with
`hidepid` set, an LSM that refuses the procfs reads, or a kernel before 5.3.
`[inferred]`

One row is a new finding and needs a follow-up check on other hosts before it
is treated as reliable: row 10, `AT_EXECFN` points at a label copy at
`env_end` under pmask, versus the real filename at `env_end` on a plain
exec.
