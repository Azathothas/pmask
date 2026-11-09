# Design

## The problem, stated exactly

A Linux process publishes three things about itself through `/proc` for
its whole lifetime:

- `cmdline`: the `argv` strings, NUL-separated,
- `environ`: the `envp` strings,
- `comm`: a 15-byte name, shown by `top` and `htop`.

`cmdline` and `comm` have no permission check: every local account reads
them. `environ`, `exe`, `maps`, `fd/*` and `cwd` need
`PTRACE_MODE_READ_FSCREDS`, which a process of the same uid and root
pass. Yama restricts `PTRACE_MODE_ATTACH` only, so it does not stop a
same-uid read of `environ` or `maps`.

Secrets passed as arguments are the classic case. The usual advice ("use
environment variables") moves the secret from one readable file to
another.

TEEs solve a different problem: they protect memory from the host. They
need hardware, firmware, a hypervisor, attestation infrastructure, and
often a rewritten workload. On a machine without any of that, the
disclosure above is still real, and it is still the one that exposes
tokens.

`pmask` targets that disclosure, and only that one. The tool reduces
what `/proc` discloses about a process; it does not change whether the
process exists.

## Trust boundary

The boundary is the same one a container draws for the filesystem:
protection against other tenants and against casual or automated
inspection, not against the host operator.

| adversary | outcome |
|---|---|
| another uid | the label in `cmdline` and `comm`; no real argv or environ |
| a monitoring agent of the same uid | the label, plus `exe`, `maps`, `fd/*` and `cwd`, which name the real binary; with `--no-dumpable` those files are refused as well |
| `ps` output pasted into a ticket or a chat | the label |
| root on the host | sees the pid, `exe`, `maps`, fds, cgroups, and can `PTRACE_ATTACH` |
| kernel-level attacker | everything |

The first three rows are the disclosure `pmask` targets. The last two are
out of scope by construction.

## Non-goals

- Encrypting process memory.
- Making a process invisible, or changing which pid it is.
- Defeating a kernel module, a hypervisor, or an eBPF program attached
  to the host.
- Privilege escalation. A traced process cannot gain set-uid privileges,
  so `sudo` under `pmask` does not elevate.
- Persistence, daemonizing into init, or surviving reboots.

## Mechanism

`pmask` is a `ptrace` supervisor: the parent of the supervised tree. It
seizes the child with `PTRACE_SEIZE`, stops the seized master with
`PTRACE_INTERRUPT`, takes the resulting `PTRACE_EVENT_STOP` as the
handshake, and only then releases the child by writing one byte to a
pipe. The child does not raise `SIGSTOP`: a process that is pid 1 of its
own pid namespace cannot rely on a self-directed job-control stop
arriving, because the kernel discards it, and the handshake went missing
under `--unshare` (issue 4).

### Following the tree

`PTRACE_O_TRACEFORK | TRACEVFORK | TRACECLONE | TRACEEXEC | TRACEEXIT`
auto-attaches every descendant, including every thread. This covers
`fork`, `vfork`, `clone`, `posix_spawn()`, `system()`, `popen()`,
double-forking daemons, static binaries, Go runtimes (raw
`clone`+`execve`) and `#!` scripts, without `LD_PRELOAD` and without a
libc dependency in the tracee.

### Zero exposure at exec entry

A process is syscall-supervised (`PTRACE_SYSCALL`) from the moment it is
attached until its first exec settles. At the `execve`/`execveat` entry
stop, before the kernel has built the new image:

1. read the real `argv`/`envp` pointer arrays and their strings,
2. write a 256-byte scratch block at `sp - 4096` in the old image
   containing the label followed by a NUL. The label is clamped to 254
   bytes here (`src/execimg.rs:265`), so a longer label is cut on the
   entry path; the completion block carries the whole label,
3. rewrite the old image's inline `argv` array to
   `[label, empty, empty, ..., NULL]` and the `envp` array to all empty
   strings, except variables named by `--keep-env=NAME`,
4. resume.

The kernel then copies the label and empty strings. The real command
line never exists in the new image of an ELF target, so
`/proc/<pid>/cmdline` never shows it, not even briefly.

The child's old image still holds the parent's argv bytes from the fork
until this stop. The kernel never copies them into the new image.

### Restoring the real arguments

At `PTRACE_EVENT_EXEC` the new image is mapped but the program has not
started. The supervisor:

1. reads `argc` from the new stack and locates the inline arrays,
2. injects `mmap` and parks the block containing the real `argv` strings,
   the real `envp` strings and the comm label, 16-byte aligned, in a new
   anonymous mapping inside the tracee,
3. repoints the inline arrays at those strings, and checks every write,
4. zeroes the visible string region, read from `/proc/<pid>/stat` fields
   48 to 51, and writes the label into `argv[0]`'s old slot,
5. injects `prctl(PR_SET_NAME)` and, with `--no-dumpable`,
   `prctl(PR_SET_DUMPABLE, 0)`, through a `syscall` instruction of the
   tracee,
6. resumes.

`argc`, the array positions and the auxiliary vector are untouched. glibc
and musl cache `argv`/`environ` from the stack at startup, so the
program sees its real values and never notices.

When a repoint write fails, the supervisor zeroes the whole visible
region instead: the worst visible result is empty strings, and the
session summary names the exec.

### Scripts, vfork children, re-execs and foreign images

The kernel needs the real `argv` to build an interpreter line for a `#!`
script, and a settled process no longer stops at syscall entry. Both
cases take the post-exec path: the kernel copies the real interpreter
command line, including the script's arguments, and, unless
`--keep-env`, the real environment. The completion stop zeroes that
region; `tests/compare.sh` prints the duration of the window for the host
it runs on.

A `vfork` child takes the same path. It shares its parent's address
space until it execs, so an entry swap would write the parent's memory.
The measured case is gcc, which runs cc1 through
`clone3(CLONE_VM|CLONE_VFORK)`; the swap corrupted the driver's heap and
it crashed in `free()` after the child exited. The child now runs its
exec unswapped and the completion redacts the new image.

A 32-bit image is not redacted. The supervisor reads `EI_CLASS` at the
entry stop, refuses the swap, prints one warning and counts the exec in
the session summary. The program keeps its real arguments. The
alternative, swapping and then failing to read the new registers, hands
the program the label as its argv.

An exec by a non-leader thread resets the tid to the group leader's
before `PTRACE_EVENT_EXEC`. The supervisor reads the former tid with
`PTRACE_GETEVENTMSG` and moves the entry-stop bookkeeping to the leader.

### Process name

`prctl(PR_SET_NAME)` is executed by the tracee, not by the supervisor:
the supervisor points the tracee's instruction pointer at a `syscall`
instruction inside the tracee's own vDSO and steps over it. No
writable-and-executable memory is mapped anywhere, and no assumption is
made about the tracee's libc. If no usable syscall instruction is found
in the vDSO, the supervisor scans the first executable mapping of the
image, and fails loudly when that also fails.

`--watch-rename` adds a seccomp filter that traps `prctl(PR_SET_NAME)`
only and returns the label in its place. The filter never matches
`execve`, so the exec-event behaviour below does not apply. A filter
that cannot be installed is a fatal error (exit 126 naming the failure),
not a line and a run without the promise.

The redirect points the trapped name argument at the label copy that
already sits in the tracee's presentation block, so it needs no write
into tracee memory. That matters with `--no-dumpable`: a non-dumpable
tracee refuses both `process_vm_writev` and `PTRACE_POKEDATA` to a
tracer that is not root, so the earlier write-based redirect silently
lost the rename and `comm` became the payload's own name (issue 60).
When the block address is unknown or no longer holds the label, the
tracer falls back to a write below the stack pointer. If that write is
refused too, it points the argument at an unmapped address: `PR_SET_NAME`
fails with `EFAULT`, `comm` keeps the label, and the session counts the
refusal. The payload's own pointer is never left in place.

### The supervisor's own entry

The supervisor lives as long as the tree, so it gives itself the same
treatment before it forks. It snapshots the child's argv and environment,
zeroes its own argv block, writes the label there, zeroes its own
environment strings, moves its own `PR_SET_MM_MAP` window onto the label,
sets its own `comm`, and makes itself non-dumpable. The fork happens
after the snapshot, so the child still execs with the real values. The
order is binding.

A refused window relocation leaves the label in place and only keeps the
slot-count extent; the run prints one note and the session does not count
it as a degradation of the tree.

The ptracer is a second thread of the supervisor (`src/mask.rs`), not a
separate process. `TracerPid` in a payload's
`/proc/<pid>/status` therefore names a thread whose `Tgid` is the
supervisor's pid. The thread name is not part of the window relocation,
so `/proc/<supervisor>/task/<tid>/comm` still publishes a name. That name
is derived from the session: the `comm` first and the label second, cut
to the kernel's 15-byte limit, and never the retired fixed string
`pmask-tracer` (issue 38). An empty, NUL-carrying or newline-carrying
candidate falls through to the next. The `Tgid != Pid` shape and the
nonzero `TracerPid` remain, and only `--detach` removes them.

### Labels and modes that do not redact

A label is a `/proc` presentation, so it exists only where `/proc` is
redacted. `--isolate` runs the payload in fresh namespaces and does not
apply the label to the payload's own `argv`, `environ` or `comm`. When a
label is set in isolate mode, the supervisor masks its own `/proc` entry
with it, as it does in every label mode (see above), and the run prints
one note at the default verbosity: "the
payload's label was not applied: isolate mode does not redact the
payload's `/proc` metadata". `--redact --isolate` composes the two: the
tracer owns the tree and the child is forked into exactly the namespaces
the list names, so the label applies and the requested set is what the
payload gets. A set the host cannot grant is reported as a degradation,
never replaced by a different set. `--no-redact --isolate` runs the
isolate path, because isolation does not need ptrace. `--isolate=none`
creates no namespace at all, sets no `no_new_privs` and applies no
Landlock policy. Plain mode applies the label nowhere. `--daemon` is
different: the client refuses `--isolate`, `--secret`, `--no-redact` and
`--image` outright, because the daemon owns the masking policy and the
job environment, and a flag it cannot honour would otherwise be dropped.

### Job control

The supervisor seizes tracees, so a group-stop arrives as
`PTRACE_EVENT_STOP`. The supervisor answers it with `PTRACE_LISTEN`, which
keeps the tracee stopped and lets `SIGCONT` and the real parent's job
control see it. `kill -STOP` holds a masked tree and `SIGCONT` resumes
it.

### Why no exec-shaped seccomp filter

A per-process seccomp filter with `SECCOMP_RET_TRACE` on `execve` was
tried in the C predecessor and is not used here. An unserviced
`RET_TRACE` stop makes `execve` return `ENOSYS` in a descendant that is
not being supervised. That is measured, and it is the reason the filter
stays out: a process that inherits the filter without a tracer cannot
exec at all.

Pure `PTRACE_SYSCALL` supervision is identical on every kernel from 5.3
on. The cost is two stops per syscall until a process's first exec
settles, and none afterwards.

A thread created with `CLONE_THREAD` cannot exec without becoming its
group's leader, so a newcomer whose group has already settled starts in
`Run` rather than under syscall supervision. That is what keeps a
threaded runtime from paying two stops per system call for the life of
the process. A real `fork` newcomer stays in `Slow`, because its own
first exec is what the entry swap exists for.

### Session end

When the master process exits, the session applies its policy:

| policy | behaviour |
|---|---|
| `detach` (default) | every settled descendant is detached with `PTRACE_INTERRUPT` and `PTRACE_DETACH`; a descendant still waiting for its first exec gets a one-second grace period, then is detached as it is |
| `wait` | the session supervises until the last descendant exits |
| `kill` | every remaining tracee gets `SIGKILL` |

A detached descendant keeps the label and its redacted image. Nothing it
forks is followed and none of its own later execs is seen, redacted or
counted, because no supervisor watches it; the session summary counts each
detach.

`PTRACE_O_EXITKILL` kills the whole tree if the supervisor dies.
`--no-exit-kill` turns it off for callers that want the tree to survive.

### Session summary

The supervisor counts execs and degradations. At session end it prints
one line unless `--quiet`:

```
pmask: N of M execs degraded (post-exec, reexec x2, foreign-arch)
```

Every entry in that line is a degradation, not a disclosure: the exec was
redacted, or one part of the treatment was skipped. `unredacted` is the
entry that means the real strings may have been visible; `script`,
`reexec`, `comm-not-set` and `foreign-arch` are the other reasons. Three
further lines print independently when their count is non-zero: the
number of execs that kept the kernel's argv and environment windows
because `PR_SET_MM_MAP` was refused, the number of tracees left detached
by `--detach`, and the number of secret descriptors that could not be
closed in a descendant. The counts are also in `ExitState::stats`.

## The daemon

`pmaskd` exists because a CI runner cannot hold the token it needs.
Any secret in the runner's argv or environment is in `/proc`. The daemon
holds the environment instead and runs jobs for clients.

### Protocol

One request per connection, one job per connection.

Client to daemon, with `SCM_RIGHTS` carrying stdin, stdout and stderr:

```
1 byte   version (2)
"PMK2"   u8 label_mode  u32 label_len  label
         u32 argc       argc * (u32 len, bytes)
```

The version byte is the first byte of the first message. A client of the
old protocol sent `'C'` there; the daemon rejects it and names the case
"protocol mismatch". `label_mode` is 0 (daemon label), 1 (empty label) or
2 (the text that follows). Daemon to client:

```
i32 exit_code  u32 has_signal  i32 signal  u32 msg_len  msg
```

A PING replaces the job frame with the four bytes `PMKP` and nothing
after them. The daemon answers with the same response frame, whose
message is one `key=value` line per fact. The body depends on who asks.
The daemon's own uid and root get the full set: protocol version, label,
uid, `run_as_uid`, job slots, environment count, allowed uids, socket
mode, I/O and job timeouts, the job-argv cap, the peer identity method
and the peer uid. Another uid admitted by `--allow-uid` gets the
protocol version, the label, the daemon uid and `run_as_uid`, and a
`detail=reduced` line; the policy fields are omitted from the wire, not
zeroed. It never reports an environment value. A PING is answered after
the same uid check a job gets.

Limits: `argc <= 4096`, one argument `<= 1 MiB`, request `<= 8 MiB`,
label `<= 4096` bytes without NUL, LF or CR, and the sum of `len + 1`
over the job arguments `<= 1 MiB` (`--max-job-bytes`). Integers are
little-endian. The daemon requires exactly three descriptors and rejects
a truncated control message.

### Authorisation

`SO_PEERCRED` on the accepted socket. The daemon accepts its own uid and
root; `--allow-uid` adds more. The socket is created with mode 0600
unless `--socket-mode` says otherwise. The client checks the peer uid of
the socket it connected to.

The identity established at `accept` is pinned. When the kernel offers
`SO_PEERPIDFD` (Linux 6.5 and later), the daemon keeps a pidfd for the
connecting process and compares the peer again before the job starts;
where `statx` on a pidfd reports an identity inode (Linux 6.9 and later)
that inode is the comparison as well. Otherwise it records the peer's pid
and start time from `/proc/<pid>/stat` and consults them again. That
fallback is best effort: a pid reused between `accept` and the check is
detectable only by the start time, and a peer that `execve`s keeps the
identity it had.

An allowed uid may execute arbitrary programs with the daemon's
privileges and inherit its environment. `--run-as-uid` on a root daemon
runs each job with the client's uid and gid instead.

### Socket safety

The parent directory is checked on every start, explicit `--socket` path
or not. `check_socket_dir` creates it `0700` when it is missing, opens it
`O_DIRECTORY | O_NOFOLLOW`, and requires a directory owned by the
effective uid that group and other cannot write to. A directory this
call created must be exactly `0700`; one that already existed may be
group- or other-readable, as `/run` is at `0755` for root's default. A
directory that fails any of those refuses service, because a writable
directory is one where the socket name can be replaced between the check
and the bind. The directory descriptor is kept, and removal goes through
it.

The socket path itself is opened `O_PATH | O_NOFOLLOW` before any
removal, so a symbolic link is never followed and never removed, and a
file that is not a socket is never removed. The daemon connects to an
existing socket first: a live daemon refuses the start, and a socket is
unlinked only after `ECONNREFUSED` and only when the pinned descriptor
still says it is a socket owned by this uid. It binds under `umask 077`,
then checks with `lstat` that the new file is a socket owned by its
euid, sets the mode (default `0600`) and checks the identity again.

The default path is `$XDG_RUNTIME_DIR/pmask.sock` when that directory
is owned by the effective uid and not writable by group or other, else
`/run/pmask.sock` for root, else the empty path. The empty path means
there is no safe default and `--socket` is required; there is no `/tmp`
fallback.

### Timeouts and concurrency

A client that stalls while sending its request or reading its response
is dropped after `--io-timeout` seconds. `--job-timeout` kills a job
tree that runs too long and returns code 137.

A masking session owns the calling process's `waitpid(-1)` domain. The
library serializes sessions with a process-wide mutex. The daemon
accepts one connection at a time by default; `--jobs N` runs each job in
a worker process, up to N at once.

### Secret handling

The job environment is loaded at startup, kept in memory, and locked
with `mlock`. `--no-inherit-env` makes the job environment exactly the
`--env-file` contents. The daemon wipes the store and exits on
`SIGTERM` or `SIGINT`.

The CLI has a second, daemon-free secret path. `--secret NAME=SRC`
delivers the value to the job on a sealed memfd descriptor (fd 3, 4,
...); `pmask read NAME` prints it inside the job, and
`PMASK_SECRET_<NAME>=<fd>` names the descriptor in the child's environment.
Sources are `file:PATH`, `env:VAR`, `agent:NAME`, `stdin` and
`literal:VAL` (a bare value is a literal). The holder hardens itself
(`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`) before the label session starts.

The descriptor is installed without `FD_CLOEXEC`, because the payload has
to read it after its own `exec`. By default every descendant inherits it,
and a same-uid peer can read `/proc/<pid>/fd/N`. `--secret-close-on-exec`
asks the tracer to close it in each direct child of the payload at that
child's fork, before the child runs; the payload keeps it. The guarantee
is for an ordinary fork/exec tree: a process that shares the payload's
descriptor table (`clone(CLONE_FILES)` without `CLONE_THREAD`) cannot be
closed without removing the payload's copy, so the run reports a
degradation and the session counts it. The flag needs the ptrace
supervisor: plain and isolate modes refuse the combination, because
`FD_CLOEXEC` would close the descriptor at the payload's own exec and no
tracer exists to close it at a fork.
`--detach` removes the tracer after the payload's exec, so the two flags
conflict: the run prints one warning and the session counts each
descriptor that stayed open. `--secret-burn` seals the descriptor without
`F_SEAL_SHRINK`, so a cooperating reader can truncate it once and cannot
grow or rewrite it. A `literal:` or `env:` source still sits in
pmask's own argv or environ until the supervisor masks itself, and a
mode that cannot redact refuses it unless `--allow-argv-secret` is given.
The `pmask agent` subcommand runs a per-user service that holds the
unlocked store and answers `GET <name>` over its own socket; it is the
only source that keeps the plaintext out of the invoking process entirely.

Both memfd families carry a name that `/proc` publishes. The descriptor
behind every delivered secret defaults to `/memfd:pmask-secret
(deleted)`; `--secret-fd-name NAME` replaces that string. The image memfd
behind `--rexec`, `--image`, `--image-from-fd`, `--exec-once` and
`--hugetlb` defaults to the label, or to the program name for `--image`
without a label; `--memfd-name NAME` replaces it, and also the tag of the
`--exec-once` temporary-file carrier. One validator serves both: not
empty, at most 200 bytes, no `/`, NUL, LF or CR, checked at parse time
and again where the object is created. The options are cosmetic by
design. They change the string a reader sees, not the fact that a memfd
backs the descriptor or the image.

## Privilege ladder

Higher privileges buy more privacy in defined steps.

| rung | requirement | what it adds | limit |
|---|---|---|---|
| 0 | none | entry swap, label, comm, per-variable environment policy | same-uid observers still read `exe`, `maps`, `fd/*`, `cwd` |
| 0 + `--no-dumpable` | none | `PR_SET_DUMPABLE=0` makes those files refused for the same uid | core dumps and debugger attach stop |
| 0 + `--rexec` | none | `/proc/<pid>/exe` names the memfd, not the file; a refused descriptor exec reports the step and continues on `/proc/self/fd/N` or a temporary file; `--memfd-name NAME` replaces the name | `/proc/<pid>/map_files` still resolves; `vm.memfd_noexec` may refuse; the on-disk fallback needs `--rexec-allow-disk` |
| 0 + `--unshare` | kernel that allows unprivileged user namespaces | private PID namespace and private procfs; the payload sees only itself | unavailable on hosts that gate user namespaces; opportunistic by design |
| 0 + `--watch-rename` | none | comm stays the label when a program renames itself, including with `--no-dumpable`, because the redirect needs no tracee memory write | traps `prctl(PR_SET_NAME)` only; implies `no_new_privs` |
| 0 + `--scope-name` | a user session manager | one consistent name in `/proc/<pid>/cgroup` and `systemctl` | the unit name is world-readable; system-level scopes need root or polkit |
| 0 (default; `--no-exact` turns it off) | none | `prctl(PR_SET_MM, PR_SET_MM_MAP)` moves `mm->arg_start`/`arg_end` and `mm->env_start`/`env_end` onto a compact block, rewrites `AT_EXECFN` in `saved_auxv`, and moves `start_stack`: `/proc/<pid>/cmdline` is exactly the label, `environ` is empty, fields 48 to 51 agree with the cmdline length, and the label's page reads `[stack]` in `maps` | a kernel without `CONFIG_CHECKPOINT_RESTORE`, or a seccomp filter denying `prctl`; `--no-exact` leaves the in-place redaction: the window is the label plus one NUL per argument and `environ` is a NUL block, not empty |
| 0 + `--detach` | none | `PTRACE_DETACH` after each settled exec, so `TracerPid` is 0 for the payload | the detached process and its descendants run unredacted at every later exec, and the session summary counts each detach |
| 2 | `CAP_SYS_RESOURCE` | the bare `PR_SET_MM_ARG_START`/`_ARG_END` operations, which resize the window without rewriting the rest of the map | not used; the one-shot map at rung 0 reaches the same result |
| 3 | root on the host | `hidepid=2,gid=` on the system `/proc` removes the tree from every other account | polkit and distribution defaults; Yama scope needs `CAP_SYS_PTRACE` and scope 3 is irreversible until reboot |

## Failure modes and what they do

| failure | behaviour |
|---|---|
| exec fails inside the child | original arrays restored, the process stays syscall-supervised, exit 127 (`ENOENT`) or 126 |
| supervisor killed | tree killed via `PTRACE_O_EXITKILL`, no half-masked orphans |
| tracee dies mid-injection | the tracee is dropped from the table; the tree continues |
| any failure after the visible spans are known | the visible argv and environment regions are zeroed, one warning is printed, and the session summary counts the exec as `unredacted`; the program may see empty arguments |
| 32-bit image | one warning, not redacted, counted as `foreign-arch` |
| no syscall instruction at a descendant's fork | the secret descriptors stay open in that process; one warning names the pid and the session summary counts each descriptor |
| daemon job fails | exit status returned to the client; the daemon keeps serving |
| daemon socket is stale | the daemon connects to it first; a live daemon refuses the start, a refused connection is unlinked |

The rows that degrade to disclosure print a warning at the default
verbosity and appear in the session summary. `tests/core.sh` drives the
repoint failure with an injected fault (`PMASK_FAULT_POKE`) and the
missing syscall site with `PMASK_FAULT_NOVDSO`.

## Kernel-consistency claim

The kernel never receives the real argv of a masked ELF exec. Two
observers read the command line, and the ordering decides what each one
sees.

- `audit_log_execve_info()` reads from `current->mm->arg_start` at
  syscall exit, which is after the `PTRACE_EVENT_EXEC` stop. The
  relocation has happened by then, so the record carries the label. It
  loops over the real `bprm->argc` and calls `send_sig(SIGKILL)` on
  `-EFAULT`, so the presentation block must satisfy two readers at once:
  `get_mm_cmdline()` wants `arg_end` small, and the audit reader wants
  `argc` NUL-terminated strings from `arg_start`. The block is the label
  followed by `argc` NULs, which does both.
- An eBPF `sched_process_exec` program cannot see argv at all. The
  tracepoint carries `bprm->filename` and two pids, and it fires before
  the ptrace exec stop. A reader cannot recover the arguments there by
  any userland action.

The audit consequence is checked by `tests/audit.sh` where the kernel
sends argument text in its `EXECVE` record. The suite runs as root; a
host whose audit control plane is gated on the initial user namespace
cannot run it.
