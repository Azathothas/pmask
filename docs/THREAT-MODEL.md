# Threat model

One row per claim the tool makes, with the mechanism that enforces it and
the test that would catch it regressing. A claim here that the code does
not support is a security bug: file it with the mechanism, the test that
should have caught it, and what you observed instead.

The measurements live in `tests/compare.sh`, `tests/conformance.sh` and
`tests/daemon.sh`; the sources are in `docs/research/`.

## Adversaries

| id | who | what they can do here |
|---|---|---|
| A1 | another account on the host | read `/proc/<pid>/{cmdline,comm,stat,status,cgroup}` for any process; `environ`, `exe`, `maps`, `fd/*`, `mem` need `PTRACE_MODE_READ_FSCREDS`, which a different uid fails |
| A2 | another process of the same account, including a compromised job step | everything A1 can, and the same-uid checks pass, so `environ`, `maps`, `mem` and `fd/*` are readable unless the target is non-dumpable |
| A3 | something that reads metadata later: a monitoring agent, a support bundle, a pasted `ps` output, a terminal recording | whatever it captured at the time |
| root | the host operator, or anything with `CAP_SYS_PTRACE` | everything: `mm` directly, `/proc/<pid>/mem`, the tracee's registers, the supervisor's memory |

## What each claim rests on

| claim | adversary it answers | mechanism | state | test |
|---|---|---|---|---|
| `/proc/<pid>/cmdline` is the label, not the arguments | A1, A2, A3 | pointer-array swap at exec entry; then `PR_SET_MM_MAP` moves `mm->arg_start`/`arg_end` onto a block this tool owns | enforced | `compare.sh` canary column, `conformance.sh` args-hidden, `validate.sh`, `suite.sh` |
| the cmdline byte length is not the original one | A1, A2 | `arg_end = arg_start + len(label) + 1`, so fields 48 to 51 of `/proc/<pid>/stat` agree with the cmdline | enforced where `PR_SET_MM_MAP` works; `--no-exact`, a kernel without `CONFIG_CHECKPOINT_RESTORE` and a seccomp filter denying `prctl` all fall back to a label-derived extent (label plus one NUL per argument) and a NUL `environ` block; the session summary counts it | `compare.sh` span column |
| the NUL padding is not a signature | A1, A2, a detector keyed on NUL runs | the block is exactly the label plus one terminator, so the run is length 1 like an ordinary command | enforced | `compare.sh` nul_count and nul_maxrun: 1 and 1 for a masked run, against 4 for the control |
| `/proc/<pid>/environ` shows nothing | A1, A2, A3 | pointer-array swap to empty strings, then `env_start = env_end` inside the presentation block | enforced by default; `--keep-env=NAME` keeps the named variables and keeps the window addresses | `conformance.sh` environ-hidden, `options.sh` O9/O10, `edge.sh` E10 |
| `comm` is the label | A1, A3 | injected `prctl(PR_SET_NAME)` at each exec completion, and the `--watch-rename` filter for a program that renames itself | enforced | `conformance.sh` comm-is-label, `options.sh` O17 |
| `ps` shows the label | A3 | `ps` reads the same `/proc` files, so the rows above carry it | enforced | `conformance.sh` ps-args-is-label |
| the supervisor's own command line is the label | A1, A2 | the same window relocation, applied by the supervisor to itself | enforced | `conformance.sh` supervisor-selfmask, `edge.sh` E6 |
| a delivered secret never appears in `cmdline`, `environ` or `ps` | A1, A2, A3 | the value travels on a sealed memfd inherited at fd 3 and up; only the name and the fd number sit in the environment, and the environment window is empty | enforced | `daemon.sh` d1 to d3, d3b (the composed daemon path: the job's `environ` is 0 bytes and the daemon's is refused to a same-uid peer) and d7, `conformance.sh` secret-absent |
| the descriptor cannot be modified by the payload | A2 (the payload itself) | `F_SEAL_WRITE\|F_SEAL_GROW\|F_SEAL_SHRINK\|F_SEAL_SEAL` at creation | enforced | `daemon.sh` d7 write-errno, `secrets.sh` c3 |
| the value is gone after a burn | A2 | `--secret-burn` seals without `F_SEAL_SHRINK`, so the reader can `ftruncate(fd, 0)` once | enforced for a cooperating reader; a reader that keeps a copy defeats it, and that is the documented limit | `secrets.sh` c2 |
| a descriptor does not reach what the payload spawns | A2 | `--secret-close-on-exec`: the tracer closes it in each direct child of the payload at that child's fork, before the child runs, and the payload keeps it. A process that shares the payload's descriptor table (`clone(CLONE_FILES)` without `CLONE_THREAD`) cannot be closed without removing the payload's copy, so the run reports a degradation and the session counts it. With `--detach` the tracer is gone after the payload's exec, so the flag cannot be enforced below it; the run prints one warning and the session counts each descriptor that stayed open | enforced for an ordinary fork/exec tree; the shared-table and `--detach` cases are reported degradations | `secrets.sh` c1 with c1b as the control, c1e for the `--detach` warning |
| no core dump, no same-uid attach to the holder | A2 | `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` on the holder before any plaintext is read; the CLI supervisor sets the flag for itself after the self-label, and `--no-dumpable` extends it to the payload | enforced; the supervisor is non-dumpable for the session in every mode | `conformance.sh` dumpable-default, nodumpable-refuses, core-limit-zero, `options.sh` O15, `compare.sh` supervisor column |
| secrets are not swapped out | A2 on a later host, a support bundle | `mlock` per buffer, `MADV_DONTDUMP`, and `memfd_secret` when the kernel has it | best effort: `RLIMIT_MEMLOCK` decides, and the run report names the tier it got | `secrets.sh` e2 squeezes the limit and reads `hardening=heap` |
| `TracerPid` is 0 for the payload | A1, A2, the first line of any detector | `--detach` releases each tracee once its exec has settled | **not the default**: without it every process of the tree carries the supervisor's pid, and the docs say so | `compare.sh` tracer column, 0 only in the `redacted-detach` row; `edge.sh` E18 |
| the kernel's exec audit record carries the label | A3, an audit-based detector | the record is read from `mm->arg_start` at syscall exit, which is after the exec stop and after the relocation | enforced by ordering; measured where the kernel sends argument text: `audit.sh` A1 to A4 and A6 PASS, `VERDICT: FAIL=0`; A5 and A7 are INFO, and A7 reports that the vfork child's audit log does not show the real argv | `audit.sh` A1 to A4 and A6; A7 for the vfork probe |
| an eBPF exec sensor cannot see the arguments before the rewrite | nobody: this row is a limit, not a claim | `trace_sched_process_exec` fires before `ptrace_event(PTRACE_EVENT_EXEC)` and carries only the filename and two pids | a limit; no userland action changes it; the attach is refused on a host without the capability, so the tracepoint fields remain a source reading | none; the attach attempt and its refusal are in `research/detection-residue.md` |
| a same-uid peer cannot read the value out of `/proc/<pid>/mem` | A2 | nothing, by default: the real strings live in the tracee for its life, and `/proc/<pid>/mem` is readable when the target is dumpable | **not enforced**; `--no-dumpable` is the lever, and `compare.sh` publishes the column that shows it | `compare.sh` mem_canary_readable: yes in every row, the control included |
| the tracer thread does not name the tool | A1, A2 | the thread is named after the session's `comm` (or the label), never `pmask-tracer`; the `Tgid != Pid` relation remains | partial: the name is gone, the relation is the ptrace model and cannot be removed in this design | `qa.d/38.sh` (negative control against a pre-fix binary) |
| the supervisor's own entry is masked | A1, A2 | the same window relocation applied to the supervisor, and `PR_SET_DUMPABLE=0` | enforced; `PMASK_NO_SELFMASK` is the documented debug escape and warns when it would publish a secret | `qa.d/39.sh`, `conformance.sh` supervisor-selfmask |
| an image or secret memfd is not named after the tool | A1, A2 | `--secret-fd-name` and `--memfd-name`; the default names are unchanged | opt-in: the default `pmask-secret` and `/memfd:<label>` are deliberate and documented | `qa.d/45.sh`, `conformance.sh` secret-fd-is-memfd |
| a PING does not serve the daemon's policy to another uid | A1 | the full body is for the daemon's own uid and root; another allowed uid gets the protocol facts only, and `limits=` is gone | enforced | `qa.d/51.sh` (two uids) |
| `literal:` and `env:` secrets warn about the audit log and wrapper argv | A3 | one warning before the run names the kernel audit record, shell history and wrapper argv, and points at non-argv sources | enforced; the value is never in the warning | `qa.d/59.sh` |
| the scope description is the label, not the command line | A3 | `systemd-run --description=<label>`; the unit name stays visible in `/proc/<pid>/cgroup` | enforced where a user manager exists | `qa.d/55.sh` (SKIP without a manager) |
| pid, parent chain, cgroup, fds, sockets, start time stay visible | nobody: this row is a limit | nothing; pmask redacts what a process is doing, not that it exists | a limit, stated in the README; a cross-view existence check sees the pid in every channel | `research/detection-residue.md`, one row per interface; `edge.sh` E19 |

## Per-interface limits

The micro-VM gap table in `docs/research/MICROVM-GAP.md` marks each
interface `closed`, `partial` or `open`. A `closed` or `partial` row
names the `tests/isolation.sh` case that asserts it. An `open` row cannot
be asserted by a test that passes, so it names one of the rows below
instead. The `L<n>` id is what the gap table's last column cites.

| id | interface | what a same-uid peer still learns | why this tree cannot close it | what would close it |
|---|---|---|---|---|
| L1 | `/proc` directory listing | that the pid exists, and its name in `readdir` | procfs is the host's; a pid namespace changes what the payload sees, not what the host sees of the payload | a second kernel (micro-VM), where the host sees one qemu process |
| L2 | `/proc/<pid>/stat` | the four window bounds (fields 48 to 51), the state, the parent pid and the start time | `PR_SET_MM_MAP` moves the bounds onto the label block, but the fields remain; `--no-exact` changes their value, not their presence | a second kernel |
| L3 | `/proc/<pid>/status` | `Seccomp`, the capability sets, and `TracerPid` (0 with `--detach`) | status is synthesized from task fields no unprivileged process can rewrite; `--detach` only zeroes `TracerPid` | a second kernel |
| L4 | `/proc/<pid>/stack` | the kernel stack, to a caller with `CAP_SYS_ADMIN`; refused `EACCES` here | the caller's capability decides; the target cannot remove it | a host where the observer lacks `CAP_SYS_ADMIN`, or a second kernel |
| L5 | `/proc/<pid>/wchan` | the kernel wait channel | task state; no userland mechanism rewrites it | a second kernel |
| L6 | `/proc/<pid>/limits` | the rlimits | rlimits are task metadata; lowering them does not hide them | a second kernel |
| L7 | `/proc/<pid>/cgroup` | the cgroup path | the redaction session does not create a cgroup namespace; isolate mode does, and that is a different mode | a cgroup namespace for the payload (isolate mode), or a second kernel |
| L8 | `pidfd_open` | a stable handle to the pid | it needs only the pid and no permission check | a pid namespace where the pid is not valid in the observer's namespace, or a second kernel |
| L9 | cgroupfs | the cgroup hierarchy and the process's place in it | cgroupfs is a host filesystem; a private mount namespace hides it from the payload, not the payload from the host | a second kernel |
| L10 | netlink `NETLINK_CONNECTOR` and `PROC_EVENTS` | fork, exec and exit events for every pid, to a caller with `CAP_NET_ADMIN`; refused here | the kernel generates the events for the host's pid namespace | a host where the observer lacks `CAP_NET_ADMIN`, or a second kernel |
| L11 | `SO_PEERCRED` | the peer's pid, uid and gid on a shared socket | it is the daemon's own peer check; removing it would remove the authorization | not sharing a socket with the observer, or a second kernel |
| L12 | `SO_PEERPIDFD` | a pidfd for the peer on a shared socket, kernel 6.5 or newer | the same peer identity as `SO_PEERCRED`, in a form that survives pid reuse | not sharing a socket with the observer, or a second kernel |
| L13 | `/dev` nodes | device presence and modes; `/dev/kvm` is mode 666 here | the redaction session keeps the host's `/dev`; isolate mode binds a fresh one | isolate mode's private `/dev` (already available), or a second kernel |
| L14 | `/proc/net` | every socket on the host | a net namespace hides the host's sockets from the payload, not the payload's sockets from the host; isolate mode has one, the redaction path does not | a net namespace for the payload (isolate mode), or a second kernel |
| L15 | `inotify` on `/proc` | creation and removal of entries | inotify watches the host's procfs; a private procfs limits what the payload can watch, but the observer watches the host | a second kernel |
| L16 | `perf_event_open` | sampling of the target, when `perf_event_paranoid` allows it; refused `EACCES` here | a kernel policy; the target cannot change the host's setting | a host with a restrictive `perf_event_paranoid`, or a second kernel |
| L17 | `userfaultfd` | page-fault handling in another process's memory, when `vm.unprivileged_userfaultfd` allows it; refused `EPERM` here | a sysctl; the target cannot change the host's setting | a host that disables unprivileged `userfaultfd`, or a second kernel |
| L18 | `/proc/kcore` | the whole kernel image, to a caller with `CAP_SYS_RAWIO`; refused `EACCES` here | root's capability; the target cannot remove it | a host where the observer lacks `CAP_SYS_RAWIO`, or a second kernel |

## What changes when a mechanism is missing

| missing | what the operator loses | how it is reported |
|---|---|---|
| `ptrace` | `cmdline`, `environ` and `comm` are not redacted at all | `probe` marks metadata redaction `unavailable` with the seccomp reason; `run` prints a note; `doctor --require redact` exits 4 |
| `PR_SET_MM_MAP` | the cmdline extent is the label plus one NUL per argument, and `environ` is a NUL block rather than empty | `probe` marks `exact cmdline window` unavailable; the session summary counts each exec that kept its extent |
| unprivileged user namespaces | the payload sees the host's pid, mount and net view | `probe` marks isolation unavailable; `run` prints the substitution |
| `memfd_secret` | the pages are locked but still in the kernel direct map | `probe` marks it unavailable; the run report says `hardening=locked` |
| `mlock` allowed | the secret may reach swap | `probe` names `RLIMIT_MEMLOCK` in bytes; the run report says `hardening=heap` |
| `SO_PEERPIDFD` | a daemon peer is identified by uid and a `/proc` read, which a pid reuse can race | the daemon prints one warning at startup and serves anyway |
| a directory the agent owns | it refuses to bind, rather than put its socket somewhere another account can pre-create | the refusal names the path and the reason |

## What this tool is not

Not a TEE and not a hypervisor. It reduces what `/proc` discloses about a
process to other local accounts and to anything that reads metadata
later. It does not hide that a process exists, does not survive a kernel
observer, and does not make a secret safe from root on the same host. The
README's limit list is the contract; `docs/research/detection-residue.md`
enumerates the interfaces that still tell the truth.
