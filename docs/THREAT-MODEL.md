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
| `/proc/<pid>/environ` shows nothing | A1, A2, A3 | pointer-array swap to empty strings, then `env_start = env_end` inside the presentation block | enforced by default; `--no-exact` keeps a NUL-filled extent, `--keep-env` publishes the whole environment, and `--keep-env=NAME` publishes the named values; all three are in the table below | `conformance.sh` environ-hidden, `options.sh` O9/O10, `edge.sh` E10 |
| `comm` is the label | A1, A3 | injected `prctl(PR_SET_NAME)` at each exec completion, and the `--watch-rename` filter for a program that renames itself | enforced | `conformance.sh` comm-is-label, `options.sh` O17 |
| `ps` shows the label | A3 | `ps` reads the same `/proc` files, so the rows above carry it | enforced | `conformance.sh` ps-args-is-label |
| the supervisor's own command line is the label | A1, A2 | the same window relocation, applied by the supervisor to itself before the fork: zero argv, write the label, collapse the environment, move the window, set `comm`, `PR_SET_DUMPABLE=0` | enforced for `cmdline` and `environ`; the second thread and the `PMASK_NO_SELFMASK` escape are residuals, in the table below | `conformance.sh` supervisor-selfmask, `edge.sh` E6 |
| a delivered secret never appears in `cmdline`, `environ` or `ps` | A1, A2, A3 | the value travels on a sealed memfd inherited at fd 3 and up; only the name and the fd number sit in the environment, and the environment window is empty | enforced | `daemon.sh` d1 to d3, d3b (the composed daemon path: the job's `environ` is 0 bytes and the daemon's is refused to a same-uid peer) and d7, `conformance.sh` secret-absent |
| the descriptor cannot be modified by the payload | A2 (the payload itself) | `F_SEAL_WRITE\|F_SEAL_GROW\|F_SEAL_SHRINK\|F_SEAL_SEAL` at creation | enforced | `daemon.sh` d7 write-errno, `secrets.sh` c3 |
| the value is gone after a burn | A2 | `--secret-burn` seals without `F_SEAL_SHRINK`, so the reader can `ftruncate(fd, 0)` once | enforced for a cooperating reader; a reader that keeps a copy defeats it, and that is the documented limit | `secrets.sh` c2 |
| a descriptor does not reach what the payload spawns | A2 | `--secret-close-on-exec`: the tracer closes it in each direct child of the payload at that child's fork, before the child runs, and the payload keeps it. A process that shares the payload's descriptor table (`clone(CLONE_FILES)` without `CLONE_THREAD`) cannot be closed without removing the payload's copy, so the run reports a degradation and the session counts it. With `--detach` the tracer is gone after the payload's exec, so the flag cannot be enforced below it; the run prints one warning and the session counts each descriptor that stayed open | enforced for an ordinary fork/exec tree; the shared-table and `--detach` cases are reported degradations | `secrets.sh` c1 with c1b as the control, c1e for the `--detach` warning |
| no core dump, no same-uid attach to the holder | A2 | `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` on the holder before any plaintext is read; the CLI supervisor sets the flag for itself after the self-label on the redaction and isolate paths, and on every path once a secret is loaded; `--no-dumpable` extends it to the payload | enforced on every path that holds a secret; a plain run with no secret holds none, does not mask itself, and its report says `mode=plain`; a plain run that holds a secret is made non-dumpable but leaves its own `/proc` entry unmasked | `conformance.sh` dumpable-default, nodumpable-refuses, core-limit-zero, `options.sh` O15, `compare.sh` supervisor column |
| secrets are not swapped out | A2 on a later host, a support bundle | `mlock` per buffer, `MADV_DONTDUMP`, and `memfd_secret` when the kernel has it | best effort: `RLIMIT_MEMLOCK` decides, and the run report names the tier it got | `secrets.sh` e2 squeezes the limit and reads `hardening=heap` |
| `TracerPid` is 0 for the payload | A1, A2, the first line of any detector | `--detach` releases each tracee once its exec has settled | **not the default**: without it every process of the tree carries the tracer thread's id, and the docs say so; the thread shape is in the table below | `compare.sh` tracer column, 0 only in the `redacted-detach` row; `edge.sh` E18 |
| the kernel's exec audit record carries the label | A3, an audit-based detector | the record is read from `mm->arg_start` at syscall exit, which is after the exec stop and after the relocation | enforced by ordering; measured where the kernel sends argument text: `audit.sh` A1 to A4 and A6 PASS, `VERDICT: FAIL=0`; A5 and A7 are INFO, and A7 reports that the vfork child's audit log does not show the real argv | `audit.sh` A1 to A4 and A6; A7 for the vfork probe |
| an eBPF exec sensor cannot see the arguments before the rewrite | nobody: this row is a limit, not a claim | `trace_sched_process_exec` fires before `ptrace_event(PTRACE_EVENT_EXEC)` and carries only the filename and two pids | a limit; no userland action changes it; the attach is refused on a host without the capability, so the tracepoint fields remain a source reading | none; the attach attempt and its refusal are in `research/detection-residue.md` |
| a same-uid peer cannot read the value out of `/proc/<pid>/mem` | A2 | nothing, by default: the real strings live in the tracee for its life, and `/proc/<pid>/mem` is readable when the target is dumpable | **not enforced**; `--no-dumpable` is the lever, and `compare.sh` publishes the column that shows it | `compare.sh` mem_canary_readable: yes in every row, the control included |
| the tracer thread does not name the tool | A1, A2 | the thread is named after the session's `comm` (or the label), never `pmask-tracer`; the `Tgid != Pid` relation remains | partial: the name is gone, the relation is the ptrace model and cannot be removed in this design | `qa.d/38.sh` (negative control against a pre-fix binary) |
| the supervisor's own entry is masked | A1, A2 | the same window relocation applied to the supervisor, and `PR_SET_DUMPABLE=0` | enforced; `PMASK_NO_SELFMASK` is the documented debug escape and warns when it would publish a secret | `qa.d/39.sh`, `conformance.sh` supervisor-selfmask |
| an image or secret memfd is not named after the tool | A1, A2 | `--secret-fd-name` and `--memfd-name`; the default names are unchanged | opt-in: the default `pmask-secret` and `/memfd:<label>` are deliberate and documented | `qa.d/45.sh`, `conformance.sh` secret-fd-is-memfd |
| a PING does not serve the daemon's policy to another uid | A1 | the full body is for the daemon's own uid and root; another allowed uid gets the protocol facts only, and `limits=` is gone | enforced | `qa.d/51.sh` (two uids) |
| `literal:` and `env:` secrets warn about the audit log and wrapper argv | A3 | one warning before the run names the kernel audit record, shell history and wrapper argv, and points at non-argv sources | enforced; the value is never in the warning | `qa.d/59.sh` |
| the scope description is not the command line | A3 | `systemd-run --description=pmask`; the unit name stays visible in `/proc/<pid>/cgroup` | enforced where a user manager exists | `qa.d/55.sh` (SKIP without a manager) |
| pid, parent chain, cgroup, fds, sockets, start time stay visible | nobody: this row is a limit | nothing; pmask redacts what a process is doing, not that it exists | a limit, stated in the README; a cross-view existence check sees the pid in every channel | `research/detection-residue.md`, one row per interface; `edge.sh` E19 |

## Residuals the b-team measured

Every row below is a residual, an attribution channel, or a measured limit.
The state says which. A limit is not a defect and not a promise: it is what a
same-uid observer still sees. The issue number in the first column is the
report that produced the row.

All numbers quoted here were measured on the b-team host: Debian 13, kernel
6.12.113, uid 1000, LXC container, release binary built from the b-team tree
(`fa46e62` plus the branch commits). The audit and eBPF rows are the
exception: they were measured in an Alpine 3.22 guest on kernel 6.12.115
with auditd 4.0.3. They are quoted, not re-measured for this document. The
note named in the row carries the command that produced them.

| claim and issue | adversary | mechanism | state | test |
|---|---|---|---|---|
| the tracer thread is not identifiable (38) | A1, A2 | the thread takes the session `comm` first and the label second, cut to 15 bytes, and never the retired fixed string `pmask-tracer`; `TracerPid` still names a thread whose `Tgid` is the supervisor's pid | limit: the fixed name is gone, the `Tgid != Pid` shape and a nonzero `TracerPid` remain; `--detach`, `--isolate` and `--no-redact` do not produce it | `qa.d/38.sh` reads `/proc/<sup>/task/*/comm` and `Tgid`/`Pid`, with a negative control against a pre-fix binary; `research/bteam-38-50.md` has the measurement |
| the supervisor's own entry carries no other fingerprint (39) | A1, A2, A3 | the self-mask of the row above; the process has two threads, and `PMASK_NO_SELFMASK=1` disables the treatment | partial: the label and the empty environment are enforced; `Threads: 2` and the escape are limits, and `--secret literal:` puts the value in the real argv for the debug window | `conformance.sh` supervisor-selfmask; the thread count and the escape are measured in `research/bteam-39-43.md` |
| the cmdline length equals the `stat` span (40) | A1, A2, a detector | `PR_SET_MM_MAP` sets `arg_end = arg_start + len(label) + 1` and `env_start = env_end` | enforced in exact mode; `--no-exact` writes the label over the arguments and keeps one NUL per argument slot, so the span is the label plus the slot count (measured), and a cross-uid reader gets `0 0 0 0` | `compare.sh` span and NUL columns, `qa.d/40.sh` |
| `environ` reveals nothing (41) | A1, A2, A3 | the environment window is collapsed to zero length | partial: the default and the image family read 0 bytes; `--no-exact` reads a NUL run, and `--keep-env` or `--keep-env=NAME` publishes the values | `conformance.sh` environ-hidden, `options.sh` O9/O10; the four shapes are measured in `research/bteam-39-43.md` |
| the label hides which binary runs (42) | A1, A2 | nothing: `exe`, `maps`, `uid`, sockets, sessions, cgroup and the parent chain stay real | limit: `--rexec` moves `exe` to `/memfd:<label>`, and `--no-dumpable` refuses `exe` and `maps` to the same uid; the `comm`/`exe` split remains readable | `compare.sh` exe and maps columns; the masquerade matrix is in `research/bteam-39-43.md` |
| `/proc/<pid>/auxv` agrees with the label (43) | A1, A2 | the `saved_auxv` rewrite points `AT_EXECFN` at a second label copy at `env_end` | partial: the served view is the label; the payload's own `getauxval(AT_EXECFN)` still returns the real path, which is a limit | none; the relation is measured in `research/bteam-39-43.md` |
| `--no-dumpable` closes same-uid reads (44) | A2 | `PR_SET_DUMPABLE=0` in every tracee, so `environ`, `maps`, `auxv`, `exe` and `fd/*` return `EACCES` to the same uid | partial: enforced where applied; the uniform `EACCES` shape is itself a fingerprint, and plain or isolate mode do not apply it | `conformance.sh` nodumpable-refuses, `compare.sh` supervisor column; `research/bteam-audit.md` |
| a memfd carries no pmask-specific name (45) | A1, A2 | `--secret-fd-name NAME` renames the secret memfd; `--memfd-name NAME` renames the image memfd and the `--exec-once` carrier tag; one validator for both | partial: the defaults are still `/memfd:pmask-secret` and `/memfd:<label>`, the options are cosmetic, and `/secretmem` cannot be named | `tests/qa.d/45.sh`; the default and named sweeps are in `research/bteam-ebpf.md` |
| the rename filter is invisible (46) | A1, A2 | a seccomp filter returns `SECCOMP_RET_TRACE` for `prctl(PR_SET_NAME)` only, and implies `no_new_privs` | limit: `/proc/<pid>/status` reads `Seccomp: 2`, `Seccomp_filters: 2`, `NoNewPrivs: 1`; the supervisor keeps 1 and 0 | `options.sh` O17; the status fields are in `research/bteam-ebpf.md` |
| what the tree looks like when the session ends (47) | A1, A2 | `detach` releases settled tracees, `wait` drains, `kill` signals; `PTRACE_O_EXITKILL` is on by default | limit: a detached tree keeps the label with `TracerPid` 0, `--no-follow` leaves descendants real, and a killed sibling discloses membership | `edge.sh` E18 and E19; the four shapes are in `research/bteam-38-50.md` |
| the real command line is never briefly visible (48) | A1, A2, A3 | the entry swap covers ELF execs; scripts and `vfork` children take the post-exec path | limit: a script payload's real `comm` was readable for a median 307.6 us (min 257.9, max 394.2) on Debian 13, kernel 6.12.113, uid 1000, LXC (`sh measurements/launch-window.sh`, `WINDOW_ROUNDS=3`, `WINDOW_N=60`); the interpreter argv is visible on the same post-exec path, and a poller below about 1 ms can see the window; `--args-from-fd` removes the payload vector from the launcher's argv | `compare.sh` window column; the window and timing figures are in `research/bteam-38-50.md` |
| the label applies in every mode (49) | A1, A2, A3 | plain and isolate do not redact the payload; `--redact --isolate` does; a 32-bit image is refused | partial: documented for plain and isolate; the composed mode now composes, and the 32-bit refusal keeps the real argv | `isolation.sh` I18, `options.sh` O19; the mode matrix is in `research/bteam-audit.md` |
| `/proc/<pid>/mem` does not hold the real argv (50) | A2 | nothing by default: the stack and the anonymous mapping keep the strings | limit: readable to the same uid while the payload is dumpable; `--no-dumpable` closes it | `compare.sh` mem_canary_readable, yes in every row including the control |
| `pmaskd` is not discoverable (51) | A1, A2 | nothing: the bound path is in `/proc/net/unix` and `ss -x`, and a PING describes the daemon's configuration, in full only to the daemon's own uid and root | limit: the name is visible regardless of socket mode; another allowed uid gets `detail=reduced` with the protocol facts only, and no field in either body carries an environment value | `daemon.sh` d1 to d3; `research/bteam-records.md` |
| the daemon tree is not identifiable (52) | A1, A2 | the daemon self-masks; `--jobs N` forks a worker per connection; every job leaf is traced | limit: one label across daemon, worker and leaf, one tracer thread per job, named after the session (38), and a listening socket at the root | `daemon.sh` d1 to d3; `research/bteam-records.md` |
| a refusal or a degradation is silent (53) | A3, a log sweep | every path prints one stable `pmask: ` or `pmaskd: ` line and exits with a stable status | limit: the prefix and the text identify pmask activity even when nothing leaked; `-q` suppresses the diagnostics | `daemon_neg.sh`, the refusal cases in `options.sh`; the string table is in `research/bteam-records.md` |
| pmask leaves nothing on disk (54) | A3, a forensics reader | the store persists 0600 with a magic header; the units, sysusers and tmpfiles entries are installed; the binary carries a `.comment` and pmask-only strings | limit: most runtime artefacts are transient, the store and the packaging are not, and the YARA rule was not re-run | `store.sh`; the footprint table is in `research/bteam-records.md` |
| nothing outside the tree records the command line (55) | A3, A2 with read access to the sink | nothing: `--report=json`, `--audit`, `pmaskd -v`, `sudo`'s child argv, shell history, the `--scope-name` unit description, and `probe`/`doctor` all describe the run | limit: `-q` with no report, audit or scope leaves only the shell history | none; the seven sinks are in `research/bteam-records.md` |
| the kernel audit record carries the label (56, 59) | A3, an audit-based detector | the payload's record is read after the relocation and holds the label plus `argc - 1` empty strings; the supervisor's own record was written before any rewrite | partial: the payload record is enforced; the supervisor record carries the real argv, so a `literal:` secret is recoverable from `EXECVE` and `PROCTITLE` for the life of the log | `audit.sh` A1 to A7; the record shapes and the 11-launch capture (quoted) are in `research/bteam-audit.md` |
| an eBPF exec sensor cannot see the arguments (57) | a kernel-side sensor | `sched_process_exec` carries the filename and two pids and fires before the ptrace stop; `sys_enter_execve` sees the swapped array | limit: the exec tracepoint cannot carry argv; the tracer's `ptrace` and `process_vm_writev` syscalls are the channel that does name the tracer and the target | none in the container (eBPF refused); the guest measurement is in `research/bteam-ebpf.md` |
| the rootkit and hidden-pid detector family finds nothing (58) | a defender | nothing to hide: pmask keeps every pid, `readdir` entry and parent link, and rewrites the contents of three files | limit: the family is blind by construction; `pspy` prints the label, and `strace` is separated by `Tgid == Pid` | none; the tool matrix is in `research/bteam-detectors.md` |

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
