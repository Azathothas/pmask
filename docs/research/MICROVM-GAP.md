reproducible: yes (sh docs/research/MICROVM-probes/run.sh)

# The micro-VM gap: what a separate kernel would buy, and what it costs

Measured on Linux 6.12.113+deb13-amd64, Debian 13, x86_64, uid 1000,
`CapEff=0000000000000000`, `Seccomp: 2`, `yama.ptrace_scope=0`,
`vm.memfd_noexec=0`, on 2026-11-03 at commit `8c0b06b`. Every number
below is reproduced by `docs/research/MICROVM-probes/run.sh`, whose
output is saved beside it as `run.out`. Claims are marked `[observed]`
(measured here) or `[inferred]` (read from source, not measured).

## 1. What the probes measured

The probe runs twice, as uid 1000 with no capabilities, against two
subjects: a plain sibling process, and a pmask session run as
`pmask --detach --no-dumpable -l microvm-probe -- /bin/sleep 30`.
The second subject is probed twice: the supervisor itself, and the
payload it spawned. Full output is in `run.out`.

## 2. One row per interface

"State in this tree" is what the measurement showed for the *payload*
of a session. `closed` means the interface is refused for a same-uid
peer; `open` means it is readable; `partial` means it is closed only
when an option that is off by default is set; `not attempted` means the
probe could not produce a number.

The last column, `case or limit`, maps each row to its assertion in the
test suite or its documented limit. A `closed` or `partial` row names a
case of `tests/isolation.sh`; an `open` row names a limit row of the
per-interface table in `docs/THREAT-MODEL.md` (the `L<n>` id).

| interface | what it needs | what one process learns about another | what closes it | state | command | case or limit |
|---|---|---|---|---|---|---|
| `/proc` directory listing | nothing | that the pid exists, and its name in `readdir` | nothing in this tree | open | `ls /proc/<pid>` | threat-model L1 |
| `/proc/<pid>/cmdline` | nothing | the label, and its byte length | the window relocation, `relocate_windows` at `src/execimg.rs:875` | closed | `wc -c < /proc/<pid>/cmdline` | tests/isolation.sh i19-cmdline-is-the-label |
| `/proc/<pid>/environ` | nothing on a dumpable target | every environment string | `--no-dumpable`, `src/execimg.rs:833` to `853` | partial | `wc -c < /proc/<pid>/environ` | tests/isolation.sh i21-environ-refused-with-no-dumpable |
| `/proc/<pid>/comm` | nothing | the 15-byte comm, which the tree sets to the label | `PR_SET_NAME` at `src/execimg.rs:817` | closed | `cat /proc/<pid>/comm` | tests/isolation.sh i20-comm-is-the-label |
| `/proc/<pid>/stat` | nothing | the four window bounds, fields 48 to 51 | nothing in this tree | open | `sed 's/^.*) //' /proc/<pid>/stat` | threat-model L2 |
| `/proc/<pid>/status` | nothing | `TracerPid`, `Seccomp`, the capability sets | `--detach` for `TracerPid`, `src/cli.rs:660` | open | `grep TracerPid /proc/<pid>/status` | threat-model L3 |
| `/proc/<pid>/maps` | nothing on a dumpable target | every mapping, including the relocated block | `--no-dumpable` | partial | `wc -c < /proc/<pid>/maps` | tests/isolation.sh i22-maps-refused-with-no-dumpable |
| `/proc/<pid>/smaps` | nothing on a dumpable target | the same, per mapping | `--no-dumpable` | partial | `wc -c < /proc/<pid>/smaps` | tests/isolation.sh i23-smaps-refused-with-no-dumpable |
| `/proc/<pid>/fd` and `fdinfo` | nothing on a dumpable target | open descriptors, including a secret memfd | `--no-dumpable`, plus `--secret-close-on-exec` | partial | `ls /proc/<pid>/fd` | tests/isolation.sh i24-fd-and-fdinfo-refused-with-no-dumpable |
| `/proc/<pid>/exe` | nothing on a dumpable target | the executed file | `--no-dumpable`; `--rexec` changes it to a memfd | partial | `readlink /proc/<pid>/exe` | tests/isolation.sh i25-exe-refused-with-no-dumpable |
| `/proc/<pid>/cwd` and `root` | nothing on a dumpable target | the working directory and root | `--no-dumpable` | partial | `readlink /proc/<pid>/cwd` | tests/isolation.sh i26-cwd-and-root-refused-with-no-dumpable |
| `/proc/<pid>/ns` | nothing on a dumpable target | the namespaces the process is in | `--no-dumpable` | partial | `ls /proc/<pid>/ns` | tests/isolation.sh i27-ns-refused-with-no-dumpable |
| `/proc/<pid>/auxv` | nothing on a dumpable target | `AT_EXECFN`, which the tree repoints | `--no-dumpable` | partial | `wc -c < /proc/<pid>/auxv` | tests/isolation.sh i28-auxv-refused-with-no-dumpable |
| `/proc/<pid>/syscall` | ptrace access | the syscall the target is in | `--no-dumpable` | partial | `cat /proc/<pid>/syscall` | tests/isolation.sh i29-syscall-refused-with-no-dumpable |
| `/proc/<pid>/stack` | `CAP_SYS_ADMIN` | the kernel stack | nothing in this tree; refused `EACCES` here | open to root, refused here | `cat /proc/<pid>/stack` | threat-model L4 |
| `/proc/<pid>/wchan` | nothing | the kernel wait channel | nothing in this tree | open | `cat /proc/<pid>/wchan` | threat-model L5 |
| `/proc/<pid>/io` | nothing on a dumpable target | read and write counters | `--no-dumpable` | partial | `cat /proc/<pid>/io` | tests/isolation.sh i30-io-refused-with-no-dumpable |
| `/proc/<pid>/limits` | nothing | the rlimits | nothing in this tree | open | `cat /proc/<pid>/limits` | threat-model L6 |
| `/proc/<pid>/cgroup` | nothing | the cgroup path | nothing in this tree | open | `cat /proc/<pid>/cgroup` | threat-model L7 |
| `/proc/<pid>/mem` | ptrace access | the payload's own memory, including the original argv | `--no-dumpable` | partial | `dd if=/proc/<pid>/mem` | tests/isolation.sh i31-mem-refused-with-no-dumpable |
| `pidfd_open` | nothing | a stable handle to the pid | nothing in this tree | open | `python3 -c 'os.syscall(434, pid, 0)'` | threat-model L8 |
| `pidfd_getfd` | ptrace access | another process's descriptor | `--no-dumpable` | partial | `pidfd_getfd(pidfd, 1)` | tests/isolation.sh i32-pidfd-getfd-refused-with-no-dumpable |
| `process_vm_readv` | ptrace access | the target's memory without stopping it | `--no-dumpable` | partial | `process_vm_readv(pid, ...)` | tests/isolation.sh i33-process-vm-readv-refused-with-no-dumpable |
| `process_vm_writev` | ptrace access | writes into the target | `--no-dumpable` | partial | `process_vm_writev(pid, ...)` | tests/isolation.sh i34-process-vm-writev-refused-with-no-dumpable |
| `PTRACE_ATTACH` and `PTRACE_SEIZE` | ptrace access | the tracee's registers and memory | `--no-dumpable` | partial | `ptrace(PTRACE_ATTACH, pid, 0, 0)` | tests/isolation.sh i35-ptrace-attach-and-seize-refused-with-no-dumpable |
| `kcmp` | ptrace access | kernel object comparison between two processes | `--no-dumpable` | partial | `kcmp(pid, pid, 0, 0, 0)` | tests/isolation.sh i36-kcmp-refused-with-no-dumpable |
| cgroupfs | nothing | the cgroup hierarchy and the process's place in it | nothing in this tree | open | `cat /proc/<pid>/cgroup` | threat-model L9 |
| netlink `NETLINK_CONNECTOR` and `PROC_EVENTS` | `CAP_NET_ADMIN` | fork, exec and exit events for every pid | nothing in this tree; the socket was created, the bind needs the capability | open to root, refused here | `socket(AF_NETLINK, SOCK_RAW, 11)` | threat-model L10 |
| `SO_PEERCRED` | a shared socket | the peer's pid, uid and gid | nothing in this tree; it is the daemon's own peer check | open | `getsockopt(SOL_SOCKET, SO_PEERCRED)` | threat-model L11 |
| `SO_PEERPIDFD` | a shared socket, kernel 6.5 or newer | a pidfd for the peer | nothing in this tree | open | `getsockopt(SOL_SOCKET, SO_PEERPIDFD)` | threat-model L12 |
| `/dev` nodes | nothing | device presence and modes; `/dev/kvm` is mode 666 here | nothing in this tree | open | `stat /dev/kvm` | threat-model L13 |
| `/proc/net` | nothing | every socket on the host | nothing in this tree | open | `wc -c < /proc/net/tcp` | threat-model L14 |
| `inotify` on `/proc` | nothing | creation and removal of entries | nothing in this tree | open | `inotify_init()` | threat-model L15 |
| `perf_event_open` | `perf_event_paranoid` low enough | sampling of the target | nothing in this tree; refused `EACCES` here | open to a permitted host | `perf_event_open(attr, ...)` | threat-model L16 |
| `userfaultfd` | `vm.unprivileged_userfaultfd` | page-fault handling in another process's memory | nothing in this tree; refused `EPERM` here | open to a permitted host | `userfaultfd(0)` | threat-model L17 |
| `/proc/kcore` | `CAP_SYS_RAWIO` | the whole kernel image | nothing in this tree; refused `EACCES` here | open to root | `head -c 16 /proc/kcore` | threat-model L18 |

### 2.1 What the measurement actually showed

Plain sibling, same uid, dumpable `[observed]`: `cmdline` 14 bytes,
`environ` 2313 bytes, `maps` 3636 bytes, `smaps` 29287 bytes, `auxv`
368 bytes, `exe` 43432 bytes, `mem` refused `EIO`, `stack` refused
`EACCES`. `pidfd_open` ok, `pidfd_getfd` ok, `process_vm_readv` ok
(8 bytes from `0x55b673a27000`), `process_vm_writev` ok (8 bytes to
`0x55b673a32000`), `PTRACE_ATTACH` ok, `PTRACE_SEIZE` ok, `kcmp` ok.

Session payload, `--detach --no-dumpable` `[observed]`:
`TracerPid=0`, `cmdline` 14 bytes and equal to the label
`microvm-probe`, `comm` 14 bytes. Refused with `EACCES`: `environ`,
`maps`, `smaps`, `fd`, `fdinfo`, `exe`, `cwd`, `root`, `ns`, `auxv`,
`syscall`, `stack`, `io`, `mem`. Refused with `EPERM`: `pidfd_getfd`,
`PTRACE_ATTACH`. Still readable: `stat` 185 bytes, `status` 1512 bytes,
`cgroup`, `wchan` 1 byte, `limits`, `loginuid`, `sessionid`,
`mountinfo`, and the directory listing with 56 entries.
`process_vm_readv` and `process_vm_writev` are `not attempted`, because
`maps` is refused, so the probe has no address to aim at; a blind
attempt would return `EFAULT` and prove nothing.

Session supervisor, same run `[observed]`: `cmdline` 14 bytes, the label,
`environ` readable but 0 bytes, `maps` 3185 bytes, `smaps` 28899 bytes,
`auxv` 368 bytes, `exe` 921832 bytes, `TracerPid` set to the probe's own
pid. The supervisor was dumpable in that run. The self-mask
(`mask_self_label_with_window`, `src/selfmask.rs:109` to `158`) zeroes
argv, writes the label, relocates the window and sets `comm`; the tree
now also calls `PR_SET_DUMPABLE(0)` there, at `src/selfmask.rs:148`, so
the supervisor reads above are the pre-change shape and need a
re-measure. The payload's flag is injected in `redact_after_exec` at
`src/execimg.rs:833` to `853`; in the measured run that was the only
process that got it.

The consequence, stated plainly: on a default run, without
`--no-dumpable`, a same-uid peer reads the payload's `environ`, `maps`,
`smaps`, `fd`, `auxv` and memory. `--no-dumpable` is off by default
(`src/mask.rs:347`), and the reason is written at `src/mask.rs:44`: a
debugger and a core dump also stop working. The always-redacted surfaces
are `cmdline` and `comm` `[observed]`.

## 3. What a separate kernel buys, and what it does not

A micro-VM puts the payload behind a second kernel. Three things change:
the host's `/proc` shows one `qemu` process and no tree; a kernel exploit
inside the payload is a kernel exploit against a kernel that holds no
other tenant's data; and every interface in the table above is answered
by the guest kernel rather than the host's. Nothing in the list of
userland mechanisms can close the first two `[inferred]`.

What it does not buy:

- The host kernel still parses every virtio request and every KVM ioctl
  the guest makes, so the host's attack surface grows by the emulated
  device set rather than shrinking `[inferred]`.
- The guest shares the host's page cache, scheduler and CPU caches, so a
  side channel between tenants survives `[inferred]`.
- The host still sees that a process exists, its memory footprint, its
  CPU time and its network traffic, which is the same limit
  `docs/research/ALTERNATIVES-honest-limits.md` names as the first one
  that cannot move.
- A micro-VM does not redact anything: the payload's own `/proc` entry
  inside the guest is whatever the guest's kernel says, so a secret in
  the guest's argv is still visible to another process in the guest
  `[inferred]`.

### 3.1 The price, measured

Boot to a working shell, 256 MiB, one CPU, no network, from the pinned
kernel in `vm/cache` `[observed]`:

| accelerator | run 1 | run 2 | run 3 |
|---|---|---|---|
| KVM, `-cpu host` | 1064 ms | 1079 ms | 1080 ms |
| TCG, `-cpu max` | 3603 ms | 3654 ms | 3492 ms |

The third KVM and TCG numbers come from a manual run of the same command
outside `run.sh`, on the same host, within the same hour. The initramfs
is 639407 bytes: busybox plus an `/init` that prints one marker and
powers off. The kernel image is 11838464 bytes.

What those numbers establish: a micro-VM is reachable on this host, and
the fixed cost per payload is about one second under KVM and about three
and a half seconds under TCG, before the payload itself starts. What
they do not establish: the cost of a micro-VM per *session* for this
tool, because the initramfs here carries no pmask binary, no test
suite and no secret store; the memory overhead of a second kernel per
tenant; the throughput of a payload that does real work under TCG; and
anything about a host without `/dev/kvm`, which was not measured here
beyond the TCG fallback.

### 3.2 The closest userland approximation, and its price

`--unshare` gives the payload its own user, pid and mount namespaces and
mounts a private procfs (`src/mask.rs:1696` calls
`userns::child_setup_proc`; the isolate path calls it at
`src/isolate.rs:1308`). The function tries `hidepid=2`, then
`subset=pid`, then a plain mount at `src/userns.rs:343` to `355`. That
closes the *other* direction of the same limit: the payload cannot
enumerate the host. It costs one `unshare` per session and needs
unprivileged user namespaces, which this host has `[observed]`.

For a deployment where an observer seeing "a process exists" is
unacceptable, the answer is the micro-VM, and the price is the table in
section 3.1 plus a kernel per workload. For a deployment where the
adversary is a same-uid peer reading `/proc`, the answer is
`--no-dumpable`, and the price is the debugger and the core dump.

## 4. What this document does not cover

No suite was run for this document. The probes ran as uid 1000 with no
capabilities; the root-only rows (`/proc/<pid>/stack`, `/proc/kcore`,
`/dev/mem`, netlink `PROC_EVENTS`, `perf_event_open` on a permissive
host, `userfaultfd` on a permissive host) were measured as refusals
here, not as successes on a host that permits them. `sudo -n` was not
used. No eBPF program was loaded, no seccomp filter denying `ptrace` was
installed, and no second tenant was run: the two-tenant test that
`ALTERNATIVES-honest-limits.md` names as what would settle limit 1 is
not built.
