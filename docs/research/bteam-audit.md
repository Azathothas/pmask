# The kernel audit subsystem and pmask

What a pmask launch leaves in the kernel audit log, which rule forms see
it, and which parts of the question this container cannot answer.

Host for every measurement in this document unless the row says
otherwise: Linux 6.12.113+deb13-amd64, Debian 13, x86_64, uid 1000,
CapEff 0, in LXC. pmask `0.1.0-beta.1`, commit `fa46e62` plus the
`qa/bteam3` commits listed at the end.

The guest rows are quoted from the evaluation recorded in issues #56 and
#59: Alpine 3.22, kernel 6.12.115, auditd 4.0.3. They are marked
`[guest]`. Nothing in this document turns a guest measurement into a
measurement of this host.

---

## 1. The blocker on this host, exactly

The audit subsystem is not reachable here, and it fails in three
different ways that are worth separating because each one needs a
different check before a test may run.

`auditctl -s` as uid 1000:

```
$ auditctl -s
You must be root to run this program.
exit=4
```

`auditctl -s` as root prints **nothing at all** and exits 0:

```
$ sudo auditctl -s
exit=0
```

`auditctl -l` as root explains it:

```
$ sudo auditctl -l
The audit system is disabled
The audit system is disabled
exit=0
```

`strace` shows the mechanism: the `NETLINK_AUDIT` socket opens, and the
kernel answers the `AUDIT_GET` request with `ECONNREFUSED`. That is the
kernel's reply to every audit request while auditing is off, and LXC
then keeps it off:

```
$ sudo strace -f -e trace=socket,sendto,recvfrom,bind auditctl -s
socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_AUDIT) = 3
sendto(3, {nlmsg_len=16, nlmsg_type=0x3e8 /* NLMSG_??? */, nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK, nlmsg_seq=1, nlmsg_pid=0}, 16, 0, ...) = 16
recvfrom(3, [{nlmsg_len=36, nlmsg_type=NLMSG_ERROR, nlmsg_flags=0, nlmsg_seq=1, nlmsg_pid=115086}, {error=-ECONNREFUSED, msg={nlmsg_len=16, nlmsg_type=AUDIT_GET, ...}}], 8988, MSG_PEEK|MSG_DONTWAIT, ...) = 36
```

The same refusal from the project's own observer, which registers as the
audit daemon and installs its own rule:

```
$ ./target/release/pmask-testcases auditwatch 2 /tmp/aw.log
auditwatch: skip: AUDIT_SET refused: Connection refused (os error 111) (errno 111)
$ cat /tmp/aw.log.ready
skip: AUDIT_SET refused: Connection refused (os error 111) (errno 111)
```

A raw `AUDIT_GET` over `NETLINK_AUDIT` from Python reproduces the same
errno, as uid 1000 and as root, so the refusal is not `auditctl`'s root
check:

```
reply len=36 type=2 flags=0 seq=1 pid=60625
error=-111
```

`-111` is `ECONNREFUSED`.

The other two kernel-audit-adjacent interfaces are also closed:

```
$ sudo mount -t tracefs tracefs /sys/kernel/tracing
mount: /sys/kernel/tracing: permission denied.
       dmesg(1) may have more information after failed mount system call.
exit=32
$ ls /sys/kernel/tracing
ls: cannot open directory '/sys/kernel/tracing': Permission denied
$ sudo bpftool prog list
sudo: bpftool: command not found
```

`/var/log/audit` exists and is owned `root:adm`, mode 0750, and is
empty even for root, so there is no log to read back. `ausearch` as
uid 1000 reports "Error opening /var/log/audit/audit.log (No such file or
directory)", which is the missing file, not the permission.

```
$ sudo ausearch -m EXECVE -ts recent
Error opening /var/log/audit/audit.log (No such file or directory)
exit=1
$ sudo ls -A /var/log/audit
(no entries)
```

**What would unblock it.** Any of:

1. A host running auditd with `auditctl -s` reporting `enabled=1` (or
   `enabled=2`). The rules in section 5 install and read back there.
2. The repository's QEMU guest (`vm/run.sh`) with `auditd` staged into
   the initramfs. The guest boots a pinned kernel and the suites already
   run as root inside it; `tests/audit.sh` does exactly this for its own
   observer and is the model to copy.
3. The sand-net microVM named in the issue tracker, which has an audit
   subsystem the container does not.

`tests/qa.d/56.sh` performs the gate itself: it asks `auditctl -s` and
`auditctl -l`, requires `ausearch`, and prints `SKIP` with the reason
when either is missing. It does not treat "no auditctl" as a pass.

---

## 2. The records a launch leaves

Five shapes `[guest]`. They are the kernel's; pmask cannot remove any of
them, and the only one it can shape is the payload's, by rewriting the
argument vector before the kernel reads it back.

### 2.1 The supervisor's own exec

```
type=EXECVE msg=audit(1794140348.833:39): argc=11 a0="/opt/pmask/pmask" a1="-v" a2="--label" a3="b4audit" a4="--secret" a5="S=literal:CANARY-pmask-B4-2" a6="--" a7="/bin/sh" a8="-c" a9=7768696C65203A3B20646F203A3B20646F6E65 a10="CANARY-pmask-B4-1"
type=PROCTITLE msg=audit(1794140348.833:39): proctitle=2F6F70742F706D61736B2F706D61736B002D7600...
```

The record holds the whole argument vector of the process that became
pmask: the label, the payload path, every payload argument, and any
`literal:` secret, in cleartext. `a9` is hex because it contains a space;
the kernel hex-encodes an argument with a space in it, and a decoder
that only reads the quoted form misses those slots. `PROCTITLE` holds the
same bytes.

This record is written before pmask runs, so no mechanism inside pmask
can reach it. It is the exposure issue #59 describes, and section 4 is
what pmask now does about it.

A live control from the same run: `/proc/<pmask-pid>/cmdline` was 8 bytes
for the same process, because pmask zeroes its argv block and writes the
label there at startup (`mask::snapshot_argv` then `zero_argv_block`).
The two disagree, and the audit record is the one that survives the run.

### 2.2 The payload's exec

```
type=EXECVE msg=audit(...): argc=4 a0="b4audit" a1="" a2="" a3=""
```

The label in the first slot and one empty string for each remaining slot.
`argc` is the original vector length, so the empty-string count is
`argc - 1`. This shape comes from the exec-entry swap: the pointer array
is rewritten to point at the label and at empty strings in scratch space
before the kernel copies the vector, so the kernel's copy is only ever
the presentation block.

The shape is distinctive enough to be a detector on its own: an ordinary
program with empty arguments exists (`prog "" ""`), but the count is then
the operator's choice, not `argc - 1` for a label that does not match
`comm`. Section 3.1 gives the rule.

### 2.3 The tracer's own syscalls

```
type=SYSCALL ... comm="pmask-tracer" exe="/opt/pmask/pmask" syscall=101        (ptrace)
type=OBJ_PID ... opid=572 ocomm="sleep"
type=SYSCALL ... comm="pmask-tracer" ... syscall=311 a0=572                    (process_vm_writev)
type=SYSCALL ... comm="pmask-tracer" ... syscall=310 a0=572                    (process_vm_readv)
```

Counts from the same capture: `ptrace` 507 records (506 with
`comm="pmask-tracer"`, one `pmask` `PTRACE_TRACEME`), `process_vm_writev`
163, `process_vm_readv` 150, `PR_SET_MM_MAP` 21, `PTRACE_SEIZE` 11 for 11
launches, 11 `OBJ_PID` records naming 11 distinct targets.

The tracer thread's `comm` is set by pmask (`pmask-tracer`), which is
what makes these records attributable. The `comm` is attacker-controlled,
so it is a discriminator only against a detector that is not being
deceived on purpose; for a torn-off binary the records are the strongest
signal, because `ptrace` from an unexpected parent is unusual by itself.

### 2.4 The seccomp install

```
type=SYSCALL ... syscall=157 a0=16 a1=2 comm="b4audit"    (one record, id 782)
```

`157` is `prctl` on x86-64, `a0=16` is `PR_SET_SECCOMP`, `a1=2` is
`SECCOMP_MODE_FILTER`. It appears once in the whole capture, on the only
launch that used `--watch-rename`. `a0=22` (`PR_SET_NAME`) appeared zero
times: the exec-time `comm` is set through the injected vDSO call, which
is not a `prctl` syscall, so a rule watching `PR_SET_NAME` sees nothing.

### 2.5 The memfd exec

```
type=SYSCALL ... syscall=322 comm="memfd:b4audit" a0=...
type=EXECVE ... exe=2F6D656D66643A62346175646974202864656C6574656429
             -> "/memfd:b4audit (deleted)"
```

`322` is `execveat` on x86-64. The `comm` is `memfd:<label>` (the
kernel's name for the anonymous file) and the `exe` field is hex, so a
rule matching the path text does not fire. A rule on the `comm` prefix
`memfd:` does.

---

## 3. The rule forms

### 3.1 What fires

The exit rule fires one record per exec:

```
auditctl -a always,exit -F arch=b64 -S execve -S execveat -k pmask-exec
```

Counting `type=EXECVE` under the key equals the number of execs, in the
guest capture: 323 exec records for 11 launches, 11 of them
`exe="/opt/pmask/pmask"`.

### 3.2 What does not

A path watch does not fire for an exec on the guest:

```
auditctl -w /path/to/binary -p x -k watch-key
```

Four watches, 11 executions of the watched binaries:

```
watch A (busybox on tmpfs)    syscall records under the key: 1   (the auditctl sendto)
watch B (pmask on tmpfs)      syscall records under the key: 1   (the auditctl sendto)
watch C (pmask on rootfs)     syscall records under the key: 1   (the auditctl sendto)
watch D (same path, 2nd run)  syscall records under the key: 1   (unchanged)
exit rule, same binaries      one record per execution, 11 of 11
```

The single record under a watch key is the `auditctl` command that
installed it, not a hit. That is the trap: a count of one looks like a
watch working and it is the installation.

The cause was not separated on the guest. Two candidates remain, and both
need a control run with the watch as the only rule in the tree:

1. The exec event is claimed by an earlier `always,exit` rule on the same
   syscall, so the watch's inode-based match never runs. Kernel audit
   stops at the first matching exit rule for a syscall unless `-F
   execve`-style flags force a second look.
2. `-p x` on a file inode does not cover `execve` at all on 6.12: the
   inode is not the object the `execve` rule is evaluated against.

Either way the operational finding holds and is the one worth acting on:
**do not rely on `-w PATH -p x` to see that a binary ran.** Use the
exit rule.

### 3.3 The 32-bit blind spot

A 32-bit payload keeps its real argv in the `EXECVE` record, because
pmask refuses to redact a foreign ABI and says so once on stderr. Every
record in the capture also says `arch=c000003e`, the architecture of the
syscall that did the exec, not of the image. A rule filtered on
`arch=b32` (`i386`) therefore cannot see the exec at all:

```
auditctl -a always,exit -F arch=b32 -S execve -k b32
```

records nothing for a 32-bit payload, and the `arch=b64` rule does record
it. The exec is a 64-bit `execve` of a 32-bit image.

---

## 4. What pmask does about it

Issue #59 asked for one of two things: a loud warning, or a refusal when
the audit subsystem is enabled. This tree implements the warning, in
`src/cli.rs` at parse time and in `src/run.rs` for the JSON report, and
does not refuse. The reasons are in section 6.

The warning is printed once, at the default verbosity, before the run
starts, for any `literal:` or `env:` source. It names the kernel audit
log, the shell history, a wrapper's argv, `--args-from-fd`, and the three
source forms that avoid all of them (`file:`, `agent:`, `stdin`). It
never includes the value.

The wording follows what the kernel actually records:

| source | in argv | in envp | in the kernel exec record | warning clause |
| --- | --- | --- | --- | --- |
| `literal:` | yes | no | yes, cleartext in `EXECVE` | audit log + history + wrapper argv |
| `env:` | no | yes | no, `EXECVE` carries argv | `/proc/<pid>/environ`, the setter's environment |
| `file:` | no | no | no | none |
| `agent:` | no | no | no | none |
| `stdin` | no | no | no | none |

The audit clause is asserted only for `literal:`. An `env:` value is not
in the exec record, and claiming it would be a false statement in the
operator's log.

`pmask run::audit_state()` asks the kernel the same question `auditctl -s`
does, over `NETLINK_AUDIT` with `AUDIT_GET`, because `auditctl` refuses a
non-root caller before it asks the kernel anything. It answers
`Enabled`/`Disabled`/`Unknown`:

- `Enabled` when the kernel replies with a status message whose
  `enabled` word is 1 or 2. The warning then says the kernel *has already
  written* the argv to its log.
- `Disabled` when the reply is `NLMSG_ERROR` with `ECONNREFUSED`, which
  is the kernel's "auditing is off" answer. The warning says the log
  *would hold it too if the subsystem were enabled*.
- `Unknown` when the socket, the bind, the send or the receive fails, or
  when the reply is neither of the two. The warning says the run *could
  not ask*.

A probe failure never turns the warning into a refusal, so a host that
cannot answer is treated as "warn" and not as "safe".

On this container the probe returns `Disabled` through the second path
because LXC answers `ECONNREFUSED`. That is the same answer a host with
auditing configured off gives, and it is the correct one to act on: there
is no record.

---

## 5. The rules a deployment should install

One launch, correlated, per section 2:

```
auditctl -a always,exit -F arch=b64 -S execve -S execveat -k pmask-exec
auditctl -a always,exit -F arch=b64 -S ptrace -k pmask-trace
auditctl -a always,exit -F arch=b64 -S process_vm_writev -S process_vm_readv -k pmask-vm
auditctl -a always,exit -F arch=b64 -S prctl -k pmask-prctl
```

Do not use `-w PATH -p x` (section 3.2), and do not filter on
`arch=b32` (section 3.3).

The strongest single record rule is the payload's empty-string tail, and
it needs the supervisor record in the same event group to exclude a
program genuinely started with empty arguments:

```
argv[0] != "" and argv[1..argc-1] are all "" and argc >= 2
```

Correlate by `auid` and the audit event id: `EXECVE` and `PROCTITLE` for
one exec share a message id, and `SYSCALL` records for the tracer share
the `auid` of the launch.

---

## 6. What the warning does not do, and why it is a warning

The record is already written when pmask starts. A refusal at parse time
would therefore be late: it would stop the run *after* the secret is in
the log. A refusal is only honest if it happens before the exec, which
means before pmask exists, which means in the shell or the service unit
that started it. That is a documentation and deployment change, not
something pmask can enforce, and `--allow-argv-secret` would then be an
override for a refusal that cannot undo the exposure it is refusing.

So the tree warns, once, and points at `--args-from-fd`, which keeps the
payload's own arguments out of pmask's argv. It does not remove
`literal:`, which remains the documented way to spell a small test value
and whose exposure now has a warning attached.

Two things would change this decision:

1. A measurement on an audit-enabled host showing that the record is
   written for a process pmask can still reach. It is not: the record is
   written at `syscall_exit` of the exec that created pmask's own image.
2. A deployment that can prove it always starts pmask through a wrapper
   that keeps the secret out of argv. That deployment does not need the
   warning, and it will not see it, because a `file:` source produces
   none.

---

## 7. Reproducing this

On a host that passes the gate in `tests/qa.d/56.sh`:

```
auditctl -a always,exit -F arch=b64 -S execve -S execveat -k pmask-exec
pmask -l b4audit --secret S=literal:VALUE -q -- /bin/sh -c 'true'
ausearch -k pmask-exec -i | head -40
```

The supervisor record is the one whose `a0` is pmask's own path. The
payload record is the one whose `a0` is the label.

On this container, the same commands produce nothing, and the reason is
section 1. `tests/qa.d/56.sh` runs the gate and prints `SKIP` with that
reason rather than reporting a pass.

The warning half needs no audit host and is covered by
`tests/qa.d/59.sh`; the audit-enabled wording is driven through
`PMASK_PROBE_AUDIT=1`, which selects the same code path a real enabled
host takes.

---

## 8. Measurements this document does not contain

- No audit record was read on this host. Every record and count in
  section 2 is `[guest]`.
- The cause of the `-w` blind spot was not separated from "an earlier
  rule claimed the event" (section 3.2).
- The `comm="pmask-tracer"` name is set by pmask and is therefore not
  evidence of anything a hostile pmask could not forge.
- Nothing here says what an audit daemon does with a record it cannot
  write, whether the kernel drops it, or how a full log affects the
  syscall. Those are `auditd` properties and none of them was measured.
