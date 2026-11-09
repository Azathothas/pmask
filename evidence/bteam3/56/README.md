# Issue 56: the auditd records a pmask launch leaves, and the rule forms

## The blocker, and what it produced

This host is an LXC container. The audit subsystem answers `ECONNREFUSED`
on `NETLINK_AUDIT` for both uid 1000 and root, so no record could be
produced or read here. The raw captures are in this directory.

| log | command | output |
|---|---|---|
| `auditctl-s-unprivileged.log` | `auditctl -s` | `You must be root to run this program.` `exit=4` |
| `auditctl-s-root.log` | `sudo auditctl -s` | no output, `exit=0` |
| `auditctl-l-root.log` | `sudo auditctl -l` | `The audit system is disabled` twice, `exit=0` |
| `auditctl-e1-root.log` | `sudo auditctl -e 1` | `The audit system is disabled` twice, `exit=0` |
| `auditctl-watch.log` | `sudo auditctl -w /bin/true -p x -k bteam3` | `Old style watch rules are slower` then `The audit system is disabled`, `exit=1` |
| `auditctl-netlink-strace.log` | `sudo strace -f -e trace=socket,sendto,recvfrom,bind auditctl -s` | socket opens, `AUDIT_GET` answered `error=-ECONNREFUSED` |
| `netlink-audit-get.py`, `netlink-audit-get-uid1000.log`, `netlink-audit-get-root.log` | a raw `AUDIT_GET` from Python | `error=-111` as uid 1000 and as root |
| `auditwatch-blocked.log` | `pmask-testcases auditwatch 2 /tmp/aw.log` | `skip: AUDIT_SET refused: Connection refused (os error 111)` |
| `mount-tracefs.log` | `sudo mount -t tracefs tracefs /sys/kernel/tracing` | `permission denied`, `exit=32` |
| `bpftool.log` | `sudo bpftool prog list` | `sudo: bpftool: command not found` |
| `ausearch.log` | `sudo ausearch -m EXECVE -ts recent` | `Error opening /var/log/audit/audit.log (No such file or directory)`, `exit=1` |

`/var/log/audit` is `root:adm` 0750 and empty even for root, so there is
nothing to read back with `ausearch` either.

**No audit measurement was made on this host.** The finding below rests
on the source, on `tests/audit.sh` (which reads the same records through
its own `NETLINK_AUDIT` client and does not run here either), and on the
guest capture quoted in issues #56 and #59: Alpine 3.22, kernel 6.12.115,
auditd 4.0.3, 11 pmask launches, 6182 audit records.

**What would unblock it**: a host with auditd answering
`auditctl -s` with `enabled=1`, the QEMU guest (`vm/run.sh`) with auditd
staged into the initramfs, or the sand-net microVM.

## What was delivered

`docs/research/bteam-audit.md` — the record shapes (five of them, with
the exact field layout), the rule-form findings (`-w PATH -p x` produces
no exec record; `-a always,exit -S execve` produces one per exec; a
`arch=b32` rule cannot see a 32-bit payload's exec), the blocker above,
and the rules a deployment should install.

`tests/qa.d/56.sh` — 9 cases gated on the host. The gate reads both
`auditctl -s` and `auditctl -l` (a container can make `-s` print nothing
while `-l` still explains the state) and requires `ausearch`; without
them it prints `SKIP` with the reason and exits 0. On this host:

```
$ sh tests/qa.d/56.sh
SKIP 56-audit-subsystem (auditctl -l: The audit system is disabled; auditctl -s printed nothing and exited 0)
== VERDICT: FAIL=0 (SKIP: audit disabled) ==
```

Every gate branch this host can reach was run:
`fragment-gate-branches.log` holds the disabled branch, a variant with no
`auditctl`, and a variant with no `ausearch`. The `no auditctl` and
`no ausearch` variants were produced by editing the search list in a copy
of the fragment, because both tools are installed here.

The 9 record cases cannot run against this kernel. They were exercised
against a fixture instead: `fixture/` holds a fake `auditctl` that answers
`enabled=1`, a fake `sudo`, and a fake `ausearch` that replays the guest
records quoted in issues #56 and #59 (the canary carries `$PPID`, because
the fragment's own canary carries `$$`). The result is
`fragment-against-fixture.log`: 9 PASS, 0 FAIL. That is a test of the
fragment's parsing, **not** a measurement of the kernel: the records it
parsed are the guest's, replayed.

The parsing logic was checked in both directions. Replacing the fixture's
payload record with one carrying a real argv (`a0="/bin/sh" a1="-c" ...`)
makes `56c-payload-record` FAIL, so the row is not vacuous.

## New defect found here, not fixed

None. The one operational finding worth acting on is the `-w` blind spot
already in the issue, now written up in
`docs/research/bteam-audit.md` section 3.2 with the two candidate causes
that were not separated on the guest.

## Files

- `docs/research/bteam-audit.md`
- `tests/qa.d/56.sh`
