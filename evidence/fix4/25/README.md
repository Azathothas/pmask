# Issue 25 — `--isolate` and the fresh `/dev`

## What was measured

Host: LXC container, Debian, uid 1000, kernel 6.12 (the kernel version is
what `uname -r` reported at the time of the run; the logs carry the raw
command output).

Before the fix, `./pmask -q --isolate -- /bin/sh -c 'ls /dev/pts'` printed
`ls: cannot access '/dev/pts': No such file or directory`, and
`python3 -c 'import pty; pty.openpty()'` raised `OSError: out of pty
devices`, while the report line said `dev` applied with no degradation.
That is the defect in the issue.

## What changed

`src/isolate.rs`:

- The six original nodes in `DEV_NODES` stay exactly as they were.
- `mount_private_dev` now also opens the host's `/dev/pts` and `/dev/ptmx`
  with `O_PATH` before the tmpfs replaces `/dev`, and binds each into the
  fresh `/dev` when the host has it.
- `/dev/shm` is a private tmpfs, mode 1777, `MS_NOSUID|MS_NODEV`.
- The four stdio links (`/dev/fd`, `/dev/stdin`, `/dev/stdout`,
  `/dev/stderr`) are created from one table, `DEV_LINKS`, and the count is
  reported.
- A missing optional member never fails the run: the member is left out and
  a `pmask: isolation degraded:` line names it.
- The optional members travel in a third status byte after the Landlock
  counts (`Report::dev_extra`), so the report can count what it got.
  `FRAME_LEN + 3` replaced `FRAME_LEN + 2`.

`tests/isolation.sh` I8 now expects `pts`, `ptmx` and `shm`, and keeps the
host-leak control over the nodes that are still not part of the fresh
`/dev` (`kvm`, `mqueue`, `fuse`, `net`, `console`, `log`, `core`,
`initctl`).

## Evidence

- `qa25.log` — the raw commands and `tests/qa.d/25.sh`, all PASS except one
  SKIP (this host has every optional member, so the degradation path has no
  member to name).
- `negative-control.log` — the same fragment against the pre-fix
  `src/isolate.rs`: q25b, q25c and q25d FAIL.

## Doc sentence (for the docs agent; do not edit `man/pmask.1` here)

> `--isolate` gives the payload a fresh `/dev` holding the six basic
> device nodes (`null`, `zero`, `full`, `random`, `urandom`, `tty`), the
> host's `/dev/pts` and `/dev/ptmx` bound in when the host has them, a
> private `/dev/shm` of mode 1777, and the `/dev/fd`, `/dev/stdin`,
> `/dev/stdout` and `/dev/stderr` links. A member the host lacks or the
> kernel refuses is left out and named in a `pmask: isolation degraded:`
> line; it never fails the run.

## What could not be tested

Nothing was blocked. A host with no `/dev/pts` would exercise the
degradation line; this host has all three members, so q25g prints SKIP.
