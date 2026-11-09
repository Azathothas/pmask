# Issue 50: the real argv in the payload's memory

**Status: documented limit, with `--no-dumpable` as the flag that closes it.**
No code change: the default stays dumpable, and the research note records the
trade.

Host: `Linux 6.12.113+deb13-amd64`, Debian 13, x86_64, uid 1000, CapEff 0,
LXC. Binaries: `target/release/pmask`, `target/release/pmask-testcases`
(the fragment uses `tests/testcases`, which `tests/run.sh` installs).

## Files

| file | what it is |
| --- | --- |
| `repro-50.sh` | the reproducer: a plain control, a default session, and a `--no-dumpable` session, each read through `/proc/<pid>/mem` by the same uid |
| `repro-50.log` | the output of that run |

## Command

```sh
TESTBIN=/tmp/testcases-b2 sh evidence/bteam2/50/repro-50.sh   # repro-50.log
sh tests/qa.d/50.sh                                          # the QA fragment
```

The reader is a small C program the script compiles: it walks the readable
mappings of `/proc/<pid>/maps`, `pread`s each through `/proc/<pid>/mem`, and
reports the mappings that contain a unique marker argument. A shell loop over
the same regions takes seconds per megabyte and would time out on a real
payload; the reader finishes in milliseconds.

## What it showed (raw, `repro-50.log`)

```
================ control: a plain process holds its argv
HIT region=5616f3430000-5616f3451000 [heap]
HIT region=7ffe54c5b000-7ffe54c7c000 [stack]
SCAN mappings_read=27 hits=2
================ default mode
payload=3824284 cmdline=b2-50-lab|
HIT region=559259cc0000-559259ce1000 [heap]
HIT region=7fcc3a082000-7fcc3a085000 [stack]
SCAN mappings_read=27 hits=2
supervisor=3824272 mem:
REFUSED maps: Permission denied
================ --no-dumpable
payload=3826263 cmdline=b2-50-lab| state=S (sleeping)
HIT: none
REFUSED maps: Permission denied
payload work: holdargs wrote its report
```

Three facts, in order:

1. The plain control proves the reader works; without it, a zero below would
   be a blind reader.
2. In the default mode the payload's served `cmdline` is the label and its
   memory still holds the real argument vector. That is the residual.
3. `--no-dumpable` makes the same read refuse, the payload keeps running, and
   it finishes its work (`holdargs` wrote its report).

The supervisor's memory is refused in both modes: it applies
`PR_SET_DUMPABLE(0)` to itself before the fork, which is the half the mask
does cover.

## Residual, in one sentence

pmask rewrites what `/proc` serves; it does not erase the payload's stack, and
a same-uid observer recovers the real argv there unless the session runs with
`--no-dumpable`, whose cost is a uniform `EACCES` signature on every `/proc`
file of the tree plus the loss of core dumps and debugger attach.

## Not covered

- The kernel-side view of the supervisor's `process_vm_writev` buffers is
  measured in the issue-48 evidence (`process_vm_writev=7740` in 6 s) but not
  reproduced as a memory read here: tracefs and eBPF are blocked in this
  container.
- `--rexec` and the image family were not exercised for this channel; the
  fragment covers the default mode and `--no-dumpable`, which is what the
  issue names.
