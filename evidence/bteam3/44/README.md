# Issue 44: `--no-dumpable` EACCES set and zeroed stat fields

Host: Linux 6.12.113+deb13-amd64, Debian 13, x86_64, uid 1000, CapEff 0,
in LXC. pmask at `target/release/pmask`, commit `fa46e62` plus the
`qa/bteam3` change to `src/run.rs`/`src/cli.rs` (that change is issue 59's
warning and does not touch dumpability).

## What was run

| log | command | what it shows |
|---|---|---|
| `repro-no-dumpable.log` | `sh /tmp/probe44.sh` | the first pass, including the `[ -r ]` comparison that shows `maps` answering yes while `open()` says EACCES |
| `repro-control.log` | `sh /tmp/probe44b.sh --no-dumpable` then `... ""` | the full five-file matrix with the flag and the control without it |
| `observed-set.log` | `sh /tmp/probe44c.sh` | supervisor and payload side by side, `fd` directory and `fd/0`, the `pmask-tracer` thread |
| `dumpable-by-mode.log` | `sh /tmp/ndu.sh` | `PR_GET_DUMPABLE` in the payload for five flag combinations |
| `note-plain.json`, `note-isolate.json` | `pmask --no-redact --no-dumpable --report=json --secret T=file:/etc/hostname -- /bin/true` and the `--isolate` form | the note that says the flag was not applied, and the `payload_dumpable` field issue 21 owns |
| `unshare-vs-dumpable.log` | `sh /tmp/ndu3.sh` | the new defect: `--unshare --no-dumpable` denies only 3 of the 5 |
| `unshare-dumpable-repeat.log` | `sh /tmp/ndu4.sh` | three repeats of the same row |
| `userns-dumpable-control.log` | hand-written C, `/tmp/nd` | the controls that separate the cause of the new defect |
| `userns-mapcurrent-control.log` | `unshare -U --map-current-user /tmp/nd` | the same control with the uid mapped to itself |

## What it showed

The flag's documented shape, reproduced:

```
--no-dumpable
  environ open=denied   maps open=denied   auxv open=denied
  exe     open=denied   fd   open=denied
  cmdline open=ok  stat open=ok
  stat48_51 = 0 0 0 0

control (no flag)
  environ open=ok  maps open=ok  auxv open=ok  exe open=ok  fd open=ok
  stat48_51 = 140415853076480 140415853076492 140415853076494 140415853076494
```

The `[ -r ]` trap is real on this host and only for `maps`:

```
environ access=no   maps access=yes   auxv access=no   exe access=no   fd access=no
```

`maps` is the one file where `access(2)` and `open(2)` disagree here, so a
detector written with `[ -r ]` would report 4 of 5 and miss the shape.
`tests/qa.d/44.sh` records which of the five disagree rather than
assuming it.

`PR_GET_DUMPABLE` in the payload:

```
flags=[]                    1
flags=[--no-dumpable]       0
flags=[--unshare]           1
flags=[--unshare --no-dumpable]  0
flags=[--no-redact --no-dumpable] 1
```

## New defect found here, not fixed

`--unshare --no-dumpable` applies the flag (the payload's own
`PR_GET_DUMPABLE` is 0) but a same-uid observer is refused only three of
the five files:

```
--unshare --no-dumpable
  environ denied  maps ok  auxv denied  exe ok  fd denied
  stat48_51 = 140379359236096 140379359236107 ...   (not zeroed)
```

`/proc/<pid>/exe` resolves to `/usr/bin/sleep` and `maps` lists the real
binary. The cause is the user namespace, not pmask's call: a process that
calls `PR_SET_DUMPABLE 0` inside a user namespace it owns is still
readable by the same uid on the host, because the kernel's dumpable check
compares against the namespace owner. The controls:

```
A  no userns,       PR_SET_DUMPABLE 0 : all five denied, stat 48-51 non-zero
B  unshare -U -r,   PR_SET_DUMPABLE 0 : all five readable
C  unshare -U --map-current-user : maps and exe readable, environ/auxv/fd denied
D  userns owned by root, payload uid 1000 : all five denied
```

Row C matches the pmask observation exactly. Row D shows that the refusal
returns when the reader is not the namespace owner.

This is not issue 44's defect and fixing it is a design question (refuse
the combination, count it as a degradation, or document it), so it is
reported here and left to a fix batch. `tests/qa.d/44.sh` does not assert
the five-file set under `--unshare`; it asserts it under the plain
`--no-dumpable` mode, which is what the issue measured.

## What could not be measured

Nothing for this issue. Every row above was run on this host.

## Files

- `tests/qa.d/44.sh` — the fragment, 14 cases.
- `docs/research/bteam-audit.md` is not this issue's; the audit warning
  lives in `src/run.rs` and `src/cli.rs` under issue 59.
