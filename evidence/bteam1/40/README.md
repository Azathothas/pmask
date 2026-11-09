# Issue 40 evidence: the argv-window arithmetic

Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86-64, uid 1000.

| log | what it shows |
|---|---|
| `repro-default.log` | default mode: `cmdline` is the label + NUL, arg span == that length, env span 0 |
| `repro-no-exact.log` | `--no-exact`: one NUL, extent kept on this payload |
| `repro-no-exact-args.log` | `--no-exact` with three 40-byte arguments: label + six NULs |
| `no-exact-count-sweep.log` | the NUL-count rule across five argument counts |
| `no-exact-script-path.log` | the post-exec (script) path keeps the real extent |
| `qa40.log` | the fragment's own output |

## Default mode (measured, `repro-default.log`)

```
cmdline   p r o c - e v i d \0           10 bytes, one NUL
arg_start 140049745862656
arg_end   140049745862666                span 10
env_start 140049745862668
env_end   140049745862668                span 0
```

So `cmdline` is exactly the label + NUL, `arg_end - arg_start` equals the
`cmdline` byte count, and `env_start == env_end`.  The `--label-empty` case
is the same arithmetic with a zero-length label: `cmdline` is one NUL,
`argspan` 1, `envspan` 0 (`qa40.log`, `w8`).

## The rule the issue presents does not fire — and neither does its
## alternative, in the way the issue describes

The issue's rule has three clauses and they hold.  What needs care is the
*fourth* thing the issue says: that `--no-exact` "keeps the original cmdline
byte extent".  Measured on this build, the extent is **not** the original:

`no-exact-count-sweep.log`, ELF entry path, label `L9abcdef` (8 bytes):

```
argv_entries=3 cmdline_bytes=11 cmdline_nuls=3 argspan=11 envspan=1
argv_entries=4 cmdline_bytes=12 cmdline_nuls=4 argspan=12 envspan=1
argv_entries=5 cmdline_bytes=13 cmdline_nuls=5 argspan=13 envspan=1
argv_entries=6 cmdline_bytes=14 cmdline_nuls=6 argspan=14 envspan=1
argv_entries=7 cmdline_bytes=15 cmdline_nuls=7 argspan=15 envspan=1
```

That is `bytes == len(label) + argc` and `nuls == argc`, because the whole
original argv was 40-byte arguments that had to be replaced: the redaction
block is built and the visible span zeroed, and the kernel's window is left
at the label+NUL extent because `--no-exact` skips the `PR_SET_MM_MAP` that
would collapse it.  The "one NUL per original argument slot" rule is real;
the "extent kept" part is not, on this build, for the entry path.

The post-exec (script) path is different and does keep the extent
(`no-exact-script-path.log`):

```
cmdline_bytes=142 cmdline_nuls=125 argspan=142 envspan=19
```

142 is the kernel's copy of the interpreter command line; the label was
written over the front of it.

Consequence for a detector: the `--no-exact` rule that survives on both
paths is the *NUL count*, not the extent.  A rule written as "extent >
label length" fires on the script path and misses the ELF path.

## Environment

`--no-exact` also leaves one NUL per environment variable and a non-zero
environment span (`envspan=1` for one variable).  Default mode collapses it
to zero.  `docs/research/bteam-39-43.md` §40 records the trade.

## Not a defect

The arithmetic is the documented design; the fragment asserts it so a
regression is visible.  What the issue got wrong is a documentation matter
and is recorded in the research note, not changed in code.
