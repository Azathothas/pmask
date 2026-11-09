# Issue 42 evidence: `comm`, `cmdline` and `exe` disagree

Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86-64, uid 1000.

| log | what it shows |
|---|---|
| `labels-and-split.log` | the label limits and the four label shapes |
| `comm-lf-stat-parse.log` | what an LF in `--comm` does to `/proc/<pid>/stat` |
| `qa42.log` | the fragment's own output |

## The label limits (measured, `labels-and-split.log`)

```
label=qa42-sshd        cmdline_bytes=10   comm_bytes=10  comm=[qa42-sshd]     tracer=85123
-l-                    cmdline_bytes=2    comm_bytes=2   comm=[ ]             tracer=85137
--label-empty          cmdline_bytes=1    comm_bytes=2   comm=[ ]             tracer=85151
comm=123456789012345   cmdline_bytes=10   comm_bytes=16  comm=[123456789012345]
254-byte label         cmdline_bytes=255  comm_bytes=16  comm=[LLLLLLLLLLLLLLL]
255-byte label         cmdline_bytes=256  + one warning on stderr
--comm 16 bytes        refused: "comm must be at most 15 bytes", rc=255
```

`comm_bytes` is the file length, which includes the trailing newline; the
payload is 15 bytes for the `--comm` case and 254 for the label case
(cut to 15 in `comm`).

The `exe` in every row is `/workspace/wt/bteam1/target/release/pmask-testcases`
— the real binary, not the label.  `TracerPid` is non-zero.  That
conjunction (label == `comm` == `cmdline[0]`, `exe` different, tracer
present) is the masquerade signal.

## The `--comm` LF defect is worse than the issue says

The issue notes that `--comm` "rejects NUL but not LF or CR (#33 upstream),
which breaks the parenthesised part of `/proc/<pid>/stat`".  Measured
(`comm-lf-stat-parse.log`), it does more than that:

```
--- raw /proc/85274/stat (first 2 lines via od):
0000000   8   5   2   7   4       (   a  \n   b   )       S       8   5
--- comm file bytes: 610a620a
--- awk field count on the raw file: 2   (a normal stat is 52)
--- python parse: fields after last ): 50
```

An `awk` that reads the file line by line sees **two fields** and stops.  A
reader that splits on the last `)` gets 50 fields instead of 52, because the
newline inside `comm` was consumed by the line split.  The `arg_start` and
`arg_end` values are still parseable at index 45 and 46 of the remainder, so
a rule that strips through the last `)` survives; anything that reads the
raw file line-wise does not.  `ps -o comm=` renders it as `a?b`.

That is fix1's issue #33 and this batch does not fix it.  The QA fragment
asserts the current behaviour under the name
`c10-comm-lf-accepted-today`, so a fix in #33 shows up as a failing case with
a message pointing at the dependency rather than as a silently different
pass.

## Why no code change

The disagreement is the documented design ("the name is controllable, the
binary is not", README honest limits).  `--rexec` moves it rather than
closing it: measured, `exe` becomes `/memfd:<label> (deleted)` and the
`comm`/`exe` mismatch disappears, at the cost of a memfd name that is its
own signal.  Both are recorded in `docs/research/bteam-39-43.md` §42.
