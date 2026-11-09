# Issue 41 evidence: the shapes of `/proc/<pid>/environ`

Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86-64, uid 1000.
Payload `testcases sleeper MARK` with `PATH`, `VERYSECRET=hunter2` and
`TOKEN=CANARY-pmask-env` planted.

| log | what it shows |
|---|---|
| `environ-shapes.log` | all four shapes, byte-for-byte |
| `keep-env-warning.log` | the new warning and its four negative cases |
| `qa41.log` | the fragment's own output |

## The four shapes (measured, `environ-shapes.log`)

```
default           bytes=0  nuls=0  envspan=0     (empty file)
no-exact          bytes=3  nuls=3  envspan=3     (three NUL bytes)
keep-env          bytes=61 nuls=3  envspan=61    (PATH, VERYSECRET, TOKEN)
keep-env=TOKEN    bytes=25 nuls=3  envspan=25    (\0\0TOKEN=...\0)
keep-env=PATH     bytes=21 nuls=3  envspan=21    (PATH=...\0\0\0)
```

All four confirm the issue.  `--keep-env=NAME` keeps the kept variable as a
full `KEY=VALUE\0` and every other slot as one NUL; the byte length is not
the variable count.

## The warning, and the case it must not fire on

The issue suggests "refusing `--keep-env` together with a `literal:` or
`env:` secret source, or printing a warning that names the leak".  Measured,
a `literal:` secret **never reaches the payload's environment**:

```
== a literal: secret under --keep-env leaves no value in environ
0000000   P   A   T   H   =   /   u   s   r   /   b   i   n   :   /   b
0000016   i   n  \0   P   M   A   S   K   _   S   E   C   R   E   T   _
0000032   T   =   3  \0
```

The descriptor number and the secret name are there; the value is not.  So a
warning that fires on `literal:` would be false, and it would train the
operator to ignore the one that matters.  The implemented check warns only
when an `env:` source reads a variable this run keeps:

| case | warning | exit |
|---|---|---|
| `--keep-env` + `env:HUSH` | 1, names `'T' (env:HUSH)` and "the whole inherited environment" | 0 |
| `--keep-env=HUSH` + `env:HUSH` | 1, names `'T' (env:HUSH)` and "HUSH stays visible" | 0 |
| `--keep-env=OTHER` + `env:HUSH` | 0 | 0 |
| `--keep-env` + `literal:` | 0 | 0 |
| `-E` + `env:HUSH` (the short spelling) | 1 | 0 |
| `-q -E` + `env:HUSH` | 1 (a quiet run is not silent) | 0 |

## The feature is not removed

`qa41.log` `e5-kept-vars-still-kept` runs `--keep-env` with an `env:` secret
and reads HUSH back out of the payload's environ.  The warning changes the
message, not the behaviour.

## Residual

`--keep-env` and `--keep-env=NAME` are documented opt-outs; the shape they
produce is an ordinary process environment.  Nothing in userland can make a
published value unpublished, which is why the answer is a warning and the
documentation pointer to `file:` and `agent:`.  See
`docs/research/bteam-39-43.md` §41.
