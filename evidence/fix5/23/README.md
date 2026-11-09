# Issue 23 evidence: tmpfiles pre-creates an empty store.enc

Date: 2026-11-09 (host date from `date -u`). Host: see `uname -a` below.
Run as uid 1000, no root needed.

## Change

`contrib/tmpfiles.d/pmask.conf`: dropped

```
f /var/lib/pmask/store.enc 0600 pmask pmask -
```

Kept

```
d /var/lib/pmask 0700 pmask pmask -
```

`pmask store init` creates the file, its mode (0600) and its header
itself; a zero-byte file left by tmpfiles makes it refuse with
"already exists" (255), and `store set` refuses the truncated header.

`contrib/sysusers.d/pmask.conf` was checked for the same class of
pre-creation defect: it only declares the `u pmask` account with
`/var/lib/pmask` as its home. It creates no file inside the store
directory, so it is correct as shipped and was not edited.
`docs/DEPLOY.md` names `install -d` for the directory and none for the
store file (docs are owned by the docs agents; no edit made).

## Guard

`tests/qa.d/23.sh` is a static check (no `f`/`w` line naming
`store.enc`, the `d` line present and 0700) plus a behavioural check
(a directory shaped the way the remaining entry shapes it must let
`store init` succeed and yield a 98-byte file with the `PMASKSTORE1`
magic and mode 0600). The negative control pre-creates a zero-byte
`store.enc` and requires `store init` to refuse with "already exists",
so the behavioural case cannot pass vacuously.

## Commands and verdicts

`planted-f-line.log` — the old `f` line appended, `sh qa.d/23.sh`:

```
FAIL qa23-tmpfiles-has-no-store-file-line (the f line pre-creates store.enc)
FAIL qa23-tmpfiles-names-no-store-file-in-any-form
QA23: FAIL (2)
[exit 1]
```

`fixed.log` — the committed file, same command:

```
PASS qa23-tmpfiles-has-no-store-file-line
PASS qa23-tmpfiles-keeps-the-directory-line
PASS qa23-tmpfiles-directory-mode-is-0700
PASS qa23-control-a-pre-created-store-file-breaks-init
PASS qa23-fresh-directory-starts-empty
PASS qa23-store-init-succeeds-in-a-tmpfiles-style-directory (rc=0)
PASS qa23-store-init-writes-the-magic (98 bytes)
PASS qa23-store-file-mode-is-0600
PASS qa23-tmpfiles-names-no-store-file-in-any-form
QA23: PASS
[exit 0]
```

## Raw `uname -a`

See `uname.log`.
