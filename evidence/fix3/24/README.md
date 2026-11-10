# Evidence: issue 24 — documented `pmaskd` ExecStart used `--store`

## What the issue claimed

`contrib/systemd/pmaskd@.service` carried a commented example
`ExecStart=/usr/bin/pmaskd --socket %t/pmask/pmask.sock --store
%S/pmask/store.enc`.  `pmaskd` has no `--store`; copy-pasting the line
gives `pmaskd: unknown option --store` and exit 255, so the unit never
starts.  The encrypted store belongs to `pmask agent`.

## What was measured

Host: Debian container, uid 1000, `pmaskd 0.1.0-beta.1`.

| command | before (`qa-base`) | after |
|---|---|---|
| `pmaskd --store /tmp/x.enc` | `unknown option --store`, rc 255 | same, rc 255 (`repro.log`) |
| `pmaskd --help \| grep -- --store` | no line | no line (`repro.log`) |
| unit, active directives naming `--store` | none — the line was already a comment | none (`baseline-vs-fixed.log`) |
| `pmaskd -S $SOCK` with the unit's real option | socket bound | socket bound (`qa-fixed.log`) |
| `pmask agent --help \| grep -- --store` | names `--store` | names `--store` (`qa-fixed.log`) |

The unit line was already commented out, so the bug was in the
documentation, not in systemd's parse of the file.  The fix replaces the
comment with a note that names `pmask agent`, and the fragment now
asserts that no active directive in the unit names `--store` or
`--passphrase-file`, and that the unit's `ExecStart` still names
`--socket` and still starts.

## Verdict

`sh tests/qa.d/24.sh` → 7 PASS, exit 0 (`qa-fixed.log`).
