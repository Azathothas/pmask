# Evidence: issue 7 — `--env-file` parsed two different grammars

## The defect

`pmask` (`src/cli.rs`) and `pmaskd` (`src/daemon.rs`) each had their own
env-file parser.  The CLI's was a plain `split_once('=')` with no
trailing-CR strip, no `export ` handling, no key validation and no quote
removal; the daemon's had all four.  The same file therefore produced a
different environment on each surface.

## The four rows, measured

`repro.log` is the raw output.  The `od -c` dump is what matters for
row 2, because a CR before an LF is invisible in a terminal.

| row | file | baseline `pmask` | baseline `pmaskd` | fixed `pmask` | fixed `pmaskd` |
|---|---|---|---|---|---|
| 1 | `export FOO=bar` | `export FOO=bar` (a name no program reads) | `FOO=bar` | `FOO=bar` | `FOO=bar` |
| 2 | `CRLF=v\r` | `CRLF=v\r` (`\r` in the dump) | `CRLF=v` | `CRLF=v` | `CRLF=v` |
| 3 | `BAD KEY=v` | accepted, rc 0 | rc 255, `key contains a space` | rc 255, `key contains a space` | rc 255, same words |
| 4 | `K="quoted value"` | `K="quoted value"` | `K=quoted value` | `K=quoted value` | `K=quoted value` |

## The fix

One parser, `pmask::daemon::parse_env_file`, and both surfaces call it:
`src/cli.rs::read_env_file` is now a two-line wrapper that maps the
error to `pmask:`'s exit 255.  The doc comment on the shared function is
the grammar; the `--env-file` line in the CLI help text states it too.

The daemon grammar was the stricter one and is unchanged in substance.
Two deliberate additions, both of which are what the CLI lacked:

- the error for an empty key now also contains `expected KEY=VALUE`, so
  the message that `tests/options.sh` O21 greps for still matches;
- the error kept its `file:line:` prefix, and the CLI no longer wraps it
  in a second `--env-file PATH:` prefix that repeated the path.

## Scope

`src/cli.rs` and `src/daemon.rs` only.  `src/bin/pmaskd.rs` already
called the shared function, so it needed no change.

## Verdicts

- `sh tests/qa.d/7.sh` (fixed): 11 PASS, exit 0 (`qa-fixed.log`).
- The same fragment against `/tmp/basebin` (the `qa-base` build):
  5 PASS, 6 FAIL, exit 6 (`qa-baseline.log`).  The five that pass are
  the fixture check, the three daemon rows (which were already correct)
  and the daemon's refusal.
- `cargo test --locked --lib daemon::` → 20 passed, 0 failed; the six
  new `env_file_*` cases cover every row of the table and the
  "same bytes, same pairs" property.
