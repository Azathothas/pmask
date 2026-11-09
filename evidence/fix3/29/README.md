# Evidence: issue 29 — `doctor --json` broke on a quoted path; `--require ''` passed

## The two defects

1. `doctor_json` interpolated the store path and the agent socket path
   into JSON strings without escaping.  `XDG_DATA_HOME='/tmp/qa"path'`
   closed the string early and the report stopped parsing.
2. `doctor --require ''` produced an empty requirement list, which the
   verdict treats as "nothing to check", so the CI assertion exited 0 on
   any host.

## What was measured

Host: Debian container, kernel `6.12.113+deb13-amd64`, uid 1000,
`jq` 1.7.  Baseline is `/tmp/basebin/pmask`, the `qa-base` build of
`fa46e62`.

| command | baseline | fixed |
|---|---|---|
| `XDG_DATA_HOME='/tmp/qa"path' pmask doctor --json \| jq .` | jq exit 5, `Invalid numeric literal at line 38` | jq exit 0, `.store.path` = `/tmp/qa"path/pmask/store.enc` |
| `PMASK_SOCKET='… "…' pmask doctor --json \| jq .` | parse error | parses, value round-trips |
| `XDG_DATA_HOME='…\path' pmask doctor --json \| jq .` | `Invalid escape` | parses |
| `pmask doctor --require '"name"' --json \| jq .` | parse error | parses, `.required[0].name` = `"name"` |
| `pmask doctor --require ''` | exit 0 | exit 255, `--require needs at least one guarantee name` |
| `pmask doctor --require=` | exit 0 | exit 255, same message |
| `pmask doctor --require ','` | exit 0 | exit 255, same message |
| `pmask doctor --require redact` | exit 0 | exit 0 (control) |
| `pmask doctor` (no `--require`) | exit 0 | exit 0 (control) |

Raw output: `repro.log` (both builds, side by side), `qa-fixed.log`
(fragment against this branch), `qa-baseline.log` (same fragment against
`/tmp/basebin/pmask`).

## Scope of the change

`src/subcmd.rs` is the only place in the tree that builds JSON by hand
outside `Caps::report_json`.  `caps.rs` already escapes every string it
interpolates (`json_escape` at `src/caps.rs:738`); `subcmd.rs` had no
escaping at all.  The fix adds a local `json_escape` that escapes `"`,
`\`, `\n`, `\r`, `\t`, `\b`, `\f` and every other C0 byte as `\u00XX`,
and routes the store path, the agent socket and every `--require` name
through it.  `Caps::report_json` is spliced in unchanged, so it keeps
its own escaping.

## Verdict

- `sh tests/qa.d/29.sh` (fixed): 10 PASS, 0 FAIL, exit 0.
- The same fragment against the baseline: 3 PASS, 7 FAIL, exit 7.
  The three that pass are the control cases and `--require redact`,
  which were already correct.
