# Issue 10: plain and isolate modes silently dropped mask options

## What was wrong

Only the label and `--no-dumpable` got a note. `--comm`, `--argv0`,
`--no-exact`, `--detach`, `--watch-rename`, `--rexec`, `--exec-once`,
`--hugetlb`, `--on-exit`, `--no-follow`, `--unshare` and
`--no-new-privs` vanished, contrary to AGENTS.md invariant 13.

Commit: `b6822b1 fix: compose redaction with the requested namespaces`.

## What changed

- `Runner::requested_options` receives `cli.mask_opts`.
- `Runner::run` appends one note per dropped option in plain and isolate
  modes, naming the option and the mode. Options that are satisfied by
  those modes (`--env`, `--env-file`, `--secret*`, `--socket`,
  `--scope-name`, `--keep-env`, `--no-redact`, `--no-new-privs` in
  isolate mode) are not called dropped.
- `--no-dumpable` keeps its specific note.

## Evidence

- `before-fragment.log`: 12 case failures, `"notes": []`.
- `after-fragment.log`: 15 PASS, `== VERDICT: FAIL=0 ==`, including the
  redaction-mode control (no "was not applied" note).

## Commands

```
sh tests/qa.d/10.sh    # exit 0, FAIL=0
```
