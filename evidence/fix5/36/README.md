# Issue 36 evidence, completions part only

Date: 2026-11-09. Host: Linux 6.12.113+deb13-amd64, uid 1000.

Issue #36 has five parts. Part 1 (`--report text`/`--report plain` accepted
and ignored) is fix2's `src/` change; part 2 (`man/pmask.1`) and part 4
(help text vs man page) are the docs agents' files. **The completions part
is mine**, and it is the part that would otherwise ship a wrong suggestion
after fix2's change: all three tables offered `text` and `plain` as
`--report` values.

## Change

The `--report` value list is now `json` alone in:

- `completions/pmask.bash` (the `--report)` arm's `compgen -W` list);
- `completions/pmask.fish` (`-a 'json'`, description says "json only");
- `completions/_pmask` (`:format:(json)`).

`src/` is untouched: the parser change belongs to fix2. If fix2 keeps
`text`/`plain` accepted, the completion is narrower than the parser, which
is the safe direction; the guard below fails only if a table offers a value
the parser does not document.

## Guard

`scripts/check-completions.sh` gained a value-list check: it extracts the
`--report` value list from each of the three tables with a
format-specific sed and fails unless it is exactly `json`.

## Commands and verdicts

`sh scripts/check-completions.sh`: exit 0, `== COMPLETIONS: FAIL=0 ==`,
including:
```
PASS pmask-pmask.bash-report-offers-json-only
PASS pmask-pmask.fish-report-offers-json-only
PASS pmask-_pmask-report-offers-json-only
```

Plant: restore `json text plain` in `completions/pmask.bash`:
```
FAIL pmask-pmask.bash-report-offers-json-only (offers [json text plain])
== COMPLETIONS: FAIL=1 ==
[exit 1; restored file then exit 0]
```
