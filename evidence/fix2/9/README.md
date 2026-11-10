# Issue 9: `--report=json` is not one JSON object when the payload writes to stdout

## What was wrong

The report was written after the payload on the same fd 1, so a payload's
own stdout landed before the document and every JSON consumer failed.

Commit: `b6822b1 fix: compose redaction with the requested namespaces`
(report-file/report-fd part of it).

## What changed

- `--report-file PATH` and `--report-fd N` write the document elsewhere.
- Both open the target **before** the payload runs, so a bad path or a
  closed descriptor is a usage error and no half-run happens.
- `--report-fd` dups the descriptor, so a shell redirect the caller owns
  is not closed.
- The payload stays on fd 1; the interleaving is documented in `--help`,
  `man/pmask.1` (`--report`, `--report-file`, `--report-fd`) and is left
  to the docs agents for README (exact sentence in the final report).

## Evidence

- `before-fragment.log`: `qa9-report-file`/`qa9-report-fd` fail with
  "unknown option", and the control shows the interleaving breaking `jq`.
- `after-fragment.log`: `== VERDICT: FAIL=0 ==`, including
  `qa9-control-interleaving-breaks-json` (the defect, reproduced) and
  both parseable paths.

## Commands

```
sh tests/qa.d/9.sh     # exit 0, FAIL=0
```
