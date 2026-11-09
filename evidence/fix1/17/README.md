# Issue 17 — evidence

## What was run

```sh
cd tests/qa.d && sh 17.sh                                  # fixed
cd tests/qa.d && TESTBIN_DIR=<baseline> sh 17.sh           # baseline
```

- `repro.log` — the defect and the fix, same command, two binaries.
- `qa-fixed.log` — fragment against `target/release/pmask` on this branch.
- `qa-baseline.log` — the same fragment against the pre-fix build.

## Result

| build | verdict |
|---|---|
| fixed | 5 PASS, 0 FAIL, exit 0 |
| baseline | 3 PASS, 2 FAIL |

Host: Debian 13 container, kernel 6.12.113+deb13-amd64, uid 1000.
