# Issue 33 — evidence

## What was run

```sh
cd tests/qa.d && sh 33.sh                                  # fixed
cd tests/qa.d && TESTBIN_DIR=<baseline> sh 33.sh           # baseline
```

- `repro.log` — the defect and the fix, same command, two binaries.
- `qa-fixed.log` — fragment against `target/release/pmask` on this branch.
- `qa-baseline.log` — the same fragment against the pre-fix build.

## Result

| build | verdict |
|---|---|
| fixed | 7 PASS, 0 FAIL, exit 0 |
| baseline | 3 PASS, 4 FAIL |

Host: Debian 13 container, kernel 6.12.113+deb13-amd64, uid 1000.
