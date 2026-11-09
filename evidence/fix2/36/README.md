# Issue 36: F17, F22, F25, F27, F28

Commit: `b6822b1 fix: compose redaction with the requested namespaces`.

| item | fix |
|---|---|
| F17 | `--report=text`/`--report=plain` are refused with exit 255 and a message that names the default (`pmask: mode=...` on stderr) |
| F22 | `man/pmask.1` DAEMON MODE now lists `--image` among the refused flags; the code already refused it and a case asserts both |
| F25 | store exit codes are unified and documented: 0 success, 1 a missing secret (`get`, `rm`), 255 usage/store/passphrase errors; `man/pmask.1` states the convention |
| F27 | `--help` and `man/pmask.1` both say `PMASK_SECRET_<NAME>`; the `<N>` spelling is gone |
| F28 | `--image-from-fd`'s `<fd image>` argv[0] placeholder is documented in `--help` and the man page |

## Evidence

- `before-fragment.log`: 9 FAIL.
- `after-fragment.log`: 19 PASS, `== VERDICT: FAIL=0 ==`.

## Commands

```
./target/release/pmask --no-redact --report=text -- /bin/true ; echo $?   # 255
sh tests/qa.d/36.sh    # exit 0, FAIL=0
```
