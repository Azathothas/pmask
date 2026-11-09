# Issue 30: `--env =VALUE` accepted in plain mode and refused in redact mode

Commit: `b6822b1 fix: compose redaction with the requested namespaces`.

## What changed

The `--env` parser splits `KEY=VALUE` and refuses a missing or empty key,
naming the offending value. Every mode now sees the same error, because
the check is in the one parser they share. The file parser already
refused an empty key; a case confirms it still does.

## Evidence

- `before-fragment.log`: plain exits 0, isolate exits 0, redaction 255.
- `after-fragment.log`: 6 PASS, `== VERDICT: FAIL=0 ==`.

## Commands

```
./target/release/pmask --no-redact --env =VALUE -- /bin/true ; echo $?   # 255
sh tests/qa.d/30.sh    # exit 0, FAIL=0
```
