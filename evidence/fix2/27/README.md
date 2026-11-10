# Issue 27: `-q` did not suppress the isolation report

Commit: `b6822b1 fix: compose redaction with the requested namespaces`.

## What changed

`isolate::run` takes `quiet`. `report_and_print(report_r, quiet)` always
drains the pipe (a full pipe would block the child) and prints nothing
when `quiet` is set. `Runner::run` passes `self.quiet`, and `main` now
forwards `-q`/`-v` to the runner at all (it previously did not, so the
runner's own `quiet` field was never set from the CLI).

## Evidence

- `before-fragment.log`: the isolation line printed under `-q`.
- `after-fragment.log`: 6 PASS, `== VERDICT: FAIL=0 ==`, including the
  control that the line IS printed without `-q` and the payload exit
  status passes through.

## Commands

```
./target/release/pmask -q --isolate -- /bin/true 2>&1 | wc -l   # 0
sh tests/qa.d/27.sh    # exit 0, FAIL=0
```
