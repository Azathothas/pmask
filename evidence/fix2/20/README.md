# Issue 20: `--no-redact --isolate` ran plain and silently dropped the isolation

Commit: `b6822b1 fix: compose redaction with the requested namespaces`.

## What changed

`Runner::select_with` no longer returns the forced Plain mode before it
reads the isolate request. `--no-redact --isolate` selects the isolate
path (isolation does not need ptrace), reports `mode=isolate`, and adds a
note saying `--no-redact` was honoured and the namespaces still apply. A
host without user namespaces selects plain with `mode_reason=
isolate_unavailable` and the existing note.

## Evidence

- `before-fragment.log`: `mode=plain`, the payload in the host's user
  namespace, no note.
- `after-fragment.log`: 5 PASS, `== VERDICT: FAIL=0 ==`, including the
  control that plain mode without `--isolate` keeps the host's user
  namespace.

## Commands

```
./target/release/pmask --no-redact --isolate --report=json -- /bin/true | jq '{mode,notes}'
sh tests/qa.d/20.sh    # exit 0, FAIL=0
```
