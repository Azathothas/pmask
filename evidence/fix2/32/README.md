# Issue 32: `--audit` was silently inert when the host selected plain mode

Commit: `b6822b1 fix: compose redaction with the requested namespaces`.

## What changed

- `Runner::audit()` records the request and `Runner::run` refuses it with
  an `InvalidInput` error naming the **selected** mode and the reason
  ("no tracer"), after the probe has decided the mode. The explicit
  `--no-redact`/`--isolate` pair is still refused in `main` before any
  secret is read.
- `main` forwards `cli.audit` to the runner (it previously only set the
  mask's flag, so the runner never knew).

## Evidence

- `before-fragment.log`: `PMASK_PROBE_PTRACE=0 ... --audit` exits 0 with
  no rows and no note.
- `after-fragment.log`: 7 PASS, `== VERDICT: FAIL=0 ==` — exit 255, the
  message names plain mode and the missing tracer, and the control shows
  `--audit` still prints residue rows on a ptrace host.

## Commands

```
PMASK_PROBE_PTRACE=0 ./target/release/pmask -q --audit --secret S=file:/tmp/tok -- /bin/true ; echo $?   # 255
sh tests/qa.d/32.sh    # exit 0, FAIL=0
```
