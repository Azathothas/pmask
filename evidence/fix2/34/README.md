# Issue 34: a ptrace-denied host gave a cryptic session error

Commit: `b6822b1 fix: compose redaction with the requested namespaces`.

## What changed

On an `EPERM` session error, `main` asks the cached probe for the reason
(seccomp filter, `yama.ptrace_scope >= 3`, or "not permitted"), prints
`pmask: cannot redact here: <reason>` and points at `--secret` with
`file:` and `agent:` sources. The bare `session error: ...` line is kept.

`tests/helpers/noptrace.c` is a real filter helper: it installs a seccomp
filter that refuses `ptrace(2)` with `EPERM` and then execs the command,
which is the sandboxed-runner shape the issue describes. The fragment
uses it when a compiler is present and falls back to
`PMASK_PROBE_PTRACE=0` only on a host that already refuses ptrace.

## Evidence

- `before-fragment.log`: only `pmask: session error: Operation not
  permitted (os error 1)`; no reason, no advice.
- `after-fragment.log`: `INFO qa34-wrapper: real seccomp filter`, 6 PASS,
  `== VERDICT: FAIL=0 ==`, including the control that the unfiltered host
  redacts and the `--secret ... file:` run that still works under the
  same filter.

## Commands

```
cc -O0 -o /tmp/noptrace tests/helpers/noptrace.c
/tmp/noptrace ./target/release/pmask -q -l x -- /bin/true
sh tests/qa.d/34.sh    # exit 0, FAIL=0
```
