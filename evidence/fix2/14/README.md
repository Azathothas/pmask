# Issue 14: CLI/UX nits N1-N8

Commit: `b6822b1 fix: compose redaction with the requested namespaces`.

| item | fix |
|---|---|
| N1 | plain mode wraps the spawn error with the program name; isolate's `execve` failure prints `pmask: <program>: <errno text>` via `die_exec` (fixed-buffer, no allocation in the child) |
| N2 | `check_comm` validates at parse time, so plain and isolate refuse `--comm` over 15 bytes (and NUL/LF/CR) exactly as redaction does |
| N3 | `--keep-env NAME -- CMD` is refused with "did you mean --keep-env=NAME?"; the bare `--keep-env` switch and the inline list are unchanged, and `--help`/man say the inline form is required |
| N4 | `--args-from-fd`, `--image-from-fd` and `--report-fd` name the offending value |
| N5 | `--help=short` (3.2 KB index) and `pmask help <topic>` for redact/isolate/secret/report/daemon/short; an unknown topic exits 255 |
| N6 | `examples/{basic_mask,env_redaction,supervise}.rs` headers say ptrace is needed and name `pmask probe`/`vm/run.sh` |
| N7 | `-v` lines carry `+SS.microseconds` since session start |
| N8 | `vm/run.sh` builds with `--locked --offline` |

## Evidence

- `before-fragment.log`: 8 FAIL (N1 plain/isolate, N2 plain/isolate,
  N3, N4 x2, N5).
- `after-fragment.log`: 20 PASS, `== VERDICT: FAIL=0 ==`.

## Commands

```
sh tests/qa.d/14.sh                       # exit 0, FAIL=0
./target/release/pmask --help=short | wc -c    # 3237 (full text 13535)
./target/release/pmask help isolate       # one section, exit 0
```
