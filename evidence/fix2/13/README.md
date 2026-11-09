# Issue 13: probe/doctor report the exact cmdline window as active where redaction is unavailable

## What was wrong

The `exact cmdline window` row described `prctl(PR_SET_MM_MAP)` being
callable and printed `active` next to `metadata redaction unavailable`,
which reads as a redaction guarantee. `doctor --require=exact` returned 0.

Commit: `b6822b1 fix: compose redaction with the requested namespaces`.

## What changed

- New `caps::State::Inapplicable(String)`, word `n/a`.
- `exact cmdline window` is `Inapplicable` whenever `metadata redaction`
  is unavailable; its reason says there is no redaction for it to make
  exact. The row stays present, so it is never inferred from an absence.
- `verdict_of` maps `Inapplicable` to 3, so `doctor --require=exact`
  exits 3 with `exact n/a (...)` and the JSON `exit` field agrees.

## Evidence

- `before-fragment.log`: 4 FAIL — the row says `active`, and
  `doctor --require=exact` exits 0 under `PMASK_PROBE_PTRACE=0`.
- `after-fragment.log`: 8 PASS, `== VERDICT: FAIL=0 ==`, including the
  control that a ptrace-capable host keeps `active` and exits 0.

## Commands

```
PMASK_PROBE_PTRACE=0 ./target/release/pmask probe         # exact row n/a
PMASK_PROBE_PTRACE=0 ./target/release/pmask doctor --require=exact ; echo $?   # 3
sh tests/qa.d/13.sh                                       # exit 0, FAIL=0
```
