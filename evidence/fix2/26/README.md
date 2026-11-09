# Issue 26: `--isolate=none` still created user, mount, UTS, IPC and cgroup namespaces

Commit: `b6822b1 fix: compose redaction with the requested namespaces`.

## What changed

- `Isolate` gains a `none` field. `Isolate::none()` is the `none`
  spelling; `Isolate::minimal()` is the old "all three off" value and is
  documented as still creating the unconditional namespaces.
- `parse_isolate("none")` returns `Isolate::none()`.
- The runner never enters `isolate::run` for `none`: the mode selection
  skips the namespace branch, so the payload gets the host's view.
- `isolate::run` refuses `Isolate::none` with an `InvalidInput` error, so
  a library caller cannot ask for it by mistake.
- The run report notes what `none` meant.

## Evidence

- `before-fragment.log`: `NoNewPrivs=1`, a private user and mount
  namespace, an `pmask: isolation:` line and no note.
- `after-fragment.log`: 7 PASS, `== VERDICT: FAIL=0 ==`, including the
  `--isolate` control (NoNewPrivs=1, private user namespace).

## Commands

```
./target/release/pmask --isolate=none -- /bin/sh -c 'grep ^NoNewPrivs /proc/self/status; readlink /proc/self/ns/user'
sh tests/qa.d/26.sh    # exit 0, FAIL=0
```

## Suite change

`tests/isolation.sh` I1 asserted `--isolate=none` still produced the
unconditional namespace report (`pid=off,net=off,tmp=off`). That assertion
encoded the defect, so it now runs `--isolate=pid` for the off-switch case
and adds `i1-none-means-no-isolation` (no report, `NoNewPrivs=0`). The I4
comment that said `--isolate=none` still creates a UTS namespace is
corrected.
