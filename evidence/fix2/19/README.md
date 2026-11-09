# Issue 19: `--redact --isolate=net` discarded the list and applied `--unshare`

## What was wrong

`src/main.rs` rewrote `--redact --isolate` into `cli.mask.unshare()` and
set `cli.isolate = None`, so the parsed `net` selection was never read and
a user+pid+mount set was created. Reproduced in `before.log`.

Commit: `b6822b1 fix: compose redaction with the requested namespaces`.

## What changed

- `main` no longer rewrites the pair. `run_with_secrets` hands the parsed
  `Isolate` to `Runner::redact_with_isolate`.
- The redaction path calls `Mask::namespaces(userns::ChildNs { .. })`,
  built from the `Isolate` fields, so the fork creates exactly the user
  namespace plus the requested pid/net/mount, and mounts a private
  `/proc` only when a pid namespace was asked for.
- `userns::fork_in_userns_with` builds the clone flags from `ChildNs`
  instead of a fixed user+pid+mount set.
- A namespace set the host refuses is reported (mode_reason
  `isolate_unavailable` + note), never replaced by a different set.
- The `--report=json` refusal no longer tells an operator to add
  `--isolate` to a line that already has it.

## Evidence

- `before.log` — the unfixed binary: `--redact --isolate=net` gives the
  host's net namespace and a private pid namespace.
- `before-fragment.log` — the fragment against `qa-base`: 2 FAIL.
- `after-fragment.log` — 6 PASS, `== VERDICT: FAIL=0 ==`:
  `qa19-net-private`, `qa19-pid-is-the-host`, cmdline exactly the label,
  empty environ, and the `--unshare` control that proves the pid row can
  fail.

## Commands

```
./target/release/pmask --redact --isolate=net -- /bin/sh -c 'readlink /proc/self/ns/pid /proc/self/ns/net'
sh tests/qa.d/19.sh    # exit 0, FAIL=0
```
