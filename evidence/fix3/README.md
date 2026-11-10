# Evidence: fix3 (issues 7, 11, 18, 22, 24, 29)

Every log here is raw command output.  Measurement host: Debian
container, kernel `6.12.113+deb13-amd64`, uid 1000, `pmask
0.1.0-beta.1`.  Native ptrace works; tracefs, eBPF and the kernel audit
subsystem are blocked by the container.

Two builds are compared throughout:

- **fixed**: `target/release/{pmask,pmaskd}` built from this branch at the
  commit named in each report.
- **baseline**: `/tmp/basebin/{pmask,pmaskd}`, the `qa-base` build of
  `fa46e62` (plus PR #37), saved before any change.

## Layout

| path | what it is |
|---|---|
| `<issue>/repro.log` | the defect and the fix, side by side, raw |
| `<issue>/qa-fixed.log` | `tests/qa.d/<issue>.sh` against this branch |
| `<issue>/qa-baseline.log` | the same fragment against `/tmp/basebin` |
| `gate-fmt-clippy.log` | `cargo fmt --check` and `cargo clippy -D warnings` |
| `gate-lib-test.log` | `cargo test --locked --lib` |
| `gate-targeted-suites.log` | the suites my files touch |

## Verdicts

| issue | fixed fragment | baseline fragment |
|---|---|---|
| 7 | 11 PASS, exit 0 | 5 PASS / 6 FAIL, exit 6 |
| 11 | 8 PASS, exit 0 | 5 PASS / 3 FAIL, exit 3 |
| 18 | 10 PASS, exit 0 | 3 PASS / 7 FAIL, exit 7 |
| 22 | 8 PASS, exit 0 | 4 PASS / 4 FAIL, exit 4 |
| 24 | 8 PASS, exit 0 | (see 24/README.md — the fix is documentation) |
| 29 | 10 PASS, exit 0 | 3 PASS / 7 FAIL, exit 7 |

Gate: `cargo fmt --check` exit 0, `cargo clippy -D warnings` exit 0,
`cargo test --locked --lib` 188 passed / 0 failed.  Targeted suites
`daemon`, `daemon_neg`, `options`, `secrets`, `core`, `validate` and
`store` all exit 0.

The full `tests/run.sh` was **not** run: the brief says not to run it
concurrently with other agents, and the suites above are the ones my
files touch.  `tests/qa.sh` (the whole fragment set) was also not run,
for the same reason — other agents' fragments live in the same
directory.
