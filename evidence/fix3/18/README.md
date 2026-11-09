# Evidence: issue 18 — `--job-timeout` overflow panicked the daemon

## The defect

`wait_job` computed the job deadline as
`Instant::now() + Duration::from_secs(cfg.job_timeout_secs)`.  That
addition panics on overflow, and `u64::MAX` seconds is about 5.8e11
years, so an operator can reach it from the command line.  The panic
aborts the daemon in the middle of the job, and the client's
`read_exact` of the response frame fails with `failed to fill whole
buffer`.

## What was measured

Host: Debian container, kernel `6.12.113+deb13-amd64`, uid 1000.
Baseline `/tmp/basebin/pmaskd` (`qa-base`, `fa46e62`).

| command | baseline | fixed |
|---|---|---|
| `pmaskd --job-timeout 9223372036854775807` | starts, binds | exits 255 at parse |
| then `pmask --daemon … -- /bin/true` | client rc 255, `failed to fill whole buffer`; **daemon aborted** (`overflow when adding duration to instant`, `src/daemon.rs:2096`) | (no daemon to talk to) |
| `pmaskd --io-timeout 18446744073709551615` | starts, binds (the value is stored but never added) | exits 255 at parse |
| `pmaskd --job-timeout 315360000` (ten years) | starts, serves | starts, serves |
| `pmaskd --job-timeout 315360001` | starts, serves | exits 255 at parse |

Raw output: `repro.log`, `qa-fixed.log`, `qa-baseline.log`.

## The fix, and the second guard

Two layers, because the parse-time cap and the arithmetic are different
defects:

1. `src/bin/pmaskd.rs` refuses a `--job-timeout` or `--io-timeout`
   above `daemon::MAX_TIMEOUT_SECS` (`10 * 365 * 24 * 60 * 60` =
   315360000, ten years).  The message names the flag, the value and
   the limit.
2. `src/daemon.rs::job_deadline` uses `Instant::checked_add` and
   returns `Err(secs)` instead of panicking.  `wait_job` treats that as
   "no deadline" and logs one warning: a library caller that sets
   `DaemonConfig::job_timeout_secs` directly gets a running job rather
   than a dead daemon.

`--io-timeout` is bounded by the same rule.  It is not an
`Instant` addition today (`set_read_timeout` takes the duration
directly, and a Linux `timeval` saturates at u64::MAX rather than
panicking — measured: a `u64::MAX`-second read timeout does not fire
within 1.5 s), but it is the same class of value and the same parse
path, so leaving it unbounded would be a gap in the rule rather than a
separate decision.

## Every other `Duration` addition in the daemon, checked

`grep -n "Instant::now() +" src/daemon.rs` after the fix:

- `stop_workers`: `Instant::now() + WORKER_STOP_GRACE`, a `const
  Duration` of 5 s.  A constant cannot overflow a clock.
- everything else goes through `job_deadline`.

The unit test `every_deadline_arithmetic_in_the_daemon_is_guarded` is a
source scan over the non-test part of `daemon.rs`: it fails on any
`Instant::now() + <non-constant>`.  Planting the old line back makes it
fail with the offending line quoted; reverting the plant makes it pass.
That is the guard's both halves, exercised.

Outside `daemon.rs`, `src/tracer.rs` adds only `DETACH_GRACE` (another
`const`), and the `src/bin/tc/*` additions are test probes with literal
seconds.

## Verdicts

- `sh tests/qa.d/18.sh` (fixed): 10 PASS, exit 0.
- The same fragment against the baseline: 3 PASS, 7 FAIL, exit 7.  The
  failures include the defect itself (`daemon alive after the job: NO`).
- `cargo test --locked --lib daemon::` → 24 passed, 0 failed.
