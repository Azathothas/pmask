# Issue 47 — end states, and the `--detach` release warning

## What was measured

All five documented end states were measured on this host and matched the
issue's report. Nothing in the defaults was changed: `--detach`,
`--no-follow`, `--on-exit detach|wait|kill` and `--no-exit-kill` behave as
documented, and `PTRACE_O_EXITKILL` stays on unless `--no-exit-kill` is
given.

The one gap was that `--detach` released each tracee with no line at the
point of release naming what the run had just given up. The session
summary printed the count at the end, but the process whose later execs
are unredacted was never named while the run was going.

## What changed

`src/tracer.rs`:

- `Tracer::detach` prints one `pmask: warning:` line the first time a
  tracee is released while `--detach` is set:
  `--detach: pid <pid> is released untraced, so its later execs are not
  redacted`.
- The line is gated on `cfg.detach`, so the `--on-exit detach` drain (which
  goes through the same `detach`) does not print it: that release is at
  session end, where a later exec of the process is no longer the run's.
- One line per session (`detach_warned`), following `warn`, so `-q`
  suppresses it and the existing session summary still counts every
  detach. No new counter, no watchdog, no change to the detach timing.

## Evidence

- `qa47.log` — the raw `--detach` run and `tests/qa.d/47.sh`, 17 PASS, 0
  FAIL, 0 SKIP.
- `negative-control.log` — the same fragment against the pre-warning
  `src/tracer.rs` (`git show 424d0e8^`): q47c and q47c2 FAIL, every other
  case PASS, so the end-state assertions are not vacuous.

`tests/qa.d/47.sh` covers: the traced default (control), `--detach`
(TracerPid 0, label kept, environ empty, alive), the release warning and
its `-q` behaviour, `--no-follow` (direct child redacted, grandchild real
and working), `--on-exit detach` (reparented labelled orphan, untraced),
`--on-exit kill` (nothing labelled survives), `--no-exit-kill` (payload
survives SIGKILL to the supervisor, TracerPid 0) and the default
exit-kill control.

## Doc sentence (for the docs agent; do not edit `man/pmask.1` here)

> With `--detach`, pmask prints one warning when it first releases a
> tracee:
> `--detach: pid N is released untraced, so its later execs are not
> redacted`. `-q` suppresses the warning; the session summary still counts
> every detach. The default `--on-exit detach` release at session end does
> not print it.

## What could not be tested

The setuid-after-detach loss of the label (issue 47, "False negatives")
needs a set-uid binary and a mount that honours it; it was not attempted.
Nothing else was blocked.
