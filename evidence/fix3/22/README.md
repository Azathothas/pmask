# Evidence: issue 22 — SIGTERM could not stop a single-job daemon

## The defect

With `jobs <= 1` the daemon serves the connection inline.  The request
read was a blocking `read_exact` on a socket with `SO_RCVTIMEO` set to
`--io-timeout` seconds.  `--io-timeout 0` clears `SO_RCVTIMEO`, and the
signal handler's `SA_RESTART` restarts the read after `SIGTERM`, so the
`SHUTDOWN` flag was observed only after the read returned — which, for a
client that never sends anything, never happened.  `stop_workers` covered
forked workers only.

## What was measured

Host: Debian container, kernel `6.12.113+deb13-amd64`, uid 1000.
Baseline `/tmp/basebin/pmaskd` (`qa-base`, `fa46e62`).  A silent client
is a `python3` process that connects and then sends nothing.

| configuration | baseline | fixed |
|---|---|---|
| `--jobs 1 --io-timeout 0`, silent client, then `SIGTERM` | still alive after 12 s; the socket was still present | exited in 0 s, status 0, socket removed |
| `--jobs 2 --io-timeout 0`, silent client, then `SIGTERM` | (worker path already stopped) | exited in 1 s |
| a normal job through the inline path | rc passes through | rc passes through |
| `--io-timeout 2`, stalled client | dropped after 2 s | dropped after 2 s |

Raw output: `repro.log`, `qa-fixed.log`, `qa-baseline.log`.

## The fix

The wake is a self-pipe, not `signalfd`: `signalfd` requires blocking the
signals in every thread, and a worker forked after `serve` started must
inherit the same block, while the tracer threads in the same process also
have to see the signal.  A pipe has neither problem and works on every
kernel the project supports.

- `install_signal_handlers` calls `install_wake_pipe` first: `pipe2(O_CLOEXEC |
  O_NONBLOCK)`.  `O_CLOEXEC` keeps the pipe out of a job; `O_NONBLOCK`
  makes the handler's `write` unable to block.  A full pipe already means
  a byte is pending, so a dropped write is harmless.
- `on_signal` sets the flag and calls `wake_notify`, one `write` of one
  byte — async-signal-safe.
- The accept loop's `poll` now carries the listener **and** the wake
  pipe.  Before, `SIGTERM` was seen only on the next 500 ms timeout; now
  it returns at once.
- `handle_conn` wraps the accepted socket in `Conn`.  Every read and write
  goes through `wait_readable` / `wait_writable`, a `poll` on the socket
  and the wake pipe with the `--io-timeout` deadline (or none).  The
  socket stays blocking for the `recvmsg` path, and `read_exact` now sees
  `ConnectionAborted` rather than an endlessly restarted `EINTR`.
- `reject` uses the same waits, so a client that never drains its own
  input cannot keep the daemon in the refusal path either.
- `stop_workers` is unchanged: the bounded 5 s wait and `SIGKILL` remain
  the last resort for a worker that is genuinely stuck.

## The worker model and the inline path are both preserved

`cfg.jobs <= 1` still runs `handle_conn` in the daemon process and
`cfg.jobs > 1` still forks a worker per connection; the only change is
what the connection's waits are made of.  The fragment runs a job and
checks its exit status on both paths.

## Guards, exercised both ways

Three unit tests: a wait with no timeout returns when the pipe fires; the
drain consumes every pending byte (on a pipe the test owns, so a
concurrent daemon cannot change the count); a timed wait still expires
with the pipe in the poll set.

The fragment was also run against a **planted** regression: the old
blocking read, selected by a sentinel file, in the same binary.  It
reproduced the defect exactly (`still alive after 10 s`, socket still
present, client closed only by the harness kill) and the fragment
reported the same four failures as the baseline.  Removing the plant
made all eight cases pass again.

## Verdicts

- `sh tests/qa.d/22.sh` (fixed): 8 PASS, exit 0.
- The same fragment against the baseline: 4 PASS, 4 FAIL, exit 4.
- `sh tests/daemon_neg.sh` → `VERDICT: FAIL=0`, including `n14` (stalled
  client dropped at 2 s) and `n26` (SIGTERM stops a stalled worker).
- `sh tests/daemon.sh` → `VERDICT: FAIL=0`.
- `cargo test --locked --lib` → 188 passed, 0 failed.
