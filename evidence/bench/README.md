# Benchmark run

Date: 2026-11-11, read from the evaluation host.
Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86_64, 8 vCPU.
User: uid 1000, `CapEff=0`, `/dev/kvm` usable.
Tool: `pmask 0.1.0-beta.5`, built with `cargo build --release --locked`.
Comparison: zapper v1.1, cloned and built by `measurements/bench.sh`.
Rounds: 5.  Startup n=100, exec n=50, syscall n=100000.
Raw log: `bench.log`.

## Medians

| measurement | baseline | zapper | zapper -f | pmask | pmask --detach | pmask --exec-once --on-exit wait |
|---|---:|---:|---:|---:|---:|---:|
| startup (us) | 2027 | 5425 | 5110 | 4831 | 4958 | 5630 |
| exec (us/exec) | 833 | 824 | 2944 | 1767 | 803 | 2236 |
| syscall loop (us) | 21196 | 20788 | 21285 | 21282 | 21136 | 21415 |
| C build (ms) | 119 | 124 | 157 | 146 | 119 | 145 |

## What the numbers say

- Startup: pmask is faster than zapper (4831 us against 5425 us) and
  slower than a bare exec (2027 us).  The cost is the ptrace handshake,
  the first exec stop and the redaction block.
- Exec throughput: zapper is the fastest because it does not keep a
  tracer.  `pmask --detach` is within noise of zapper (803 us against
  824 us) and gives up later-exec coverage.  The default pmask row is
  1767 us.  `--exec-once --on-exit wait` is 2236 us for this payload:
  the benchmark forks a fresh child for each exec, so the cache redirect
  and the seccomp trap cost more than they save.  The fast path is for a
  session that re-execs the same program in the same tracee, not for a
  fork-per-exec loop.
- Syscall loop: all rows are within the run-to-run spread.  A settled
  tracee is not syscall-traced.
- C build: pmask is 146 ms against 124 ms for zapper, about 18 percent
  slower.  `pmask --detach` is 119 ms, at the baseline.

The benchmark is a point measurement on one host.  The conditions above
are part of the number.  A different kernel, CPU or load will move them.
