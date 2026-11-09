# fix2 evidence: issues 6, 9, 10, 13, 14, 19, 20, 21, 26, 27, 30, 32, 34, 36

Host: LXC container, `uname -r` 6.12.113+deb13-amd64, uid 1000, ptrace
permitted, unprivileged user namespaces permitted, Landlock ABI 6.
Every measurement below was made on this host on 2026-11-09.

## Layout

One directory per issue:

```
<issue>/README.md             what was wrong, what changed, the commands
<issue>/before-fragment.log   tests/qa.d/<issue>.sh on a build of qa-base
<issue>/after-fragment.log    the same fragment on this branch
```

`19/before.log` is the raw reproducer transcript from the unfixed binary.

`run-all.log` is the full native gate (`sh tests/run.sh`) on this branch:
`################ FINAL: ALL-PASS`, exit 0.
`run-all-flaky.log` is an earlier run of the same gate that failed
`o14-on-exit-detach` and `o14-on-exit-wait`; both pass when
`tests/options.sh` is run alone and the next full run was ALL-PASS. That
suite's timing is load-sensitive, not a regression from this branch.

## Gate results on this branch

```
cargo fmt --all -- --check                                              exit 0
cargo clippy --locked --all-targets --features testbins -- -D warnings   exit 0
cargo test --locked --lib                                               174 passed
sh tests/run.sh                                                         exit 0, FINAL: ALL-PASS
sh tests/qa.sh                                                          exit 0, QA: PASS cases=14
```
