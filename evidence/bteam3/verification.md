# bteam3 verification

Host: Linux 6.12.113+deb13-amd64, Debian 13, x86_64, uid 1000, CapEff 0,
in LXC. Every command below was run from `/workspace/wt/bteam3` unless
the transcript says otherwise.

## The gates

```
$ PATH=$PATH:/usr/local/cargo/bin cargo fmt --all -- --check
exit=0

$ PATH=$PATH:/usr/local/cargo/bin cargo clippy --locked --all-targets --features testbins -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.06s
exit=0

$ PATH=$PATH:/usr/local/cargo/bin cargo test --locked --lib
test result: ok. 175 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.57s
exit=0

$ sh scripts/check-rename.sh
exit=0
```

The library tests went from 168 (measured on a clean `qa-base`
checkout) to 175, with seven new `run::tests` cases: `audit_state`,
`the_netlink_reply_parser_reads_the_three_shapes`, the four warning
wordings (literal, env, enabled-audit, disabled-audit), the no-warning
case, and the mixed literal/env source list.  `run::tests` went from 6
`#[test]` functions to 13.

## The fragments

```
$ cd tests && PMASK_BINS_READY=1 sh qa.sh
...
################ QA: PASS cases=4
exit=0
```

46 PASS, 0 FAIL, 1 SKIP. The SKIP is `56-audit-subsystem`: this
container's kernel refuses the audit netlink request, so the nine record
cases cannot run. `evidence/bteam3/56/README.md` is the full account and
`evidence/bteam3/56/fragment-against-fixture.log` is the 9 PASS the same
fragment produces against the replayed guest records, which is a test of
its parsing rather than a measurement of a kernel.

## The suites this batch touches

Run one at a time, never concurrently with `tests/run.sh`:

```
$ PMASK_BINS_READY=1 sh secrets.sh
== VERDICT: PASS=33 FAIL=0 SKIP=0 ==

$ PMASK_BINS_READY=1 sh core.sh
== VERDICT: FAIL=0 ==

$ PMASK_BINS_READY=1 sh options.sh
== VERDICT: FAIL=0 ==

$ PMASK_BINS_READY=1 sh conformance.sh
CONFORMANCE: PASS pass=21 fail=0 skip=3

$ PMASK_BINS_READY=1 sh isolation.sh
== VERDICT: FAIL=0 ==

$ PMASK_BINS_READY=1 sh edge.sh
== VERDICT: FAIL=0 ==          (after the cleanup below)

$ PMASK_BINS_READY=1 sh regressions.sh
== VERDICT: FAIL=0 ==
```

`edge.sh` failed once, on `e6-supervisor-selfmask`, because
`isolation.sh` leaves its `MATRIX_CTL` control payload running: the
sleeper is started with `"$CASES" sleeper "$MATRIX_CAN"` and never
killed, and `cleanup` only calls `kill_comm mkiso`, which does not match
`testcases`. The leaked process's real argv is what `e6` counts as a
leak. Killing it makes `edge.sh` green. That is a defect in
`tests/isolation.sh` (a missing cleanup), not in the product, and it is
recorded in the report rather than fixed here because `isolation.sh` is
not this batch's file.

```
$ ps -eo pid,ppid,args | grep 'testcases sleeper PMKISO'
 820639       1 /workspace/wt/bteam3/tests/testcases sleeper PMKISO-788089
$ kill -9 820639 && PMASK_BINS_READY=1 sh edge.sh
== VERDICT: FAIL=0 ==
```

## The guard, in both directions

`tests/qa.d/59.sh` with `if false &&` wrapped around the warning in
`src/cli.rs`: six cases FAIL (`59a-one-warning`,
`59a-warning-names-the-artefacts-and-the-way-out`, `59f`,
both `59g`, `59h`). Source restored, re-run, `== VERDICT: FAIL=0 ==`.

`tests/qa.d/56.sh` with the fixture's payload record replaced by one
carrying a real argv: `56c-payload-record` FAILs. Fixture restored.

`tests/qa.d/49.sh` with the musl binary copied over `tests/pmask`: the
`--unshare` rows turn into `SKIP ... (the redaction defect is #4 ...)`,
which is the branch that must not pass when the build serves the real
argv. The release build takes the other branch and passes.
