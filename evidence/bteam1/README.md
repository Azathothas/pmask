# b-team evidence: summary

One directory per issue, each with a `README.md` and the raw logs the README
points at.  Host for every measurement: Debian 13, kernel
`6.12.113+deb13-amd64`, x86-64, uid 1000 (`agent`), `ptrace_scope` 0, native
ptrace working, `NETLINK_AUDIT` refused with `ECONNREFUSED` for both uids.
Build: `pmask 0.1.0-beta.1`, commit `fa46e62` plus this batch.

| issue | verdict | one line |
|---|---|---|
| [39](39/README.md) | partially closable | the escape's silent publication now warns and, on an audited host, refuses; the supervisor's own shape stays |
| [40](40/README.md) | not a defect | the arithmetic holds; `--no-exact` does not keep the extent on the ELF entry path |
| [41](41/README.md) | design limit, contradiction warned | four environ shapes reproduced; a `literal:` value never reaches environ, so the warning covers `env:` only |
| [42](42/README.md) | design limit | all label limits reproduced; `--comm` LF/CR is fix1 #33 and is recorded, not fixed |
| [43](43/README.md) | design limit | the served label and the in-payload dissent reproduced; `AT_EXECFN == env_end` is conditional and `--no-exact` does not rewrite auxv |

## Reproducing

From the worktree root after
`cargo build --release --bins --features testbins`:

```sh
cd tests
sh qa.d/39.sh    # the self-mask, the escape, the audit refusal
sh qa.d/40.sh    # the argv window arithmetic
sh qa.d/41.sh    # the environ shapes and the keep-env warning
sh qa.d/42.sh    # the label limits and the comm/cmdline/exe split
sh qa.d/43.sh    # AT_EXECFN
```

`39/window-measure.sh` is standalone and reproduces the escape's window; run
it from the worktree root.

## What was not run

`tests/run.sh` and `vm/run.sh`.  This batch is instructed not to run the full
gate while other agents share the host; the five fragments and
`cargo test --locked --lib` were run instead.
