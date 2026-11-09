# Team Red: close the 57 issue backlog

This branch closes every open issue on the tracker (57 of them) plus the
dependabot actions bump (PR #37). It is one merge commit on top of
`fa46e62`; the history below it is a batch per area, so a single area can
be reverted without touching the rest.

## What changed, by area

**Core redaction.** The child/tracer handshake is now `PTRACE_INTERRUPT`
on the seized master instead of a self-directed `SIGSTOP`, which the
kernel discards when the child is pid 1 of its own pid namespace; that is
what made `--unshare` and `--redact --isolate` silently skip redaction
(#4). `--redact --isolate=LIST` composes: the tree is redacted and the
child enters exactly the namespaces the list names, including when
`--unshare` is also given (#19, #F2). `--no-redact --isolate` runs the
isolate path instead of falling back to plain (#20). `--isolate=none`
creates nothing (#26). The nested `pmask read NAME` works inside a masked
payload because the argv snapshot comes from the runtime's copy (#5).
`--keep-env` and `--keep-env=NAME` compose in either order (#16). `--comm`
refuses NUL, LF and CR in every mode (#33). `--watch-rename` together with
`--no-dumpable` now redirects the rename to the label already mapped in
the tracee, so it needs no tracee write, and refuses the rename with
`EFAULT` rather than letting the payload choose its own `comm` (#60).
`--audit` survives a closed stdout (#17, and the same class on the new
`--report` path). The secret memfd is `MFD_CLOEXEC` (#15).

**Report and modes.** `--report-file PATH` and `--report-fd N` write the
JSON document somewhere a consumer can parse, opened before the payload
runs; neither descriptor reaches the payload, and a closed stdout no
longer changes the payload's status (#9). `payload_dumpable` is computed
from the selected mode (#21). Every dropped mask option prints one note
(#10). The `exact` capability row reads `n/a` when redaction is
unavailable, and `doctor --require=exact` returns 3 there (#13). `-q`
reaches the isolation report (#27). `--env =VALUE` is refused by the
parser in every mode (#30). `--comm` over 15 bytes is refused in plain
mode too (#14 N2). A ptrace-denied host names the reason and the
secret-side path (#34).

**Daemon.** One `--env-file` grammar for `pmask` and `pmaskd` (#7). The
job deadline is bounded and checked (#18). SIGTERM stops the daemon even
while a client is silent with `--io-timeout 0` (#22). `doctor --json`
escapes every string it builds, and an empty `--require` is a usage error
(#29). The PING body is reduced for a peer that is neither the daemon's
own uid nor root: the policy fields are not on the wire, and the `limits=`
sentence is gone (#51). A response frame no longer panics on a truncated
write.

**Isolation and images.** The private `/dev` carries the host's
`/dev/pts` and `/dev/ptmx` when present, a private `/dev/shm`, and the
stdio links; each absent member is named and counted (#25). `--hugetlb
--image -` and `--image-from-fd` fall back to an ordinary memfd exactly as
the path carrier does (#28). `--args-from-fd` duplicates the caller's
descriptor, so fd 0 keeps working (#31). `--memfd-name` reaches every
image carrier, and `--secret-fd-name` renames the delivered secret memfd
(#45).

**Detection and documentation.** The tracer thread is named after the
session's `comm` instead of the fixed `pmask-tracer`, so one read of the
task directory no longer names every supervised tree on the host (#38).
The four-hunk correction to the detection research is applied and the
numbers are re-measured (#61). The README, `DEPLOY`, `SECURITY`, the man
pages, the completions and the source comments now state what the code
does: `--no-exact` extent, the two-tier PING body, the supervisor's
non-dumpable scope, the audit-log exposure of a `literal:` secret, the
store's owner, and the exit-status contract. The b-team channel studies
are added under `docs/research/bteam-*.md`, each number with its host,
kernel, uid and command.

**Tests.** 54 per-issue fragments under `tests/qa.d/`, dispatched by
`tests/qa.sh` from `tests/run.sh`, each with a negative control or a
named dependency where the property cannot be decided on this host. The
suite has 1086 passing cases on the native gate, and the same gate passes
as root and as uid 1000. The micro-VM gate (`vm/run.sh`) passes both
passes. A completion guard (`scripts/check-completions.sh`) fails the
build when the parser grows an option the tables do not offer.

## What is not claimed

- The audit and eBPF rows are source-level plus the issue authors'
  guest measurements; this development host blocks `tracefs`, eBPF and
  the kernel audit subsystem even for root. The exact refusal is in
  `evidence/bteam3/56/` and `evidence/bteam5/57/`.
- The detector-tool rows (`rkhunter`, `unhide`, `chkproc`) were measured
  from Debian-archive extractions; the four tools with no package
  (`sandfly-processdecloak`, `pspy`, `zapper`, `lsrootkit`) are cited
  from the issues, not re-run.
- The b-team issues that describe the design rather than a defect (#40,
  #42, #43, #44, #46, #48, #49, #50, #52, #53, #54, #56, #57, #58) are
  closed with a test that pins the measured shape and a research note
  that states the residual, not with a code change that would remove the
  documented feature.

## Verification

```sh
cargo build --locked --release --bins --features testbins
cargo fmt --all -- --check
cargo clippy --locked --all-targets --features testbins -- -D warnings
cargo test --locked --lib
sh tests/run.sh          # final: ALL-PASS, 1086 PASS
sudo sh tests/run.sh     # final: ALL-PASS (same-uid rows skip as root)
sh vm/run.sh             # VM-HARNESS: ALL-PASS (root and non-root)
sh scripts/check-completions.sh
sh scripts/check-rename.sh
python3 scripts/notices.py --check
mandoc -T lint -W error man/pmask.1 man/pmaskd.8
```

`ISSUE-CLOSURE.md` maps each issue to the commits, the test and the
evidence directory. `CHANGELOG.md` lists every commit on the branch.
