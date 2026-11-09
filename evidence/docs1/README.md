# docs1 evidence: README, DEPLOY, SECURITY

Batch: docs. Worktree `/workspace/wt/docs1`, branch `qa/docs1`, base
`d2f331a` (`qa-base` plus the dependabot bump).

No code was built and no suite was run for this batch: the change is
documentation, and the task says no code build is needed. Every claim in
the edited text was checked against one of two things, and each is named
in the row that uses it:

1. **The current tree** (`/workspace/wt/docs1` at `d2f331a`) for what the
   code does *today*. Where today's code is the defect, the text says
   what the fixed behavior is and the report carries a `NOTE FOR MERGE`.
2. **The parallel fix branch that owns the issue**, read with
   `git show <commit>` in `/workspace/wt/fix<N>`. This is what lets the
   text describe the fixed behavior rather than the broken one. The
   commit is named per row below.

The issue reports under `/workspace/meta/issues/` supply the measured
numbers. Those measurements were made by the b-team on their own hosts
(Debian 13 / 6.12.113, Alpine 3.22 / 6.12.115, Artix). This container is
LXC and blocks tracefs, eBPF and the kernel audit subsystem even for
root, so none of them was re-measured here. The text quotes the issue,
it does not claim a new measurement.

## Source of each documented claim

| claim in the docs | issue | checked against |
|---|---|---|
| `literal:` value is in the supervisor's exec record (`EXECVE`, `PROCTITLE`) | 59, 56 | issue 59 capture, quoted; `src/selfmask.rs` ordering |
| `sudo` argv and shell history hold a `literal:` value | 55 | issue 55 measured samples |
| `env:` source is in the caller's environment, not in the exec record | 59 | issue 59, "What is not affected" |
| `--args-from-fd` duplicates the source descriptor, fd 0 keeps working, source is consumed | 31 | `fix4` `f314d9b`, `src/cli.rs` `load_args_fd` |
| `pmask read NAME` works inside a masked payload, and the requirement | 5 | `fix1` `0b01a4f`, `src/mask.rs` `snapshot_argv` |
| mode table: what redact, isolate and plain remove and keep | 10, 19, 20, 21, 26, 27, 32, 49 | `fix2` `b6822b1`; issue 49 measured mode matrix |
| `--redact --isolate=LIST` composes the named namespaces, never substitutes `--unshare` | 19 | `fix2` `b6822b1`, `src/main.rs` `redact_with_isolate` |
| `--isolate=none` means no isolation at all | 26 | `fix2` `b6822b1`, `src/run.rs` `is_none_isolation` |
| `--no-redact --isolate` applies the namespaces and reports `mode=isolate` | 20 | `fix2` `b6822b1`, `src/run.rs` `Selection` |
| `payload_dumpable` comes from the selected mode | 21 | `fix2` `b6822b1`, `src/run.rs` |
| `--audit` is refused in every non-redaction mode | 32 | `fix2` `b6822b1`, `src/run.rs` |
| every dropped mask option gets one note | 10 | `fix2` `b6822b1`, `src/run.rs` notes loop |
| `-q` does not suppress `--audit` rows or the report | 27 | `src/tracer.rs` `print_summary`; `fix2` `b6822b1` |
| fresh `/dev` binds `/dev/pts`, `/dev/ptmx`, private `/dev/shm`, `/proc/self/fd` links, and counts each | 25 | `fix4` `240feec`, `33d5bf0`, `src/isolate.rs` `DEV_EXTRAS` |
| `--hugetlb` falls back to an ordinary memfd on the `--image -` and pipe path | 28 | `fix4` `8bcfcb0`, `f04c75a`, `src/rexec.rs` `prepare_fd` |
| `--keep-env` re-exposes everything, `--keep-env=NAME` the named values, order of the two | 41, 16 | issue 41 shapes 3 and 4; `fix1` `9b3fe5f`, `src/mask.rs` `keep_env_vars` |
| `--no-dumpable` refuses five files and `/proc/<pid>/mem`, and is a fingerprint | 44, 50 | issue 44 EACCES table, issue 50 memory hits |
| the tracer thread, `Tgid != Pid`, `pmask-tracer`, `TracerPid` | 38 | `src/mask.rs` `.name("pmask-tracer")`; issue 38 measured trio |
| the launch window, about 1 ms and 747 microseconds for a script | 48 | issue 48 measured windows |
| memfd names `/memfd:<label>`, `/memfd:pmask-secret`, `/secretmem` | 45 | issue 45; `src/mem.rs` `c"pmask-secret"` |
| defender table links `docs/research/` instead of copying it | 38, 40, 43, 48, 50, 56, 61 | `docs/research/detection-residue.md` read in this worktree |
| the store belongs to `pmask agent`, not `pmaskd` | 24 | `fix3` `a487a5a`; `pmaskd` has no `--store` in `src/bin/pmaskd.rs` |
| tmpfiles has no `f` line for the store | 23 | `fix5` `a5b63b7`, `contrib/tmpfiles.d/pmask.conf` |
| the native gate is run unprivileged and skips the same-uid cases as root | 35 | `fix5` `6fef4c3`, `tests/lib.sh` |
| the daemon socket path is in `/proc/net/unix` and the PING carries counts, not values | 51 | issue 51 measured reply; `src/daemon.rs` `DaemonStatus` |

## Not verified here, and why

- No audit record was produced in this container: the kernel audit
  subsystem is blocked here even for root. The text states the record and
  names its fields, and rests on issue 59's guest capture.
- No eBPF or tracefs measurement: blocked in this container.
- The `--report-file` and `--report-fd` flags do **not** exist in this
  worktree. They are added by `fix2` `b6822b1` (issue 9). The README
  therefore documents only the stdout interleaving, which is true of both
  today's tree and the merged result, and the report back carries the
  exact paragraph to add after the merge.
- The `--isolate` `/dev` extras and the `--hugetlb` pipe fallback are
  documented as the fixed behavior. They are not in this worktree yet;
  the merge note names both.

## Commands run, with exit codes

| command | exit | verdict |
|---|---|---|
| `sh scripts/check-rename.sh` | 0 | no old project name in the tree, log in `check-rename.log` |
| `grep -n "—" README.md docs/DEPLOY.md SECURITY.md` | 1 | no em-dash, log in `style-checks.log` |
| `grep -nE "[A-Za-z0-9,)] -- [A-Za-z]" README.md docs/DEPLOY.md SECURITY.md` | 1 | no prose double hyphen, log in `style-checks.log` |
| `python3 scripts/notices.py --check` | not run | no notice file was touched |
