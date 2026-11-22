# Issue closure

Each issue below has a provenance row and a detail section.
The `fix commit` column names the commit or release that fixes the issue.
A value of `none` marks a measurement, design boundary, or record item with no code fix, where the test and note form the closure.
The `commits` column holds provenance commits that reference the issue or carry its test, evidence, or documentation.
The `test` column names the automated check that fails if the behaviour regresses.
The `evidence` column names the directory or report holding the recorded logs.

| # | issue | fix commit | commits | test | evidence |
|---|---|---|---|---|---|
| 4 | `--unshare` / `--redact --isolate` silently disables redaction | `d0cadd7`, `f740675` | `b48373f`, `398eda3`, `74b7b6a` | `tests/qa.d/4.sh` | `evidence/fix1` |
| 5 | `pmask read NAME` fails inside a masked payload | `0b01a4f` | `320c056`, `b48373f`, `398eda3` | `tests/qa.d/5.sh` | `evidence/fix1` |
| 6 | `pmask store --help` and `pmask get --help` do not print help | `96a6c82` | `fa0204a`, `96a6c82` | `tests/qa.d/6.sh` | `evidence/fix2` |
| 7 | `--env-file` parses two different grammars in pmask and pmaskd | `8b505d6` | `8b505d6` | `tests/qa.d/7.sh` | `evidence/fix3` |
| 8 | Completions miss seven flags | `07340b9` | `07340b9` | `scripts/check-completions.sh` (run by `tests/run.sh`) | `evidence/fix5` |
| 9 | `--report=json` is not one JSON object when the payload writes to stdout | `b6822b1` | `ad77b37`, `fa0204a` | `tests/qa.d/9.sh` | `evidence/fix2` |
| 10 | Plain and isolate modes silently drop mask options | `b6822b1` | `2e1627b`, `fa0204a` | `tests/qa.d/10.sh` | `evidence/fix2` |
| 11 | An unknown `--secret` scheme is silently delivered as a literal | `efbc85b` | `efbc85b` | `tests/qa.d/11.sh` | `evidence/fix3` |
| 12 | `isolation.sh`, `compare.sh` and `conformance.sh` never run in CI | `030197a` | `030197a` | `.github/workflows/ci.yml` `native-suites` job | `evidence/fix5` |
| 13 | `probe`/`doctor` report the exact cmdline window as active where redaction is unavailable | `b6822b1` | `2e1627b`, `fa0204a` | `tests/qa.d/13.sh` | `evidence/fix2` |
| 14 | Assorted small CLI/UX nits (N1–N8) | `d61e6b7`, `b6822b1` | `d61e6b7`, `2e1627b`, `fa0204a` | `tests/qa.d/14.sh` | `evidence/fix2` |
| 15 | The supervisor's `memfd_secret` buffer is not `MFD_CLOEXEC`, so the plaintext leaks into the tree | `8797876` | `b48373f`, `398eda3` | `tests/qa.d/15.sh` | `evidence/fix1` |
| 16 | `--keep-env` followed by `--keep-env=NAME` exposes the whole environment | `9b3fe5f` | `b48373f`, `398eda3` | `tests/qa.d/16.sh` | `evidence/fix1` |
| 17 | `--audit` aborts the supervisor on a closed stdout and kills the payload | `9e1de9d` | `320c056`, `b48373f`, `398eda3` | `tests/qa.d/17.sh` | `evidence/fix1` |
| 18 | `--job-timeout` overflow panics the daemon | `15c638f` | `15c638f` | `tests/qa.d/18.sh` | `evidence/fix3` |
| 19 | `--redact --isolate=net` discards the list and applies `--unshare` | `b6822b1`, `2b1dc3a` | `ad77b37`, `2e1627b`, `2b1dc3a`, `fa0204a`, `96a6c82` | `tests/qa.d/19.sh` | `evidence/fix2` |
| 20 | `--no-redact --isolate` runs plain and silently drops the isolation | `b6822b1` | `2e1627b`, `fa0204a` | `tests/qa.d/20.sh` | `evidence/fix2` |
| 21 | `payload_dumpable` is false in plain mode while the payload is dumpable | `b6822b1` | `fa0204a` | `tests/qa.d/21.sh` | `evidence/fix2` |
| 22 | SIGTERM cannot stop a single-job daemon while a client is silent with `--io-timeout 0` | `62e9811` | `62e9811` | `tests/qa.d/22.sh` | `evidence/fix3` |
| 23 | The tmpfiles entry creates an empty store file, so `store init` fails | `a5b63b7` | `a5b63b7` | `tests/qa.d/23.sh` | `evidence/fix5` |
| 24 | Documented `pmaskd` ExecStart uses `--store`, which `pmaskd` does not accept | `a487a5a` | `a487a5a` | `tests/qa.d/24.sh` | `evidence/fix3` |
| 25 | `--isolate` gives the payload a `/dev` without `/dev/pts`, `/dev/ptmx` or `/dev/shm` | `240feec`, `1a4309a`, `014b66c`, `5b96f6e`, `33d5bf0` | `882c9eb`, `33d5bf0`, `7f80d21`, `ecd419d` | `tests/qa.d/25.sh` | `evidence/fix4` |
| 26 | `--isolate=none` still creates user, mount, uts, ipc and cgroup namespaces | `b6822b1` | `2e1627b`, `8dc0db0`, `fa0204a` | `tests/qa.d/26.sh` | `evidence/fix2` |
| 27 | `-q` does not suppress the isolation report | `b6822b1` | `2e1627b`, `fa0204a` | `tests/qa.d/27.sh` | `evidence/fix2` |
| 28 | `--hugetlb --image -` fails instead of falling back to an ordinary memfd | `f04c75a`, `8bcfcb0` | `7f80d21`, `ecd419d` | `tests/qa.d/28.sh` | `evidence/fix4` |
| 29 | `doctor --json` breaks on a quoted store path; `doctor --require ''` passes | `bdc6b37` | `bdc6b37` | `tests/qa.d/29.sh` | `evidence/fix3` |
| 30 | `--env =VALUE` is accepted in plain mode and refused in redact mode | `b6822b1` | `12e4740`, `fa0204a` | `tests/qa.d/30.sh` | `evidence/fix2` |
| 31 | `--args-from-fd 0` closes the payload's stdin | `f314d9b` | `7f80d21`, `ecd419d` | `tests/qa.d/31.sh` | `evidence/fix4` |
| 32 | `--audit` is silently inert when the host selects plain mode | `b6822b1` | `64d6514`, `2e1627b`, `fa0204a` | `tests/qa.d/32.sh` | `evidence/fix2` |
| 33 | `--comm` accepts LF and CR | `35080b0` | `b48373f`, `398eda3` | `tests/qa.d/33.sh` | `evidence/fix1` |
| 34 | A ptrace-denied host gives a cryptic `session error` for a mask run | `b6822b1` | `fa0204a` | `tests/qa.d/34.sh` | `evidence/fix2` |
| 35 | The test gate is not root-safe (`sudo sh tests/run.sh` fails) | `6fef4c3` | `6fef4c3` | `tests/qa.d/35.sh` | `evidence/fix5` |
| 36 | Assorted small CLI/docs nitpicks (F17, F22, F25, F27, F28) | `03a4be6`, `b6822b1` | `2e1627b`, `03a4be6`, `fa0204a` | `tests/qa.d/36.sh` | `evidence/fix2`, `evidence/fix5` |
| 38 | [b-team] The tracer thread is named `pmask-tracer`, and `TracerPid` points at a thread of the supervisor | `69cc3f8` | `5abd5e4`, `45e7683`, `fbc4666`, `f1a3a3d`, `f0bd7e0` | `tests/qa.d/38.sh` | `evidence/bteam2` |
| 39 | [b-team] The supervisor's own `/proc` entry: the label, a zero argv window, two threads, and the `PMASK_NO_SELFMASK` escape | `fcec4b0`, `ee9e7e2` | `6ebbedd`, `36e134a`, `ee9e7e2`, `26aeb7a`, `a5c7708`, `bc2888f`, `bd8b77a`, `0e5b064` | `tests/qa.d/39.sh` | `evidence/bteam1` |
| 40 | [b-team] The argv window arithmetic of a masked process: `cmdline` is the label, its byte count equals the `stat` span, and the environment span is zero | `v0.1.0` | `a5c7708`, `bd8b77a`, `0e5b064`, `v0.1.0` | `tests/qa.d/40.sh`, `tests/redteam.sh` R1/R2 | `evidence/bteam1`, `docs/REDTEAM-RESULTS.md` |
| 41 | [b-team] The `environ` file of a masked process: zero bytes, a NUL run, or the kept variables | `fcec4b0` | `a5c7708`, `bd8b77a`, `0e5b064` | `tests/qa.d/41.sh` | `evidence/bteam1` |
| 42 | [b-team] `comm`, `cmdline` and `exe` disagree: label limits, blank labels and the masquerade | none (design boundary) | `199580b`, `a5c7708`, `bd8b77a`, `0e5b064`, `v0.1.0` | `tests/qa.d/42.sh` | `evidence/bteam1`, `docs/THREAT-MODEL.md` |
| 43 | [b-team] `AT_EXECFN` serves a second label copy at `env_end`, while the payload's own `getauxval` keeps the real path | `v0.1.0` (exact mode) | `2cc6a62`, `babede3`, `149ee7c`, `a5c7708`, `bc2888f`, `bd8b77a`, `0e5b064`, `v0.1.0` | `tests/qa.d/43.sh`, `tests/redteam.sh` `R1-inprocess-auxv` | `evidence/bteam1`, `docs/REDTEAM-RESULTS.md` |
| 44 | [b-team] `--no-dumpable` answers `EACCES` on five files and zeroes four `stat` fields | none | `ee9e7e2`, `66937c9`, `74fbe52`, `720873b`, `9ca47ad`, `8d1c552` | `tests/qa.d/44.sh` | `evidence/bteam3` |
| 45 | [b-team] Named kernel objects: `/memfd:<label>`, `/memfd:pmask-secret` and `/secretmem` | `812b15d` | `12d334a`, `ad77b37`, `0022762`, `20716d0` | `tests/qa.d/45.sh` | `evidence/bteam5` |
| 46 | [b-team] `--watch-rename` leaves a second seccomp filter and `NoNewPrivs=1` | none | `5abd5e4`, `e77a5da`, `03720b3`, `c4b61fc`, `d155066`, `af95ff7` | `tests/qa.d/46.sh` | `evidence/bteam5` |
| 47 | [b-team] End states: `--detach`, `--no-follow`, `--on-exit` and `PTRACE_O_EXITKILL` | `424d0e8`, `1063b67` | `3eb7ab2`, `7f80d21`, `e51b7bd`, `ecd419d`, `fbc4666`, `f1a3a3d`, `f0bd7e0` | `tests/qa.d/47.sh` | `evidence/bteam2`, `evidence/fix4` |
| 48 | [b-team] The launch window and the statistical side channels of supervision | none | `fbc4666`, `f1a3a3d`, `f0bd7e0` | `tests/qa.d/48.sh` | `evidence/bteam2` |
| 49 | [b-team] Modes that do not redact: 32-bit images, plain, `--isolate` and `--unshare` | `v0.1.0` (32-bit refused by default, plain and `--isolate` documented limits) | `66937c9`, `9ca47ad`, `74b7b6a`, `v0.1.0` | `tests/qa.d/49.sh` | `evidence/bteam3`, `docs/DETECTION-AUDIT.md` |
| 50 | [b-team] The real argv stays in payload memory | none | `fbc4666`, `f1a3a3d`, `f0bd7e0` | `tests/qa.d/50.sh` | `evidence/bteam2` |
| 51 | [b-team] `pmaskd` is discoverable: the socket table, the 0600 node and the PING oracle | `fc23d43` | `ef061ad`, `fc23d43` | `tests/qa.d/51.sh` | `evidence/bteam4` |
| 52 | [b-team] `pmaskd`'s own entry, its workers and the job leaf | none | `997c22c` | `tests/qa.d/52.sh` | `evidence/bteam4` |
| 53 | [b-team] `pmaskd` refusals, exit codes and error strings | none | `997c22c` | `tests/qa.d/53.sh` | `evidence/bteam4` |
| 54 | [b-team] The on-disk footprint: `store.enc`, the agent socket, the unit files, the tmpfiles entry and the release binary | none | `997c22c`, `032f78c` | `tests/qa.d/54.sh` | `evidence/bteam4`, `evidence/fix5` |
| 55 | [b-team] Records outside the masked tree: report, audit, daemon log, `sudo` argv, shell history, systemd scope, `probe`/`doctor` | none | `997c22c` | `tests/qa.d/55.sh` | `evidence/bteam4` |
| 56 | [b-team] auditd: the records a pmask launch leaves, and the rule forms that do and do not see them | none | `bc75077`, `9ca47ad`, `8031b41`, `07d7cc8` | `tests/qa.d/56.sh` | `evidence/bteam3` |
| 57 | [b-team] eBPF sensors and the process connector: what each sees of a masked exec | none (kernel/OS boundary) | `ee9e7e2`, `307491a`, `7d12efc`, `ca32ce6`, `v0.1.0` | `tests/qa.d/57.sh` | `evidence/bteam5`, `docs/THREAT-MODEL.md` |
| 58 | [b-team] The detector family that does not see pmask, and what pmask genuinely hides | none (kernel/OS boundary + `--hide-pid` exception) | `da57ffa`, `5f996f6`, `v0.1.0` | `tests/qa.d/58.sh`, `tests/blueteam.sh` | `evidence/bteam5`, `docs/THREAT-MODEL.md` |
| 59 | The supervisor's own exec writes the payload argv and any `literal:` secret into the kernel audit log | `34b20e3` | `9ca47ad`, `07d7cc8`, `6a1ba77`, `34b20e3` | `tests/qa.d/59.sh` | `evidence/bteam3` |
| 60 | `--watch-rename` and `--no-dumpable` together cannot redirect a rename | `cd389fd`, `320c056` | `320c056`, `b48373f`, `398eda3` | `tests/qa.d/60.sh` | `evidence/fix1` |
| 61 | Detection documentation contradicts its own measurements: a four-hunk patch | `bb9d755` | `bb9d755` | the corrected text itself, `evidence/docs2/61-git-apply-check.log` | `evidence/docs2` |
| 64 | `--exec-once` carrier replacement, cache key, reaper cleanup, and `seal()` warning (001) | `v0.1.0` | `v0.1.0` | `src/rexec.rs::carrier_tests`, `tests/redteam.sh` (note: `tests/qa.d/64.sh` tests `--encrypt-memory`, not issue #64) | `docs/REDTEAM-RESULTS.md` |
| 65 | `--exec-once` fast path fails under non-dumpable modes (002) | `v0.1.0` | `v0.1.0` | `tests/qa.d/65.sh`, `tests/options.sh` O39 | `docs/REDTEAM-RESULTS.md` |
| 66 | Exposure window on `#!` scripts, `vfork`, fallbacks, re-exec bypasses, and `--detach` (003) | `v0.1.0` | `v0.1.0` | `tests/qa.d/66.sh` | `docs/REDTEAM-RESULTS.md` |
| 67 | Same-uid memory, secret fd, and supervisor image fd reads (004) | `v0.1.0` | `v0.1.0` | `tests/qa.d/67.sh`, `tests/options.sh` O27, `tests/daemon.sh` d7b/d8 | `docs/REDTEAM-RESULTS.md` |
| 68 | Secret holder dumpable during load window (005) | `v0.1.0` | `v0.1.0` | `tests/qa.d/68.sh` | `docs/REDTEAM-RESULTS.md` |
| 69 | `/proc/self/exe` and `/proc/thread-self/` under `--exec-once` (006) | `v0.1.0` | `v0.1.0` | `tests/qa.d/69.sh`, `tests/redteam.sh` R4 | `docs/REDTEAM-RESULTS.md` |
| 70 | Report staging, non-dumpable supervisor preservation, `--audit` + JSON refusal, and residue fd detection (007) | `v0.1.0` | `v0.1.0` | `tests/qa.d/70.sh`, `tests/redteam.sh` R6 | `docs/REDTEAM-RESULTS.md` |
| 71 | `write(2)` to `/proc/self/comm` bypasses `--watch-rename` (008) | `v0.1.0` | `v0.1.0` | `tests/qa.d/71.sh`, `tests/redteam.sh` R7 | `docs/REDTEAM-RESULTS.md` |
| 72 | `--watch-rename` leaves an orphaned seccomp filter after detach (009) | `v0.1.0` | `v0.1.0` | `tests/qa.d/72.sh` | `docs/REDTEAM-RESULTS.md` |
| 73 | `--hide-pid` kernel/OS boundary against cgroupfs and non-`/proc` syscalls (010) | `v0.1.0` (boundary documented + notice) | `v0.1.0` | `tests/qa.d/73.sh` | `docs/REDTEAM-RESULTS.md`, `docs/THREAT-MODEL.md` |
| 74 | `--no-exact` shortens argv extent and repeats decoy environment (011) | `v0.1.0` | `v0.1.0` | `tests/qa.d/74.sh`, `tests/redteam.sh` R2 | `docs/REDTEAM-RESULTS.md` |
| 75 | Exact mode `stat` gap, `start_stack`, `[stack]` VMA, and `--encrypt-memory` `MADV_DONTDUMP` placement (012) | `v0.1.0` | `v0.1.0` | `tests/qa.d/75.sh`, `tests/qa.d/64.sh`, `tests/redteam.sh` R1 | `docs/REDTEAM-RESULTS.md` |
| 76 | `--rexec` silent fallback to on-disk execution (013) | `v0.1.0` | `v0.1.0` | `tests/qa.d/76.sh`, `tests/options.sh` O32 | `docs/REDTEAM-RESULTS.md` |
| 77 | Plain mode supervisor leaves an all-NUL `cmdline` (014) | `v0.1.0` | `v0.1.0` | `tests/qa.d/77.sh`, `tests/redteam.sh` R3 | `docs/REDTEAM-RESULTS.md` |

## Details

### #4 `--unshare` / `--redact --isolate` silently disables redaction

- `b48373f` test: add fix1 evidence for issues 4 5 15 16 17 33 60
- `398eda3` test: add QA fragments for issues 4 5 15 16 17 33 60
- `74b7b6a` test: cover the mode table that does not redact
  The fragment tests six modes: default, `--no-redact`, `--isolate`, `--unshare`, `--redact --isolate`, and a 32-bit image. Each row checks the command line shape, the `environ` byte count, `TracerPid`, and namespace fingerprints (`hidepid=invisible` in `mountinfo` and a two-entry `NSpid` chain). For `--unshare`, the fragment asserts the fixed shape when the build serves the label. When the build serves the real argv, the fragment prints `SKIP` naming the `#4/qa-fix1` dependency. Both branches ran, with the release build taking the fixed branch and the musl build taking the skip branch. The fragment walks process trees by `PPid` rather than `pgrep -x sleep` to stay isolated from concurrent suites. Refs #49.
- Test: `tests/qa.d/4.sh`

### #5 `pmask read NAME` fails inside a masked payload

- `0b01a4f` fix: snapshot argv from the runtime's own copy
  A nested `pmask read NAME` failed because the supervisor re-read `/proc/self/cmdline`, which an outer exact mask had replaced with the label. `pmask` now snapshots its runtime argv vector directly and falls back to `/proc/self/cmdline` only when the runtime vector is empty.
  Files: `src/mask.rs`
- `b48373f` test: add fix1 evidence for issues 4 5 15 16 17 33 60
- `398eda3` test: add QA fragments for issues 4 5 15 16 17 33 60
- Test: `tests/qa.d/5.sh`

### #6 `pmask store --help` and `pmask get --help` do not print help

- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- `96a6c82` fix: handle help as the first store and get token
  Files: `src/subcmd.rs`
- Test: `tests/qa.d/6.sh`

### #7 `--env-file` parses two different grammars in pmask and pmaskd

- `8b505d6` fix: one --env-file grammar for pmask and pmaskd
  Files: `src/cli.rs`, `src/daemon.rs`
- Test: `tests/qa.d/7.sh`

### #8 Completions miss seven flags

- `07340b9` fix: complete the shell tables and guard them
  Files: `.github/workflows/ci.yml`, `completions/_pmask`, `completions/pmask.bash`, `completions/pmask.fish`, `scripts/check-completions.sh`, `tests/run.sh`

### #9 `--report=json` is not one JSON object when the payload writes to stdout

- `ad77b37` test: cover the report sink, the composition and the image names
- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- Test: `tests/qa.d/9.sh`

### #10 Plain and isolate modes silently drop mask options

- `2e1627b` docs: refresh the per-issue fragment logs
- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- Test: `tests/qa.d/10.sh`

### #11 An unknown `--secret` scheme is silently delivered as a literal

- `efbc85b` fix: warn when a --secret source names an unknown scheme
  Files: `src/cli.rs`, `src/secret.rs`
- Test: `tests/qa.d/11.sh`

### #12 `isolation.sh`, `compare.sh` and `conformance.sh` never run in CI

- `030197a` ci: run isolation, compare and conformance natively
  Files: `.github/workflows/ci.yml`, `tests/native-suites.sh`

### #13 `probe`/`doctor` report the exact cmdline window as active where redaction is unavailable

- `2e1627b` docs: refresh the per-issue fragment logs
- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- Test: `tests/qa.d/13.sh`

### #14 Assorted small CLI/UX nits (N1–N8)

- `d61e6b7` fix: warn instead of refusing the keep-env space form
  Files: `README.md`, `man/pmask.1`, `src/cli.rs`
- `2e1627b` docs: refresh the per-issue fragment logs
- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- Test: `tests/qa.d/14.sh`

### #15 The supervisor's `memfd_secret` buffer is not close-on-exec, so the plaintext leaks into the tree

> Later correction (`0.1.0-beta.5` final): `memfd_secret(2)` accepts `O_CLOEXEC`, not `MFD_CLOEXEC`. Passing `0x1` returns `EINVAL` on that ABI. The code and unit test now pass `O_CLOEXEC`. The commit subjects below record the initial fix verbatim.

- `b48373f` test: add fix1 evidence for issues 4 5 15 16 17 33 60
- `398eda3` test: add QA fragments for issues 4 5 15 16 17 33 60
- Test: `tests/qa.d/15.sh`

### #16 `--keep-env` followed by `--keep-env=NAME` exposes the whole environment

- `b48373f` test: add fix1 evidence for issues 4 5 15 16 17 33 60
- `398eda3` test: add QA fragments for issues 4 5 15 16 17 33 60
- Test: `tests/qa.d/16.sh`

### #17 `--audit` aborts the supervisor on a closed stdout and kills the payload

- `9e1de9d` fix: ignore a failed stdout write in audit rows
  Files: `src/tracer.rs`
- `b48373f` test: add fix1 evidence for issues 4 5 15 16 17 33 60
- `398eda3` test: add QA fragments for issues 4 5 15 16 17 33 60
- Test: `tests/qa.d/17.sh`

### #18 `--job-timeout` overflow panics the daemon

- `15c638f` fix: bound --job-timeout and guard the deadline addition
  Files: `src/bin/pmaskd.rs`, `src/daemon.rs`
- Test: `tests/qa.d/18.sh`

### #19 `--redact --isolate=net` discards the list and applies `--unshare`

- `ad77b37` test: cover the report sink, the composition and the image names
- `2e1627b` docs: refresh the per-issue fragment logs
- `2b1dc3a` fix: name a refused composed namespace set in the report
  Files: `src/run.rs`, `src/userns.rs`
- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- `96a6c82` fix: handle help as the first store and get token
  Files: `src/subcmd.rs`
- Test: `tests/qa.d/19.sh`

### #20 `--no-redact --isolate` runs plain and silently drops the isolation

- `2e1627b` docs: refresh the per-issue fragment logs
- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- Test: `tests/qa.d/20.sh`

### #21 `payload_dumpable` is false in plain mode while the payload is dumpable

- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- Test: `tests/qa.d/21.sh`

### #22 SIGTERM cannot stop a single-job daemon while a client is silent with `--io-timeout 0`

- `62e9811` fix: wake the daemon on SIGTERM while a client is silent
  Files: `src/daemon.rs`
- Test: `tests/qa.d/22.sh`

### #23 The tmpfiles entry creates an empty store file, so `store init` fails

- `a5b63b7` fix: stop tmpfiles pre-creating an empty store file
  Files: `contrib/tmpfiles.d/pmask.conf`
- Test: `tests/qa.d/23.sh`

### #24 Documented `pmaskd` ExecStart uses `--store`, which `pmaskd` does not accept

- `a487a5a` fix: drop the pmaskd --store example from the unit
  Files: `contrib/systemd/pmaskd@.service`
- Test: `tests/qa.d/24.sh`

### #25 `--isolate` gives the payload a `/dev` without `/dev/pts`, `/dev/ptmx` or `/dev/shm`

- `882c9eb` test: refresh the issue 25 evidence for the counted dev entry
- `33d5bf0` fix: count the fresh /dev members in the applied entry
  Files: `src/isolate.rs`
- `7f80d21` test: record the evidence for issues 25, 28, 31 and 47
- `ecd419d` test: add QA fragments for issues 25, 28, 31 and 47
- Test: `tests/qa.d/25.sh`

### #26 `--isolate=none` still creates user, mount, uts, ipc and cgroup namespaces

- `2e1627b` docs: refresh the per-issue fragment logs
- `8dc0db0` docs: index the fix2 evidence
- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- Test: `tests/qa.d/26.sh`

### #27 `-q` does not suppress the isolation report

- `2e1627b` docs: refresh the per-issue fragment logs
- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- Test: `tests/qa.d/27.sh`

### #28 `--hugetlb --image -` fails instead of falling back to an ordinary memfd

- `7f80d21` test: record the evidence for issues 25, 28, 31 and 47
- `ecd419d` test: add QA fragments for issues 25, 28, 31 and 47
- Test: `tests/qa.d/28.sh`

### #29 `doctor --json` breaks on a quoted store path; `doctor --require ''` passes

- `bdc6b37` fix: escape doctor JSON strings and refuse an empty --require
  Files: `src/subcmd.rs`
- Test: `tests/qa.d/29.sh`

### #30 `--env =VALUE` is accepted in plain mode and refused in redact mode

- `12e4740` test: assert --isolate=none creates no namespace
  Files: `src/cli.rs`, `tests/isolation.sh`
- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- Test: `tests/qa.d/30.sh`

### #31 `--args-from-fd 0` closes the payload's stdin

- `7f80d21` test: record the evidence for issues 25, 28, 31 and 47
- `ecd419d` test: add QA fragments for issues 25, 28, 31 and 47
- Test: `tests/qa.d/31.sh`

### #32 `--audit` is silently inert when the host selects plain mode

- `b6822b1` fix: compose redaction with the requested namespaces
  The body's `32:` line refuses `--audit` in every non-redaction mode, including a host that selects plain.
- `2e1627b` docs: refresh the per-issue fragment logs
- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- Test: `tests/qa.d/32.sh`

### #33 `--comm` accepts LF and CR

- `b48373f` test: add fix1 evidence for issues 4 5 15 16 17 33 60
- `398eda3` test: add QA fragments for issues 4 5 15 16 17 33 60
- Test: `tests/qa.d/33.sh`

### #34 A ptrace-denied host gives a cryptic `session error` for a mask run

- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- Test: `tests/qa.d/34.sh`

### #35 The test gate is not root-safe (`sudo sh tests/run.sh` fails)

- `6fef4c3` test: make the gate root-safe and stop the payload leak
  Files: `tests/conformance.sh`, `tests/isolation.sh`, `tests/lease.sh`, `tests/lib.sh`
- Test: `tests/qa.d/35.sh`

### #36 Assorted small CLI/docs nitpicks (F17, F22, F25, F27, F28)

- `2e1627b` docs: refresh the per-issue fragment logs
- `03a4be6` fix: offer only json as the --report value
  Files: `completions/_pmask`, `completions/pmask.bash`, `completions/pmask.fish`, `scripts/check-completions.sh`
- `fa0204a` test: add QA fragments for the fix2 issues
  Files: `man/pmask.1`, `src/cli.rs`, `src/main.rs`, `src/run.rs`, `tests/helpers/noptrace.c`
- Test: `tests/qa.d/36.sh`

### #38 [b-team] The tracer thread is named `pmask-tracer`, and `TracerPid` points at a thread of the supervisor

- `69cc3f8` fix: name the tracer thread after the session label
  The tracer thread uses the session `comm` instead of the fixed `pmask-tracer` string. Reading `/proc/<supervisor>/task/*/comm` no longer identifies every supervised tree on the host.
  Files: `src/mask.rs`
- `5abd5e4` test: tighten the 38 and 46 controls for the fixed tree
- `45e7683` docs: date the audit capture against #38
  Files: `docs/research/bteam-audit.md`
- `fbc4666` test: report the launch-window spread instead of one sample
  The launch window lasts a few hundred microseconds, so a single `/proc` scan under load can miss the interval. Masked rows now repeat and report the median, minimum, and maximum across attempts that catch a window. A row that misses every attempt prints `SKIP` with the reason instead of zero. The note corrects two earlier errors: the harness reports the median rather than the biased maximum, and the plain spawn-latency row is marked `UNSTABLE`.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- `f1a3a3d` test: make every QA fragment clean up its own processes
  Parked payloads such as `holdargs` carry real argv and `comm` values that can pollute concurrent sweeps. Every QA fragment now records spawned pids, traps `EXIT`, `INT`, `TERM`, `HUP`, and `QUIT`, and kills both recorded pids and labelled leftovers. Verification on `50.sh` confirmed that aborting a run leaves zero parked `testcases holdargs` processes.
- `f0bd7e0` test: cover the tracer name, end states, launch window and memory
  Commit `f0bd7e0` adds QA fragments, the measurement harness, the research note, and raw evidence for issues #38, #47, #48, and #50. Issue #38 verifies the tracer thread name on both the `--secret` runner and daemon paths against a pre-fix negative control. Issue #47 covers all four documented end states and the `--detach` warning. Issue #48 adds `measurements/launch-window.sh` with a C `/proc/<pid>/comm` sampler. The note records that a shell sampler (~2 ms per sample) misses the window and `strace -f` breaks seizure. Issue #50 confirms same-uid `/proc/<pid>/mem` recovery in default mode and refusal under `--no-dumpable`.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- Test: `tests/qa.d/38.sh`

### #39 [b-team] The supervisor's own `/proc` entry: the label, a zero argv window, two threads, and the `PMASK_NO_SELFMASK` escape

- `fcec4b0` feat: warn when a documented escape publishes a secret
  `pmask` warns on `PMASK_NO_SELFMASK` and refuses plain-mode runs that would write the supervisor argv into an active kernel audit log.
  Files: `src/caps.rs`, `src/cli.rs`, `src/main.rs`
- `6ebbedd` test: reap a plain-mode payload before its supervisor
- `36e134a` test: poll for the escape's argv instead of one sample
- `ee9e7e2` fix: one warning for one exposure, and the thread names the label
  Files: `src/main.rs`, `src/subcmd.rs`
- `26aeb7a` docs: record the refusal-before-warning ordering in the evidence
  Runs blocked by a refusal print only the refusal and suppress exposure warnings for commands that will not execute.
- `a5c7708` docs: refresh the evidence logs and add the verification transcript
  All five QA fragments ran against the final build with outputs saved alongside `verification.log` (fmt, clippy, lib tests, and rename check).
- `bc2888f` docs: measure the zero-argv startup window
  Twelve shell-loop runs sampled the supervisor `cmdline` at startup, and five caught an all-NUL window of the original length before the label landed. The window cannot close in userland because zeroing must precede parsing to avoid exposing secrets.
  Files: `docs/research/bteam-39-43.md`
- `bd8b77a` docs: record the b-team 39-43 residue measurements
  The research note and evidence directories document each detector rule, measured output, userland limit, and design trade for issues #39 through #43. Four log-backed corrections appear in the note. First, `PMASK_NO_SELFMASK` applies on the plain path and is overridden after fork in redact and isolate modes (#39). Second, pre-`v0.1.0` `--no-exact` kept one NUL per argument slot on ELF entry (#40). Third, `literal:` secrets never enter payload `environ`, so the `--keep-env` warning scopes to `env:` (#41). Fourth, `--no-exact` leaves `auxv` unchanged, and `AT_EXECFN == env_end` held only when `environ` was redacted (#43).
  Files: `docs/research/bteam-39-43.md`
- `0e5b064` test: cover the self-mask, windows, environ and auxv channels
  Five QA fragments cover issues #39 through #43 with negative controls, liveness checks, and explicit `BIN_DIR` setup. Fragment `39.sh` tests supervisor `comm`/`cmdline`/tracer task, non-dumpable zeros, root-relocated window, and `PMASK_NO_SELFMASK` handling.
- Test: `tests/qa.d/39.sh`

### #40 [b-team] The argv window arithmetic of a masked process: `cmdline` is the label, its byte count equals the `stat` span, and the environment span is zero

- `v0.1.0` fix: stack-region presentation block and `--no-exact` extent preservation
  Exact mode places the presentation block inside `[stack]` with `arg_end == env_start`, plausible decoy `environ`, and `start_stack < arg_start`. The real `[stack]` VMA remains intact. `--no-exact` preserves the original argv extent, fills `cmdline` with spaces plus one NUL, and writes complete non-repeating decoy `environ` entries (see #74 and #75).
- `a5c7708` docs: refresh the evidence logs and add the verification transcript
- `bd8b77a` docs: record the b-team 39-43 residue measurements
  Files: `docs/research/bteam-39-43.md`
- `0e5b064` test: cover the self-mask, windows, environ and auxv channels
  Fragment `40.sh` checks argv window arithmetic, label length cuts, `env_start == arg_end`, decoy `environ`, and `--no-exact` formatting.
- Test: `tests/qa.d/40.sh`, `tests/redteam.sh` R1/R2

### #41 [b-team] The `environ` file of a masked process: zero bytes, a NUL run, or the kept variables

- `fcec4b0` feat: warn when a documented escape publishes a secret
  The `--keep-env` warning fires only for an `env:` source that the run keeps. A `literal:` value never enters payload `environ`, so warning on `literal:` would be false.
  Files: `src/caps.rs`, `src/cli.rs`, `src/main.rs`
- `a5c7708` docs: refresh the evidence logs and add the verification transcript
- `bd8b77a` docs: record the b-team 39-43 residue measurements
  Files: `docs/research/bteam-39-43.md`
- `0e5b064` test: cover the self-mask, windows, environ and auxv channels
  Fragment `41.sh` verifies the decoy window, NUL handling, `--keep-env`, `--keep-env=NAME`, and the `env:` warning.
- Test: `tests/qa.d/41.sh`

### #42 [b-team] `comm`, `cmdline` and `exe` disagree: label limits, blank labels and the masquerade

- `v0.1.0` note: documented design boundary
  `comm` stays within the 15-byte kernel limit, `cmdline` carries the label, and `exe` stays the real binary unless `--rexec` runs. `docs/THREAT-MODEL.md` records this design boundary.
- `199580b` test: update the suites for the fixed behaviours
  Files: `completions/_pmask`, `completions/pmask.bash`, `completions/pmask.fish`, `tests/options.sh`
- `a5c7708` docs: refresh the evidence logs and add the verification transcript
- `bd8b77a` docs: record the b-team 39-43 residue measurements
  Files: `docs/research/bteam-39-43.md`
- `0e5b064` test: cover the self-mask, windows, environ and auxv channels
  Fragment `42.sh` verifies label length limits, the `comm`/`cmdline`/`exe` split, and `--comm` LF/CR rejection (issue #33).
- Test: `tests/qa.d/42.sh`

### #43 [b-team] `AT_EXECFN` serves a second label copy at `env_end`, while the payload's own `getauxval` keeps the real path

- `v0.1.0` fix: rewrite stack `AT_EXECFN` in exact mode
  In exact mode, `patch_stack_execfn` rewrites stack `AT_EXECFN` so in-process `getauxval(AT_EXECFN)` matches `/proc/<pid>/auxv`, and `pres_bytes` fixes the trailing NUL. Under `--no-exact`, both `getauxval(AT_EXECFN)` and `/proc/<pid>/auxv` stay the real path.
- `2cc6a62` docs: elide the worktree path from a research capture
  Files: `docs/research/bteam-39-43.md`
- `babede3` docs: date the pre-38 tracer captures
  Files: `docs/research/bteam-39-43.md`, `docs/research/bteam-ebpf.md`
- `149ee7c` docs: point every claim in the residue note at its source
  Each measured claim names the producing source function and replaces one rounded figure with the exact logged value.
  Files: `docs/research/bteam-39-43.md`
- `a5c7708` docs: refresh the evidence logs and add the verification transcript
- `bc2888f` docs: measure the zero-argv startup window
  Files: `docs/research/bteam-39-43.md`
- `bd8b77a` docs: record the b-team 39-43 residue measurements
  Files: `docs/research/bteam-39-43.md`
- `0e5b064` test: cover the self-mask, windows, environ and auxv channels
  Fragment `43.sh` checks `/proc/<pid>/auxv` `AT_EXECFN`, in-process `getauxval(AT_EXECFN)`, and `--no-exact` behaviour.
- Test: `tests/qa.d/43.sh`, `tests/redteam.sh` `R1-inprocess-auxv`

### #44 [b-team] `--no-dumpable` answers `EACCES` on five files and zeroes four `stat` fields

- `ee9e7e2` fix: one warning for one exposure, and the thread names the label
  Files: `src/main.rs`, `src/subcmd.rs`
- `66937c9` docs: correct which process is the isolate namespace init
  Under `--isolate`, the leaf payload has host-side `NSpid` `<hostpid> 1` and serves as the namespace init carrying the real argv. The commit adds the four-run transcript confirming this correction.
- `74fbe52` test: drop the exit-0 claim from the 44 liveness row
- `720873b` test: correct the liveness comment in the 44 fragment
- `9ca47ad` docs: add the bteam3 evidence bundles
  The bundles store the commands, host metadata, and raw outputs for bteam3. The bundles include the LXC audit refusals for issue #56 and the `--unshare`/`--no-dumpable` controls for issue #44.
- `8d1c552` test: measure the no-dumpable EACCES set with open
  Fragment `44.sh` tests `open(2)` via shell redirection rather than `test -r` (`access(2)`), because `maps` can answer readable to `access(2)` while refusing `open(2)`. The control payload without `--no-dumpable` stays readable on all tested files with non-zero `stat` fields 48-51. The fragment also asserts liveness, supervisor refusals, the tracer thread, and `PR_GET_DUMPABLE`. Refs #44.
- Test: `tests/qa.d/44.sh`

### #45 [b-team] Named kernel objects: `/memfd:<label>`, `/memfd:pmask-secret` and `/secretmem`

- `12d334a` test: scope the secret sweep to this run
- `ad77b37` test: cover the report sink, the composition and the image names
- `0022762` docs: record the issue 45 memfd-name evidence
- `20716d0` test: cover the memfd name options
- Test: `tests/qa.d/45.sh`

### #46 [b-team] `--watch-rename` leaves a second seccomp filter and `NoNewPrivs=1`

- `5abd5e4` test: tighten the 38 and 46 controls for the fixed tree
- `e77a5da` test: decide the 60 case from the observed shape
- `03720b3` docs: correct the run count in the 46 evidence
- `c4b61fc` docs: note the fragment race the 46 case hit
- `d155066` test: wait for the renamer report before reading its pid
- `af95ff7` test: cover the watch-rename filter row
- Test: `tests/qa.d/46.sh`

### #47 [b-team] End states: `--detach`, `--no-follow`, `--on-exit` and `PTRACE_O_EXITKILL`

- `424d0e8` fix: warn when --detach releases a tracee untraced
  Files: `src/tracer.rs`
- `1063b67` fix: warn when --detach releases a tracee untraced
  The same warning runs on the exec-image release path.
  Files: `src/execimg.rs`
- `3eb7ab2` test: scope the no-follow grandchild and reap QA leftovers
  Files: `tests/qa.sh`
- `7f80d21` test: record the evidence for issues 25, 28, 31 and 47
- `e51b7bd` merge: fix4
  Files: `src/isolate.rs`, `src/rexec.rs`, `src/tracer.rs`, `tests/isolation.sh`
- `ecd419d` test: add QA fragments for issues 25, 28, 31 and 47
- `fbc4666` test: report the launch-window spread instead of one sample
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- `f1a3a3d` test: make every QA fragment clean up its own processes
- `f0bd7e0` test: cover the tracer name, end states, launch window and memory
  Fragment `47.sh` verifies all four documented end states with non-vacuous controls and asserts the `--detach` release warning.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- Test: `tests/qa.d/47.sh`

### #48 [b-team] The launch window and the statistical side channels of supervision

- `fbc4666` test: report the launch-window spread instead of one sample
  The harness repeats masked rows and reports median, min, and max instead of a biased maximum, and marks the plain spawn-latency row `UNSTABLE`.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- `f1a3a3d` test: make every QA fragment clean up its own processes
- `f0bd7e0` test: cover the tracer name, end states, launch window and memory
  `measurements/launch-window.sh` measures spawn latency, runs a C `/proc/<pid>/comm` sampler for the launch window, and captures the syscall signature. The note records that a shell sampler (~2 ms per sample) misses the window and that `strace -f` kills a session by seizing before `pmask`.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- Test: `tests/qa.d/48.sh`

### #49 [b-team] Modes that do not redact: 32-bit images, plain, `--isolate` and `--unshare`

- `v0.1.0` update: 32-bit refusal by default and documented non-redacting modes
  `pmask` refuses 32-bit images by default with `SIGKILL`, with `--allow-foreign` as the explicit opt-in. `--unshare` redacts, while plain mode and `--isolate` remain documented limits.
- `66937c9` docs: correct which process is the isolate namespace init
  Under `--isolate`, the leaf payload has host-side `NSpid` `<hostpid> 1` and acts as the namespace init carrying the real argv.
- `9ca47ad` docs: add the bteam3 evidence bundles
- `74b7b6a` test: cover the mode table that does not redact
  Fragment `49.sh` tests default, `--no-redact`, `--isolate`, `--unshare`, `--redact --isolate`, and 32-bit image behaviour, walking process trees by `PPid`. Refs #49.
- Test: `tests/qa.d/49.sh`

### #50 [b-team] The real argv stays in payload memory

- `fbc4666` test: report the launch-window spread instead of one sample
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- `f1a3a3d` test: make every QA fragment clean up its own processes
- `f0bd7e0` test: cover the tracer name, end states, launch window and memory
  Fragment `50.sh` confirms that same-uid `/proc/<pid>/mem` reads recover real argv in default mode and fail under `--no-dumpable` while the payload runs normally.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- Test: `tests/qa.d/50.sh`

### #51 [b-team] `pmaskd` is discoverable: the socket table, the 0600 node and the PING oracle

- `ef061ad` test: run the refused-uid case as a PING
  Files: `src/bin/protocases.rs`
- `fc23d43` fix: reduce the PING body for a peer that is not the owner
  Files: `src/daemon.rs`
- Test: `tests/qa.d/51.sh`

### #52 [b-team] `pmaskd`'s own entry, its workers and the job leaf

- `997c22c` docs: record the daemon and out-of-tree records
  Files: `README.md`, `docs/DEPLOY.md`, `docs/DESIGN.md`, `docs/README.md`, `docs/research/README.md`, `docs/research/bteam-records.md`, `docs/research/detection-measured.md`, `docs/research/detection-residue.md`
- Test: `tests/qa.d/52.sh`

### #53 [b-team] `pmaskd` refusals, exit codes and error strings

- `997c22c` docs: record the daemon and out-of-tree records
  Files: `README.md`, `docs/DEPLOY.md`, `docs/DESIGN.md`, `docs/README.md`, `docs/research/README.md`, `docs/research/bteam-records.md`, `docs/research/detection-measured.md`, `docs/research/detection-residue.md`
- Test: `tests/qa.d/53.sh`

### #54 [b-team] The on-disk footprint: `store.enc`, the agent socket, the unit files, the tmpfiles entry and the release binary

- `997c22c` docs: record the daemon and out-of-tree records
  Files: `README.md`, `docs/DEPLOY.md`, `docs/DESIGN.md`, `docs/README.md`, `docs/research/README.md`, `docs/research/bteam-records.md`, `docs/research/detection-measured.md`, `docs/research/detection-residue.md`
- `032f78c` feat: report the on-disk footprint and ELF fingerprint
  Files: `scripts/check-artifacts.sh`
- Test: `tests/qa.d/54.sh`

### #55 [b-team] Records outside the masked tree: report, audit, daemon log, `sudo` argv, shell history, systemd scope, `probe`/`doctor`

- `997c22c` docs: record the daemon and out-of-tree records
  Files: `README.md`, `docs/DEPLOY.md`, `docs/DESIGN.md`, `docs/README.md`, `docs/research/README.md`, `docs/research/bteam-records.md`, `docs/research/detection-measured.md`, `docs/research/detection-residue.md`
- Test: `tests/qa.d/55.sh`

### #56 [b-team] auditd: the records a pmask launch leaves, and the rule forms that do and do not see them

- `bc75077` docs: drop the duplicate auditctl capture
- `9ca47ad` docs: add the bteam3 evidence bundles
- `8031b41` test: gate the audit checks on a host that can answer
  Fragment `56.sh` queries `auditctl -s`, `auditctl -l`, and `ausearch`, printing `SKIP` with the reason when audit is unavailable or LXC returns `ECONNREFUSED`. When active, `56.sh` checks nine audit record cases for control execs, supervisor argv, payload tail, and tracer `ptrace`/`OBJ_PID`. The fragment also checks watch versus exit rules and 32-bit arch rows. Refs #56.
- `07d7cc8` docs: record the audit records and the rule forms that see them
  `docs/research/bteam-audit.md` documents the five audit record shapes, rule coverage, and the LXC refusal, tagging guest records separately. A `-w PATH -p x` watch produces no exec record. An `arch=b32` filter misses a 32-bit payload exec because the record carries the calling ABI. Refs #56, #59.
  Files: `docs/research/bteam-audit.md`
- Test: `tests/qa.d/56.sh`

### #57 [b-team] eBPF sensors and the process connector: what each sees of a masked exec

- `v0.1.0` note: kernel and OS boundary
  eBPF sensors and the netlink process connector observe exec events at the kernel boundary. `docs/THREAT-MODEL.md` and `docs/research/bteam-ebpf.md` document this boundary.
- `ee9e7e2` fix: one warning for one exposure, and the thread names the label
  Files: `src/main.rs`, `src/subcmd.rs`
- `307491a` docs: isolate the second-tracer refusal in evidence
- `7d12efc` test: assert the tracer relation, not its old name
- `ca32ce6` docs: record the eBPF and connector refusals
  Files: `docs/research/bteam-ebpf.md`
- Test: `tests/qa.d/57.sh`

### #58 [b-team] The detector family that does not see pmask, and what pmask genuinely hides

- `v0.1.0` note: kernel and OS boundary plus `--hide-pid` exception
  Default redaction hides no pids, while `--hide-pid` hides `/proc/<pid>` under `hidepid=invisible|ptraceable` and leaves `chkproc`, `getpriority`, and `cgroup.procs` visible. `docs/THREAT-MODEL.md` documents these channels.
- `da57ffa` test: prove the hidden-pid sweep can fire
  Files: `docs/research/bteam-detectors.md`
- `5f996f6` docs: record the hidden-pid detector measurements
  Files: `docs/research/bteam-detectors.md`
- Test: `tests/qa.d/58.sh`, `tests/blueteam.sh`

### #59 The supervisor's own exec writes the payload argv and any `literal:` secret into the kernel audit log

- `9ca47ad` docs: add the bteam3 evidence bundles
- `07d7cc8` docs: record the audit records and the rule forms that see them
  Files: `docs/research/bteam-audit.md`
- `6a1ba77` test: cover the argv-secret audit warning
  Fragment `59.sh` tests fourteen cases covering the warning text, zero secret leakage in stderr or JSON reports, `-q` suppression, and fd 3 delivery. The fragment also checks `file:` and `env:` behaviour, audit wording variants, and `--args-from-fd`. Refs #59.
- `34b20e3` fix: warn that argv secrets reach the kernel audit log
  `pmask` prints one warning before launch when a `literal:` or `env:` source exposes secrets via kernel exec records, shell history, or wrapper argv. `run::audit_state()` queries `NETLINK_AUDIT` with `AUDIT_GET` to adjust the wording without blocking on unavailable audit probes. The warning recommends `--args-from-fd` and non-argv sources, and the JSON report includes the same fact. Refs #59.
  Files: `src/cli.rs`, `src/run.rs`
- Test: `tests/qa.d/59.sh`

### #60 `--watch-rename` and `--no-dumpable` together cannot redirect a rename

- `320c056` fix: refuse a rename the redirect cannot aim at the label
  Files: `src/tracer.rs`
- `b48373f` test: add fix1 evidence for issues 4 5 15 16 17 33 60
- `398eda3` test: add QA fragments for issues 4 5 15 16 17 33 60
- Test: `tests/qa.d/60.sh`

### #61 Detection documentation contradicts its own measurements: a four-hunk patch

- `bb9d755` docs: apply the four-hunk detection correction
  Files: `docs/research/detection-measured.md`, `docs/research/detection-residue.md`, `docs/research/detection-techniques.md`

### #64 `--exec-once` carrier replacement, cache key, reaper cleanup, and `seal()` warning (001)

- `v0.1.0` fix: carrier verification, `$XDG_RUNTIME_DIR` preference, reaper cleanup, and `Cache` key hardening
  `verify_carrier` re-opens the carrier with `O_NOFOLLOW` and checks `dev`, `ino`, `ctime`, and content bytes against the cached descriptor before reuse. `pmask` prefers `$XDG_RUNTIME_DIR` for carriers, keys `Cache` entries on `dev`, `ino`, and `ctime`, and warns visibly when `seal()` fails. The carrier reaper cleans up fds and stdio on `Image::drop`. Residual TOCTOU when `$XDG_RUNTIME_DIR` is unset is documented. Note that `tests/qa.d/64.sh` tests `--encrypt-memory`, not issue #64.
  Files: `src/rexec.rs`
- Test: `src/rexec.rs::carrier_tests`, `tests/redteam.sh`

### #65 `--exec-once` fast path fails under non-dumpable modes (002)

- `v0.1.0` fix: refuse incompatible non-dumpable `--exec-once` combinations and reorder filter installation
  Both the CLI (`src/main.rs`) and library (`src/mask.rs`) refuse `--exec-once` combined with `--no-dumpable`, `--hide-pid`, `--stealth` on non-`hidepid` hosts, and default non-dumpable `--secret` sessions. `install_exec_filter` runs before `PR_SET_DUMPABLE=0`.
  Files: `src/main.rs`, `src/mask.rs`, `src/tracer.rs`
- Test: `tests/qa.d/65.sh`, `tests/options.sh` O39

### #66 Exposure window on `#!` scripts, `vfork`, fallbacks, re-exec bypasses, and `--detach` (003)

- `v0.1.0` fix: add `--strict-exec` to refuse post-exec exposure shapes
  `--strict-exec` refuses `#!` scripts, `vfork` children, entry-redaction fallbacks (`write_mem`, scratch, overflow), settled re-exec bypasses, and `--detach`.
  Files: `src/cli.rs`, `src/execimg.rs`, `src/tracer.rs`
- Test: `tests/qa.d/66.sh`

### #67 Same-uid memory, secret fd, and supervisor image fd reads (004)

- `v0.1.0` fix: default `--secret` sessions to non-dumpable and close supervisor image fds
  `--secret` sessions default to `--no-dumpable` and a non-dumpable supervisor, with `--allow-dumpable` as the explicit opt-out. `close_parent_image_fds` closes supervisor fds 200 and 210 after fork, including under `--exec-once`. Non-secret default dumpability remains a documented trade.
  Files: `src/cli.rs`, `src/main.rs`, `src/mask.rs`, `src/run.rs`
- Test: `tests/qa.d/67.sh`, `tests/options.sh` O27, `tests/daemon.sh` d7b/d8

### #68 Secret holder dumpable during load window (005)

- `v0.1.0` fix: call `harden_self()` before loading secrets, passphrases, or `--env-file`
  `harden_self()` now runs before secret, passphrase, and `--env-file` reads in `src/run.rs`, `src/bin/pmaskd.rs`, `src/subcmd.rs`, and `src/agent.rs`. `pmask` prints a visible warning if `harden_self()` fails.
  Files: `src/run.rs`, `src/bin/pmaskd.rs`, `src/subcmd.rs`, `src/agent.rs`
- Test: `tests/qa.d/68.sh`

### #69 `/proc/self/exe` and `/proc/thread-self/` under `--exec-once` (006)

- `v0.1.0` fix: rewrite tracee self-links before resolving exec images
  `tracee_open_path`, `path_is_elf`, and `elf_is_32` rewrite `/proc/self/` and `/proc/thread-self/` to `/proc/{pid}/` so `--exec-once` resolves the tracee binary instead of `pmask`.
  Files: `src/execimg.rs`, `src/tracer.rs`
- Test: `tests/qa.d/69.sh`, `tests/redteam.sh` R4

### #70 Report staging, non-dumpable supervisor preservation, `--audit` + JSON refusal, and residue fd detection (007)

- `v0.1.0` fix: harden report writing and audit fd classification
  `ReportSink` stages reports in `O_TMPFILE` or a 0600 file with `Drop` cleanup, and `src/run.rs` preserves `supervisor_non_dumpable(true)`. `--audit` plus stdout `--report=json` is refused, and report runs default to `WaitTree`. `fd_is_residue` checks `/memfd:`, `(deleted)`, and `.pmask-rexec-`.
  Files: `src/main.rs`, `src/run.rs`, `src/tracer.rs`
- Test: `tests/qa.d/70.sh`, `tests/redteam.sh` R6

### #71 `write(2)` to `/proc/self/comm` bypasses `--watch-rename` (008)

- `v0.1.0` fix: trap comm-file opens and add `--watch-rename=strict`
  `--watch-rename` traps `prctl(PR_SET_NAME)` plus `open`, `openat`, `openat2`, and `creat` with lexical path normalization, and `--watch-rename=strict` traps write syscalls. The `aarch64` `NT_ARM_SYSTEM_CALL` denial path is fixed, and non-dumpable `EACCES` prints a visible warning.
  Files: `src/arch.rs`, `src/cli.rs`, `src/seccomp.rs`, `src/tracer.rs`
- Test: `tests/qa.d/71.sh`, `tests/redteam.sh` R7

### #72 `--watch-rename` leaves an orphaned seccomp filter after detach (009)

- `v0.1.0` fix: refuse `--on-exit detach` with `--watch-rename`
  `--watch-rename` refuses `--on-exit detach` in both the CLI and the `Mask` library API, and defaults to `WaitTree` in the CLI.
  Files: `src/cli.rs`, `src/main.rs`, `src/mask.rs`
- Test: `tests/qa.d/72.sh`

### #73 `--hide-pid` kernel/OS boundary against cgroupfs and non-`/proc` syscalls (010)

- `v0.1.0` note: documented kernel and OS boundary plus runtime notice
  Documentation and runtime notices state that `--hide-pid` does not hide pids from cgroupfs (`cgroup.procs`, `cgroup.threads`) or non-`/proc` syscalls (`getpriority`, `sched_getaffinity`, `prlimit`).
  Files: `README.md`, `docs/THREAT-MODEL.md`, `src/cli.rs`, `src/main.rs`
- Test: `tests/qa.d/73.sh`

### #74 `--no-exact` shortens argv extent and repeats decoy environment (011)

- `v0.1.0` fix: preserve original extents and write unique decoy entries under `--no-exact`
  `--no-exact` preserves the original `arg_lo..arg_hi` and `env_lo..env_hi` extents, pads `cmdline` with spaces plus one NUL, and writes complete non-repeating decoy `environ` entries.
  Files: `src/execimg.rs`
- Test: `tests/qa.d/74.sh`, `tests/redteam.sh` R2

### #75 Exact mode `stat` gap, `start_stack`, `[stack]` VMA, and `--encrypt-memory` `MADV_DONTDUMP` placement (012)

- `v0.1.0` fix: place presentation block in `[stack]` and keep `--encrypt-memory` `MADV_DONTDUMP` on the anonymous block
  Exact mode writes the presentation block inside `[stack]` with `arg_end == env_start`, a plausible decoy `environ`, `start_stack < arg_start`, and the `[stack]` VMA intact. `--encrypt-memory` marks the separate anonymous block `MADV_DONTDUMP`, not `[stack]`.
  Files: `src/execimg.rs`, `src/presetmm.rs`
- Test: `tests/qa.d/75.sh`, `tests/qa.d/64.sh`, `tests/redteam.sh` R1

### #76 `--rexec` silent fallback to on-disk execution (013)

- `v0.1.0` fix: fail closed on `--rexec` placement failure unless `--rexec-allow-disk` is set
  `--rexec` exits 126 (or 127 when the source is missing) with an actionable `RLIMIT_NOFILE` error unless `--rexec-allow-disk` is passed.
  Files: `src/cli.rs`, `src/main.rs`, `src/rexec.rs`
- Test: `tests/qa.d/76.sh`, `tests/options.sh` O32

### #77 Plain mode supervisor leaves an all-NUL `cmdline` (014)

- `v0.1.0` fix: restore caller argv in plain mode and zeroize `original_argv` in non-plain modes
  Plain mode restores caller argv via `restore_own_argv` when no plain-sight secret is present. Non-plain modes zeroize `original_argv` immediately.
  Files: `src/main.rs`, `src/selfmask.rs`
- Test: `tests/qa.d/77.sh`, `tests/redteam.sh` R3

## Corrections made after 0.1.0-beta.2

The `0.1.0-beta.2` documentation made claims that the code or tests contradicted.
`0.1.0-beta.3` corrected those claims.
None of the corrections changed a redaction mechanism, and two fixed behaviour that earlier text described inaccurately.

| claim in 0.1.0-beta.2 | what the artefact said | fixed in |
|---|---|---|
| `README.md` installed from `releases/latest/download/...` | Every beta tag was a prerelease, which `releases/latest` skipped and returned 404 (in `v0.1.0`, the release is a non-prerelease GitHub Latest release) | `README.md` pinned the tag for beta releases and targets `v0.1.0` |
| `--detach`, `--isolate`, and `--no-redact` have no tracer | `Mask::spawn_prepared` spawns the tracer thread for every mode. `--detach` detaches each tracee rather than omitting the thread | `README.md`, `docs/THREAT-MODEL.md` |
| `compare.sh` `mem_canary_readable` is "yes in every row" | `evidence/fix5/12/compare-conformance.log` records `SKIP` in `redacted-nodumpable` | `docs/THREAT-MODEL.md` (two rows) |
| `AT_EXECFN` is rewritten in `saved_auxv` | Rewrite ran only when window relocation ran. `--no-exact` and a refused map leave `auxv` unchanged, asserted by `tests/qa.d/43.sh` | `README.md`, `docs/THREAT-MODEL.md` |
| The `--no-exact` span is the label plus one NUL per argument | A script payload keeps the original extent on its post-exec path, as `README.md` stated | `docs/THREAT-MODEL.md` |
| `--secret-fd-name` is 1 to 200 printable bytes | `validate_memfd_name` refuses `/`, every C0 control byte, and DEL, and accepts bytes above `0x7e` | `README.md` |
| `map_files` resolves to `/memfd:<label> (deleted)`, asserted by `compare.sh` | `tests/compare.sh` asserts a `*/memfd:*` target only | `README.md` |
| The units use `ExecStart=/usr/bin/pmask` | `pmaskd@.service` uses `/usr/bin/pmaskd` | `README.md` |
| The micro-VM gate runs "the full suite" | `vm/common.sh` stages a subset of suites and names the suites it does not stage | `README.md`, `0.1.0-beta.2` notes |
| `--memfd-name` uses the same name on every carrier | Memfd carriers use the name as given. The temporary-file tag is sanitised and cut to 64 bytes | release notes, `src/rexec.rs` |
| `hardening=heap` when `mlock` is unavailable | The tier is `secret_mem` when `memfd_secret` alone carries the value | `docs/THREAT-MODEL.md` |
| `--report-file` creates a `0600` file | The mode applied only on creation, so an existing `0644` file kept its mode | `src/main.rs` narrows permissions, `tests/qa.d/9.sh` asserts it |
| `--exec-once` is disabled under a mount namespace | A namespace set cleared the cache silently, and `--redact --isolate` dropped the cache without notice | `src/mask.rs` reports the reason, `tests/qa.d/61.sh` covers it |

`evidence/bteam4/51/README.md` identifies which log is the pre-fix run so its `VERDICT: FAIL=2` line is not read as the current state.

## Commits whose message has no `#N` reference

None of the commits below match `#N` in their subject or body, though several still address numbered issues.
Commit `b6822b1` lists issues with a bare `19:` prefix, and commits `0b01a4f`, `9e1de9d`, and `69cc3f8` name issues #5, #17, and #38 only in diff comments.
The `fix commit` column in the main table records the exact mapping.

- `d28a822` test: decide the wait policy by the child, not the clock
- `45ad062` docs: drop the worktree name from the changelog
- `696c0ff` docs: regenerate the closure table at the final head
- `4a21569` docs: add the landing instructions and the verify script
- `64e3a92` docs: name the guard for the issues without a fragment
- `2ecca23` docs: regenerate the closure table for the final tree
- `2a91253` merge: Team Red QA pass over the 57 issue backlog
- `4e0bb8c` docs: name the report flag and the image family in refusals
- `3394b8b` test: wait for the validate control instead of one sample
- `dae8f8a` docs: correct the supervisor and isolate claims
- `7c051c5` test: skip the root batch with the same reason as lib
- `76878d9` test: match the control's own path and wait for it
- `85714ed` test: reap a root-run payload with sudo
- `6fe4c18` fix: harden the report sink, the namespace composition and names
- `dbb5201` docs: mark the audit capture as the pre-38 build
- `ce6f9e8` docs: correct the no-exact extent and the PING body
- `c9cb23d` test: read the secret probe answer from stdout only
- `f4e5c4a` docs: name the secret variable and the suite count
- `218c8c4` style: indent the comment continuation lines
- `0332162` docs: apply the source comment audit
- `fc252c6` merge: docs3 latest
- `4c9b1c3` docs: record the example formatting check
- `2077d35` man: distinguish refused images from dropped rexec
- `1c93abd` merge: docs1
- `491ccac` docs: add the CLI dumpable comment to the audit
- `0207666` docs: cover the dumpable comments in the audit
- `dcb22c3` man: qualify the daemon warning and audit record
- `79dc249` merge: docs3
- `56e0405` docs: audit source comments for stale facts
- `21d5346` merge: docs2
- `60d35a9` docs: say the examples need a ptrace host
- `ddff6dd` man: state pmaskd store ownership and refusals
- `6846be1` docs: fix the DET0164 counts and the last-byte direction
- `f40f3d8` man: document modes, image and isolation limits
- `7d2171b` docs: say when the mode line is printed
- `b7e1367` docs: index the docs2 evidence
- `882e2ad` test: make the VM gate skip repository-only checks
- `50485ea` docs: reconcile the detection numbers with a re-measurement
- `2b1a8a6` man: name the secret variable PMASK_SECRET_NAME
- `2a37687` man: refuse --image in the --daemon refusal list
- `644522b` docs: refresh the docs1 commit log
- `42443c4` docs: note the gate is run unprivileged in DEPLOY
- `8a23e4b` docs: tighten the secret and mode wording
- `155fd4a` docs: add the docs1 evidence index
- `38ce703` docs: same-uid reader also reads payload memory
- `939fdf7` docs: the tracer pid is a thread, not the supervisor
- `d847eff` docs: name the argv source in SECURITY
- `f3bf29f` docs: index the b-team research notes
- `e940dd3` docs: the daemon has no store of its own
- `e8805c2` docs: add the b-team residuals to the threat model
- `91f644d` docs: note the gate skips same-uid cases as root
- `22c948c` merge: fix4 latest
- `c08e32c` docs: add the audit and wrapper exposure to SECURITY
- `50e9514` docs: list the signals a defender still sees
- `82f2598` docs: state the keep-env and no-dumpable exposure
- `4e2f75d` docs: document the isolate /dev and hugetlb fallback
- `54f81f4` docs: describe the interrupt handshake and the self-mask
- `8f3b453` docs: add the hardening rows to the threat model
- `3cc2003` docs: --report json shares stdout with the payload
- `2d09e7c` docs: the store belongs to pmask agent, not pmaskd
- `68000d7` docs: say what each mode redacts and does not
- `2563d76` test: record the final full-gate run
- `33da474` docs: nested pmask read works under a mask
- `c8d4839` test: reap the I19 matrix control so the next suite is clean
- `f8ccfbc` docs: state the audit-log exposure of literal secrets
- `5b96f6e` fix: close the held ptmx fds on the failed-dev path
- `8509579` merge: fix2 residual
- `6ec1125` test: record the clean full-gate run
- `6042bc8` merge: fix2 latest
- `a0903cb` docs: refresh the fix2 gate logs
- `4592794` merge: fix5 final
- `c56ccf7` merge: fix4 final
- `67e3a3d` merge: fix2 final
- `8220c7c` merge: fix2 and fix4 refresh
- `9af04d1` docs: state the keep-env space-form rule in help and man
- `875fc5d` test: align the mode and timing suites with the fixes
- `0c5014f` fix: do not claim a member is absent on a cut-short report
- `a53853b` fix: give the rexec test the default memfd name
- `e746f78` merge: fix5
- `0718250` merge: fix2
- `b6822b1` fix: compose redaction with the requested namespaces
- `37e0f78` refactor: keep the hugetlb fallback in one helper
- `ea40e22` merge: fix3 final
- `0ddc6b2` test: drop the new dev members from the host-leak examples
- `f04c75a` fix: spool a pipe source so the hugetlb retry is complete
- `6901e8a` docs: refresh the gate logs after the last build
- `2007eeb` docs: record the isolation suite in the gate log
- `0a495a1` docs: state the secret-scheme and doctor exit-code contracts in help
- `badb87c` docs: record the gate and targeted suite verdicts
- `1850dee` test: give the wake waits their own pipe in tests
- `4b32de7` test: expect pts, ptmx and shm in the fresh /dev
- `630bfec` test: cover the fresh /dev member report
- `d5fe647` test: cover the pipe-source hugetlb fallback
- `dcf2cc2` merge: bteam4
- `bcf8fca` test: update the /dev set and reap the isolation control
- `424d0e8` fix: warn when --detach releases a tracee untraced
- `014b66c` fix: collapse the /dev/shm mkdir and mount check
- `8bcfcb0` fix: fall back to an ordinary memfd in prepare_fd
- `1a4309a` fix: treat the /dev extras as optional, not fatal
- `95e2841` merge: fix4
- `f29449b` merge: fix3
- `240feec` fix: bind /dev/pts and /dev/ptmx, add a private /dev/shm
- `f314d9b` fix: dup the --args-from-fd descriptor before reading it
- `5c2b660` test: factor the env-file agreement table into a helper
- `593ad24` merge: fix1 handshake refresh
- `15b10f8` merge: fix1 final
- `f740675` fix: keep the handshake signals and clear a stale rename address
- `1d15594` test: refresh fix1 evidence after the final gate
- `cd75e5d` merge: bteam5 final
- `b33b426` fix: reap the master when the handshake wait fails
- `5671d0b` docs: refresh the final qa run
- `31f98ea` docs: say the memfd name warns when it names nothing
- `ce93a04` docs: index the bteam5 evidence
- `4cda318` test: add the evilrename probe for issue 60
- `e93a003` test: assert memfd_secret is created close-on-exec
- `7d1b5e4` test: log which stop the handshake took
- `9f4d723` fix: validate --comm before the mode is chosen
- `e84af93` docs: name the strace limit in the eBPF note
- `4265298` merge: bteam5 refresh
- `68fab27` merge: bteam2 refresh
- `e852567` fix: report a memfd name that names nothing
- `cb56f9e` merge: fix1
- `d0cadd7` fix: interrupt the seized master for the handshake
- `cd389fd` fix: redirect rename to the mapped label, no write
- `9e1de9d` fix: ignore a failed stdout write in audit rows
- `8797876` fix: create memfd_secret with MFD_CLOEXEC
- `0b01a4f` fix: snapshot argv from the runtime's own copy
- `35080b0` fix: reject LF and CR in --comm like the label
- `9b3fe5f` fix: keep-env list overrides an earlier --keep-env
- `e8a8454` merge: bteam5
- `f55ecc3` merge: bteam2
- `1063b67` fix: warn when --detach releases a tracee untraced
- `69cc3f8` fix: name the tracer thread after the session label
- `b1ce019` merge: bteam3
- `ef260ca` merge: bteam1
- `812b15d` feat: name the memfds behind --secret and --rexec
- `8fd8074` docs: refresh the final fragment run
- `d4e2e0e` docs: correct the library test count and its baseline
- `6e05fa6` docs: record the verification transcript and the fragment run
- `c9ed635` fix: warn about the escapes only for a run that happens
- `fcec4b0` feat: warn when a documented escape publishes a secret


## beta.5 review (PR #63) and `v0.1.0` closure: issues 001-014 (#64-#77) and b-team records

The `v0.1.0` release carries the PR #63 red-team fixes and final hardening updates below.
The `test` column names the fragment or suite case that fails if a fix regresses.

| issue | fix (`v0.1.0`) | test |
|---|---|---|
| 001 (#64) `--exec-once` carrier replaceable and cache metadata-only | `verify_carrier` re-opens the carrier with `O_NOFOLLOW` and compares `dev`, `ino`, `ctime`, and content bytes with the cached descriptor before reuse. A mismatch kills the exec. `pmask` prefers `$XDG_RUNTIME_DIR`, keys `Cache` on `dev`/`ino`/`ctime`, warns visibly on `seal()` failure, and runs a double-forked reaper with fd and stdio cleanup on `Image::drop`. Residual TOCTOU when `$XDG_RUNTIME_DIR` is unset is documented. | `src/rexec.rs::carrier_tests`, `tests/redteam.sh` (note: `tests/qa.d/64.sh` tests `--encrypt-memory`, not issue #64) |
| 002 (#65) `--no-dumpable` drops the fast path | Both the CLI (`src/main.rs`) and library (`src/mask.rs`) refuse `--exec-once` with `--no-dumpable`, `--hide-pid`, `--stealth` on non-`hidepid` hosts, and default non-dumpable `--secret` sessions before fork. `install_exec_filter` runs before `PR_SET_DUMPABLE=0`. | `tests/qa.d/65.sh`, `tests/options.sh` O39 |
| 003 (#66) argv window on script, `vfork`, `--no-dumpable`, and `--detach` | `--strict-exec` refuses `#!` scripts, `vfork` children, entry-redaction fallbacks (`write_mem`, scratch, overflow), settled re-exec bypasses, and `--detach`. Docs state the default trade and residual window. | `tests/qa.d/66.sh` |
| 004 (#67) same-uid memory, secret, and image reads | `--secret` sessions default to `--no-dumpable` and a non-dumpable supervisor (`--allow-dumpable` opts out). `close_parent_image_fds` closes supervisor fds 200 and 210 after fork, including under `--exec-once`. Daemon jobs stay non-dumpable. Non-secret default dumpability remains a documented trade. | `tests/qa.d/67.sh`, `tests/options.sh` O27, `tests/daemon.sh` d7b/d8 |
| 005 (#68) secret load window | `harden_self()` (`PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0`) runs before secret, passphrase, or `--env-file` load in `src/run.rs`, `src/bin/pmaskd.rs`, `src/subcmd.rs`, and `src/agent.rs`, with a visible warning on failure. | `tests/qa.d/68.sh` |
| 006 (#69) `/proc/self/exe` later exec runs `pmask` | `tracee_open_path`, `path_is_elf`, and `elf_is_32` rewrite `/proc/self/` and `/proc/thread-self/` to `/proc/{pid}/` before resolving the cache key. | `tests/qa.d/69.sh`, `tests/redteam.sh` R4 |
| 007 (#70) report and audit writable, audit fd name-keyed | `ReportSink` stages reports in `O_TMPFILE` or a 0600 file with `Drop` cleanup and links after the tree exits. `src/run.rs` preserves `supervisor_non_dumpable(true)`, reports default to `WaitTree`, `--audit` plus stdout `--report=json` is refused, and `fd_is_residue` checks `/memfd:`, `(deleted)`, and `.pmask-rexec-`. | `tests/qa.d/70.sh`, `tests/redteam.sh` R6 |
| 008 (#71) `write(2)` to `/proc/self/comm` | `--watch-rename` traps `prctl(PR_SET_NAME)` plus `open`, `openat`, `openat2`, and `creat` with lexical path normalization. `--watch-rename=strict` traps write syscalls. `aarch64` `NT_ARM_SYSTEM_CALL` denial is fixed, and non-dumpable `EACCES` prints a visible warning. | `tests/qa.d/71.sh`, `tests/redteam.sh` R7 |
| 009 (#72) orphan filter after detach | `--watch-rename` refuses `--on-exit detach` in both the CLI and `Mask` library API and defaults to `WaitTree` in the CLI. | `tests/qa.d/72.sh` |
| 010 (#73) `--hide-pid` cgroup and syscall channels | `README.md`, help text, runtime notices, and `docs/THREAT-MODEL.md` document the kernel boundary for cgroupfs (`cgroup.procs`, `cgroup.threads`) and non-`/proc` syscalls (`getpriority`, `sched_getaffinity`, `prlimit`). | `tests/qa.d/73.sh` |
| 011 (#74) `--no-exact` extent and repeated decoy | `--no-exact` skips entry transformation, preserves original `arg_lo..arg_hi` and `env_lo..env_hi`, pads `cmdline` with spaces plus one NUL, and writes complete non-repeating decoy `environ` entries. | `tests/qa.d/74.sh`, `tests/redteam.sh` R2 |
| 012 (#75) exact `stat` gap, `start_stack`, `[stack]`, and `dd` | Exact mode writes the presentation block inside `[stack]` with `arg_end == env_start`, plausible decoy `environ`, `start_stack < arg_start`, and the `[stack]` VMA intact. `--encrypt-memory` marks the separate anonymous block `MADV_DONTDUMP`, not `[stack]`. | `tests/qa.d/75.sh`, `tests/qa.d/64.sh`, `tests/redteam.sh` R1 |
| 013 (#76) `--rexec` silent disk fallback | `--rexec` fails closed with exit 126 (or 127 when the source is missing) and an actionable `RLIMIT_NOFILE` error unless `--rexec-allow-disk` is passed. | `tests/qa.d/76.sh`, `tests/options.sh` O32 |
| 014 (#77) plain supervisor NUL `cmdline` | Plain mode restores caller argv via `restore_own_argv` when no plain-sight secret is present. Non-plain modes zeroize `original_argv` immediately. | `tests/qa.d/77.sh`, `tests/redteam.sh` R3 |
| #40 / #42 / #43 b-team measurements | Exact mode keeps `arg_end == env_start`, plausible decoy `environ`, `start_stack < arg_start`, `[stack]` intact, and matching `AT_EXECFN` via `patch_stack_execfn` plus trailing NUL fix in `pres_bytes`. Under `--no-exact`, `AT_EXECFN` stays the real path. The `comm`/`cmdline`/`exe` split remains a documented design boundary. | `tests/redteam.sh` R1 (`R1-inprocess-auxv`), `tests/core.sh` k13/k13b, `tests/qa.d/40.sh`, `tests/qa.d/42.sh`, `tests/qa.d/43.sh` |
| #49 / #57 / #58 b-team modes and kernel observers | 32-bit images are refused by default with `SIGKILL` (`--allow-foreign` opts in), `--unshare` redacts, and plain/`--isolate` remain documented limits. eBPF/process connector and hidden-pid kernel boundaries (plus the `--hide-pid` exception) are documented in `docs/THREAT-MODEL.md`. | `tests/qa.d/49.sh`, `tests/qa.d/57.sh`, `tests/qa.d/58.sh`, `tests/blueteam.sh` |
