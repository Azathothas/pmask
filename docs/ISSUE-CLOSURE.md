# Issue closure

One section per issue. The `fix commit` column names the commit whose change fixes the issue, as its diff shows; `none` means the issue is a measurement, design or record item with no code fix, and the test and note below are the closure. The `commits` column is provenance, not a fix list: it holds the commits that name the issue and the commits that carry its test, evidence or documentation. The test column names the fragment that would fail if the behaviour changed; the evidence column names the directory holding the raw logs.

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
| 40 | [b-team] The argv window arithmetic of a masked process: `cmdline` is the label, its byte count equals the `stat` span, and the environment span is zero | none | `a5c7708`, `bd8b77a`, `0e5b064` | `tests/qa.d/40.sh` | `evidence/bteam1` |
| 41 | [b-team] The `environ` file of a masked process: zero bytes, a NUL run, or the kept variables | `fcec4b0` | `a5c7708`, `bd8b77a`, `0e5b064` | `tests/qa.d/41.sh` | `evidence/bteam1` |
| 42 | [b-team] `comm`, `cmdline` and `exe` disagree: label limits, blank labels and the masquerade | none | `199580b`, `a5c7708`, `bd8b77a`, `0e5b064` | `tests/qa.d/42.sh` | `evidence/bteam1` |
| 43 | [b-team] `AT_EXECFN` serves a second label copy at `env_end`, while the payload's own `getauxval` keeps the real path | none | `2cc6a62`, `babede3`, `149ee7c`, `a5c7708`, `bc2888f`, `bd8b77a`, `0e5b064` | `tests/qa.d/43.sh` | `evidence/bteam1` |
| 44 | [b-team] `--no-dumpable` answers `EACCES` on five files and zeroes four `stat` fields | none | `ee9e7e2`, `66937c9`, `74fbe52`, `720873b`, `9ca47ad`, `8d1c552` | `tests/qa.d/44.sh` | `evidence/bteam3` |
| 45 | [b-team] Named kernel objects: `/memfd:<label>`, `/memfd:pmask-secret` and `/secretmem` | `812b15d` | `12d334a`, `ad77b37`, `0022762`, `20716d0` | `tests/qa.d/45.sh` | `evidence/bteam5` |
| 46 | [b-team] `--watch-rename` leaves a second seccomp filter and `NoNewPrivs=1` | none | `5abd5e4`, `e77a5da`, `03720b3`, `c4b61fc`, `d155066`, `af95ff7` | `tests/qa.d/46.sh` | `evidence/bteam5` |
| 47 | [b-team] End states: `--detach`, `--no-follow`, `--on-exit` and `PTRACE_O_EXITKILL` | `424d0e8`, `1063b67` | `3eb7ab2`, `7f80d21`, `e51b7bd`, `ecd419d`, `fbc4666`, `f1a3a3d`, `f0bd7e0` | `tests/qa.d/47.sh` | `evidence/bteam2`, `evidence/fix4` |
| 48 | [b-team] The launch window and the statistical side channels of supervision | none | `fbc4666`, `f1a3a3d`, `f0bd7e0` | `tests/qa.d/48.sh` | `evidence/bteam2` |
| 49 | [b-team] Modes that do not redact: 32-bit images, plain, `--isolate` and `--unshare` | none | `66937c9`, `9ca47ad`, `74b7b6a` | `tests/qa.d/49.sh` | `evidence/bteam3` |
| 50 | [b-team] The real argv stays in payload memory | none | `fbc4666`, `f1a3a3d`, `f0bd7e0` | `tests/qa.d/50.sh` | `evidence/bteam2` |
| 51 | [b-team] `pmaskd` is discoverable: the socket table, the 0600 node and the PING oracle | `fc23d43` | `ef061ad`, `fc23d43` | `tests/qa.d/51.sh` | `evidence/bteam4` |
| 52 | [b-team] `pmaskd`'s own entry, its workers and the job leaf | none | `997c22c` | `tests/qa.d/52.sh` | `evidence/bteam4` |
| 53 | [b-team] `pmaskd` refusals, exit codes and error strings | none | `997c22c` | `tests/qa.d/53.sh` | `evidence/bteam4` |
| 54 | [b-team] The on-disk footprint: `store.enc`, the agent socket, the unit files, the tmpfiles entry and the release binary | none | `997c22c`, `032f78c` | `tests/qa.d/54.sh` | `evidence/bteam4`, `evidence/fix5` |
| 55 | [b-team] Records outside the masked tree: report, audit, daemon log, `sudo` argv, shell history, systemd scope, `probe`/`doctor` | none | `997c22c` | `tests/qa.d/55.sh` | `evidence/bteam4` |
| 56 | [b-team] auditd: the records a pmask launch leaves, and the rule forms that do and do not see them | none | `bc75077`, `9ca47ad`, `8031b41`, `07d7cc8` | `tests/qa.d/56.sh` | `evidence/bteam3` |
| 57 | [b-team] eBPF sensors and the process connector: what each sees of a masked exec | none | `ee9e7e2`, `307491a`, `7d12efc`, `ca32ce6` | `tests/qa.d/57.sh` | `evidence/bteam5` |
| 58 | [b-team] The detector family that does not see pmask, and what pmask genuinely hides | none | `da57ffa`, `5f996f6` | `tests/qa.d/58.sh` | `evidence/bteam5` |
| 59 | The supervisor's own exec writes the payload argv and any `literal:` secret into the kernel audit log | `34b20e3` | `9ca47ad`, `07d7cc8`, `6a1ba77`, `34b20e3` | `tests/qa.d/59.sh` | `evidence/bteam3` |
| 60 | `--watch-rename` and `--no-dumpable` together cannot redirect a rename | `cd389fd`, `320c056` | `320c056`, `b48373f`, `398eda3` | `tests/qa.d/60.sh` | `evidence/fix1` |
| 61 | Detection documentation contradicts its own measurements: a four-hunk patch | `bb9d755` | `bb9d755` | the corrected text itself; `evidence/docs2/61-git-apply-check.log` | `evidence/docs2` |

## Details

### #4 `--unshare` / `--redact --isolate` silently disables redaction

- `b48373f` test: add fix1 evidence for issues 4 5 15 16 17 33 60
- `398eda3` test: add QA fragments for issues 4 5 15 16 17 33 60
- `74b7b6a` test: cover the mode table that does not redact
  One row per mode: default, --no-redact, --isolate, --unshare, --redact --isolate and a 32-bit image. Each asserts the real or the label shape, the environ byte count, TracerPid, and the namespace fingerprints (`hidepid=invisible` in mountinfo, an NSpid chain of two). The --unshare row is decided by measurement: if the build serves the label the fragment asserts the fixed shape, and if it serves the real argv it prints SKIP naming the #4/qa-fix1 dependency instead of passing. Both branches were exercised, the release build against the first and the musl build against the second. Trees are walked by PPid, never `pgrep -x sleep`, because other suites run on this host. Refs #49
- Test: `tests/qa.d/4.sh`

### #5 `pmask read NAME` fails inside a masked payload

- `0b01a4f` fix: snapshot argv from the runtime's own copy
  A nested `pmask read NAME` failed because the supervisor re-read `/proc/self/cmdline`, which an outer exact mask had already moved onto the label. The snapshot now comes from the runtime's own argv, with `/proc/self/cmdline` only as the fallback for an empty runtime vector.
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

### #15 The supervisor's `memfd_secret` buffer is not `MFD_CLOEXEC`, so the plaintext leaks into the tree

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
  The fixed `pmask-tracer` comm is replaced by the session's own comm, so one read of `/proc/<supervisor>/task/*/comm` no longer names every supervised tree on the host.
  Files: `src/mask.rs`
- `5abd5e4` test: tighten the 38 and 46 controls for the fixed tree
- `45e7683` docs: date the audit capture against #38
  Files: `docs/research/bteam-audit.md`
- `fbc4666` test: report the launch-window spread instead of one sample
  The window is a few hundred microseconds, and the sampler finds the payload by scanning /proc, so a scan under load can take longer than the interval it is measuring. A single sample therefore sometimes reports "no window", which is a property of the instrument rather than of the mask. The masked rows are now repeated, the median of the attempts that caught a window is quoted with its min and max, and a row that missed every attempt prints SKIP with the reason instead of a zero. The per-attempt lines stay in the output so the spread is visible. Two measurement errors are corrected in the note with the numbers that replace them: * the median is quoted, not the largest. Taking the largest across retries is a biased estimator: repeating until the number looks big is how a measurement stops meaning anything. * the spawn-latency plain row is marked UNSTABLE in the recorded run, and the note says so rather than quoting the quieter run as if it were the only one. The masked median is the same across runs; the ratio moves with the denominator.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- `f1a3a3d` test: make every QA fragment clean up its own processes
  A parked payload is not inert: `holdargs` and the labelled sleepers carry a real argv and a real comm, and the gate's world-wide sweeps attribute a stranger's process to whatever case is scanning at that moment. A fragment that exits through an assertion, a timeout or a signal therefore has to remove what it started, not only the happy path. Every fragment now records each pid it starts and kills the list in its trap, kills by its own labels (which is exhaustive for the payloads it cannot name ahead of time), and traps HUP and QUIT as well as EXIT, INT and TERM. Proved both ways on 50.sh: with the cleanup removed, an abort after the control starts leaves `testcases holdargs` parked; with the cleanup in place it does not.
- `f0bd7e0` test: cover the tracer name, end states, launch window and memory
  One QA fragment per b-team issue, plus the measurement harness, the research note that carries the numbers, and the evidence each claim points at. 38 the tracer thread is named after the session comm. The negative control runs the same observer against a pre-fix binary and finds the retired name, so the zero after the fix means the name is gone. The runner path (--secret) and the daemon path are both covered: the first because it calls spawn before the self-mask, the second because it is the only other caller of Mask::spawn. 47 the four documented end states, each with the control that stops it being vacuous, and the new --detach release warning. 48 measurements/launch-window.sh: spawn latency with per-round spread, a C /proc/<pid>/comm sampler for the launch window, and the syscall signature from a per-thread attach. Two findings beyond the issue: a shell sampler cannot see the window (one sample costs about 2 ms here), and strace -f kills a session because strace seizes the payload before pmask can. 50 /proc/<pid>/mem as the same uid recovers the real argv in default mode; --no-dumpable refuses it while the payload keeps working. The research note states every number with its kernel, uid and command, and names --args-from-fd as the launcher-argv mitigation for the launch window.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- Test: `tests/qa.d/38.sh`

### #39 [b-team] The supervisor's own `/proc` entry: the label, a zero argv window, two threads, and the `PMASK_NO_SELFMASK` escape

- `fcec4b0` feat: warn when a documented escape publishes a secret
  The `PMASK_NO_SELFMASK` warning, and the refusal of a plain-mode run that would put the supervisor's argv into the kernel audit log when the audit subsystem answers.
  Files: `src/caps.rs`, `src/cli.rs`, `src/main.rs`
- `6ebbedd` test: reap a plain-mode payload before its supervisor
- `36e134a` test: poll for the escape's argv instead of one sample
- `ee9e7e2` fix: one warning for one exposure, and the thread names the label
  Files: `src/main.rs`, `src/subcmd.rs`
- `26aeb7a` docs: record the refusal-before-warning ordering in the evidence
  Two runs where a refusal makes the command impossible now print only the refusal, with no exposure warning for a run that will not happen.
- `a5c7708` docs: refresh the evidence logs and add the verification transcript
  The five QA fragments were re-run against the final build and their output is stored beside the measurements. verification.log carries the exact fmt, clippy, lib-test and rename-check invocations with their exit codes.
- `bc2888f` docs: measure the zero-argv startup window
  The issue title names it and no log measured it. Twelve runs sampled the supervisor's own cmdline as fast as a POSIX shell loop can: five of them caught an all-NUL window of the original length before the label landed. It is not closable, because the label cannot be written before the block is zeroed without leaving the secret readable during the parse.
  Files: `docs/research/bteam-39-43.md`
- `bd8b77a` docs: record the b-team 39-43 residue measurements
  New research note plus one evidence directory per issue. The note carries each detector rule, the measured output, why the channel cannot be closed in userland, and the trade of every alternative. It also records four corrections to the issue reports, each backed by a log: - PMASK_NO_SELFMASK is honoured on the plain path and overridden after the fork in redact and isolate mode (issue 39) - --no-exact does not keep the original extent on the ELF entry path; it keeps one NUL per argument slot (issue 40) - a literal: secret never reaches the payload's environ, so the keep-env warning must be scoped to env: (issue 41) - --no-exact does not rewrite the auxv at all, and AT_EXECFN == env_end only holds when the environment is redacted (issue 43)
  Files: `docs/research/bteam-39-43.md`
- `0e5b064` test: cover the self-mask, windows, environ and auxv channels
  Five QA fragments, one per b-team issue: 39 the supervisor's own entry: comm/cmdline/tracer task, the non-dumpable zeros for a same-uid reader, the relocated window as root, and the PMASK_NO_SELFMASK warning and audit refusal 40 the argv window arithmetic: label+NUL, arg span == cmdline bytes, env_start == env_end, the label cuts, and the --no-exact count rule 41 the environ shapes: 0 bytes, a NUL run, --keep-env and --keep-env=NAME, plus the env: warning and that the kept variables stay kept 42 the label limits and the comm/cmdline/exe split, with the --comm LF and CR behaviour recorded against fix1's issue 33 43 AT_EXECFN: the served label, AT_EXECFN == env_end, the in-payload getauxval dissent, and the two modes where each fails Each has a negative control and a liveness check. The fragments set BIN_DIR themselves because lib.sh derives it from the cwd, which is tests/qa.d for a fragment.
- Test: `tests/qa.d/39.sh`

### #40 [b-team] The argv window arithmetic of a masked process: `cmdline` is the label, its byte count equals the `stat` span, and the environment span is zero

- `a5c7708` docs: refresh the evidence logs and add the verification transcript
  The five QA fragments were re-run against the final build and their output is stored beside the measurements. verification.log carries the exact fmt, clippy, lib-test and rename-check invocations with their exit codes.
- `bd8b77a` docs: record the b-team 39-43 residue measurements
  New research note plus one evidence directory per issue. The note carries each detector rule, the measured output, why the channel cannot be closed in userland, and the trade of every alternative. It also records four corrections to the issue reports, each backed by a log: - PMASK_NO_SELFMASK is honoured on the plain path and overridden after the fork in redact and isolate mode (issue 39) - --no-exact does not keep the original extent on the ELF entry path; it keeps one NUL per argument slot (issue 40) - a literal: secret never reaches the payload's environ, so the keep-env warning must be scoped to env: (issue 41) - --no-exact does not rewrite the auxv at all, and AT_EXECFN == env_end only holds when the environment is redacted (issue 43)
  Files: `docs/research/bteam-39-43.md`
- `0e5b064` test: cover the self-mask, windows, environ and auxv channels
  Five QA fragments, one per b-team issue: 39 the supervisor's own entry: comm/cmdline/tracer task, the non-dumpable zeros for a same-uid reader, the relocated window as root, and the PMASK_NO_SELFMASK warning and audit refusal 40 the argv window arithmetic: label+NUL, arg span == cmdline bytes, env_start == env_end, the label cuts, and the --no-exact count rule 41 the environ shapes: 0 bytes, a NUL run, --keep-env and --keep-env=NAME, plus the env: warning and that the kept variables stay kept 42 the label limits and the comm/cmdline/exe split, with the --comm LF and CR behaviour recorded against fix1's issue 33 43 AT_EXECFN: the served label, AT_EXECFN == env_end, the in-payload getauxval dissent, and the two modes where each fails Each has a negative control and a liveness check. The fragments set BIN_DIR themselves because lib.sh derives it from the cwd, which is tests/qa.d for a fragment.
- Test: `tests/qa.d/40.sh`

### #41 [b-team] The `environ` file of a masked process: zero bytes, a NUL run, or the kept variables

- `fcec4b0` feat: warn when a documented escape publishes a secret
  The `--keep-env` warning fires only for an `env:` source the run keeps; a `literal:` value never reaches the payload's environ, so warning on it would be false.
  Files: `src/caps.rs`, `src/cli.rs`, `src/main.rs`
- `a5c7708` docs: refresh the evidence logs and add the verification transcript
  The five QA fragments were re-run against the final build and their output is stored beside the measurements. verification.log carries the exact fmt, clippy, lib-test and rename-check invocations with their exit codes.
- `bd8b77a` docs: record the b-team 39-43 residue measurements
  New research note plus one evidence directory per issue. The note carries each detector rule, the measured output, why the channel cannot be closed in userland, and the trade of every alternative. It also records four corrections to the issue reports, each backed by a log: - PMASK_NO_SELFMASK is honoured on the plain path and overridden after the fork in redact and isolate mode (issue 39) - --no-exact does not keep the original extent on the ELF entry path; it keeps one NUL per argument slot (issue 40) - a literal: secret never reaches the payload's environ, so the keep-env warning must be scoped to env: (issue 41) - --no-exact does not rewrite the auxv at all, and AT_EXECFN == env_end only holds when the environment is redacted (issue 43)
  Files: `docs/research/bteam-39-43.md`
- `0e5b064` test: cover the self-mask, windows, environ and auxv channels
  Five QA fragments, one per b-team issue: 39 the supervisor's own entry: comm/cmdline/tracer task, the non-dumpable zeros for a same-uid reader, the relocated window as root, and the PMASK_NO_SELFMASK warning and audit refusal 40 the argv window arithmetic: label+NUL, arg span == cmdline bytes, env_start == env_end, the label cuts, and the --no-exact count rule 41 the environ shapes: 0 bytes, a NUL run, --keep-env and --keep-env=NAME, plus the env: warning and that the kept variables stay kept 42 the label limits and the comm/cmdline/exe split, with the --comm LF and CR behaviour recorded against fix1's issue 33 43 AT_EXECFN: the served label, AT_EXECFN == env_end, the in-payload getauxval dissent, and the two modes where each fails Each has a negative control and a liveness check. The fragments set BIN_DIR themselves because lib.sh derives it from the cwd, which is tests/qa.d for a fragment.
- Test: `tests/qa.d/41.sh`

### #42 [b-team] `comm`, `cmdline` and `exe` disagree: label limits, blank labels and the masquerade

- `199580b` test: update the suites for the fixed behaviours
  Files: `completions/_pmask`, `completions/pmask.bash`, `completions/pmask.fish`, `tests/options.sh`
- `a5c7708` docs: refresh the evidence logs and add the verification transcript
  The five QA fragments were re-run against the final build and their output is stored beside the measurements. verification.log carries the exact fmt, clippy, lib-test and rename-check invocations with their exit codes.
- `bd8b77a` docs: record the b-team 39-43 residue measurements
  New research note plus one evidence directory per issue. The note carries each detector rule, the measured output, why the channel cannot be closed in userland, and the trade of every alternative. It also records four corrections to the issue reports, each backed by a log: - PMASK_NO_SELFMASK is honoured on the plain path and overridden after the fork in redact and isolate mode (issue 39) - --no-exact does not keep the original extent on the ELF entry path; it keeps one NUL per argument slot (issue 40) - a literal: secret never reaches the payload's environ, so the keep-env warning must be scoped to env: (issue 41) - --no-exact does not rewrite the auxv at all, and AT_EXECFN == env_end only holds when the environment is redacted (issue 43)
  Files: `docs/research/bteam-39-43.md`
- `0e5b064` test: cover the self-mask, windows, environ and auxv channels
  Five QA fragments, one per b-team issue: 39 the supervisor's own entry: comm/cmdline/tracer task, the non-dumpable zeros for a same-uid reader, the relocated window as root, and the PMASK_NO_SELFMASK warning and audit refusal 40 the argv window arithmetic: label+NUL, arg span == cmdline bytes, env_start == env_end, the label cuts, and the --no-exact count rule 41 the environ shapes: 0 bytes, a NUL run, --keep-env and --keep-env=NAME, plus the env: warning and that the kept variables stay kept 42 the label limits and the comm/cmdline/exe split, with the --comm LF and CR behaviour recorded against fix1's issue 33 43 AT_EXECFN: the served label, AT_EXECFN == env_end, the in-payload getauxval dissent, and the two modes where each fails Each has a negative control and a liveness check. The fragments set BIN_DIR themselves because lib.sh derives it from the cwd, which is tests/qa.d for a fragment.
- Test: `tests/qa.d/42.sh`

### #43 [b-team] `AT_EXECFN` serves a second label copy at `env_end`, while the payload's own `getauxval` keeps the real path

- `2cc6a62` docs: elide the worktree path from a research capture
  Files: `docs/research/bteam-39-43.md`
- `babede3` docs: date the pre-38 tracer captures
  Files: `docs/research/bteam-39-43.md`, `docs/research/bteam-ebpf.md`
- `149ee7c` docs: point every claim in the residue note at its source
  Each measured statement now names the function that produces it, so a reader can check the note against the tree instead of trusting it. Also replaces one rounded figure with the number the log carries.
  Files: `docs/research/bteam-39-43.md`
- `a5c7708` docs: refresh the evidence logs and add the verification transcript
  The five QA fragments were re-run against the final build and their output is stored beside the measurements. verification.log carries the exact fmt, clippy, lib-test and rename-check invocations with their exit codes.
- `bc2888f` docs: measure the zero-argv startup window
  The issue title names it and no log measured it. Twelve runs sampled the supervisor's own cmdline as fast as a POSIX shell loop can: five of them caught an all-NUL window of the original length before the label landed. It is not closable, because the label cannot be written before the block is zeroed without leaving the secret readable during the parse.
  Files: `docs/research/bteam-39-43.md`
- `bd8b77a` docs: record the b-team 39-43 residue measurements
  New research note plus one evidence directory per issue. The note carries each detector rule, the measured output, why the channel cannot be closed in userland, and the trade of every alternative. It also records four corrections to the issue reports, each backed by a log: - PMASK_NO_SELFMASK is honoured on the plain path and overridden after the fork in redact and isolate mode (issue 39) - --no-exact does not keep the original extent on the ELF entry path; it keeps one NUL per argument slot (issue 40) - a literal: secret never reaches the payload's environ, so the keep-env warning must be scoped to env: (issue 41) - --no-exact does not rewrite the auxv at all, and AT_EXECFN == env_end only holds when the environment is redacted (issue 43)
  Files: `docs/research/bteam-39-43.md`
- `0e5b064` test: cover the self-mask, windows, environ and auxv channels
  Five QA fragments, one per b-team issue: 39 the supervisor's own entry: comm/cmdline/tracer task, the non-dumpable zeros for a same-uid reader, the relocated window as root, and the PMASK_NO_SELFMASK warning and audit refusal 40 the argv window arithmetic: label+NUL, arg span == cmdline bytes, env_start == env_end, the label cuts, and the --no-exact count rule 41 the environ shapes: 0 bytes, a NUL run, --keep-env and --keep-env=NAME, plus the env: warning and that the kept variables stay kept 42 the label limits and the comm/cmdline/exe split, with the --comm LF and CR behaviour recorded against fix1's issue 33 43 AT_EXECFN: the served label, AT_EXECFN == env_end, the in-payload getauxval dissent, and the two modes where each fails Each has a negative control and a liveness check. The fragments set BIN_DIR themselves because lib.sh derives it from the cwd, which is tests/qa.d for a fragment.
- Test: `tests/qa.d/43.sh`

### #44 [b-team] `--no-dumpable` answers `EACCES` on five files and zeroes four `stat` fields

- `ee9e7e2` fix: one warning for one exposure, and the thread names the label
  Files: `src/main.rs`, `src/subcmd.rs`
- `66937c9` docs: correct which process is the isolate namespace init
  The earlier note read the nsenter shell's own Pid as if it were the payload's and concluded the leaf was not the namespace init. It is: the host-side NSpid of the leaf is "<hostpid> 1", and an in-namespace /proc/1/comm names the leaf's program. Under --isolate that means the namespace init is the process carrying the real argv, which is exactly why a one-level check reads clean. Adds the four-run transcript.
- `74fbe52` test: drop the exit-0 claim from the 44 liveness row
- `720873b` test: correct the liveness comment in the 44 fragment
- `9ca47ad` docs: add the bteam3 evidence bundles
  One directory per issue: what was run, on what host, and the raw output. Issue 56's bundle carries the exact refusals that blocked the audit measurement, the fixture the fragment was exercised against, and the two gate branches. Issue 44's carries the new --unshare/--no-dumpable defect with its four controls.
- `8d1c552` test: measure the no-dumpable EACCES set with open
  The five files are measured with a redirection, which is open(2), not with `test -r`, which is access(2) and answers differently for a non-dumpable process: on this host `maps` says readable to access() and refused to open(). The fragment records which of the five disagree rather than assuming. The control is the same payload without the flag, readable on all five and with non-zero stat fields 48-51. Liveness, the supervisor's own refused set, the pmask-tracer thread, and the note a mode that cannot apply the flag prints are asserted too. `payload_dumpable` is left to issue 21; only the note and the measured PR_GET_DUMPABLE are asserted. Refs #44
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
  The same warning on the exec-image release path.
  Files: `src/execimg.rs`
- `3eb7ab2` test: scope the no-follow grandchild and reap QA leftovers
  Files: `tests/qa.sh`
- `7f80d21` test: record the evidence for issues 25, 28, 31 and 47
- `e51b7bd` merge: fix4
  Files: `src/isolate.rs`, `src/rexec.rs`, `src/tracer.rs`, `tests/isolation.sh`
- `ecd419d` test: add QA fragments for issues 25, 28, 31 and 47
- `fbc4666` test: report the launch-window spread instead of one sample
  The window is a few hundred microseconds, and the sampler finds the payload by scanning /proc, so a scan under load can take longer than the interval it is measuring. A single sample therefore sometimes reports "no window", which is a property of the instrument rather than of the mask. The masked rows are now repeated, the median of the attempts that caught a window is quoted with its min and max, and a row that missed every attempt prints SKIP with the reason instead of a zero. The per-attempt lines stay in the output so the spread is visible. Two measurement errors are corrected in the note with the numbers that replace them: * the median is quoted, not the largest. Taking the largest across retries is a biased estimator: repeating until the number looks big is how a measurement stops meaning anything. * the spawn-latency plain row is marked UNSTABLE in the recorded run, and the note says so rather than quoting the quieter run as if it were the only one. The masked median is the same across runs; the ratio moves with the denominator.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- `f1a3a3d` test: make every QA fragment clean up its own processes
  A parked payload is not inert: `holdargs` and the labelled sleepers carry a real argv and a real comm, and the gate's world-wide sweeps attribute a stranger's process to whatever case is scanning at that moment. A fragment that exits through an assertion, a timeout or a signal therefore has to remove what it started, not only the happy path. Every fragment now records each pid it starts and kills the list in its trap, kills by its own labels (which is exhaustive for the payloads it cannot name ahead of time), and traps HUP and QUIT as well as EXIT, INT and TERM. Proved both ways on 50.sh: with the cleanup removed, an abort after the control starts leaves `testcases holdargs` parked; with the cleanup in place it does not.
- `f0bd7e0` test: cover the tracer name, end states, launch window and memory
  One QA fragment per b-team issue, plus the measurement harness, the research note that carries the numbers, and the evidence each claim points at. 38 the tracer thread is named after the session comm. The negative control runs the same observer against a pre-fix binary and finds the retired name, so the zero after the fix means the name is gone. The runner path (--secret) and the daemon path are both covered: the first because it calls spawn before the self-mask, the second because it is the only other caller of Mask::spawn. 47 the four documented end states, each with the control that stops it being vacuous, and the new --detach release warning. 48 measurements/launch-window.sh: spawn latency with per-round spread, a C /proc/<pid>/comm sampler for the launch window, and the syscall signature from a per-thread attach. Two findings beyond the issue: a shell sampler cannot see the window (one sample costs about 2 ms here), and strace -f kills a session because strace seizes the payload before pmask can. 50 /proc/<pid>/mem as the same uid recovers the real argv in default mode; --no-dumpable refuses it while the payload keeps working. The research note states every number with its kernel, uid and command, and names --args-from-fd as the launcher-argv mitigation for the launch window.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- Test: `tests/qa.d/47.sh`

### #48 [b-team] The launch window and the statistical side channels of supervision

- `fbc4666` test: report the launch-window spread instead of one sample
  The window is a few hundred microseconds, and the sampler finds the payload by scanning /proc, so a scan under load can take longer than the interval it is measuring. A single sample therefore sometimes reports "no window", which is a property of the instrument rather than of the mask. The masked rows are now repeated, the median of the attempts that caught a window is quoted with its min and max, and a row that missed every attempt prints SKIP with the reason instead of a zero. The per-attempt lines stay in the output so the spread is visible. Two measurement errors are corrected in the note with the numbers that replace them: * the median is quoted, not the largest. Taking the largest across retries is a biased estimator: repeating until the number looks big is how a measurement stops meaning anything. * the spawn-latency plain row is marked UNSTABLE in the recorded run, and the note says so rather than quoting the quieter run as if it were the only one. The masked median is the same across runs; the ratio moves with the denominator.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- `f1a3a3d` test: make every QA fragment clean up its own processes
  A parked payload is not inert: `holdargs` and the labelled sleepers carry a real argv and a real comm, and the gate's world-wide sweeps attribute a stranger's process to whatever case is scanning at that moment. A fragment that exits through an assertion, a timeout or a signal therefore has to remove what it started, not only the happy path. Every fragment now records each pid it starts and kills the list in its trap, kills by its own labels (which is exhaustive for the payloads it cannot name ahead of time), and traps HUP and QUIT as well as EXIT, INT and TERM. Proved both ways on 50.sh: with the cleanup removed, an abort after the control starts leaves `testcases holdargs` parked; with the cleanup in place it does not.
- `f0bd7e0` test: cover the tracer name, end states, launch window and memory
  One QA fragment per b-team issue, plus the measurement harness, the research note that carries the numbers, and the evidence each claim points at. 38 the tracer thread is named after the session comm. The negative control runs the same observer against a pre-fix binary and finds the retired name, so the zero after the fix means the name is gone. The runner path (--secret) and the daemon path are both covered: the first because it calls spawn before the self-mask, the second because it is the only other caller of Mask::spawn. 47 the four documented end states, each with the control that stops it being vacuous, and the new --detach release warning. 48 measurements/launch-window.sh: spawn latency with per-round spread, a C /proc/<pid>/comm sampler for the launch window, and the syscall signature from a per-thread attach. Two findings beyond the issue: a shell sampler cannot see the window (one sample costs about 2 ms here), and strace -f kills a session because strace seizes the payload before pmask can. 50 /proc/<pid>/mem as the same uid recovers the real argv in default mode; --no-dumpable refuses it while the payload keeps working. The research note states every number with its kernel, uid and command, and names --args-from-fd as the launcher-argv mitigation for the launch window.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- Test: `tests/qa.d/48.sh`

### #49 [b-team] Modes that do not redact: 32-bit images, plain, `--isolate` and `--unshare`

- `66937c9` docs: correct which process is the isolate namespace init
  The earlier note read the nsenter shell's own Pid as if it were the payload's and concluded the leaf was not the namespace init. It is: the host-side NSpid of the leaf is "<hostpid> 1", and an in-namespace /proc/1/comm names the leaf's program. Under --isolate that means the namespace init is the process carrying the real argv, which is exactly why a one-level check reads clean. Adds the four-run transcript.
- `9ca47ad` docs: add the bteam3 evidence bundles
  One directory per issue: what was run, on what host, and the raw output. Issue 56's bundle carries the exact refusals that blocked the audit measurement, the fixture the fragment was exercised against, and the two gate branches. Issue 44's carries the new --unshare/--no-dumpable defect with its four controls.
- `74b7b6a` test: cover the mode table that does not redact
  One row per mode: default, --no-redact, --isolate, --unshare, --redact --isolate and a 32-bit image. Each asserts the real or the label shape, the environ byte count, TracerPid, and the namespace fingerprints (`hidepid=invisible` in mountinfo, an NSpid chain of two). The --unshare row is decided by measurement: if the build serves the label the fragment asserts the fixed shape, and if it serves the real argv it prints SKIP naming the #4/qa-fix1 dependency instead of passing. Both branches were exercised, the release build against the first and the musl build against the second. Trees are walked by PPid, never `pgrep -x sleep`, because other suites run on this host. Refs #49
- Test: `tests/qa.d/49.sh`

### #50 [b-team] The real argv stays in payload memory

- `fbc4666` test: report the launch-window spread instead of one sample
  The window is a few hundred microseconds, and the sampler finds the payload by scanning /proc, so a scan under load can take longer than the interval it is measuring. A single sample therefore sometimes reports "no window", which is a property of the instrument rather than of the mask. The masked rows are now repeated, the median of the attempts that caught a window is quoted with its min and max, and a row that missed every attempt prints SKIP with the reason instead of a zero. The per-attempt lines stay in the output so the spread is visible. Two measurement errors are corrected in the note with the numbers that replace them: * the median is quoted, not the largest. Taking the largest across retries is a biased estimator: repeating until the number looks big is how a measurement stops meaning anything. * the spawn-latency plain row is marked UNSTABLE in the recorded run, and the note says so rather than quoting the quieter run as if it were the only one. The masked median is the same across runs; the ratio moves with the denominator.
  Files: `docs/research/bteam-38-50.md`, `measurements/launch-window.sh`
- `f1a3a3d` test: make every QA fragment clean up its own processes
  A parked payload is not inert: `holdargs` and the labelled sleepers carry a real argv and a real comm, and the gate's world-wide sweeps attribute a stranger's process to whatever case is scanning at that moment. A fragment that exits through an assertion, a timeout or a signal therefore has to remove what it started, not only the happy path. Every fragment now records each pid it starts and kills the list in its trap, kills by its own labels (which is exhaustive for the payloads it cannot name ahead of time), and traps HUP and QUIT as well as EXIT, INT and TERM. Proved both ways on 50.sh: with the cleanup removed, an abort after the control starts leaves `testcases holdargs` parked; with the cleanup in place it does not.
- `f0bd7e0` test: cover the tracer name, end states, launch window and memory
  One QA fragment per b-team issue, plus the measurement harness, the research note that carries the numbers, and the evidence each claim points at. 38 the tracer thread is named after the session comm. The negative control runs the same observer against a pre-fix binary and finds the retired name, so the zero after the fix means the name is gone. The runner path (--secret) and the daemon path are both covered: the first because it calls spawn before the self-mask, the second because it is the only other caller of Mask::spawn. 47 the four documented end states, each with the control that stops it being vacuous, and the new --detach release warning. 48 measurements/launch-window.sh: spawn latency with per-round spread, a C /proc/<pid>/comm sampler for the launch window, and the syscall signature from a per-thread attach. Two findings beyond the issue: a shell sampler cannot see the window (one sample costs about 2 ms here), and strace -f kills a session because strace seizes the payload before pmask can. 50 /proc/<pid>/mem as the same uid recovers the real argv in default mode; --no-dumpable refuses it while the payload keeps working. The research note states every number with its kernel, uid and command, and names --args-from-fd as the launcher-argv mitigation for the launch window.
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
  One directory per issue: what was run, on what host, and the raw output. Issue 56's bundle carries the exact refusals that blocked the audit measurement, the fixture the fragment was exercised against, and the two gate branches. Issue 44's carries the new --unshare/--no-dumpable defect with its four controls.
- `8031b41` test: gate the audit checks on a host that can answer
  The fragment asks `auditctl -s` and `auditctl -l` and requires ausearch, then prints SKIP with the reason when any of them is missing or the subsystem is off. On this container `-s` prints nothing because LXC answers ECONNREFUSED, and `-l` is what explains it, so both are read. Nine record cases: the control exec record, the supervisor's argv including the literal secret, the payload's empty-string tail, the tracer ptrace and OBJ_PID records, the watch-versus-exit-rule counts run one after the other, and the 32-bit arch row. Refs #56
- `07d7cc8` docs: record the audit records and the rule forms that see them
  The five record shapes a pmask launch leaves, the rule forms that do and do not see them, and the exact LXC refusal that stopped every audit measurement on this host. Guest records are tagged and not presented as measurements of the container. Two findings worth acting on: a `-w PATH -p x` watch produces no exec record (its single hit is the auditctl that installed it), and a rule filtered on arch=b32 cannot see a 32-bit payload's exec because the record carries the exec'ing syscall's ABI. Refs #56, #59
  Files: `docs/research/bteam-audit.md`
- Test: `tests/qa.d/56.sh`

### #57 [b-team] eBPF sensors and the process connector: what each sees of a masked exec

- `ee9e7e2` fix: one warning for one exposure, and the thread names the label
  Files: `src/main.rs`, `src/subcmd.rs`
- `307491a` docs: isolate the second-tracer refusal in evidence
- `7d12efc` test: assert the tracer relation, not its old name
- `ca32ce6` docs: record the eBPF and connector refusals
  Files: `docs/research/bteam-ebpf.md`
- Test: `tests/qa.d/57.sh`

### #58 [b-team] The detector family that does not see pmask, and what pmask genuinely hides

- `da57ffa` test: prove the hidden-pid sweep can fire
  Files: `docs/research/bteam-detectors.md`
- `5f996f6` docs: record the hidden-pid detector measurements
  Files: `docs/research/bteam-detectors.md`
- Test: `tests/qa.d/58.sh`

### #59 The supervisor's own exec writes the payload argv and any `literal:` secret into the kernel audit log

- `9ca47ad` docs: add the bteam3 evidence bundles
  One directory per issue: what was run, on what host, and the raw output. Issue 56's bundle carries the exact refusals that blocked the audit measurement, the fixture the fragment was exercised against, and the two gate branches. Issue 44's carries the new --unshare/--no-dumpable defect with its four controls.
- `07d7cc8` docs: record the audit records and the rule forms that see them
  The five record shapes a pmask launch leaves, the rule forms that do and do not see them, and the exact LXC refusal that stopped every audit measurement on this host. Guest records are tagged and not presented as measurements of the container. Two findings worth acting on: a `-w PATH -p x` watch produces no exec record (its single hit is the auditctl that installed it), and a rule filtered on arch=b32 cannot see a 32-bit payload's exec because the record carries the exec'ing syscall's ABI. Refs #56, #59
  Files: `docs/research/bteam-audit.md`
- `6a1ba77` test: cover the argv-secret audit warning
  Fourteen cases: the warning appears once and names the audit log, the shell history, a wrapper's argv, --args-from-fd and the three non-argv sources; it never contains the value; -q still suppresses it; the secret still arrives on fd 3; a file: source is quiet; an env: source makes no exec-record claim; both audit wordings; --args-from-fd still warns while a literal secret remains; the JSON report carries it and does not leak the value. The rows that assert "nothing leaks" have the pairing the protocol asks for: 59b checks the warning text and 59i checks the report, both against a canary the run really carries. Refs #59
- `34b20e3` fix: warn that argv secrets reach the kernel audit log
  A `literal:` or `env:` secret source puts the value in pmask's own argv or environment. pmask already masks its own /proc entry, but three other copies are out of reach and none of them was named anywhere in the output: the kernel's exec record (written before pmask runs), the shell history, and any wrapper's argv. The run now prints one warning at the default verbosity, before it starts, naming all three, `--args-from-fd` and the non-argv sources. `run::audit_state()` asks the kernel the question `auditctl -s` asks, over NETLINK_AUDIT with AUDIT_GET, because auditctl refuses a non-root caller before it asks anything; an enabled subsystem makes the wording claim the record exists rather than that it would. A probe that cannot answer never turns the warning into a refusal. The JSON report carries a shorter form of the same fact, so a CI job that asserts on the report sees it without scraping stderr. `literal:` stays: the record is written before pmask exists, so a refusal at parse time would be a refusal after the exposure. Refs #59
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

## Commits whose message has no `#N` reference

No entry below matches `#N` in its subject or body; that is not the same as naming no issue. `b6822b1` names its issues as a bare `19:` list, and `0b01a4f`, `9e1de9d` and `69cc3f8` name theirs only in a diff comment (#5, #17, #38). The `fix commit` column in the table above is the mapping.

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

