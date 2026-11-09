# Issue closure

One section per issue. A commit is listed when its subject or body names the issue. The test column names the fragment that would fail if the fix were reverted; the evidence column names the directory holding the raw logs.

| # | issue | commits | test | evidence |
|---|---|---|---|---|
| 4 | `--unshare` / `--redact --isolate` silently disables redaction | `74b7b6a` | none | none |
| 5 | `pmask read NAME` fails inside a masked payload | none | none | none |
| 6 | `pmask store --help` and `pmask get --help` do not print help | none | none | none |
| 7 | `--env-file` parses two different grammars in pmask and pmaskd | none | none | none |
| 8 | Completions miss seven flags | none | none | none |
| 9 | `--report=json` is not one JSON object when the payload writes to stdout | none | none | none |
| 10 | Plain and isolate modes silently drop mask options | none | none | none |
| 11 | An unknown `--secret` scheme is silently delivered as a literal | none | none | none |
| 12 | `isolation.sh`, `compare.sh` and `conformance.sh` never run in CI | none | none | none |
| 13 | `probe`/`doctor` report the exact cmdline window as active where redaction is unavailable | none | none | none |
| 14 | Assorted small CLI/UX nits (N1–N8) | none | none | none |
| 15 | The supervisor's `memfd_secret` buffer is not `MFD_CLOEXEC`, so the plaintext leaks into the tree | none | none | none |
| 16 | `--keep-env` followed by `--keep-env=NAME` exposes the whole environment | none | none | none |
| 17 | `--audit` aborts the supervisor on a closed stdout and kills the payload | none | none | none |
| 18 | `--job-timeout` overflow panics the daemon | none | none | none |
| 19 | `--redact --isolate=net` discards the list and applies `--unshare` | none | none | none |
| 20 | `--no-redact --isolate` runs plain and silently drops the isolation | none | none | none |
| 21 | `payload_dumpable` is false in plain mode while the payload is dumpable | none | none | none |
| 22 | SIGTERM cannot stop a single-job daemon while a client is silent with `--io-timeout 0` | none | none | none |
| 23 | The tmpfiles entry creates an empty store file, so `store init` fails | none | none | none |
| 24 | Documented `pmaskd` ExecStart uses `--store`, which `pmaskd` does not accept | none | none | none |
| 25 | `--isolate` gives the payload a `/dev` without `/dev/pts`, `/dev/ptmx` or `/dev/shm` | none | none | none |
| 26 | `--isolate=none` still creates user, mount, uts, ipc and cgroup namespaces | none | none | none |
| 27 | `-q` does not suppress the isolation report | none | none | none |
| 28 | `--hugetlb --image -` fails instead of falling back to an ordinary memfd | none | none | none |
| 29 | `doctor --json` breaks on a quoted store path; `doctor --require ''` passes | none | none | none |
| 30 | `--env =VALUE` is accepted in plain mode and refused in redact mode | none | none | none |
| 31 | `--args-from-fd 0` closes the payload's stdin | none | none | none |
| 32 | `--audit` is silently inert when the host selects plain mode | none | none | none |
| 33 | `--comm` accepts LF and CR | none | none | none |
| 34 | A ptrace-denied host gives a cryptic `session error` for a mask run | none | none | none |
| 35 | The test gate is not root-safe (`sudo sh tests/run.sh` fails) | none | none | none |
| 36 | Assorted small CLI/docs nitpicks (F17, F22, F25, F27, F28) | none | none | none |
| 38 | [b-team] The tracer thread is named `pmask-tracer`, and `TracerPid` points at a thread of the supervisor | `fbc4666`, `f1a3a3d`, `f0bd7e0` | `tests/qa.d/38.sh` | `evidence/bteam2` |
| 39 | [b-team] The supervisor's own `/proc` entry: the label, a zero argv window, two threads, and the `PMASK_NO_SELFMASK` escape | `26aeb7a`, `a5c7708`, `bc2888f`, `bd8b77a`, `0e5b064` | `tests/qa.d/39.sh` | `evidence/bteam1` |
| 40 | [b-team] The argv window arithmetic of a masked process: `cmdline` is the label, its byte count equals the `stat` span, and the environment span is zero | `a5c7708`, `bd8b77a`, `0e5b064` | `tests/qa.d/40.sh` | `evidence/bteam1` |
| 41 | [b-team] The `environ` file of a masked process: zero bytes, a NUL run, or the kept variables | `a5c7708`, `bd8b77a`, `0e5b064` | `tests/qa.d/41.sh` | `evidence/bteam1` |
| 42 | [b-team] `comm`, `cmdline` and `exe` disagree: label limits, blank labels and the masquerade | `a5c7708`, `bd8b77a`, `0e5b064` | `tests/qa.d/42.sh` | `evidence/bteam1` |
| 43 | [b-team] `AT_EXECFN` serves a second label copy at `env_end`, while the payload's own `getauxval` keeps the real path | `149ee7c`, `a5c7708`, `bc2888f`, `bd8b77a`, `0e5b064` | `tests/qa.d/43.sh` | `evidence/bteam1` |
| 44 | [b-team] `--no-dumpable` answers `EACCES` on five files and zeroes four `stat` fields | `66937c9`, `74fbe52`, `720873b`, `9ca47ad`, `8d1c552` | `tests/qa.d/44.sh` | `evidence/bteam3` |
| 45 | [b-team] Named kernel objects: `/memfd:<label>`, `/memfd:pmask-secret` and `/secretmem` | `0022762`, `20716d0` | `tests/qa.d/45.sh` | `evidence/bteam5` |
| 46 | [b-team] `--watch-rename` leaves a second seccomp filter and `NoNewPrivs=1` | `af95ff7` | `tests/qa.d/46.sh` | `evidence/bteam5` |
| 47 | [b-team] End states: `--detach`, `--no-follow`, `--on-exit` and `PTRACE_O_EXITKILL` | `fbc4666`, `f1a3a3d`, `f0bd7e0` | `tests/qa.d/47.sh` | `evidence/bteam2` |
| 48 | [b-team] The launch window and the statistical side channels of supervision | `fbc4666`, `f1a3a3d`, `f0bd7e0` | `tests/qa.d/48.sh` | `evidence/bteam2` |
| 49 | [b-team] Modes that do not redact: 32-bit images, plain, `--isolate` and `--unshare` | `66937c9`, `9ca47ad`, `74b7b6a` | `tests/qa.d/49.sh` | `evidence/bteam3` |
| 50 | [b-team] The real argv stays in payload memory | `fbc4666`, `f1a3a3d`, `f0bd7e0` | `tests/qa.d/50.sh` | `evidence/bteam2` |
| 51 | [b-team] `pmaskd` is discoverable: the socket table, the 0600 node and the PING oracle | none | none | none |
| 52 | [b-team] `pmaskd`'s own entry, its workers and the job leaf | none | none | none |
| 53 | [b-team] `pmaskd` refusals, exit codes and error strings | none | none | none |
| 54 | [b-team] The on-disk footprint: `store.enc`, the agent socket, the unit files, the tmpfiles entry and the release binary | none | none | none |
| 55 | [b-team] Records outside the masked tree: report, audit, daemon log, `sudo` argv, shell history, systemd scope, `probe`/`doctor` | none | none | none |
| 56 | [b-team] auditd: the records a pmask launch leaves, and the rule forms that do and do not see them | `bc75077`, `9ca47ad`, `8031b41`, `07d7cc8` | `tests/qa.d/56.sh` | `evidence/bteam3` |
| 57 | [b-team] eBPF sensors and the process connector: what each sees of a masked exec | `7d12efc`, `ca32ce6` | `tests/qa.d/57.sh` | `evidence/bteam5` |
| 58 | [b-team] The detector family that does not see pmask, and what pmask genuinely hides | `5f996f6` | `tests/qa.d/58.sh` | `evidence/bteam5` |
| 59 | The supervisor's own exec writes the payload argv and any `literal:` secret into the kernel audit log | `9ca47ad`, `07d7cc8`, `6a1ba77`, `34b20e3` | `tests/qa.d/59.sh` | `evidence/bteam3` |
| 60 | `--watch-rename` and `--no-dumpable` together cannot redirect a rename | none | none | none |
| 61 | Detection documentation contradicts its own measurements: a four-hunk patch | none | none | none |

## Details

### #4 `--unshare` / `--redact --isolate` silently disables redaction

- `74b7b6a` test: cover the mode table that does not redact
  One row per mode: default, --no-redact, --isolate, --unshare, --redact --isolate and a 32-bit image. Each asserts the real or the label shape, the environ byte count, TracerPid, and the namespace fingerprints (`hidepid=invisible` in mountinfo, an NSpid chain of two). The --unshare row is decided by measurement: if the build serves the label the fragment asserts the fixed shape, and if it serves the real argv it prints SKIP naming the #4/qa-fix1 dependency instead of passing. Both branches were exercised, the release build against the first and the musl build against the second. Trees are walked by PPid, never `pgrep -x sleep`, because other suites run on this host. Refs #49

### #5 `pmask read NAME` fails inside a masked payload

No commit names this issue.

### #6 `pmask store --help` and `pmask get --help` do not print help

No commit names this issue.

### #7 `--env-file` parses two different grammars in pmask and pmaskd

No commit names this issue.

### #8 Completions miss seven flags

No commit names this issue.

### #9 `--report=json` is not one JSON object when the payload writes to stdout

No commit names this issue.

### #10 Plain and isolate modes silently drop mask options

No commit names this issue.

### #11 An unknown `--secret` scheme is silently delivered as a literal

No commit names this issue.

### #12 `isolation.sh`, `compare.sh` and `conformance.sh` never run in CI

No commit names this issue.

### #13 `probe`/`doctor` report the exact cmdline window as active where redaction is unavailable

No commit names this issue.

### #14 Assorted small CLI/UX nits (N1–N8)

No commit names this issue.

### #15 The supervisor's `memfd_secret` buffer is not `MFD_CLOEXEC`, so the plaintext leaks into the tree

No commit names this issue.

### #16 `--keep-env` followed by `--keep-env=NAME` exposes the whole environment

No commit names this issue.

### #17 `--audit` aborts the supervisor on a closed stdout and kills the payload

No commit names this issue.

### #18 `--job-timeout` overflow panics the daemon

No commit names this issue.

### #19 `--redact --isolate=net` discards the list and applies `--unshare`

No commit names this issue.

### #20 `--no-redact --isolate` runs plain and silently drops the isolation

No commit names this issue.

### #21 `payload_dumpable` is false in plain mode while the payload is dumpable

No commit names this issue.

### #22 SIGTERM cannot stop a single-job daemon while a client is silent with `--io-timeout 0`

No commit names this issue.

### #23 The tmpfiles entry creates an empty store file, so `store init` fails

No commit names this issue.

### #24 Documented `pmaskd` ExecStart uses `--store`, which `pmaskd` does not accept

No commit names this issue.

### #25 `--isolate` gives the payload a `/dev` without `/dev/pts`, `/dev/ptmx` or `/dev/shm`

No commit names this issue.

### #26 `--isolate=none` still creates user, mount, uts, ipc and cgroup namespaces

No commit names this issue.

### #27 `-q` does not suppress the isolation report

No commit names this issue.

### #28 `--hugetlb --image -` fails instead of falling back to an ordinary memfd

No commit names this issue.

### #29 `doctor --json` breaks on a quoted store path; `doctor --require ''` passes

No commit names this issue.

### #30 `--env =VALUE` is accepted in plain mode and refused in redact mode

No commit names this issue.

### #31 `--args-from-fd 0` closes the payload's stdin

No commit names this issue.

### #32 `--audit` is silently inert when the host selects plain mode

No commit names this issue.

### #33 `--comm` accepts LF and CR

No commit names this issue.

### #34 A ptrace-denied host gives a cryptic `session error` for a mask run

No commit names this issue.

### #35 The test gate is not root-safe (`sudo sh tests/run.sh` fails)

No commit names this issue.

### #36 Assorted small CLI/docs nitpicks (F17, F22, F25, F27, F28)

No commit names this issue.

### #38 [b-team] The tracer thread is named `pmask-tracer`, and `TracerPid` points at a thread of the supervisor

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

- `a5c7708` docs: refresh the evidence logs and add the verification transcript
  The five QA fragments were re-run against the final build and their output is stored beside the measurements. verification.log carries the exact fmt, clippy, lib-test and rename-check invocations with their exit codes.
- `bd8b77a` docs: record the b-team 39-43 residue measurements
  New research note plus one evidence directory per issue. The note carries each detector rule, the measured output, why the channel cannot be closed in userland, and the trade of every alternative. It also records four corrections to the issue reports, each backed by a log: - PMASK_NO_SELFMASK is honoured on the plain path and overridden after the fork in redact and isolate mode (issue 39) - --no-exact does not keep the original extent on the ELF entry path; it keeps one NUL per argument slot (issue 40) - a literal: secret never reaches the payload's environ, so the keep-env warning must be scoped to env: (issue 41) - --no-exact does not rewrite the auxv at all, and AT_EXECFN == env_end only holds when the environment is redacted (issue 43)
  Files: `docs/research/bteam-39-43.md`
- `0e5b064` test: cover the self-mask, windows, environ and auxv channels
  Five QA fragments, one per b-team issue: 39 the supervisor's own entry: comm/cmdline/tracer task, the non-dumpable zeros for a same-uid reader, the relocated window as root, and the PMASK_NO_SELFMASK warning and audit refusal 40 the argv window arithmetic: label+NUL, arg span == cmdline bytes, env_start == env_end, the label cuts, and the --no-exact count rule 41 the environ shapes: 0 bytes, a NUL run, --keep-env and --keep-env=NAME, plus the env: warning and that the kept variables stay kept 42 the label limits and the comm/cmdline/exe split, with the --comm LF and CR behaviour recorded against fix1's issue 33 43 AT_EXECFN: the served label, AT_EXECFN == env_end, the in-payload getauxval dissent, and the two modes where each fails Each has a negative control and a liveness check. The fragments set BIN_DIR themselves because lib.sh derives it from the cwd, which is tests/qa.d for a fragment.
- Test: `tests/qa.d/41.sh`

### #42 [b-team] `comm`, `cmdline` and `exe` disagree: label limits, blank labels and the masquerade

- `a5c7708` docs: refresh the evidence logs and add the verification transcript
  The five QA fragments were re-run against the final build and their output is stored beside the measurements. verification.log carries the exact fmt, clippy, lib-test and rename-check invocations with their exit codes.
- `bd8b77a` docs: record the b-team 39-43 residue measurements
  New research note plus one evidence directory per issue. The note carries each detector rule, the measured output, why the channel cannot be closed in userland, and the trade of every alternative. It also records four corrections to the issue reports, each backed by a log: - PMASK_NO_SELFMASK is honoured on the plain path and overridden after the fork in redact and isolate mode (issue 39) - --no-exact does not keep the original extent on the ELF entry path; it keeps one NUL per argument slot (issue 40) - a literal: secret never reaches the payload's environ, so the keep-env warning must be scoped to env: (issue 41) - --no-exact does not rewrite the auxv at all, and AT_EXECFN == env_end only holds when the environment is redacted (issue 43)
  Files: `docs/research/bteam-39-43.md`
- `0e5b064` test: cover the self-mask, windows, environ and auxv channels
  Five QA fragments, one per b-team issue: 39 the supervisor's own entry: comm/cmdline/tracer task, the non-dumpable zeros for a same-uid reader, the relocated window as root, and the PMASK_NO_SELFMASK warning and audit refusal 40 the argv window arithmetic: label+NUL, arg span == cmdline bytes, env_start == env_end, the label cuts, and the --no-exact count rule 41 the environ shapes: 0 bytes, a NUL run, --keep-env and --keep-env=NAME, plus the env: warning and that the kept variables stay kept 42 the label limits and the comm/cmdline/exe split, with the --comm LF and CR behaviour recorded against fix1's issue 33 43 AT_EXECFN: the served label, AT_EXECFN == env_end, the in-payload getauxval dissent, and the two modes where each fails Each has a negative control and a liveness check. The fragments set BIN_DIR themselves because lib.sh derives it from the cwd, which is tests/qa.d for a fragment.
- Test: `tests/qa.d/42.sh`

### #43 [b-team] `AT_EXECFN` serves a second label copy at `env_end`, while the payload's own `getauxval` keeps the real path

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

- `0022762` docs: record the issue 45 memfd-name evidence
- `20716d0` test: cover the memfd name options
- Test: `tests/qa.d/45.sh`

### #46 [b-team] `--watch-rename` leaves a second seccomp filter and `NoNewPrivs=1`

- `af95ff7` test: cover the watch-rename filter row
- Test: `tests/qa.d/46.sh`

### #47 [b-team] End states: `--detach`, `--no-follow`, `--on-exit` and `PTRACE_O_EXITKILL`

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

No commit names this issue.

### #52 [b-team] `pmaskd`'s own entry, its workers and the job leaf

No commit names this issue.

### #53 [b-team] `pmaskd` refusals, exit codes and error strings

No commit names this issue.

### #54 [b-team] The on-disk footprint: `store.enc`, the agent socket, the unit files, the tmpfiles entry and the release binary

No commit names this issue.

### #55 [b-team] Records outside the masked tree: report, audit, daemon log, `sudo` argv, shell history, systemd scope, `probe`/`doctor`

No commit names this issue.

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

- `7d12efc` test: assert the tracer relation, not its old name
- `ca32ce6` docs: record the eBPF and connector refusals
  Files: `docs/research/bteam-ebpf.md`
- Test: `tests/qa.d/57.sh`

### #58 [b-team] The detector family that does not see pmask, and what pmask genuinely hides

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

No commit names this issue.

### #61 Detection documentation contradicts its own measurements: a four-hunk patch

No commit names this issue.

## Commits that name no issue

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

