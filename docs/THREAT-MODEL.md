# Threat model

Each row below states one security claim, the mechanism that enforces it, and the test that catches regressions. Any claim that the code does not enforce is a security bug. File it with the mechanism, the test, and the observed output.

Measurements live in `tests/compare.sh`, `tests/conformance.sh`, and `tests/daemon.sh`. Source notes live in `docs/research/`.

## Adversaries

| id | who | capability |
|---|---|---|
| A1 | another account on the host | reads `/proc/<pid>/{cmdline,comm,stat,status,cgroup}` for any process. `environ`, `exe`, `maps`, `fd/*`, and `mem` require `PTRACE_MODE_READ_FSCREDS`, which fails across uids |
| A2 | another process of the same account, including a compromised job step | everything A1 does, plus same-uid `PTRACE_MODE_READ_FSCREDS` checks pass. Reads `environ`, `maps`, `mem`, and `fd/*` unless the target is non-dumpable |
| A3 | a later metadata reader: monitoring agent, support bundle, pasted `ps` output, or terminal recording | reads whatever was captured at the time |
| root | host operator or anything with `CAP_SYS_PTRACE` | full access to `mm`, `/proc/<pid>/mem`, tracee registers, and supervisor memory |

## What each claim rests on

| claim | adversary | mechanism | state | test |
|---|---|---|---|---|
| `/proc/<pid>/cmdline` shows the label, not the arguments | A1, A2, A3 | pointer-array swap at exec entry, then `PR_SET_MM_MAP` moves `mm->arg_start`/`arg_end` onto the presentation block in `[stack]` | enforced | `compare.sh` canary column, `conformance.sh` args-hidden, `validate.sh`, `suite.sh` |
| `cmdline` byte length does not match the original arguments | A1, A2 | `arg_end = arg_start + len(label) + 1`, so `/proc/<pid>/stat` fields 48 to 51 match the label length | enforced where `PR_SET_MM_MAP` works. `--no-exact`, kernels without `CONFIG_CHECKPOINT_RESTORE`, or seccomp blocking `prctl` keep the original extent (space-padded label plus one NUL, and decoy `environ`). Counted in summary | `compare.sh` span column |
| NUL padding is not a signature | A1, A2, NUL-run detectors | presentation holds the label plus one NUL terminator, matching an ordinary single-argument command | enforced | `compare.sh` `nul_count` and `nul_maxrun`: 1 and 1 masked vs 4 control |
| `/proc/<pid>/environ` is a plausible decoy | A1, A2, A3 | entry pointer swap, then completion points `env_start = arg_end` at a complete 110-byte decoy environment (or `--keep-env` entries) in the presentation area | enforced by default. `--no-exact` fills the original extent with the same entries. `--keep-env` exposes the full environment, and `--keep-env=NAME` exposes named variables | `conformance.sh`, `options.sh` O9/O10, `edge.sh` E10 |
| `comm` stays the label | A1, A3 | injected `prctl(PR_SET_NAME)` at exec completion, plus `--watch-rename` seccomp filter trapping `prctl(PR_SET_NAME)` and write-mode `open`/`openat`/`openat2`/`creat` on `/proc/.../comm` (with `dirfd`/`cwd` resolution and lexical path normalization). `--watch-rename=strict` also traps `write`/`writev`/`pwrite64`/`pwritev`/`pwritev2` and checks descriptor targets via `readlink` | enforced for paths the filter can decide. Symlink aliases and `SCM_RIGHTS` descriptors require `--watch-rename=strict` (`--stealth` uses the default filter). If `readlink` fails with `EACCES` on a non-dumpable tracee, the tracer emits a visible warning rather than failing open silently. Refuses `--detach` and `--on-exit detach` | `conformance.sh` comm-is-label, `options.sh` O17, `qa.d/71.sh`, `qa.d/72.sh`, `redteam.sh` R7/R7b/R7c |
| `ps` shows the label | A3 | `ps` reads the same `/proc` files covered above | enforced | `conformance.sh` ps-args-is-label |
| the supervisor's own command line is the label | A1, A2 | supervisor zeroes its `argv`, writes the label, sets the decoy `environ`, relocates its window, sets `comm`, and scrubs at-rest copies after fork | enforced for `cmdline` and `environ`. The second thread and `PMASK_NO_SELFMASK` escape remain residuals below. `--no-dumpable`, `--hide-pid`, `--encrypt-memory`, `--secret`, and `--report` pin the supervisor non-dumpable | `conformance.sh` supervisor-selfmask, `edge.sh` E6 |
| a delivered secret never appears in `cmdline`, `environ`, or `ps` | A1, A2, A3 | value travels on a sealed memfd at fd 3+. Only `PMASK_SECRET_<NAME>=<fd>` sits in the real environment, and `/proc/<pid>/environ` shows a decoy. In redaction mode, the payload is non-dumpable by default, blocking same-uid reads of fd and memory (`--allow-dumpable` opts out) | enforced | `daemon.sh` d1 to d3, d3b, d7, `conformance.sh` secret-absent, `qa.d/67.sh` |
| the payload cannot modify the secret descriptor | A2 (the payload) | `F_SEAL_WRITE\|F_SEAL_GROW\|F_SEAL_SHRINK\|F_SEAL_SEAL` at creation | enforced | `daemon.sh` d7 write-errno, `secrets.sh` c3 |
| the secret value is gone after a burn | A2 | `--secret-burn` omits `F_SEAL_SHRINK`, allowing one `ftruncate(fd, 0)` without regrowth | enforced for a cooperating reader. A reader that copies the value defeats it | `secrets.sh` c2 |
| a secret descriptor does not reach payload descendants | A2 | `--secret-close-on-exec` injects `close(2)` in each direct child at fork while keeping the descriptor open in the payload. Shared-table children (`clone(CLONE_FILES)` without `CLONE_THREAD`) are warned and counted. `--detach` warns and counts unclosed descriptors | enforced for standard fork/exec trees. Shared-table and `--detach` cases are reported degradations | `secrets.sh` c1, c1b, c1e |
| no core dump and no same-uid attach to the holder | A2 | holder applies `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` (`harden_self()`) before loading secrets, passphrases, or `--env-file`. CLI pins the supervisor non-dumpable on secret runs and under `--no-dumpable`, `--hide-pid`, `--encrypt-memory`, or `--report`. `--no-dumpable` extends to the payload | enforced before load on every secret path. Plain runs without secrets hold none, do not mask themselves, and report `mode=plain`. Default non-secret redaction supervisors stay dumpable. Plain secret runs harden the holder without masking its `/proc` entry | `conformance.sh` dumpable-default, nodumpable-refuses, core-limit-zero, `options.sh` O15, `compare.sh` supervisor column, `qa.d/68.sh` |
| secrets are not swapped out | A2 on a later host, support bundle | `mlock`, `MADV_DONTDUMP`, and `memfd_secret` when available | best effort. `RLIMIT_MEMLOCK` decides, and the report names the tier. The payload redaction block stays anonymous and `MADV_DONTDUMP` (not `memfd_secret`) to avoid a `/secretmem` VMA fingerprint | `secrets.sh` e2, `qa.d/64.sh` |
| `TracerPid` is 0 for the payload | A1, A2, detectors | `--detach` detaches each tracee after its exec settles | **not default**. Attached trees show the tracer thread id in `TracerPid` | `compare.sh` tracer column, `edge.sh` E18 |
| kernel exec audit record carries the label | A3, audit detectors | kernel reads `mm->arg_start` at syscall exit, after completion and window relocation | enforced by ordering. Measured on Alpine 3.22, kernel 6.12.115, auditd 4.0.3: `audit.sh` A1 to A4 and A6 PASS (`VERDICT: FAIL=0`). A5 and A7 are INFO (A7 reports no real `argv` in the `vfork` child's audit log) | `audit.sh` A1 to A7 |
| eBPF exec sensor cannot see arguments before rewrite | limit, not a claim | `trace_sched_process_exec` fires before `PTRACE_EVENT_EXEC` and carries only filename and two pids | kernel limit. No userland action changes it | `research/detection-residue.md` |
| same-uid peer cannot read real `argv` from `/proc/<pid>/mem` | A2 | not blocked by default because real strings live in the tracee's mapping | **not default** for non-secret runs. `--no-dumpable` (and default `--secret` in redaction mode) closes it | `compare.sh` `mem_canary_readable`: 1 in control/redacted/detached, `SKIP` in `redacted-nodumpable` |
| tracer thread does not name `pmask` | A1, A2 | tracer thread uses the session `comm` or label, never `pmask-tracer`. `Tgid != Pid` stays visible | partial. The fixed string is gone; the thread relation is inherent to ptrace | `qa.d/38.sh` |
| supervisor's own entry is masked | A1, A2 | supervisor applies the same window relocation to itself. `PR_SET_DUMPABLE=0` applies with `--no-dumpable`, `--hide-pid`, `--encrypt-memory`, `--secret`, or `--report` | partial. Window relocation is enforced; dumpable flag is conditional. `PMASK_NO_SELFMASK=1` is a debug escape that warns when exposing secrets | `qa.d/39.sh`, `conformance.sh` supervisor-selfmask |
| image or secret memfd does not carry a `pmask` name | A1, A2 | `--secret-fd-name` and `--memfd-name` override defaults | opt-in. Defaults stay `pmask-secret` and `/memfd:<label>` | `qa.d/45.sh`, `conformance.sh` secret-fd-is-memfd |
| PING does not expose daemon policy to another uid | A1 | daemon returns full PING details only to its own uid and root. Other allowed uids get protocol facts and `detail=reduced` without policy fields | enforced | `qa.d/51.sh` |
| `literal:` and `env:` secrets warn about audit log and wrapper `argv` | A3 | pre-run warning names audit records, shell history, and wrapper `argv` without printing the secret value | enforced | `qa.d/59.sh` |
| systemd scope description does not contain the command line | A3 | `systemd-run --description=pmask`. Unit name stays visible in `/proc/<pid>/cgroup` | enforced where a user manager exists | `qa.d/55.sh` |
| pid, parent chain, cgroup, fds, sockets, and start time stay visible | limit | `pmask` redacts process content, not process existence | kernel limit. Cross-view existence checks still see the pid | `research/detection-residue.md`, `edge.sh` E19 |

## Residuals the b-team measured

Each row below records a measured residual, attribution channel, or kernel limit. The issue number identifies the originating report.

Numbers below were measured on the b-team host: Debian 13, kernel 6.12.113, uid 1000, LXC container, release binary from the b-team tree (`fa46e62` plus branch commits). The audit and eBPF rows were measured in an Alpine 3.22 guest on kernel 6.12.115 with auditd 4.0.3. These records are quoted as measured. Each referenced research note contains the exact command for its measurement.

| claim and issue | adversary | mechanism | state | test |
|---|---|---|---|---|
| tracer thread is not identifiable (38) | A1, A2 | thread takes session `comm` or label (up to 15 bytes), never `pmask-tracer`. `TracerPid` still names a thread with `Tgid` equal to supervisor pid | limit. Fixed name is gone, but `Tgid != Pid` and nonzero `TracerPid` remain. `--isolate` and `--no-redact` use no tracer; `--detach` zeroes tracee `TracerPid` while keeping the supervisor thread | `qa.d/38.sh`, `research/bteam-38-50.md` |
| supervisor entry carries no fingerprint (39) | A1, A2, A3 | self-mask relocates the window, sets the label, and presents a plausible 110-byte decoy `environ` (unless `--keep-env` keeps entries). Supervisor has two threads, and `PMASK_NO_SELFMASK=1` disables self-masking | partial. Label and decoy `environ` are enforced. `Threads: 2` and the debug escape remain limits. `--secret literal:` exposes the value in real `argv` during the debug window | `conformance.sh` supervisor-selfmask, `research/bteam-39-43.md` |
| `cmdline` length matches `stat` span (40) | A1, A2, detector | `PR_SET_MM_MAP` sets `arg_end = arg_start + len(label) + 1` and `env_start = arg_end`, keeping kernel `start_stack` | enforced in exact mode. `--no-exact` keeps the original extent padded with spaces and one NUL. Cross-uid readers see `0 0 0 0` | `compare.sh`, `qa.d/40.sh` |
| `environ` is a plausible decoy (41) | A1, A2, A3 | environment window holds a complete 110-byte decoy environment (or kept entries) at `arg_end`, with no real secret values | partial. Fixed 110-byte decoy length when no variable is kept is itself a signature. `--no-exact` fills the original extent; `--keep-env` exposes real values | `conformance.sh` environ-hidden, `options.sh` O9/O10, `blueteam.sh` H7, `research/bteam-39-43.md` |
| label hides which binary runs (42) | A1, A2 | `exe`, `maps`, uid, sockets, sessions, cgroups, and parent chain stay real by default | limit. `--rexec` moves `exe` to `/memfd:<label>`, and `--no-dumpable` blocks same-uid `exe` and `maps`. The `comm`/`exe` split stays visible to root | `compare.sh`, `research/bteam-39-43.md` |
| `/proc/<pid>/auxv` and payload agree on label (43) | A1, A2 | completion rewrites `AT_EXECFN` in both `saved_auxv` and the stack vector to point at the label copy at `env_end` | enforced in exact mode. `--no-exact` and refused `PR_SET_MM_MAP` keep the real exec path in both | `qa.d/43.sh`, `redteam.sh` R1, `research/bteam-39-43.md` |
| `--no-dumpable` closes same-uid reads (44) | A2 | `PR_SET_DUMPABLE=0` in every tracee makes `environ`, `maps`, `auxv`, `exe`, `fd/*`, and `mem` return `EACCES` to the same uid | partial. Uniform `EACCES` set is a fingerprint. Plain and isolate modes do not apply it | `conformance.sh` nodumpable-refuses, `compare.sh`, `research/bteam-audit.md` |
| memfd carries no `pmask` name (45) | A1, A2 | `--secret-fd-name` renames secret memfds; `--memfd-name` renames image memfds and `--exec-once` carriers | partial. Defaults stay `/memfd:pmask-secret` and `/memfd:<label>`. Options are cosmetic; `/secretmem` cannot be named | `qa.d/45.sh`, `research/bteam-ebpf.md` |
| rename filter is invisible (46) | A1, A2 | seccomp filter traps `prctl(PR_SET_NAME)` plus `open`/`openat`/`openat2`/`creat` on `/proc/.../comm` (and write syscalls under `=strict`), implying `no_new_privs` | limit. `/proc/<pid>/status` shows `Seccomp: 2`, `Seccomp_filters: 1`, `NoNewPrivs: 1` (`Seccomp_filters: 2` when combined with the `--exec-once` exec filter) | `options.sh` O17, `qa.d/71.sh`, `research/bteam-ebpf.md` |
| tree appearance at session end (47) | A1, A2 | `detach` releases settled tracees, `wait` drains, `kill` sends `SIGKILL`. `PTRACE_O_EXITKILL` is default | limit. Detached trees keep the label with `TracerPid` 0; `--no-follow` leaves descendants real; killed siblings reveal membership | `edge.sh` E18/E19, `research/bteam-38-50.md` |
| real command line is never briefly visible (48) | A1, A2, A3 | entry swap covers ELF execs; `#!` scripts and `vfork` children take the post-exec path unless `--strict-exec` refuses them | limit. Script `comm` stayed readable for median 307.6 us (min 257.9, max 394.2) on Debian 13, kernel 6.12.113, uid 1000, LXC (`sh measurements/launch-window.sh`, `WINDOW_ROUNDS=3`, `WINDOW_N=60`). A sub-millisecond poller sees that window. `--args-from-fd` removes the vector from launcher `argv` | `compare.sh` window column, `qa.d/66.sh`, `research/bteam-38-50.md` |
| label applies in every mode (49) | A1, A2, A3 | plain and bare isolate do not redact payloads. `--redact --isolate` composes both. 32-bit images are refused by default | partial. Composed mode redacts; 32-bit images are killed with `SIGKILL` unless `--allow-foreign` is set | `isolation.sh` I18, `options.sh` O19, `qa.d/49.sh`, `research/bteam-audit.md` |
| `/proc/<pid>/mem` does not hold real `argv` (50) | A2 | real strings live in the injected anonymous block for process lifetime | limit. Same-uid peers can read `/proc/<pid>/mem` while dumpable; `--no-dumpable` blocks it | `compare.sh` `mem_canary_readable` |
| `pmaskd` is not discoverable (51) | A1, A2 | bound Unix socket appears in `/proc/net/unix` and `ss -x`. Full PING body is restricted to daemon uid and root | limit. Socket path is visible regardless of mode. Other allowed uids get `detail=reduced` with no environment values | `daemon.sh` d1 to d3, `qa.d/51.sh`, `research/bteam-records.md` |
| daemon tree is not identifiable (52) | A1, A2 | daemon self-masks; `--jobs N` spawns one worker per connection; every job leaf is traced | limit. Shared label across daemon, worker, and leaf, one tracer thread per job (38), and listening socket at root | `daemon.sh` d1 to d3, `research/bteam-records.md` |
| refusal or degradation is silent (53) | A3, log sweeps | every path prints a `pmask: ` or `pmaskd: ` diagnostic and returns a stable exit code | limit. Prefix identifies `pmask` activity; `-q` suppresses normal diagnostics | `daemon_neg.sh`, `options.sh`, `research/bteam-records.md` |
| `pmask` leaves nothing on disk (54) | A3, forensics | store persists at mode `0600` with magic header; units and packaging files persist; binary holds strings and `.comment` | limit. Runtime artifacts are transient; store and packaging persist | `store.sh`, `research/bteam-records.md` |
| nothing outside the tree records the command line (55) | A3, A2 with sink access | `--report=json`, `--audit`, `pmaskd -v`, `sudo` child `argv`, shell history, `--scope-name` unit description, and `probe`/`doctor` describe runs | limit. `-q` without report, audit, or scope leaves only shell history | `research/bteam-records.md` |
| kernel audit record carries the label (56, 59) | A3, audit detectors | payload record is captured after relocation; supervisor record is captured before self-masking | partial. Payload record holds label plus empty slots; supervisor `EXECVE`/`PROCTITLE` captures real `argv` including `literal:` secrets | `audit.sh` A1 to A7, `research/bteam-audit.md` |
| eBPF exec sensor cannot see arguments (57) | kernel sensor | `sched_process_exec` carries filename and two pids; `sys_enter_execve` sees swapped pointers | limit. Exec tracepoint omits `argv`, but tracer `ptrace` and `process_vm_writev` syscalls identify tracer and target | `qa.d/57.sh`, `research/bteam-ebpf.md` |
| hidden-pid detectors find nothing (58) | defender | default mode hides no pids, keeping `readdir` and parent links intact | limit. Blind in default mode, but under `--hide-pid`, `chkproc` finds the pid via `getpriority`/`sched_getaffinity`/`prlimit`, and `cgroup.procs`/`cgroup.threads` still list it. `pspy` shows the label; `strace` differs by `Tgid == Pid` | `qa.d/58.sh`, `qa.d/73.sh`, `blueteam.sh`, `research/bteam-detectors.md` |

## What one command finds, per mode

A single `awk` sweep detects every run that installs a seccomp filter:

```sh
awk '$1=="Seccomp:" && $2!=0 {print FILENAME}' /proc/*/status
```

Measured in an Alpine 3.22 guest, kernel 6.12.115, release binary built from this tree, one `sleeping` payload per row, run as uid 0 and uid 1000. On a non-`hidepid` host, `--stealth` enables `--no-dumpable` (so `--stealth --exec-once` is refused there). On a `hidepid=invisible` or `hidepid=ptraceable` host, `--stealth` omits `--no-dumpable` so the tree does not become a hidden pid, which leaves `environ`, `exe`, `maps`, and `/proc/<pid>/mem` readable to same-uid observers unless `--no-dumpable` is explicitly added.

| mode | payload `Seccomp:` | payload `TracerPid` | supervisor `exe` | payload `exe` | payload `environ` |
|---|---|---|---|---|---|
| default | absent | the tracer | `/app/tests/pmask` | the real binary | the 110-byte decoy |
| `--watch-rename` | 2 | the tracer | `/app/tests/pmask` | the real binary | the 110-byte decoy |
| `--watch-rename=strict` | 2 | the tracer | `/app/tests/pmask` | the real binary | the 110-byte decoy |
| `--stealth` (`hidepid=0`) | 2 | the tracer | unreadable to uid 1000, `/app/tests/pmask` to root | `/memfd:<label> (deleted)` to root, unreadable to uid 1000 | unreadable to uid 1000 |
| `--on-exit detach` | absent | the tracer while running, 0 after master exits | `/app/tests/pmask` | the real binary | the 110-byte decoy |
| `--rexec` | absent | the tracer | `/app/tests/pmask` | `/memfd:<label> (deleted)` | the 110-byte decoy |
| `--no-exact` | absent | the tracer | `/app/tests/pmask` | the real binary | the 110-byte decoy at original extent |

The sweep finds 0 matches before any run and 1 match for every mode that installs a filter, including `--stealth`. `--stealth` installs the default (non-strict) rename filter and, on `hidepid=0`, makes supervisor and payload non-dumpable. Unprivileged readers lose `exe`, `maps`, and `environ`, but still read `Seccomp:`.

In the `--stealth` row above, the uid-1000 `environ` refusal (0 bytes) and root `exe` were measured directly. The same `PTRACE_MODE_READ_FSCREDS` check governs uid-1000 `exe`, making it unreadable as well.

`tests/blueteam.sh` runs this grid as root and uid 1000 and asserts all documented claims.

## Per-interface limits

`docs/research/MICROVM-GAP.md` marks each kernel interface `closed`, `partial`, or `open`. Every `open` row cites one `L<n>` entry below.

| id | interface | what a same-uid peer still learns | why `pmask` cannot close it | what closes it |
|---|---|---|---|---|
| L1 | `/proc` directory listing | pid existence and name in `readdir` | procfs belongs to the host; a pid namespace changes only the payload's view | a micro-VM (second kernel) |
| L1a | `/proc` directory listing with `--hide-pid` | hidden from `/proc` `readdir` and `stat` on `hidepid=invisible` or `hidepid=ptraceable`. Existing dentries on `hidepid=ptraceable` return `EPERM` instead of `ENOENT`. `cgroup.procs`, `cgroup.threads`, `kill(0)`, `pidfd_open`, `getpriority`, `sched_getaffinity`, `prlimit` (e.g. `chkproc`), and root still detect the pid | opt-in only. Refuses weaker mounts. cgroupfs and non-`/proc` syscalls query the global pid table outside `/proc` | a micro-VM, or host policies hiding the pid from non-`/proc` syscalls and cgroupfs |
| L1b | supervisor at-rest copies with `--encrypt-memory` | supervisor copies are XChaCha20-Poly1305 ciphertext under a per-session key (in `memfd_secret` when available), with sources zeroed on load. Payload redaction block is anonymous and `MADV_DONTDUMP`. Payload heap, stack, and `/proc/<pid>/mem` remain unchanged | `pmask` does not encrypt payload runtime memory | a TEE, or a payload that does not retain copies |
| L2 | `/proc/<pid>/stat` | window bounds (fields 48 to 51), state, parent pid, and start time | `PR_SET_MM_MAP` updates bounds, but fields remain visible | a micro-VM |
| L3 | `/proc/<pid>/status` | `Seccomp`, capability sets, and `TracerPid` (0 with `--detach`) | kernel synthesizes status from task fields | a micro-VM |
| L4 | `/proc/<pid>/stack` | kernel stack, if caller has `CAP_SYS_ADMIN` | caller capability controls access | removing `CAP_SYS_ADMIN`, or a micro-VM |
| L5 | `/proc/<pid>/wchan` | kernel wait channel | task state cannot be rewritten from userland | a micro-VM |
| L6 | `/proc/<pid>/limits` | process rlimits | rlimits are task metadata | a micro-VM |
| L7 | `/proc/<pid>/cgroup` | cgroup path | plain redaction does not create a cgroup namespace; isolate mode does | isolate mode cgroup namespace, or a micro-VM |
| L8 | `pidfd_open` | stable handle to any pid | requires only the pid with no permission check | separate pid namespace for observer, or a micro-VM |
| L9 | cgroupfs | cgroup hierarchy and member pids (`cgroup.procs`, `cgroup.threads`) | cgroupfs is a host filesystem; a mount namespace hides it from the payload, not from the host | delegated cgroup isolation or a micro-VM |
| L10 | netlink `NETLINK_CONNECTOR` and `PROC_EVENTS` | fork, exec, and exit events for every pid (requires `CAP_NET_ADMIN`) | kernel emits events for the host pid namespace | removing `CAP_NET_ADMIN`, or a micro-VM |
| L11 | `SO_PEERCRED` | peer pid, uid, and gid on a shared Unix socket | required for daemon authorization | avoiding shared sockets, or a micro-VM |
| L12 | `SO_PEERPIDFD` | peer pidfd on a shared Unix socket (Linux 6.5+) | persistent form of `SO_PEERCRED` | avoiding shared sockets, or a micro-VM |
| L13 | `/dev` nodes | host device presence and modes | plain redaction keeps host `/dev`; isolate mode mounts a fresh `/dev` | isolate mode private `/dev`, or a micro-VM |
| L14 | `/proc/net` | all host sockets | redaction path shares host net namespace; isolate mode adds a private net namespace | `--isolate=net`, or a micro-VM |
| L15 | `inotify` on `/proc` | creation and removal of `/proc` entries | observer watches host procfs | a micro-VM |
| L16 | `perf_event_open` | process sampling when `perf_event_paranoid` permits | host kernel sysctl controls access | restrictive `perf_event_paranoid`, or a micro-VM |
| L17 | `userfaultfd` | page-fault monitoring when `vm.unprivileged_userfaultfd` permits | host sysctl controls access | disabling unprivileged `userfaultfd`, or a micro-VM |
| L18 | `/proc/kcore` | kernel memory image (requires `CAP_SYS_RAWIO`) | caller capability controls access | removing `CAP_SYS_RAWIO`, or a micro-VM |

## What changes when a mechanism is missing

| missing mechanism | operator impact | how `pmask` reports it |
|---|---|---|
| `ptrace` | `cmdline`, `environ`, and `comm` are not redacted | `probe` marks metadata redaction `unavailable` with seccomp reason. `run` prints a note. `doctor --require redact` exits 4 |
| `PR_SET_MM_MAP` | `cmdline` keeps original extent (space-padded label plus one NUL); `environ` holds the plausible 110-byte decoy (or kept entries) in place at the original extent | `probe` marks `exact cmdline window` unavailable. Session summary counts each exec that kept its extent |
| unprivileged user namespaces | payload sees host pid, mount, and network views | `probe` marks isolation unavailable. `run` prints the substitution |
| `memfd_secret` | secret pages stay locked but remain in the kernel direct map | `probe` marks it unavailable. Report says `hardening=locked` |
| `mlock` | secret pages may reach swap | `probe` reports `RLIMIT_MEMLOCK` in bytes. Report says `hardening=heap` or `hardening=secret_mem` |
| `SO_PEERPIDFD` | daemon identifies peers by uid and `/proc` start time, which can race pid reuse | daemon prints one startup warning and continues serving |
| agent-owned socket directory | agent refuses to bind in a directory owned by another account | refusal names the path and reason |

## What pmask is not

`pmask` is not a TEE and not a hypervisor. `pmask` reduces `/proc` disclosure to other local accounts and later metadata readers. It does not hide process existence from the host, survive kernel observers, or protect secrets from root on the same host. The README limit table defines the contract, and `docs/research/detection-residue.md` catalogs every surviving interface.
