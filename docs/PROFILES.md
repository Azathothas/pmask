# Execution Profiles, Audit Invariants, and `psgen` Integration

`pmask` v0.3.0 organizes masking, image staging, dumpability, memory hygiene, and isolation into explicit execution profiles (`auto`, `single`, `tree`, `tee`, and `compat`), paired with a machine-verifiable audit engine (`pmask --audit`) and a native `psgen` `schema: 2` profile export (`pmask --profile-json`) requiring zero adapter.

## Profile Ranking (Which Mode to Choose)

1. **`single` (#1 for direct native ELFs, default under `--profile auto`)**: In-place masked `execve`/`execveat` with zero persistent supervisor, `TracerPid: 0`, `Threads: 1`, `Seccomp: 0`, `NoNewPrivs: 0`, `--rexec` (`auto`), and `PR_SET_DUMPABLE=0`. Note: `cwd` stays real unless `--cwd PATH` is passed (same-uid reads still get `EACCES` while non-dumpable).
2. **`tree` (default under `--profile auto` for shells, `#!` scripts, and descendants)**: Single-threaded (`Threads: 1`) supervisor tracking every fork, shell pipeline, and re-exec. `--stealth` is a `tree`-mode preset (`--rexec-mode=auto`, `--watch-rename`, hidepid-aware `--no-dumpable`, silent on `hidepid=off`).
3. **Cross-UID `pmaskd --run-as-uid=UID[:GID]` (or dedicated host uid / subuid)**: Eliminates the same-uid `EACCES` denial signal by placing the payload on a separate host uid; jobs default to `dumpable=1` because Linux DAC naturally denies restricted `/proc` surfaces to other unprivileged uids.
4. **`tee` (fail-closed namespaces)**: Composes redaction with user, pid, and mount namespaces, private `/proc` and `/tmp`, and `cwd=/` normalization. Fails closed with exit `255` whenever unprivileged userns OR the private `/proc` mount is refused.

## Honest Threat Model

`pmask` is engineered to achieve **9+/10 confidentiality and low-residue execution against a same-uid local observer, not root**.

- **In scope (primary observer):** An unprivileged local process running as the **same uid** (or another unprivileged uid) on the same Linux kernel, inspecting `/proc/<pid>/*`, `/proc/<pid>/mem`, `ps`, `top`, `htop`, and standard process monitors without special capabilities.
- **Explicitly out of scope:**
  - `root` (uid 0) and any process holding `CAP_SYS_PTRACE`, `CAP_SYS_ADMIN`, or `CAP_PERFMON` / `CAP_BPF`.
  - Kernel modules, eBPF/kprobe/tracepoint/perf observers, hypervisors, and hardware TEE adversaries.
  - Network observers (unless paired with `--isolate=net`, which creates a private network namespace).
  - Generating decoy background process populations (owned by `psgen`, consuming `pmask --profile-json`).

Run `pmask --explain [--profile NAME] [--json]` on any host to inspect the active observer scope, detected kernel capabilities, hidden surfaces, denial tradeoffs, and residuals before running a workload.

## Profile Comparison

| property | `auto` (default) | `single` | `tree` | `tee` | `compat` |
|---|---|---|---|---|---|
| selection | `single` for direct native ELFs; `tree` for shells, launchers, `#!` scripts, and tree flags | explicit `--profile single` | explicit `--profile tree` or `--follow` | explicit `--profile tee` | explicit `--profile compat` (legacy v0.1.0) |
| persistent supervisor | none when `single`; single-threaded (`Threads: 1`) when `tree` | **none** (transient double-forked helper detaches and exits) | single-threaded (`Threads: 1`) supervisor | single-threaded supervisor + namespaces | single-threaded supervisor |
| `TracerPid` after exec | `0` (`single`) / supervisor pid (`tree`) | **`0`** | supervisor pid (`0` only with `--detach`) | supervisor pid inside host view | supervisor pid (`0` with `--detach`) |
| `Threads` (payload / supervisor) | `1` / none or `1` | `1` / none | `1` / `1` | `1` / `1` | `1` / `1` |
| `Seccomp` / `NoNewPrivs` added | `0` / `0` (unless `--watch-rename` / `--exec-once`) | **`0` / `0`** (unless `--no-new-privs`) | `0` / `0` (unless `--watch-rename` / `--exec-once`) | namespace/isolation defaults | `0` / `0` (opt-in) |
| `PR_SET_DUMPABLE=0` default | yes (`--allow-dumpable` opts out) | **yes** | **yes** (skipped by `--stealth` on `hidepid`) | **yes** | no (opt-in via `--no-dumpable` or `--secret`) |
| `--rexec` default | yes for native ELFs (`--rexec-mode=auto`) | **yes** (`--rexec-mode=auto`, opt out via `--no-rexec`) | **yes** for native ELFs (`--rexec-mode=auto`) | **yes** for native ELFs (`--rexec-mode=auto`) | no (opt-in via `--rexec`) |
| `--encrypt-memory` default | `tree` only | opt-in (helper exits before `main()`) | **yes** | **yes** | no (opt-in) |
| namespaces & private `/proc` | none (unless `--isolate` / `--unshare`) | none (refuses `--isolate`/`--unshare`) | none (optional `--isolate`/`--unshare`) | **required** (user, pid, mount, private `/proc`, private `/tmp`, `cwd=/`; fails closed with exit `255`) | none (opt-in) |
| descendant coverage | `single`: none; `tree`: full tree | none (single native binary) | full descendant tree | full descendant tree inside namespaces | full descendant tree |

### How `--profile auto` chooses

`select_auto_profile` picks `tree` when:

1. Any tree or supervisor feature is requested (`--follow`, `--no-follow`, `--watch-rename`, `--exec-once`, non-`detach` `--on-exit`, `--hide-pid`, `--report`, `--secret-close-on-exec`, `--daemon`, `--unshare`, `--isolate`, `--stealth`, `--audit`, `--image`, `--image-from-fd`, `--parent-label`, `--detach`, `--no-redact`).
2. The target basename matches a known shell or launcher (`sh`, `bash`, `dash`, `ash`, `zsh`, `ksh`, `mksh`, `fish`, `csh`, `tcsh`, `env`, `make`, `xargs`, `timeout`, `nice`, `nohup`, `sudo`, `su`, `busybox`, `run-parts`, `setsid`, `stdbuf`, `ionice`, `chrt`, `taskset`).
3. The resolved program starts with `#!` (script interpreter).

Otherwise, `--profile auto` selects `single`. If `--no-redact` is set under `auto`, it resolves to `compat` (plain mode).

### How `single` achieves zero-supervisor in-place execution

1. `pmask` resolves the command, prepares the staged executable carrier (default `--rexec-mode=auto`), applies `RLIMIT_CORE=0` and optional `--cwd`, and double-forks a transient helper `G`.
2. `pmask` reaps the intermediate child so zero zombies remain, grants `prctl(PR_SET_PTRACER, G_pid)` (working even under `kernel.yama.ptrace_scope=1`), and lets `G` seize it with `PTRACE_SEIZE`.
3. `pmask` calls `execve`/`execveat` in place. `G` intercepts the exec-entry stop for zero-exposure argument/environment redaction, then completes the full rewrite at `PTRACE_EVENT_EXEC` (anonymous `MADV_DONTDUMP` redaction block, batched `argv`/`envp` repoint, decoy `environ`, `AT_EXECFN`, `PR_SET_MM_MAP`, `PR_SET_NAME`, and `PR_SET_DUMPABLE=0`).
4. `G` unlinks any staged `path` carrier and removes its private `0700` directory, then calls `PTRACE_DETACH` and `_exit(0)`.

Result: the payload runs in place in `pmask`'s original PID with **zero supervisor process**, `TracerPid: 0`, `Threads: 1`, `Seccomp: 0`, and `NoNewPrivs: 0`. Pass `--reparent` to double-fork the payload so its `PPid` is PID 1 (or the nearest subreaper) and have `pmask` return `0` as soon as the masked exec detaches.

## The `EACCES` vs Helper-UID / Subuid Tradeoff

Under Linux DAC rules, `cmdline` and `comm` are world-readable, whereas `environ`, `maps`, `auxv`, `exe`, `fd`, `cwd`, and `/proc/<pid>/mem` are gated by `PTRACE_MODE_READ_FSCREDS`. A process running under the **same uid** passes that check by default (Yama `ptrace_scope=1` restricts `PTRACE_MODE_ATTACH`, not `PTRACE_MODE_READ_FSCREDS`).

To close all seven same-uid surfaces without root, `single`, `tree`, and `tee` set `PR_SET_DUMPABLE=0` by default:

- **What it blocks:** Same-uid reads of `/proc/<pid>/mem`, `environ`, `maps`, `auxv`, `exe`, `fd`, and `cwd` all fail with `EACCES`. Core dumps and same-uid `ptrace` attach are also disabled.
- **Observable side effects:**
  1. **Seven-surface `EACCES` signal:** A same-uid scanner expecting readable `/proc` files sees `EACCES` on a process of its own uid.
  2. **Zeroed `/proc/<pid>/stat` fields 48-51:** While `dumpable == 0`, Linux zeroes `arg_start`, `arg_end`, `env_start`, and `env_end` in `/proc/<pid>/stat` (`0 0 0 0`).
  3. **`hidepid` interaction:** On `/proc` mounted with `hidepid=invisible` or `hidepid=ptraceable`, a non-dumpable process becomes invisible to same-uid `readdir("/proc")`, which hidden-pid sweepers (`chkproc`, `unhide`) can flag. `--stealth` detects this mount and keeps the tree dumpable unless `--hide-pid` is explicitly requested.

**How to eliminate the same-uid `EACCES` signal:** Move the payload across a real host uid or VM boundary:

- Run `pmaskd` under a dedicated service account (different host uid from the observer), or
- Run the workload inside a separate host account / microVM.

When the observer has a different host uid, Linux naturally denies restricted `/proc` files through standard cross-uid permissions without an anomalous same-uid `EACCES` mismatch.

> **Linux `CLONE_NEWUSER` note (`--profile tee`):** In `--profile tee`, `pmask` creates unprivileged user/PID/mount namespaces (with private `/proc` and `/tmp`) to isolate the **host from the payload**, and applies `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `MADV_DONTDUMP`, staged `--rexec-mode=auto`, and default `cwd=/`. However, Linux `security/commoncap.c:cap_capable()` unconditionally grants the user-namespace creator's host uid `CAP_SYS_PTRACE` over the child user namespace (even when `newuidmap` maps the child to a subuid). As a result, same-uid host observers still receive `EACCES` on `mem`, `environ`, `auxv`, and `fd` (via `root:root` VFS DAC), while `exe` (staged path), `maps`, `cwd` (`/`), and `stat` fields 48-51 remain readable to the creator uid (reported as the `userns_owner_read_bypass` residual by `pmask --audit`). To close all seven surfaces with `EACCES` against a same-uid host observer, use `--profile single` or `--profile tree` (which stay in the host user namespace); for true host-to-payload separation without same-uid `EACCES`, run under a separate host uid (`pmaskd`) or a microVM.

## `--rexec-mode` Carriers (`path`, `tmpfile`, `memfd`, `auto`)

Hiding the real executable path from `/proc/<pid>/exe`, `/proc/<pid>/maps`, and `/proc/<pid>/smaps` requires executing a staged copy (`--rexec`). `pmask` supports four `--rexec-mode` settings:

| carrier | mechanism | `/proc/<pid>/exe` & `maps` | pros | cons |
|---|---|---|---|---|
| `path` (preferred by `auto`) | private `0500` executable named `<sanitized_label>` inside a private `0700` dir (`$XDG_RUNTIME_DIR`, `/dev/shm`, or `/tmp`), unlinked immediately at `PTRACE_EVENT_EXEC` with a `SIGKILL`-safe reaper | private file path (or `EACCES` when non-dumpable); **zero `/memfd:` fingerprint** | passes `INV-4` cleanly with no `memfd:` tell; works where `vm.memfd_noexec` blocks memfd execution; zero `.rt-*` dirs left even on `SIGKILL` | requires a writable, executable mount (`exec`, not `noexec`) |
| `tmpfile` | unnamed `O_TMPFILE` inode on an executable mount executed via `execveat(fd, "", AT_EMPTY_PATH)` | `<mount>/#inode (deleted)` (or `EACCES` when non-dumpable); **zero directory entry, zero `/memfd:` fingerprint** | never links a directory entry on disk (100% immune to `SIGKILL` at any microsecond); ideal for containers and CI runners | requires filesystem `O_TMPFILE` support on a writable `exec` mount |
| `memfd` | `memfd_create` with `F_SEAL_SEAL\|SHRINK\|GROW\|WRITE`, executed via `execveat(AT_EMPTY_PATH)` | `/memfd:<name> (deleted)` (or `EACCES` when non-dumpable) | no staging directory on disk; works with `--image -`, `--image-from-fd`, `--hugetlb` | exposes `/memfd:` fingerprint to readable observers (`INV-4` fails in `single` unless `--allow-memfd`); blocked by `vm.memfd_noexec=2` |

`--rexec-mode=auto` (the default, including under `--stealth`) tries `path` first and falls back to `memfd` only when no writable executable staging directory is available. Use `--no-rexec` to opt out of image staging entirely.

## Container & CI/CD Deployment Guidance

Run `pmask doctor [--json]` in your container or CI image before executing secrets. `pmask doctor` reports:

- **Private-`/proc` userns mount readiness (`tee`):** proves both `CLONE_NEWUSER` and mounting a fresh `/proc` succeed (many container runtimes allow `unshare(CLONE_NEWUSER)` but block mounting `/proc` with AppArmor/seccomp or masked `/proc` subpaths, causing `--profile tee` to fail closed with exit `255`).
- **`O_TMPFILE` exec staging readiness (`--rexec-mode=tmpfile`):** checks whether `$XDG_RUNTIME_DIR`, `/dev/shm`, or `/tmp` is mounted writable + `exec` and accepts `O_TMPFILE`.
- **`/etc/subuid` + `newuidmap` cross-UID readiness:** reports whether unprivileged multi-UID mapping is configured; for zero same-uid `EACCES` in CI, prefer a root-managed `pmaskd --run-as-uid=UID[:GID]` service account.

Decoy `/proc/<pid>/environ` size (when dumpable or inspected via `--allow-dumpable`): `110` bytes as root (`HOME=/root`) or `109` bytes as non-root (`HOME=/tmp`) (`PATH`, `HOME`, `LANG`, `TERM`), truncated to complete entries only if the kernel window is smaller.

## `pmask-audit/1` Invariants (`INV-1` through `INV-10`)

`pmask --audit` (standalone self-audit) and `pmask --audit --pid PID` evaluate ten invariants against a live `/proc/<pid>` snapshot and a bounded full-VMA `/proc/<pid>/mem` scan (up to 64 MiB in 64 KiB chunks). Exit status is `0` when all ten pass and `1` if any fails. Add `--json` for deterministic `pmask-audit/1` JSON output.

| ID | name | what it verifies |
|---|---|---|
| `INV-1` | `no_token_in_proc_surfaces` | The supplied token (or synthetic self-audit token) does not appear in `cmdline`, `comm`, `environ`, `auxv` (including dereferenced `AT_EXECFN`), `exe`, `maps`, `smaps`, `fd`, `cwd`, or `status`. |
| `INV-2` | `no_token_in_mem` | Bounded full-VMA scan of `/proc/<pid>/mem` either returns `EACCES` (`denied_eacces`) or completes with zero matches (`clean`). Fails on `leaked`. |
| `INV-3` | `label_and_cmdline_consistent` | `comm`, `cmdline`, and every thread in `/proc/<pid>/task/*/comm` agree with the expected label; `cmdline` has at most 2 trailing NUL bytes; `/proc/<pid>/stat` `arg_start..arg_end` span does not disagree with `cmdline`. |
| `INV-4` | `exe_and_maps_hidden` | `exe`, `maps`, `smaps`, `auxv` `AT_EXECFN`, and `fd` do not expose `--real-exe`. In `single` profile, also fails if `/memfd:` appears unless `--allow-memfd` is passed. |
| `INV-5` | `no_mask_fingerprint` | In `single` profile: `TracerPid == 0`, `Seccomp_filters <= baseline`, `NoNewPrivs <= baseline`, and no supervisor/payload label-twin parent. Other profiles declare their supervisor residuals explicitly. |
| `INV-6` | `process_shape_and_cwd` | Process shape (`status`, `stat`, `ppid`, `threads`, `fd_count`, `rss_kb`, `starttime`) is readable and `/proc/<pid>/cwd` does not expose `--real-cwd`. |
| `INV-7` | `core_dump_hygiene` | Either `PR_SET_DUMPABLE=0` is active (`dumpable_zero == true`) or `RLIMIT_CORE == 0` (`core_limit_zero == true`), or `limits` is denied to an `other-uid` observer. |
| `INV-8` | `profile_export_clean` | Exporting native `psgen` `schema: 2` JSON from the probed snapshot emits `"schema": 2` and contains zero raw bytes of the secret token or unredacted secret patterns. |
| `INV-9` | `audit_verdict_enforced` | Live target `status` or `cmdline` was actively probed so the exit code reflects a real verdict rather than a vacuous check. |
| `INV-10` | `cross_uid_non_amplification` | Under `--observer other-uid`, verifies the other-uid observer sees neither the secret token nor restricted `/proc` surfaces (`environ`, `auxv`, `mem`). |

Never pass secret tokens on `pmask --audit`'s command line: use `--token-env VAR` (scrubbed immediately) or `--token-fd N`. Raw secret bytes are scrubbed from all report fields and replaced with `memory.token_present` and `memory.token_sha256`.

## Native `psgen` `schema: 2` Export (Zero-Adapter Pipeline)

`pmask` redacts individual processes and process trees; it does not spawn synthetic background processes. Generating matching decoy process populations is the responsibility of `psgen`, which natively consumes the strict `schema: 2` JSON emitted directly by `pmask --profile-json` with zero adapter script.

### Generating a profile

```sh
# From a live masked process (captures 1-level children, parent, and tracer):
pmask --profile-json --pid "$PID" --profile single --label ci-runner > profile.json

# Static template without a live PID:
pmask --profile-json --profile single --label ci-runner > profile.json
```

### Schema (`schema: 2`, strict 18-key contract)

```json
{
  "schema": 2,
  "source": {
    "masker": "pmask",
    "profile": "single",
    "version": "0.3.0",
    "observer_uid": 1000
  },
  "identity": {
    "label": "ci-runner",
    "comm": "ci-runner",
    "argv": ["ci-runner"],
    "cmdline_raw_nuls": 1,
    "pid": 4242,
    "ppid": 1,
    "pgid": 4242,
    "sid": 4242,
    "uid": 1000,
    "gid": 1000,
    "groups": [1000],
    "starttime": 123456,
    "cwd": "",
    "root": "/",
    "exe": "",
    "ns": {}
  },
  "status": {
    "Name": "ci-runner",
    "State": "S",
    "PPid": 1,
    "Uid": "1000 1000 1000 1000",
    "Gid": "1000 1000 1000 1000",
    "Threads": 1,
    "TracerPid": 0,
    "NoNewPrivs": 0,
    "Seccomp": 0,
    "Seccomp_filters": 0,
    "CapEff": "0000000000000000",
    "CapPrm": "0000000000000000",
    "CapBnd": "0000000000000000"
  },
  "stat": {
    "ppid": 1,
    "num_threads": 1,
    "starttime": 123456,
    "vsize": 0,
    "rss": 512,
    "arg_start": 0,
    "arg_end": 0,
    "env_start": 0,
    "env_end": 0,
    "startstack": 0
  },
  "memory": {
    "maps": [],
    "smaps": [],
    "token_present": false,
    "token_sha256": null,
    "token_placements": [],
    "readable_by": ["uid:1000"],
    "denied_by": ["environ", "mem", "maps", "smaps", "auxv", "exe", "fd", "cwd"]
  },
  "fds": [],
  "auxv": {
    "AT_EXECFN": null,
    "AT_PLATFORM": "x86_64",
    "AT_BASE": 0,
    "AT_ENTRY": 0
  },
  "environ": [],
  "environ_raw_len": 0,
  "environ_all_nul": false,
  "task": [
    {"tid": 4242, "comm": "ci-runner", "state": "S"}
  ],
  "syscall": {
    "syscall": "poll",
    "wchan": "do_poll",
    "policy": 0,
    "priority": 20
  },
  "timing": {
    "exec_ms": 0.0,
    "first_conceal_ms": 0.0
  },
  "dumpable": false,
  "children": []
}
```

### Contract guarantees for `psgen`

- **Secret-free by construction (`INV-8`):** Explicit tokens (`--token-env`/`--token-fd`), sensitive environment keys (`SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`, `API_KEY`, `APIKEY`, `PRIVATE_KEY`, `CREDENTIAL`, `AUTH_KEY`), and inline secret patterns (`ghp_`, `github_pat_`, `xoxb-`, `xoxp-`, `AKIA...`, PEM private keys) are scrubbed to `<REDACTED:len=N>` across every field before serialization. `memory` records only `token_present`, optional `token_sha256`, `token_len`, `token_charset`, and `token_placements` (`anon`, `argv`, `environ`, `heap`, `stack`).
- **Strict schema compliance:** Emits numeric `"schema": 2` and zero unknown fields at any nesting level, matching `psgen`'s `Profile::from_json` and `Profile::validate` directly.
- **Label policy:** Both `pmask` and `pmask --audit` reject kernel-thread bracket names (`[...]`) and critical system services (`sshd`, `systemd`, `init`, `cron`, `auditd`, etc.) by default (exit 2) unless `--allow-impersonation` is passed explicitly.

## Residual Risks Table

Every remaining observation channel is accounted for honestly below:

| residual / channel | affected profiles | what leaks or signals | mitigation / boundary |
|---|---|---|---|
| `root` / `CAP_SYS_PTRACE` | all | Full visibility into PIDs, `/proc/<pid>/mem`, `exe`, `maps`, `fd`, and kernel state. | Explicitly out of scope; requires a hardware TEE or separate host/VM. |
| `EACCES` denial signal + zeroed `stat` 48-51 | `single`, `tree` (same-uid observer) | Same-uid reads of `mem`, `environ`, `maps`, `auxv`, `exe`, `fd`, `cwd` return `EACCES`; `stat` fields 48-51 read `0 0 0 0`. | Run `pmaskd` under a dedicated service uid or isolate in a separate host account / microVM. |
| `userns_owner_read_bypass` | `tee` (same-uid host observer) | Linux `cap_capable()` grants the userns creator uid `CAP_SYS_PTRACE` over the child userns, leaving `exe` (staged path), `maps`, `cwd` (`/`), and `stat` 48-51 readable to same-uid host observers while `mem`/`environ`/`auxv`/`fd` stay `EACCES`. | Use `--profile single` or `--profile tree` to deny all seven surfaces under the same uid, or a separate host uid (`pmaskd`) / microVM. |
| `/memfd:` executable path | `single` (if `memfd` fallback/mode), `tree`, `compat` | Readable `exe`/`maps`/`smaps` show `/memfd:<name> (deleted)`. | Use default `--rexec-mode=auto` or `--rexec-mode=path` on an executable mount; `INV-4` flags `/memfd:` in `single`. |
| `ptrace` supervisor & `TracerPid` | `tree`, `tee` (host view), `compat` | Non-zero `TracerPid` and visible parent supervisor (`Threads: 1`). | Use `--profile single` (default under `auto` for native ELFs) for `TracerPid: 0` and zero supervisor; use `--parent-label` in `tree` to avoid label twins. |
| `perf_event_open` | all | Hardware/software performance events and sample profiling when `kernel.perf_event_paranoid` allows same-uid attach. | Blocked for non-dumpable targets on hardened kernels (`perf_event_paranoid >= 2`), otherwise kernel-policy dependent. |
| `bpf` / eBPF tracers | all | `execve` tracepoints, kprobes, LSM hooks capture real arguments and binaries at kernel entry. | Requires `CAP_BPF` / `CAP_SYS_ADMIN` / root; out of scope. |
| `process_vm_readv` / `process_vm_writev` | all | Cross-process memory reads bypass `/proc/<pid>/mem` path checks. | Gated by `PTRACE_MODE_ATTACH_REALCREDS`; blocked for same-uid observers by `PR_SET_DUMPABLE=0` (and by Yama `ptrace_scope >= 1`). |
| `pidfd_getfd` | all | Clones open file descriptors (including `--secret-fd` / `--secret` fds) from another PID. | Gated by `PTRACE_MODE_ATTACH_REALCREDS`; blocked for same-uid observers by `PR_SET_DUMPABLE=0` and Yama. |
| `kcmp` | all | Compares kernel resources (files, VM, fs) between two PIDs. | Gated by `PTRACE_MODE_READ_REALCREDS`; blocked for same-uid observers by `PR_SET_DUMPABLE=0`. |
| `io_uring` | all | Asynchronous kernel submissions do not bypass DAC/ptrace checks on `/proc` or `pidfd_getfd`, but observer-side timing and kernel tracing still apply. | Same DAC and `PR_SET_DUMPABLE=0` boundary; root/kernel tracing out of scope. |
| `userfaultfd` | all | Only operates on fds explicitly handed to another process or via `pidfd_getfd`. | Blocked from cross-process acquisition by `PR_SET_DUMPABLE=0` and Yama. |
| Timing, launch window, and behavioral channels | all | Sub-millisecond exec window for `#!` scripts and `vfork` children; sockets (`/proc/net/tcp`), cgroups, CPU/RSS/IO counters, and audit logs (`type=EXECVE`) for `literal:` args. | Use `--secret-fd` / `--args-from-fd` / `file:` / `agent:` to avoid `argv` secrets, `--strict-exec` to refuse post-exec fallbacks, `--isolate=net` for sockets, and `psgen` for population blending. |
