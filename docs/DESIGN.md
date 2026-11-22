# Design

## The problem, stated exactly

A Linux process publishes three metadata items through `/proc` for its entire lifetime:

- `cmdline`: the NUL-separated `argv` strings.
- `environ`: the NUL-separated `envp` strings.
- `comm`: a 15-byte process name shown by `top` and `htop`.

`cmdline` and `comm` require no permission check, so every local account reads them. `environ`, `exe`, `maps`, `fd/*`, and `cwd` require `PTRACE_MODE_READ_FSCREDS`, which any same-uid process and root pass. Yama restricts `PTRACE_MODE_ATTACH` only and does not block same-uid reads of `environ` or `maps`.

Secrets passed as command-line arguments are the classic exposure. Moving a secret into an environment variable only moves it from one readable `/proc` file to another.

Trusted Execution Environments (TEEs) solve a different problem by protecting memory from the host. TEEs require specialized hardware, firmware, a hypervisor, attestation infrastructure, and often a rewritten workload. On machines without TEEs, `/proc` metadata exposure still leaks tokens.

`pmask` closes this `/proc` disclosure surface and only this surface. `pmask` reduces what `/proc` reveals about a process without changing whether the process exists.

## Trust boundary

`pmask` draws the same boundary for process metadata that a container draws for the filesystem. It protects against other local tenants and casual or automated inspection, not against the host operator.

| adversary | outcome |
|---|---|
| another uid | sees the label in `cmdline` and `comm`, with no real `argv` or `environ` |
| a monitoring agent of the same uid (default) | sees the label, plus `exe`, `maps`, `fd/*`, `cwd`, and `/proc/<pid>/mem` naming the real binary and real strings. Default `--secret` sessions in redaction mode set `PR_SET_DUMPABLE=0`, so those reads return `EACCES` unless `--allow-dumpable` is given |
| a monitoring agent of the same uid, with `--no-dumpable` | sees only the label. `environ`, `maps`, `auxv`, `exe`, `fd`, and `/proc/<pid>/mem` return `EACCES` |
| a monitoring agent of the same uid, with `--stealth` | on `hidepid=0` hosts, gets the label plus `--rexec`, `--watch-rename`, and `--no-dumpable` refusals. On `hidepid=invisible` or `hidepid=ptraceable` hosts, omits `--no-dumpable` so the tree does not become a hidden pid |
| a monitoring agent of the same uid, with `--hide-pid` | cannot list or `stat` the pid in `/proc` on `hidepid=invisible` or `hidepid=ptraceable` mounts. `cgroup.procs`, `cgroup.threads`, `kill(0)`, `pidfd_open`, `sched_getaffinity`, `getpriority`, `prlimit`, and root still see the pid |
| a monitoring agent of the same uid, with `--encrypt-memory` | sees the label. Supervisor at-rest copies are encrypted under a per-session key (in `memfd_secret` when available), and the payload's separate anonymous redaction block is `MADV_DONTDUMP`. Payload heap and stack stay unencrypted |
| a monitoring agent of the same uid, with `--strict-exec` | cannot observe any post-exec disclosure window because `pmask` kills `#!` scripts, `vfork` children, entry-redaction fallbacks, and settled re-execs with `SIGKILL` before they run |
| `ps` output pasted into a ticket or chat | shows only the label |
| root on the host | sees the pid, `exe`, `maps`, open descriptors, cgroups, and process memory through `PTRACE_ATTACH` |
| kernel-level attacker | sees everything |

`pmask` addresses the unprivileged and casual-inspection rows. Root and kernel-level attackers are out of scope by design.

## Non-goals

- Encrypting payload heap or stack memory.
- Making a process invisible to root or changing its pid.
- Defeating a kernel module, a hypervisor, or a host eBPF program.
- Escalating privileges. A traced process cannot gain set-uid privileges, so `sudo` does not elevate under `pmask`.
- Persisting across reboots or daemonizing into init.

## Mechanism

`pmask` runs as a `ptrace` supervisor and parent of the supervised tree. The tracer seizes the child with `PTRACE_SEIZE`, stops the master with `PTRACE_INTERRUPT`, waits for `PTRACE_EVENT_STOP` as the handshake, and writes one byte to a synchronization pipe to release the child. The child never raises `SIGSTOP` because pid 1 inside a new pid namespace discards self-directed job-control stops, which broke the handshake under `--unshare` (issue 4).

### Following the tree

`PTRACE_O_TRACEFORK | TRACEVFORK | TRACECLONE | TRACEEXEC | TRACEEXIT` auto-attaches every descendant and thread. This mechanism covers `fork`, `vfork`, `clone`, `posix_spawn()`, `system()`, `popen()`, double-forking daemons, static binaries, Go runtimes (raw `clone` plus `execve`), and `#!` scripts without `LD_PRELOAD` or any libc dependency in the tracee.

### Zero exposure at exec entry

The tracer keeps each new process under `PTRACE_SYSCALL` from attachment until its first exec settles. At the `execve`/`execveat` entry stop, before the kernel constructs the new process image, the tracer performs four steps:

1. Read the real `argv` and `envp` pointer arrays and strings from the tracee.
2. Write a scratch block at `sp - 4096` in the old image containing the label followed by NUL (clamped to 254 bytes on the entry path in `src/execimg.rs`), plus presentation-sized filler strings for `envp`.
3. Rewrite the old image's inline `argv` array to `[label, empty, empty, ..., NULL]` and rewrite `envp` to presentation-sized fillers (keeping variables named by `--keep-env=NAME`).
4. Resume the tracee into the kernel.

The kernel copies only the label and filler strings into the new ELF image. The real command line never enters the new image, so `/proc/<pid>/cmdline` never exposes it. The child's old image holds the parent's `argv` bytes between fork and this stop, and the kernel never copies those bytes into the new image.

### Restoring real arguments and relocating windows

At `PTRACE_EVENT_EXEC`, the kernel has mapped the new image, but the program has not executed its first instruction. The tracer performs six steps:

1. Read `argc` from the new stack and locate the inline `argv` and `envp` arrays.
2. Inject an anonymous `mmap` in the tracee to build the separate redaction block containing the real `argv` strings, the real `envp` strings, and the `comm` label, 16-byte aligned. Under `--encrypt-memory`, mark this separate anonymous block `MADV_DONTDUMP` (never `[stack]`).
3. Repoint the inline stack `argv` and `envp` arrays at the strings in the anonymous block and verify every write.
4. Overwrite the original visible string region (from `/proc/<pid>/stat` fields 48 to 51) with the label and decoy or kept environment entries.
5. In exact mode (default), place the presentation strings (`label\0`, decoy or kept `environ`, and `label\0` for `AT_EXECFN`) inside the kernel's `[stack]` region (`arg_end == env_start`, `start_stack < arg_start`, `[stack]` VMA intact). Call `prctl(PR_SET_MM, PR_SET_MM_MAP)` to point the kernel's `arg` and `env` windows at that `[stack]` presentation, and rewrite `AT_EXECFN` in both `saved_auxv` and the stack auxiliary vector. Fall back to placing the presentation inside the anonymous redaction block only when the `[stack]` region is too small.
6. Inject `prctl(PR_SET_NAME)` and, when `--no-dumpable` is active, `prctl(PR_SET_DUMPABLE, 0)` through a `syscall` instruction inside the tracee, then restore registers and resume.

`argc`, inline array positions, and auxiliary vector structure remain intact. glibc, musl, and static runtimes cache `argv` and `environ` from the stack at startup and see their real values.

If any repoint write fails, the tracer zeroes the entire visible region instead. The worst visible result is empty strings, and the session summary counts the exec as `unredacted`.

### Scripts, vfork children, re-execs, and foreign images

The kernel requires the real `argv` to parse `#!` interpreter lines, and a settled process no longer stops at syscall entry. Both cases take the post-exec path. The kernel briefly copies the real interpreter command line and environment (unless `--keep-env`), and the completion stop overwrites that region. Run `tests/compare.sh` to measure the post-exec window on your host.

A `vfork` child also takes the post-exec path. Because a `vfork` child shares its parent's address space until exec, an entry swap would corrupt parent memory (measured with `gcc` invoking `cc1` via `clone3(CLONE_VM|CLONE_VFORK)`, which crashed `gcc` in `free()`). The `vfork` child runs unswapped and is redacted at completion.

Pass `--strict-exec` to refuse every post-exec shape instead of allowing a disclosure window. Under `--strict-exec`, the tracer kills `#!` scripts, `vfork` children, entry-redaction fallbacks (`write_mem`, scratch, or overflow failures), and settled re-execs with `SIGKILL` (exit 137) and prints `pmask: refused:` even under `-q`. `--strict-exec` also refuses `--detach`.

32-bit (foreign-ABI) images cannot be redacted by a 64-bit tracer. The tracer reads `EI_CLASS` at entry (resolving `/proc/self/` and `/proc/thread-self/` against the tracee pid), kills the 32-bit exec with `SIGKILL` by default, prints one warning, and counts it as `foreign-refused`. Pass `--allow-foreign` to run a 32-bit image unredacted (counted as `foreign-arch`). Any later exec by that tracee is still refused.

When a non-leader thread calls `execve`, the kernel resets its tid to the thread-group leader before `PTRACE_EVENT_EXEC`. The tracer reads the former tid with `PTRACE_GETEVENTMSG` and transfers entry-stop bookkeeping to the leader.

### Process name and `--watch-rename`

The tracee executes `prctl(PR_SET_NAME)` itself. The tracer points the instruction pointer at a `syscall` instruction inside the tracee's vDSO and single-steps it. `pmask` never maps writable-and-executable memory and makes no assumptions about libc. If the vDSO lacks a usable syscall instruction, the tracer scans the first executable mapping and fails loudly if none is found.

`--watch-rename` installs a seccomp filter that traps:

- `prctl(PR_SET_NAME)`.
- `open`, `openat`, `openat2`, and `creat` (on architectures that provide `SYS_creat`) targeting `/proc/.../comm` in write mode. The tracer resolves `dirfd` or tracee `cwd` and applies lexical path normalization (collapsing repeated `/`, `.`, and `..`) before checking the target path.
- Under `--watch-rename=strict`, `write`, `writev`, `pwrite64`, `pwritev`, and `pwritev2`. The tracer resolves `/proc/<pid>/fd/<fd>` with `readlink` to catch symlink aliases and descriptors passed over `SCM_RIGHTS`.

If installing the rename filter fails, the child exits 126 naming the error rather than running unprotected. Because a seccomp filter cannot be removed, `--watch-rename` refuses `--detach` and `--on-exit detach` (and defaults to `WaitTree` in the CLI). If `readlink` fails with `EACCES` on a non-dumpable tracee during open or strict-write checks, the tracer emits a visible warning rather than failing open silently.

On a trapped `prctl(PR_SET_NAME)`, the tracer redirects the name pointer to the label already stored in the tracee's presentation block (`Tracee::rename_addr`). Redirecting to an existing address avoids `process_vm_writev` and `PTRACE_POKEDATA`, which fail on non-dumpable tracees for unprivileged tracers (issue 60). If the label address is unavailable or unreadable, the tracer tries writing below the stack pointer. If that write also fails, the tracer points the argument at an unmapped address (`1`) so `PR_SET_NAME` returns `EFAULT`, `comm` keeps the label, and the session counts `rename_refused`.

### The supervisor's own entry

Because the supervisor lives as long as the tree, it redacts its own `/proc` entry before forking:

1. Snapshot the child's `argv` and environment.
2. Zero the supervisor's kernel `argv` block and write the label.
3. Replace the supervisor's visible environment with the decoy and relocate its windows with `PR_SET_MM_MAP`.
4. Set the supervisor's `comm`.
5. Scrub the supervisor's at-rest copies after fork.

By default, the supervisor stays dumpable at rest so it does not become a hidden pid on `hidepid=invisible` hosts. `--no-dumpable`, `--hide-pid`, `--encrypt-memory`, `--secret`, `--report`, and `PMASK_NO_SELFMASK=1` pin the supervisor non-dumpable (`PR_SET_DUMPABLE=0`). Plain runs without secrets restore the caller's original `argv`. Non-plain runs zeroize `original_argv` immediately.

If `PR_SET_MM_MAP` is refused on the supervisor, the label stays in place at the original extent, one note prints, and the session does not count it as a tree degradation.

The tracer runs on a second thread of the supervisor (`src/mask.rs`), so each payload's `TracerPid` names a thread whose `Tgid` is the supervisor pid. The thread's `/proc/<supervisor>/task/<tid>/comm` takes the session `comm` first and the label second (clamped to 15 bytes), never the retired string `pmask-tracer` (issue 38). `Tgid != Pid` and nonzero `TracerPid` remain visible unless `--detach` is used.

### Labels and non-redacting modes

A label applies only where `/proc` is redacted. `--isolate` places the payload in fresh namespaces without redacting the payload's `argv`, `environ`, or `comm`. When a label is given in isolate mode, the supervisor masks its own entry and prints a note stating that isolate mode did not apply the label to the payload.

`--redact --isolate=LIST` composes both features: the tracer supervises the tree while the child enters the exact namespaces in `LIST`. Unavailable namespaces are reported as degradations, never silently substituted. `--no-redact --isolate` runs isolate mode without `ptrace`. `--isolate=none` disables namespaces, `no_new_privs`, and Landlock while keeping the redaction path. Plain mode applies no label.

In `--daemon` mode, the client refuses `--isolate`, `--secret`, `--no-redact`, `--hide-pid`, `--encrypt-memory`, `--image`, `--image-from-fd`, and `--report*` because the daemon owns policy and environment construction.

### Job control

Because the supervisor seizes tracees, group-stops arrive as `PTRACE_EVENT_STOP`. The tracer answers group-stops with `PTRACE_LISTEN`, keeping the tracee stopped while allowing `SIGCONT` and parent job control to work normally. `kill -STOP` pauses a masked tree and `SIGCONT` resumes it.

### The exec seccomp filter and who may carry it

An unserviced `SECCOMP_RET_TRACE` stop makes `execve` return `ENOSYS` in any surviving process. Therefore, `pmask` installs the exec-shaped seccomp filter only when the tracer is guaranteed to outlive every tracee carrying it.

That `--exec-once` fast path requires all of these conditions:

- `--on-exit wait` or `--on-exit kill` (not `detach`).
- No `--detach`, tree following enabled, no `--unshare`, no namespace set, and no `--run-as`.
- `PTRACE_O_EXITKILL` enabled, so unexpected tracer death kills the tree.

All other configurations use `PTRACE_SYSCALL` supervision (two stops per syscall until a process's first exec settles, zero stops afterward). The exec filter is installed once per tracee at its first completion stop (before `PR_SET_DUMPABLE=0`) and inherited by children.

A `CLONE_THREAD` newcomer shares its group's settled state and starts in `State::Run` rather than `State::Slow`, avoiding syscall-stop overhead in multithreaded runtimes. A forked child starts in `State::Slow` so its first exec takes the entry-swap path.

### Session end

When the master process exits, the tracer enforces the configured session-end policy:

| policy | behaviour |
|---|---|
| `detach` (default) | detaches every settled descendant with `PTRACE_INTERRUPT` and `PTRACE_DETACH`. Descendants waiting for their first exec get a one-second grace period before detaching |
| `wait` | keeps supervising until the last descendant exits |
| `kill` | sends `SIGKILL` to every remaining tracee |

Detached descendants keep their label and redacted image, but later forks and execs run unredacted. `PTRACE_O_EXITKILL` is enabled by default so supervisor death kills the tree. `--no-exit-kill` disables it.

### Session summary

The tracer counts execs and degradations and prints a summary at session end unless `-q` is set. (`--audit` always prints `pmask audit: residue: N (...)`, even under `-q`.)

```
pmask: N of M execs degraded (post-exec, reexec x2, foreign-arch)
```

Every item in that line names a degradation. Only `unredacted` indicates that real strings may have remained visible. The exact reason tags from `src/tracer.rs` are:

- `post-exec` (from `stats.script`): `#!` scripts, `vfork` children, or `--no-exact` execs redacted at completion.
- `reexec`: settled processes that re-executed on the post-exec path.
- `unredacted`: execs where completion redaction failed.
- `comm-not-set`: execs where `PR_SET_NAME` injection failed.
- `foreign-arch`: 32-bit images allowed to run unredacted via `--allow-foreign`.
- `foreign-refused`: 32-bit images refused and killed with `SIGKILL`.

Additional independent lines print whenever their condition or counter is non-zero:

- `hide_pid` active: `pmask: hide-pid: the tree is non-dumpable; same-uid /proc readers cannot see it. cgroup.procs/cgroup.threads, kill(0), pidfd_open, sched_getaffinity/getpriority/prlimit and root still can.`
- `vfork_cache_skipped > 0`: `pmask: N vfork child(ren) took the post-exec path; the --exec-once cache tag is not applied there`
- `foreign_refused > 0`: `pmask: N 32-bit (foreign ABI) exec(s) refused; a 32-bit image cannot be redacted, so it is not run unless --allow-foreign is set`
- `sized_skipped > 0`: `pmask: N of M execs kept the kernel's argv and environ windows (PR_SET_MM_MAP refused)`
- `detached > 0`: `pmask: N tracee(s) left detached after their exec (--detach: their later execs are not redacted)`
- `dumpable_failed > 0`: `pmask: N tracee(s) stayed dumpable (PR_SET_DUMPABLE refused); --hide-pid is not active for them`
- `dontdump_failed > 0`: `pmask: N redaction block(s) could not be marked MADV_DONTDUMP; a core dump could include the block`
- `secret_close_failed > 0`: `pmask: N secret descriptor(s) could not be closed in a descendant`
- `rexec_fallback > 0`: `pmask: N --rexec fallback step(s) taken (K used the on-disk last resort)` (where `K` is `rexec_disk`)
- `rename_refused > 0`: `pmask: N rename(s) refused because the label address was not available (comm kept the label)`

All counters are also exposed in `ExitState::stats`.

## The daemon

`pmaskd` holds job secrets outside the CI runner so tokens never appear in the runner's `argv` or environment.

### Protocol

Each connection sends one request and runs one job.

Client to daemon, with `SCM_RIGHTS` passing stdin, stdout, and stderr:

```
1 byte   version (2)
"PMK2"   u8 label_mode  u32 label_len  label
         u32 argc       argc * (u32 len, bytes)
```

The first byte is the protocol version. Clients sending `'C'` from protocol v1 are rejected with "protocol mismatch". `label_mode` is `0` (daemon label), `1` (empty label), or `2` (explicit label text).

Daemon to client:

```
i32 exit_code  u32 has_signal  i32 signal  u32 msg_len  msg
```

A PING sends the four bytes `PMKP` in place of a job frame. The daemon replies with a response frame containing `key=value` lines after performing the same uid authorization check. The daemon's own uid and root receive the full status body: protocol version, label, uid, `run_as_uid`, job slots, environment count, allowed uids, socket mode, I/O and job timeouts, job-argv cap, peer identity method, and peer uid. Other uids permitted by `--allow-uid` receive only protocol version, label, daemon uid, `run_as_uid`, and `detail=reduced`, with policy fields omitted from the wire. PING never discloses environment values.

Protocol limits (little-endian integers): `argc <= 4096`, each argument `<= 1 MiB`, total request `<= 8 MiB`, label `<= 4096` bytes with no NUL, LF, or CR, and total job argument bytes (`len + 1` sum) `<= 1 MiB` (`--max-job-bytes`). The daemon requires exactly three file descriptors and rejects truncated control messages.

### Authorisation

`pmaskd` checks `SO_PEERCRED` on every accepted connection. By default it authorizes only its own uid and root. `--allow-uid` adds uids. The socket defaults to mode `0600` (`--socket-mode` overrides), and the client checks the server's peer uid.

`pmaskd` pins the peer identity established at `accept`. On Linux 6.5 and newer, `pmaskd` uses `SO_PEERPIDFD` to pin a pidfd and re-checks the peer before starting the job (including the pidfd identity inode via `statx` on Linux 6.9 and newer). On older kernels, `pmaskd` falls back to checking the peer pid and `/proc/<pid>/stat` start time on a best-effort basis.

Any allowed uid can execute arbitrary programs with the daemon's privileges and environment. On a root daemon, pass `--run-as-uid` to drop each job to the client's uid and gid.

### Socket safety

`check_socket_dir` validates the parent directory on every startup. If missing, it creates the directory with mode `0700`. It opens the directory with `O_DIRECTORY | O_NOFOLLOW` and verifies ownership by the effective uid and no group or other write permissions. Newly created directories must have mode `0700`; pre-existing directories may allow read/execute (such as `/run` at `0755`). Any failure refuses startup to prevent socket substitution races. Removal uses the pinned directory descriptor.

Before removing an existing path, `pmaskd` opens it with `O_PATH | O_NOFOLLOW` so symlinks and non-sockets are never followed or unlinked. `pmaskd` attempts to connect first: if a live daemon responds, startup fails. Only after `ECONNREFUSED` and confirming the pinned descriptor is a socket owned by the current uid does `pmaskd` unlink it. `pmaskd` binds under `umask 077`, verifies ownership with `lstat`, applies the socket mode (default `0600`), and re-verifies identity.

The default socket path is `$XDG_RUNTIME_DIR/pmask.sock` when that directory is owned by the effective uid and not writable by group or other, or `/run/pmask.sock` for root. Otherwise `--socket` is required; there is no `/tmp` fallback.

### Timeouts and concurrency

`--io-timeout` drops clients that stall while sending requests or reading responses. `--job-timeout` kills jobs that exceed the limit and returns exit code 137.

Because a masking session owns `waitpid(-1)`, the library serializes sessions with a process-wide mutex. `pmaskd` serves one job at a time by default; `--jobs N` spawns a worker process per job up to `N` concurrent jobs.

### Secret handling

`pmaskd` hardens itself (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`) before loading `--env-file`, keeps the job environment in `mlock`-protected memory, and wipes the store on `SIGTERM` or `SIGINT`. `--no-inherit-env` restricts the job environment strictly to `--env-file`.

The CLI also supports daemon-free delivery via `--secret NAME=SRC`. `pmask` hardens itself before loading secrets or passphrases, places each value in a sealed memfd at fd 3, 4, ..., and sets `PMASK_SECRET_<NAME>=<fd>`. Supported sources are `file:PATH`, `env:VAR`, `agent:NAME`, `stdin`, and `literal:VAL` (a bare value is a literal). Inside the payload, `pmask read NAME` reads the value.

Secret descriptors clear `FD_CLOEXEC` so the payload can read them after exec. In redaction mode, `--secret` makes the payload non-dumpable by default (`--allow-dumpable` opts out) so same-uid peers cannot read `/proc/<pid>/fd/N`. `--secret-close-on-exec` injects `close(2)` in each direct child at fork while leaving the descriptor open in the payload. Children created with `clone(CLONE_FILES)` without `CLONE_THREAD` share the payload's descriptor table, so closing is skipped, warned, and counted. Plain and isolate modes refuse `--secret-close-on-exec`. `--detach` warns and counts unclosed descriptors because no tracer remains after the payload execs.

`--secret-burn` seals the memfd without `F_SEAL_SHRINK`, letting a cooperating reader truncate it once without regrowth. `literal:` and `env:` sources sit in `pmask`'s `argv` or `environ` before self-masking and are refused in non-redacting modes unless `--allow-argv-secret` is set. `pmask agent` holds the encrypted store unlocked in a separate process and serves `GET <name>` over a Unix socket, keeping plaintext out of the invoking process.

Both memfd families publish a name in `/proc`. Secret descriptors default to `/memfd:pmask-secret (deleted)` (`--secret-fd-name NAME` overrides). Image memfds for `--rexec`, `--image`, `--image-from-fd`, `--exec-once`, and `--hugetlb` default to the label or program name (`--memfd-name NAME` overrides both the memfd and the `--exec-once` carrier tag). Both options share one validator: 1 to 200 bytes, no `/`, no control bytes, and no DEL. These options are cosmetic and change only the displayed name.

## Privilege ladder

Higher privileges provide stronger isolation in defined steps.

| rung | requirement | what it adds | limit |
|---|---|---|---|
| 0 | none | entry swap, label, `comm`, per-variable environment policy | same-uid observers still read `exe`, `maps`, `fd/*`, and `cwd` |
| 0 + `--no-dumpable` | none | `PR_SET_DUMPABLE=0` blocks same-uid reads of `environ`, `maps`, `auxv`, `exe`, `fd`, and `mem` | disables core dumps and debugger attach |
| 0 + `--rexec` | none | `/proc/<pid>/exe` names the memfd rather than the on-disk binary. Falls back through `/proc/self/fd/N` and temporary files. `--memfd-name NAME` changes the name | `/proc/<pid>/map_files` still resolves. `vm.memfd_noexec` may block memfd execution. On-disk fallback requires `--rexec-allow-disk` |
| 0 + `--unshare` | unprivileged user namespaces | private PID namespace and private procfs | unavailable where user namespaces are restricted. Opportunistic by design |
| 0 + `--watch-rename` | none | keeps `comm` at the label across self-renames, including under `--no-dumpable` | traps `prctl(PR_SET_NAME)` and `open`/`openat`/`openat2`/`creat` on `/proc/.../comm` (plus write syscalls under `=strict`). Implies `no_new_privs` and refuses `--detach`/`--on-exit detach` |
| 0 + `--scope-name` | user systemd manager | consistent unit name in `/proc/<pid>/cgroup` and `systemctl` | unit name is world-readable. System scopes need root or polkit |
| 0 (default; `--no-exact` disables) | none | `prctl(PR_SET_MM, PR_SET_MM_MAP)` points `arg_start`/`arg_end` and `env_start`/`env_end` at the presentation inside `[stack]` (`arg_end == env_start`, `start_stack < arg_start`, `[stack]` VMA intact, falling back to the anonymous block only if `[stack]` is too small) and rewrites `AT_EXECFN` in `saved_auxv` and the stack vector | unavailable without `CONFIG_CHECKPOINT_RESTORE` or when seccomp blocks `prctl`. `--no-exact` fills the original extent with spaces and a decoy environment |
| 0 + `--detach` | none | `PTRACE_DETACH` after settled exec sets `TracerPid` to 0 | detached processes and descendants run unredacted at later execs. Counted in summary |
| 2 | `CAP_SYS_RESOURCE` | bare `PR_SET_MM_ARG_START`/`_ARG_END` operations | unused. One-shot `PR_SET_MM_MAP` achieves the same result at rung 0 |
| 3 | root on the host | `hidepid=2,gid=` on system `/proc` hides the tree from other accounts | conflicts with some polkit/distro defaults. Yama scope needs `CAP_SYS_PTRACE`, and scope 3 lasts until reboot |

## Failure modes and behaviour

| failure | behaviour |
|---|---|
| exec fails inside child | restores original inline arrays, keeps syscall supervision, exits 127 (`ENOENT`) or 126 |
| supervisor killed | `PTRACE_O_EXITKILL` kills the tree so no half-masked orphans survive |
| tracee dies mid-injection | drops tracee from table and continues supervising the tree |
| failure after visible spans are known | zeroes visible `argv` and `environ`, prints a warning, counts `unredacted` |
| 32-bit image | kills the exec with `SIGKILL`, prints a warning, counts `foreign-refused`. With `--allow-foreign`, runs unredacted and counts `foreign-arch` |
| no syscall site at descendant fork | leaves secret descriptors open, warns with pid, counts `secret_close_failed` |
| daemon job fails | returns exit status to client and keeps serving |
| stale daemon socket | tests with `connect()` first. Live daemon refuses startup; `ECONNREFUSED` unlinks the pinned socket |

Every failure that degrades confidentiality prints a warning at default verbosity and records a summary count. `tests/core.sh` exercises repoint failures via `PMASK_FAULT_POKE` and missing syscall sites via `PMASK_FAULT_NOVDSO`.

## Kernel-consistency claim

The kernel never receives the real `argv` of a masked ELF exec. Two kernel observers read the command line, and execution order determines what each sees:

- `audit_log_execve_info()` reads from `current->mm->arg_start` at syscall exit, after `PTRACE_EVENT_EXEC` and window relocation have completed. Therefore, the audit record receives the label. Because the audit reader walks `bprm->argc` NUL-terminated strings from `arg_start` and sends `SIGKILL` on `-EFAULT`, the presentation block provides `label\0`, the decoy environment, and the second label copy so the audit reader sees only the label and decoy entries, never real arguments.
- An eBPF `sched_process_exec` tracepoint fires before `PTRACE_EVENT_EXEC`, carrying only `bprm->filename` and two pids. It never sees `argv`, and no userland action changes that tracepoint.

`tests/audit.sh` verifies the audit record as root on hosts where the audit control plane is accessible.
