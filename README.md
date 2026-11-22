# pmask

**Confidential execution without trusted hardware.** Run a command, binary, or job so other local users and pasted `ps` output cannot read its command line or environment. Every program keeps its real arguments and environment and runs normally. A same-uid monitoring agent still reads `exe`, `maps`, `fd/*`, and `cwd` unless you set `--no-dumpable`.

```sh
pmask --label ci-runner ./deploy.sh --env prod
```

`ps`, `top`, `htop`, `/proc/<pid>/cmdline`, and `/proc/<pid>/comm` display `ci-runner` for that process and every process it spawns. `/proc/<pid>/environ` displays a plausible decoy environment (110 bytes by default, or the variables named by `--keep-env`). The program still reads its own `argv`, its own environment, its own stdin, and its own exit code.

## Why

Confidential computing usually requires a Trusted Execution Environment (TEE) such as AMD SEV-SNP, Intel TDX, ARM CCA, or SGX enclaves. TEEs protect memory against the host. They also require specialized hardware, a hypervisor or guest OS that can launch and attest, an attestation service, and a trust policy. Enclave models often require a rewritten workload.

Most machines lack TEE hardware. A self-hosted CI runner, a shared build host, a lab box, a container, a laptop, or a VPS has no TEE. Secrets still have to run on these machines.

The primary leak in those environments is `/proc`, not memory:

```sh
$ ps -eo user,args | grep deploy
ci     ./deploy.sh --token ghp_9f3c... --env prod
```

CI vendors document this exact hazard. Other local users read command-line arguments through `ps`, and audit subsystems capture them in exec events. MITRE ATT&CK T1036.011 ("Overwrite Process Arguments") catalogs these mechanics.

`pmask` closes this `/proc` disclosure surface on standard Linux hardware as an unprivileged user.

## What pmask is not

`pmask` is not a TEE and does not encrypt payload memory. The limit table defines the exact trust boundary:

| observer | sees |
|---|---|
| another uid | the label in `cmdline` and `comm`, with no real `argv` or `environ` |
| a monitoring agent of the same uid | the label, plus `exe`, `maps`, `fd/*`, and `cwd` (naming the real binary), plus the real `argv` and environment in `/proc/<pid>/mem`. A `--secret` run in redaction mode is non-dumpable by default, so `/proc` refuses those reads (`EACCES`) |
| a monitoring agent of the same uid, with `--no-dumpable` | the label. `environ`, `maps`, `auxv`, `exe`, `fd`, and `/proc/<pid>/mem` return `EACCES`, and those six refusals are themselves a signal |
| a monitoring agent of the same uid, with `--stealth` | on a `hidepid=0` host, the label and the `--no-dumpable` refusals (including `exe`, so only root sees `/memfd:<label>`). On `hidepid=invisible` or `hidepid=ptraceable`, the tree stays dumpable to avoid creating a hidden pid, so same-uid `environ` and memory reads stay open |
| a monitoring agent of the same uid, with `--hide-pid` | the pid disappears from same-uid `/proc` `readdir` and `stat` when `/proc` uses `hidepid=invisible` or `hidepid=ptraceable`. On `hidepid=ptraceable`, an existing inode returns `EPERM`, which is a visible signal. `cgroup.procs`, `cgroup.threads`, `kill(0)`, `pidfd_open`, `sched_getaffinity`, `getpriority`, `prlimit`, and root still see the pid |
| a monitoring agent of the same uid, with `--encrypt-memory` | the label. The supervisor seals its at-rest `argv` and environment with a per-session key in `memfd_secret` memory when available. The payload's redaction block stays anonymous and `MADV_DONTDUMP`, avoiding a `/secretmem` VMA fingerprint. The payload's heap and stack remain unchanged |
| `ps` output pasted into a ticket or chat | the label |
| root on the host | **that** a pid exists, its `/proc/<pid>/exe`, its `maps`, its open files, its cgroups, and its memory via `PTRACE_ATTACH` |
| anyone with kernel access | everything |

Network identity is outside the mask. `ss -tnp`, `lsof`, and `/proc/net/tcp` still report the real pid, uid, inode, and descriptor, while showing the label as the process name. Use `--isolate=net` to place the payload in a private network namespace and keep its sockets out of the host socket table. The private namespace requires its own connectivity.

`cmdline` and `comm` require no ptrace check, so every local account reads them. `environ`, `exe`, `maps`, `fd/*`, and `cwd` require `PTRACE_MODE_READ_FSCREDS`, which a same-uid process passes. Yama restricts `PTRACE_MODE_ATTACH` only and does not block same-uid reads. `PR_SET_DUMPABLE=0` blocks those same-uid reads.

After forking the child, the supervisor scrubs the real `argv` and environment from its own memory. Because the supervisor holds no plaintext at rest, it stays dumpable by default. Staying dumpable prevents the supervisor from becoming a hidden pid on a `hidepid=invisible` host. `--no-dumpable` extends `PR_SET_DUMPABLE=0` to the payload and pins the supervisor non-dumpable. A plain run without secrets holds no secret, does not mask itself, reports `mode=plain`, and runs as an ordinary process of the caller's uid. A plain run with a secret makes itself non-dumpable before loading the secret, but does not mask its own `/proc` entry.

`pmask` provides confidentiality against other local tenants and casual inspection, not against the host operator. That trust boundary matches what a container provides for the filesystem, applied to process metadata. An adversary with root on the same kernel requires a TEE or a separate machine.

Run `pmask probe` to report each host mechanism as `active`, `degraded`, or `unavailable`, along with its absence cost and a final `tier=` word. Run `pmask doctor --require redact,exact` to exit 0 when both mechanisms are active, 3 when one is degraded, and 4 when one is unavailable. CI jobs can assert on the host posture before running secrets.

## Three ways to use pmask

### 1. CLI: run one command under a label

```sh
pmask --label 'ci-runner' ./deploy.sh --token "$TOKEN" --env prod
```

Every descendant of the command inherits the label. Wrap a full shell session once, and background jobs survive when the shell exits:

```sh
exec pmask --label 'dev-shell' bash --login -i
```

Key options:

| option | effect |
|---|---|
| `-l, --label NAME` | sets the presented `cmdline` and `comm` |
| `--comm NAME` | sets a `comm` separate from the label, up to 15 bytes |
| `--argv0 NAME` | sets `argv[0]` of the program. Defaults to the command as typed |
| `--keep-env` | leaves `environ` visible in full, values included. A later `--keep-env=NAME` narrows visibility to the named variables. Takes no value, so `--keep-env NAME -- CMD` treats `NAME` as the program and warns when `NAME` looks like a variable list |
| `--keep-env=NAME` | keeps only the named variables visible in `/proc/<pid>/environ`, repeatable. The environment window starts at `arg_end` and holds each named entry once without repetition |
| `--env K=V`, `--env-file PATH` | sets variables in the child environment |
| `--args-from-fd N` | reads a NUL-separated command vector (up to 8 MiB) from fd `N`, keeping secrets off the supervisor's command line. `pmask` reads a duplicate descriptor, so the caller's descriptor stays open and `--args-from-fd 0` preserves stdin. The source offset advances to the end of the vector |
| `--on-exit detach\|wait\|kill` | selects how `pmask` handles surviving descendants when the master command exits |
| `--detach` | calls `PTRACE_DETACH` on each process after its exec settles, setting `TracerPid` to 0. Detached processes are not followed, so their future forks and execs run unredacted |
| `--no-exact` | leaves the kernel's `argv` and `environ` windows in place instead of relocating them. The completion stop overwrites the original extent with the label padded by spaces and one final NUL, and fills `environ` with a complete non-repeating decoy environment (or the `--keep-env` variables) |
| `--no-dumpable` | sets `PR_SET_DUMPABLE=0` in every tracee and pins the supervisor non-dumpable. Same-uid observers receive `EACCES` on `environ`, `maps`, `auxv`, `exe`, `fd`, and `/proc/<pid>/mem`. Active by default for `--secret` runs in redaction mode (`--allow-dumpable` opts out). Plain and isolate modes note that they cannot apply the flag. `--hide-pid` and `--encrypt-memory` also pin the supervisor non-dumpable |
| `--allow-dumpable` | keeps the payload dumpable during a `--secret` run. Same-uid descriptor and memory reads remain open |
| `--strict-exec` | refuses exec shapes that cannot be redacted at syscall entry: `#!` scripts, `vfork` children, entry-redaction fallbacks, and settled re-execs. Also refuses `--detach`. Kills the refused process with `SIGKILL` (exit status 137) and prints `pmask: refused:` naming the shape even under `-q` |
| `--hide-pid` | hides the tree's pids from same-uid `/proc` readers. Opt-in only. Requires `/proc` mounted with `hidepid=invisible` or `hidepid=ptraceable` and refuses weaker mounts. On `hidepid=ptraceable`, an existing dentry returns `EPERM` instead of `ENOENT`. `cgroup.procs`, `cgroup.threads`, `kill(0)`, `pidfd_open`, `sched_getaffinity`, `getpriority`, `prlimit`, and root still see the pid. Refused with `--no-follow`, `--detach`, and `--exec-once`. A descendant detached by the default `--on-exit detach` stays hidden only until its next exec resets `PR_SET_DUMPABLE` |
| `--encrypt-memory` | seals the supervisor's at-rest `argv` and environment copies with XChaCha20-Poly1305 under a per-session key in `memfd_secret` memory when available. Marks the payload's separate anonymous redaction block `MADV_DONTDUMP` (not `memfd_secret`, avoiding a `/secretmem` VMA). Opt-in only. Does not encrypt the payload's heap or stack |
| `--stealth` | composes `--rexec`, `--watch-rename`, and `--no-dumpable` on non-`hidepid` hosts. On `hidepid=invisible` or `hidepid=ptraceable` hosts, omits `--no-dumpable` so the tree does not become a hidden pid. Prints the chosen trade. Refused with `--exec-once` on non-`hidepid` hosts because `--no-dumpable` conflicts with `--exec-once` |
| `--allow-foreign` | runs a 32-bit image unredacted. By default, `pmask` refuses 32-bit images because they keep their real `cmdline`, `environ`, and `comm` |
| `--no-new-privs` | sets `PR_SET_NO_NEW_PRIVS` before exec so set-uid binaries and file capabilities gain nothing |
| `--watch-rename` | keeps the label when a program renames itself. The seccomp filter traps `prctl(PR_SET_NAME)` plus `open`, `openat`, `openat2`, and `creat` (where supported) targeting `/proc/.../comm` after lexical path normalization. `--watch-rename=strict` also traps `write`, `writev`, `pwrite64`, `pwritev`, and `pwritev2` to check descriptor targets, catching symlink aliases and `SCM_RIGHTS` descriptors at the cost of one stop per write. Waits for the tree by default. Refuses `--detach` and `--on-exit detach` (exit 255). Warns if `readlink` fails with `EACCES` on a non-dumpable tracee |
| `--rexec` | runs from a sealed memfd so `exe` names the label. Falls back in order to `/proc/self/fd/N`, then an `O_TMPFILE` or named temporary file on an executable mount, reporting each failed step. Fails closed with exit 126 (or 127 if the source is missing) unless you pass `--rexec-allow-disk` |
| `--rexec-allow-disk` | enables the on-disk path as an explicit last resort in the `--rexec` carrier chain. Never automatic |
| `--image PATH` | reads program bytes from `PATH` (or `-` for stdin) and executes them from a sealed image. Implies `--rexec` |
| `--image-from-fd N` | reads program bytes from descriptor `N`. Implies `--rexec` |
| `--exec-once` | caches one sealed image per distinct program, keyed by resolved path, device/inode/ctime, and mtime. Later execs use a guarded temporary-file carrier verified by inode and bytes before every reuse. Kills the exec if the carrier was replaced. Resolves `/proc/self/exe` in the tracee, not the supervisor. Refused with `--no-dumpable`, `--hide-pid`, `--stealth` (on non-`hidepid` hosts), and default non-dumpable `--secret` runs. Implies `--rexec` |
| `--hugetlb` | requests a hugetlbfs-backed image and reports the backing. Falls back to an ordinary memfd on any source (including `--image -`) if the huge-page pool fails. Implies `--rexec` |
| `--unshare` | creates private user, pid, and mount namespaces with a private procfs when the kernel allows it |
| `--isolate[=LIST]` | creates fresh user, mount, UTS, IPC, and cgroup namespaces plus the `pid`, `net`, and `tmp` axes named in `LIST` (default `all`). `--isolate=none` disables all isolation (no namespace, no `no_new_privs`, no Landlock). The private `/dev` binds `/dev/pts` and `/dev/ptmx` and creates a private `/dev/shm` when available |
| `--no-redact` | skips all `/proc` metadata redaction, even when `ptrace` is available |
| `--scope-name NAME` | wraps the run in a transient systemd scope named `NAME` |
| `--secret N=SRC` | delivers a secret on descriptor 3, 4, ... and sets `PMASK_SECRET_<NAME>=<fd>` in the child environment |
| `--secret-burn` | allows a cooperating reader to truncate the secret memfd once and prevents regrowth |
| `--secret-close-on-exec` | closes the secret descriptor in each direct child of the payload at fork while keeping it open in the payload. Requires the `ptrace` supervisor and is refused in plain and isolate modes |
| `--secret-fd-name NAME` | names the secret memfd `NAME` instead of `pmask-secret`. Accepts 1 to 200 bytes with no `/`, C0 control bytes, or DEL |
| `--memfd-name NAME` | names the image memfd `NAME` instead of the label. Applies to `--rexec`, `--image`, `--image-from-fd`, `--exec-once`, and `--hugetlb` |
| `--allow-argv-secret` | keeps a `literal:` or `env:` secret source in a non-redacting mode and warns instead of refusing |
| `--report=json` | prints one JSON report object to stdout, including `mode` and `mode_reason`. The payload shares fd 1, so use `--report-file` or `--report-fd` for clean parsing. Works on every local path and is refused with `--daemon` (exit 255) |
| `--report-file PATH` | writes the JSON report to `PATH` instead of stdout so the payload keeps fd 1. Implies `--report=json`. Refused with `--daemon` |
| `--report-fd N` | writes the JSON report to descriptor `N` (3 or higher; 0, 1, and 2 are refused with exit 255). Checked before execution and not inherited by the payload. Implies `--report=json` |
| `--audit` | prints one residue row per tracee at each exec completion and a final residue count. Requires redaction mode |

`--args-from-fd` also keeps commands out of shell history files such as `.bash_history`. Fill the descriptor from your caller before invoking `pmask`. See `man pmask.1` for the complete option list.

`--report=json` writes to stdout after the payload exits. Because the payload shares fd 1, a parser sees payload output before the JSON object. Use `--report-file` or `--report-fd` when a consumer must parse the JSON document cleanly.

Under `--isolate`, `pmask` mounts a tmpfs `/dev` containing `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, and `/dev/tty`. The setup also binds `/dev/pts` and `/dev/ptmx` from the host when present, creates a private `/dev/shm`, and links `/dev/fd`, `/dev/stdin`, `/dev/stdout`, and `/dev/stderr` through `/proc/self/fd`. Each optional member is reported and counted if absent or refused by the kernel.

### 2. Library: supervise from your own program

```toml
[dependencies]
pmask = { git = "https://github.com/Azathothas/pmask", tag = "v0.1.0" }
```

```rust
use pmask::Mask;

let st = Mask::new()
    .label("ci-runner")
    .run("/usr/bin/deploy", &["--token", "SECRET"])?;
println!("exit: {} ({} of {} execs degraded)", st.code, st.stats.degraded, st.stats.execs);
```

`Mask` is a builder. `Mask::run` blocks and supervises on the calling thread. `Mask::spawn` returns a `MaskedChild` immediately and runs the tracer on its own thread. Use `try_wait` and `wait_timeout` for non-blocking checks, and `kill_tree` to terminate the entire tree. Use `envs` and `env_clear` to replace the child environment, `run_as` to drop the child to a specific uid and gid, and `session_end` to pick the descendant policy.

### 3. Daemon: keep the secret out of the caller

CI runners often need a secret token. Placing that token in the runner's environment exposes `/proc/<pid>/environ`, and placing it on a command line exposes `/proc/<pid>/cmdline`.

Run `pmaskd` to hold the token instead:

```sh
# as the runner user, once:
cat > ~/.config/pmask/runner.env <<'EOF'
CI_TOKEN=ghp_...
EOF
chmod 600 ~/.config/pmask/runner.env

pmaskd --label ci-runner --env-file ~/.config/pmask/runner.env \
    --socket "$XDG_RUNTIME_DIR/pmask.sock"

# the runner, for every job:
pmask --daemon "$XDG_RUNTIME_DIR/pmask.sock" -- ./deploy.sh --env prod
```

Pass the same socket path to both sides. For a root daemon, start `pmaskd` with `--socket /run/pmask.sock --allow-uid <runner-uid>` and point the client at `/run/pmask.sock`.

The client sends only the command. The daemon supplies the environment, supervises the job with the client's stdio, and returns the exit status. The token lives only in the daemon's memory and in the job's redacted environment block. The token never appears in the client's `argv`, the client's environment, or the job's `/proc/<pid>/{cmdline,environ}`.

The `--env-file` is not the encrypted store. `pmaskd` does not accept `--store` or `--passphrase-file` and exits 255 with `unknown option --store` if given either flag. The encrypted store belongs to `pmask agent`, which serves `--secret NAME=agent:NAME` requests over its own socket.

`pmaskd` authorizes peers through `SO_PEERCRED`. By default, `pmaskd` accepts only its own uid and root, plus any uid added with `--allow-uid`. The socket defaults to mode `0600`, and the client verifies the daemon's peer uid. On Linux 6.5 and newer, `pmaskd` pins the connecting peer with `SO_PEERPIDFD` and re-verifies it before starting the job. On older kernels, `pmaskd` falls back to checking the peer's pid and `/proc` start time on a best-effort basis.

`--daemon` refuses local-only flags that the daemon cannot honor. Passing `--secret`, `--isolate`, `--no-redact`, `--hide-pid`, `--encrypt-memory`, `--image`, `--image-from-fd`, or `--report*` with `--daemon` exits 255 and names the refused flag. Other mask options besides `--label` and `--label-empty` print one warning and have no effect.

**Warning:** Any allowed uid can execute arbitrary programs with the daemon's privileges and environment. Grant `--allow-uid` only to trusted uids. On a root daemon, pass `--run-as-uid` to run each job under the client's own uid and gid.

## Secret delivery without a daemon: `--secret`

`--secret NAME=SRC` delivers a value on a sealed memfd at descriptor 3, 4, ... and sets `PMASK_SECRET_<NAME>=<fd>` in the child's environment. The secret value never enters the child's `argv` or `environ`. Inside the payload, read the secret with `pmask read NAME` or read the descriptor directly. Supported sources are `file:PATH`, `env:VAR`, `agent:NAME`, `stdin`, and `literal:VALUE` (a bare value is a literal).

```sh
token=$(pmask read DEPLOY_TOKEN)
```

`pmask read` works inside a masked payload because `pmask` snapshots its own arguments from the runtime before zeroing the kernel `argv` block. A binary that reads `/proc/self/cmdline` instead sees only the label, finds no subcommand, and exits 255. Reading the file descriptor directly works in every mode without calling `pmask`.

The source type determines what the host can still observe:

- `file:`, `agent:`, and `stdin` keep the secret out of every command line that invokes `pmask`.
- `--args-from-fd` keeps the payload's argument vector off `pmask`'s command line.
- `literal:` travels in `pmask`'s `argv` until self-masking runs. The kernel audit subsystem logs `type=EXECVE` and `type=PROCTITLE` before self-masking, so the cleartext persists in the audit log, in any wrapper's `/proc/<pid>/cmdline` (such as `sudo`), and in interactive shell history.
- `env:` travels in the caller's environment. Kernel exec audit records omit `environ`, but the shell and wrappers still hold the variable.

Use `file:`, `agent:`, or `stdin` whenever possible, and add `--args-from-fd` when the payload vector must stay off the command line.

Add `--secret-burn` to let a cooperating reader truncate the memfd once without allowing regrowth. Add `--secret-close-on-exec` to close the secret descriptor in each direct child of the payload at fork while keeping it open in the payload. That guarantee covers standard fork/exec trees. A child created with `clone(CLONE_FILES)` without `CLONE_THREAD` shares the payload's descriptor table, so closing it would break the payload. `pmask` reports and counts that degradation. `--secret-close-on-exec` requires the `ptrace` supervisor and is refused in plain and isolate modes.

In redaction mode, `--secret` makes the payload non-dumpable by default so same-uid peers cannot read `/proc/<pid>/fd/N` or payload memory. Pass `--allow-dumpable` to opt out. `literal:` and `env:` sources are refused in non-redacting modes unless you pass `--allow-argv-secret`.

## Modes: what each mode redacts

`pmask` selects one of three execution modes. Runs on the secret or isolation path print `mode=` and one note per unapplied option at default verbosity. Direct redaction runs without secrets or isolation omit the `mode=` line and print a degradation summary when needed. `--report=json` always includes `mode` and `mode_reason`.

| mode | selected by | redacts | does not |
|---|---|---|---|
| `redact` | default when the host permits `ptrace`, or `--redact` | `cmdline`, `comm`, and `environ` for every process in the tree, at exec entry (or exec completion for scripts and re-execs), relocating windows by default | `exe`, `maps`, `fd/*`, and `cwd` still name the real binary unless `--rexec` is set. Payload memory still holds real `argv` unless `--no-dumpable` is set |
| `isolate` | `--isolate[=LIST]`, or `--no-redact --isolate` | nothing: the payload inside the namespaces keeps its real `cmdline`, `comm`, and `environ` | the host sees the supervisor and helper under the label. The namespace leaves a private `hidepid=invisible` procfs in `mountinfo` and an `NSpid` chain |
| `plain` | `--no-redact`, or a host that denies `ptrace` on the runner path | nothing | prints `mode=plain` and notes that the label was not applied. The payload runs as an ordinary process with the caller's environment |

Mode composition rules:

- `--redact --isolate=LIST` composes redaction with the exact namespaces in `LIST` (`pid`, `net`, `tmp`, default `all`). `pmask` never substitutes `--unshare` for `LIST` and reports any unavailable namespace as a degradation.
- `--isolate=none` disables all isolation (no namespace, no `no_new_privs`, no Landlock). It still runs on the redaction path, so the payload gets the label and a plausible decoy `environ` in the host namespace view. A bare `--isolate` requests `all`.
- `--no-redact --isolate` selects `mode=isolate` and applies the namespaces without requiring `ptrace`.
- `--unshare` runs the redaction path inside private user, pid, and mount namespaces with a private procfs.
- Plain and isolate modes print one note for every mask option they cannot apply, including `--no-dumpable`. The JSON report derives `payload_dumpable` from the active mode rather than the requested flag.
- `--audit` requires redaction mode and exits 255 under `--no-redact`, bare `--isolate`, or a host that falls back to `plain`. Every local mode supports `--report`. Only `--daemon` refuses it (exit 255).
- `pmask` refuses 32-bit images before execution by default, prints one warning, counts the refusal, and kills the exec with `SIGKILL` unless you pass `--allow-foreign`.
- `-q` suppresses the `mode=` line, notes, and the session summary. `-q` does not suppress `--audit` rows, `--report` output, or `pmask: refused:` lines.

## How pmask works

`pmask` operates as a `ptrace` supervisor and parent of the process tree:

1. **Follow every descendant.** `PTRACE_O_TRACE{FORK,VFORK,CLONE,EXEC,EXIT}` auto-attaches children, grandchildren, threads, `posix_spawn()`, `system()`, double-forking daemons, static binaries, Go runtimes, and `#!` scripts. `pmask` uses no `LD_PRELOAD` and requires no libc in the tracee.
2. **Swap pointers at exec entry for zero exposure.** Each new process runs under `PTRACE_SYSCALL` until its first exec settles. At `execve`/`execveat` entry, the tracer replaces the old image's `argv` and `envp` pointer arrays with the label and presentation-sized filler strings. The kernel never copies the real command line into the new image of an ELF target.
3. **Restore real arguments before execution begins.** At exec completion (`PTRACE_EVENT_EXEC`), the tracer injects an anonymous mapping into the tracee, writes the saved real strings there, and repoints the stack's inline `argv`/`envp` arrays. `argc`, stack layout, and auxiliary vector structure stay intact, so glibc, musl, and static binaries start normally.
4. **Set `comm` inside the tracee.** The tracer injects `prctl(PR_SET_NAME)` through a `syscall` instruction in the tracee's own vDSO (or executable mapping). `pmask` never creates writable-and-executable memory.
5. **Present a decoy environment.** The entry swap and completion stop replace `/proc/<pid>/environ` with a plausible decoy environment, keeping only variables named by `--keep-env=NAME`.
6. **Relocate the kernel's windows in `[stack]`.** At completion, one unprivileged `prctl(PR_SET_MM, PR_SET_MM_MAP)` call points `mm->arg_start`/`arg_end` and `mm->env_start`/`env_end` at the presentation block inside the kernel-copied `[stack]` region (falling back to the anonymous block only if the stack region is too small). `cmdline` becomes the label plus one NUL, `arg_end == env_start`, `environ` holds the decoy or kept entries, and a second label copy sits at `env_end`. `start_stack` stays at the kernel value and the `[stack]` VMA keeps its normal size and `gd` flag. The completion stop also rewrites `AT_EXECFN` in `saved_auxv` and on the tracee's stack so `/proc/<pid>/auxv` and `getauxval(AT_EXECFN)` both return the label. `--no-exact` skips relocation and overwrites the original extent in place. Unlike bare `PR_SET_MM_ARG_*`, `PR_SET_MM_MAP` does not require `CAP_SYS_RESOURCE`.
7. **Preserve job control.** The tracer answers group-stops with `PTRACE_LISTEN`, so `Ctrl-Z`, `kill -STOP`, and `SIGCONT` work normally inside a masked shell.
8. **Enforce an explicit session-end policy.** By default (`--on-exit detach`), surviving descendants are detached when the master exits. Detached processes keep their label and redacted image, but later execs are not redacted. `--on-exit wait` and `--on-exit kill` are the other two policies.
9. **Trade `TracerPid` explicitly.** Active supervision sets `TracerPid` to the tracer thread id. `--detach` detaches each tracee after its exec settles, resetting `TracerPid` to 0 at the cost of losing coverage for all later forks and execs.

Scripts (`#!`), `vfork` children, and settled re-execs take the post-exec path. The kernel needs the real `argv` to parse `#!` interpreters, `vfork` children share parent memory, and settled processes do not stop at syscall entry. On the post-exec path, the kernel briefly copies the real strings before the completion stop overwrites them. Run `tests/compare.sh` to measure that window on your host. Use `--strict-exec` to refuse post-exec fallbacks instead of allowing them.

32-bit images are refused before execution by default. A 64-bit tracer cannot safely rewrite 32-bit registers for an entry swap, so `pmask` kills the exec with `SIGKILL`, prints one warning, and counts it in the summary unless you pass `--allow-foreign`.

## Privilege ladder

Higher privileges unlock stronger privacy in defined steps. Every rung 0 feature runs unprivileged.

| rung | requirement | what it adds | limit |
|---|---|---|---|
| 0 | none | entry swap, label, `comm`, per-variable environment policy | same-uid observers still read `exe`, `maps`, `fd/*`, and `cwd` |
| 0 | none | `prctl(PR_SET_MM_MAP)` window relocation in `[stack]` | unavailable without `CONFIG_CHECKPOINT_RESTORE` or when seccomp blocks `prctl`. `--no-exact` turns it off |
| 0 | none | `--detach`: sets `TracerPid` to 0 for settled payloads | detached processes and their descendants run unredacted at later execs |
| 0 | none | `--no-dumpable`: blocks same-uid reads of `environ`, `maps`, `auxv`, `exe`, `fd`, and `mem` | disables core dumps and debugger attach |
| 0 | none | `--rexec`: moves `exe` to `/memfd:<label> (deleted)` | `map_files` resolves to `/memfd:` (asserted by `tests/compare.sh`). `vm.memfd_noexec` may block memfd execution |
| 0 | unprivileged user namespaces | `--unshare`: private pid namespace and private procfs | unavailable on hosts that disable user namespaces. Opportunistic by design |
| 0 | none | `--watch-rename`: keeps `comm` at the label across self-renames | traps `prctl(PR_SET_NAME)` and `open`/`openat`/`openat2`/`creat` on `/proc/.../comm` (plus write syscalls under `=strict`). Implies `no_new_privs` and refuses `--on-exit detach` |
| 2 | `CAP_SYS_RESOURCE` | bare `PR_SET_MM_ARG_START`/`_ARG_END` calls | unused. One-shot `PR_SET_MM_MAP` achieves the same result at rung 0 |
| 3 | root on the host | `hidepid=2,gid=` on system `/proc` hides the tree from other accounts | conflicts with some polkit and distro defaults. Yama scope requires `CAP_SYS_PTRACE`, and scope 3 lasts until reboot |

## Verification

Each detection suite proves its detector works before testing `pmask`. First, the suite runs the workload without `pmask` and requires the observer to detect the markers (negative control). Next, the suite requires zero sightings under the mask, verifies process liveness under the label, and checks `argv`, environment, stdio, signals, and exit codes.

```sh
sh tests/run.sh      # on a host that permits ptrace
sh vm/run.sh         # anywhere: 11 staged suites in a QEMU micro-VM
```

Run the native gate (`tests/run.sh`) as an unprivileged uid. As root, `CAP_SYS_PTRACE` bypasses same-uid refusals, so those cases print `SKIP` instead of asserting refusal. `vm/run.sh` runs both root and uid-1000 passes automatically.

`tests/run.sh` runs 18 suites plus the per-issue QA dispatcher (`tests/qa.sh`): `validate`, `suite`, `stress`, `edge`, `daemon`, `daemon_neg`, `options`, `redteam`, `blueteam`, `core`, `audit`, `store`, `isolation`, `lease`, `secrets`, `compare`, `conformance`, and `regressions`.

`vm/run.sh` stages 11 suites (`validate`, `suite`, `stress`, `edge`, `daemon`, `daemon_neg`, `options`, `redteam`, `blueteam`, `core`, and `audit`). The VM harness downloads a pinned Alpine kernel and static busybox verified by SHA-256, compiles static musl binaries, packs an initramfs, and boots QEMU. It uses KVM when `/dev/kvm` is usable for the guest architecture and TCG otherwise (`PMASK_VM_KVM=0|1` overrides). `vm/run.sh` runs all staged suites as root and as uid 1000 and exits 0 only when both passes report `FINAL: ALL-PASS`.

`measurements/` contains the speed and zapper comparison harnesses. Run them on a quiet host and check the environment conditions they print.

## Honest limits

- Root sees that a pid exists and reads its memory. `pmask` hides *what* a process is doing, not *that* the process exists.
- Every local account reads `cmdline` and `comm`. Same-uid processes and root also read `environ`, `exe`, `maps`, `fd/*`, and `cwd` unless `--no-dumpable` is set.
- `/proc/<pid>/exe`, `maps`, open files, sockets, and cgroups reflect the real binary unless you pass `--rexec`. With `--rexec`, `exe`, the executable mapping, and `map_files/<range>` name `/memfd:<label> (deleted)`, while open files, sockets, and cgroups remain real. Fallback carriers name `/proc/self/fd/N` or a guarded mode-`0700` temporary file. Under `--exec-once`, later execs use a verified temporary-file carrier in `$XDG_RUNTIME_DIR` (or `/dev/shm`) that is unlinked at session end.
- Set-uid and set-gid binaries do not elevate privileges under `ptrace` supervision, with or without `--no-new-privs`.
- `#!` scripts, `vfork` children, and settled re-execs take the post-exec path unless `--strict-exec` refuses them. On the post-exec path, the interpreter command line and environment remain briefly visible until the completion stop overwrites them. `tests/compare.sh` measures that window.
- In exact mode, the completion stop rewrites `AT_EXECFN` in both `saved_auxv` and the stack auxiliary vector so `/proc/<pid>/auxv` and `getauxval(AT_EXECFN)` both report the label. `--no-exact` and a refused `PR_SET_MM_MAP` leave the real executable path in both locations.
- A kernel without `CONFIG_CHECKPOINT_RESTORE` or a seccomp filter blocking `prctl` refuses `PR_SET_MM_MAP`. `pmask` then falls back to in-place overwriting: `/proc/<pid>/stat` keeps the original extent, `cmdline` shows the label padded with spaces and one NUL, and the session summary counts each affected exec. `pmask probe` reports this capability on the `exact cmdline window` row.
- The real `argv` and environment strings live in the tracee's injected anonymous mapping for the life of the process. A same-uid reader recovers them from `/proc/<pid>/mem` while the tracee is dumpable. `--no-dumpable` blocks that read at the cost of a six-file `EACCES` fingerprint (`environ`, `maps`, `auxv`, `exe`, `fd`, and `mem`) and `0 0 0 0` in `/proc/<pid>/stat` fields 48 to 51.
- `--keep-env` re-exposes the full environment, and `--keep-env=NAME` re-exposes named variables. Secrets in kept variables become readable to same-uid observers. A later `--keep-env=NAME` narrows an earlier `--keep-env`, and a later `--keep-env` widens it again.
- `docs/research/detection-residue.md` lists every surviving `/proc` and kernel interface and the condition that reveals it.
- A `literal:` secret enters `pmask`'s `argv` before self-masking, so kernel audit records (`type=EXECVE`, `type=PROCTITLE`), wrappers such as `sudo`, and interactive shell history capture it. An `env:` secret stays in the caller's shell and wrapper environments. Use `file:`, `agent:`, `stdin`, and `--args-from-fd` to keep secrets off command lines.
- A `--secret` value never enters the payload's `cmdline`, `environ`, or `ps`. In redaction mode, the payload is non-dumpable by default, blocking same-uid reads of `/proc/<child>/fd/<N>` and payload memory (`--allow-dumpable` opts out). The descriptor clears `FD_CLOEXEC` so the payload can read it after exec. `--secret-close-on-exec` closes the descriptor in direct children at fork, except for processes sharing the descriptor table via `clone(CLONE_FILES)` without `CLONE_THREAD` (reported and counted). `--detach` warns because no tracer remains to close descriptors in descendants. `--secret-burn` clears `F_SEAL_SHRINK` so a cooperating reader can truncate the memfd once without regrowth, though a reader that copies the value or a peer that reads before the burn defeats it.
- Labels truncate at three boundaries: 15 bytes for `comm`, 254 bytes for the exec-entry scratch buffer, and the kernel's copied argument span on the post-exec path. `pmask` warns once when a label exceeds 254 bytes. Under default `PR_SET_MM_MAP` relocation, the settled `/proc/<pid>/cmdline` holds the full label. Under `--no-exact`, the visible window keeps the 254-byte entry copy. The kernel rejects arguments over 131072 bytes with `E2BIG`.
- Without `--detach`, every tracee reports the tracer thread id in `/proc/<pid>/status` `TracerPid`. That thread uses the session's `comm` or label, has `Tgid` equal to the supervisor's pid, and has `Pid` equal to its thread id, so `/proc/<sup>/task/` shows two threads. `--detach` sets `TracerPid` to 0 at the cost of losing later-exec coverage.
- A supervision session consumes `SIGCHLD` notifications (`CLD_STOPPED`, `CLD_TRAPPED`, `CLD_CONTINUED`, `CLD_DUMPED`) for its tracees.
- `pmask` requires Linux 5.3 or newer (`PTRACE_GET_SYSCALL_INFO`) on `x86_64` or `aarch64`.
- A masking session owns the calling process's `waitpid(-1)` domain, so sessions inside one process are serialized.

## What a defender still sees

`pmask` rewrites `/proc` content, not the kernel process table. The signals below survive and are readable in one line. Measured details, commands, and host conditions live in `docs/research/detection-residue.md` and `docs/research/detection-measured.md`. The red-team review fixes and shape comparisons against `zapper` and `psgen` live in `docs/REDTEAM-RESULTS.md` and `docs/COMPETITORS.md`.

| signal | what it shows | when |
|---|---|---|
| the tracer thread | a second thread inside the supervisor whose `comm` is the session label (never the retired `pmask-tracer`). Its `Tgid` is the supervisor pid and its `Pid` is the thread id, exposing `Tgid != Pid` in `/proc/<sup>/task/<tid>/status` | every redacting mode. `--isolate` and `--no-redact` have no tracer. `--detach` zeroes each tracee's `TracerPid` while keeping the supervisor's thread for the session |
| `TracerPid` | the tracer thread id in `/proc/<pid>/status`, which differs from the parent pid and is absent from `readdir("/proc")` | every attached mode. `0` under `--detach` |
| the label and `exe` split | `comm` and `cmdline` show the label, while `exe` and `maps` name the real binary | default. `--rexec` moves `exe` to `/memfd:<label> (deleted)` while open files and cgroups stay real |
| memfd and carrier names | `/proc/<pid>/exe -> /memfd:<label> (deleted)` for images and `/proc/<pid>/fd/N -> /memfd:pmask-secret (deleted)` for secrets. Later `--exec-once` execs use a named carrier in `$XDG_RUNTIME_DIR` or `/dev/shm/.pmask-rexec-<label>-<pid>-<hex>-0` | `--rexec`, `--image`, `--secret`, `--exec-once` |
| the `environ` window | a complete plausible decoy environment (110 bytes by default), or the `--keep-env` entries. The payload keeps its real environment | default and exact runs. `--no-exact` fills the original extent with the same entries |
| the supervisor's own entry | a labelled process with a compact `argv` window, a decoy `environ`, a dumpable descriptor table at rest, and two threads. `auxv` `AT_EXECFN` matches the label when `PR_SET_MM_MAP` succeeds, and names `pmask` otherwise | every mask run. `--no-dumpable`, `--hide-pid`, `--encrypt-memory`, `--secret`, and `--report` pin the supervisor non-dumpable. `PMASK_NO_SELFMASK=1` is the debug escape |
| the launch window | the supervisor's `argv`, an interpreter command line, and a script's real `comm` stay readable for a few hundred microseconds at exec | every mode. The script `comm` window measured a median 307.6 us (min 257.9, max 394.2) on Debian 13, kernel 6.12.113, uid 1000, LXC (`sh measurements/launch-window.sh`, `WINDOW_ROUNDS=3`, `WINDOW_N=60`) |
| the seccomp status fingerprint | `/proc/<pid>/status` shows `NoNewPrivs: 1` and one filter per active feature: `Seccomp_filters: 1` for `--watch-rename` or the `--exec-once` exec filter, and `2` when both are active. Compare deltas in containers that already attach a filter | `--exec-once` (with `--on-exit wait` or `kill` and without `--no-exit-kill`), `--watch-rename`, and `--stealth` |
| the audit record | the supervisor's `EXECVE`/`PROCTITLE` record holds its real `argv` (including any `literal:` secret). The payload's record holds the label plus one empty string per extra argument | any host with Linux audit enabled |
| non-redacting modes | real `cmdline`, `comm`, and `environ`, with no rewrite | `--no-redact`, bare `--isolate`, or a host denying `ptrace`. 32-bit images are refused by default and run unredacted only with `--allow-foreign` |

No single signal is unique to `pmask`. `TracerPid != 0` matches `strace`, and `0 0 0 0` in stat fields 48 to 51 appears on ordinary non-dumpable daemons. A detector identifies a masked tree by combining the tracer thread, the label/`exe` split, and the decoy `environ`.

## Prior art

`zapper` acts at exec completion, zeroes `argv` and `environ` in place, repairs `auxv` pointers, and detaches (or follows children with `-f`). `mimic` executes the binary with fake `argv`/`envp` and injects the real arguments at `main()`. `memexec` runs a binary from a memfd through `execveat` to bypass `noexec` mounts and redacts nothing. `hidepid=2` is a system-wide `/proc` policy that does not stop same-uid observers. `setproctitle` rewrites the title in-process inside the shared `environ` region.

`pmask` combines exec-entry pointer swapping with `PR_SET_MM_MAP` window relocation. Every program keeps its real `argv` and `environ`, while `/proc` shows the label with no padding. See `docs/research/survey-2025/` for the full comparison, and run `measurements/vs-zapper.sh` on a host with a C compiler and network access to reproduce the `zapper` benchmarks.

## Build

`pmask` builds on Linux 5.3 or newer (`x86_64` or `aarch64`, glibc or musl) with Rust 1.87 or newer (`rust-version` in `Cargo.toml`).

```sh
./build.sh            # glibc build
./build.sh --static   # static musl binaries (needs the musl target)
./build.sh --test     # also run cargo test --lib and the unwrap audit
```

Manual build commands:

```sh
cargo build --locked --release
# static (needs: rustup target add x86_64-unknown-linux-musl):
cargo build --locked --release --target x86_64-unknown-linux-musl
# tests, unit tests and packaging:
cargo test --locked --lib
cargo package --list
```

`Cargo.lock` pins all dependencies. The first build fetches crates from crates.io. Subsequent builds with a warm cargo cache work offline.

The build produces `pmask` (CLI) and `pmaskd` (daemon). Passing `--features testbins` also builds `pmask-testcases` and `pmask-protocases` for the test suites. Copy the release binaries into a directory on `PATH`. Neither binary reads a configuration file. The repository also ships `man/pmask.1`, `man/pmaskd.8`, and shell completions for bash, zsh, and fish. The systemd units under `contrib/systemd/` set `ExecStart=/usr/bin/pmask` for `pmask-run@.service` and `ExecStart=/usr/bin/pmaskd` for `pmaskd@.service`. Install the binaries into `/usr/bin` or adjust `ExecStart` to match your path.

## Install

`pmask` is distributed through GitHub Releases (not crates.io) as static musl binaries for `x86_64` and `aarch64`.

Download the latest release (`v0.1.0` and newer):

```sh
curl -fLO "https://github.com/Azathothas/pmask/releases/latest/download/pmask-x86_64-unknown-linux-musl"
chmod +x pmask-x86_64-unknown-linux-musl
./pmask-x86_64-unknown-linux-musl --version
```

Pin a specific release tag:

```sh
V=v0.1.0
curl -fLO "https://github.com/Azathothas/pmask/releases/download/$V/pmask-x86_64-unknown-linux-musl"
chmod +x pmask-x86_64-unknown-linux-musl
./pmask-x86_64-unknown-linux-musl --version
```

Each release also provides `pmaskd-<target>`, manual pages, a tarball with shell completions and systemd units, `SHA256SUMS`, and a Sigstore provenance bundle. Verify downloads before use:

```sh
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify pmask-x86_64-unknown-linux-musl --repo Azathothas/pmask
```

## Repository layout

```
src/              the supervisor, the daemon, the secret side
tests/            the suites and the QA fragments; run.sh is the native gate
vm/               QEMU micro-VM harness
measurements/     speed and zapper comparison harnesses
evidence/         raw logs for the b-team measurements
docs/             design, threat model, deployment, research, comment audit, issue closure
man/, completions/  manual pages and shell completions
contrib/          systemd units, tmpfiles.d and sysusers.d
fuzz/             the store header parser target
scripts/          the CI guards and verify.sh, the gate wrapper
```

## License

0BSD. See `LICENSE`. Use and distribute `pmask` without attribution.
