# pmask

**Confidential execution without trusted hardware.** Run a command, a
binary or a job so that other local users and pasted `ps` output cannot
read its command line or environment, while the program itself keeps its
real arguments and environment and works normally. A same-uid monitoring
agent still sees `exe`, `maps`, `fd/*` and `cwd` unless `--no-dumpable`
is set.

```sh
pmask --label ci-runner ./deploy.sh --env prod
```

`ps`, `top`, `htop`, `/proc/<pid>/cmdline` and `/proc/<pid>/comm` show
`ci-runner` for that process and everything it spawns.
`/proc/<pid>/environ` is empty. The program still reads its own `argv`,
its own environment, its own stdin and its own exit code.

## Why

Confidential computing today means a TEE: AMD SEV-SNP, Intel TDX, ARM
CCA, SGX enclaves. Those protect memory against the host, and they are
excellent at it. They also require hardware that supports them, a
hypervisor or a guest OS that can launch and attest, an attestation
service and a policy that trusts it, and, for the enclave models, a
rewritten workload.

Most machines have none of that. A self-hosted CI runner, a shared build
host, a lab box, a container, a laptop, a VPS: no TEE, and no way to get
one. The secrets still have to run somewhere.

The leak in those environments is not memory. It is `/proc`:

```sh
$ ps -eo user,args | grep deploy
ci     ./deploy.sh --token ghp_9f3c... --env prod
```

CI vendors document the same hazard: command-line arguments are visible
to other local users through `ps` or captured by audit events. MITRE
ATT&CK T1036.011, "Overwrite Process Arguments", catalogs the same
mechanics.

`pmask` closes that specific disclosure surface, on hardware you already
have, as an unprivileged user.

## What it is not

It is not a TEE and it does not encrypt memory. The limit table states the
line exactly:

| observer | sees |
|---|---|
| another uid | the label in `cmdline` and `comm`; no real argv or environ |
| a monitoring agent of the same uid | the label, and also `exe`, `maps`, `fd/*` and `cwd`, which name the real binary; a `pmaskd` job's child on the composed daemon path reads `environ` as 0 bytes, and the holder's `environ` is refused (`EACCES`) |
| the same, with `--no-dumpable` | the label; those files are refused |
| `ps` output pasted into a ticket or a chat | the label |
| root on the host | **that** a pid exists, its `/proc/<pid>/exe`, its `maps`, its open files, its cgroups, and its memory via `PTRACE_ATTACH` |
| anyone with kernel access | everything |

`cmdline` and `comm` carry no ptrace check, so every local account sees
them. `environ`, `exe`, `maps`, `fd/*` and `cwd` require
`PTRACE_MODE_READ_FSCREDS`, which a process of the same uid passes. Yama
restricts `PTRACE_MODE_ATTACH` only, so it does not stop the same-uid
read; `PR_SET_DUMPABLE=0` does. The supervisor sets it for itself for the
life of the session, because it holds the real argv of every tracee it
has swapped, and `--no-dumpable` extends the treatment to the payload.

So: confidentiality against other tenants and against casual inspection,
not against the host operator. That is the same trust boundary a
container gives you for the filesystem, applied to process metadata. An
adversary with root on the same kernel needs a TEE or a separate
machine; `pmask` does not address that case.

`pmask probe` reports each mechanism this host allows with an `active`,
`degraded` or `unavailable` state and the cost of its absence, and a
final `tier=` word. `pmask doctor --require redact,exact` exits 0 only
when both are active, 3 when one is degraded and 4 when one is
unavailable, so a CI job asserts on the deployment instead of assuming
it.

## Three ways to use it

### 1. CLI: one command under a label

```sh
pmask --label 'ci-runner' ./deploy.sh --token "$TOKEN" --env prod
```

Everything the command spawns inherits the label. A whole shell session
can be wrapped once, and background jobs survive the shell exit:

```sh
exec pmask --label 'dev-shell' bash --login -i
```

Options that matter most:

| option | effect |
|---|---|
| `-l, --label NAME` | the presented command line and comm |
| `--comm NAME` | a comm separate from the label, at most 15 bytes |
| `--argv0 NAME` | argv[0] of the program; the default is the command as typed |
| `--keep-env` | leave `environ` visible |
| `--keep-env=NAME` | keep only the named variables visible, repeatable |
| `--env K=V`, `--env-file PATH` | set the child environment |
| `--args-from-fd N` | read the command from a NUL-separated vector on fd N, so the secret never enters the supervisor's own command line; the vector is capped at 8 MiB. pmask reads a duplicate, so the descriptor stays open for the payload and `--args-from-fd 0` leaves the payload its stdin; the source is consumed, so its offset ends at the end of the vector |
| `--on-exit detach\|wait\|kill` | what happens to descendants when the command exits |
| `--detach` | `PTRACE_DETACH` each process once its exec settles, so `TracerPid` reads 0; a detached process is not followed at all, so nothing it forks and none of its own later execs are redacted |
| `--no-exact` | keep the kernel's original argv window instead of relocating it; `cmdline` is the label plus one NUL per argument |
| `--no-dumpable` | `PR_SET_DUMPABLE=0` in the payload: same-uid observers lose `environ`, `maps`, `exe`, `fd`. The supervisor is non-dumpable in every mode |
| `--no-new-privs` | set-uid and file capabilities gain nothing |
| `--watch-rename` | keep the label when a program renames itself |
| `--rexec` | run from a sealed memfd, so `exe` names the label; the ordered chain falls back to `/proc/self/fd/N`, then an `O_TMPFILE` or named temporary file on an executable mount, reporting each failed step |
| `--rexec-allow-disk` | add the on-disk path as the explicit last resort of the `--rexec` chain; never automatic |
| `--image PATH` | read the program bytes from PATH (or `-` for stdin) and exec them from a sealed image; implies `--rexec` |
| `--image-from-fd N` | read the program bytes from descriptor N; implies `--rexec` |
| `--exec-once` | reuse one sealed image per distinct program, keyed by resolved path and mtime, across the execs of the session; implies `--rexec` |
| `--hugetlb` | ask for a hugetlbfs-backed image and report the backing; falls back to an ordinary memfd; implies `--rexec` |
| `--unshare` | private user, pid and mount namespaces with a private procfs, when the kernel allows it |
| `--isolate[=LIST]` | run the payload in fresh pid, net and tmp namespaces (default `all`) |
| `--no-redact` | never touch `/proc` metadata, even where ptrace works |
| `--scope-name NAME` | one transient systemd scope named NAME |
| `--secret N=SRC` | deliver a secret on descriptor 3, 4, ...; `PMASK_SECRET_<NAME>=<fd>` names it in the child |
| `--secret-burn` | let a cooperating reader truncate the value once and never grow it back |
| `--secret-close-on-exec` | close the descriptor in each direct child of the payload at its fork, not in the payload; needs the ptrace supervisor, so plain and isolate modes refuse it |
| `--allow-argv-secret` | keep a `literal:` or `env:` source in a mode that cannot redact, and warn instead of refusing |
| `--report=json` | print the run as one JSON object, including `mode` and `mode_reason`, after the payload exits; needs `--secret`, `--isolate` or `--no-redact`, and a plain or `--daemon` run refuses it with exit 255 |
| `--audit` | print one residue row per tracee at each exec completion, then a residue count naming the interfaces the tree still discloses; needs the redaction mode |

`--args-from-fd` matters for shell history as well: a command read from
a descriptor never appears in `ps` or in `.bash_history`. How the
descriptor is filled is the caller's business. `man pmask.1` has the full
option list.

`--report=json` writes its document to standard output after the payload
has exited, so a payload that writes to standard output shares fd 1 with
the report. A consumer that parses the stream sees the payload's bytes
first, and a `| tee` keeps both. Send the payload's own output somewhere
else, or read the final JSON object, when a parser must have the document
alone.

### 2. Library: supervise from your own program

```toml
[dependencies]
pmask = { git = "https://github.com/Azathothas/pmask" }
```

```rust
use pmask::Mask;

let st = Mask::new()
    .label("ci-runner")
    .run("/usr/bin/deploy", &["--token", "SECRET"])?;
println!("exit: {} ({} of {} execs degraded)", st.code, st.stats.degraded, st.stats.execs);
```

`Mask` is a builder. `run` blocks and supervises on the calling thread.
`spawn` returns a `MaskedChild` immediately and runs the tracer on its
own thread; `try_wait` and `wait_timeout` do not block forever, and
`kill_tree` terminates the whole tree. `envs` and `env_clear` replace the
child environment wholesale, `run_as` drops the child to a uid and gid,
and `session_end` selects the policy for descendants.

### 3. Daemon: the secret never enters the caller

This is the case that matters for CI runners. The runner needs a token.
If the token is in the runner's environment, `/proc/<pid>/environ`
publishes it. If it is on a command line, `/proc/<pid>/cmdline` does.

`pmaskd` holds the token instead:

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

Both sides name the same socket. A root daemon is the other shape: start it
with `--socket /run/pmask.sock --allow-uid <runner-uid>`, and give the
client the same path.

The client sends only the command. The daemon supplies the environment,
supervises the job with the client's stdio, and returns the exit status.
The token exists in the daemon's memory and in the job's redacted
environment block. It does not exist in the client's argv, the client's
environment, or the job's `/proc/<pid>/{cmdline,environ}`.

Access is decided by `SO_PEERCRED`: the daemon's own uid and root only,
plus whatever `--allow-uid` adds. The socket is mode 0600 and the client
verifies the peer uid of the socket it connected to. Where the kernel
offers `SO_PEERPIDFD` (Linux 6.5 and later), the daemon pins the
accepted peer with a pidfd and checks it again before the job starts;
without one it falls back to the peer's pid and start time, which is
best effort.

`--daemon` refuses the flags it cannot honour. `--secret`, `--isolate`,
`--no-redact` and `--image` change what this process would do locally,
and the daemon owns the masking policy and the job environment, so the
client exits 255 and names the flag rather than dropping it. `--report`
is refused the same way: a daemon job returns the exit status only. Mask
options other than `--label` and `--label-empty` print one warning and
have no effect.

**Warning:** an allowed uid may execute arbitrary programs with the
daemon's privileges and inherit its environment. Grant `--allow-uid` only
to uids that may already do that. On a root daemon, `--run-as-uid` runs
each job with the client's own uid and gid instead.

## Secret delivery without a daemon: `--secret`

`--secret NAME=SRC` delivers a value to the job on a sealed memfd
descriptor at fd 3, 4, ... and sets `PMASK_SECRET_<NAME>=<fd>` in the
child's environment. The value never enters the child's `argv` or
`environ`. The program reads it with `pmask read NAME` inside the payload
or from the descriptor. Sources are `file:PATH`, `env:VAR`,
`agent:NAME`, `stdin` and `literal:VALUE`; a bare value is a literal.

```sh
token=$(pmask read DEPLOY_TOKEN)
```

That works inside a masked payload. The requirement is that the payload
runs a `pmask` that snapshots its own arguments from the runtime's copy
before it zeroes the kernel argv block. A build that reads
`/proc/self/cmdline` instead sees only the label when it runs under a
mask, finds no subcommand, prints the help text and exits 255. Reading
the descriptor directly works in every mode and has no such requirement.

The source decides what the host can still read. `file:`, `agent:`,
`stdin` and `--args-from-fd` keep the value out of every command line
that starts pmask. A `literal:` value travels in pmask's own argv until
pmask masks itself, and the kernel audit subsystem writes the exec record
(`type=EXECVE` and `type=PROCTITLE`) before that point. The cleartext
value is therefore in the audit log for the retention of the log, not for
the life of the run. The same string is in the
`/proc/<pid>/cmdline` of any wrapper that held the command line, `sudo`
included, for as long as the wrapper lives, and in the interactive
shell's history file. An `env:` source travels in the caller's
environment instead: the exec record carries argv and not environ, so the
value is not in that record, but the shell and every wrapper on the way
already hold it. Use `file:` or `agent:` where the value can be read from
a path or the agent, `stdin` where it can be piped, and `--args-from-fd`
where the whole payload vector must stay off pmask's command line.
`--secret-burn` lets a cooperating reader truncate the value once and
never grow it back.
`--secret-close-on-exec` closes the descriptor in each of the payload's
direct children at its fork, while the payload keeps it. The guarantee is
for an ordinary fork/exec tree: a process that shares the payload's
descriptor table (`clone(CLONE_FILES)` without `CLONE_THREAD`) cannot be
closed without removing the payload's copy, so the run reports a
degradation and the session counts it. It needs the ptrace supervisor;
plain and isolate modes refuse the combination rather than start the
payload without its secret. The descriptor is readable through
`/proc/<pid>/fd/N` by a same-uid peer unless the payload is non-dumpable;
`--no-dumpable` closes that, and `--secret-burn` narrows the window for a
reader that cooperates. `literal:` and `env:` sources are refused in a
mode that cannot redact unless `--allow-argv-secret` is given.

## Modes: what each one redacts

pmask selects one of three modes. The run prints `mode=` and, at the
default verbosity, one note per request the mode could not apply. The
JSON report carries the same `mode` and a `mode_reason` naming the axis
that kept the run below the strongest available one.

| mode | selected by | redacts | does not |
|---|---|---|---|
| redact | the default on a host that allows `ptrace`; `--redact` names it | `cmdline`, `comm` and `environ` for every process of the tree, from the exec-entry stop, with the windows relocated by default | `exe`, `maps`, `fd/*` and `cwd` name the real binary, and the payload's memory holds its real argv, unless `--rexec` and `--no-dumpable` are added |
| isolate | `--isolate[=LIST]`, or `--no-redact --isolate` | nothing: the payload inside the namespaces keeps its real `cmdline`, `comm` and `environ` | the host still sees the intermediate process under the label; the namespace leaves a private `hidepid=invisible` procfs in `mountinfo` and an `NSpid` chain |
| plain | `--no-redact`, or a host that does not allow `ptrace` | nothing | the run prints `mode=plain` and says the label was not applied; the payload is an ordinary process with the caller's environment |

- `--redact --isolate=LIST` composes the two. It redacts the tree and
  gives the payload exactly the namespaces the list names (`pid`, `net`,
  `tmp`; `all` is the default). It does not substitute `--unshare` for
  the list. A list the host cannot grant is reported as a degradation; it
  is never replaced by a different namespace set.
- `--isolate=none` means no isolation at all: no namespace, no
  `no_new_privs`, no Landlock, and the payload runs with the host's view
  unchanged. A bare `--isolate` asks for `all`.
- `--no-redact --isolate` runs the isolation path. Isolation does not
  need `ptrace`, and dropping the namespaces would be a silent fallback,
  so the namespaces are applied and the run reports `mode=isolate`.
- `--unshare` is the redaction path with private user, pid and mount
  namespaces and a private procfs. The host-side entry is the label.
- Every mask option that the plain or isolate mode cannot apply prints
  one note naming the option and the reason. `--no-dumpable` is one of
  them: the plain and isolate paths do not change the payload's
  dumpability, and the report's `payload_dumpable` is computed from the
  selected mode rather than from the request.
- `--audit` needs the redaction mode. It is refused with exit 255 for
  `--no-redact`, for `--isolate`, and on a host that selects plain
  because `ptrace` is unavailable. `--report=json` needs `--secret`,
  `--isolate` or `--no-redact`; a plain mask run and a `--daemon` job
  refuse it with exit 255.
- A 32-bit image is refused, not redacted: one warning names it, the
  session counts it, and the payload keeps its real `cmdline`, `comm` and
  `environ`.
- `-q` suppresses the `mode=` line, every note and the summary. It does
  not suppress the `--audit` rows or a `--report` document, which were
  requested explicitly.

## How it works

`pmask` is a `ptrace` supervisor and the parent of the tree:

1. **Follow everything.** `PTRACE_O_TRACE{FORK,VFORK,CLONE,EXEC,EXIT}`
   attaches to children, grandchildren, threads, `posix_spawn()`,
   `system()`, double-forking daemons, static binaries, Go runtimes and
   `#!` scripts. No `LD_PRELOAD`, no libc dependency.
2. **Zero exposure at exec entry.** Each process is syscall-supervised
   until its first exec settles, so `execve`/`execveat` stops at syscall
   entry. The supervisor swaps the `argv`/`envp` pointer arrays in the
   old image to point at the label and at empty strings. The kernel
   never copies the real command line into the new image of an ELF
   target. The child's old image holds the parent's argv bytes from the
   fork until this stop; the kernel never copies them.
3. **The program still gets its arguments.** At exec completion the
   saved strings are written into an injected anonymous mapping inside
   the tracee and the stack's inline arrays are repointed there. `argc`,
   the stack layout and the auxiliary vector are untouched, so glibc,
   musl and static binaries start normally.
4. **The process name is set too.** `prctl(PR_SET_NAME)` runs inside the
   tracee, through a `syscall` instruction in its own vDSO, so
   `/proc/<pid>/comm` shows the label. No writable-and-executable memory
   is created anywhere.
5. **The environment is redacted** from `/proc/<pid>/environ` by the
   same swap, except variables named by `--keep-env=NAME`.
6. **The kernel's own windows are moved, not just filled.** After the
   swap, one `prctl(PR_SET_MM, PR_SET_MM_MAP)` call inside the tracee
   points `mm->arg_start`/`arg_end` and `mm->env_start`/`env_end` at a
   compact presentation block this tool owns, and rewrites the
   `AT_EXECFN` entry of `saved_auxv` to the label. So `/proc/<pid>/cmdline`
   is exactly the label with no padding, `/proc/<pid>/environ` is empty,
   `/proc/<pid>/stat` fields 48 to 51 report that same extent, and
   `/proc/<pid>/auxv` names the label. The one-shot map is not gated by
   `CAP_SYS_RESOURCE`; the bare `PR_SET_MM_ARG_*` operations are, and the
   capability check sits after the map dispatch. `--no-exact` keeps the
   in-place redaction: the window is the label plus one NUL per argument,
   and `/proc/<pid>/environ` reads back as a NUL block instead of an
   empty file. The program's own argv was never in that window, because
   the entry swap replaces it before the kernel copies it.
7. **Job control works.** Group-stops are answered with
   `PTRACE_LISTEN`, so `Ctrl-Z`, `kill -STOP` and `SIGCONT` behave in a
   masked shell.
8. **Session end is explicit.** By default, descendants still running
   when the command exits are detached: they keep the label and their
   redacted image, and a later exec in them is not redacted because no
   supervisor watches them any more. `--on-exit wait` and
   `--on-exit kill` are the other two policies.
9. **`TracerPid` is zero only with `--detach`.** A supervisor has to
   exist for the tree to stay redacted. `--detach` releases each process
   once its exec has settled, which brings `TracerPid` to 0 and costs
   coverage: a detached process is not followed at all, so nothing it
   forks and none of its own later execs are redacted. The session
   summary counts each detach, and the tree below the detach runs
   unredacted for the rest of its life.

Scripts and re-execs fall back to post-exec redaction: the kernel needs
the real argv to build an interpreter line, and a settled process no
longer stops at syscall entry. The kernel copies the interpreter command
line, including the script's arguments, and the real environment unless
`--keep-env`; the completion stop zeroes that region. `tests/compare.sh`
prints the duration of that window for the host it runs on.

A 32-bit program is refused, not redacted: one warning names it and the
session summary counts it. The program keeps its real arguments, because
a supervisor that cannot read 32-bit registers must not swap them.

## Privilege ladder

Higher privileges buy more privacy in defined steps. Nothing below rung
2 needs any privilege, and the effect of rung 2 is available at rung 0
because the one-shot map is not gated.

| rung | requirement | what it adds | limit |
|---|---|---|---|
| 0 | none | entry swap, label, comm, per-variable environment policy | same-uid observers read `exe`, `maps`, `fd/*`, `cwd` |
| 0 | none | the argv and environment windows moved with `prctl(PR_SET_MM_MAP)` | a kernel built without `CONFIG_CHECKPOINT_RESTORE`, or a seccomp filter denying `prctl`; `--no-exact` turns it off |
| 0 | none | `--detach`: `TracerPid` 0 for the payload | the detached process and its descendants are not redacted at later execs |
| 0 | none | `--no-dumpable` makes `environ`, `maps`, `fd/*` and `exe` refused for the same uid | core dumps and debugger attach stop |
| 0 | none | `--rexec`: `exe` names the memfd, not the file | `map_files` resolves to `/memfd:<label> (deleted)`, asserted by `tests/compare.sh`; `vm.memfd_noexec` may refuse |
| 0 | a kernel that allows unprivileged user namespaces | `--unshare`: private pid namespace and private procfs | unavailable on hosts that gate user namespaces; opportunistic by design |
| 0 | none | `--watch-rename`: comm stays the label after a self-rename | traps `prctl(PR_SET_NAME)` only; implies `no_new_privs` |
| 2 | `CAP_SYS_RESOURCE` | the bare `PR_SET_MM_ARG_START`/`_ARG_END` operations, which would resize the window without rewriting the rest of the map | not used; the one-shot map at rung 0 already reaches the same result |
| 3 | root on the host | `hidepid=2,gid=` on the system `/proc` removes the tree from every other account | polkit and distribution defaults; Yama scope needs `CAP_SYS_PTRACE`, and scope 3 lasts until reboot |

## Verification

The detection suites do not ask you to trust this README. Each detection
suite runs its battery *without* `pmask` first and requires the observer
to find the markers. A detector that cannot detect proves nothing, so the
negative control comes first. Then zero sightings under the mask,
liveness under the label, and functional checks on argv, environment,
stdio, signals and exit codes.

```sh
sh tests/run.sh      # on a host that permits ptrace
sh vm/run.sh         # anywhere: the same suites inside a QEMU micro-VM
```

`tests/run.sh` runs sixteen suites: validate, suite, stress, edge,
daemon, daemon_neg, options, core, audit, store, isolation, lease,
secrets, compare, conformance and regressions. `vm/run.sh` fetches a
pinned kernel and static busybox by sha256, builds the musl binaries,
packs an initramfs and boots it under QEMU: KVM when the host provides a
usable `/dev/kvm` for the guest architecture, TCG otherwise
(`PMASK_VM_KVM=0|1` forces the choice). It runs the staged suites twice,
as root and as uid 1000, and exits 0 only when both passes report
`FINAL: ALL-PASS`.

`measurements/` holds the speed comparison and the zapper comparison
harnesses. They are not part of the gate; run them on a quiet host and
read the conditions they print.

## Honest limits

- Root on the host sees that a pid exists and can read its memory. The
  tool removes *what* a pid is, not *that* it is.
- `cmdline` and `comm` are readable by every local account. `environ`,
  `exe`, `maps`, `fd/*` and `cwd` are readable by the same uid and root,
  unless `--no-dumpable` is set.
- `/proc/<pid>/exe`, `maps`, open files, sockets and cgroups describe
  the real binary unless `--rexec` is set. With `--rexec` the `exe` link,
  the executable map and the `map_files/<range>` entry all name
  `/memfd:<label> (deleted)`; the open files, sockets and cgroup path
  still name the real thing. When the descriptor exec is refused, the
  chain's later carriers name `/proc/self/fd/N` or a guarded temporary
  file instead. With `--exec-once`, a later exec of a program runs from a
  guarded temporary-file image on an executable mount, because the
  non-dumpable supervisor cannot hand its descriptor to the tracee; the
  file is mode 0700, sealed where the filesystem supports it, and
  removed at session end.
- Set-uid and set-gid programs do not gain privileges under supervision,
  with or without `--no-new-privs`.
- A `#!` script, a second exec in one process, and a 32-bit image take
  the post-exec path or no redaction. The script window covers the
  interpreter command line including the script's arguments and the
  environment, until the completion stop zeroes them; `tests/compare.sh`
  prints its duration.
- `AT_EXECFN` is rewritten in `saved_auxv`, so `/proc/<pid>/auxv` and
  anything reading it report the label. `getauxval(AT_EXECFN)` inside the
  payload still returns the real path, because glibc reads the vector the
  kernel copied onto the stack at startup rather than the saved copy.
- The relocating `prctl` is a single unprivileged call, but a kernel
  without `CONFIG_CHECKPOINT_RESTORE`, or a seccomp filter that denies
  `prctl`, refuses it. The label still replaces the arguments in place,
  the extent in `/proc/<pid>/stat` becomes the label plus one NUL per
  argument rather than the original byte length, and the session summary
  prints how many execs kept their extent. `pmask probe` reports the
  same thing as the `exact cmdline window` row.
- The real `argv` and environment strings live in the tracee's memory for
  the life of the process, in the injected block its own libc reads. A
  reader with `ptrace` permission over it, which means the same uid when
  the payload is dumpable, recovers them from `/proc/<pid>/mem`;
  `--no-dumpable` closes that for the same uid.
- What still tells the truth after the window moves is listed one
  interface at a time in `docs/research/detection-residue.md`, with the
  condition that reveals it in each row.
- A `literal:` secret is in pmask's own argv until the self-mask runs,
  and the kernel audit record for that exec is written before the
  self-mask. `type=EXECVE` and `type=PROCTITLE` hold the value in
  cleartext for the retention of the log. The value is also in the
  `/proc/<pid>/cmdline` of a wrapper such as `sudo` for the wrapper's
  whole life, and in the interactive shell's history file. `--args-from-fd`
  keeps the payload vector out of pmask's argv; `file:`, `agent:` and
  `stdin` sources never put the value in pmask's own argv. An `env:`
  source is in the caller's environment, which is where the shell and the
  wrapper already hold it.
- A delivered `--secret` value is absent from the payload's `cmdline`,
  `environ` and `ps`. It is still readable by the host: the payload holds
  it on an inherited descriptor whose `FD_CLOEXEC` is cleared on purpose,
  so every descendant inherits it, and `/proc/<child>/fd/<N>` names a
  sealed `memfd` that a same-uid peer can open. `--secret-close-on-exec` closes
  it in each of the payload's direct children at its fork, while the
  payload keeps it; a process that shares the payload's descriptor table
  (`clone(CLONE_FILES)` without `CLONE_THREAD`) is reported as a
  degradation. `--detach` cannot enforce the close below the payload, and
  the run warns. `--secret-burn` narrows the window to the reader's own
  `ftruncate(fd, 0)` call: the descriptor is sealed without
  `F_SEAL_SHRINK`, so the reader can truncate it once and cannot grow it
  back. It is enforced for a reader that cooperates; a reader that keeps
  a copy defeats it, and a peer that opens the memfd before the burn sees
  the value.
- The label is cut at three places: `comm` keeps 15 bytes, the exec entry
  scratch keeps 254 bytes, and the post-exec path cuts it to the argument
  area the kernel copied. A warning prints once when a label is longer
  than 254 bytes. The completion block carries the whole label, so with
  the default `PR_SET_MM_MAP` relocation `/proc/<pid>/cmdline` is the
  whole label; with `--no-exact` the visible window keeps the 254-byte
  entry copy. The kernel refuses an argument over 131072 bytes with
  `E2BIG`.
- Without `--detach`, every process of the tree carries the supervisor's
  pid in `/proc/<pid>/status` `TracerPid`, and a reader can see that the
  tree is supervised. `--detach` brings it to 0 and gives up later-exec
  coverage; the session summary counts each detach.
- A session consumes the `SIGCHLD` notifications `CLD_STOPPED`,
  `CLD_TRAPPED`, `CLD_CONTINUED` and `CLD_DUMPED` for its tracees, so a
  program that watches those codes sees fewer of them.
- Linux 5.3 or newer (`PTRACE_GET_SYSCALL_INFO`), x86-64 or aarch64.
- A masking session owns the calling process's `waitpid(-1)` domain, so
  sessions in one process are serialized.

## Prior art

`zapper` is the closest tool: it acts at the exec stop, zeroes argv and
environ in place, repairs the auxv pointers, and detaches (or follows
children with `-f`). `mimic` execs the real binary with a
fake `argv`/`envp` and injects the real arguments at `main()`. `memexec`
writes a binary to a memfd and execs it through `execveat`, so a `noexec`
mount cannot refuse the exec; it redacts nothing. `hidepid=2` is a
system-wide `/proc` policy and does not help a same-uid observer.
`setproctitle` rewrites the title in process, which on Linux shares the
area with `environ`.

`pmask`'s difference is the exec-entry swap plus the relocation of the
kernel's own windows: the program keeps its real `argv` and `environ`,
and `/proc` shows the label with no padding. The field survey in
`docs/research/survey-2025/` records the comparison, and
`measurements/vs-zapper.sh` reproduces the zapper rows on a host that has
a C compiler and network access.

## Build

Any Linux 5.3 or newer, x86-64 or aarch64, glibc or musl. Rust 1.85 or
newer (`rust-version` in `Cargo.toml`, checked by a CI job).

```sh
./build.sh            # glibc build
./build.sh --static   # static musl binaries (needs the musl target)
./build.sh --test     # also run cargo test --lib and the unwrap audit
```

Manual equivalent:

```sh
cargo build --locked --release
# static (needs: rustup target add x86_64-unknown-linux-musl):
cargo build --locked --release --target x86_64-unknown-linux-musl
# tests, unit tests and packaging:
cargo test --locked --lib
cargo package --list
```

Dependencies are pinned by `Cargo.lock`. The first build reads crates.io;
a later build with the same lock and a warm cargo cache needs no network.

Binaries: `pmask` (CLI), `pmaskd` (daemon), and, with
`--features testbins`, `pmask-testcases` and `pmask-protocases` (probes
the suites use). Copy the binaries you want to a directory on `PATH`; no
config file is read. The package also ships `man/pmask.1`,
`man/pmaskd.8` and completions for bash, zsh and fish. The systemd units
under `contrib/systemd/` use `ExecStart=/usr/bin/pmask`; for a portable
install, copy the binaries to `/usr/bin` or edit `ExecStart` to the
installed path.

## Install

Release binaries are static musl, for x86-64 and ARM64:

```sh
curl -fLO https://github.com/Azathothas/pmask/releases/latest/download/pmask-x86_64-unknown-linux-musl
chmod +x pmask-x86_64-unknown-linux-musl
./pmask-x86_64-unknown-linux-musl --version
```

Each release also has `pmaskd-<target>`, the manual pages, a tarball with
the completions and systemd units, `SHA256SUMS`, and a Sigstore
provenance bundle. Check a download with:

```sh
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify pmask-x86_64-unknown-linux-musl --repo Azathothas/pmask
```

## Repository layout

```
src/              the supervisor, the daemon, the secret side
tests/            the suites; run.sh is the native gate
vm/               QEMU micro-VM harness
measurements/     speed and zapper comparison harnesses
docs/             design, threat model, deployment, research
man/, completions/  manual pages and shell completions
contrib/          systemd units, tmpfiles.d and sysusers.d
fuzz/             the store header parser target
scripts/          the unwrap audit and release helpers
```

## License

0BSD. See `LICENSE`. Use it, ship it, no attribution required.
