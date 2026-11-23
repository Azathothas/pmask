# pmask

**Confidential execution without trusted hardware.** Run a command, binary, or job so local observers and pasted `ps` output cannot read its command line, environment, executable path, or process memory. Every program keeps its real arguments and environment and runs normally.

```sh
# Direct ELF binary: auto selects `single` (zero persistent supervisor, TracerPid: 0)
pmask --label ci-runner -- ./worker --config prod.toml

# Process tree / shell script with a secret on an open descriptor:
pmask --profile tree --label ci-runner --secret-fd 3 -- sh -c './deploy.sh' 3<token

# Isolated redaction (user/pid/mount namespaces + private /proc):
pmask --profile tee --label ci-runner -- ./worker
```

`ps`, `top`, `htop`, `/proc/<pid>/cmdline`, and `/proc/<pid>/comm` display `ci-runner`. `/proc/<pid>/environ` displays a minimal decoy environment (110 bytes by default: `PATH`, `HOME`, `LANG`, `TERM`, or the variables named by `--keep-env`). In the default profiles (`auto`, `single`, `tree`, `tee`), `pmask` also stages native ELFs via `--rexec` (`--rexec-mode=auto`, preferring a private `0500` path with zero `/memfd:` fingerprint), sets `PR_SET_DUMPABLE=0` (denying same-uid reads of `environ`, `maps`, `auxv`, `exe`, `fd`, `cwd`, and `/proc/<pid>/mem` with `EACCES`), and encrypts supervisor at-rest copies.

> **Honest scope:** `pmask` is designed for **9+/10 confidentiality and low-residue execution against a same-uid local observer, not root**. Root on the host, `CAP_SYS_PTRACE`, kernel modules, eBPF/perf tracers, hypervisors, and hardware enclaves are explicitly out of scope. Run `pmask --explain` to inspect your host capabilities, hidden surfaces, `EACCES` tradeoffs, and residuals. See [`docs/PROFILES.md`](docs/PROFILES.md) for the full profile guide, audit invariants (`INV-1..INV-10`), and `psgen` integration contract.

## Why

Confidential computing usually requires a Trusted Execution Environment (TEE) such as AMD SEV-SNP, Intel TDX, ARM CCA, or SGX enclaves. TEEs protect memory against the host, but require specialized hardware, hypervisor or guest OS support, attestation infrastructure, and often rewritten workloads.

Most machines lack TEE hardware. A self-hosted CI runner, a shared build host, a lab box, a container, a laptop, or a VPS has no TEE—yet secrets still run on these machines. The primary leak in those environments is `/proc`:

```sh
$ ps -eo user,args | grep deploy
ci     ./deploy.sh --token ghp_9f3c... --env prod
```

Other local users read command-line arguments through `ps`, same-uid agents can read `/proc/<pid>/environ`, `exe`, `maps`, `fd/*`, `cwd`, and `/proc/<pid>/mem`, and audit subsystems capture exec arguments. `pmask` closes these `/proc` surfaces on standard Linux hardware as an unprivileged user.

## Execution profiles

`pmask` v0.2.0 organizes redaction into five profiles via `--profile NAME` (full comparison in [`docs/PROFILES.md`](docs/PROFILES.md)):

| profile | behavior | `TracerPid` / supervisor | defaults |
|---|---|---|---|
| `auto` (default) | Selects `single` for direct native ELF binaries; `tree` for shells, launchers, `#!` scripts, and tree flags | `0` (none) for ELFs; `Threads: 1` supervisor for trees | `--rexec` (`--rexec-mode=auto`), `--no-dumpable`, `--encrypt-memory` |
| `single` | In-place masked `execve`/`execveat` via a transient double-forked helper that detaches and exits immediately | **`TracerPid: 0`**, **zero persistent supervisor**, `Threads: 1`, `Seccomp: 0`, `NoNewPrivs: 0` | `--rexec` (`auto`), `--no-dumpable`, `--encrypt-memory`; optional `--reparent` |
| `tree` | Single-threaded (`Threads: 1`) supervisor following forks, shells, `#!` scripts, and all descendants | supervisor pid in `TracerPid` (use `--parent-label` to avoid a label twin) | `--rexec` (`auto` for ELFs), `--no-dumpable`, `--encrypt-memory` |
| `tee` | Redaction composed with user, pid, and mount namespaces + private `/proc` (and private `/tmp`) | fails closed if unprivileged user namespaces are unavailable | `--rexec` (`auto`), `--no-dumpable`, `--encrypt-memory`, namespaces |
| `compat` | Legacy `v0.1.0` flag-driven defaults (metadata-only, dumpable unless `--no-dumpable` or `--secret`) | `Threads: 1` supervisor (`0` with `--detach`) | opt-in `--rexec`, `--no-dumpable`, `--encrypt-memory` |

### Self-audit, explain, and `psgen` export

```sh
# 1. Inspect host capabilities, observer scope, EACCES tradeoff, and residuals:
pmask --explain --profile single --label ci-runner

# 2. Live self-audit (launches a masked child with a synthetic heap token,
#    probes every /proc surface + full-VMA /proc/<pid>/mem scan against INV-1..INV-10):
pmask --audit --json

# 3. Audit an existing masked PID (pass secret via --token-env or --token-fd, never argv):
pmask --audit --pid "$PID" --profile single --label ci-runner --token-fd 4 --json

# 4. Export versioned pmask-profile/1 JSON for psgen (never emits raw secret bytes):
pmask --profile-json --pid "$PID" --profile single --label ci-runner > profile.json
```

## What pmask is not (and the `EACCES` tradeoff)

`pmask` is not a TEE and does not encrypt payload heap/stack memory. The table defines the exact trust boundary:

| observer | sees |
|---|---|
| another unprivileged uid | the label in `cmdline` and `comm`, with no real `argv`, `environ`, `exe`, `maps`, `fd`, `cwd`, or `mem` |
| same-uid observer, default profiles (`auto` / `single` / `tree` / `tee`) | the label in `cmdline` and `comm`. `PR_SET_DUMPABLE=0` denies **seven** `/proc` surfaces (`environ`, `maps`, `auxv`, `exe`, `fd`, `cwd`, and `/proc/<pid>/mem`) with `EACCES`, and Linux zeroes `/proc/<pid>/stat` fields 48–51 (`arg_start`..`env_end`). Those `EACCES` refusals are themselves an observable denial signal; use a helper uid / subuid namespace (`--profile tee` with subuid) or `pmaskd` under a dedicated uid to eliminate same-uid `EACCES` |
| same-uid observer, `--profile compat` or `--allow-dumpable` | the label and minimal decoy `environ`, plus `exe`, `maps`, `fd/*`, `cwd`, and real `argv`/`environ` in `/proc/<pid>/mem` (unless `--rexec` hides `exe`/`maps`) |
| same-uid observer, `--stealth` | on `hidepid=0`, the label plus `--rexec`, `--watch-rename`, and `--no-dumpable`. On `hidepid=invisible` or `hidepid=ptraceable`, keeps the tree dumpable to avoid creating a hidden pid, so same-uid `environ` and memory reads stay open |
| same-uid observer, `--hide-pid` | the pid disappears from same-uid `/proc` `readdir` and `stat` on `hidepid=invisible` or `hidepid=ptraceable` (`EPERM` on existing inode under `ptraceable`). `cgroup.procs`, `cgroup.threads`, `kill(0)`, `pidfd_open`, `sched_getaffinity`, `getpriority`, `prlimit`, and root still see the pid |
| `ps` output pasted into a ticket or chat | the label |
| root / `CAP_SYS_PTRACE` on the host | **that** a pid exists, its `/proc/<pid>/exe`, `maps`, open files, cgroups, and memory via `PTRACE_ATTACH` |
| kernel modules, eBPF/perf, hypervisor | everything (out of scope) |

Network identity is outside the mask: `ss -tnp`, `lsof`, and `/proc/net/tcp` report real sockets under the label. Add `--isolate=net` to place the payload in a private network namespace.

`cmdline` and `comm` require no ptrace check, so every local account reads them. `environ`, `maps`, `auxv`, `exe`, `fd/*`, `cwd`, and `mem` require `PTRACE_MODE_READ_FSCREDS`, which a same-uid process passes even under Yama `ptrace_scope=1` (Yama restricts `PTRACE_MODE_ATTACH` only). `PR_SET_DUMPABLE=0` blocks those seven same-uid surfaces.

Run `pmask probe` to report each host mechanism as `active`, `degraded`, or `unavailable`, and `pmask doctor --require redact,exact` (exits `0` active, `3` degraded, `4` unavailable) in CI before running secrets.

## Three ways to use pmask

### 1. CLI: run one command under a profile and label

```sh
# Direct native ELF (auto -> single: zero persistent supervisor, TracerPid: 0)
pmask --label 'ci-runner' -- ./worker --env prod

# Process tree / shell script (auto -> tree)
pmask --label 'ci-runner' -- ./deploy.sh --env prod

# Wrap a full interactive shell session:
exec pmask --profile tree --label 'dev-shell' bash --login -i
```

Run `pmask --help` for the concise one-screen summary, `pmask --help=all` for the complete flag reference, or `pmask help <topic>` (`profiles`, `redact`, `secrets`, `isolate`, `daemon`, `audit`, `report`, `short`, `all`).

Key options:

| option | effect |
|---|---|
| `--profile auto\|single\|tree\|tee\|compat` | selects execution and stealth profile (default `auto`; `--auto` is an alias) |
| `-l, --label NAME` | sets presented `cmdline` and `comm`. Kernel-thread `[...]` and critical daemon names (`sshd`, `systemd`, `cron`, etc.) require `--allow-impersonation` (exit 2) |
| `--comm NAME` | sets `comm` separate from the label (up to 15 bytes; subject to impersonation policy) |
| `--parent-label NAME` | sets a separate label for the `tree`-mode supervisor so parent and payload are not label twins |
| `--reparent` | in `single` profile, double-forks the masked payload to PID 1 (or nearest subreaper) and returns 0 once masked exec detaches |
| `--cwd PATH` | changes the child's working directory after resolving `COMMAND`, normalizing `/proc/<pid>/cwd` |
| `--rexec`, `--rexec-mode auto\|path\|memfd`, `--no-rexec` | executes from a staged image (`auto` prefers a private `0500` file in a `0700` dir for zero `/memfd:` fingerprint, falling back to sealed `memfd` on `noexec` mounts). Enabled by default in `single`, `tree`, and `tee` for native ELFs (`--no-rexec` opts out). Fails closed (126/127) unless `--rexec-allow-disk` is passed |
| `--secret-fd [NAME=]N` | preserves caller-opened fd `N` across exec at its existing number and exports `PMASK_SECRET_FD=N` or `PMASK_SECRET_<NAME>=N`. Enables `--no-dumpable` unless `--allow-dumpable` is passed |
| `--secret NAME=SRC` | delivers a secret on sealed memfd 3, 4, ... (`file:PATH`, `env:VAR`, `agent:NAME`, `stdin`, `literal:VAL`) and exports `PMASK_SECRET_<NAME>=<fd>`. Pair with `--secret-burn`, `--secret-close-on-exec`, `--secret-fd-name NAME` |
| `--args-from-fd N` | reads a NUL-separated command vector (up to 8 MiB) from fd `N`, keeping secrets off `pmask`'s argv and shell history |
| `--keep-env`, `--keep-env=NAME[,...]` | leaves `environ` visible in full or only for named variables. Inline `=` is required for variable lists; space form `--keep-env NAME cmd` fails fast with exit 2 |
| `--env K=V`, `--env-file PATH` | sets variables in the child's real environment |
| `--no-dumpable`, `--allow-dumpable` | toggles `PR_SET_DUMPABLE=0` (blocks seven same-uid `/proc` surfaces: `environ`, `maps`, `auxv`, `exe`, `fd`, `cwd`, `mem`). Default on in `single`, `tree`, `tee`, and `--secret`/`--secret-fd` runs; `--allow-dumpable` opts out |
| `--encrypt-memory` | seals supervisor at-rest `argv`/`environ` with XChaCha20-Poly1305 under a `memfd_secret` key (or `mlock`'ed heap) and marks the payload's anonymous redaction block `MADV_DONTDUMP`. Default on in `single`, `tree`, and `tee`; opt-in in `compat` |
| `--follow`, `--no-follow`, `--on-exit detach\|wait\|kill`, `--detach` | controls descendant supervision and exit policy in `tree`/`compat` modes |
| `--watch-rename[=strict]` | traps `prctl(PR_SET_NAME)` and `/proc/.../comm` opens (plus write syscalls under `=strict`) to keep `comm` at the label. Implies `--no-new-privs`, defaults `--on-exit` to `wait`, and refuses `--detach`, `--on-exit detach`, and `--profile single` |
| `--strict-exec`, `--allow-foreign` | `--strict-exec` refuses `#!` scripts, `vfork`, and post-exec fallbacks with `SIGKILL`; 32-bit images are refused by default unless `--allow-foreign` is set |
| `--stealth`, `--hide-pid` | `--stealth` composes `--rexec`, `--watch-rename`, and hidepid-aware `--no-dumpable`; `--hide-pid` hides pids on `hidepid=invisible\|ptraceable` mounts |
| `--isolate[=LIST]`, `--unshare`, `--redact`, `--no-redact` | namespace isolation (`pid`, `net`, `tmp`, `all`, `none`) and redaction mode controls |
| `--explain`, `--profile-json`, `--audit` | host/profile explainer, `pmask-profile/1` JSON exporter for `psgen`, and standalone self/PID `/proc` + `/proc/<pid>/mem` invariant auditor (`INV-1..INV-10`; also `--pid`, `--observer`, `--json`, `--token-env`, `--token-fd`, `--real-exe`, `--real-cwd`, `--allow-memfd`) |
| `--report=json`, `--report-file PATH`, `--report-fd N` | structured run report (`json` only; use `--report-file` or `--report-fd` to keep payload stdout clean; refused with `--daemon` and explicit `--profile single`) |
| `--image PATH`, `--image-from-fd N`, `--exec-once`, `--hugetlb`, `--memfd-name NAME`, `--scope-name NAME`, `--no-exact`, `--no-new-privs`, `--argv0 NAME` | advanced image loading, caching, systemd scope wrapping, and window/privilege controls (see `man pmask.1`) |

### 2. Library: supervise from your own program

```toml
[dependencies]
pmask = { git = "https://github.com/Azathothas/pmask", tag = "v0.2.0" }
```

```rust
use pmask::Mask;

let st = Mask::new()
    .label("ci-runner")
    .run("/usr/bin/deploy", &["--token", "SECRET"])?;
println!("exit: {} ({} of {} execs degraded)", st.code, st.stats.degraded, st.stats.execs);
```

`Mask` is a builder (`Mask::run` supervises on the calling thread; `Mask::spawn` returns a `MaskedChild` on a dedicated tracer thread). For zero-supervisor in-place masking from Rust, call `pmask::single::exec_single` / `exec_single_with`. For programmatic auditing and profile export, use `pmask::audit` (`audit_pid`, `export_profile_for_pid`, `render_explain`).

### 3. Daemon: keep the secret out of the caller

CI runners often need a secret token without holding it in the runner's own memory or environment. Run `pmaskd` (optionally under a dedicated service uid, which also removes same-uid `EACCES` signals):

```sh
# as the service/runner user, once:
cat > ~/.config/pmask/runner.env <<'EOF'
CI_TOKEN=ghp_...
EOF
chmod 600 ~/.config/pmask/runner.env

pmaskd --label ci-runner --env-file ~/.config/pmask/runner.env \
    --socket "$XDG_RUNTIME_DIR/pmask.sock"

# the runner, for every job:
pmask --daemon "$XDG_RUNTIME_DIR/pmask.sock" -- ./deploy.sh --env prod
```

`pmaskd` authorizes peers through `SO_PEERCRED` (its own uid, root, and `--allow-uid`) and pins each peer via `SO_PEERPIDFD` (Linux 6.5+) or `/proc` pid and start time, failing closed if neither succeeds. `pmaskd` loads job environments via `--env-file` only (it does not accept `--store` or `--passphrase-file`; the encrypted store belongs to `pmask agent`).

`--daemon` refuses local-only flags that the daemon cannot honor: `--secret`, `--secret-fd`, `--isolate`, `--no-redact`, `--hide-pid`, `--encrypt-memory`, `--image`, `--image-from-fd`, `--report*`, `--profile single`, and `--profile tee` (exit 255). Other mask options besides `--label` and `--label-empty` emit one warning and have no effect.

**Warning:** Any allowed uid can execute arbitrary programs with the daemon's privileges and environment. Grant `--allow-uid` only to trusted uids. On a root daemon, pass `--run-as-uid` to run each job under the client's uid and gid.

## Secret delivery without a daemon: `--secret-fd` and `--secret`

- **`--secret-fd [NAME=]N`** keeps an already-open caller descriptor `N` open across exec (clearing `FD_CLOEXEC`) and exports `PMASK_SECRET_FD=N` (unnamed) or `PMASK_SECRET_<NAME>=N` (named) in the payload's real environment. Because the secret never passes through `pmask`'s `argv` or `environ`, nothing enters shell history or kernel `EXECVE` audit records.
- **`--secret NAME=SRC`** loads a secret from `file:PATH`, `env:VAR`, `agent:NAME`, `stdin`, or `literal:VALUE` into a sealed memfd on descriptor 3, 4, ... and exports `PMASK_SECRET_<NAME>=<fd>`. Inside the payload, read the descriptor directly or run `pmask read NAME`.

Use `--secret-fd`, `file:`, `agent:`, or `stdin` (plus `--args-from-fd` for sensitive arguments) so secrets never appear in `pmask`'s own `argv`, shell history, or kernel audit logs (`type=EXECVE`, `type=PROCTITLE`). In redaction modes, both `--secret-fd` and `--secret` enforce `--no-dumpable` by default (`--allow-dumpable` opts out).

## Modes: what each mode redacts

Underneath the profiles, `pmask` selects one of three execution modes:

| mode | selected by | redacts | does not |
|---|---|---|---|
| `redact` | default when the host permits `ptrace`, or `--redact` | `cmdline`, `comm`, `environ`, and `AT_EXECFN` (plus `exe`/`maps` under `--rexec` and seven same-uid `/proc` surfaces under `--no-dumpable`) | network sockets (`/proc/net/tcp`), cgroups, and root/kernel inspection |
| `isolate` | `--isolate[=LIST]`, or `--no-redact --isolate` | nothing: the payload keeps its real `cmdline`, `comm`, and `environ` inside fresh namespaces | adds private `hidepid=invisible` procfs and `NSpid` chain |
| `plain` | `--no-redact`, or a host denying `ptrace` on the runner path | nothing | prints `mode=plain` and runs as an ordinary process |

`--profile tee` (and `--redact --isolate=LIST`) composes `redact` with namespaces; `--profile tee` fails closed if unprivileged user namespaces are unavailable. Plain and isolate modes report every unapplied tracer-only flag in stderr notes and `--report=json`, and fail closed on `--audit`, `--hide-pid`, `--encrypt-memory`, `--image`, `--image-from-fd`, and `--secret-close-on-exec` (when a secret is delivered).

## How pmask works

1. **In-place single-process engine (`single` profile, default for direct ELFs).** A transient double-forked helper grants `PR_SET_PTRACER` (compatible with `yama.ptrace_scope=1`), seizes `pmask`, intercepts the `execve`/`execveat` entry and completion stops, completes the redaction, unlinks any staged `--rexec-mode=path` carrier, and immediately detaches and exits. The payload runs in place with `TracerPid: 0`, `Threads: 1`, `Seccomp: 0`, and `NoNewPrivs: 0`.
2. **Single-threaded process-tree supervision (`tree`, `tee`, `compat`).** `PTRACE_O_TRACE{FORK,VFORK,CLONE,EXEC,EXIT}` auto-attaches children, grandchildren, threads, `posix_spawn()`, `system()`, double-forking daemons, static binaries, Go runtimes, and `#!` scripts from a single-threaded supervisor (`Threads: 1`), with no `LD_PRELOAD` and no libc requirement.
3. **Exec-entry pointer swap for zero exposure.** At `execve`/`execveat` entry, the tracer replaces the old image's `argv`/`envp` pointer arrays with the label and filler strings so the kernel never copies the real command line into the new image of an ELF target.
4. **Batched exec-completion restoration & `[stack]` relocation.** At `PTRACE_EVENT_EXEC`, the tracer writes the real strings into an anonymous `MADV_DONTDUMP` mapping in the tracee, repoints the stack's inline `argv`/`envp` arrays, sets `comm` via `prctl(PR_SET_NAME)` through an existing syscall gadget (never W+X), installs a 110-byte decoy `environ` (or `--keep-env` entries), rewrites `AT_EXECFN` in both `saved_auxv` and the stack auxiliary vector, and relocates `arg_start..env_end` inside `[stack]` with one unprivileged `prctl(PR_SET_MM, PR_SET_MM_MAP)`.
5. **Same-uid protection and job control.** `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` block same-uid reads across seven `/proc` surfaces and disable core dumps. `PTRACE_LISTEN` preserves job control (`Ctrl-Z`, `SIGSTOP`, `SIGCONT`) inside masked shells.

Scripts (`#!`), `vfork` children, and settled re-execs take the post-exec path unless `--strict-exec` refuses them. 32-bit images are refused before execution unless `--allow-foreign` is set.

## What a defender still sees

`pmask` rewrites `/proc` content, not the kernel process table. Measured details live in [`docs/PROFILES.md`](docs/PROFILES.md), [`docs/research/detection-residue.md`](docs/research/detection-residue.md), [`docs/DETECTION-AUDIT.md`](docs/DETECTION-AUDIT.md), and [`docs/REDTEAM-RESULTS.md`](docs/REDTEAM-RESULTS.md).

| signal | what it shows | when |
|---|---|---|
| `EACCES` denial + zeroed `stat` 48–51 | Same-uid reads of `environ`, `maps`, `auxv`, `exe`, `fd`, `cwd`, and `mem` return `EACCES`; `/proc/<pid>/stat` fields 48–51 read `0 0 0 0` | default in `single`, `tree`, `tee`, and `--no-dumpable` runs. Avoidable by crossing a uid boundary (helper uid / subuid / dedicated `pmaskd` uid) |
| supervisor & `TracerPid` | single-threaded (`Threads: 1`) parent supervisor and non-zero `TracerPid` | `tree`, `tee` (host view), and `compat` modes. **Absent in `single` profile** (`TracerPid: 0`, zero persistent supervisor) |
| staged `exe` carrier | private `0500` staged file path (`--rexec-mode=path`, zero `/memfd:` tell) or `/memfd:<name> (deleted)` (`--rexec-mode=memfd`) | `--rexec` (default for ELFs in `single`, `tree`, `tee`; hidden by `EACCES` from same-uid observers when non-dumpable) |
| decoy `environ` window | minimal 110-byte decoy environment (`PATH`, `HOME`, `LANG`, `TERM`), or `--keep-env` entries | readable when dumpable (`compat` or `--allow-dumpable`) |
| seccomp status fingerprint | `NoNewPrivs: 1` and `Seccomp_filters` delta above host baseline | `--watch-rename`, `--exec-once` (with wait/kill), `--stealth`. **Zero added filters in `single` and default `tree`** |
| launch window & audit log | sub-millisecond window on `#!` scripts / `vfork`; kernel audit `EXECVE`/`PROCTITLE` captures `pmask`'s own `argv` if `literal:` secrets are passed | use `--secret-fd` / `--args-from-fd` / `file:` / `agent:` and `--strict-exec` to eliminate |

## Verification

```sh
sh tests/run.sh      # native gate (on a host that permits ptrace)
sh vm/run.sh         # micro-VM gate (QEMU, root and uid 1000 passes)
pmask --audit        # instant live self-audit (INV-1..INV-10)
```

Every detection suite verifies a negative control (detecting markers without `pmask`), requires zero sightings under `pmask`, checks process liveness under the label, and verifies `argv`, environment, stdio, signals, and exit codes.

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
# unit tests:
cargo test --locked --lib
```

The build produces `pmask` (CLI) and `pmaskd` (daemon). Passing `--features testbins` also builds `pmask-testcases` and `pmask-protocases` for the test suites. The repository ships `man/pmask.1`, `man/pmaskd.8`, shell completions for bash, zsh, and fish, and systemd units under `contrib/systemd/`.

## Install

`pmask` is distributed through **GitHub Releases only** (not crates.io) as static musl binaries for `x86_64` and `aarch64`.

Download the latest release:

```sh
curl -fLO "https://github.com/Azathothas/pmask/releases/latest/download/pmask-x86_64-unknown-linux-musl"
chmod +x pmask-x86_64-unknown-linux-musl
./pmask-x86_64-unknown-linux-musl --version
```

Pin a specific release tag:

```sh
V=v0.2.0
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
src/                single-process engine, tree supervisor, audit/profile engine, daemon, secret side
tests/              test suites and QA fragments; run.sh is the native gate
vm/                 QEMU micro-VM harness
measurements/       speed and zapper comparison harnesses
evidence/           raw logs for measurements and detection audits
docs/               PROFILES.md, DESIGN.md, THREAT-MODEL.md, DEPLOY.md, INTEGRATION.md, audits, releases/
man/, completions/  manual pages and shell completions (bash, fish, zsh)
contrib/            systemd units, tmpfiles.d and sysusers.d
fuzz/               store header parser fuzz target
scripts/            CI guards and verify.sh
```

## License

0BSD. See `LICENSE`. Use and distribute `pmask` without attribution.
