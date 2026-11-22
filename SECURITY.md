# Security

## Report a vulnerability

Do not open a public issue for a vulnerability.
Open a private GitHub security advisory at <https://github.com/Azathothas/pmask/security/advisories/new>.
Include four items in your report:

- The version (`pmask --version`) and kernel (`uname -a`).
- The output of `pmask probe`.
- The exact steps that reproduce the fault.
- What an attacker gains and what access the attacker needs first.

The maintainer responds inside the private advisory.
The maintainer ships the fix in a new release and publishes the advisory after the release.

## Supported versions

Only the latest release and `main` receive security fixes.
A stable release such as `v0.1.0` replaces prior prerelease tags (tags with a suffix such as `v0.1.0-beta.5`).

## What pmask does not protect

The limit table in `README.md` defines the security contract.
Keep these boundaries in mind:

- Root on the host sees every pid and can read its memory.
- Every local account can read `/proc/<pid>/cmdline` and `/proc/<pid>/comm`.
- Same-uid observers can read `environ`, `exe`, `maps`, `fd/*`, and `cwd` unless `--no-dumpable` is set.
- Real argv and environment strings live in tracee memory. A same-uid ptrace reader recovers them unless `--no-dumpable` blocks attach.
- `--secret` runs in redact mode enable `--no-dumpable` on the payload and supervisor by default (`--allow-dumpable` opts out). When the payload is dumpable, a same-uid peer can read `/proc/<pid>/fd/N`.
- `--secret-burn` narrows the read window for a cooperating reader. A reader that retains a copy defeats truncation.
- `--detach` ends supervision after the first exec, leaving later execs unredacted.
- `#!` scripts have a short post-exec redaction window unless `--strict-exec` refuses them. Run `tests/compare.sh` to measure the window on your host.
- A `literal:` secret travels in `pmask`'s own argv until self-masking runs. The kernel audit subsystem records `type=EXECVE` and `type=PROCTITLE` before self-masking. That value persists in audit logs, wrapper `cmdline` entries such as `sudo`, and shell history.
- An `env:` secret already exists in the caller's environment. Use `file:`, `agent:`, or `stdin` to keep secrets off the command line, and use `--args-from-fd` to keep payload arguments off the command line.
- `--keep-env` exposes the full environment and `--keep-env=NAME` exposes named variables. Same-uid observers can read any secret placed in those variables.

## The daemon

`--allow-uid` permits the listed uid to run arbitrary programs with `pmaskd`'s privileges and environment.
Grant `--allow-uid` only to uids already trusted with that access.
`pmaskd` creates its socket with mode 0600 by default and authorizes clients via `SO_PEERCRED`.
The client verifies the daemon's peer uid before sending a request.
On a root daemon, pass `--run-as-uid` to run each job under the client's uid and gid.

Every local uid can see the socket path in `/proc/net/unix` and `ss -x`, even when the socket is mode 0600 inside a mode 0700 directory.
The `PING` reply returns two detail levels:

- The daemon's own uid and root receive the full policy: job slots, environment variable count, allowed uids, socket mode, timeouts, peer-identity method, and peer uid.
- Another uid admitted by `--allow-uid` receives only `protocol`, `detail=reduced`, `label`, `uid`, and `run_as_uid`.

Neither reply includes environment variable values.

## Secrets

The encrypted store uses Argon2id and XChaCha20-Poly1305 in a mode 0600 file.
`pmask agent` holds the unlocked store in memory. `pmaskd` does not open the store.
`--secret` values never enter the child's `argv` or `environ`.
The caller-side caveats listed above still apply to `literal:` and `env:` sources.
The agent's hash-chained audit record omits secret values.
Each audit line logs the timestamp, secret name, peer pid, peer executable, and lease id.
`tests/lease.sh` verifies that secret values never appear in audit records.

## Dependencies

`.github/workflows/deny.yml` runs `cargo deny` on every push and on a daily schedule.
The workflow checks advisories, licenses, bans, and sources against `deny.toml`.
Dependabot opens weekly updates for crates and GitHub Actions.
`pmask` uses the 0BSD license, and every dependency must use a permissive license.

## Known gaps

`pmask` has not undergone an external third-party security audit.
The fuzz target currently covers only the store header parser.
Supported platforms are Linux 5.3 or newer on x86-64 and aarch64.
Release artifacts ship static musl binaries for x86-64 and ARM64 only.
