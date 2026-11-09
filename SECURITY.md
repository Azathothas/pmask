# Security

## Report a vulnerability

Do not open a public issue for a vulnerability. Use the private report
of GitHub: open <https://github.com/Azathothas/pmask/security/advisories/new>
and include:

- the version (`pmask --version`) and the system (`uname -a`);
- the output of `pmask probe`;
- the steps that show the fault;
- what an attacker can do, and what the attacker must have first.

The maintainer replies in the report. A fix comes in a new release, and
the report becomes a public advisory after the release.

## Supported versions

Only the latest release and `main` get fixes. A prerelease (a tag with a
suffix, for example `v0.1.0-beta.1`) is replaced by the next release.

## What pmask does not protect

The limit table in `README.md` is the contract. In particular:

- Root on the host sees that a pid exists and can read its memory.
- `cmdline` and `comm` are readable by every local account.
- `environ`, `exe`, `maps`, `fd/*` and `cwd` are readable by the same uid
  unless `--no-dumpable` is set.
- The real argv and environment live in the tracee's memory; a same-uid
  ptrace reader recovers them.
- A `--secret` descriptor is readable through `/proc/<pid>/fd/N` unless
  the payload is non-dumpable. `--secret-burn` narrows the window for a
  reader that cooperates; a reader that keeps a copy defeats it.
- `--detach` gives up later-exec coverage.
- A `#!` script has a post-exec window. `tests/compare.sh` prints its
  duration on the host that runs it.
- A `literal:` secret travels in pmask's own argv until the self-mask
  runs, and the kernel audit subsystem writes the exec record
  (`type=EXECVE` and `type=PROCTITLE`) before that point. The value stays
  in the audit log for the retention of the log, in the
  `/proc/<pid>/cmdline` of a wrapper such as `sudo` for the wrapper's
  life, and in the interactive shell's history file. An `env:` source is
  in the caller's environment, which the shell and the wrapper already
  hold. `file:`, `agent:` and `stdin` keep the value out of the command
  line, and `--args-from-fd` keeps the payload's argument vector out of
  it.
- `--keep-env` re-exposes the whole environment and `--keep-env=NAME`
  re-exposes the named values. A secret in either is readable by the same
  uid.

## The daemon

`--allow-uid` lets that uid execute arbitrary programs with the daemon's
privileges and inherit its environment. Grant it only to uids that may
already do that. The socket is mode 0600; authorisation is
`SO_PEERCRED`; the client checks the peer uid of the socket it connected
to. On a root daemon, `--run-as-uid` runs each job with the client's own
uid and gid.

The socket path is visible in `/proc/net/unix` and `ss -x` to every uid,
even when the node is 0600 inside a 0700 directory and connecting is
refused. The PING reply describes the running configuration to any uid
the daemon authorises: it carries counts and policy, never environment
values.

## Secrets

The store is Argon2id + ChaCha20-Poly1305, mode 0600. `pmask agent`
holds the unlocked store, not `pmaskd`. `--secret` values never enter the
child's argv or environ; the descriptor caveat above applies. The
caller's side is separate: a `literal:` value is in pmask's own argv and
in the audit log and the shell history, as listed under what pmask does
not protect. The log masking is asserted by a test.

## Dependencies

`.github/workflows/deny.yml` runs `cargo deny` on each push and each day:
advisories, licenses, bans and sources (`deny.toml`). Dependabot opens
crate and action updates weekly. The crate is 0BSD and every dependency
must be permissive.

## Known gaps

No third-party audit. The fuzz target covers the store header only.
Linux 5.3 or newer, x86-64 or aarch64. The release binaries are static
musl for x86-64 and ARM64; the other architectures are not shipped.
