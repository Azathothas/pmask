# Issue 45: named kernel objects (`/memfd:<label>`, `/memfd:pmask-secret`)

Host: Debian 13, kernel `6.12.113+deb13-amd64`, uid 1000, LXC container.
Binary: built from this branch at `812b15d` (`pmask 0.1.0-beta.1`).
Raw captures: `baseline.log` (qa-base + `d2f331a`), `after.log` (this branch).

## What was measured before the change (`baseline.log`)

| mode | observation |
| --- | --- |
| `--secret TOK=literal:XYZZY123` | `/proc/<payload>/fd/3 -> /memfd:pmask-secret (deleted)`; 1 host-wide sweep hit |
| `--rexec -l sshd` | `/proc/<payload>/exe = /memfd:sshd (deleted)`; 3 executable maps segments from the same inode |
| `--image PATH` without `-l` | `/proc/<payload>/exe = /memfd:testcases (deleted)` |
| `--exec-once` later exec | carrier is `/dev/shm/.pmask-rexec-<label>-<pid>-<n>` (the fault hook forces the named form) |
| `--audit` | the payload row's fd list names `3:/memfd:pmask-secret (deleted)` |

The default name is a pmask-specific literal with no benign user, so a
host-wide `for l in /proc/[0-9]*/fd/*; do readlink "$l"; done` finds every
`--secret` delivery of the build.

## What the change does

Two options, both defaulting to the previous behaviour, so nothing is
removed:

* `--secret-fd-name NAME` — the memfd behind every delivered secret
  (`src/mem.rs` `SealedFd::new_named`, threaded through
  `Delivery::with_mode_named` in `src/secret.rs` and `src/run.rs`).
* `--memfd-name NAME` — the image memfd for `--rexec`, `--image`,
  `--image-from-fd`, `--exec-once` and `--hugetlb`, and the tag of the
  temporary-file carrier (`src/rexec.rs` `Options::memfd_name`).

The name is validated by one function, `mem::validate_memfd_name`: not
empty, at most 200 bytes, no `/`, no NUL, no LF, no CR. The CLI validates
at parse time (before the fork) and `create_image`/`SealedFd::create`
validate again, so a library caller cannot inject a name that would corrupt
the `/memfd:` link or split a temporary-file name into two components.

The `--exec-once` carrier name also gained a per-create 32-bit random tag:
`.pmask-rexec-<tag>-<pid>-<run>-<n>`. Two carriers of one session, and two
sessions with the same pid on a host that recycles pids, no longer share a
name (the `O_EXCL` open still decides the race).

## What was measured after the change (`after.log`)

```
default:  path=/memfd:pmask-secret (deleted)
named:    path=/memfd:secret-deadbeef (deleted)
default sweep while alive: 1 link(s)
named sweep while alive:   0 link(s)
--rexec -l sshd:                     exe=/memfd:sshd (deleted)
--rexec -l sshd --memfd-name image-1a2b3c4d:
                                     exe=/memfd:image-1a2b3c4d (deleted), 4 maps hits
--image PATH --memfd-name blobs-...: exe=/memfd:blobs-9f8e7d6c (deleted)
--exec-once carrier tag:             /dev/shm/.pmask-rexec-image-1a2b3c4d-<pid>-<run>-0
```

Validation (all `rc=255`, message names the reason): empty, `a/b`, `a\nb`,
`a\rb`, 201 bytes. A 200-byte name is accepted and carried whole.

## Residual

* `--secret-fd-name` and `--memfd-name` are cosmetic by design: they change
  the string a reader sees, not the fact that a memfd backs the descriptor
  or the image. `/proc/<pid>/exe` still reads `/memfd:... (deleted)` with
  `--rexec`, and `/proc/<pid>/maps` still shows the memfd inode.
* The supervisor's own `memfd_secret` buffer is created with
  `memfd_secret(0)` — no name is passed, and the kernel names it
  `/secretmem`. Neither option can change it; `memfd_secret(2)` takes only
  flags. It is also not readable through `/proc/<pid>/mem`, so its name is
  the whole disclosure.
* `--secret-close-on-exec` is still not the default; a descendant can
  still find the descriptor by number (`PMASK_SECRET_<NAME>=<fd>`). That
  is issue #45's own "suggested fix direction 2" and is not changed here:
  making it the default removes a documented behaviour.
* `--no-dumpable` still removes the whole `/proc/<pid>/fd` sweep for
  same-uid observers.
* The temporary-file carrier is still a path a reader can see while the
  session runs (`--exec-once`, and the `--rexec` fallback when a kernel
  refuses the memfd exec). Its name now follows `--memfd-name`, but its
  existence is a separate disclosure that only memfd execs avoid.

## QA fragment

`tests/qa.d/45.sh` — 17 cases, all PASS on this host:

```
PASS q1-default-secret-fd-name (/memfd:pmask-secret)
PASS q1b-control-sweep-sees-pmask-secret (hits=1)
PASS q2-secret-fd-name (secret-deadbeef)
PASS q2a-no-default-literal-left
PASS q2b-sweep-finds-no-pmask-secret (hits=0)
PASS q2c-payload-read-the-secret (bytes=8)
PASS q3-rexec-memfd-name (/memfd:image-1a2b3c4d (deleted), maps=4)
PASS q3b-control-rexec-default-name (/memfd:qa45-label (deleted))
PASS q4-image-memfd-name (/memfd:image-1a2b3c4d (deleted))
PASS q5-exec-once-carrier-tag
PASS q6a..q6f name validation
PASS q7-200-byte-name-accepted
== QA45: PASS
```

`tests/conformance.sh` still passes (`secret-fd-is-memfd
link=/memfd:pmask-secret (deleted)`, 21 PASS / 0 FAIL / 3 SKIP) and
`tests/daemon.sh`'s `d7-cli-memfd-backing` is unaffected: the default is
the old literal.
