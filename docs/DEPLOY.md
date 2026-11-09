# Deployment

Three shapes, in increasing order of what an attacker has to do. Pick the
one the host allows, and read `docs/THREAT-MODEL.md` for the row each one
closes.

Everything here is a statement about what the code in this tree does. The
units under `contrib/` were written against that code, and the two
directives that would break this workload are called out below.

## 1. One account, no privilege

The default. Nothing needs a capability.

```sh
pmask store init --passphrase-file ~/.config/pmask/pass
pmask store set DEPLOY_TOKEN < token.txt
pmask run --label ci-runner \
    --secret DEPLOY_TOKEN=agent:DEPLOY_TOKEN \
    -- ./deploy.sh
```

Two things to know before relying on this:

- `pmask agent` must be running for an `agent:` source, and it must own
  a directory it created. With `XDG_RUNTIME_DIR` set to a directory this
  account owns at `0700`, that is `$XDG_RUNTIME_DIR/pmask.sock`. The
  agent refuses a socket in a directory owned by another account.
- The supervisor holds the value for the life of the run. `--secret-burn`
  lets the payload destroy it once it has read it, and a lease
  (`PMASK_AGENT_LEASE`) bounds how long the agent will serve it.

What this shape does not close: another process of the same account can
open `/proc/<payload>/fd/3` and read the value, because the payload is
dumpable after `exec`. `--no-dumpable` closes that for the payload at the
cost of the payload's own ability to debug itself. The run report's
`payload_dumpable` describes the payload's `PR_GET_DUMPABLE`, not the
flag: it is `true` in plain and isolate modes even with `--no-dumpable`,
because those modes do not apply the flag, and the run says so in a note.

## 2. A dedicated holder account

Move the secret to a uid the workload does not share, and let DAC do the
work. This is the cheapest real improvement, and it needs `CAP_SETUID`
once, at setup.

```sh
# as root, once
useradd --system --no-create-home --shell /usr/sbin/nologin pmask
install -d -m 0700 -o pmask -g pmask /var/lib/pmask
install -d -m 0700 -o pmask -g pmask /run/pmask
sudo -u pmask pmask store init --passphrase-file /etc/pmask/pass
sudo -u pmask pmask agent --store /var/lib/pmask/store.enc \
    --passphrase-file /etc/pmask/pass --socket /run/pmask/pmask.sock
```

`/run` is a tmpfs, so the `/run/pmask` directory has to be recreated at
every boot: a `tmpfiles.d` entry of your own, or a unit with
`RuntimeDirectory=pmask`, does it. Without the directory the agent's
`mkdir` fails with `EACCES` and it refuses to bind.

The workload then runs as its own account and asks the agent for the
value over the socket. A same-account peer of the workload can no longer
read the holder's memory, because it is not the same account.

What this does not close: root, and any process of the holder's account.

## 3. A systemd unit with `ProtectProc=invisible`

This is the shape that does the most, and almost none of it is pmask.
A service with its own procfs instance does not see other accounts'
processes at all.

The daemon unit, `pmaskd@.service`, sets `DynamicUser=yes`: the daemon
runs as a uid nobody else has, and `RuntimeDirectory=pmask` creates
`/run/pmask` at `0700` owned by that user, which is the ownership check
`pmaskd` makes before it binds.

The payload unit, `pmask-run@.service`, does **not** set `User=` or
`DynamicUser=`. It runs as the unit's default user, which is root. That
is deliberate: the example payload reads `/usr/local/bin/job.sh` and a
credential, and it may need the caller's files. If the payload should be
unprivileged, add `User=` or `DynamicUser=yes` to that unit and make the
payload's files readable by that account.

```sh
install -D -m 0644 contrib/systemd/pmaskd@.service /etc/systemd/system/
install -D -m 0644 contrib/systemd/pmask-run@.service /etc/systemd/system/
install -D -m 0644 contrib/tmpfiles.d/pmask.conf /usr/lib/tmpfiles.d/
systemd-tmpfiles --create
systemctl daemon-reload
systemctl enable --now pmaskd@default.service
systemctl start pmask-run@ci-runner
```

`pmaskd@.service` is `Type=simple`, because `pmaskd` does not call
`sd_notify`; a `Type=notify` unit would wait for a `READY=1` that never
arrives. Start the service directly. There is no socket unit: `pmaskd`
does not adopt a socket passed by systemd (it never reads `LISTEN_FDS`), and
a socket unit's `DirectoryMode=0700` would create `/run/pmask` as root,
which `DynamicUser=` cannot then own.

`pmask-run@.service` is the payload side. It loads the token with
`LoadCredential=`, which puts a `0400` file in a private tmpfs, and passes
it as `--secret TOKEN=file:%d/token`. It sets `ProtectProc=invisible`,
which is the half pmask cannot provide from inside a process: the
payload cannot enumerate other accounts' processes at all.

Two directives matter more than the rest, and both break the workload if
they are wrong:

- `SystemCallFilter=` must permit `ptrace`. Both shipped units name it on
  the allow line (`SystemCallFilter=@system-service ptrace`), because
  `@system-service` excludes it: the payload unit traces the job from
  inside the unit, and the daemon unit traces every job it runs
  (`Mask::spawn` seizes the child with `PTRACE_SEIZE`). In the payload
  unit a preset that denies `ptrace` turns redaction off and the run
  reports `mode=plain` rather than pretending. In the daemon unit it
  makes the seize fail, so the daemon cannot start a job at all.
- `RestrictNamespaces=` must permit `user pid net mount ipc uts cgroup`
  when `--unshare` or `--isolate` is used.

`MemoryDenyWriteExecute=` is safe to set for the daemon and unsafe for a
payload with a JIT.

## Which shape closes which row

| row in the threat model | 1 | 2 | 3 |
|---|---|---|---|
| cmdline is the label | yes | yes | yes |
| cmdline byte length is not the original | yes | yes | yes |
| environ shows nothing | yes | yes | yes |
| a delivered secret is not in `cmdline` or `environ` | yes | yes | yes |
| a same-uid peer cannot read `/proc/<pid>/mem` | with `--no-dumpable` | with `--no-dumpable` | yes |
| a same-uid peer cannot read the holder's memory | with `--no-dumpable` | yes | yes |
| the payload cannot enumerate other accounts' processes | no | no | yes, from `ProtectProc=invisible` |
| the payload cannot reach another job's descriptor | no | no | yes |
| `TracerPid` is 0 for the payload | with `--detach` | with `--detach` | with `--detach` |
| root cannot read the value | no | no | no |

## What to verify on the target

Run these on the host that will run the units; the scores depend on the
systemd version and on the directives that version knows:

```sh
systemd-analyze verify --man=no /etc/systemd/system/pmaskd@.service
systemd-analyze verify --man=no /etc/systemd/system/pmask-run@.service
systemd-analyze security --offline=yes pmaskd@default.service
```

`verify` parses and loads the units; `security` scores the sandbox
directives. Neither boots a unit, and the score is that of the
directives, not of a running job. Treat a directive this document names
but the installed systemd does not know as a version mismatch to resolve
rather than a line to delete.

The `contrib/` directory is excluded from the published crate; it is
deployment material, not a build dependency. It ships in the release
tarball and in the repository.
