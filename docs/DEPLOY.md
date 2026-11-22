# Deployment

Choose one of the three deployment shapes below based on the host's capabilities. Read `docs/THREAT-MODEL.md` to see which adversary rows each shape closes.

Every statement here matches the `v0.1.0` codebase and the units under `contrib/`. Two systemd directives that break execution if misconfigured are highlighted in Shape 3.

## 1. One account, no privilege

This is the default deployment. No special capability is required.

```sh
pmask store init --passphrase-file ~/.config/pmask/pass
pmask store set DEPLOY_TOKEN < token.txt
pmask run --label ci-runner \
    --secret DEPLOY_TOKEN=agent:DEPLOY_TOKEN \
    -- ./deploy.sh
```

Observe these operational rules before relying on this shape:

- Start `pmask agent` before using an `agent:` source. The agent must own its socket directory. When `XDG_RUNTIME_DIR` points to a mode-`0700` directory owned by the account, the default socket is `$XDG_RUNTIME_DIR/pmask.sock`. The agent refuses to bind in a directory owned by another account.
- The supervisor holds the secret descriptor for the life of the run. Pass `--secret-burn` so a cooperating payload can truncate the secret after reading it, and set a lease (`PMASK_AGENT_LEASE`) to bound how long the agent serves the secret.
- In redaction mode, `--secret` makes both the supervisor and the payload non-dumpable (`PR_SET_DUMPABLE=0`) by default, blocking same-uid reads of `/proc/<payload>/fd/3` and `/proc/<payload>/mem`. Pass `--allow-dumpable` only when the payload must remain debuggable.
- Plain and isolate modes cannot set `PR_SET_DUMPABLE=0` on the payload. In those modes, the run prints a note, `payload_dumpable` in the JSON report is `true`, and another process of the same account can read `/proc/<payload>/fd/3`.

## 2. A dedicated holder account

Move the encrypted store and agent to a dedicated uid that the workload does not share. Standard DAC permissions then isolate the holder. This setup requires `CAP_SETUID` (root) once at installation time.

```sh
# as root, once
useradd --system --no-create-home --shell /usr/sbin/nologin pmask
install -d -m 0700 -o pmask -g pmask /var/lib/pmask
install -d -m 0700 -o pmask -g pmask /run/pmask
sudo -u pmask pmask store init --passphrase-file /etc/pmask/pass
sudo -u pmask pmask agent --store /var/lib/pmask/store.enc \
    --passphrase-file /etc/pmask/pass --socket /run/pmask/pmask.sock
```

Because `/run` is a tmpfs, recreate `/run/pmask` at every boot using a `tmpfiles.d` entry or a systemd unit with `RuntimeDirectory=pmask`. Without that directory, the agent fails with `EACCES` and refuses to bind.

Run the workload under its own unprivileged account and fetch secrets from the agent socket. Same-account peers of the workload cannot inspect the holder's memory because the holder runs under a different uid.

This shape does not protect against root or processes running as the `pmask` holder account.

## 3. A systemd unit with `ProtectProc=invisible`

This shape provides the strongest host isolation, mostly through systemd's kernel sandboxing. A service with `ProtectProc=invisible` gets a private procfs view and cannot see other accounts' processes.

The daemon unit (`contrib/systemd/pmaskd@.service`) sets `DynamicUser=yes` and `RuntimeDirectory=pmask`. Systemd allocates an isolated uid and creates `/run/pmask` at mode `0700` owned by that user, satisfying `pmaskd`'s ownership check.

The payload unit (`contrib/systemd/pmask-run@.service`) omits `User=` and `DynamicUser=` by default so it can read `/usr/local/bin/job.sh` and loaded credentials. To run the payload unprivileged, add `User=` or `DynamicUser=yes` and grant read access to the payload files.

Install and start the units:

```sh
install -D -m 0644 contrib/systemd/pmaskd@.service /etc/systemd/system/
install -D -m 0644 contrib/systemd/pmask-run@.service /etc/systemd/system/
install -D -m 0644 contrib/tmpfiles.d/pmask.conf /usr/lib/tmpfiles.d/
systemd-tmpfiles --create
systemctl daemon-reload
systemctl enable --now pmaskd@default.service
systemctl start pmask-run@ci-runner
```

Follow these unit rules:

- Keep `Type=simple` in `pmaskd@.service`. `pmaskd` does not call `sd_notify`, so `Type=notify` hangs waiting for `READY=1`.
- Do not add a systemd `.socket` unit for `pmaskd`. `pmaskd` ignores `LISTEN_FDS`, and a socket unit creates `/run/pmask` owned by root, which fails `DynamicUser=` ownership checks.
- Keep the daemon `ExecStart` as `/usr/bin/pmaskd --socket %t/pmask/pmask.sock` (plus `--env-file` as needed). Never pass `--store` or `--passphrase-file` to `pmaskd`: `pmaskd` has no encrypted store and exits `255` with `unknown option --store`. Run `pmask agent` separately to serve `--secret NAME=agent:NAME`.
- Keep `contrib/tmpfiles.d/pmask.conf` creating only the `/var/lib/pmask` directory. Never add a tmpfiles `f` line for `store.enc`. A pre-created zero-byte file causes `pmask store init` to refuse with `already exists` (`255`) and `store set` to reject the truncated header.
- `pmask-run@.service` loads the secret with `LoadCredential=` into a mode-`0400` file on a private tmpfs and passes `--secret TOKEN=file:%d/token`. It also sets `ProtectProc=invisible` so the payload cannot enumerate other accounts' processes.

Verify these two critical directives in any customized unit:

- `SystemCallFilter=` must allow `ptrace`. Both shipped units use `SystemCallFilter=@system-service ptrace` because `@system-service` excludes `ptrace`. Blocking `ptrace` forces `pmask-run@.service` into `mode=plain` (no redaction) and prevents `pmaskd@.service` from seizing jobs.
- `RestrictNamespaces=` must include `user pid net mnt ipc uts cgroup` whenever `--unshare` or `--isolate` is used.

`MemoryDenyWriteExecute=yes` is safe for `pmaskd@.service` but breaks payloads that use a JIT compiler.

## Which shape closes which row

| row in the threat model | 1 | 2 | 3 |
|---|---|---|---|
| `cmdline` is the label | yes | yes | yes |
| `cmdline` byte length is not the original | yes | yes | yes |
| `environ` hides real variables (shows plausible decoy) | yes | yes | yes |
| delivered secret is absent from `cmdline` and `environ` | yes | yes | yes |
| same-uid peer cannot read `/proc/<pid>/mem` | yes (default for `--secret` in redaction mode; `--no-dumpable` otherwise) | yes (default for `--secret` in redaction mode; `--no-dumpable` otherwise) | yes |
| same-uid peer cannot read the holder's memory | yes (hardened before load) | yes | yes |
| payload cannot enumerate other accounts' processes | no | no | yes, via `ProtectProc=invisible` |
| payload cannot reach another job's descriptor | no | no | yes |
| `TracerPid` is 0 for the payload | with `--detach` | with `--detach` | with `--detach` |
| root cannot read the value | no | no | no |

## What to verify on the target

Run these commands on the target host to validate the installed units. Sandboxing scores depend on the installed systemd version:

```sh
systemd-analyze verify --man=no /etc/systemd/system/pmaskd@.service
systemd-analyze verify --man=no /etc/systemd/system/pmask-run@.service
systemd-analyze security --offline=yes pmaskd@default.service
```

`systemd-analyze verify` checks unit syntax and loading. `systemd-analyze security` scores static sandbox directives without starting a job. If the host's systemd version does not recognize a directive, resolve the version difference rather than deleting hardening lines blindly.

Run the native test gate (`sh tests/run.sh`) as an unprivileged uid, not as root. Root holds `CAP_SYS_PTRACE`, which bypasses same-uid refusals so `tests/isolation.sh` and `tests/conformance.sh` print `SKIP` on those checks. `sh vm/run.sh` runs both root and uid-1000 passes automatically.

The `contrib/` directory is deployment material excluded from the crate package. It ships in the repository and in the GitHub release tarball.
