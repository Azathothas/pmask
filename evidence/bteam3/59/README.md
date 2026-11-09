# Issue 59: the supervisor's own exec writes the payload argv and any `literal:` secret into the kernel audit log

Host: Linux 6.12.113+deb13-amd64, Debian 13, x86_64, uid 1000, CapEff 0,
in LXC.

## What was measured here, and what was not

Measured: the warning, its wording, that it never contains the value,
that `-q` suppresses it, that the secret still works, that the JSON
report carries the exposure, and the `PMASK_PROBE_AUDIT` wording
variants. All of that is in `tests/qa.d/59.sh`.

Not measured: **the audit record itself**. This container refuses the
audit subsystem, so no `EXECVE` record could be produced or read. The
refusal and the exact commands are in `evidence/bteam3/56/README.md`;
`tests/qa.d/56.sh` gates on it and prints `SKIP` here. Every audit
record quoted anywhere in this batch is `[guest]`, from the capture in
issues #56 and #59 (Alpine 3.22, kernel 6.12.115, auditd 4.0.3).

## The change

`src/run.rs`:

- `AuditState` (`Enabled` / `Disabled` / `Unknown`) and `audit_state()`,
  which asks the kernel over `NETLINK_AUDIT` with `AUDIT_GET` — the same
  question `auditctl -s` asks, and the one `auditctl` refuses to ask for
  a non-root caller. `parse_audit_reply()` is split out so the wire
  format is testable without a kernel that answers.
- `argv_secret_warning(sources)`, which builds the warning text once.
  It names the kernel audit log, the shell history, a wrapper's argv,
  `--args-from-fd`, and `file:`/`agent:`/`stdin`. It asserts the audit
  clause only for a `literal:` source, because the kernel's exec record
  carries argv and not envp.
- `PMASK_PROBE_AUDIT=1|0` overrides the probe for the two wordings, in
  the same spirit as the `PMASK_PROBE_*` host-profile hooks in
  `src/caps.rs`.

`src/cli.rs`: one `eprintln!` at the default verbosity, before the run
starts, suppressed by `-q` and by `--daemon` (which refuses `--secret`
anyway). Not in `src/tracer.rs`, which was out of scope.

`src/run.rs` `Outcome.notes` carries a shorter version of the same fact,
so `--report=json` records it and a CI job that asserts on the report
sees it without scraping stderr.

`literal:` is not removed and no mode refuses it. The record is written
before pmask exists, so a refusal at parse time would be a refusal after
the exposure; section 6 of `docs/research/bteam-audit.md` says why.

## The three wordings, captured

```
$ PMASK_PROBE_AUDIT=1 ./target/release/pmask -l w5 --secret T=literal:VAL-9 -- /bin/true
pmask: warning: secret source T=literal: puts the value in pmask's own argv, where the shell
history and any wrapper's argv keep a copy, and this host's audit subsystem is enabled, so the
kernel has already written that argv into its audit log (type=EXECVE and PROCTITLE) for the life
of the log. pmask cannot reach the copies outside its own process: use file:PATH, agent:NAME or
stdin for the value, and --args-from-fd N to keep the payload's own arguments out of pmask's argv

$ PMASK_PROBE_AUDIT=0 ./target/release/pmask -l w6 --secret T=literal:VAL-9 -- /bin/true
... and the kernel audit log would hold it too if this host's audit subsystem were enabled. ...

$ ./target/release/pmask -l w7 --secret T=literal:VAL-9 -- /bin/true      (real probe here)
... and the kernel audit log would hold it too if this host's audit subsystem were enabled. ...
```

The real probe on this host answers `Disabled` through the
`ECONNREFUSED` path, which is the same answer a host with auditing
configured off gives. That is the correct answer to act on: there is no
record.

The `env:` wording, which deliberately makes no audit claim:

```
pmask: warning: secret source T=env:W_TOKEN puts the value in pmask's own environment, where
/proc/<pmask-pid>/environ serves it until pmask masks itself and the shell history or a
wrapper's environment may keep a copy; the kernel's exec record carries argv, not the
environment. pmask cannot reach the copies outside its own process: use file:PATH, agent:NAME
or stdin for the value, and --args-from-fd N to keep the payload's own arguments out of pmask's
argv
```

## The guard, in both directions

`tests/qa.d/59.sh`: 14 cases, all PASS. Shown to fail when the warning is
removed: with `if false &&` around the `eprintln!` in `src/cli.rs`, six
cases FAIL (`59a-one-warning`, `59a-warning-names-...`, `59f`, both
`59g`, `59h`). The source was restored after.

## New defect found while working on this, not fixed

`pmask read NAME` inside a masked payload falls through to the help text
and exits 255: 11496 bytes on stderr, nothing on stdout. That is issue
#5, which fix1 owns. It is recorded here because it makes the documented
way to consume a delivered secret (`token=$(pmask read NAME)`) unusable
in the default mode, which is the mode the `literal:` warning is about.
With `--detach` the same command prints `VAL-123`. Transcript in
`issue5-nested-read.log`.

## Files

- `src/run.rs`, `src/cli.rs`
- `tests/qa.d/59.sh`
- `docs/research/bteam-audit.md` (sections 4 and 6)
