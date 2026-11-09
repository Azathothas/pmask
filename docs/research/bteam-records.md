# The daemon's own footprint and the records outside the tree

Issues 52, 53, 54 and 55 describe what a `pmaskd` deployment and a
`pmask` launch leave behind: the daemon's own `/proc` entry and its
workers, the refusal strings, the on-disk artefacts, and the sinks that
something other than pmask writes about the run.

Host for the measurements marked `[observed]`: Linux
6.12.113+deb13-amd64, Debian 13, x86_64, uid 1000, CapEff 0, in LXC,
ptrace allowed, `kernel.yama.ptrace_scope = 0`. Rows marked `[quoted]`
are the issue's own measurements and are not re-run here; the command
that produced them is in the issue.

## 52. The daemon, its workers and the job leaf

`[observed]` `pmaskd -q -l b4d -S DIR/d.sock --jobs 2`, sampled 0.5 s
after start, then one `/bin/sleep 2` job:

```
daemon pid=716488 comm=b4d cmdline=b4d| environ EACCES maps EACCES
       auxv EACCES exe EACCES fd EACCES
job    pid=718296 comm=b4job cmdline=b4job| environ_bytes=0 tracer=718294
```

The daemon is non-dumpable in every mode, so the same-uid reader gets
`EACCES` on the five files and the five-file refusal set is the daemon's
normal state. The job carries the label, an empty environment window and
a tracer tid that is a task of the worker (or of the daemon with
`--jobs 1`). A listening unix socket at the root of that tree is what
separates a daemon from a bare supervisor.

This shape is the design, not a defect. The reduction that was possible
is in the PING body (issue 51): the full policy report is now served only
to the daemon's own uid and root, and another allowed uid gets the
protocol facts it needs to frame a job.

## 53. Refusal strings and exit codes

`[observed]` on this build:

| command | status | line |
| --- | --- | --- |
| `pmask --badopt` | 255 | `pmask: unknown option --badopt` |
| a label containing LF | 255 | `pmask: /bin/true: label must not contain NUL, LF or CR bytes` |
| `--comm` over 15 bytes | 255 | `pmask: comm must be at most 15 bytes` |
| `pmaskd --jobs 0` | 255 | `pmaskd: --jobs needs a number of at least 1` |
| a socket directory the daemon does not own | 255 | `pmaskd: refusing to start: ... is owned by uid N, not by uid M` |
| `--isolate` with a `literal:` secret | 255 | `pmask: secret 'X' uses literal:; isolate mode ... is refused; ... --allow-argv-secret` |

The strings are versioned behaviour: the suites assert them, and several
name the exact misconfiguration. A log reader that alerts on the
`pmask: ` / `pmaskd: ` prefix plus a nonzero status identifies tool
activity even when the redaction leaked nothing. That is a documented
failure-path channel, not something a userland rewrite can close.

The one reduction worth making was the `limits=` sentence in the PING
body, which served deployment documentation to any allowed caller; it is
gone.

## 54. On-disk footprint

`[observed]` a fresh store:

```
pmask store init --store DIR/store.enc --passphrase-file DIR/pp
created DIR/store.enc
98 600 store.enc
0 600 store.enc.lock
P M A S K S T O R E 1 \0 \0 \0 \0 \0
```

The store is encrypted at rest; its size grows with the key name and the
value, so the size is not diagnostic. The magic and the 0600 mode are.
`scripts/check-artifacts.sh` reports this set without failing on a clean
host.

`[quoted]` the release binaries are static PIE, stripped, with a
`.comment` section naming the Rust toolchain and LLD. That section is a
cheap on-disk match; removing it is a release-workflow step
(`objcopy --remove-section=.comment` after the link), not a source
change, and the pmask strings remain, so a rule keyed on those still
matches. The limit is recorded rather than hidden.

The tmpfiles defect (#23) is fixed: the unit creates the directory and
not an empty `store.enc`, so `store init` no longer refuses a file it
just created.

## 55. Records outside the masked tree

`[observed]` `--report=json` describes the run, including `mode`,
`payload_dumpable`, the exec counters and the secret hardening tier; a
CI log or a `| tee` keeps it. `--audit` prints one row per tracee with
the real `exe` path and the tracer pid, then a residue count. `probe` and
`doctor` describe the host's posture and the reason strings. None of
these is inside the mask; each is written by pmask about the run.

The same is true of the sinks pmask does not own: `sudo`'s own argv, the
shell history, and a transient systemd scope's description. The first two
are why `--args-from-fd` exists. The scope description is now the session
label rather than the real command line, and the unit name is still
visible in `/proc/<pid>/cgroup` by design.

`probe`/`doctor` are a host-posture oracle when captured in a log. They
are also the operator's own diagnostic; a quiet form that omits the
reason strings would be a feature request, not a defect. The exact-window
row now reads `n/a` when metadata redaction is unavailable (issue 13),
so the report no longer implies a guarantee the mode cannot make.

## What is not closable here

- The daemon's own entry is non-dumpable in every mode, and that is the
  refusal set a same-uid reader sees. A daemon that is readable is a
  different, worse design.
- The refusal strings and the shell history are outside the process.
- The audit record of pmask's own exec is written before pmask runs.
- The release binary's strings are in the binary.

Each of those is stated in the README's honest limits or in
`THREAT-MODEL.md`, not implied away.
