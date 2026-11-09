# Issue 39 evidence: the supervisor's own `/proc` entry and `PMASK_NO_SELFMASK`

Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86-64, uid 1000 (`agent`),
`kernel.yama.ptrace_scope` = 0. Build: `pmask 0.1.0-beta.1`, commit
`fa46e62` plus this batch's changes, `cargo build --release --bins
--features testbins`.

| log | what it shows |
|---|---|
| `selfmask-shape.log` | the default shape, the uid-1000 zeros, the root window, and the escape in both modes |
| `audit-probe.log` | the kernel audit subsystem refuses `NETLINK_AUDIT` here, for root and for uid 1000 |
| `audit-outcomes.log` | the four CLI outcomes the new check produces |
| `window-measure.log` | 40 samples per mode of the supervisor's own cmdline during a `stdin:` secret block |
| `zero-argv-window.log` | 12 runs sampling for an all-NUL cmdline: 5 saw it |
| `repro-plain-exposure.log` | the plain-mode leak, and the startup NUL window in a redact run |
| `qa39.log` | the fragment's own output |

## The default shape (measured)

```
cmdline: proc-evid|
comm: [proc-evid]
uid1000 stat 48-51: 0 0 0 0
root    stat 48-51: 140721073217341 140721073217351 140721073217351 140721073217351
threads: 2
  task proc-evid
  task pmask-tracer
exe: (readlink refused)  environ bytes: (EACCES)
```

The uid-1000 zeros are the non-dumpable flag: the kernel zeroes fields 48-51
for a reader without `PTRACE_MODE_READ`.  Root sees the relocated window:
`arg_end - arg_start == 9 + 1` for the 8-byte label `proc-evid`.

## The escape is mode-dependent, and the issue does not say so

The issue states the escape "disables the self-mask, and the supervisor then
serves its real `argv` (`src/main.rs:190`, `src/main.rs:338`)".  Measured,
that is only true on the plain path.  `src/main.rs:190` zeroes the argv
block at startup; the runner then applies `mask_self_with_window`
unconditionally in its redact and isolate branches, so the second write
overrides the escape.

`window-measure.log`, 40 samples during a `stdin:` secret (which blocks the
supervisor in `load` long enough for every sample to land in the same
window):

```
selfmask-on : samples=40 with_canary=0 ... last=[|||||||||...]
NO_SELFMASK : samples=40 with_canary=40 last=[/path/pmask|-q|-l|wtest|--secret|T=stdin|...]
```

A 20-sample sweep of a redact-mode run with `PMASK_NO_SELFMASK=1` and a
`literal:` secret found the real argv in 2 of 20 samples
(`selfmask-shape.log` section 2); the same run in plain mode serves it for
the whole run (`selfmask-shape.log` section 3).

## A window the issue names but does not measure

The issue title mentions "a zero argv window".  Measured
(`zero-argv-window.log`), it is real and intermittent: `zero_argv_block`
runs at startup and the label is written later, so the supervisor's
`cmdline` is a run of NUL bytes of the original length in between.

```
run  3: all-NUL samples=1 of 60, final bytes=10
run  4: all-NUL samples=2 of 60, final bytes=10
...
runs with at least one all-NUL sample: 5 of 12 (720 samples in total)
```

5 of 12 runs showed it; each run sampled as fast as the shell can loop, so
this is an observation about how often a poller catches it, not a
probability.  It is not closable: the label cannot be written before the
argv block is zeroed, because writing it first would leave the value
readable.  A detector that samples fast enough sees a `cmdline` of NULs with
the process still alive, which is not produced by any ordinary program.


## The audit subsystem is not reachable here

```
uid 1000: reply 80 bytes, NLMSG_ERROR errno -111 (ECONNREFUSED)
root:     NLMSG_ERROR errno -111 (ECONNREFUSED)
CapEff uid 1000: 0000000000000000
CapEff root:     000001ffffffffff
```

So a refusal on this host would be a refusal on the strength of a probe that
says "audit is blocked".  The new check therefore warns here and refuses
only when the probe answers `active`, which the suites drive with
`PMASK_PROBE_AUDIT=1`.

## What the fix does (measured, `audit-outcomes.log`)

| case | stderr | exit |
|---|---|---|
| plain + `literal:` + `PMASK_NO_SELFMASK`, real host (audit blocked) | one warning, naming `'T' (literal:)` and `--args-from-fd` | 0 |
| same, `PMASK_PROBE_AUDIT=1` | refusal naming the audit subsystem | 255 |
| same, `PMASK_PROBE_AUDIT=1` + `--allow-argv-secret` | the warning | 0 |
| redact + `literal:` + `PMASK_NO_SELFMASK` | "is overridden in redact mode" and the short window | 0 |
| `PMASK_NO_SELFMASK` with no secret | nothing | 0 |

The warning is printed even with `-q`.  A quiet run that publishes a secret
is the silent degradation invariant 13 forbids; the message is a fact about
the command, not a progress note.

## Residual

The supervisor's own entry is still a fingerprint: a labelled parent whose
`comm == cmdline[0]`, `Threads: 2` and a `pmask-tracer` task.  It is not
closable in userland without removing the self-mask, which is a documented
feature (invariant 12).  See `docs/research/bteam-39-43.md` §39.
