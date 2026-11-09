# b-team research: issues 39-43, measured

This note records what a defender can actually read on a masked process for
five channels, what was measured, and what each residual would cost to close.
It is the measurement behind the QA fragments `tests/qa.d/39.sh` to `43.sh`
and the two warnings added in `src/main.rs`.

Every number here was taken on one host; a number carries its conditions or
it is not a number.

- Debian 13, kernel `6.12.113+deb13-amd64`, x86-64.
- uid 1000 (`agent`), `CapEff=0000000000000000`; root via passwordless
  `sudo`, `CapEff=000001ffffffffff`.
- `kernel.yama.ptrace_scope` = 0; native ptrace works; user namespaces work.
- `NETLINK_AUDIT` is refused with `ECONNREFUSED` for both uids.
- `pmask 0.1.0-beta.1`, commit `fa46e62` plus this batch.
- Payloads are `target/release/pmask-testcases` (`sleeper`, `execfn`) and
  `/bin/sleep` where a real argv is the point.

Raw logs are under `evidence/bteam1/<issue>/`.

Detector rules are written the way an observer would write them: from
`/proc` alone, no trace, no privilege beyond same-uid.

---

## 39. The supervisor's own entry, and `PMASK_NO_SELFMASK`

### Rules

```
sup = candidate supervising process
ok  = comm(sup) == cmdline0(sup)
      and cmdline_len(sup) == len(comm(sup)) + 1
      and any(comm(t) == "pmask-tracer" for t in tasks(sup))   # pre-#38 only
if ok: alert("pmask supervisor", sup)
```

The thread-name clause is a capture of the build these rows were measured
on.  From #38 on the thread takes the session's `comm`, so that clause no
longer fires; the two-clause shape without it (label served as both
`cmdline` and `comm`, plus a second task) is the durable part, and the
`Tgid != Pid` relation in `bteam-38-50.md` is the replacement.

and, for the debug variant:

```
ok  = comm(sup) is pmask-flavoured
      and cmdline(sup) contains the real option vector
if ok: alert("pmask supervisor, self-mask disabled", sup)
```

### Measured

Default run, uid-1000 reader then root reader
(`evidence/bteam1/39/selfmask-shape.log`):

```
cmdline: proc-evid|                     (label + one NUL)
comm: [proc-evid]
uid1000 stat 48-51: 0 0 0 0
root    stat 48-51: <4 addresses>       arg_end-arg_start = 9, env span 0
threads: 2      task proc-evid, task pmask-tracer   [pre-#38 build]
exe: readlink refused, environ: EACCES
```

The uid-1000 zeros are the non-dumpable flag, not a missing measurement:
fields 48-51 are zeroed for a reader without `PTRACE_MODE_READ`.  Both
readers are part of the shape, and the QA fragment asserts both.

### `PMASK_NO_SELFMASK` is mode-dependent, and the issue is wrong about it

The issue says the escape "disables the self-mask, and the supervisor then
serves its real `argv`".  Measured
(`evidence/bteam1/39/window-measure.log`), with the supervisor held in
`load` by a `stdin:` source so that every sample lands in the same window:

```
selfmask-on : samples=40 with the canary in cmdline=0
NO_SELFMASK : samples=40 with the canary in cmdline=40
```

That is the redact path, where `Runner::run` applies
`selfmask::mask_self_with_window` unconditionally after `spawn`.  A
20-sample sweep of that same run found the real argv in 2 of 20 samples
(the exec-to-selfmask window).  On the plain path the escape is honoured for
the whole run (`selfmask-shape.log` §3).

So the exposure the escape creates is:

| mode | escape honoured | exposure |
|---|---|---|
| plain (`--no-redact`, or no ptrace) | yes | the supervisor's argv, for the whole run |
| redact | overridden after the fork | the supervisor's argv, exec-to-selfmask |
| isolate | overridden after the fork | same |

This matters for the fix.  A warning that says "for the whole run" in redact
mode is a claim the measurement refutes, and a refusal there would remove a
documented debug escape for an exposure that is already the default one.  The
implemented check therefore names the mode:

- redact and isolate: "is overridden in … mode … only until then".
- plain: "leaves … readable for the whole run in plain mode".

### The audit axis, and why a refusal is conditional

On a host whose kernel audit subsystem answers, the supervisor's own `exec`
is also written to the audit log (`EXECVE`/`PROCTITLE`), which turns a
transient `/proc` exposure into a durable record that `pmask` cannot reach.
That is a real difference in kind and it is why the plain-mode combination is
refused there.

This host does not answer: `NETLINK_AUDIT` returns `ECONNREFUSED` for uid
1000 and for root (`evidence/bteam1/39/audit-probe.log`).  A refusal on a
"blocked" probe result would only make the documented escape unusable, so the
check warns there.  The probe is `caps::kernel_audit_reachable()`, an
`AUDIT_GET` request over `NETLINK_AUDIT`, with `PMASK_PROBE_AUDIT` as the
test hook, so both branches are exercised on any host.

### The zero-argv window

The issue's title names "a zero argv window" without measuring it.  It is
real and intermittent (`evidence/bteam1/39/zero-argv-window.log`): the
startup `zero_argv_block` runs before the label is written, so the
supervisor's `cmdline` is a run of NUL bytes of the original length in
between.

```
run  3: all-NUL samples=1 of 60, final bytes=10
run  4: all-NUL samples=2 of 60, final bytes=10
...
runs with at least one all-NUL sample: 5 of 12 (720 samples in total)
```

5 of 12 runs caught it, sampling as fast as a POSIX shell loop can.  That is
an observation about a poller, not a probability: the window is the time
between the zeroing write and the label write in `main`, which is a handful
of instructions plus the option parse.

It is not closable.  The label cannot be written before the argv block is
zeroed, because writing it first would leave the secret readable for the
duration of the parse — which is the whole point of the ordering in
invariant 12.  A detector that samples fast enough sees a live process with
an all-NUL `cmdline`, which no ordinary program produces.

### Verdict: **partially closable**

Closed: the silent publication of a `literal:`/`env:` value by the escape. It
now warns, and on an audited host it refuses unless `--allow-argv-secret`
says otherwise.  Measured outcomes in
`evidence/bteam1/39/audit-outcomes.log`.

Not closed: the supervisor's own shape, or the zero-argv startup window.  The
first is a labelled parent with a tracer task, and removing it means removing
the self-mask (invariant 12, and a documented feature).  A supervisor that
kept its real `comm` would trade the `pmask-tracer` signal for a `pmask`
name, which is the louder fingerprint the issue itself names as the
alternative.  The second is forced by the ordering: zero, then label.

### Trades of the alternatives

| alternative | cost |
|---|---|
| refuse the escape whenever a plain-sight secret is present | removes a documented debug escape for an exposure that is already the pre-fork default in redact mode; breaks `tests/options.sh` O12's control, which needs the escape to work |
| drop the escape | same, and it is in `--help` and `man/pmask.1` |
| mask the supervisor with a non-label `comm` | a `pmask`-shaped name in every process table is a wider signal than the label it replaces |
| keep the escape and stay silent | the status quo; the value is readable for the whole run in plain mode with nothing said |

---

## 40. The argv-window arithmetic

### Rules

```
pid=$1
cmd=$(wc -c < /proc/$pid/cmdline)
nul=$(tr -cd '\0' < /proc/$pid/cmdline | wc -c)
read -r as ae es ee < <(awk '{sub(/.*\) /,""); print $46,$47,$48,$49}' /proc/$pid/stat)
[ "$nul" = 1 ] && [ $((ae-as)) = "$cmd" ] && [ $((ee-es)) = 0 ] && echo hit
```

and, for `--no-exact`, the count rule.

### Measured

Default mode (`evidence/bteam1/40/repro-default.log`):

```
cmdline   10 bytes, one NUL: "proc-evid\0"
arg span  10
env span  0        (env_start == env_end)
```

Both clauses hold, and `--label-empty` gives `cmdline=1, argspan=1,
envspan=0`.

`--no-exact` (`evidence/bteam1/40/no-exact-count-sweep.log`), ELF entry
path, 8-byte label:

```
argv_entries=3 bytes=11 nuls=3 argspan=11 envspan=1
argv_entries=4 bytes=12 nuls=4 argspan=12 envspan=1
argv_entries=5 bytes=13 nuls=5 argspan=13 envspan=1
argv_entries=6 bytes=14 nuls=6 argspan=14 envspan=1
argv_entries=7 bytes=15 nuls=7 argspan=15 envspan=1
```

`bytes == len(label) + argc` and `nuls == argc`.

The issue says `--no-exact` "keeps the original cmdline byte extent".  That
is false on this build for the ELF entry path: the extent is the label plus
one NUL per slot, and the original 3×40 bytes are gone.  It is true for the
post-exec (script) path, which does keep the kernel's copy's extent
(`no-exact-script-path.log`: 142 bytes for a 17-byte label and 3×40-byte
arguments).

The NUL count is the rule that survives on both paths.  A rule written as
"extent greater than the label length" fires on the script path and misses
the ELF path, so it is not a usable detector on its own.

### Verdict: **not a defect — design**

The arithmetic is the documented design and the measurement in the issue is
correct apart from the `--no-exact` extent claim.  No code change; the QA
fragment pins the arithmetic so a regression is visible, and the
documentation correction belongs to whichever batch owns
`docs/research/detection-*.md` (docs2).

### Trades of the alternatives

| alternative | cost |
|---|---|
| make `--no-exact` the default | restores the extent signal, reintroduces the NUL-run signal; also makes `environ` a NUL run, which the issue 41 measurement shows is itself narrow |
| collapse `environ` under `--no-exact` too | `--no-exact` means "keep the extent"; collapsing one window and not the other is two behaviours under one flag |
| leave as is | a detector gets `nul == 1 && argspan == cmdlen && envspan == 0` as a three-clause conjunction, which ordinary processes also match only when started with no arguments and an empty environment |

---

## 41. The shapes of `/proc/<pid>/environ`

### Rules

```
env = read_bytes("/proc/pid/environ")
if len(env) == 0 and not is_kernel_thread(pid) and not is_zombie(pid):
    alert("empty environ", pid)
elif has_nul_run(env, min_run=2):
    alert("rewritten environ window", pid)
```

### Measured

`evidence/bteam1/41/environ-shapes.log`:

```
default          bytes=0  nuls=0  envspan=0
no-exact         bytes=3  nuls=3  envspan=3
keep-env         bytes=61 nuls=3  envspan=61     PATH, VERYSECRET, TOKEN
keep-env=TOKEN   bytes=25 nuls=3  envspan=25     \0\0TOKEN=<value>\0
keep-env=PATH    bytes=21 nuls=3  envspan=21     PATH=...\0\0\0
```

All four shapes confirm the issue.  The empty-environ rule is the narrow one
in the default mode; the NUL run is narrow in `--no-exact`; `--keep-env` is
indistinguishable from an ordinary process by construction.

### The hardening, and the case it must not cover

The issue suggests refusing or warning on `--keep-env` combined with a
`literal:` or `env:` source.  Measured, `literal:` never reaches the payload's
environment:

```
== a literal: secret under --keep-env leaves no value in environ
0000000   P A T H = / u s r / b i n : / b i n \0 P M A S K _ S E C R E T _ T = 3 \0
```

Only the secret's name and its descriptor number are there.  A warning on
`literal:` would be false.  The implemented check warns only when an `env:`
source reads a variable the run keeps visible, and it names both the secret
and the variable.  The kept variables stay kept: `qa41.log`
`e5-kept-vars-still-kept` reads HUSH back out of the payload's environ after
the warning fired.

The warning prints even with `-q`, for the same reason as issue 39: a quiet
run that publishes a value is a silent degradation.

### Verdict: **design limit, with the contradiction warned**

Closed: the silence.  An operator who asks for a secret to be hidden and for
the place it lives to be published is now told.
Not closed: the `environ` shape itself.  `--keep-env` is the documented
opt-out, and a process with a large visible environment is an ordinary
process.

### Trades of the alternatives

| alternative | cost |
|---|---|
| refuse `--keep-env` with any plain-sight secret | removes a documented flag's only use next to a secret; `tests/options.sh` O9/O10 depend on it; a `literal:` refusal would be false anyway |
| keep the window but blank the secret's variable | silently redacts a variable the operator asked to keep — feature removal under a flag whose name says otherwise |
| warn as implemented | one line on stderr; the value is still published, which is the operator's choice |

---

## 42. `comm`, `cmdline` and `exe` disagree

### Rules

```
a0 = first_token(cmdline(pid)); c = comm(pid); e = basename(readlink(exe(pid)))
if a0 and c and e and a0 == c and e != a0:
    if tracer_is_thread(pid) or arg_span(pid) == 0 or environ_len(pid) == 0:
        alert("label versus exe split", pid)
```

and the blank-label rule on a 1-byte or `0x20 0x00` cmdline.

### Measured

`evidence/bteam1/42/labels-and-split.log`:

| input | cmdline bytes | comm file bytes | comm | exe | TracerPid |
|---|---|---|---|---|---|
| `-l qa42-sshd` | 10 | 10 | `qa42-sshd` | the real testcases binary | non-zero |
| `-l-` | 2 (`20 00`) | 2 | one space | the real binary | non-zero |
| `--label-empty` | 1 (`00`) | 2 | empty | the real binary | non-zero |
| `--comm 123456789012345` | 10 | 16 (15 + newline) | the 15 bytes | the real binary | non-zero |
| 254-byte label | 255 | 16 | first 15 bytes | the real binary | non-zero |
| 255-byte label | 256 + one warning | 16 | first 15 bytes | the real binary | non-zero |
| `--comm` 16 bytes | refused, rc 255 | — | — | — | — |

All confirm the issue.  The `exe` axis is what makes the label a signal: the
label is on `comm` and `cmdline[0]`, and `exe` names a different binary.

### The `--comm` control-byte defect is worse than the issue says

`--comm` accepts LF and CR.  The issue says this "breaks the parenthesised
part of `/proc/<pid>/stat`".  Measured
(`evidence/bteam1/42/comm-lf-stat-parse.log`):

```
raw stat: 85274 (a\nb) S 85270 ...
comm file bytes: 610a620a
awk field count on the raw file: 2      (a normal stat has 52)
python parse after the last ')': 50 fields
```

An `awk` reading the file line by line sees two fields and stops.  A parser
that strips through the last `)` still finds `arg_start` and `arg_end` at the
expected offsets, because the `)` is on the second physical line and the
strip is done on the whole buffer.  `ps -o comm=` renders `a?b`.

This is fix1's issue #33 and is not fixed here.  The QA fragment asserts the
current behaviour (`c10-comm-lf-accepted-today`,
`c11-comm-cr-accepted-today`) with a message naming the dependency, so a fix
lands as a visible failing case rather than a silently different pass.

### Verdict: **design limit**

The design is "the name is controllable, the binary is not".  `--rexec` moves
the mismatch to `/memfd:<label> (deleted)`, which is its own signal and a
narrower one; making it the default would trade one signal for another
without removing the disagreement, and it changes every run's behaviour.

### Trades of the alternatives

| alternative | cost |
|---|---|
| make `--rexec` the default | `exe` becomes a memfd name, which no ordinary process has; static-link and seccomp edge cases; changes the default for every run |
| `--no-dumpable` as the default | closes the `exe` axis for a same-uid reader, but breaks core dumps and same-uid debugging for the whole tree — a documented opt-in, not a default |
| leave as is | one conjunction of four clauses; each clause alone has ordinary matches |

---

## 43. `AT_EXECFN` versus the payload's own `getauxval`

### Rules

```
ptr = auxv_field(pid, 31)
served = read_cstring(pid, ptr)
if served != basename(readlink(exe(pid))):
    alert("AT_EXECFN serves a label", pid)
```

and, inside the payload:

```
real = getauxval(AT_EXECFN); served = read("/proc/self/cmdline")
if real != served: alert("in-process auxv dissent")
```

### Measured

`evidence/bteam1/43/execfn-layout.log`, payload `testcases execfn 20`
(argv: `testcases execfn 20`, argc 3):

```
label=abcd   AT_EXECFN -> "abcd"             env_end - AT_EXECFN = 0   ptr - arg_start = 8
label=8      AT_EXECFN -> "abcdefgh"         env_end - AT_EXECFN = 0   ptr - arg_start = 12
label=12     AT_EXECFN -> "abcdefghijkl"     env_end - AT_EXECFN = 0   ptr - arg_start = 16
payload:     getauxval(AT_EXECFN) = /workspace/wt/bteam1/target/release/pmask-testcases
```

The issue's main claims hold: the served view is the label, the payload's own
view is the real path, and the offset is `1 + len(label) + argc`.

### Two corrections to the issue

**`AT_EXECFN == env_end` holds only when the environment is redacted.** With
`--keep-env` the environment window keeps its original addresses
(`evidence/bteam1/43/execfn-relations.log`):

```
exact,label4     env_start == env_end == AT_EXECFN
keep-env,label4  env_start=140731932532657 env_end=140731932532676 AT_EXECFN=139891444633608
keep-env,label12 env_start=140737409040305 env_end=140737409040324 AT_EXECFN=139733903212560
                 (env_end - AT_EXECFN = 1003505827764 bytes)
```

A detector that gates on `AT_EXECFN == env_end` gets no hit in `--keep-env`.
The rule that survives every mode is the offset
`AT_EXECFN - arg_start == 1 + len(label) + argc`, which held at 8 and 16 in
all three modes.

**`--no-exact` does not rewrite the auxv, so there is no dissent.**
`evidence/bteam1/43/execfn-no-exact-dissent.log`:

```
## exact mode, label=neatlabel
in-payload: /tmp/qa43-probe      served: neatlabel

## --no-exact, label=neatlabel
in-payload: /tmp/qa43-probe      served: /tmp/qa43-probe
cmdline:    [neatlabel|||]
```

The rewrite lives inside the `PR_SET_MM_MAP` call, and `--no-exact` skips
that call (`src/execimg.rs`: `relocate_windows` runs only under
`cfg.exact`).  Both views agree, so a detector comparing them gets nothing,
and `/proc/<pid>/auxv` names the real binary while `cmdline` shows the label.
That is a weaker served view, not a stronger one, and it is a mode-specific
fact the issue's false-negatives section gets backwards.

### The `--rexec` boundary

```
--rexec, label=neatlabel
in-payload: /dev/fd/200     served: neatlabel     exe: /memfd:neatlabel (deleted)
```

The served view is still the label.  The "served versus `exe`" check no
longer fails by name because `exe` is the memfd, so the memfd name is the
remaining signal.

### Verdict: **design limit**

Both halves are structural.  The served view is `saved_auxv` rewritten by
`PR_SET_MM_MAP`, which is the mechanism the whole design rests on.  The
in-payload view is the kernel's own copy on the process stack, which pmask
does not own and must not corrupt: a program that reads
`getauxval(AT_EXECFN)` and finds a label there has been lied to by its own
runtime, and nothing userland can do about that is compatible with "every
program keeps its real argv".

### Trades of the alternatives

| alternative | cost |
|---|---|
| skip the auxv rewrite | `AT_EXECFN` then names the block's scratch or the real path while `cmdline` names the label — a new disagreement that a detector can read without `/proc/<pid>/mem`; also breaks `AT_EXECFN == env_end` |
| rewrite the payload's stack copy | pmask would have to know where the kernel put it and rewrite it before the program runs; the stack is the kernel's, and a wrong offset is a crash; the program's own `argv`/`argv[0]` handling depends on the same region |
| leave as is | the served view disagrees with the payload's own view in every redacting mode; that is the documented boundary |

---

## Cross-cutting: what a defender should actually run

For each channel the narrow rule is the conjunction, never one clause.  The
measured facts that change a rule someone might already have written:

1. `cmdline` shorter than the `stat` span never fires (issue 40).  Both
   lengths are equal in default mode.
2. `AT_EXECFN == arg_start` never fires; the pointer is at `env_end` when the
   environment is redacted (issue 43).
3. `AT_EXECFN == env_end` misses `--keep-env`; the offset does not
   (issue 43).
4. `--no-exact` keeps neither the extent nor the dissent on the ELF entry
   path; it keeps the NUL count (issues 40 and 43).
5. `PMASK_NO_SELFMASK` does not remove the self-mask in redact or isolate
   mode; it only does on the plain path (issue 39).
6. A `literal:` secret never reaches the payload's `environ`; only its name
   and descriptor number do (issue 41).

## Where each claim lives in the source

| claim | source |
|---|---|
| the startup zeroing, before the parse | `src/main.rs` `main`, `zero_argv_block` under the `PMASK_NO_SELFMASK` test |
| the runner re-masks after the fork, unconditionally | `src/run.rs` `Runner::run`, the `Mode::Redact` and `Mode::Isolate` arms |
| the self-mask steps and their order | `src/selfmask.rs` `mask_self_label_with_window` |
| the argv/env window relocation and the auxv rewrite | `src/execimg.rs` `relocate_windows`, called only under `cfg.exact` |
| the block layout, including the second label copy | `src/execimg.rs` `build_redaction_block`, `label_presentation_len` |
| the same layout for the supervisor | `src/selfmask.rs` `relocate_own_window` |
| `--comm` size and the three label cut points | `src/mask.rs` `validate`, `to_config`, `ENTRY_SCRATCH_LABEL` |
| the environ shapes | `src/execimg.rs` `redact_after_exec` step 5, `src/mask.rs` `keep_environ_visible` |
| the warning and the audit refusal | `src/main.rs` `check_no_selfmask`, `warn_keep_env_secret`; `src/caps.rs` `kernel_audit_reachable` |

## What this batch did not do

- Did not run `tests/run.sh` or `vm/run.sh`.  The instructions for this batch
  say not to while other agents are working.  The five fragments were run
  directly, and `cargo test --locked --lib` was run.
- Did not measure on the VM gate.  Every number is from this container.
- Did not fix `--comm` accepting LF/CR.  That is fix1's issue #33; this batch
  asserts the current behaviour and names the dependency.
- Did not edit `docs/DESIGN.md`, `docs/THREAT-MODEL.md`,
  `docs/research/detection-*.md`, `README.md` or `man/`.  The corrections
  above are recorded here for whichever batch owns those files.
- Did not touch `src/mask.rs` or `src/tracer.rs`.  No issue in this batch
  required it.
