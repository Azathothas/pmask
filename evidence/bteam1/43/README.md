# Issue 43 evidence: `AT_EXECFN` and the in-payload dissent

Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86-64, uid 1000.
`/proc/<pid>/auxv` is readable by any uid; resolving the pointer needs
`/proc/<pid>/mem`, which is same-uid or root.

| log | what it shows |
|---|---|
| `execfn-layout.log` | the served label at three label lengths, plus the plain control |
| `execfn-relations.log` | whether `AT_EXECFN` is `env_end` or `1+label+argc`, per mode |
| `execfn-no-exact-dissent.log` | `--no-exact` does **not** rewrite the auxv |
| `execfn-modes.log` | `--keep-env`, `--detach`, `--rexec` |
| `qa43.log` | the fragment's own output |

## The issue is right about the main shape

`execfn-layout.log`, payload `testcases execfn 20` (argv has three entries:
`testcases execfn 20`):

```
masked, label=abcd (4 bytes)
payload printed: execfn=/workspace/wt/bteam1/target/release/pmask-testcases
auxv+mem:        execfn_ptr=...44072 str=abcd
stat:            arg_start=...44064 arg_end=...44069 env_start=...44072 env_end=...44072
exe:             /workspace/wt/bteam1/target/release/pmask-testcases
```

- `/proc/<pid>/auxv` resolves `AT_EXECFN` to the label.
- `AT_EXECFN == env_end` and `AT_EXECFN != arg_start`.
- the payload's own `getauxval(AT_EXECFN)` prints the real path.
- the second label copy sits at `1 + len(label) + argc`: 8 for a 4-byte
  label, 16 for a 12-byte label, with `argc = 3`.
- the plain control has `AT_EXECFN == env_end` too, and the pointer resolves
  to the real path.

## Two corrections to the issue

### 1. `AT_EXECFN == env_end` only holds when the environment is redacted

`execfn-relations.log`:

```
exact,label4       env_start=...422216 env_end=...422216 AT_EXECFN=...422216  env_end-ptr=0
exact,label12      env_start=...134608 env_end=...134608 AT_EXECFN=...134608  env_end-ptr=0
keep-env,label4    env_start=140731932532657 env_end=140731932532676 AT_EXECFN=139891444633608  env_end-ptr=840487899068
keep-env,label12   env_start=140737409040305 env_end=140737409040324 AT_EXECFN=139733903212560  env_end-ptr=1003505827764
no-exact,label4    env_start=...206467 env_end=...206468 AT_EXECFN=...206468  env_end-ptr=0
```

With `--keep-env` the environment window keeps its original addresses, so
`env_end` is far away and the `env_end == AT_EXECFN` rule produces no hit.
The rule a detector can use in every mode is the **offset**:
`AT_EXECFN - arg_start == 1 + len(label) + argc`, which held at 8 and 16
in all three modes.

### 2. `--no-exact` does not rewrite the auxv at all

The issue says "under `--no-exact` the block layout differs and the offset
formula does not describe the second copy; the dissent still holds."
Measured (`execfn-no-exact-dissent.log`), the dissent does **not** hold —
there is no dissent, because there is no rewrite:

```
## exact mode, label=neatlabel
in-payload: execfn=/tmp/qa43-probe
served:     execfn_ptr=...327757 str=neatlabel

## --no-exact, label=neatlabel
in-payload: execfn=/tmp/qa43-probe
served:     execfn_ptr=...477864 str=/tmp/qa43-probe
cmdline:    [neatlabel|||]
```

The auxv rewrite lives inside `PR_SET_MM_MAP`, which `--no-exact` skips
(`src/execimg.rs` `relocate_windows` is called only when `cfg.exact`).  So
in `--no-exact` both views agree, and a detector that compares them gets
nothing.  This is a strictly weaker mode for the served view: `/proc/<pid>/auxv`
names the real binary while `cmdline` shows the label.

## The `--rexec` boundary

```
## --rexec, label=neatlabel
in-payload: execfn=/dev/fd/200
served:     execfn_ptr=...492941 str=neatlabel
exe:        /memfd:neatlabel (deleted)
```

The served view still serves the label, the in-payload view names the
carrier, and `exe` names the memfd.  The "served vs `exe`" check no longer
fails by name; the memfd name replaces it.

## What the fragment asserts

`a2` served label, `a3` `AT_EXECFN == env_end`, `a4` `AT_EXECFN != arg_start`,
`a5` in-payload real path, `a6` the two disagree, `a7` the second-copy
offset, `a9` the relation at 4 and 12 bytes, `a10` `--no-exact` agrees with
the payload, `a11` `--keep-env` breaks the `env_end` relation.  `a1`/`a1b`
are the plain control.

## Residual

Neither the served view nor the in-payload dissent can be closed in
userland: the served view is `saved_auxv` rewritten by design, and the
in-payload view is the kernel's own stack, which pmask does not own.  See
`docs/research/bteam-39-43.md` §43.
