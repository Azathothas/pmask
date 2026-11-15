# Competitor comparison

The measurements below are the ones in the repository's own audit
(`docs/REDTEAM-RESULTS.md`, `research/bteam-*`).  A cell is marked
"measured" only where a run exists in this tree; "read" means the
competitor's source or documentation.  No competitor binary is shipped
or downloaded by the gate.

| property | pmask (this tree) | zapper | psgen (proc-self tier) | a plain `env -i` process |
|---|---|---|---|---|
| `cmdline` | the label, one NUL | the label, padded; 164-175 byte NUL run measured | template argv | real argv |
| `cmdline` bytes vs `stat` span | equal (`arg_end = arg_start + len(label) + 1`) | equal (in-place extent) | not applicable | equal |
| `comm` | the label | the payload's real name | template comm | real name |
| `comm` / `cmdline` agree | yes | no (comm stays real) | yes | yes |
| `environ` | complete decoy, non-zero span | original extent, real values | fixed stub environment | real |
| `arg_end == env_start` | yes | yes | not applicable | yes |
| `start_stack` below `arg_start` | yes | yes | yes | yes |
| `[stack]` VMA | the real 132 kB VMA with `gd` | untouched | synthesised process | real |
| `AT_EXECFN` served | the label | rewritten on the stack | the psgen binary (proc-self) | real path |
| payload `getauxval(AT_EXECFN)` | the label | the label | the psgen binary | real path |
| `exe` | real by default, `/memfd:<label>` under `--rexec` | real | the psgen binary in proc-self, a template path in bind tier | real |
| survives a hidden-pid sweeper | yes (no pid hidden) | yes | yes (real pids) | yes |
| tracer residue | a tracer thread; `TracerPid != 0` unless `--detach` | ptrace-based, same class | none | none |
| real argv in memory | hidden block; same-uid read unless `--no-dumpable` | original stack, same-uid read | stub memory, not the workload | readable |
| later exec | cached carrier, authenticated, fail-closed | re-applies the mask per exec | stubs only | real |

## What the table does and does not claim

pmask wins the measured shape columns that a `/proc` reader can decide:
the label is the `comm` and the `cmdline`, the `cmdline` is short and
has a one-byte NUL run, the environment is a complete decoy rather than
the real one, and the `stat`/`auxv`/`[stack]` relations match an ordinary
exec.  `zapper` leaves the real `comm` and a long NUL run; `psgen`'s
proc-self tier leaves the psgen binary in `exe`, and the workload is a
stub rather than the real job.

pmask does not win the kernel-side channels.  An eBPF `sched_process_exec`
sensor still sees the real image path at exec time, `strace` still sees a
tracer, and root reads everything.  A competitor that hides in another
kernel (gVisor, a VM) wins those channels; a competitor that only
rewrites `argv` does not.

The comparison is a shape comparison, not a stealth score.  A defender
that uses the rules in issues 40-43 sees the label-versus-`exe` split on
pmask and the real `comm`/NUL run on zapper; neither tool is invisible,
and the table exists so the difference is measurable rather than
asserted.
