# Competitor comparison

The table below summarizes measurements from the repository audits in `docs/REDTEAM-RESULTS.md` and `docs/research/bteam-*`.
A cell is marked "measured" only when a recorded run exists in this repository.
A cell marked "read" comes from the competitor source code or documentation.
The test gate does not ship or download any competitor binary.

| property | pmask (`v0.1.0`) | zapper | psgen (proc-self tier) | plain `env -i` process |
|---|---|---|---|---|
| `cmdline` | the label, one NUL (exact mode) | the label, padded, 164-175 byte NUL run measured | template argv | real argv |
| `cmdline` bytes vs `stat` span | equal (`arg_end = arg_start + len(label) + 1`) | equal (in-place extent) | not applicable | equal |
| `comm` | the label | real payload name | template comm | real name |
| `comm` / `cmdline` agree | yes | no (`comm` stays real) | yes | yes |
| `environ` | complete decoy with non-zero span (or `--keep-env` values) | original extent, real values | fixed stub environment | real |
| `arg_end == env_start` | yes | yes | not applicable | yes |
| `start_stack` below `arg_start` | yes | yes | yes | yes |
| `[stack]` VMA | real 132 kB VMA with `gd` | untouched | synthesised process | real |
| `AT_EXECFN` served | the label (exact mode) | rewritten on the stack | the psgen binary (proc-self) | real path |
| payload `getauxval(AT_EXECFN)` | the label (exact mode, matches `/proc/<pid>/auxv`) | the label | the psgen binary | real path |
| `exe` | real by default, `/memfd:<label>` under `--rexec` | real | the psgen binary in proc-self, a template path in bind tier | real |
| survives a hidden-pid sweeper | yes by default (no pid hidden). `--hide-pid` opts into hiding | yes | yes (real pids) | yes |
| tracer residue | one tracer thread and `TracerPid != 0` unless `--detach` is set | ptrace-based, same class | none | none |
| real argv in memory | hidden block, same-uid readable unless `--no-dumpable` is set (`--secret` sets `--no-dumpable` by default) | original stack, same-uid readable | stub memory, not the workload | readable |
| later exec | cached carrier under `--exec-once`, authenticated (`dev`/`ino`/`ctime` and bytes) and fail-closed | re-applies the mask per exec | stubs only | real |

## What the table does and does not claim

`pmask` wins the measured `/proc` shape columns that a userland reader can inspect.
`pmask` sets both `comm` and `cmdline` to the label.
The `cmdline` is short and ends with a single NUL byte.
The `environ` window holds a complete decoy instead of the real environment.
The `stat`, `auxv`, and `[stack]` values match an ordinary `execve`.

`zapper` leaves the real `comm` and a long NUL run.
The `psgen` proc-self tier leaves the `psgen` binary in `exe` and runs a stub rather than the real workload.

`pmask` does not win the kernel-side channels.
An eBPF `sched_process_exec` sensor still sees the real image path at exec time.
`strace` still detects a tracer, and root still reads every mode.
A tool that runs the workload in another kernel, such as gVisor or a VM, closes those kernel channels.
A tool that only rewrites `argv` does not close them.

The table compares process shapes rather than computing a stealth score.
A defender applying the rules in issues #40 through #43 sees the label-versus-`exe` split on `pmask`.
The same defender sees the real `comm` and NUL run on `zapper`.
Neither tool is invisible, so the table records measurable differences instead of assertions.
