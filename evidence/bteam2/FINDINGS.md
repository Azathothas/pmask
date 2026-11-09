# b-team 2: cross-cutting notes

Two things that are not in any single issue's directory.

## A pre-existing leak in `tests/isolation.sh`

Found while running the full native gate for this batch. It is **not** mine
and it is **not** touched by this branch; it is recorded here because it makes
`tests/edge.sh` fail intermittently for whoever runs the gate next.

`tests/isolation.sh` starts two long-lived payloads in its matrix group and
never kills them:

```
965:  "$TOOL" run --label mkisomatrix --no-dumpable -- "$CASES" sleeper "$MATRIX_CAN" &
      MATRIX_SUP=$!
968:  MK_ISO_ENV="$MATRIX_CAN" "$CASES" sleeper "$MATRIX_CAN" &
      MATRIX_CTL=$!
```

Its `cleanup` is `kill_comm mkiso KILL`. `kill_comm` matches the *comm* of a
process, not its argv. The supervisor and the payload carry the label
`mkisomatrix` and are killed; the **control** is a plain
`testcases sleeper PMKISO-<pid>`, whose comm is `testcases`, so it is never
matched and is reparented to init when the suite ends.

`tests/edge.sh`'s `e6` case then walks `/proc` looking for any process whose
cmdline looks like a real argv, and reports the orphan:

```
FAIL e6-supervisor-selfmask (leak=1 selfmasked=1 leakers:
  3744678:[testcases][/workspace/wt/bteam2/tests/testcases sleeper PMKISO-3670527])
```

It reproduced twice in three consecutive `sh tests/run.sh` runs of this batch,
and `sh tests/edge.sh` alone passes when no orphan is present. The fix belongs
to whoever owns `isolation.sh`: kill `MATRIX_CTL` in its `cleanup` (or use
`kill_label`, which is what the b-team fragments use for exactly this reason).
Not fixed here: `tests/isolation.sh` is not this batch's file and the change
is another agent's to make.

## Why every fragment kills by label *and* by pid

The same mechanism bit this batch's own fragments: a fragment that exits
through an assertion, a timeout or a signal leaves whatever it started
running, and the gate's world-wide sweeps then attribute that process to
whatever case happens to be scanning. `tests/qa.d/50.sh` leaked a
`testcases holdargs` this way once (observed in the first full-gate run of
this batch).

Both halves are needed:

- **by pid**, because a payload started by `sh` may not have a label yet when
  the trap fires;
- **by label**, because a payload started by pmask detaches from the
  fragment's process tree and the pid recorded for the supervisor is not the
  payload's pid.

Proved with a planted abort in `50.sh`: without the cleanup, the control
`holdargs` stays parked; with it, nothing survives the abort.
