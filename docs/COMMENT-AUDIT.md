# Source comment audit

This is the comment half of the documentation batch. It lists every comment
in `src/` whose stated fact is wrong once the fix branches merge. The
reconciler applies these after the source branches merge; `qa/docs3` does not
edit `src/`.

Line numbers are from `qa-base` (`fa46e62`). They shift in the merged tree;
match on the quoted text, not the number.

## Wrong after the merge

### 1. Rename redirection is unconditional

- File: `src/tracer.rs`, line 36
- Current:
  `/// (`SECCOMP_RET_TRACE`); the tracer reverts renames to the label.`
- Replacement:
  `/// (`SECCOMP_RET_TRACE`). The tracer redirects the rename to the label,`
  `/// or refuses the call when it cannot reach the label address.`
- Why: `qa/fix1` commit `320c056` refuses a `prctl(PR_SET_NAME)` whose label
  address is not reachable in a non-dumpable tracee. The call then fails and
  `comm` keeps the label; `--watch-rename --no-dumpable` is no longer
  "revert on every rename".

### 2. Same claim on the seccomp handler

- File: `src/tracer.rs`, line 1294
- Current:
  `/// `prctl(PR_SET_NAME)` only.  The rename is redirected to the label.`
- Replacement:
  `/// `prctl(PR_SET_NAME)` only.  The rename is redirected to the label`
  `/// when the label address is reachable, and refused otherwise.`
- Why: same change as item 1 (`qa/fix1` commit `320c056`,
  `redirect_rename`).

### 3. The label always names the image memfd

- File: `src/rexec.rs`, line 29
- Current:
  `//!   label sets the memfd name.`
- Replacement:
  `//!   memfd name is the label unless `--memfd-name` sets another.`
- Why: `qa/bteam5` adds `--memfd-name NAME` (`src/cli.rs:193` in that
  branch). The default remains the label, so the sentence is wrong only as
  an absolute.

### 4. Same claim on `prepare`

- File: `src/rexec.rs`, line 332
- Current:
  `/// Copy `program` into a sealed memfd named after `label`.`
- Replacement:
  `/// Copy `program` into a sealed image memfd. The name is `label` unless`
  `/// `--memfd-name` supplied another.`
- Why: same flag as item 3. `prepare` in that branch takes the chosen name
  from the mask rather than deriving it only from `label`.

### 5. `pmaskd` has no secret store

- File: `src/daemon.rs`, line 150
- Current heading:
  `//! # Secret store`
- Replacement:
  `//! # Job environment`
- Why: the section that follows describes `mlock` and the wipe of the job
  environment, not an encrypted store. The store belongs to `pmask agent`
  (issue 24, `qa/fix3` commit `a487a5a`, and `man/pmaskd.8`).
  The heading is the only "ownership" claim; the prose itself is correct.

### 6. `read_main` exit status is incomplete

- File: `src/secret.rs`, line 719
- Current:
  `/// be found or read, 255 on a usage error.`
  The full paragraph claims only 0, 1 and 255.
- Replacement:
  `/// be found, read or written to a terminal (2 for the terminal refusal),`
  `/// and 255 on a usage error.`
- Why: `read_main` returns 2 when the destination is a terminal and
  `--tty` is absent (`src/subcmd.rs:873` in `qa-base`). The man page now
  states 2; the comment should too.

## Stale in `qa-base` but removed by a fix branch

These comments are wrong in `qa-base` and already deleted by `qa/fix1`.
Listed so the reconciler does not restore them while resolving conflicts.

### 7. `SIGSTOP` handshake

- File: `src/tracer.rs`, lines 360 to 362
- Current:
  `/// child's `SIGSTOP` handshake stop as the point from which the first`
  `/// exec is supervised.`
- State after merge: the whole paragraph is replaced by the
  `PTRACE_INTERRUPT` description in `qa/fix1` commit `d0cadd7`.

### 8. Second `SIGSTOP` mention

- File: `src/tracer.rs`, line 484
- Current:
  `// Signal 0 suppresses the handshake SIGSTOP.`
- State after merge: removed with the `wait_master_stop` path in
  `qa/fix1` commit `d0cadd7`; the release now follows a
  `PTRACE_EVENT_STOP`.

## Checked and not wrong

- Tracer thread name: the only statement is the code at
  `src/mask.rs:1042`, `.name("pmask-tracer".into())`. No comment claims a
  different name, and no fix branch renames the thread. Issue 38 is a
  research finding, not a documentation defect.
- `--no-dumpable` and `payload_dumpable`: the comments at
  `src/run.rs:559` and `src/run.rs:841` describe the request; after
  `qa/fix2` the report field is computed from the selected mode, and the
  comments there are updated in that branch. No stale copy remains in
  `qa-base` other than the two rename claims above.
- Test counts: I found no comment in `src/` that states a test or case
  count. The suite counts live in `tests/` and `evidence/`, not in source
  comments.

## Comments I could not verify

- Whether `qa/bteam5` merges at all. Items 3 and 4 describe its
  `--memfd-name` flag; if that branch is dropped, the comments are already
  correct and the two replacements must not be applied.
- Whether the reconciler keeps the `qa/fix1` handshake hunk verbatim. Items
  7 and 8 are correct only if that hunk survives the merge.

## Evidence

- `evidence/docs3/comment-audit-grep.log`: the raw line excerpts used above.
- Source of truth: `git show qa/fix1:src/tracer.rs`,
  `git show qa/bteam5:src/cli.rs`, `git show qa/fix3:contrib/systemd/pmaskd@.service`,
  and the `qa-base` lines quoted above.
