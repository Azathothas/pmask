# Source comment audit

This records the comments in `src/` that were wrong once the fix branches
merged, and the replacement each one got. It is kept as a record of the
sweep, not as a work order: every item below is applied in this tree, so
a reader who finds an item that does not match the code should treat that
as a fresh defect and file it, not as an instruction.

## Applied

1. `src/tracer.rs`, module doc: "the tracer reverts renames to the label"
   became "redirects the rename to the label, or refuses the call when it
   cannot reach the label address" (issue 60).
2. `src/tracer.rs`, `on_seccomp_stop`: the same correction on the
   seccomp-stop handler.
3. `src/rexec.rs`, module doc and `prepare`: the memfd name is the label
   unless `--memfd-name` supplied another (issue 45).
4. `src/daemon.rs`: the section heading "Secret store" became "Job
   environment"; the store belongs to `pmask agent` (issue 24).
5. `src/run.rs` and `src/cli.rs`: `payload_dumpable` describes the
   payload's `PR_GET_DUMPABLE`, and only the redaction path makes it
   false (issue 21).
6. `src/secret.rs`: `read_main` returns 2 for the terminal refusal
   (issue 36 F25).
7. `src/run.rs`: a reference to a non-existent `docs/DEFAULTS.md` now
   points at the privilege ladder in `docs/DESIGN.md`.
8. `src/isolate.rs`, `src/cli.rs`: the `-q` and `--redact --isolate`
   notes described fixed defects as open; both now state the behaviour.
9. `src/subcmd.rs`, `src/main.rs`: `PMASK_SECRET_<NAME>`, not `<N>`.

## Removed by the fix branches, not restored

The `SIGSTOP` handshake paragraphs in `src/tracer.rs` (issue 4 replaced
them with the `PTRACE_INTERRUPT` description).

## Checked and correct

- No comment in `src/` states a test or case count.
- The tracer thread name appears only as code (`tracer_thread_name`), not
  as a comment claiming a different value.
