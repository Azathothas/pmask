# Source comment audit

The audit below records inaccurate comments in `src/` after the fix branches merged and lists each replacement.
The list serves as a historical record, not a work order.
Every item below is already applied in the repository.
If an item does not match the code, treat the mismatch as a new defect and file an issue.

## Applied

1. `src/tracer.rs`, module doc: Replaced `"the tracer reverts renames to the label"` for issue #60. The updated text reads `"redirects the rename to the label, or refuses the call when it cannot reach the label address"`. In `v0.1.0`, issue #71 extended `--watch-rename` comments to cover `open`, `openat`, `openat2`, `creat`, and `--watch-rename=strict` write traps.
2. `src/tracer.rs`, `on_seccomp_stop`: Applied the same correction to the seccomp-stop handler comment.
3. `src/rexec.rs`, module doc and `prepare`: Clarified that the memfd name uses the label unless `--memfd-name` supplies another name (issue #45).
4. `src/daemon.rs`: Renamed the section heading `"Secret store"` to `"Job environment"`. The secret store belongs to `pmask agent` (issue #24).
5. `src/run.rs` and `src/cli.rs`: Clarified that `payload_dumpable` describes the payload `PR_GET_DUMPABLE` state. Only the redaction path sets `payload_dumpable` to false (issue #21).
6. `src/secret.rs`: Clarified that `read_main` returns exit code 2 for a terminal refusal (issue #36 F25).
7. `src/run.rs`: Replaced a broken reference to `docs/DEFAULTS.md` with the privilege ladder in `docs/DESIGN.md`.
8. `src/isolate.rs` and `src/cli.rs`: Updated `-q` and `--redact --isolate` comments to state the fixed behaviour instead of open defects.
9. `src/subcmd.rs` and `src/main.rs`: Corrected the environment variable pattern from `PMASK_SECRET_<N>` to `PMASK_SECRET_<NAME>`.

## Removed by the fix branches, not restored

The fix for issue #4 removed the `SIGSTOP` handshake paragraphs from `src/tracer.rs`.
The `PTRACE_INTERRUPT` description replaced those paragraphs.

## Checked and correct

- No comment in `src/` states a test count or case count.
- The tracer thread name appears only in code (`tracer_thread_name`), not in comments that claim a different value.
