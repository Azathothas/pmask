# docs2 evidence

Working notes for the docs2 batch (DESIGN, THREAT-MODEL, research, releases).
Host for every measurement below: Debian 13, kernel `6.12.113+deb13-amd64`,
x86_64, uid 1000 gid 1000, `CapEff 0000000000000000`, LXC container,
`kernel.yama.ptrace_scope = 0`, binary built from this worktree at `fa46e62`
with `cargo build --locked --release --bins`.

## Issue 61

- `61-four-hunk.patch`: the four-hunk patch extracted verbatim from
  `/workspace/meta/issues/61.md`.
- `61-git-apply-check.log`: `git apply --check` on the qa-base tree, `rc=0`,
  then the applied result.
- `61-source-checks.log`: the source lines the patch relies on, read from this
  worktree: `arg_end = block.base + label.len() as u64 + 1`
  (`src/execimg.rs:879`), `execfn = 1 + fl + argv.len()`
  (`src/execimg.rs:1058`), the tracer thread `pmask-tracer`
  (`src/mask.rs:1042`), and the `--detach` doc comment that makes `TracerPid`
  0 at rest.

## Re-measurements

- `measured-shape.log`: `pmask -q -l ci-runner -- /bin/sleep 8`; child read
  0.5 s in. `cmdline` 10 bytes, `stat` span 10, `environ` 0 bytes, `comm`
  `ci-runner`, `TracerPid` non-zero.
- `measured-auxv.log`: the same run; `AT_EXECFN == env_end` (delta 0),
  `execfn - arg_start = 12` for `argc=2`, both `arg_start` and `AT_EXECFN` in
  a `[stack]` mapping, and the bytes at `AT_EXECFN` are `ci-runner\0`.
- `measured-tracerpid.log`: default run reads `TracerPid` 2062321 for
  supervisor 2062315; `/proc/2062321/status` has `Tgid: 2062315` and
  `Pid: 2062321`, `comm` `pmask-tracer`, and the tid is absent from
  `readdir("/proc")`. `--detach` reads `TracerPid: 0`.
- `measured-supervisor-environ.log`: the supervisor's own entry (`cmdline`
  8 bytes for `sup-lab`, `environ` refused, `Threads: 2`, `exe` and `maps`
  refused); `--no-exact` gives a 39-byte NUL `environ` and an 11-byte
  `cmdline` for a two-argument payload; `--keep-env=PATH` gives 145 bytes.
- `measured-stack-string.log`: the real `/bin/sleep` string is still in the
  payload's `[stack]` and in an anonymous mapping while `environ` reads 0.

The two `--no-exact` and `--keep-env` captures are the shapes issues 40 and
41 describe; they were taken to check the rows, not to change the documents
beyond the rows cited in the report.
