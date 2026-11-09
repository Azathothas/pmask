# docs2 evidence

Working notes for the docs2 batch (DESIGN, THREAT-MODEL, research, releases).

- `61-four-hunk.patch`: the four-hunk patch extracted verbatim from
  `/workspace/meta/issues/61.md`, applied with `git apply`.
- `61-git-apply-check.log`: `git apply --check` result on the qa-base tree
  (`rc=0`), then the applied result.
- `61-source-checks.log`: the source lines the patch relies on, read from this
  worktree at `fa46e62`.
