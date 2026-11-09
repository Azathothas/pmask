# How to land this work

This archive contains one branch, `qa/final`, on top of upstream
`fa46e62` (with the dependabot actions bump from PR #37 already merged).
It closes the 57 open issues listed in `ISSUE-CLOSURE.md` plus the
dependabot PR. Nothing here needs `gh` to build or verify.

## The four ways to land it

### 1. Carry the branch with a git bundle (recommended)

```sh
git clone pmask-team-red.bundle pmask
cd pmask
git checkout qa/final
git remote add upstream https://github.com/Azathothas/pmask
# push to your fork, then open the pull request with the body in PR-BODY.md
git push git@github.com:<you>/pmask.git qa/final:team-red/qa
gh pr create --repo Azathothas/pmask --base main --head <you>:team-red/qa \
    --title "Team Red: close the 57 issue backlog" --body-file PR-BODY.md
```

### 2. Apply the patch series to a fresh clone

```sh
git clone https://github.com/Azathothas/pmask pmask
cd pmask
git checkout -b team-red/qa fa46e62
git am --3way patches/*.patch
```

### 3. Merge the dependabot pull request first, then apply

```sh
gh pr merge 37 --repo Azathothas/pmask --merge   # or merge it in the web UI
git clone https://github.com/Azathothas/pmask pmask
cd pmask
git checkout -b team-red/qa
git am --3way patches/*.patch
```

### 4. Copy the tree

`tree/` is the working tree at `qa/final`. Copy it over a checkout of
`fa46e62` and commit. It is relocatable: no absolute path, no home
directory and no fixed prefix is baked in.

## After landing

- `ISSUE-CLOSURE.md` has one comment per issue, with the commit and the
  test that proves it. Post it, then close the issue.
- The dependabot PR #37 is already contained in the branch. If you land
  it separately, drop the first commit (`ci: bump the actions group`)
  before pushing.
- Run `verify.sh` on the target host before opening the pull request.

## What was not possible here

This host is an LXC container. It runs the native ptrace suites, but
`tracefs`, eBPF and the kernel audit subsystem are refused even for
root. The audit and eBPF findings are source-level plus the issues' own
guest measurements; the exact refusal is in `evidence/`. Run the audit
suite on a host with `auditd` before closing #56, #59 and the audit half
of #57.
