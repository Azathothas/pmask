# Issue 8 evidence: completions miss seven flags

Date: 2026-11-09 (`date -u`). Host: Linux 6.12.113+deb13-amd64 x86_64,
uid 1000, cargo 1.99.1.

## Change

`completions/pmask.bash`, `pmask.fish`, `_pmask` gained `--image`,
`--image-from-fd`, `--exec-once`, `--hugetlb`, `--rexec-allow-disk`,
`--redact`, `--audit`, plus bash's `-c`/`-f`. The check also found
`--no-exitkill`, a real alias in `src/cli.rs:495` (`"no-exit-kill" |
"no-exitkill"`) that none of the three tables offered, so it was added
too.

`src/bin/pmaskd.rs` accepts only the options the `pmaskd` tables already
carry (16 long, 7 short); the daemon tables needed no change, and the new
guard asserts that rather than assuming it.

`scripts/check-completions.sh` extracts the option names from the parser
(source of truth, read only) and compares them against each table in both
directions:

1. every long option in `src/cli.rs` appears in `pmask.bash`, `pmask.fish`
   and `_pmask`;
2. every long option in `src/bin/pmaskd.rs` appears in `pmaskd.bash`,
   `pmaskd.fish` and `_pmaskd`;
3. every short option in each parser appears in the matching bash table;
4. no bash table offers an option the parser would refuse;
5. `bash -n` parses both bash tables.

Extraction is from the parser's own match arms, not from `--help` text:
a line is a candidate only when it is a run of quoted lowercase literals
followed by `=>`, so an error-message literal ("unknown option --{}") is
not mistaken for an option.

## Commands and verdicts

- `sh scripts/check-completions.sh` on the pre-fix table
  (`git show HEAD:completions/pmask.bash`): exit 1, naming
  `--image --image-from-fd --exec-once --hugetlb --rexec-allow-disk
  --redact --audit --no-exitkill -f -c`. See `baseline.log`.
- `sh scripts/check-completions.sh` on the fixed tree: exit 0,
  `== COMPLETIONS: FAIL=0 ==`, 40 long options and 11 short options for
  `pmask`, 16 long and 7 short for `pmaskd`. See `baseline.log`.
- Plant test: each of the ten flags was deleted from `pmask.bash` one at
  a time and the guard run; all ten exited 1 and named the deleted flag,
  then the file was restored and the guard exited 0. See `baseline.log`
  (`## Plant test`).

## Wiring

- `.github/workflows/ci.yml`, job `check`, step `completions`:
  `sh scripts/check-completions.sh`.
- `tests/run.sh`: a `completions` stage before the suites. A missing
  script is a FAIL there, not a SKIP.
