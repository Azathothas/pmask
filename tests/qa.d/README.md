# QA fragments

One POSIX `sh` fragment per issue, named `<issue>.sh`, run by
`tests/qa.sh`. The fragment runs with cwd `tests/qa.d`, so the helper
library is `. ../lib.sh` and the built binaries are `../pmask`,
`../pmaskd`, `../testcases`.

Rules:

- Print `PASS <name>`, `FAIL <name>` or `SKIP <name> (<reason>)`.
- Exit nonzero if any case failed.
- A property of the form "nothing sees X" needs the negative control:
  the observer must see the marker without the fix and must not see it
  with the fix, and the payload must still work.
- Never turn an undecidable case into a pass. Print `SKIP` and say why.
- Keep each fragment independent: fresh markers, scoped cleanup, no
  assumption that another fragment ran first.