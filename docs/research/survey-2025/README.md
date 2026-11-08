# 2025 process-concealment survey

This folder holds the queries, the replay script and the review ledger
behind the prior-art comparison in `docs/research/`.

- Survey date: 2026-11-03.
- Window: repositories created on or after 2025-01-01. No end date;
  everything up to the survey date counts.
- Access: the pkgforge services only, which proxy GitHub and web search.
- Review ledger: [`triage.md`](triage.md), one verdict and one reason per
  row.
- Review data: [`review/`](review/), the per-row source reading.
- Replay: [`search.py`](search.py) and [`queries.json`](queries.json).

## Coverage, and what it does not mean

"Every repository" is not a claim this survey can make. GitHub search
returns capped result sets, and no query language enumerates a topic.
What was done is 194 queries (60 repository, 74 code, 60 web) plus 7
manual Chinese repository queries, aimed at every mechanism the
repository knows about.

Measurements from the run:

| step | count |
| --- | --- |
| queries issued | 194, plus 7 manual |
| unique repositories in search output | 5,276 |
| repositories with metadata fetched | 1,350 |
| of those, created on or after 2025-01-01 | 402 |
| rows after the first triage | 84 |
| rows reviewed against pmask | 84 |
| rows kept after review | 43 |
| kept rows inside the window | 34 |

The gap between 402 and 84 is the first judgement layer: hits whose
description was unrelated, documentation-only projects, forks with no
change, and repositories that no longer exist. The gap between 84 and 43
is the second: a review of every row against pmask's own properties, with
source read where the mechanism mattered. [`triage.md`](triage.md)
records all 84 verdicts and the 41 removals. An exclusion is a judgement
about this survey's purpose, not a claim that the tool does nothing.

Repository search was the productive channel. Code search did not find
the one 2025 project that uses `PR_SET_MM_MAP`, because the string
appears in kernel trees and the API caps results at 100 per query. Search
code, then confirm the repository with repository search, then read the
source. Do not treat a code search miss as absence.

## Endpoints

Observed paths and limits on 2026-11-03:

| service | path | limit |
| --- | --- | --- |
| repository search | `https://forge.web.pkgforge.dev/github/search/repositories?q=&per_page=100&sort=stars` | 30 requests/min |
| code search | `https://forge.web.pkgforge.dev/github/search/code?q=&per_page=100` | 10 requests/min |
| web search | `https://search.web.pkgforge.dev/search?q=&count=10` | no limit observed, 1.2 s spacing used |
| core API | `https://forge.web.pkgforge.dev/github/...` | 5,000 requests/hour |

Code search has no `created` filter. Recency had to be recovered per
repository from the metadata response, which is why every candidate got a
metadata fetch.

Other limits seen during the run: repository search answered `502` once;
`/repos/t0mmysen/ghost_process` answered `404` because the repository was
deleted; code search produced one TLS timeout, one `IncompleteRead` and
one `408`. The replay script logs the failing query to stderr and
continues.

## Replaying

[`search.py`](search.py) reads [`queries.json`](queries.json) and writes
one JSON line per result. Test one query before the full run, which takes
about two hours at the limits above.

```sh
python3 search.py repo --out repo.jsonl --limit 1
python3 search.py repo --out repo.jsonl
python3 search.py code --out code.jsonl
python3 search.py web  --out web.jsonl
```

The script appends, so delete the output file before a fresh run.

## What the ledger records

`triage.md` is the row-by-row verdict. The `basis` column is the evidence
behind a row, and it is the column to read first:

- `source read` means the code that implements the mechanism was read.
- `README`, `rules + fixtures read`, `README + client source` and similar
  mean only the named material was read.
- `description` means only the repository description and metadata were
  read.

No kept row rests on the repository description alone. Two rest on the
README: `Mao` (README plus tree) and `claw-wrap` (README). The other 41
cite source or a named document. Two rows that could not be read at all
were removed in the review: `Wcccc06/adf` answered `404` on its README
and `K0rnhulio/ksu_hideproc` had no readable files.

Nothing in this survey was built or run. Every mechanism claim is the
source's or README's claim, not a measurement from this machine.
