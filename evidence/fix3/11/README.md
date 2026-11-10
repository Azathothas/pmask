# Evidence: issue 11 — an unknown `--secret` scheme was delivered silently

## The defect

`Source::parse` fell through to `Source::Literal(rest)` for any source
that was not one of the known prefixes.  A typo such as
`--secret TOK=flie:/etc/passwd` therefore delivered the string
`flie:/etc/passwd`, with no line anywhere naming `flie`.  The run either
succeeded (with the escape hatch) or was refused with a message that
named only `literal:` — the scheme the operator had mistyped was never
mentioned.

## What was measured

Host: Debian container, uid 1000.  Baseline `/tmp/basebin/pmask`
(`qa-base`, `fa46e62`).

| command | baseline | fixed |
|---|---|---|
| `--secret TOK=flie:/x --allow-argv-secret -- true` | exit 0, **no line names `flie`** | exit 0, one warning: `'flie:' is not a known secret scheme (literal:, file:, env:, agent:, daemon)` |
| the same, then `sh -c 'cat <&3'` | `flie:/x` | `flie:/x` (the literal is still delivered) |
| `--secret TOK=abc123 --allow-argv-secret` | silent | silent (control) |
| `--secret TOK=/etc/passwd` | silent | silent (control) |
| `--secret TOK=./a:b` | silent | silent (control) |
| `--secret TOK=file:PATH` | silent | silent (control) |
| `-q --secret TOK=flie:/x` | silent | silent (`-q` suppresses it) |
| `--secret TOK=flie:/x` without the escape hatch | refused 255, message names only `literal:` | refused 255, **and** the scheme warning is printed first |

Raw output: `repro.log`, `qa-fixed.log`, `qa-baseline.log`.

## The fix

`Source::parse_spec` returns `(name, source, Option<scheme>)`.  The third
element is set only when the source begins `word:` and `word` is not one
of `literal:`, `file:`, `env:`, `agent:`, `daemon:`; `scheme_candidate`
is deliberately narrow (short run of ASCII alphanumerics plus `-_.+`), so
a path, a relative path with a colon and a token containing a colon are
not mistaken for a typo.  `Source::parse` keeps its signature and drops
the third element.

The CLI collects the unknown schemes while parsing and prints them after
the whole command line is read, so the last of `-q` and `-v` decides
whether the warning appears — the same rule the daemon-option warning
follows.  The warning is one line and names the secret, the word, every
known scheme and the consequence.

The value is **not** refused.  `--secret TOK=flie:/x` still delivers
`flie:/x`: a literal containing a colon is legal, and turning a typo into
a hard failure would break a working command line.  What changed is that
the run no longer looks like a `file:` source.

## Verdicts

- `sh tests/qa.d/11.sh` (fixed): 8 PASS, exit 0.
- The same fragment against the baseline: 5 PASS, 3 FAIL, exit 3.
- `cargo test --locked --lib secret::` → 20 passed, 0 failed; three new
  cases pin the third element, the silent controls and the message text.
