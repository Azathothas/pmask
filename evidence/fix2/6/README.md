# Issue 6: `pmask store --help` and `pmask get --help` printed no help

## What was wrong

`cmd_store` took `args.first()` as the verb before it looked for
`-h/--help`, so `store --help` resolved a passphrase (and failed with
"no terminal" under the gate); `cmd_get` turned every non-option token
into the secret name, so `get --help` tried to reach an agent.

Commit: `96a6c82 fix: handle help as the first store and get token`.

## What changed

- `cmd_store` parses options and positionals in one pass, handles
  `-h/--help` anywhere, refuses an unknown option or verb *before* the
  passphrase prompt, and prints a real usage block (`STORE_HELP`).
- `cmd_get` recognises `-h/--help`, `--socket` (inline and separate),
  refuses an unknown option, and takes at most one NAME.

## Evidence

- `before-fragment.log` — `tests/qa.d/6.sh` against a build of
  `qa-base` (fa46e62 + the dispatcher commit): 6 FAIL, the defect.
- `after-fragment.log` — the same fragment against this branch: 8 PASS,
  `== VERDICT: FAIL=0 ==`, exit 0.

## Commands

```
cargo build --release --bins --features testbins    # exit 0
sh tests/qa.d/6.sh                                  # exit 0, FAIL=0
cargo fmt --all -- --check                          # exit 0
cargo clippy --locked --all-targets --features testbins -- -D warnings  # exit 0
cargo test --locked --lib                           # 174 passed
```
