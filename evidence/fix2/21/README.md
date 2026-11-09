# Issue 21: `payload_dumpable` was false in plain mode while the payload was dumpable

Commit: `b6822b1 fix: compose redaction with the requested namespaces`.

## What changed

`Outcome.payload_dumpable` is `mode != Mode::Redact || !self.no_dumpable`.
The note that `--no-dumpable` was not applied stays. The doc comment on
`Outcome::payload_dumpable` now says the field describes the payload's
`PR_GET_DUMPABLE`, not the flag.

## Evidence

- `before-fragment.log`: `payload_dumpable: false` with the payload's
  `PR_GET_DUMPABLE` measured at 1.
- `after-fragment.log`: 6 PASS, `== VERDICT: FAIL=0 ==` — plain says true
  and the payload measures 1; the redaction control says false and the
  payload measures 0, so the field can be false.

## Commands

```
./target/release/pmask -q --no-redact --no-dumpable --report=json -- /bin/true | jq .payload_dumpable
sh tests/qa.d/21.sh    # exit 0, FAIL=0
```
