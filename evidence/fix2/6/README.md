# issue 6 evidence

## defect before the fix (fa46e62 build)
pmask store --help -> exit 255, "no terminal to ask for a passphrase"
pmask get --help   -> exit 1, "no agent socket is configured"

## after the fix
```
    Finished `release` profile [optimized] target(s) in 0.02s
PASS qa6-control-a-verb-without-a-passphrase-prompts (rc=255)
PASS qa6-store-help---help
PASS qa6-store-help--h
PASS qa6-get-help---help
PASS qa6-get-help--h
PASS qa6-unknown-verb-refused-before-the-passphrase
PASS qa6-unknown-store-option-named
PASS qa6-help-after-the-verb
== VERDICT: FAIL=0 ==
```
