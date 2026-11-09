#!/bin/sh
# QA fragment for issue 11: an unknown `--secret` scheme was delivered as
# a literal with no diagnostic, so `--secret TOK=flie:/etc/passwd`
# delivered the string `flie:/etc/passwd` and looked like a working file
# source.
#
# Cases:
#   qa11-typo-warns               `TOK=flie:/x` prints one warning naming
#                                 `flie:`
#   qa11-typo-warning-names-known the warning lists the real schemes, so
#                                 the operator can correct it
#   qa11-typo-still-delivers      the same run still delivers the literal
#                                 `flie:/x` (a typo is data, not a fatal)
#   qa11-bare-value-silent        `TOK=abc123` prints no warning (the
#                                 control: the fix must not make every
#                                 literal noisy)
#   qa11-bare-path-silent         `TOK=/etc/passwd` and `TOK=./a:b` are
#                                 silent too
#   qa11-known-scheme-silent      `TOK=file:PATH` prints no scheme warning
#   qa11-quiet-suppresses         `-q` suppresses the warning
#   qa11-refusal-names-the-run    without `--allow-argv-secret` the plain
#                                 run still refuses, and the warning is
#                                 printed before the refusal
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
[ -x "$TOOL" ] || { echo "FATAL: $TOOL is missing"; exit 2; }
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa11.XXXXXX") || {
    echo "FATAL: mktemp -d failed"; exit 2; }
chmod 700 "$D"
trap 'rm -rf "$D"' EXIT INT TERM

# Count the scheme warning's occurrences in a stderr file.  The exact
# sentence is what the operator reads, so the case greps for it rather
# than for the word "warning", which every note also carries.
scheme_warnings() {
    n=$(grep -c "is not a known secret scheme" "$1" 2>/dev/null)
    [ -n "$n" ] || n=0
    echo "$n"
}

# ------------------------------------------------- the typo'd scheme
# `-q` suppresses it, so the case that checks the warning exists runs
# without -q; the quiet case comes later as its own assertion.
"$TOOL" --no-redact --secret TOK=flie:/x --allow-argv-secret \
    -- /bin/true >"$D/typo.out" 2>"$D/typo.err"
rc=$?
n=$(scheme_warnings "$D/typo.err")
if [ "$rc" = 0 ] && [ "$n" = 1 ]; then
    pass "qa11-typo-warns ($(grep "is not a known secret scheme" "$D/typo.err" | head -1))"
elif [ "$n" = 0 ]; then
    fail "qa11-typo-warns (no warning in stderr: $(head -2 "$D/typo.err" | tr '\n' '|'))"
else
    fail "qa11-typo-warns ($n warnings, want exactly 1)"
fi

# The message has to name the word that was typed, and at least one real
# scheme, or the operator cannot tell what to change.
if grep -q "'flie:'" "$D/typo.err" && grep -q "literal:" "$D/typo.err"; then
    pass "qa11-typo-warning-names-known"
else
    fail "qa11-typo-warning-names-known ($(grep "is not a known" "$D/typo.err" | head -1))"
fi

# The run is not refused: a typo is data.  The literal is what reaches
# the payload, on descriptor 3.  `cat <&3` reads the delivered value.
got=$("$TOOL" -q --no-redact --secret TOK=flie:/x --allow-argv-secret \
    -- /bin/sh -c 'cat <&3' 2>/dev/null)
if [ "$got" = "flie:/x" ]; then
    pass "qa11-typo-still-delivers ($got)"
else
    fail "qa11-typo-still-delivers (got [$got], want [flie:/x])"
fi

# ------------------------------------------------------- the controls
# A bare value names no scheme and must stay silent.  This is the case
# that keeps the fix from turning every `--secret TOK=value` into a
# warning.
"$TOOL" --no-redact --secret TOK=abc123 --allow-argv-secret \
    -- /bin/true >/dev/null 2>"$D/bare.err"
n=$(scheme_warnings "$D/bare.err")
[ "$n" = 0 ] && pass "qa11-bare-value-silent" \
    || fail "qa11-bare-value-silent ($n warnings: $(grep 'not a known' "$D/bare.err" | head -1))"

# A path and a relative path with a colon are values, not schemes.
"$TOOL" --no-redact --secret TOK=/etc/passwd --allow-argv-secret \
    -- /bin/true >/dev/null 2>"$D/path.err"
n1=$(scheme_warnings "$D/path.err")
"$TOOL" --no-redact --secret 'TOK=./a:b' --allow-argv-secret \
    -- /bin/true >/dev/null 2>"$D/rel.err"
n2=$(scheme_warnings "$D/rel.err")
if [ "$n1" = 0 ] && [ "$n2" = 0 ]; then
    pass "qa11-bare-path-silent"
else
    fail "qa11-bare-path-silent (path=$n1 rel=$n2)"
fi

# A known scheme is silent.
printf 'tok\n' > "$D/token"
chmod 600 "$D/token"
"$TOOL" --no-redact --secret "TOK=file:$D/token" --allow-argv-secret \
    -- /bin/true >/dev/null 2>"$D/known.err"
n=$(scheme_warnings "$D/known.err")
[ "$n" = 0 ] && pass "qa11-known-scheme-silent" \
    || fail "qa11-known-scheme-silent ($n warnings)"

# `-q` suppresses it, like every other note.
"$TOOL" -q --no-redact --secret TOK=flie:/x --allow-argv-secret \
    -- /bin/true >/dev/null 2>"$D/quiet.err"
n=$(scheme_warnings "$D/quiet.err")
[ "$n" = 0 ] && pass "qa11-quiet-suppresses" \
    || fail "qa11-quiet-suppresses ($n warnings under -q)"

# Without the escape hatch, the plain run is refused (that behaviour is
# unchanged), and the warning is printed before the refusal so the
# operator sees the typo as well as the refusal.
out=$("$TOOL" --no-redact --secret TOK=flie:/x -- /bin/true 2>&1 >/dev/null)
rc=$?
case "$out" in
    *"not a known secret scheme"*)
        [ "$rc" = 255 ] \
            && pass "qa11-refusal-names-the-run (rc=$rc)" \
            || fail "qa11-refusal-names-the-run (rc=$rc, want 255)"
        ;;
    *)
        fail "qa11-refusal-names-the-run (rc=$rc, err=[$(printf '%s' "$out" | head -2 | tr '\n' '|')])"
        ;;
esac

echo "== VERDICT: $FAIL failure(s) =="
exit "$FAIL"
