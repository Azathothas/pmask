#!/bin/sh
# QA fragment for issue 36: F17, F22, F25, F27, F28.
#
# F17 `--report text|plain` were accepted and did nothing; the parser now
#     refuses them and names the default.
# F22 the man page's `--daemon` refusal list omitted `--image`; the page
#     now lists it and the parser really refuses it.
# F25 store exit codes: 1 for a missing secret, 255 for a usage error.
# F27 help and man page say PMASK_SECRET_<NAME>, not PMASK_SECRET_<N>.
# F28 `--image-from-fd` names its argv[0] placeholder in help and man.
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa36.$$"
mkdir -p "$D" || { echo "FAIL qa36-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() { rm -rf "$D"; }
trap cleanup EXIT

# ---------------------------------------------------------------- F17
for form in text plain; do
    "$TOOL" -q --no-redact --report=$form -- /bin/true >"$D/f17.out" 2>"$D/f17.err"
    rc=$?
    if [ "$rc" = 255 ] && grep -q -- "--report takes json" "$D/f17.err"; then
        pass "qa36-f17-report-$form-refused"
    else
        fail "qa36-f17-report-$form-refused (rc=$rc err=$(tr '\n' '|' <"$D/f17.err"))"
    fi
    if grep -q "the default output" "$D/f17.err"; then
        pass "qa36-f17-report-$form-names-the-default"
    else
        fail "qa36-f17-report-$form-names-the-default (err=$(tr '\n' '|' <"$D/f17.err"))"
    fi
done
# Control: the accepted spelling still works, so the rows are about the
# value and not about refusing `--report` outright.
"$TOOL" -q --no-redact --report=json -- /bin/true >"$D/f17ok.json" 2>"$D/f17ok.err"
rc=$?
if [ "$rc" = 0 ] && grep -q '"mode"' "$D/f17ok.json"; then
    pass "qa36-f17-control-json-still-accepted"
else
    fail "qa36-f17-control-json-still-accepted (rc=$rc err=$(tr '\n' '|' <"$D/f17ok.err"))"
fi

# ---------------------------------------------------------------- F22
F22_CODE=0
"$TOOL" -q --daemon "$D/no.sock" --image /bin/true -- /bin/true >"$D/f22.out" 2>"$D/f22.err"
rc=$?
if [ "$rc" = 255 ] && grep -q -- "--image" "$D/f22.err"; then
    pass "qa36-f22-daemon-refuses-image"
else
    fail "qa36-f22-daemon-refuses-image (rc=$rc err=$(tr '\n' '|' <"$D/f22.err"))"
fi
MAN="$BIN_DIR/../man/pmask.1"
if [ -r "$MAN" ]; then
    # The DAEMON MODE section: the --image line has to be among the
    # refused flags, so grep the section rather than the whole page.
    if sed -n '/^\.SH DAEMON MODE/,/^\.SH EXIT STATUS/p' "$MAN" | grep -q '\\-\\-image'; then
        pass "qa36-f22-man-daemon-section-names-image"
    else
        fail "qa36-f22-man-daemon-section-names-image (man page omits --image)"
    fi
    # Control: the section really is the one under test.
    if sed -n '/^\.SH DAEMON MODE/,/^\.SH EXIT STATUS/p' "$MAN" | grep -q '\\-\\-isolate'; then
        pass "qa36-f22-man-daemon-section-is-present"
    else
        fail "qa36-f22-man-daemon-section-is-present (the section could not be read)"
    fi
else
    skip "qa36-f22-man-daemon-section-names-image (man/pmask.1 not staged)"
fi

# ---------------------------------------------------------------- F25
printf 'qa36-pass\n' >"$D/pp"
chmod 600 "$D/pp"
STORE="$D/s.enc"
"$TOOL" store init --store "$STORE" --passphrase-file "$D/pp" >/dev/null 2>&1
printf 'v' | "$TOOL" store set A --store "$STORE" --passphrase-file "$D/pp" >/dev/null 2>&1
"$TOOL" store get NOPE --store "$STORE" --passphrase-file "$D/pp" >/dev/null 2>"$D/f25.err"
rc=$?
if [ "$rc" = 1 ]; then
    pass "qa36-f25-missing-secret-is-one (exit 1)"
else
    fail "qa36-f25-missing-secret-is-one (rc=$rc err=$(tr '\n' '|' <"$D/f25.err"))"
fi
"$TOOL" store get --store "$STORE" --passphrase-file "$D/pp" >/dev/null 2>"$D/f25b.err"
rc=$?
if [ "$rc" = 255 ]; then
    pass "qa36-f25-usage-error-is-255 (exit 255)"
else
    fail "qa36-f25-usage-error-is-255 (rc=$rc err=$(tr '\n' '|' <"$D/f25b.err"))"
fi
# Control: the value is readable, so the store is not simply broken.
got=$("$TOOL" store get A --store "$STORE" --passphrase-file "$D/pp" 2>/dev/null)
if [ "$got" = "v" ]; then
    pass "qa36-f25-control-store-get-works"
else
    fail "qa36-f25-control-store-get-works (got=[$got])"
fi
if [ -r "$MAN" ]; then
    if grep -q "1 when the store holds no secret" "$MAN"; then
        pass "qa36-f25-man-documents-the-convention"
    else
        fail "qa36-f25-man-documents-the-convention (the page does not state it)"
    fi
else
    skip "qa36-f25-man-documents-the-convention (man/pmask.1 not staged)"
fi

# ---------------------------------------------------------------- F27
if "$TOOL" --help 2>&1 | grep -q "PMASK_SECRET_<NAME>"; then
    pass "qa36-f27-help-says-NAME"
else
    fail "qa36-f27-help-says-NAME ($("$TOOL" --help 2>&1 | grep -o 'PMASK_SECRET_[^ ,)]*' | head -1))"
fi
if "$TOOL" --help 2>&1 | grep -q "PMASK_SECRET_<N>"; then
    fail "qa36-f27-help-drops-the-N-spelling"
else
    pass "qa36-f27-help-drops-the-N-spelling"
fi
if [ -r "$MAN" ]; then
    if grep -q "PMASK_SECRET_<NAME>" "$MAN"; then
        pass "qa36-f27-man-says-NAME"
    else
        fail "qa36-f27-man-says-NAME ($(grep -m1 'PMASK_SECRET' "$MAN"))"
    fi
else
    skip "qa36-f27-man-says-NAME (man/pmask.1 not staged)"
fi
# The code's spelling is the contract; `<NAME>` is what the delivery
# writes.  A secret called `deploy-token` reaches the child as
# PMASK_SECRET_DEPLOY_TOKEN.
if "$TOOL" --secret deploy-token=literal:x --help 2>&1 | grep -q "PMASK_SECRET_<NAME>"; then
    pass "qa36-f27-code-and-help-agree"
else
    fail "qa36-f27-code-and-help-agree (the help text changed under the test)"
fi

# ---------------------------------------------------------------- F28
if "$TOOL" --help 2>&1 | grep -q "fd image"; then
    pass "qa36-f28-help-names-the-argv0-placeholder"
else
    fail "qa36-f28-help-names-the-argv0-placeholder (the placeholder is undocumented)"
fi
if [ -r "$MAN" ]; then
    if grep -q "fd image" "$MAN"; then
        pass "qa36-f28-man-names-the-argv0-placeholder"
    else
        fail "qa36-f28-man-names-the-argv0-placeholder"
    fi
else
    skip "qa36-f28-man-names-the-argv0-placeholder (man/pmask.1 not staged)"
fi
# The placeholder is real: --image-from-fd with no --argv0 gives it.
if "$TOOL" -q --image-from-fd 3 --argv0 qa36-argv0 3</bin/true -- /bin/true \
    >"$D/f28.out" 2>"$D/f28.err"; then
    pass "qa36-f28-argv0-can-override-the-placeholder"
else
    skip "qa36-f28-argv0-can-override-the-placeholder (--image-from-fd refused: $(tr '\n' '|' <"$D/f28.err"))"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
