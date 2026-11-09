#!/bin/sh
# QA fragment for issue 30: `--env =VALUE` was accepted in plain mode and
# refused in redaction mode.
#
# The defect: the parser split KEY=VALUE and never rejected an empty key.
# The redaction path validated the mask's pairs and refused, while the
# plain path passed the pair to `Command::env` and ran.
#
# Cases:
#   qa30-control-a-valid-env-pair-is-accepted  the shape of the argument
#                                              is not what is refused
#   qa30-redact-refuses-an-empty-key           --env =VALUE exits 255
#   qa30-plain-refuses-an-empty-key            the same input exits 255
#   qa30-isolate-refuses-an-empty-key          and in isolate mode
#   qa30-message-names-the-empty-key           the refusal shows the value
#   qa30-env-file-still-refuses-an-empty-key   the file parser agrees
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa30.$$"
mkdir -p "$D" || { echo "FAIL qa30-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() { rm -rf "$D"; }
trap cleanup EXIT

"$TOOL" -q --no-redact --env K=V -- /bin/sh -c 'echo k=$K' >"$D/ok.out" 2>"$D/ok.err"
rc=$?
if [ "$rc" = 0 ] && grep -q '^k=V$' "$D/ok.out"; then
    pass "qa30-control-a-valid-env-pair-is-accepted"
else
    fail "qa30-control-a-valid-env-pair-is-accepted (rc=$rc out=[$(cat "$D/ok.out")] err=$(tr '\n' '|' <"$D/ok.err"))"
fi

"$TOOL" -q --env =VALUE -- /bin/true >"$D/r.out" 2>"$D/r.err"
rc=$?
if [ "$rc" = 255 ]; then
    pass "qa30-redact-refuses-an-empty-key"
else
    fail "qa30-redact-refuses-an-empty-key (rc=$rc err=$(tr '\n' '|' <"$D/r.err"))"
fi

"$TOOL" -q --no-redact --env =VALUE -- /bin/true >"$D/p.out" 2>"$D/p.err"
rc=$?
if [ "$rc" = 255 ]; then
    pass "qa30-plain-refuses-an-empty-key"
else
    fail "qa30-plain-refuses-an-empty-key (rc=$rc err=$(tr '\n' '|' <"$D/p.err"))"
fi

"$TOOL" -q --isolate --env =VALUE -- /bin/true >"$D/i.out" 2>"$D/i.err"
rc=$?
if [ "$rc" = 255 ]; then
    pass "qa30-isolate-refuses-an-empty-key"
else
    fail "qa30-isolate-refuses-an-empty-key (rc=$rc err=$(tr '\n' '|' <"$D/i.err"))"
fi

# The refusal must name the empty key the way the mask's own validation
# does, so one wording covers every mode.
if grep -q 'environment variable name "" must not be empty' "$D/p.err"; then
    pass "qa30-message-names-the-empty-key"
else
    fail "qa30-message-names-the-empty-key (err=$(tr '\n' '|' <"$D/p.err"))"
fi

# The same rule in the file parser: a line with an empty key is refused.
printf '=VALUE\n' >"$D/envfile"
"$TOOL" -q --no-redact --env-file "$D/envfile" -- /bin/true >"$D/f.out" 2>"$D/f.err"
rc=$?
if [ "$rc" = 255 ]; then
    pass "qa30-env-file-still-refuses-an-empty-key"
else
    fail "qa30-env-file-still-refuses-an-empty-key (rc=$rc err=$(tr '\n' '|' <"$D/f.err"))"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
