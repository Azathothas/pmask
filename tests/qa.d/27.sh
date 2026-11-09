#!/bin/sh
# QA fragment for issue 27: `-q` did not suppress the isolation report.
#
# The defect: `Runner` has a `quiet` field and applies it to the mask path,
# but `isolate::run` took no quiet flag and `report_and_print` printed the
# effective set unconditionally.
#
# Cases:
#   qa27-quiet-isolate        `-q --isolate` prints no isolation line
#   qa27-quiet-redact-isolate `-q --redact --isolate` does either
#   qa27-payload-still-runs   the payload runs and exits with its own status
#   qa27-control-not-quiet    without -q the line IS printed, so the case
#                             above cannot pass vacuously
#   qa27-control-quiet-mask   `-q` on the redaction path still prints
#                             nothing from the session summary
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa27.$$"
mkdir -p "$D" || { echo "FAIL qa27-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    kill_label qa27 KILL 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT

if ! unshare -Ur true 2>/dev/null; then
    skip "qa27-user-namespaces (unshare -Ur true refused here)"
    echo "== VERDICT: SKIP =="
    exit 0
fi

"$TOOL" -q --isolate -- /bin/sh -c 'exit 7' >"$D/q.out" 2>"$D/q.err"
rc=$?
if [ "$rc" = 7 ]; then
    pass "qa27-payload-still-runs (exit 7 passed through)"
else
    fail "qa27-payload-still-runs (rc=$rc)"
fi
if grep -q "^pmask: isolation:" "$D/q.err"; then
    fail "qa27-quiet-isolate (isolation line printed: $(head -1 "$D/q.err"))"
else
    pass "qa27-quiet-isolate"
fi
if grep -q "isolation degraded" "$D/q.err"; then
    fail "qa27-quiet-isolate-no-degradation-lines ($(head -1 "$D/q.err"))"
else
    pass "qa27-quiet-isolate-no-degradation-lines"
fi

"$TOOL" -q --redact --isolate -- /bin/true >"$D/ri.out" 2>"$D/ri.err"
rc=$?
if [ "$rc" = 0 ] && ! grep -q "^pmask: isolation:" "$D/ri.err"; then
    pass "qa27-quiet-redact-isolate"
else
    fail "qa27-quiet-redact-isolate (rc=$rc stderr=$(tr '\n' '|' <"$D/ri.err"))"
fi

# Control: without -q the report IS printed.  A tool that never printed
# the line would pass every case above.
"$TOOL" --isolate -- /bin/true >"$D/loud.out" 2>"$D/loud.err"
rc=$?
if [ "$rc" = 0 ] && grep -q "^pmask: isolation:" "$D/loud.err"; then
    pass "qa27-control-not-quiet-prints-the-line"
else
    fail "qa27-control-not-quiet-prints-the-line (rc=$rc stderr=$(tr '\n' '|' <"$D/loud.err"))"
fi

# Control: the mask path's own summary is quiet under -q as before.
"$TOOL" -q -l qa27 -- /bin/true >"$D/m.out" 2>"$D/m.err"
if ! grep -q "^pmask: mode=" "$D/m.err"; then
    pass "qa27-control-quiet-mask-summary"
else
    fail "qa27-control-quiet-mask-summary (stderr=$(tr '\n' '|' <"$D/m.err"))"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
