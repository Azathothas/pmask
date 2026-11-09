#!/bin/sh
# QA fragment for issue 13: `probe`/`doctor` reported the exact cmdline
# window as active where redaction is unavailable.
#
# The defect: the row describes `prctl(PR_SET_MM_MAP)`, which may be
# callable, but next to "metadata redaction unavailable" a bare "active"
# reads as a redaction guarantee; `doctor --require=exact` returned 0.
#
# Cases:
#   qa13-control-redaction-active   on a ptrace host the exact row is not
#                                   n/a, so the n/a row below is not the
#                                   only outcome the code can produce
#   qa13-exact-row-is-na            with ptrace denied the row says n/a
#   qa13-exact-row-explains         the row's reason says there is no
#                                   redaction for it to make exact
#   qa13-doctor-exact-degraded      `doctor --require=exact` exits 3
#   qa13-doctor-exact-json          the JSON verdict agrees (exit 3)
#   qa13-control-doctor-exact-ok    on the real host it exits 0
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa13.$$"
mkdir -p "$D" || { echo "FAIL qa13-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() { rm -rf "$D"; }
trap cleanup EXIT

PMASK_PROBE_PTRACE=0 "$TOOL" probe >"$D/denied.txt" 2>"$D/denied.err"
rc=$?
if [ "$rc" = 0 ]; then
    pass "qa13-probe-with-denied-ptrace-exits-zero"
else
    fail "qa13-probe-with-denied-ptrace-exits-zero (rc=$rc err=$(tr '\n' '|' <"$D/denied.err"))"
fi

# The row is one line; the state word is the second column.
exact_line=$(grep -m1 "^  exact cmdline window" "$D/denied.txt")
case "$exact_line" in
    *"n/a"*) pass "qa13-exact-row-is-na [$exact_line]" ;;
    *) fail "qa13-exact-row-is-na (row=[$exact_line])" ;;
esac
case "$exact_line" in
    *"no redaction"*) pass "qa13-exact-row-explains" ;;
    *) fail "qa13-exact-row-explains (row=[$exact_line])" ;;
esac
# The row must still be present: a reader must never infer it from an
# absence.
if [ -n "$exact_line" ]; then
    pass "qa13-exact-row-is-present"
else
    fail "qa13-exact-row-is-present (the row vanished)"
fi

PMASK_PROBE_PTRACE=0 "$TOOL" doctor --require=exact >"$D/doc.txt" 2>"$D/doc.err"
rc=$?
if [ "$rc" = 3 ]; then
    pass "qa13-doctor-exact-degraded (exit 3)"
else
    fail "qa13-doctor-exact-degraded (rc=$rc out=$(tr '\n' '|' <"$D/doc.txt" | cut -c1-300))"
fi

PMASK_PROBE_PTRACE=0 "$TOOL" doctor --json --require=exact >"$D/doc.json" 2>/dev/null
rc=$?
json_exit=$(sed -n 's/.*"exit": \([0-9]*\).*/\1/p' "$D/doc.json" | head -1)
if [ "$rc" = 3 ] && [ "$json_exit" = "3" ]; then
    pass "qa13-doctor-exact-json (exit=$json_exit)"
else
    fail "qa13-doctor-exact-json (rc=$rc json exit=[$json_exit])"
fi

# Control: on a host where ptrace works, exact is active and the doctor
# exits 0.  A build that always printed n/a would pass the rows above and
# fail this one.
"$TOOL" probe >"$D/host.txt" 2>/dev/null
if grep -q "^  metadata redaction *active" "$D/host.txt"; then
    host_exact=$(grep -m1 "^  exact cmdline window" "$D/host.txt")
    case "$host_exact" in
        *"n/a"*) fail "qa13-control-redaction-active-keeps-the-row (row=[$host_exact])" ;;
        *) pass "qa13-control-redaction-active-keeps-the-row [$host_exact]" ;;
    esac
    "$TOOL" doctor --require=exact >/dev/null 2>&1
    rc=$?
    if [ "$rc" = 0 ]; then
        pass "qa13-control-doctor-exact-ok (exit 0)"
    else
        fail "qa13-control-doctor-exact-ok (rc=$rc)"
    fi
else
    skip "qa13-control-redaction-active-keeps-the-row (this host cannot redact)"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
