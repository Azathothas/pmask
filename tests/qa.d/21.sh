#!/bin/sh
# QA fragment for issue 21: `payload_dumpable` was false in plain mode while
# the payload was dumpable.
#
# The defect: `src/run.rs` built the field from the request
# (`!self.no_dumpable`), while `--no-dumpable` is a redaction-mode
# treatment that plain mode never applies.  The report therefore
# contradicted the property `docs/DEPLOY.md` tells a watcher to assert on.
#
# Cases:
#   qa21-plain-reports-dumpable      plain + --no-dumpable says true
#   qa21-plain-payload-is-dumpable   the payload's real PR_GET_DUMPABLE is 1
#   qa21-note-says-not-applied       the report still names the dropped flag
#   qa21-redact-honours-the-request  redact + --no-dumpable says false, and
#                                    the payload's flag really is 0 (the
#                                    control that the field can be false)
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa21.$$"
mkdir -p "$D" || { echo "FAIL qa21-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    kill_label qa21 KILL 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT

# A payload that prints its own PR_GET_DUMPABLE, so the report is compared
# with the property and not with another report.
cat >"$D/dumpable.py" <<'PY'
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
print(libc.prctl(3, 0, 0, 0, 0))
PY
DUMPABLE=""
if command -v python3 >/dev/null 2>&1; then
    DUMPABLE="python3 $D/dumpable.py"
fi

"$TOOL" -q --no-redact --no-dumpable --report=json -- /bin/true \
    >"$D/plain.json" 2>"$D/plain.err"
rc=$?
if [ "$rc" = 0 ]; then
    pass "qa21-plain-run-exits-zero"
else
    fail "qa21-plain-run-exits-zero (rc=$rc err=$(tr '\n' '|' <"$D/plain.err"))"
fi

field=$(sed -n 's/^[[:space:]]*"payload_dumpable": \([a-z]*\).*/\1/p' "$D/plain.json" | head -1)
if [ "$field" = "true" ]; then
    pass "qa21-plain-reports-dumpable"
else
    fail "qa21-plain-reports-dumpable (report says [$field], the payload is dumpable in plain mode)"
fi

if grep -q -- "--no-dumpable was not applied" "$D/plain.json"; then
    pass "qa21-note-says-not-applied"
else
    fail "qa21-note-says-not-applied (notes: $(tr '\n' '|' <"$D/plain.json" | cut -c1-300))"
fi

if [ -n "$DUMPABLE" ]; then
    real=$("$TOOL" -q --no-redact --no-dumpable -- sh -c "$DUMPABLE" 2>/dev/null | tail -1)
    if [ "$real" = "1" ]; then
        pass "qa21-plain-payload-is-dumpable (PR_GET_DUMPABLE=1)"
    else
        fail "qa21-plain-payload-is-dumpable (PR_GET_DUMPABLE=[$real])"
    fi
else
    skip "qa21-plain-payload-is-dumpable (no python3 for prctl)"
fi

# Control: in redaction mode the request is applied, and the field can be
# false.  Without this a report hard-wired to true would pass above.  A
# report needs a secret-side run, so one file source makes the mode
# redaction without changing what the field describes.
printf 'qa21-token\n' >"$D/tok"
chmod 600 "$D/tok"
"$TOOL" -q --no-dumpable --secret T=file:"$D/tok" --report=json -- /bin/true \
    >"$D/redact.json" 2>"$D/redact.err"
rc=$?
field=$(sed -n 's/^[[:space:]]*"payload_dumpable": \([a-z]*\).*/\1/p' "$D/redact.json" | head -1)
if [ "$rc" = 0 ] && [ "$field" = "false" ]; then
    pass "qa21-redact-honours-the-request (payload_dumpable=false)"
else
    fail "qa21-redact-honours-the-request (rc=$rc payload_dumpable=[$field])"
fi

if [ -n "$DUMPABLE" ]; then
    real=$("$TOOL" -q --no-dumpable -- sh -c "$DUMPABLE" 2>/dev/null | tail -1)
    if [ "$real" = "0" ]; then
        pass "qa21-redact-payload-is-not-dumpable (PR_GET_DUMPABLE=0)"
    else
        fail "qa21-redact-payload-is-not-dumpable (PR_GET_DUMPABLE=[$real])"
    fi
else
    skip "qa21-redact-payload-is-not-dumpable (no python3 for prctl)"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
