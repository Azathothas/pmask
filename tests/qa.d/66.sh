#!/bin/sh
# Issue 66: the post-exec window on script and later execs.
# --strict-exec refuses the shapes that cannot be redacted at entry.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
T=$(mktemp -d "${TMPDIR:-/tmp}/qa66.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
printf '#!/bin/sh\nexit 0\n' > "$T/s.sh"; chmod 755 "$T/s.sh"
out=$("$TOOL" -q --strict-exec -l q66 -- "$T/s.sh" 2>&1); rc=$?
if [ "$rc" != 0 ] && printf '%s' "$out" | grep -q 'strict-exec refuses'; then
    pass q66-strict-refuses-script
else
    fail "q66-strict-refuses-script (rc=$rc out=$out)"
fi
out=$("$TOOL" -q -l q66 -- "$T/s.sh" 2>&1); rc=$?
[ "$rc" = 0 ] && pass q66-default-runs-script || fail "q66-default-runs-script (rc=$rc out=$out)"
echo "################ QA66: FAIL=$FAIL"
[ "$FAIL" = 0 ]
