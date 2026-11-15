#!/bin/sh
# Issue 72: --watch-rename with the default detach leaves a filter with
# no tracer.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
out=$("$TOOL" -q --watch-rename --detach -l q72 -- "$CASES" sleeper 1 2>&1); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$out" | grep -q 'on-exit detach'; then
    pass q72-detach-refused
else
    fail "q72-detach-refused (rc=$rc out=$out)"
fi
out=$("$TOOL" -q --watch-rename -l q72 -- "$CASES" sleeper 1 2>&1); rc=$?
[ "$rc" = 0 ] && pass q72-default-keeps-tracer || fail "q72-default-keeps-tracer (rc=$rc)"
echo "################ QA72: FAIL=$FAIL"
[ "$FAIL" = 0 ]
