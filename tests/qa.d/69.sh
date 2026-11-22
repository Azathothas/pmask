#!/bin/sh
# Issue 69: --exec-once runs the pmask binary when the payload execs
# /proc/self/exe.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
out=$("$TOOL" -q --exec-once -l q69 -- "$CASES" selfexec 2>&1); rc=$?
if [ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'SELF-SECOND' \
    && ! printf '%s' "$out" | grep -q 'Usage:'; then
    pass q69-self-exec-runs-the-payload
else
    fail "q69-self-exec-runs-the-payload (rc=$rc out=$(printf '%s' "$out" | head -c 120))"
fi
out=$("$TOOL" -q --rexec -l q69 -- "$CASES" selfexec 2>&1)
printf '%s' "$out" | grep -q 'SELF-SECOND' && pass q69-rexec-control \
    || fail "q69-rexec-control ($out)"
echo "################ QA69: FAIL=$FAIL"
[ "$FAIL" = 0 ]
