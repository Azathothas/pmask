#!/bin/sh
# Issue 65: --no-dumpable drops the --exec-once fast path.
# The combination is now refused before the fork; a plain --exec-once
# still runs a payload that execs /proc/self/exe.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
out=$("$TOOL" -q --exec-once --no-dumpable -l q65 -- "$CASES" selfexec 2>&1); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$out" | grep -q 'dumpable tracee'; then
    pass q65-exec-once-refuses-no-dumpable
else
    fail "q65-exec-once-refuses-no-dumpable (rc=$rc out=$out)"
fi
out=$("$TOOL" -q --exec-once -l q65 -- "$CASES" selfexec 2>&1); rc=$?
if [ "$rc" = 0 ] && printf '%s' "$out" | grep -q SELF-SECOND; then
    pass q65-exec-once-self-exec
else
    fail "q65-exec-once-self-exec (rc=$rc out=$out)"
fi
echo "################ QA65: FAIL=$FAIL"
[ "$FAIL" = 0 ]
