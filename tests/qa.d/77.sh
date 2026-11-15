#!/bin/sh
# Issue 77: plain mode leaves the supervisor's cmdline as a NUL run.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
"$TOOL" -q --no-redact -l q77 -- "$CASES" sleeper 2 >/dev/null 2>&1 & sup=$!; sleep 0.7
cmd=$(tr '\0' ' ' < "/proc/$sup/cmdline" 2>/dev/null)
case "$cmd" in
    *pmask*) pass q77-supervisor-argv ;;
    *) fail "q77-supervisor-argv [$cmd]" ;;
esac
len=$(wc -c < "/proc/$sup/cmdline" 2>/dev/null | tr -d ' ')
nul=$(tr -cd '\0' < "/proc/$sup/cmdline" 2>/dev/null | wc -c | tr -d ' ')
[ "$nul" != "$len" ] && pass q77-not-a-nul-run || fail q77-not-a-nul-run
kill -9 "$sup" 2>/dev/null; wait "$sup" 2>/dev/null
echo "################ QA77: FAIL=$FAIL"
[ "$FAIL" = 0 ]
