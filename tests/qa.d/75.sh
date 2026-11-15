#!/bin/sh
# Issue 75: exact mode breaks ordinary stat and [stack] invariants.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
"$TOOL" -q -l q75 -- "$CASES" sleeper 2 >/dev/null 2>&1 & sup=$!; sleep 0.8
pay=""; for d in /proc/[0-9]*; do [ "$(cat "$d/comm" 2>/dev/null)" = q75 ] && { pay=${d#/proc/}; break; }; done
if [ -n "$pay" ]; then
    set -- $(awk '{sub(/.*\) /,""); print $46,$47,$48,$49,$26}' "/proc/$pay/stat")
    as=$1; ae=$2; es=$3; ee=$4; ss=$5
    [ "$es" = "$ae" ] && pass q75-no-gap || fail "q75-no-gap ($ae/$es)"
    [ "$ee" -gt "$es" ] && pass q75-env-span || fail q75-env-span
    [ "$ss" -lt "$as" ] && pass q75-start-stack || fail "q75-start-stack ($ss/$as)"
    grep -q '\[stack\]' "/proc/$pay/maps" && pass q75-stack-vma || fail q75-stack-vma
else
    fail q75-payload-not-found
fi
kill -9 "$pay" "$sup" 2>/dev/null; wait "$sup" 2>/dev/null
echo "################ QA75: FAIL=$FAIL"
[ "$FAIL" = 0 ]
