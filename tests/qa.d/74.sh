#!/bin/sh
# Issue 74: --no-exact does not keep the original argv extent, and its
# decoy environment is truncated and repeated.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
spans() { awk '{sub(/.*\) /,""); print $47-$46, $49-$48}' "/proc/$1/stat" 2>/dev/null; }
"$CASES" sleeper BIG >/dev/null 2>&1 & ctl=$!; sleep 0.5
set -- $(spans "$ctl"); cas=$1; ces=$2; kill -9 "$ctl" 2>/dev/null
"$TOOL" -q --no-exact -l q74 -- "$CASES" sleeper BIG >/dev/null 2>&1 & sup=$!; sleep 0.8
pay=""; for d in /proc/[0-9]*; do [ "$(cat "$d/comm" 2>/dev/null)" = q74 ] && { pay=${d#/proc/}; break; }; done
if [ -n "$pay" ]; then
    set -- $(spans "$pay")
    [ "$1" = "$cas" ] && pass q74-argv-extent || fail "q74-argv-extent ($1 vs $cas)"
    [ "$2" = "$ces" ] && pass q74-env-extent || fail "q74-env-extent ($2 vs $ces)"
    n=$(tr '\0' '\n' < "/proc/$pay/environ" 2>/dev/null | grep -c '^PATH=')
    [ "$n" -le 2 ] && pass q74-env-unique || fail "q74-env-unique (PATH=$n)"
else
    fail q74-payload-not-found
fi
kill -9 "$pay" "$sup" 2>/dev/null; wait "$sup" 2>/dev/null
echo "################ QA74: FAIL=$FAIL"
[ "$FAIL" = 0 ]
