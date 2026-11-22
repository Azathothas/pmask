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
nuls() { od -An -tx1 "/proc/$1/cmdline" 2>/dev/null | tr ' ' '\n' | grep -c '^00$'; }
env -u _ "$CASES" sleeper BIG >/dev/null 2>&1 & ctl=$!; sleep 0.5
set -- $(spans "$ctl"); cas=$1; ces=$2; kill -9 "$ctl" 2>/dev/null
env -u _ "$TOOL" -q --no-exact -l q74 -- "$CASES" sleeper BIG >/dev/null 2>&1 & sup=$!; sleep 0.8
# The supervisor carries the label too, so the payload is found by comm
# plus exe; measuring the supervisor reports the tracer's own window.
pay=$(payload_pid q74 testcases 5)
if [ -n "$pay" ]; then
    set -- $(spans "$pay")
    [ "$1" = "$cas" ] && pass "q74-argv-extent ($1 = control $cas)" || fail "q74-argv-extent ($1 vs $cas)"
    [ "$2" = "$ces" ] && pass "q74-env-extent ($2 = control $ces)" || fail "q74-env-extent ($2 vs $ces)"
    n=$(nuls "$pay")
    [ "$n" = 1 ] && pass "q74-no-nul-run (NULs=$n in $1 bytes)" || fail "q74-no-nul-run (NULs=$n)"
    [ "$(head -c 3 "/proc/$pay/cmdline" 2>/dev/null)" = q74 ] &&
        pass "q74-label-visible (cmdline[0..2]=q74)" || fail "q74-label-visible"
    n=$(tr '\0' '\n' < "/proc/$pay/environ" 2>/dev/null | grep -c '^PATH=')
    [ "$n" -le 2 ] && pass "q74-env-unique (PATH entries=$n)" || fail "q74-env-unique (PATH=$n)"
else
    fail q74-payload-not-found
fi
kill -9 "$sup" $pay 2>/dev/null; wait "$sup" 2>/dev/null
echo "################ QA74: FAIL=$FAIL"
[ "$FAIL" = 0 ]
