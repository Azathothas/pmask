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
D=$(mktemp -d "${TMPDIR:-/tmp}/qa72.XXXXXX") || exit 2
trap 'rm -rf "$D"' EXIT
out=$("$TOOL" -q --watch-rename --detach -l q72 -- "$CASES" sleeper 1 2>&1); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$out" | grep -q 'cannot be combined'; then
    pass q72-flag-detach-refused
else
    fail "q72-flag-detach-refused (rc=$rc out=$out)"
fi
# Issue 009 is about the policy, not the flag: the default `--on-exit
# detach` reaches the orphan-filter state for a descendant.  Asking for
# it explicitly must be refused, because the filter cannot be removed.
out=$("$TOOL" -q --watch-rename --on-exit detach -l q72 -- "$CASES" sleeper 1 2>&1); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$out" | grep -q -- '--on-exit detach would leave it'; then
    pass q72-policy-detach-refused
else
    fail "q72-policy-detach-refused (rc=$rc out=$out)"
fi
# The default policy waits for the tree, because a filter with no tracer
# is worse than a slow exit.  A payload that never exits is what tells the
# two policies apart: after a second the supervisor must still be there.
"$TOOL" -q --watch-rename -l q72 -- "$CASES" sleeper 1 >"$D/out" 2>&1 &
sup=$!
sleep 1
if kill -0 "$sup" 2>/dev/null; then
    pass q72-default-keeps-tracer
else
    fail "q72-default-keeps-tracer (returned while the tree was still alive)"
fi
kill "$sup" 2>/dev/null
wait "$sup" 2>/dev/null
pkill -9 -x testcases 2>/dev/null
echo "################ QA72: FAIL=$FAIL"
[ "$FAIL" = 0 ]
