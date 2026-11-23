#!/bin/sh
# Issue 73: --hide-pid does not hide the tree from cgroupfs or non-/proc
# syscalls.  The channels are documented and the help says so.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
help=$("$TOOL" --help=all 2>&1)
printf '%s' "$help" | grep -q 'cgroup.procs' && pass q73-help-names-cgroup \
    || fail q73-help-names-cgroup
if printf '%s' "$help" | grep -q 'sched_getaffinity'; then
    pass q73-help-names-syscalls
else
    fail q73-help-names-syscalls
fi
out=$("$TOOL" -q --hide-pid --detach -l q73 -- "$CASES" sleeper 1 2>&1); rc=$?
[ "$rc" = 255 ] && pass q73-detach-refused || fail "q73-detach-refused (rc=$rc)"
echo "################ QA73: FAIL=$FAIL"
[ "$FAIL" = 0 ]
