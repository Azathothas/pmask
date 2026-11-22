#!/bin/sh
# Issue 76: --rexec silently runs the on-disk program when the image
# cannot be placed.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
T=$(mktemp -d "${TMPDIR:-/tmp}/qa76.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
( ulimit -n 64; "$TOOL" -q --rexec -l q76 -- "$CASES" exe-id >/dev/null 2>"$T/q76.err" )
rc=$?
case "$rc" in
    126|127) pass q76-fail-closed ;;
    *) fail "q76-fail-closed (rc=$rc $(head -1 "$T/q76.err"))" ;;
esac
grep -q 'RLIMIT_NOFILE' "$T/q76.err" && pass q76-names-the-limit \
    || fail "q76-names-the-limit ($(head -1 "$T/q76.err"))"
rm -f "$T/q76.err"
echo "################ QA76: FAIL=$FAIL"
[ "$FAIL" = 0 ]
