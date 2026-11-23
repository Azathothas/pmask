#!/bin/sh
# Issue 71: write(2) to /proc/self/comm bypasses --watch-rename.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
T=$(mktemp -d "${TMPDIR:-/tmp}/qa71.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
# check MODE TAG: start the writer in MODE and report whether the rename
# was refused.  The writer prints the comm it ends up with, so the verdict
# is its own report, not a scan: a scan for the label matches the
# supervisor, which carries the label from the start and would pass the
# case no matter what the payload did.  The payload is then located by
# comm plus exe, so a refused write is shown to leave a live process
# presenting the label rather than merely no evidence of a rename.
check() {
    ck_mode=$1; ck_tag=$2
    "$TOOL" -q --profile compat --watch-rename -l q71 -- "$CASES" commwrite 3 "$ck_mode" \
        >"$T/q71.out" 2>/dev/null &
    sup=$!; sleep 1.2
    pay=$(payload_pid q71 testcases 5)
    got=$(sed -n 's/^comm=//p' "$T/q71.out" | head -n 1)
    wr=$(sed -n 's/^commwrite-write=\([0-9-]*\).*/\1/p' "$T/q71.out" | head -n 1)
    op=$(sed -n 's/^commwrite-open-errno=//p' "$T/q71.out" | head -n 1)
    if [ "$ctl" = blocked ]; then
        echo "SKIP $ck_tag ($(tr -d '\n' <"$T/q71.ctl"))"
    elif [ -z "$got" ]; then
        fail "$ck_tag (the writer printed no comm: $(tr '\n' ' ' <"$T/q71.out"))"
    elif [ "$got" = q71 ] && [ -n "$pay" ]; then
        pass "$ck_tag (comm=$got, payload=$pay; open_errno=${op:-none} wrote=${wr:-none})"
    elif [ "$got" = q71 ]; then
        fail "$ck_tag (comm=$got but no live payload presents it)"
    else
        fail "$ck_tag (comm=$got: the rename went through)"
    fi
    kill -9 "$sup" $pay 2>/dev/null; wait "$sup" 2>/dev/null
    rm -f "$T/q71.out"
}
# Control: without pmask the writer renames itself.  On a host that
# denies the write to every process the case decides nothing, so it is
# reported as a skip rather than a refusal pmask did not make.
ctl=writes
"$CASES" commwrite 1 "" >"$T/q71.ctl" 2>/dev/null
grep -q '^comm=evil-write' "$T/q71.ctl" || ctl=blocked

check "" q71-direct-write-refused
# The same write through a descriptor: the path the filter reads is
# `comm`, with no `/proc/` prefix, so the shape test needs the dirfd.
check dirfd q71-dirfd-write-refused
echo "################ QA71: FAIL=$FAIL"
[ "$FAIL" = 0 ]
