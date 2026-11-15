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
# comm_of_payload MODE: start the writer in MODE, then report the comm the
# process presents.  The writer renames itself `evil-write`, so a comm of
# q71 is the refusal and anything else is a bypass.
check() {
    ck_mode=$1; ck_tag=$2
    "$TOOL" -q --watch-rename -l q71 -- "$CASES" commwrite 3 "$ck_mode" \
        >"$T/q71.out" 2>/dev/null &
    sup=$!; sleep 1.2
    pay=""
    for d in /proc/[0-9]*; do
        [ "$(cat "$d/comm" 2>/dev/null)" = q71 ] && { pay=${d#/proc/}; break; }
    done
    if [ "$ctl" = blocked ]; then
        echo "SKIP $ck_tag ($(tr -d '\n' <"$T/q71.ctl"))"
    elif [ -n "$pay" ]; then
        pass "$ck_tag"
    else
        # The writer changed its comm, so no process presents the label.
        fail "$ck_tag (no payload presents q71: $(grep -o 'commwrite-[a-z]*=[-0-9]*' "$T/q71.out" | tr '\n' ' '))"
    fi
    kill -9 "$sup" "$pay" 2>/dev/null; wait "$sup" 2>/dev/null
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
