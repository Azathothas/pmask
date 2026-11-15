#!/bin/sh
# Issue 67: the delivered secret and the image are readable by the same uid.
# The discriminating check is the payload's memory: with a secret the tree
# is non-dumpable, so /proc/<pid>/mem belongs to root and a same-uid peer
# cannot open it.  The same payload without a secret stays dumpable, which
# is the control that proves the instrument can see a readable process.
# The secret is not on a fixed descriptor of the payload (fd 3 is absent in
# both runs), so an assertion on that descriptor would pass for its absence.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
T=$(mktemp -d "${TMPDIR:-/tmp}/qa67.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
printf 'q67-secret' > "$T/tok"
# Prints "<memory readable> <exe basename>".  The exe is empty when the
# process is non-dumpable, which is the case the fragment is about.
run_case() {  # [pmask args...]
    "$TOOL" -q "$@" -l q67 -- "$CASES" sleeper 4 >/dev/null 2>&1 &
    rc_sup=$!; sleep 1
    # With --secret the payload is non-dumpable, so its exe is unreadable
    # and payload_pid cannot match it; the parent relation still names it.
    rc_pay=$(child_pid "$rc_sup" 5)
    if [ -n "$rc_pay" ]; then
        [ -r "/proc/$rc_pay/mem" ] && rc_mem=yes || rc_mem=no
        rc_exe=$(readlink "/proc/$rc_pay/exe" 2>/dev/null)
        rc_exe=${rc_exe##*/}
    else
        rc_mem=none; rc_exe=none
    fi
    kill -9 "$rc_sup" $rc_pay 2>/dev/null; wait "$rc_sup" 2>/dev/null
    echo "$rc_mem $rc_exe"
}
if [ "$(id -u)" = 0 ]; then
    echo "SKIP q67 (root is not a same-uid peer)"
else
    set -- $(run_case)
    ctl_mem=$1; ctl_exe=$2
    if [ "$ctl_mem" != yes ]; then
        echo "SKIP q67 (control is blind: mem=$ctl_mem without a secret)"
    elif [ "$ctl_exe" != testcases ]; then
        echo "SKIP q67 (control did not find the payload: exe=$ctl_exe)"
    else
        set -- $(run_case --secret TOK=file:"$T/tok")
        got=$1
        case "$got" in
            no) pass "q67-memory-is-refused (control=readable, secret=refused)" ;;
            none) fail "q67-payload-not-found (with --secret)" ;;
            *) fail "q67-memory-is-refused (control=readable, secret=$got)" ;;
        esac
    fi
fi
echo "################ QA67: FAIL=$FAIL"
[ "$FAIL" = 0 ]
