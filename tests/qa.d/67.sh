#!/bin/sh
# Issue 67: the delivered secret and the image are readable by the same uid.
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
if [ "$(id -u)" = 0 ]; then
    echo "SKIP q67 (root is not a same-uid peer)"
else
    "$TOOL" -q --secret TOK=file:"$T/tok" -l q67 -- "$CASES" sleeper 4 >/dev/null 2>&1 &
    sup=$!; sleep 1
    pay=""; for d in /proc/[0-9]*; do [ "$(cat "$d/comm" 2>/dev/null)" = q67 ] && { pay=${d#/proc/}; break; }; done
    if [ -n "$pay" ]; then
        if cat "/proc/$pay/fd/3" >/dev/null 2>&1; then
            fail q67-secret-fd-is-refused
        else
            pass q67-secret-fd-is-refused
        fi
        [ -r "/proc/$pay/mem" ] && fail q67-memory-is-refused || pass q67-memory-is-refused
    else
        fail q67-payload-not-found
    fi
    kill -9 "$sup" 2>/dev/null; wait "$sup" 2>/dev/null
fi
echo "################ QA67: FAIL=$FAIL"
[ "$FAIL" = 0 ]
