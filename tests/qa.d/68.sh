#!/bin/sh
# Issue 68: the holder is dumpable while it loads a secret.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
T=$(mktemp -d "${TMPDIR:-/tmp}/qa68.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
mkfifo "$T/fifo"
"$TOOL" -q --secret TOK=file:"$T/fifo" -l q68 -- "$CASES" sleeper 2 >/dev/null 2>&1 &
sup=$!; sleep 0.7
if [ "$(id -u)" = 0 ]; then
    echo "SKIP q68 (root reads a non-dumpable process)"
else
    if [ -r "/proc/$sup/mem" ]; then
        fail q68-holder-is-non-dumpable-before-load
    else
        pass q68-holder-is-non-dumpable-before-load
    fi
fi
printf 'q68-secret' > "$T/fifo" 2>/dev/null || true
kill -9 "$sup" 2>/dev/null; wait "$sup" 2>/dev/null
echo "################ QA68: FAIL=$FAIL"
[ "$FAIL" = 0 ]
