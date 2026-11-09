#!/bin/sh
# QA fragment for issue 33: `--comm` accepts LF and CR.
#
# The defect: `validate` rejected only NUL in `comm`.  A newline in the name
# breaks the parenthesised part of `/proc/<pid>/stat`, which readers split
# on newlines; before the fix `pmask --comm "$(printf 'ab\ncd')"` exited 0
# and the payload ran with a corrupted `comm`.
#
# The fix rejects NUL, LF and CR for `--comm`, matching `--label`, at parse
# time in every mode.  "Every mode" is the second half of the defect: the
# check first only lived in `Mask::validate`, which `--isolate` and
# `--no-redact` never reach, so those two modes still accepted the LF.
#
# Cases:
#   qa33-lf-refused        --comm with LF on the mask path
#   qa33-cr-refused        --comm with CR on the mask path
#   qa33-lf-isolate        the same refusal with --isolate=all
#   qa33-lf-no-redact      the same refusal with --no-redact
#   qa33-nul-through-tool  a NUL cannot reach a process through argv, so the
#                          library surface is checked through the testcase
#                          binary's debug hook
#   qa33-tab-accepted      control: TAB is legal and still reaches /proc
#   qa33-label-lf-control  control: --label already refused LF, so this is
#                          the existing rule and not a new one
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa33.XXXXXX") || {
    echo "FAIL qa33-cannot-create-tmp"; exit 2
}
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

cleanup() {
    kill_label qa33 KILL 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT

LF=$(printf 'ab\ncd')
CR=$(printf 'ab\rcd')

# refused NAME VALUE [OPTIONS...]
refused() {
    rf_name="$1"
    rf_val="$2"
    shift 2
    err=$("$TOOL" --comm "$rf_val" "$@" -- /bin/true 2>&1 >/dev/null)
    rf_rc=$?
    if [ "$rf_rc" != 0 ] && printf '%s' "$err" | grep -q 'comm must not contain NUL, LF or CR'; then
        pass "$rf_name"
    else
        fail "$rf_name (rc=$rf_rc stderr=[$(printf '%s' "$err" | head -1)])"
    fi
}

refused qa33-lf-refused "$LF"
refused qa33-cr-refused "$CR"
refused qa33-lf-isolate "$LF" --isolate=all
refused qa33-lf-no-redact "$LF" --no-redact

# A NUL cannot be passed through argv at all (the kernel's execve takes
# NUL-terminated strings), so the library-level rule is exercised by the
# unit test `comm_rejects_nul_lf_and_cr` in src/mask.rs.  This case asserts
# that test exists and covers all three bytes, so a later edit cannot drop
# the NUL half and leave the fragment green.
if grep -q 'a\\0b", "a\\nb", "a\\rb' "$BIN_DIR/../src/mask.rs" 2>/dev/null; then
    pass qa33-nul-covered-by-the-unit-test
else
    fail "qa33-nul-covered-by-the-unit-test (the unit test does not cover all three bytes)" 
fi

# ------------------------------------------------------- control: TAB is legal
"$TOOL" -q --comm "$(printf 'ab\tcd')" -l qa33tab -- /bin/sh -c 'cat /proc/self/comm' \
    >"$D/tab.out" 2>/dev/null
rc=$?
got=$(cat "$D/tab.out" 2>/dev/null)
if [ "$rc" = "0" ] && [ "$got" = "$(printf 'ab\tcd')" ]; then
    pass qa33-tab-accepted
else
    fail "qa33-tab-accepted (rc=$rc comm=[$got])"
fi

# ---------------------------------------- control: --label already refused LF
err=$("$TOOL" -l "$LF" -- /bin/true 2>&1 >/dev/null)
rc=$?
if [ "$rc" != 0 ] && printf '%s' "$err" | grep -qi 'label must not contain NUL, LF or CR'; then
    pass qa33-label-lf-refused-control
else
    fail "qa33-label-lf-refused-control (rc=$rc stderr=[$(printf '%s' "$err" | head -1)])"
fi

exit "$FAIL"
