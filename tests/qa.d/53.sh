#!/bin/sh
# Issue 53: refusals, exit codes and error strings are a contract.
#
# A log or telemetry consumer identifies the tool by the stable prefix and
# the status.  This fragment pins the paths that are reachable without
# root or a second uid; the root-only rows are in evidence/bteam4/53/.
set -u
cd "$(dirname "$0")" || exit 2
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
DAEMON="$BIN_DIR/pmaskd"
[ -x "$TOOL" ] || { echo "FATAL: $TOOL is missing"; exit 2; }

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa53.XXXXXX") || exit 2
chmod 700 "$D"
cleanup() { rm -rf "$D"; }
trap cleanup EXIT INT TERM

check() { # check NAME EXPECTED_STATUS PATTERN -- COMMAND...
    ck_name=$1; ck_status=$2; ck_pat=$3; shift 3
    [ "${1:-}" = "--" ] && shift
    ck_out=$("$@" 2>&1 >/dev/null)
    ck_rc=$?
    if [ "$ck_rc" = "$ck_status" ] && printf '%s' "$ck_out" | grep -qF -- "$ck_pat"; then
        pass "$ck_name"
    else
        fail "$ck_name (rc=$ck_rc out=[$ck_out])"
    fi
}

check "53-unknown-option" 255 "pmask: unknown option --badopt" -- \
    "$TOOL" --badopt
check "53-label-lf" 255 "label must not contain NUL, LF or CR bytes" -- \
    "$TOOL" -l "$(printf 'a\nb')" -- /bin/true
check "53-comm-too-long" 255 "comm must be at most 15 bytes" -- \
    "$TOOL" --comm 1234567890123456 -- /bin/true
check "53-jobs-zero" 255 "--jobs needs a number of at least 1" -- \
    "$DAEMON" --jobs 0 -S "$D/x.sock"
check "53-missing-command" 127 "cannot exec" -- \
    "$TOOL" -- /nonexistent-cmd-qa53

# The daemon's socket-directory refusal names the misconfiguration.
mkdir -p "$D/open" && chmod 777 "$D/open"
check "53-socket-dir-world-writable" 255 "refusing to start" -- \
    "$DAEMON" -S "$D/open/x.sock"
chmod 700 "$D/open"

echo "== QA53: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL) =="
[ "$FAIL" = 0 ] || exit 1
exit 0
