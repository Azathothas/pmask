#!/bin/sh
# QA fragment for issue 17: `--audit` aborts the supervisor on a closed
# stdout and kills the payload.
#
# The defect: the audit rows used `println!`.  A reader that went away
# (`| head -1`) made the write fail, `println!` panicked, `panic = "abort"`
# turned that into SIGABRT (exit 134), and `PTRACE_O_EXITKILL` killed the
# payload with it, so the payload's own work never happened.
#
# The fix writes the rows through a helper that locks stdout and ignores a
# failed write.  A report that cannot be delivered must cost the report and
# nothing else.
#
# Cases:
#   qa17-head-payload-survives  --audit | head -1: the payload writes its
#                               file after the reader went away
#   qa17-head-not-sigabrt       the supervisor's own exit status, captured
#                               around the pipeline, is not 134
#   qa17-first-row              head -1 still gets the header row
#   qa17-full-audit-works       without the pipe the report prints and the
#                               run exits 0
#   qa17-payload-exit-status    the payload's own status passes through
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa17.XXXXXX") || {
    echo "FAIL qa17-cannot-create-tmp"; exit 2
}
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

cleanup() {
    kill_label qa17 KILL 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT

# ------------------------------------------------------- the closed pipe
# The supervisor's status is written to a file inside the same brace group
# that runs it, so it is the supervisor's own `$?`, not `head`'s.
MARKER="$D/alive"
rm -f "$MARKER" "$D/rc"
{ "$TOOL" --audit -l qa17 -- /bin/sh -c "sleep 1; echo alive > $MARKER" 2>"$D/e.err"
  echo $? > "$D/rc"; } | head -1 > "$D/first.out"
sleep 2

sup_rc=$(cat "$D/rc" 2>/dev/null)
if [ -f "$MARKER" ] && [ "$(cat "$MARKER" 2>/dev/null)" = "alive" ]; then
    pass qa17-head-payload-survives
else
    fail "qa17-head-payload-survives (no $MARKER; supervisor rc=$sup_rc stderr=$(head -c 120 "$D/e.err" | tr '\n' ' '))"
fi

if [ "$sup_rc" = "134" ]; then
    fail "qa17-head-not-sigabrt (supervisor exited 134: SIGABRT)"
elif [ -n "$sup_rc" ] && [ "$sup_rc" != "0" ]; then
    fail "qa17-head-not-sigabrt (supervisor exited $sup_rc)"
else
    pass qa17-head-not-sigabrt
fi

case "$(head -1 "$D/first.out")" in
    "pmask audit: header"*) pass qa17-first-row ;;
    *) fail "qa17-first-row (first line: $(head -1 "$D/first.out"))" ;;
esac

# ------------------------------------------------------ the report intact
rm -f "$MARKER"
"$TOOL" --audit -l qa17s -- /bin/sh -c "sleep 0.3; echo alive > $MARKER" \
    >"$D/full.out" 2>"$D/full.err"
rc=$?
if [ "$rc" = "0" ] && [ "$(cat "$MARKER" 2>/dev/null)" = "alive" ]; then
    pass qa17-full-audit-works
else
    fail "qa17-full-audit-works (rc=$rc marker=$(cat "$MARKER" 2>/dev/null))"
fi

# --------------------------------------------- payload status passthrough
"$TOOL" --audit -l qa17e -- /bin/sh -c 'exit 7' >/dev/null 2>&1
rc=$?
if [ "$rc" = "7" ]; then
    pass qa17-payload-exit-status
else
    fail "qa17-payload-exit-status (rc=$rc, want 7)"
fi

exit "$FAIL"
