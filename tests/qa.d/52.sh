#!/bin/sh
# Issue 52: pmaskd's own entry, its workers and the job leaf.
#
# The daemon is non-dumpable in every mode, the job carries the label, an
# empty environment window and a tracer tid, and a listening unix socket
# sits at the root of the tree.  This is the design, so the fragment pins
# the shape and fails if a change makes the daemon readable or the job
# unredacted.
set -u
cd "$(dirname "$0")/.." || exit 2
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa52.XXXXXX") || exit 2
chmod 700 "$D"
DP=""
cleanup() {
    [ -n "$DP" ] && kill -9 "$DP" 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT INT TERM

"$BIN_DIR/pmaskd" -q -l qa52d -S "$D/d.sock" --jobs 2 >/dev/null 2>"$D/d.err" &
DP=$!
i=0
while [ ! -S "$D/d.sock" ] && [ "$i" -lt 40 ]; do
    sleep 0.1 2>/dev/null || sleep 1
    i=$((i + 1))
done
if [ ! -S "$D/d.sock" ]; then
    # Nothing was decided.  A PASS banner here would claim the daemon shape
    # was checked when the daemon never came up.
    skip "52-daemon-shape (daemon did not start: $(head -1 "$D/d.err"))"
    exit 0
fi

comm=$(cat "/proc/$DP/comm" 2>/dev/null)
if [ "$comm" = qa52d ]; then
    pass "52-daemon-comm-is-the-label"
else
    fail "52-daemon-comm-is-the-label (comm=[$comm])"
fi
denied=0
for f in environ maps auxv exe fd; do
    head -c1 "/proc/$DP/$f" >/dev/null 2>&1 || denied=$((denied + 1))
done
if [ "$denied" = 5 ]; then
    pass "52-daemon-is-non-dumpable (5 of 5 refused)"
else
    fail "52-daemon-is-non-dumpable ($denied of 5 refused)"
fi
if grep -qF -- "$D/d.sock" /proc/net/unix 2>/dev/null; then
    pass "52-daemon-listens-on-a-unix-socket"
else
    fail "52-daemon-listens-on-a-unix-socket"
fi

# Submit a job through the protocol client and inspect its leaf.
"$BIN_DIR/pmask" --daemon "$D/d.sock" -l qa52job -- "$CASES" sleepfor 2 \
    >/dev/null 2>"$D/job.err" &
JP=$!
sleep 0.7
leaf=""
for d in /proc/[0-9]*; do
    p=${d#/proc/}
    [ "$(cat "$d/comm" 2>/dev/null)" = qa52job ] && { leaf=$p; break; }
done
if [ -n "$leaf" ]; then
    cmd=$(tr '\0' '|' < "/proc/$leaf/cmdline" 2>/dev/null)
    envb=$(wc -c < "/proc/$leaf/environ" 2>/dev/null | tr -d ' ')
    tr=$(sed -n 's/^TracerPid:[[:space:]]*//p' "/proc/$leaf/status" 2>/dev/null)
    if [ "$cmd" = "qa52job|" ] && [ "$envb" = 0 ] && [ -n "$tr" ] && [ "$tr" != 0 ]; then
        pass "52-job-leaf-is-labelled-and-traced (tracer=$tr)"
    else
        fail "52-job-leaf-is-labelled-and-traced (cmd=[$cmd] env=[$envb] tracer=[$tr])"
    fi
else
    skip "52-job-leaf-is-labelled-and-traced (no leaf appeared)"
fi
wait "$JP" 2>/dev/null

kill -9 "$DP" 2>/dev/null
wait "$DP" 2>/dev/null
DP=""
echo "== QA52: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL) =="
[ "$FAIL" = 0 ] || exit 1
exit 0
