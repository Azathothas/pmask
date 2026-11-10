#!/bin/sh
# QA fragment for issue 20: `--no-redact --isolate` ran plain and silently
# dropped the isolation.
#
# The defect: `--no-redact` set `force_mode = Plain`, and
# `Runner::select_with` returned that before it looked at the isolate
# request, so no namespace was created and the only note was the generic
# "metadata was not redacted" line.
#
# The fix runs the isolate path on plain mode, because isolation does not
# need ptrace.
#
# Cases:
#   qa20-mode-is-isolate       the run report says mode=isolate
#   qa20-user-namespace-private the payload is in a new user namespace
#   qa20-note-names-the-pair   the report explains that --no-redact was
#                              honoured and --isolate still applied
#   qa20-control-plain-namespace  the plain path without --isolate keeps
#                              the host's user namespace, so the row above
#                              can fail
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa20.$$"
mkdir -p "$D" || { echo "FAIL qa20-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() { rm -rf "$D"; }
trap cleanup EXIT

if ! unshare -Ur true 2>/dev/null; then
    skip "qa20-user-namespaces (unshare -Ur true refused here)"
    echo "== VERDICT: SKIP =="
    exit 0
fi

HOST_USER=$(readlink /proc/self/ns/user 2>/dev/null)
[ -n "$HOST_USER" ] || { skip "qa20-host-user-ns (readlink failed)"; exit 0; }

"$TOOL" --no-redact --isolate --report=json -- /bin/sh -c 'readlink /proc/self/ns/user' \
    >"$D/rep.json" 2>"$D/err"
rc=$?
if [ "$rc" = 0 ]; then
    pass "qa20-run-exits-zero"
else
    fail "qa20-run-exits-zero (rc=$rc err=$(tr '\n' '|' <"$D/err"))"
fi

mode=$(sed -n 's/^[[:space:]]*"mode": "\([^"]*\)".*/\1/p' "$D/rep.json" | head -1)
if [ "$mode" = "isolate" ]; then
    pass "qa20-mode-is-isolate"
else
    fail "qa20-mode-is-isolate (mode=[$mode])"
fi

# The report's mode is a claim; the payload's own namespace is the fact.
INSIDE=$("$TOOL" -q --no-redact --isolate -- /bin/sh -c 'readlink /proc/self/ns/user' 2>/dev/null)
if [ -n "$INSIDE" ] && [ "$INSIDE" != "$HOST_USER" ]; then
    pass "qa20-user-namespace-private (inside=$INSIDE host=$HOST_USER)"
else
    fail "qa20-user-namespace-private (inside=[$INSIDE] host=[$HOST_USER]: the isolation was dropped)"
fi

if grep -q -- "--no-redact was honoured and --isolate still applies" "$D/rep.json"; then
    pass "qa20-note-names-the-pair"
else
    fail "qa20-note-names-the-pair (notes: $(tr '\n' '|' <"$D/rep.json" | cut -c1-300))"
fi

# Control: plain mode without --isolate keeps the host's user namespace.
CTL=$("$TOOL" -q --no-redact -- /bin/sh -c 'readlink /proc/self/ns/user' 2>/dev/null)
if [ "$CTL" = "$HOST_USER" ]; then
    pass "qa20-control-plain-keeps-the-host-user-ns ($CTL)"
else
    fail "qa20-control-plain-keeps-the-host-user-ns (plain=[$CTL] host=[$HOST_USER])"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
