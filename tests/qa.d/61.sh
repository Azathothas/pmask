#!/bin/sh
# QA fragment for the `--exec-once` degradation under a namespace set.
#
# The defect: `Mask::to_config` cleared `rexec_per_exec` whenever
# `namespaces` was set, but the warning block only named `--unshare` and
# `--run-as`.  `--redact --isolate` therefore dropped the cache silently,
# which is the invariant-13 failure: a degradation the operator cannot see.
#
# Cases:
#   qa61-exec-once-namespace-warns   `--redact --isolate --exec-once`
#                                    prints the reason
#   qa61-exec-once-unshare-warns     the `--unshare` reason still prints
#   qa61-control-plain-is-silent     a run that keeps the cache prints
#                                    neither line, so the rows above can
#                                    fail
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa61.$$"
mkdir -p "$D" || { echo "FAIL qa61-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() { rm -rf "$D"; }
trap cleanup EXIT

if ! unshare -Ur true 2>/dev/null; then
    skip "qa61-exec-once-namespace-warns (unshare -Ur true refused here)"
    skip "qa61-exec-once-unshare-warns (unshare -Ur true refused here)"
    skip "qa61-control-plain-is-silent (unshare -Ur true refused here)"
    echo "== VERDICT: FAIL=$FAIL =="
    exit 0
fi

# `--redact --isolate` composes the two, and the cache cannot be reached
# from the tracee's mount namespace.
"$TOOL" -l qa61 --redact --isolate --exec-once -- /bin/true \
    >"$D/iso.out" 2>"$D/iso.err"
if grep -q 'exec-once unavailable' "$D/iso.err"; then
    pass "qa61-exec-once-namespace-warns ($(head -1 "$D/iso.err" | cut -c1-90))"
else
    fail "qa61-exec-once-namespace-warns (stderr=$(tr '\n' '|' <"$D/iso.err" | cut -c1-200))"
fi

"$TOOL" -l qa61 --unshare --exec-once -- /bin/true \
    >"$D/uns.out" 2>"$D/uns.err"
if grep -q 'exec-once unavailable' "$D/uns.err"; then
    pass "qa61-exec-once-unshare-warns ($(head -1 "$D/uns.err" | cut -c1-90))"
else
    fail "qa61-exec-once-unshare-warns (stderr=$(tr '\n' '|' <"$D/uns.err" | cut -c1-200))"
fi

# Control: no namespace set, so the cache is kept and nothing is said.
"$TOOL" -l qa61 --exec-once -- /bin/true >"$D/plain.out" 2>"$D/plain.err"
if grep -q 'exec-once unavailable' "$D/plain.err"; then
    fail "qa61-control-plain-is-silent (stderr=$(tr '\n' '|' <"$D/plain.err" | cut -c1-200))"
else
    pass "qa61-control-plain-is-silent"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
