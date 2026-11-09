#!/bin/sh
# Issue 28: `--hugetlb --image -` must fall back to an ordinary memfd.
#
#   q28a  control: `--hugetlb --image PATH` falls back with the note, so
#         the host genuinely lacks usable huge pages (or has them, in
#         which case the check says so and the case is a SKIP)
#   q28b  `--hugetlb --image -` runs the piped bytes and exits 0
#   q28c  the degradation note names the ordinary memfd
#   q28d  `--hugetlb --image-from-fd N` takes the same path
#   q28e  the payload still works: it prints its own marker
#
# Catches: `prepare_fd` returning the hugetlb write error instead of
# retrying on an ordinary memfd, which makes `--hugetlb` fail a run its
# documentation says it never fails.
set -u
here=$(dirname "$0")
cd "$here/.." || { echo "FATAL: cannot enter tests/"; exit 2; }
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
T="/tmp/qa28.$$"
mkdir -p "$T" || { echo "FATAL: cannot create $T"; exit 2; }
cleanup() { rm -rf "$T"; }
trap cleanup EXIT INT TERM HUP QUIT

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

# q28a control: does this host have usable huge pages?  A note on the
# path carrier means the host lacks them, so the fallback is the only
# route — which is the case this issue is about.
"$TOOL" --hugetlb --image "$CASES" exe-id >"$T/a.out" 2>"$T/a.err"
rc=$?
if [ "$rc" != 0 ]; then
    fail "q28a-control (a plain --hugetlb run failed: rc=$rc err=[$(cat "$T/a.err")])"
    HAVE_HUGETLB=1
elif grep -q "hugetlb unavailable" "$T/a.err"; then
    HAVE_HUGETLB=0
    echo "INFO q28a-control the host lacks usable huge pages; the fallback is exercised"
else
    HAVE_HUGETLB=1
    echo "INFO q28a-control the host has usable huge pages; the fallback is unreachable here"
fi

# q28b/q28c/q28e the piped image.
cat "$CASES" | "$TOOL" --hugetlb --image - exe-id >"$T/b.out" 2>"$T/b.err"
rc=$?
if [ "$rc" = 0 ]; then
    pass "q28b-hugetlb-image-stdin-runs"
else
    fail "q28b-hugetlb-image-stdin-runs (rc=$rc err=[$(cat "$T/b.err")])"
fi
case "$(cat "$T/b.out")" in
    *"exe=/memfd:"*) pass "q28e-hugetlb-image-stdin-payload-works" ;;
    *) fail "q28e-hugetlb-image-stdin-payload-works (out=[$(cat "$T/b.out")])" ;;
esac
if [ "$HAVE_HUGETLB" = 0 ]; then
    if grep -q "hugetlb unavailable: .*using an ordinary memfd" "$T/b.err"; then
        pass "q28c-hugetlb-image-stdin-carries-the-degradation-note"
    else
        fail "q28c-hugetlb-image-stdin-carries-the-degradation-note (err=[$(cat "$T/b.err")])"
    fi
else
    skip "q28c-hugetlb-image-stdin-carries-the-degradation-note (this host has huge pages)"
fi

# q28d the same fallback on the descriptor carrier.
cat "$CASES" | "$TOOL" --hugetlb --image-from-fd 0 exe-id >"$T/d.out" 2>"$T/d.err"
rc=$?
if [ "$rc" = 0 ] && [ -s "$T/d.out" ]; then
    pass "q28d-hugetlb-image-from-fd-runs"
else
    fail "q28d-hugetlb-image-from-fd-runs (rc=$rc out=[$(cat "$T/d.out")] err=[$(cat "$T/d.err")])"
fi

echo "################ qa28: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
