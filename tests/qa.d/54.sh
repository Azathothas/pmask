#!/bin/sh
# Issue 54: the on-disk footprint, and the release binary fingerprint.
#
# `scripts/check-artifacts.sh` is the instrument: it reports the store and
# its lock, the sockets, the live memfd names, the exec-once carrier, the
# packaging entries and the ELF metadata of the built binaries, and exits 0
# whenever the report could be produced.  A report that silently stopped
# covering one of those sections would be worse than no report, because a
# reader would take the absence for "nothing there".  So this fragment
# asserts each section is present and that the measured values match what
# the issue recorded.
set -u
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
tests=$(CDPATH= cd -- "$here/.." && pwd) || exit 1
root=$(CDPATH= cd -- "$tests/.." && pwd) || exit 1
. "$tests/lib.sh"
TOOL="$tests/pmask"
CASES="$tests/testcases"
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

SCRIPT="$root/scripts/check-artifacts.sh"
if [ ! -f "$SCRIPT" ]; then
    echo "FAIL qa54-script-present (scripts/check-artifacts.sh is absent)"
    echo "QA54: FAIL (1)"
    exit 1
fi

T="${TMPDIR:-/tmp}/pmask-qa54.$$"
rm -rf "$T"
mkdir -p "$T"
chmod 700 "$T"
trap 'rm -rf "$T"' EXIT

# ------------------------------------- the report is produced and complete
out=$(sh "$SCRIPT" 2>&1)
rc=$?
if [ "$rc" = 0 ]; then
    pass "qa54-report-exits-0 (rc=$rc)"
else
    fail "qa54-report-exits-0 (rc=$rc)"
fi
for section in "store" "sockets" "live memfd names" "exec-once carrier" \
    "packaging" "release binary fingerprint" "ARTIFACTS: report complete"; do
    case "$out" in
        *"$section"*) pass "qa54-section-present: $section" ;;
        *) fail "qa54-section-present: $section (the report omits it)" ;;
    esac
done

# ------------------------------- the store, measured on a real store file
if [ ! -x "$TOOL" ]; then
    skip "qa54-store-magic (no pmask binary)"
else
    printf 'qa54-pass\n' > "$T/pass"
    chmod 600 "$T/pass"
    if "$TOOL" store init --store "$T/store.enc" --passphrase-file "$T/pass" \
        >/dev/null 2>"$T/init.err"; then
        pass "qa54-store-init-succeeds"
        # The issue records 98 bytes for an empty store and the magic
        # PMASKSTORE1 followed by five NULs.  Both are asserted from the
        # file, not from the script's own rendering of it.
        n=$(wc -c < "$T/store.enc" | tr -d ' ')
        if [ "$n" = 98 ]; then
            pass "qa54-empty-store-is-98-bytes"
        else
            fail "qa54-empty-store-is-98-bytes (got $n)"
        fi
        if head -c 12 "$T/store.enc" | grep -q 'PMASKSTORE1'; then
            pass "qa54-store-magic-is-PMASKSTORE1"
        else
            fail "qa54-store-magic-is-PMASKSTORE1"
        fi
        m=$(ls -l "$T/store.enc" | cut -c1-10)
        case "$m" in
            -rw-------) pass "qa54-store-mode-is-0600" ;;
            *) fail "qa54-store-mode-is-0600 (mode=$m)" ;;
        esac
        lm=$(ls -l "$T/store.enc.lock" 2>/dev/null | cut -c1-10)
        case "$lm" in
            -rw-------) pass "qa54-lock-mode-is-0600" ;;
            *) fail "qa54-lock-mode-is-0600 (mode=[$lm])" ;;
        esac
        # And the report must show that same store when pointed at it.
        rep=$(PMASK_STORE="$T/store.enc" sh "$SCRIPT" 2>&1)
        case "$rep" in
            *"PMASKSTORE1"*) pass "qa54-report-reads-the-store-magic" ;;
            *) fail "qa54-report-reads-the-store-magic" ;;
        esac
        case "$rep" in
            *"600 98"*) pass "qa54-report-shows-mode-and-size" ;;
            *) fail "qa54-report-shows-mode-and-size" ;;
        esac
    else
        fail "qa54-store-init-succeeds ($(tr '\n' '|' < "$T/init.err"))"
    fi
fi

# -------------------------------- the packaging entry, from the same report
case "$out" in
    *"no f line; store init creates the file itself"*)
        pass "qa54-report-flags-no-tmpfiles-store-line" ;;
    *) fail "qa54-report-flags-no-tmpfiles-store-line" ;;
esac

# ------------------------------- the binary fingerprint, when one is built
bin=""
for b in "$root/target/x86_64-unknown-linux-musl/release/pmask" \
    "$root/target/release/pmask"; do
    [ -f "$b" ] && bin=$b && break
done
if [ -z "$bin" ]; then
    skip "qa54-binary-fingerprint (no pmask binary built)"
elif ! command -v readelf >/dev/null 2>&1; then
    skip "qa54-binary-fingerprint (no readelf)"
else
    rep=$(sh "$SCRIPT" "$bin" 2>&1)
    case "$rep" in
        *".comment"*) pass "qa54-report-shows-the-comment-section" ;;
        *) fail "qa54-report-shows-the-comment-section" ;;
    esac
    case "$rep" in
        *"build id"*) pass "qa54-report-shows-the-build-id" ;;
        *) fail "qa54-report-shows-the-build-id" ;;
    esac
    case "$rep" in
        *"pmask strings"*) pass "qa54-report-counts-the-pmask-strings" ;;
        *) fail "qa54-report-counts-the-pmask-strings" ;;
    esac
    # The fact the issue rests on: the shipped build names the toolchain in
    # .comment.  If a later change removes it, this case fails and the
    # packaging note in evidence/fix5/54/ is stale, which is the point.
    # Only a missing readelf is a skip (handled above); a built binary
    # without the fact is a failure, not an undecided case.
    if readelf -p .comment "$bin" 2>/dev/null | grep -q 'rustc version'; then
        pass "qa54-shipped-build-names-the-toolchain-in-.comment"
    else
        fail "qa54-shipped-build-names-the-toolchain-in-.comment (.comment does not name the toolchain; the packaging note in evidence/fix5/54/ is stale)"
    fi
fi

[ "$FAIL" = 0 ] && echo "QA54: PASS" || echo "QA54: FAIL ($FAIL)"
[ "$FAIL" = 0 ]
