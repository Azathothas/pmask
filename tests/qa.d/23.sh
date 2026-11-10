#!/bin/sh
# Issue 23: the tmpfiles entry must not pre-create an empty store file.
#
# `contrib/tmpfiles.d/pmask.conf` used to carry both:
#     d /var/lib/pmask 0700 pmask pmask -
#     f /var/lib/pmask/store.enc 0600 pmask pmask -
# The `f` line creates a zero-byte `store.enc` at boot.  `pmask store init`
# refuses an existing path with "already exists" (255) and `store set`
# refuses the truncated header, so the packaged deployment could never
# create a store.
#
# The guard here is static (the `f` line must be absent, the `d` line must
# be present) plus behavioural: a directory shaped exactly the way the
# remaining tmpfiles entry shapes it must let `store init` succeed and
# produce a file with the store magic.
set -u
# qa.sh runs a fragment from tests/ while the fragment's own directory is
# tests/qa.d, so resolve both from $0 instead of the caller's cwd.
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
tests=$(CDPATH= cd -- "$here/.." && pwd) || exit 1
. "$tests/lib.sh"
TOOL="$tests/pmask"
CASES="$tests/testcases"
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

CONF="$tests/../contrib/tmpfiles.d/pmask.conf"
T="${TMPDIR:-/tmp}/pmask-qa23.$$"
rm -rf "$T"
mkdir -p "$T" || { echo "FAIL qa23-no-tmpdir"; exit 1; }
trap 'rm -rf "$T"' EXIT

# ------------------------------------------------ static: the entry itself
if [ ! -f "$CONF" ]; then
    skip "qa23-tmpfiles-conf-present ($CONF is not staged)"
else
    if grep -Eq '^[[:space:]]*f[[:space:]]+/var/lib/pmask/store\.enc([[:space:]]|$)' "$CONF"; then
        fail "qa23-tmpfiles-has-no-store-file-line (the f line pre-creates store.enc)"
    else
        pass "qa23-tmpfiles-has-no-store-file-line"
    fi
    if grep -Eq '^[[:space:]]*d[[:space:]]+/var/lib/pmask([[:space:]]|$)' "$CONF"; then
        pass "qa23-tmpfiles-keeps-the-directory-line"
        if grep -Eq '^[[:space:]]*d[[:space:]]+/var/lib/pmask[[:space:]]+0700([[:space:]]|$)' "$CONF"; then
            pass "qa23-tmpfiles-directory-mode-is-0700"
        else
            fail "qa23-tmpfiles-directory-mode-is-0700 (the d line does not say 0700)"
        fi
    else
        fail "qa23-tmpfiles-keeps-the-directory-line (no d line for /var/lib/pmask)"
    fi
fi

# ------------------- negative control: the removed f line did break init
# Shape the directory the old `f` line shaped: the directory exists, and
# a zero-byte store.enc is already there.  `store init` must refuse, which
# proves the behavioural case below is not vacuous.
S="$T/ctl"
mkdir -p "$S"
: > "$S/store.enc"
printf 'pp\n' > "$T/pass"
chmod 600 "$T/pass"
"$TOOL" store init --store "$S/store.enc" --passphrase-file "$T/pass" \
    >"$T/ctl.out" 2>"$T/ctl.err"
ctl_rc=$?
if [ "$ctl_rc" = 255 ] && grep -q "already exists" "$T/ctl.err"; then
    pass "qa23-control-a-pre-created-store-file-breaks-init"
else
    fail "qa23-control-a-pre-created-store-file-breaks-init (rc=$ctl_rc err=[$(tr '\n' '|' < "$T/ctl.err")])"
fi

# ---------------------- the fix: a fresh tmpfiles-style directory works
# Only the `d` line remains, so the directory is what tmpfiles leaves.
# `store init` must create the file and write the magic.
G="$T/fresh"
mkdir -p "$G"
chmod 700 "$G"
if [ -e "$G/store.enc" ]; then
    fail "qa23-fresh-directory-starts-empty (store.enc already exists)"
else
    pass "qa23-fresh-directory-starts-empty"
fi
"$TOOL" store init --store "$G/store.enc" --passphrase-file "$T/pass" \
    >"$T/init.out" 2>"$T/init.err"
init_rc=$?
if [ "$init_rc" = 0 ] && [ -f "$G/store.enc" ]; then
    pass "qa23-store-init-succeeds-in-a-tmpfiles-style-directory (rc=$init_rc)"
else
    fail "qa23-store-init-succeeds-in-a-tmpfiles-style-directory (rc=$init_rc err=[$(tr '\n' '|' < "$T/init.err")])"
fi

# The file is a real store, not an empty file with the right name.
if [ -f "$G/store.enc" ]; then
    n=$(wc -c < "$G/store.enc" | tr -d ' ')
    if [ "$n" -gt 16 ] && head -c 12 "$G/store.enc" | grep -q "PMASKSTORE1"; then
        pass "qa23-store-init-writes-the-magic ($n bytes)"
    else
        fail "qa23-store-init-writes-the-magic (bytes=$n)"
    fi
    mode=$(ls -l "$G/store.enc" 2>/dev/null | cut -c1-10)
    case "$mode" in
        -rw-------) pass "qa23-store-file-mode-is-0600" ;;
        *) fail "qa23-store-file-mode-is-0600 (mode=$mode)" ;;
    esac
fi

# The packaged entry names no store file at all, in any spelling a
# tmpfiles `f` or `f+` line could take.
if [ -f "$CONF" ]; then
    if grep -Eq '^[[:space:]]*[fw][+!]*[[:space:]]+.*store\.enc' "$CONF"; then
        fail "qa23-tmpfiles-names-no-store-file-in-any-form"
    else
        pass "qa23-tmpfiles-names-no-store-file-in-any-form"
    fi
fi

[ "$FAIL" = 0 ] && echo "QA23: PASS" || echo "QA23: FAIL ($FAIL)"
[ "$FAIL" = 0 ]
