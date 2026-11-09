#!/bin/sh
# QA fragment for issue 24: the documented `pmaskd` ExecStart used
# `--store`, which `pmaskd` does not accept, so copy-pasting the line from
# `contrib/systemd/pmaskd@.service` made the unit unstartable.
#
# Cases:
#   qa24-control-detects-the-old-line  the extractor below flags the old
#                                  commented --store line, so a pass means
#                                  something (SKIP without the git object)
#   qa24-unit-has-no-store-option   no active (non-comment) directive in
#                                  the unit names --store or
#                                  --passphrase-file
#   qa24-unit-execstart-binds       the unit's ExecStart names --socket
#   qa24-execstart-still-valid      the unit still has an uncommented
#                                  ExecStart (a deleted one is not a fix)
#   qa24-help-claims-no-store       `pmaskd --help` does not list --store
#   qa24-store-option-refused       `pmaskd --store PATH` exits 255 with
#                                  "unknown option --store" (the defect,
#                                  reproduced)
#   qa24-agent-owns-the-store       `pmask agent --help` does name --store,
#                                  so the note's claim has a witness
#   qa24-daemon-starts-with-the-documented-options  a real start binds
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
DAEMON="$BIN_DIR/pmaskd"
TOOL="$BIN_DIR/pmask"
UNIT="$BIN_DIR/../contrib/systemd/pmaskd@.service"
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

if [ ! -f "$UNIT" ]; then
    skip "qa24-unit-file (no $UNIT in this staging; contrib/ is outside the crate)"
    echo "== VERDICT: $FAIL failure(s) =="
    exit "$FAIL"
fi

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa24.XXXXXX") || {
    fail "qa24-cannot-create-tmp"; echo "== VERDICT: $FAIL failure(s) =="; exit "$FAIL"; }
chmod 700 "$D"
trap 'rm -rf "$D"' EXIT INT TERM

# Active directives only: a comment may describe the old line, and the
# point of the case is what systemd would actually parse.
unit_active() {
    sed -n 's/^[[:space:]]*//; /^#/d; /^$/d; p' "$1"
}
active() { unit_active "$UNIT"; }

# ------------------------------------------------- negative control
# The check below is only worth something if it can fail.  Rebuild the
# pre-fix text (the commented line that documented --store) and require
# the same extractor to flag it.  Without git the control is undecidable
# and says so rather than passing.
old=$(git -C "$BIN_DIR/.." show qa-base:contrib/systemd/pmaskd@.service 2>/dev/null)
if [ -z "$old" ]; then
    skip "qa24-control-detects-the-old-line (no git object qa-base here)"
else
    CTL="$D/unit.old"
    printf '%s\n' "$old" \
        | sed 's|^#ExecStart=\(.*\)|ExecStart=\1|' > "$CTL"
    if unit_active "$CTL" | grep -q -- '--store'; then
        pass "qa24-control-detects-the-old-line"
    else
        fail "qa24-control-detects-the-old-line (the checker cannot see the defect it exists for)"
    fi
fi

# ------------------------------------------------ no --store in the unit
if active | grep -q -e '--store' -e '--passphrase-file'; then
    fail "qa24-unit-has-no-store-option ($(active | grep -e '--store' -e '--passphrase-file' | head -1))"
else
    pass "qa24-unit-has-no-store-option"
fi

# --------------------------------------------- ExecStart names a real option
es=$(active | sed -n 's/^ExecStart=//p' | head -1)
case "$es" in
    */pmaskd*socket*)
        pass "qa24-unit-execstart-binds ($es)"
        ;;
    *)
        fail "qa24-unit-execstart-binds (ExecStart=[$es])"
        ;;
esac

# The unit must keep its uncommented ExecStart: a unit with no ExecStart is
# not a fix.
if printf '%s' "$es" | grep -q -- '--socket'; then
    pass "qa24-execstart-still-valid"
else
    fail "qa24-execstart-still-valid (ExecStart=[$es])"
fi

# ------------------------------------------------ the option is really gone
if "$DAEMON" --help 2>&1 | grep -q -- '--store'; then
    fail "qa24-help-claims-no-store (pmaskd --help names --store)"
else
    pass "qa24-help-claims-no-store"
fi

# The defect itself: the documented line is refused, and the message names
# the option.  This is the reproduction, so it must hold on every build.
out=$("$DAEMON" --store /tmp/qa24-nope.enc 2>&1)
rc=$?
case "$out" in
    *"unknown option --store"*)
        [ "$rc" = 255 ] \
            && pass "qa24-store-option-refused (rc=$rc, $out)" \
            || fail "qa24-store-option-refused (rc=$rc, want 255)"
        ;;
    *)
        fail "qa24-store-option-refused (rc=$rc, out=[$out])"
        ;;
esac

# Control: the store option lives on `pmask agent`, which is what the
# unit's comment now tells the operator to run.
if "$TOOL" agent --help 2>&1 | grep -q -- '--store'; then
    pass "qa24-agent-owns-the-store"
else
    fail "qa24-agent-owns-the-store (pmask agent --help does not name --store)"
fi

# Control: a real pmaskd start with the documented options works, so the
# unit is not merely unstartable in a different way.
SOCK="$D/pmask.sock"
"$DAEMON" -q -S "$SOCK" &
dpid=$!
i=0
while [ ! -S "$SOCK" ] && [ "$i" -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done
if [ -S "$SOCK" ]; then
    pass "qa24-daemon-starts-with-the-documented-options"
else
    fail "qa24-daemon-starts-with-the-documented-options (no socket at $SOCK)"
fi
kill -TERM "$dpid" 2>/dev/null
wait "$dpid" 2>/dev/null
rm -rf "$D"

echo "== VERDICT: $FAIL failure(s) =="
exit "$FAIL"
