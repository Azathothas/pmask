#!/bin/sh
# QA fragment for issue 29: `doctor --json` broke on a quoted store path,
# and `doctor --require ''` passed (exit 0) when it should have refused.
#
# The store path comes from $XDG_DATA_HOME and the agent socket from
# $PMASK_SOCKET, so a `"` in either used to close the JSON string early
# and the whole report stopped parsing.  The same applies to the names in
# `--require`, which come straight from argv.
#
# Cases:
#   qa29-control-json-parses       `doctor --json` with an ordinary
#                                  environment parses, so a pass below
#                                  means something
#   qa29-store-path-in-json        a `"` in XDG_DATA_HOME still parses,
#                                  and the path round-trips through jq
#   qa29-store-backslash-in-json   a `\` in XDG_DATA_HOME still parses
#   qa29-agent-socket-in-json      a `"` in PMASK_SOCKET still parses
#   qa29-require-quote-escaped     `--require '"x"'` puts the quotes in
#                                  the JSON as an escaped value
#   qa29-empty-require-refused     `--require ''` exits 255 and says why
#   qa29-eq-empty-require-refused  `--require=` does the same
#   qa29-comma-require-refused     `--require ','` names nothing and is
#                                  refused too
#   qa29-valid-require-still-works `--require redact` still exits 0
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
[ -x "$TOOL" ] || { echo "FATAL: $TOOL is missing"; exit 2; }
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa29.XXXXXX") || {
    echo "FATAL: mktemp -d failed"; exit 2; }
chmod 700 "$D"
cleanup() { rm -rf "$D"; }
trap cleanup EXIT INT TERM

if ! command -v jq >/dev/null 2>&1; then
    skip "qa29-json-cases (jq is not installed, so JSON well-formedness is undecidable here)"
    echo "== VERDICT: $FAIL failure(s) =="
    exit "$FAIL"
fi

# A private, empty data home, so the store line is the "not created yet"
# shape and nothing reads the caller's real store.  PMASK_SOCKET is set
# to the empty string so the report does not depend on the caller's
# runtime directory.
mkdir -p "$D/plain"
chmod 700 "$D/plain"
export PMASK_SOCKET=""

# ------------------------------------------- control: the report parses
XDG_DATA_HOME="$D/plain" "$TOOL" doctor --json > "$D/base.json" 2>"$D/base.err"
rc=$?
if [ "$rc" = 0 ] && jq -e . "$D/base.json" >/dev/null 2>&1; then
    pass "qa29-control-json-parses"
else
    fail "qa29-control-json-parses (rc=$rc, err=$(head -1 "$D/base.err"))"
fi

# ------------------------------------------------ a quote in the store path
QUOTED="$D/qa\"path"
mkdir -p "$QUOTED" || fail "qa29-cannot-create-quoted-dir"
chmod 700 "$QUOTED"
XDG_DATA_HOME="$QUOTED" "$TOOL" doctor --json > "$D/quote.json" 2>"$D/quote.err"
if jq -e . "$D/quote.json" >/dev/null 2>&1; then
    got=$(jq -r '.store.path' "$D/quote.json")
    if [ "$got" = "$QUOTED/pmask/store.enc" ]; then
        pass "qa29-store-path-in-json"
    else
        fail "qa29-store-path-in-json (path=$got, want $QUOTED/pmask/store.enc)"
    fi
else
    fail "qa29-store-path-in-json (jq: $(jq . "$D/quote.json" 2>&1 | head -1))"
fi

# --------------------------------------------- a backslash in the store path
BS="$D/qa\\path"
mkdir -p "$BS" || fail "qa29-cannot-create-backslash-dir"
chmod 700 "$BS"
XDG_DATA_HOME="$BS" "$TOOL" doctor --json > "$D/bs.json" 2>"$D/bs.err"
if jq -e . "$D/bs.json" >/dev/null 2>&1; then
    got=$(jq -r '.store.path' "$D/bs.json")
    [ "$got" = "$BS/pmask/store.enc" ] \
        && pass "qa29-store-backslash-in-json" \
        || fail "qa29-store-backslash-in-json (path=$got)"
else
    fail "qa29-store-backslash-in-json (jq: $(jq . "$D/bs.json" 2>&1 | head -1))"
fi

# ----------------------------------------------- a quote in the socket path
SOCKQ="$D/sock\"et"
PMASK_SOCKET="$SOCKQ" XDG_DATA_HOME="$D/plain" "$TOOL" doctor --json > "$D/sock.json" 2>"$D/sock.err"
if jq -e . "$D/sock.json" >/dev/null 2>&1; then
    got=$(jq -r '.agent.socket' "$D/sock.json")
    [ "$got" = "$SOCKQ" ] \
        && pass "qa29-agent-socket-in-json" \
        || fail "qa29-agent-socket-in-json (socket=$got, want $SOCKQ)"
else
    fail "qa29-agent-socket-in-json (jq: $(jq . "$D/sock.json" 2>&1 | head -1))"
fi
export PMASK_SOCKET=""

# ------------------------------------------------ a quote in a --require name
# The name is unknown, so the verdict is 255, but the report is still
# printed and it still has to be valid JSON with the name intact.
XDG_DATA_HOME="$D/plain" \
    "$TOOL" doctor --json --require='"quoted name"' > "$D/req.json" 2>"$D/req.err"
if jq -e . "$D/req.json" >/dev/null 2>&1; then
    got=$(jq -r '.required[0].name' "$D/req.json")
    [ "$got" = '"quoted name"' ] \
        && pass "qa29-require-quote-escaped" \
        || fail "qa29-require-quote-escaped (name=[$got])"
else
    fail "qa29-require-quote-escaped (jq: $(jq . "$D/req.json" 2>&1 | head -1))"
fi

# ---------------------------------------------------- empty --require lists
# `--require ''` was an assertion that anything passes: it exits 0 on a
# host that cannot redact at all.  It has to be a usage error.
out=$(XDG_DATA_HOME="$D/plain" "$TOOL" doctor --require '' 2>&1 >/dev/null)
rc=$?
case "$out" in
    *"at least one guarantee"*)
        [ "$rc" = 255 ] \
            && pass "qa29-empty-require-refused (rc=$rc)" \
            || fail "qa29-empty-require-refused (rc=$rc, want 255)"
        ;;
    *)
        fail "qa29-empty-require-refused (rc=$rc, err=[$out])"
        ;;
esac

out=$(XDG_DATA_HOME="$D/plain" "$TOOL" doctor --require= 2>&1 >/dev/null)
rc=$?
case "$out" in
    *"at least one guarantee"*)
        [ "$rc" = 255 ] \
            && pass "qa29-eq-empty-require-refused (rc=$rc)" \
            || fail "qa29-eq-empty-require-refused (rc=$rc, want 255)"
        ;;
    *)
        fail "qa29-eq-empty-require-refused (rc=$rc, err=[$out])"
        ;;
esac

out=$(XDG_DATA_HOME="$D/plain" "$TOOL" doctor --require ',' 2>&1 >/dev/null)
rc=$?
case "$out" in
    *"at least one guarantee"*)
        [ "$rc" = 255 ] \
            && pass "qa29-comma-require-refused (rc=$rc)" \
            || fail "qa29-comma-require-refused (rc=$rc, want 255)"
        ;;
    *)
        fail "qa29-comma-require-refused (rc=$rc, err=[$out])"
        ;;
esac

# Control: a real requirement is unchanged.  `redact` is active on any
# host this gate runs on (the gate needs ptrace), so the code is 0.
XDG_DATA_HOME="$D/plain" "$TOOL" doctor --require redact >/dev/null 2>&1
rc=$?
[ "$rc" = 0 ] \
    && pass "qa29-valid-require-still-works" \
    || fail "qa29-valid-require-still-works (rc=$rc, want 0)"

# Control: no --require at all is still the plain report and still exits 0.
XDG_DATA_HOME="$D/plain" "$TOOL" doctor >/dev/null 2>&1
rc=$?
[ "$rc" = 0 ] \
    && pass "qa29-control-no-require-exits-zero" \
    || fail "qa29-control-no-require-exits-zero (rc=$rc, want 0)"

echo "== VERDICT: $FAIL failure(s) =="
exit "$FAIL"
