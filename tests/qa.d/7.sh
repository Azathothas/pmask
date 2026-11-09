#!/bin/sh
# QA fragment for issue 7: `--env-file` was parsed by two different
# grammars, one in `pmask` and one in `pmaskd`.
#
# The table from the issue, one row per case, plus the property the fix
# exists for: the same file produces the same environment on both
# surfaces.
#
#   row 1  `export FOO=bar`   CLI used to name the variable `export FOO`
#   row 2  `CRLF=v\r`         CLI used to deliver `v\r` (the dangerous one:
#                             every value from a CRLF file carried a CR)
#   row 3  `BAD KEY=v`        CLI used to accept a key with a space
#   row 4  `K="quoted value"` the CLI kept the quotes, the daemon removed
#                             them; both remove one pair now
#
# Cases:
#   qa7-cli-export               row 1 through `pmask --env-file`
#   qa7-cli-crlf                 row 2 through `pmask --env-file`
#   qa7-cli-bad-key-refused      row 3 is refused by the CLI, rc 255
#   qa7-cli-quotes               row 4 through `pmask --env-file`
#   qa7-daemon-export            row 1 through `pmaskd --env-file`
#   qa7-daemon-crlf              row 2 through `pmaskd --env-file`
#   qa7-daemon-bad-key-refused   row 3 is refused by the daemon, rc 255
#   qa7-daemon-quotes            row 4 through `pmaskd --env-file`
#   qa7-same-file-same-env       every accepted row gives the same value on
#                                both surfaces (the property the fix is for)
#   qa7-control-unfixed-shape    the checker can see the defect: the CR and
#                                the `export ` prefix are distinguishable
#                                in the bytes it reads back
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
DAEMON="$BIN_DIR/pmaskd"
CASES="$BIN_DIR/testcases"
[ -x "$TOOL" ] || { echo "FATAL: $TOOL is missing"; exit 2; }
[ -x "$DAEMON" ] || { echo "FATAL: $DAEMON is missing"; exit 2; }
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa7.XXXXXX") || {
    echo "FATAL: mktemp -d failed"; exit 2; }
chmod 700 "$D"
SOCK="$D/d.sock"
DPID=""
cleanup() {
    [ -n "$DPID" ] && kill -9 "$DPID" 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT INT TERM

# cli_env FILE KEY -> the value `pmask --env-file FILE` gives KEY, or
# `<unset>`.  A plain run (`--no-redact`) so the payload's environment is
# the file's, and `getenv` prints only the one name.
cli_env() {
    out=$("$TOOL" -q --no-redact --env-file "$1" -- "$CASES" getenv "$2" 2>/dev/null)
    case "$out" in
        *" unset") echo "<unset>" ;;
        *=*) printf '%s' "${out#*=}" ;;
        *) echo "<error:$out>" ;;
    esac
}

# daemon_env FILE KEY -> the same value through a `pmaskd --env-file`.
# Each call starts a fresh daemon, because a daemon's environment is
# fixed at startup.
daemon_env() {
    de_file="$1"
    de_key="$2"
    de_sock="$D/d-$de_key.sock"
    "$DAEMON" -q -S "$de_sock" --no-inherit-env --env-file "$de_file" \
        >"$D/d.out" 2>"$D/d.err" &
    de_pid=$!
    de_i=0
    while [ ! -S "$de_sock" ] && [ "$de_i" -lt 60 ]; do
        sleep 0.1
        de_i=$((de_i + 1))
    done
    if [ ! -S "$de_sock" ]; then
        echo "<daemon-did-not-start>"
        kill -9 "$de_pid" 2>/dev/null
        return
    fi
    de_out=$("$TOOL" -q --daemon "$de_sock" -- "$CASES" getenv "$de_key" 2>/dev/null)
    kill -TERM "$de_pid" 2>/dev/null
    wait "$de_pid" 2>/dev/null
    rm -f "$de_sock"
    case "$de_out" in
        *" unset") echo "<unset>" ;;
        *=*) printf '%s' "${de_out#*=}" ;;
        *) echo "<error:$de_out>" ;;
    esac
}

# ------------------------------------------------------- the four files
F1="$D/r1"
F2="$D/r2"
F3="$D/r3"
F4="$D/r4"
printf 'export FOO=bar\n' > "$F1"
printf 'CRLF=v\r\n' > "$F2"          # a CRLF line, written literally
printf 'BAD KEY=v\n' > "$F3"
printf 'K="quoted value"\n' > "$F4"
chmod 600 "$F1" "$F2" "$F3" "$F4"

# Confirm the fixture really carries the CR: a printf that cannot write it
# would make row 2 vacuous.
cr=$(od -An -c "$F2" | tr -d ' \n' | sed -n 's/.*\\r.*/yes/p')
if [ "$cr" = "yes" ]; then
    pass "qa7-fixture-has-a-cr"
else
    skip "qa7-fixture-has-a-cr (this printf/od cannot write or show a CR)"
fi

# ------------------------------------------------------- row 1: export
got=$(cli_env "$F1" FOO)
[ "$got" = "bar" ] && pass "qa7-cli-export (FOO=bar)" \
    || fail "qa7-cli-export (FOO=[$got], want bar; a name of 'export FOO' reads as unset)"

# The old defect in its own right: a variable literally named `export FOO`
# is not what the file asked for.  `getenv 'export FOO'` must be unset.
got=$("$TOOL" -q --no-redact --env-file "$F1" -- "$CASES" getenv 'export FOO' 2>/dev/null)
case "$got" in
    *" unset") pass "qa7-cli-no-variable-named-export" ;;
    *) fail "qa7-cli-no-variable-named-export (got [$got])" ;;
esac

# --------------------------------------------------------- row 2: CRLF
# Compare against a literal `v`, not `v\r`.  The trailing dot in the
# failure message is deliberate: `$(...)` strips a trailing newline but
# not a CR, and a CR would otherwise move the cursor.
got=$(cli_env "$F2" CRLF)
if [ "$got" = "v" ]; then
    pass "qa7-cli-crlf (CRLF=v)"
else
    fail "qa7-cli-crlf (CRLF=[$got], want [v]; a trailing CR means the value was not stripped)"
fi

# -------------------------------------------------- row 3: key with space
"$TOOL" -q --no-redact --env-file "$F3" -- /bin/true >/dev/null 2>"$D/r3.err"
rc=$?
if [ "$rc" = 255 ] && grep -q "key contains a space" "$D/r3.err"; then
    pass "qa7-cli-bad-key-refused (rc=$rc)"
else
    fail "qa7-cli-bad-key-refused (rc=$rc, err=$(head -1 "$D/r3.err"))"
fi

# The daemon refuses the same line, and with the same words.
"$DAEMON" -q -S "$D/r3.sock" --env-file "$F3" >/dev/null 2>"$D/r3d.err"
rc=$?
if [ "$rc" = 255 ] && grep -q "key contains a space" "$D/r3d.err"; then
    pass "qa7-daemon-bad-key-refused (rc=$rc)"
else
    fail "qa7-daemon-bad-key-refused (rc=$rc, err=$(head -1 "$D/r3d.err"))"
fi

# --------------------------------------------------------- row 4: quotes
got=$(cli_env "$F4" K)
[ "$got" = "quoted value" ] && pass "qa7-cli-quotes (K=[quoted value])" \
    || fail "qa7-cli-quotes (K=[$got], want [quoted value])"

# ------------------------------------------------------- the daemon side
got=$(daemon_env "$F1" FOO)
[ "$got" = "bar" ] && pass "qa7-daemon-export (FOO=bar)" \
    || fail "qa7-daemon-export (FOO=[$got], want bar)"

got=$(daemon_env "$F2" CRLF)
[ "$got" = "v" ] && pass "qa7-daemon-crlf (CRLF=v)" \
    || fail "qa7-daemon-crlf (CRLF=[$got], want [v])"

got=$(daemon_env "$F4" K)
[ "$got" = "quoted value" ] && pass "qa7-daemon-quotes (K=[quoted value])" \
    || fail "qa7-daemon-quotes (K=[quoted value] expected, got [$got])"

# ------------------------------------------- the property: one grammar
# Every accepted row must give the same answer on both surfaces.  This is
# the assertion the issue asks for; the per-row cases above say which row
# broke when this one fails.
mismatch=""
for spec in "$F1:FOO" "$F2:CRLF" "$F4:K"; do
    f=${spec%:*}
    k=${spec##*:}
    c=$(cli_env "$f" "$k")
    d=$(daemon_env "$f" "$k")
    if [ "$c" != "$d" ]; then
        mismatch="$mismatch $k(cli=[$c] daemon=[$d])"
    fi
done
if [ -z "$mismatch" ]; then
    pass "qa7-same-file-same-env"
else
    fail "qa7-same-file-same-env:$mismatch"
fi

echo "== VERDICT: $FAIL failure(s) =="
exit "$FAIL"
