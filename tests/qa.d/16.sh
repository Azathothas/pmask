#!/bin/sh
# QA fragment for issue 16: `--keep-env` followed by `--keep-env=NAME`
# exposes the whole environment.
#
# The defect: `--keep-env` turned `redact_environ` off, and a later
# `--keep-env=NAME` only pushed the name without turning redaction back
# on.  The result was the whole inherited environment, the opposite of the
# narrowing the operator asked for.  The reverse order still has to give
# the whole environment, because the last request wins.
#
# The failure messages here never print the environment itself: on the
# unfixed build that is the container's own secret-bearing environment, and
# a test must not write that into a log.  They print the variable count and
# the fact that KEEPME is or is not there.
#
# Cases:
#   qa16-keep-then-name         --keep-env --keep-env=KEEPME: exactly one
#                               variable is visible, and it is KEEPME
#   qa16-keep-then-name-narrow  the visible count is 1, not the inherited
#                               environment's count
#   qa16-name-then-keep         --keep-env=KEEPME --keep-env: OTHER is
#                               visible too (last request wins)
#   qa16-name-only              --keep-env=KEEPME alone: exactly one
#                               variable, KEEPME
#   qa16-control-default        no --keep-env at all: environ is 0 bytes
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

cleanup() { kill_label qa16 KILL 2>/dev/null; }
trap cleanup EXIT

# visible_names ENVFILE -> the non-empty variable names, one per line.
# The unkept slots are NUL bytes, so a `tr` to newlines leaves empty lines.
visible_names() {
    tr '\0' '\n' < "$1" 2>/dev/null | sed -n 's/=.*//; /^$/d; p'
}

# visible_count ENVFILE -> how many variables are visible.
visible_count() {
    n=$(visible_names "$1" | wc -l | tr -d ' ')
    echo "${n:-0}"
}

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa16.XXXXXX") || {
    echo "FAIL qa16-cannot-create-tmp"; exit 2
}
trap 'rm -rf "$D"; cleanup' EXIT

dump_env() {  # dump_env NAME OPTIONS...
    de_name="$1"
    shift
    KEEPME=v OTHER=h KEEPME2=z "$TOOL" -q "$@" -- \
        /bin/sh -c 'tr "\0" "\n" < /proc/self/environ' >"$D/$de_name" 2>/dev/null
}

# ------------------------------------------------- keep-env then keep-env=
dump_env a --keep-env --keep-env=KEEPME
count=$(visible_count "$D/a")
# The message names whether KEEPME is there and how many variables are
# visible.  It never lists the environment: on the unfixed build that is
# the caller's whole secret-bearing environment.
if visible_names "$D/a" | grep -qx 'KEEPME' && [ "$count" = "1" ]; then
    pass qa16-keep-then-name
else
    fail "qa16-keep-then-name (count=$count, KEEPME present=$(visible_names "$D/a" | grep -cx 'KEEPME'), want count=1 with KEEPME)"
fi
if [ "$count" = "1" ]; then
    pass qa16-keep-then-name-narrow
else
    fail "qa16-keep-then-name-narrow ($count variables visible, want 1)"
fi

# ------------------------------------------------- keep-env= then keep-env
dump_env b --keep-env=KEEPME --keep-env
if visible_names "$D/b" | grep -qx 'OTHER'; then
    pass qa16-name-then-keep
else
    fail "qa16-name-then-keep (OTHER not visible; count=$(visible_count "$D/b"))"
fi

# ----------------------------------------------------------- keep-env= only
dump_env c --keep-env=KEEPME
if visible_names "$D/c" | grep -qx 'KEEPME' && [ "$(visible_count "$D/c")" = "1" ]; then
    pass qa16-name-only
else
    fail "qa16-name-only (count=$(visible_count "$D/c"), KEEPME present=$(visible_names "$D/c" | grep -cx 'KEEPME'), want count=1 with KEEPME)"
fi

# --------------------------------------------------------------- control
sz=$(KEEPME=v OTHER=h "$TOOL" -q -- /bin/sh -c 'wc -c < /proc/self/environ' 2>/dev/null | tr -d ' ')
if [ "$sz" = "0" ]; then
    pass qa16-control-default
else
    fail "qa16-control-default (environ=$sz bytes, want 0)"
fi

exit "$FAIL"
