#!/bin/sh
# Issue 41: the shapes of /proc/<pid>/environ under a mask.
#
# Four measured shapes, one per mode (evidence/bteam1/41/):
#   1. default: 0 bytes, environment window collapsed (env_start == env_end)
#   2. --no-exact: a run of NUL bytes, window extent kept
#   3. --keep-env: the inherited environment, values included
#   4. --keep-env=NAME: the kept variable plus one NUL per other slot
#
# Shapes 1, 2 and 4 are the delivered behaviour and this fragment asserts
# them so a regression is visible.  Shape 3 is the one with a security
# edge, and the new part is the warning: an `env:` secret source reads
# the value from the environment, so `--keep-env` publishes exactly the
# value the run was asked to hide.  The warning names it and the run
# continues: keeping the variable is the documented behaviour of the
# flag, so this is a warning, never a refusal.
#
# Cases:
#   E1 default: environ is 0 bytes and the window is collapsed
#   E2 --no-exact: environ is a NUL run and the window keeps its extent
#   E3 control: --keep-env shows the planted value (the shape is real)
#   E4 --keep-env + env: secret warns once and names the variable
#   E5 the kept variable is still kept after the warning (no removal)
#   E6 --keep-env=NAME + env: secret for the same name warns
#   E7 --keep-env=OTHER + env: secret for a different name does not warn
#   E8 --keep-env + literal: secret does not warn (measured: no leak)
#   E9 --keep-env + file: secret does not warn
#   E10 the payload still runs normally after the warning
set -u
cd "$(dirname "$0")"
. ../lib.sh

# lib.sh derives BIN_DIR from the cwd, which for a fragment is tests/qa.d.
# The binaries live in tests/; point the helpers at them.
BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa41.XXXXXX") || {
    echo "FATAL: cannot create a temp dir"; exit 2
}
SUP=""
cleanup() {
    [ -n "$SUP" ] && kill "$SUP" 2>/dev/null
    kill_label qa41-
    rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

L=qa41-env
SECRET=QA41-CANARY-hunter2
printf 'file-source-value\n' > "$D/tok"

# start FLAGS...  -- run the payload with the planted environment and
# leave SUP and PAY set.  Returns 1 when no payload appeared.
start() {
    env -i PATH=/usr/bin:/bin HUSH="$SECRET" KEEPME=QA41-KEEPME \
        "$TOOL" -q -l "$L" "$@" -- "$CASES" sleeper QAMARK \
        >/dev/null 2>"$D/last.err" &
    SUP=$!
    PAY=""
    i=0
    while [ $i -lt 40 ]; do
        sleep 0.05
        PAY=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
        [ -n "$PAY" ] && return 0
        i=$((i + 1))
    done
    return 1
}
stop() {
    [ -n "${SUP:-}" ] && kill "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
    SUP=""; PAY=""
}

env_bytes() { wc -c < "/proc/$1/environ" 2>/dev/null || echo 0; }
env_nuls() { tr -cd '\0' < "/proc/$1/environ" 2>/dev/null | wc -c; }
env_span() { awk '{sub(/.*\) /,""); print $49 - $48}' "/proc/$1/stat" 2>/dev/null; }

# ------------------------------------------- E1: default, 0 bytes
if start; then
    n=$(env_bytes "$PAY")
    sp=$(env_span "$PAY")
    if [ "$n" = 0 ] && [ "$sp" = 0 ]; then
        pass "e1-default-empty-environ (bytes=$n span=$sp)"
    else
        fail "e1-default-empty-environ (bytes=$n span=$sp, want 0 and 0)"
    fi
    stop
else
    fail "e1-default-empty-environ (no payload)"
    stop
fi

# ---------------------------- E2: --no-exact, NUL run, extent kept
if start --no-exact; then
    n=$(env_bytes "$PAY")
    z=$(env_nuls "$PAY")
    sp=$(env_span "$PAY")
    # Three variables: PATH, HUSH, KEEPME.  The rule is one NUL per
    # variable; the extent is non-zero because it is not relocated.
    if [ "$n" = "$z" ] && [ "$z" -ge 2 ] && [ "$sp" != 0 ]; then
        pass "e2-no-exact-nul-run (bytes=$n nuls=$z span=$sp)"
    else
        fail "e2-no-exact-nul-run (bytes=$n nuls=$z span=$sp, want bytes==nuls>=2 and span!=0)"
    fi
    stop
else
    fail "e2-no-exact-nul-run (no payload)"
    stop
fi

# ------------------------- E3: control, --keep-env publishes the value
if start --keep-env; then
    if tr '\0' '\n' < "/proc/$PAY/environ" 2>/dev/null | grep -qF "HUSH=$SECRET"; then
        pass "e3-control-keep-env-shows-the-value"
    else
        fail "e3-control-keep-env-shows-the-value (environ=$(tr '\0' '|' < "/proc/$PAY/environ" 2>/dev/null))"
    fi
    stop
else
    fail "e3-control-keep-env-shows-the-value (no payload)"
    stop
fi

# ------------------- E4: --keep-env + env: secret warns and names it
err="$D/e4.err"
env -i PATH=/usr/bin:/bin HUSH="$SECRET" \
    "$TOOL" -l "$L" --keep-env --secret T=env:HUSH \
    -- "$CASES" sleeper QAMARK >/dev/null 2>"$err" &
SUP=$!
sleep 0.9
warn=$(grep -c -- '--keep-env publishes' "$err" 2>/dev/null)
named=$(grep -c "'T' (env:HUSH)" "$err" 2>/dev/null)
alive=no
kill -0 "$SUP" 2>/dev/null && alive=yes
if [ "$warn" = 1 ] && [ "$named" = 1 ] && [ "$alive" = yes ]; then
    pass "e4-keep-env-env-secret-warns (warn=$warn named=$named)"
else
    fail "e4-keep-env-env-secret-warns (warn=$warn named=$named alive=$alive; $(tr '\n' '|' < "$err"))"
fi
# E10 liveness: a live child running the program.  The payload is masked
# here, so its cmdline is the label; the check is comm plus the real exe.
pay=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
if [ -n "$pay" ] && [ "$(cat "/proc/$pay/comm" 2>/dev/null)" = "$L" ] \
    && [ -n "$(readlink "/proc/$pay/exe" 2>/dev/null)" ]; then
    pass "e10-warned-run-still-runs (payload=$pay masked, exe readable)"
else
    fail "e10-warned-run-still-runs (payload=[$pay] comm=[$(cat "/proc/$pay/comm" 2>/dev/null)] exe=[$(readlink "/proc/$pay/exe" 2>/dev/null)])"
fi
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""

# ------------------- E5: the kept variable is still kept
# The warning must not turn into a silent redaction: --keep-env keeps
# everything, warning or not.
if start --keep-env --secret U=env:HUSH; then
    if tr '\0' '\n' < "/proc/$PAY/environ" 2>/dev/null | grep -qF "HUSH=$SECRET"; then
        pass "e5-kept-vars-still-kept"
    else
        fail "e5-kept-vars-still-kept (HUSH gone: $(tr '\0' '|' < "/proc/$PAY/environ" 2>/dev/null))"
    fi
    stop
else
    fail "e5-kept-vars-still-kept (no payload)"
    stop
fi

# ------------------- E6: --keep-env=NAME for the same name warns
err="$D/e6.err"
env -i PATH=/usr/bin:/bin HUSH="$SECRET" \
    "$TOOL" -l "$L" --keep-env=HUSH --secret T=env:HUSH \
    -- "$CASES" sleeper QAMARK >/dev/null 2>"$err" &
SUP=$!
sleep 0.9
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
warn=$(grep -c -- '--keep-env publishes' "$err" 2>/dev/null)
if [ "$warn" = 1 ]; then
    pass "e6-keep-env-named-warns"
else
    fail "e6-keep-env-named-warns (warn=$warn; $(tr '\n' '|' < "$err"))"
fi

# ---------------- E7: a different kept name does not warn
err="$D/e7.err"
env -i PATH=/usr/bin:/bin HUSH="$SECRET" KEEPME=x \
    "$TOOL" -l "$L" --keep-env=KEEPME --secret T=env:HUSH \
    -- "$CASES" sleeper QAMARK >/dev/null 2>"$err" &
SUP=$!
sleep 0.9
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
warn=$(grep -c -- '--keep-env publishes' "$err" 2>/dev/null)
if [ "$warn" = 0 ]; then
    pass "e7-other-name-does-not-warn"
else
    fail "e7-other-name-does-not-warn (warn=$warn; $(tr '\n' '|' < "$err"))"
fi

# -------- E8/E9: a literal or file source does not warn under --keep-env
# Measured: a literal value never enters the payload's environment (only
# PMASK_SECRET_<N>=<fd> does), so warning there would be false.
err="$D/e8.err"
env -i PATH=/usr/bin:/bin "$TOOL" -l "$L" --keep-env \
    --secret T=literal:"$SECRET" -- "$CASES" sleepfor 0 >/dev/null 2>"$err"
warn=$(grep -c -- '--keep-env publishes' "$err" 2>/dev/null)
if [ "$warn" = 0 ]; then
    pass "e8-keep-env-literal-does-not-warn"
else
    fail "e8-keep-env-literal-does-not-warn (warn=$warn; $(tr '\n' '|' < "$err"))"
fi

err="$D/e9.err"
env -i PATH=/usr/bin:/bin "$TOOL" -l "$L" --keep-env \
    --secret T=file:"$D/tok" -- "$CASES" sleepfor 0 >/dev/null 2>"$err"
warn=$(grep -c -- '--keep-env publishes' "$err" 2>/dev/null)
if [ "$warn" = 0 ]; then
    pass "e9-keep-env-file-does-not-warn"
else
    fail "e9-keep-env-file-does-not-warn (warn=$warn; $(tr '\n' '|' < "$err"))"
fi

echo "== QA41: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
[ "$FAIL" = 0 ] || exit 1
exit 0
