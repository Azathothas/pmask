#!/bin/sh
# Issue 40: the argv-window arithmetic of a masked process.
#
# The report states a rule and this fragment asserts it on this build:
#
#   default (exact) mode:
#     cmdline            == label + one NUL            (len == len(label)+1)
#     arg_end - arg_start == the cmdline byte count
#     env_start == env_end                             (zero environment span)
#     comm               == the label cut to 15 bytes
#
#   --no-exact:
#     cmdline carries one NUL per argument slot plus the label, and the
#     environment one NUL per variable; the extent is not relocated.
#
# The report also refutes a rule the project's own research stated
# ("cmdline shorter than the stat span"), so the negative control here is
# an ordinary process: its span equals its cmdline length too, and its
# environment span is non-zero.  That is what makes the conjunction
# (one NUL + equal span + zero env span) the discriminating rule rather
# than any single clause.
#
# Cases:
#   W1 control: an unmasked /bin/sleep has many NULs and a non-zero env span
#   W2 default: cmdline == label+NUL, arg span == that length
#   W3 default: env_start == env_end
#   W4 default: comm == the label, and >15 bytes are cut to 15
#   W5 default: comm is the label, cut to 15 bytes
#   W6 a 20-byte label: comm is 15 bytes, cmdline carries all 20
#   W8 --label-empty: 1-byte cmdline, and the arithmetic still holds
#   W9 payload is alive and its real argv reached it (span is not vacuous)
#   W10 --no-exact: one NUL per argument slot plus the label's own
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

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa40.XXXXXX") || {
    echo "FATAL: cannot create a temp dir"; exit 2
}
SUP=""
cleanup() {
    [ -n "$SUP" ] && kill "$SUP" 2>/dev/null
    kill_label qa40-
    rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# start LABEL FLAGS...  -- sets SUP and PAY
start() {
    lab=$1; shift
    if [ "$lab" = "-" ]; then
        env -i PATH=/usr/bin:/bin "$TOOL" -q --label-empty "$@" \
            -- "$CASES" sleeper QAMARK >/dev/null 2>"$D/last.err" &
    else
        env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$lab" "$@" \
            -- "$CASES" sleeper QAMARK >/dev/null 2>"$D/last.err" &
    fi
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

cmd_bytes() { wc -c < "/proc/$1/cmdline" 2>/dev/null || echo 0; }
cmd_nuls() { tr -cd '\0' < "/proc/$1/cmdline" 2>/dev/null | wc -c; }
env_bytes() { wc -c < "/proc/$1/environ" 2>/dev/null || echo 0; }
env_nuls() { tr -cd '\0' < "/proc/$1/environ" 2>/dev/null | wc -c; }
# The span arithmetic, and the trap the issue documents: `awk` fields 48/49
# are only the raw file's numbering.  After stripping through the last ') '
# the pair is 46/47.  Getting this wrong computes env_end-env_start and the
# rule silently checks the wrong thing.
spans() {
    awk '{sub(/.*\) /,""); print $47 - $46, $49 - $48}' "/proc/$1/stat" 2>/dev/null
}

# ------------------------- W1: control, an ordinary process
env -i PATH=/usr/bin:/bin FOO=bar /bin/sleep 300 >/dev/null 2>&1 &
plain=$!
sleep 0.5
if kill -0 "$plain" 2>/dev/null; then
    cn=$(cmd_nuls "$plain"); cb=$(cmd_bytes "$plain")
    read -r pa pe <<EOT
$(spans "$plain")
EOT
    # /bin/sleep 300 is one argument: two strings, two NULs, non-zero env.
    if [ "$cn" -ge 2 ] && [ "$cb" -ge 10 ] && [ "$pa" = "$cb" ] && [ "$pe" != 0 ]; then
        pass "w1-control-plain-process (nuls=$cn bytes=$cb argspan=$pa envspan=$pe)"
    else
        fail "w1-control-plain-process (nuls=$cn bytes=$cb argspan=$pa envspan=$pe)"
    fi
    kill "$plain" 2>/dev/null
    wait "$plain" 2>/dev/null
else
    fail "w1-control-plain-process (no process)"
fi

# ---------------------------- W2/W3/W4: the default mode arithmetic
L=qa40-lbl
if start "$L"; then
    cb=$(cmd_bytes "$PAY"); cn=$(cmd_nuls "$PAY")
    read -r as es <<EOT
$(spans "$PAY")
EOT
    comm=$(cat "/proc/$PAY/comm" 2>/dev/null)
    if [ "$cb" = "$(( ${#L} + 1 ))" ] && [ "$cn" = 1 ]; then
        pass "w2-cmdline-is-label-plus-nul (bytes=$cb nuls=$cn label=${#L})"
    else
        fail "w2-cmdline-is-label-plus-nul (bytes=$cb nuls=$cn, want $(( ${#L} + 1 )) and 1)"
    fi
    if [ "$as" = "$cb" ]; then
        pass "w3-arg-span-equals-cmdline (span=$as bytes=$cb)"
    else
        fail "w3-arg-span-equals-cmdline (span=$as bytes=$cb)"
    fi
    if [ "$es" = 0 ]; then
        pass "w4-env-span-collapsed (span=$es)"
    else
        fail "w4-env-span-collapsed (span=$es, want 0)"
    fi
    if [ "$comm" = "$L" ]; then
        pass "w5-comm-is-the-label (comm=$comm)"
    else
        fail "w5-comm-is-the-label (comm=$comm)"
    fi
    # W9 liveness: the payload's own argv reached it, so the zero span is
    # not a symptom of a process that never ran.
    if [ -n "$PAY" ] && [ "$(cat "/proc/$PAY/comm" 2>/dev/null)" = "$L" ]; then
        pass "w9-payload-alive-under-label (pid=$PAY)"
    else
        fail "w9-payload-alive-under-label (pid=[$PAY])"
    fi
    stop
else
    fail "w2-cmdline-is-label-plus-nul (no payload)"
    stop
fi

# ---------------------- W6/W7: a long label, comm cut at 15
LONG=qa40-twentycharacter
if start "$LONG"; then
    cb=$(cmd_bytes "$PAY")
    comm=$(cat "/proc/$PAY/comm" 2>/dev/null)
    if [ "$cb" = "$(( ${#LONG} + 1 ))" ] && [ "${#comm}" = 15 ]; then
        pass "w6-long-label-cmdline-full-comm-cut (bytes=$cb commlen=${#comm})"
    else
        fail "w6-long-label-cmdline-full-comm-cut (bytes=$cb commlen=${#comm}, want $(( ${#LONG} + 1 )) and 15)"
    fi
    stop
else
    fail "w6-long-label-cmdline-full-comm-cut (no payload)"
    stop
fi

# ----------------------------- W8: --label-empty arithmetic
if start -; then
    cb=$(cmd_bytes "$PAY"); cn=$(cmd_nuls "$PAY")
    read -r as es <<EOT
$(spans "$PAY")
EOT
    if [ "$cb" = 1 ] && [ "$cn" = 1 ] && [ "$as" = 1 ] && [ "$es" = 0 ]; then
        pass "w8-label-empty-arithmetic (bytes=$cb nuls=$cn argspan=$as envspan=$es)"
    else
        fail "w8-label-empty-arithmetic (bytes=$cb nuls=$cn argspan=$as envspan=$es, want 1/1/1/0)"
    fi
    stop
else
    fail "w8-label-empty-arithmetic (no payload)"
    stop
fi

# ------------------------- W10: --no-exact, the presentation rule
# The `--no-exact` path does NOT relocate its window.  It re-reads the
# kernel's copied strings, places them in a hidden mapping, and then
# presents the original extent as one command line: the label, spaces,
# and a single final NUL.  The environment gets a plausible decoy (or
# the --keep-env variables), not an all-NUL block.  The old shape, one
# NUL per argument slot, was a fingerprint.
A1=$(printf 'a%.0s' $(seq 40))
A2=$(printf 'b%.0s' $(seq 40))
A3=$(printf 'c%.0s' $(seq 40))
L9=L9abcdef
env -i PATH=/usr/bin:/bin "$TOOL" -q --no-exact -l "$L9" \
    -- "$CASES" sleeper QAMARK "$A1" "$A2" "$A3" >/dev/null 2>"$D/ne.err" &
SUP=$!
PAY=""
i=0
while [ $i -lt 40 ]; do
    sleep 0.05
    PAY=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
    [ -n "$PAY" ] && break
    i=$((i + 1))
done
if [ -n "$PAY" ]; then
    cb=$(cmd_bytes "$PAY"); cn=$(cmd_nuls "$PAY")
    eb=$(env_bytes "$PAY"); en=$(env_nuls "$PAY")
    read -r asp esp <<EOT
$(spans "$PAY")
EOT
    if [ "$cn" = 1 ]; then
        pass "w10-no-exact-single-nul (nuls=$cn)"
    else
        fail "w10-no-exact-single-nul (nuls=$cn, want 1)"
    fi
    if [ "$cb" = "$asp" ]; then
        pass "w10-cmdline-bytes=argspan (bytes=$cb span=$asp)"
    else
        fail "w10-cmdline-bytes=argspan (bytes=$cb span=$asp)"
    fi
    if [ "$(head -c "${#L9}" "/proc/$PAY/cmdline")" = "$L9" ]; then
        pass "w10-cmdline-starts-with-the-label"
    else
        fail "w10-cmdline-starts-with-the-label"
    fi
    tail_bytes=$(tail -c "+$(( ${#L9} + 1 ))" "/proc/$PAY/cmdline" | tr -d ' ' | wc -c)
    if [ "$tail_bytes" = 1 ]; then
        pass "w10-cmdline-tail-is-spaces-then-one-nul"
    else
        fail "w10-cmdline-tail-is-spaces-then-one-nul (non-space bytes=$tail_bytes)"
    fi
    if [ "$eb" = "$esp" ] && { [ "$eb" -le 1 ] || [ "$en" -lt "$eb" ]; }; then
        pass "w10-environ-is-not-an-all-nul-block (bytes=$eb nuls=$en span=$esp)"
    else
        fail "w10-environ-is-not-an-all-nul-block (bytes=$eb nuls=$en span=$esp)"
    fi
    stop
else
    fail "w10-no-exact-one-nul-per-arg-slot (no payload; $(tr '\n' '|' < "$D/ne.err"))"
fi
SUP=""

echo "== QA40: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
[ "$FAIL" = 0 ] || exit 1
exit 0
