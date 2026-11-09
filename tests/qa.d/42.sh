#!/bin/sh
# Issue 42: comm, cmdline and exe disagree, and the label limits.
#
# After a masked exec, `comm` is the label cut to 15 bytes, `cmdline` is
# the whole label plus one NUL, and `exe` still names the real binary.
# Each axis alone occurs in ordinary software; the conjunction is what
# identifies a masked process.  The label has three cut points, and this
# fragment pins the two a caller can reach from the CLI: `--comm` is
# rejected above 15 bytes, and a label above 254 bytes warns while the
# settled cmdline still carries it (the window relocation runs).
#
# `--comm` accepts LF and CR, which corrupts the parenthesised field of
# /proc/<pid>/stat that every rule in this set parses.  That is a real
# defect and it belongs to fix1 (issue #33); this fragment asserts the
# current behaviour so the dependency is visible and a fix shows up as a
# changed expectation, not a silently different pass.
#
# Cases:
#   C1 control: a plain process has comm == basename(exe); argv[0] is the
#      path as typed, so the comparison is against basename, not argv[0]
#   C2 default: comm == cmdline[0], basename(exe) != that (the masquerade)
#   C3 default: TracerPid is non-zero, which a real daemon does not have
#   C4 --comm 15 bytes: accepted, comm file is 16 bytes (15 + newline)
#   C5 --comm 16 bytes: refused with 255 and a message naming the limit
#   C6 -l- gives a 2-byte cmdline (space, NUL) and comm is one space
#   C7 --label-empty gives a 1-byte cmdline (NUL) and an empty comm
#   C8 a 254-byte label: accepted silently, cmdline carries 255 bytes
#   C9 a 255-byte label: warns once, cmdline carries 256 bytes
#   C10 --comm LF is accepted today (fix1 #33 owns the fix; recorded, not failed)
#   C11 --comm CR is accepted today (same dependency)
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

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa42.XXXXXX") || {
    echo "FATAL: cannot create a temp dir"; exit 2
}
SUP=""
cleanup() {
    [ -n "$SUP" ] && kill "$SUP" 2>/dev/null
    kill_label qa42-
    rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# start LABEL ARGS...  -- SUP/PAY, label defaults to the program name
start() {
    env -i PATH=/usr/bin:/bin "$TOOL" -q "$@" \
        -- "$CASES" sleeper QAMARK >/dev/null 2>"$D/last.err" &
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
cmd_first() { tr '\0' '\n' < "/proc/$1/cmdline" 2>/dev/null | head -n 1; }

# ------------------------- C1: control, an ordinary process
"$CASES" sleeper QAMARK >/dev/null 2>&1 &
plain=$!
sleep 0.5
if kill -0 "$plain" 2>/dev/null; then
    c=$(cat "/proc/$plain/comm" 2>/dev/null)
    e=$(basename "$(readlink "/proc/$plain/exe" 2>/dev/null)" 2>/dev/null)
    if [ -n "$c" ] && [ "$e" = "$c" ]; then
        pass "c1-control-plain-process (comm=$c exe=$e)"
    else
        fail "c1-control-plain-process (comm=$c exe=$e)"
    fi
    kill "$plain" 2>/dev/null
    wait "$plain" 2>/dev/null
else
    fail "c1-control-plain-process (no process)"
fi

# ------------------- C2/C3: the label-versus-exe split, and the tracer
L=qa42-sshd
if start -l "$L"; then
    c=$(cat "/proc/$PAY/comm" 2>/dev/null)
    a=$(cmd_first "$PAY")
    e=$(basename "$(readlink "/proc/$PAY/exe" 2>/dev/null)" 2>/dev/null)
    tracer=$(sed -n 's/^TracerPid:[[:space:]]*\([0-9]*\).*/\1/p' "/proc/$PAY/status" 2>/dev/null)
    if [ "$c" = "$a" ] && [ -n "$e" ] && [ "$e" != "$c" ]; then
        pass "c2-label-vs-exe-split (label=$c exe=$e)"
    else
        fail "c2-label-vs-exe-split (label=$c exe=$e argv0=$a)"
    fi
    if [ -n "$tracer" ] && [ "$tracer" != 0 ]; then
        pass "c3-tracerpid-non-zero (tracer=$tracer)"
    else
        fail "c3-tracerpid-non-zero (tracer=[$tracer])"
    fi
    stop
else
    fail "c2-label-vs-exe-split (no payload)"
    stop
fi

# -------------------------------------- C4/C5: the --comm limit
C15=123456789012345
if start --comm "$C15" -l qa42-comm; then
    n=$(wc -c < "/proc/$PAY/comm" 2>/dev/null)
    c=$(cat "/proc/$PAY/comm" 2>/dev/null)
    if [ "$n" = 16 ] && [ "$c" = "$C15" ]; then
        pass "c4-comm-15-bytes-accepted (comm=$c file_bytes=$n)"
    else
        fail "c4-comm-15-bytes-accepted (comm=$c file_bytes=$n, want $C15 and 16)"
    fi
    stop
else
    fail "c4-comm-15-bytes-accepted (no payload)"
    stop
fi

C16=1234567890123456
out=$("$TOOL" -q --comm "$C16" -- "$CASES" sleeper QAMARK 2>&1)
rc=$?
if [ "$rc" = 255 ]; then
    case "$out" in
        *"comm must be at most 15 bytes"*) pass "c5-comm-16-bytes-refused" ;;
        *) fail "c5-comm-16-bytes-refused (rc=$rc message=[$out])" ;;
    esac
else
    fail "c5-comm-16-bytes-refused (rc=$rc, want 255; [$out])"
fi

# ------------------------------ C6: -l- is one space plus NUL
if start -l-; then
    n=$(wc -c < "/proc/$PAY/cmdline" 2>/dev/null)
    hex=$(od -An -tx1 "/proc/$PAY/cmdline" 2>/dev/null | tr -d ' \n')
    c=$(cat "/proc/$PAY/comm" 2>/dev/null)
    if [ "$n" = 2 ] && [ "$hex" = "2000" ] && [ "$c" = " " ]; then
        pass "c6-dash-label-blank (bytes=$n hex=$hex comm=[$c])"
    else
        fail "c6-dash-label-blank (bytes=$n hex=$hex comm=[$c], want 2/2000/space)"
    fi
    stop
else
    fail "c6-dash-label-blank (no payload)"
    stop
fi

# -------------------------------- C7: --label-empty
if start --label-empty; then
    n=$(wc -c < "/proc/$PAY/cmdline" 2>/dev/null)
    hex=$(od -An -tx1 "/proc/$PAY/cmdline" 2>/dev/null | tr -d ' \n')
    if [ "$n" = 1 ] && [ "$hex" = "00" ]; then
        pass "c7-label-empty (bytes=$n hex=$hex)"
    else
        fail "c7-label-empty (bytes=$n hex=$hex, want 1/00)"
    fi
    stop
else
    fail "c7-label-empty (no payload)"
    stop
fi

# --------------------- C8/C9: the 254 and 255-byte labels
L254=$(printf 'L%.0s' $(seq 254))
out=$(env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$L254" -- "$CASES" sleeper QAMARK 2>&1) &
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
    n=$(wc -c < "/proc/$PAY/cmdline" 2>/dev/null)
    if [ "$n" = 255 ]; then
        pass "c8-254-byte-label (cmdline_bytes=$n)"
    else
        fail "c8-254-byte-label (cmdline_bytes=$n, want 255)"
    fi
    stop
else
    fail "c8-254-byte-label (no payload)"
    stop
fi

L255=$(printf 'M%.0s' $(seq 255))
env -i PATH=/usr/bin:/bin "$TOOL" -l "$L255" -- "$CASES" sleeper QAMARK \
    >/dev/null 2>"$D/c9.err" &
SUP=$!
PAY=""
i=0
while [ $i -lt 40 ]; do
    sleep 0.05
    PAY=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
    [ -n "$PAY" ] && break
    i=$((i + 1))
done
warn=$(grep -c 'label is 255 bytes' "$D/c9.err" 2>/dev/null)
if [ "$warn" = 1 ] && [ -n "$PAY" ]; then
    n=$(wc -c < "/proc/$PAY/cmdline" 2>/dev/null)
    if [ "$n" = 256 ]; then
        pass "c9-255-byte-label-warns (warn=$warn cmdline_bytes=$n)"
    else
        fail "c9-255-byte-label-warns (warn=$warn cmdline_bytes=$n, want 256)"
    fi
else
    fail "c9-255-byte-label-warns (warn=$warn payload=[$PAY]; $(tr '\n' '|' < "$D/c9.err"))"
fi
stop

# --------------------------- C10/C11: --comm LF and CR (fix1 #33)
# These are recorded, not asserted as correct: the defect is real and it
# is fix1's.  A PASS here means "the current behaviour is what the issue
# measured", so a fix in #33 shows up as a failing case with a message
# that points at the dependency, and the reconciler updates it.
if start --comm "$(printf 'a\nb')" -l qa42-lf; then
    c=$(od -An -tx1 "/proc/$PAY/comm" 2>/dev/null | tr -d ' \n')
    stat_ok=no
    awk '{sub(/.*\) /,""); if ($47 - $46 > 0) exit 0; exit 1}' "/proc/$PAY/stat" 2>/dev/null \
        && stat_ok=yes
    if [ "$c" = "610a620a" ]; then
        pass "c10-comm-lf-accepted-today (comm hex=$c; fix1 #33 owns the fix)"
    else
        fail "c10-comm-lf-accepted-today (comm hex=$c, expected 610a620a; if #33 landed, update this case)"
    fi
    # The parenthesised comm now contains a raw LF, so a reader that
    # strips through the last ') ' still finds it, but `ps` and any line
    # oriented reader see two lines.  Recorded as an observation.
    echo "INFO c10 stat parse with an LF comm: $([ "$stat_ok" = yes ] && echo ok || echo broken)"
    stop
else
    fail "c10-comm-lf-accepted-today (no payload)"
    stop
fi

if start --comm "$(printf 'a\rb')" -l qa42-cr; then
    c=$(od -An -tx1 "/proc/$PAY/comm" 2>/dev/null | tr -d ' \n')
    if [ "$c" = "610d620a" ]; then
        pass "c11-comm-cr-accepted-today (comm hex=$c; fix1 #33 owns the fix)"
    else
        fail "c11-comm-cr-accepted-today (comm hex=$c, expected 610d620a; if #33 landed, update this case)"
    fi
    stop
else
    fail "c11-comm-cr-accepted-today (no payload)"
    stop
fi

echo "== QA42: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
[ "$FAIL" = 0 ] || exit 1
exit 0
