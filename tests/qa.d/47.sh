#!/bin/sh
# Issue 47: the end states are documented design.  Each shape is asserted
# as documented; nothing here changes a default.
#
#   q47a  control: without --detach the payload is traced (TracerPid != 0)
#   q47b  --detach: TracerPid 0, the label and the empty environ stay, and
#         the payload is alive and functional
#   q47c  --detach warns once, at the release, that later execs of that
#         process are not redacted; -q suppresses it
#   q47d  --no-follow: the direct child is redacted, the grandchild keeps
#         its real argv and still runs
#   q47e  --on-exit detach: a labelled orphan survives the supervisor
#   q47f  --on-exit kill: no labelled process survives the supervisor
#   q47g  --no-exit-kill: the payload survives SIGKILL to the supervisor
#   q47h  control: the default exit-kill takes the payload with its
#         supervisor
#
# Catches: a flag ignored, an end state that differs from its man page,
# a payload that dies or stops working under any of them, and a detach
# release with no warning naming the coverage it gives up.
set -u
here=$(dirname "$0")
cd "$here/.." || { echo "FATAL: cannot enter tests/"; exit 2; }
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
T="/tmp/qa47.$$"
mkdir -p "$T" || { echo "FATAL: cannot create $T"; exit 2; }

# Labels are at most 15 bytes so `comm` is the label with nothing clipped.
SHORT=$(printf '%s' "$$" | tail -c 5)
BASE="q47-$SHORT"
SUP=""
PAY=""

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    [ -n "${SUP:-}" ] && kill -9 "$SUP" 2>/dev/null
    [ -n "${PAY:-}" ] && kill -9 "$PAY" 2>/dev/null
    kill_label "$BASE" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM HUP QUIT

status_field() {
    sed -n "s/^$2:[[:space:]]*\(.*\)$/\1/p" "/proc/$1/status" 2>/dev/null
}

# wait_child PID SECONDS -> the first live child of PID
wait_child() {
    wc_end=$(( $(date +%s 2>/dev/null || echo 0) + $2 ))
    while :; do
        for d in /proc/[0-9]*; do
            [ "$(proc_ppid "${d#/proc/}")" = "$1" ] && { echo "${d#/proc/}"; return 0; }
        done
        wc_now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$wc_now" -ge "$wc_end" ] && break
        sleep 0.05 2>/dev/null || sleep 1
    done
    return 1
}

# comm_count LABEL -> processes whose comm is exactly LABEL
comm_count() {
    cc_n=0
    for d in /proc/[0-9]*; do
        [ "${d#/proc/}" = "$$" ] && continue
        [ "$(cat "$d/comm" 2>/dev/null)" = "$1" ] && cc_n=$((cc_n + 1))
    done
    echo "$cc_n"
}

# -------------------------------------------------- q47a: traced by default
L="$BASE-a"
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$L" -- "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
sleep 0.3
if [ -n "$PAY" ]; then
    TP=$(status_field "$PAY" TracerPid)
    if [ -n "$TP" ] && [ "$TP" != 0 ]; then
        pass "q47a-control-default-is-traced (TracerPid=$TP)"
    else
        fail "q47a-control-default-is-traced (payload TracerPid=[$TP], want non-zero)"
    fi
else
    fail "q47a-control-default-is-traced (no payload)"
fi
kill -9 "$SUP" 2>/dev/null; wait "$SUP" 2>/dev/null; SUP=""
PAY=""
kill_label "$L" 2>/dev/null

# ------------------------------------------------- q47b: --detach end state
L="$BASE-b"
env -i PATH=/usr/bin:/bin "$TOOL" --detach -l "$L" -- "$CASES" sleeper \
    >/dev/null 2>"$T/det.err" &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
if [ -n "$PAY" ]; then
    sleep 0.5
    TP=$(status_field "$PAY" TracerPid)
    PC=$(tr '\0' '|' < "/proc/$PAY/cmdline" 2>/dev/null)
    PB=$(wc -c < "/proc/$PAY/environ" 2>/dev/null | tr -d ' ')
    PS=$(status_field "$PAY" State)
    [ "$TP" = 0 ] && pass "q47b-detach-tracerpid-is-0" \
        || fail "q47b-detach-tracerpid-is-0 (TracerPid=[$TP])"
    [ "$PC" = "$L|" ] && pass "q47b2-detach-keeps-the-label ($PC)" \
        || fail "q47b2-detach-keeps-the-label (cmdline=[$PC] want [$L|])"
    [ "${PB:-1}" = 0 ] && pass "q47b3-detach-environ-is-empty" \
        || fail "q47b3-detach-environ-is-empty (bytes=[${PB:-unreadable}])"
    case "$PS" in
        R*|S*|D*) pass "q47b4-detach-payload-is-alive (state=$PS)" ;;
        *) fail "q47b4-detach-payload-is-alive (state=[${PS:-gone}])" ;;
    esac
else
    fail "q47b-detach-tracerpid-is-0 (no payload)"
    fail "q47b2-detach-keeps-the-label (no payload)"
    fail "q47b3-detach-environ-is-empty (no payload)"
    fail "q47b4-detach-payload-is-alive (no payload)"
fi

# ------------------------------------- q47c: the release warning is printed
kill -9 "$SUP" 2>/dev/null; wait "$SUP" 2>/dev/null; SUP=""
PAY=""
kill_label "$L" 2>/dev/null
if grep -q "warning: --detach: pid [0-9]* is released untraced, so its later execs are not redacted" \
    "$T/det.err"; then
    pass "q47c-detach-names-the-release-and-its-coverage-gap"
else
    fail "q47c-detach-names-the-release-and-its-coverage-gap (err=[$(cat "$T/det.err")])"
fi
n=$(grep -c "released untraced" "$T/det.err")
[ "$n" = 1 ] && pass "q47c2-detach-warning-is-one-line (n=$n)" \
    || fail "q47c2-detach-warning-is-one-line (n=$n, want 1)"

env -i PATH=/usr/bin:/bin "$TOOL" -q --detach -l "$L" -- /bin/true \
    >/dev/null 2>"$T/detq.err"
if [ -s "$T/detq.err" ]; then
    fail "q47c3-quiet-suppresses-the-detach-warning (err=[$(cat "$T/detq.err")])"
else
    pass "q47c3-quiet-suppresses-the-detach-warning"
fi

# ------------------------------------------------ q47d: --no-follow shape
L="$BASE-d"
"$TOOL" -q --no-follow -l "$L" /bin/sh -c \
    "$CASES sleeper $L-GRANDCHILD & wait" >/dev/null 2>&1 &
SUP=$!
DIRECT=""
GC=""
end=$(( $(date +%s 2>/dev/null || echo 0) + 10 ))
while :; do
    DIRECT=$(wait_child "$SUP" 1) || DIRECT=""
    if [ -n "$DIRECT" ]; then
        GC=$(wait_child "$DIRECT" 1) || GC=""
    fi
    [ -n "$GC" ] && break
    now=$(date +%s 2>/dev/null || echo 99999999999)
    [ "$now" -ge "$end" ] && break
    sleep 0.1 2>/dev/null || sleep 1
done
if [ -n "$GC" ]; then
    DTP=$(status_field "$DIRECT" TracerPid)
    # The grandchild is expected to keep the real argv; the label is the
    # control that the direct child does not.
    case "$(tr '\0' ' ' < "/proc/$DIRECT/cmdline" 2>/dev/null)" in
        *"$L-GRANDCHILD"*)
            fail "q47d-no-follow-direct-child-redacted (direct argv still real)" ;;
        *)
            pass "q47d-no-follow-direct-child-redacted (TracerPid=${DTP:-?})" ;;
    esac
    case "$(tr '\0' ' ' < "/proc/$GC/cmdline" 2>/dev/null)" in
        *"$L-GRANDCHILD"*)
            pass "q47d2-no-follow-grandchild-keeps-real-argv" ;;
        *)
            fail "q47d2-no-follow-grandchild-keeps-real-argv (argv was redacted)" ;;
    esac
    # Liveness: the grandchild runs, and the deep tree still works after
    # 1 s (it is not a corpse the tracer is holding).
    sleep 1
    case "$(status_field "$GC" State)" in
        R*|S*|D*) pass "q47d3-no-follow-grandchild-still-works" ;;
        *) fail "q47d3-no-follow-grandchild-still-works (state=[$(status_field "$GC" State)])" ;;
    esac
else
    fail "q47d-no-follow-direct-child-redacted (no grandchild within 10 s)"
    fail "q47d2-no-follow-grandchild-keeps-real-argv (no grandchild)"
    fail "q47d3-no-follow-grandchild-still-works (no grandchild)"
fi
kill -9 "$SUP" 2>/dev/null; wait "$SUP" 2>/dev/null; SUP=""
DIRECT=""; GC=""
kill_label "$L" 2>/dev/null

# ------------------------------------------- q47e: --on-exit detach orphan
L="$BASE-e"
env -i PATH=/usr/bin:/bin "$TOOL" -q --on-exit detach -l "$L" /bin/sh -c \
    "$CASES sleeper $L-ORPHAN </dev/null >/dev/null 2>&1 & exit 0" \
    >/dev/null 2>&1
sleep 0.5
ORPH=""
for d in /proc/[0-9]*; do
    [ "$(cat "$d/comm" 2>/dev/null)" = "$L" ] || continue
    ORPH=${d#/proc/}
    break
done
if [ -n "$ORPH" ]; then
    OPP=$(proc_ppid "$ORPH")
    OTP=$(status_field "$ORPH" TracerPid)
    [ "$OPP" = 1 ] && pass "q47e-on-exit-detach-leaves-a-reparented-orphan (ppid=$OPP)" \
        || fail "q47e-on-exit-detach-leaves-a-reparented-orphan (ppid=[$OPP])"
    [ "$OTP" = 0 ] && pass "q47e2-on-exit-detach-orphan-is-untraced" \
        || fail "q47e2-on-exit-detach-orphan-is-untraced (TracerPid=[$OTP])"
else
    fail "q47e-on-exit-detach-leaves-a-reparented-orphan (no labelled process)"
    fail "q47e2-on-exit-detach-orphan-is-untraced (no labelled process)"
fi
kill_label "$L" 2>/dev/null

# ------------------------------------------------ q47f: --on-exit kill
L="$BASE-f"
env -i PATH=/usr/bin:/bin "$TOOL" -q --on-exit kill -l "$L" /bin/sh -c \
    "$CASES sleeper $L-VICTIM </dev/null >/dev/null 2>&1 & exit 0" \
    >/dev/null 2>&1
n=1
w=0
while [ "$w" -lt 30 ]; do
    n=$(comm_count "$L")
    [ "$n" = 0 ] && break
    w=$((w + 1))
    sleep 0.1 2>/dev/null || sleep 1
done
[ "$n" = 0 ] && pass "q47f-on-exit-kill-leaves-no-labelled-process" \
    || fail "q47f-on-exit-kill-leaves-no-labelled-process (alive=$n)"
kill_label "$L" 2>/dev/null

# ---------------------------------------------- q47g: --no-exit-kill
L="$BASE-g"
env -i PATH=/usr/bin:/bin "$TOOL" -q --no-exit-kill -l "$L" -- "$CASES" sleeper \
    >/dev/null 2>&1 &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
if [ -n "$PAY" ]; then
    kill -9 "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
    SUP=""
    sleep 0.5
    PS=$(status_field "$PAY" State)
    case "$PS" in
        R*|S*|D*) pass "q47g-no-exit-kill-payload-survives-the-supervisor (state=$PS)" ;;
        *) fail "q47g-no-exit-kill-payload-survives-the-supervisor (state=[${PS:-gone}])" ;;
    esac
    TP=$(status_field "$PAY" TracerPid)
    [ "$TP" = 0 ] && pass "q47g2-no-exit-kill-payload-is-untraced" \
        || fail "q47g2-no-exit-kill-payload-is-untraced (TracerPid=[$TP])"
else
    fail "q47g-no-exit-kill-payload-survives-the-supervisor (no payload)"
    fail "q47g2-no-exit-kill-payload-is-untraced (no payload)"
fi
PAY=""
kill_label "$L" 2>/dev/null

# ------------------------------------- q47h: default exit-kill (control)
L="$BASE-h"
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$L" -- "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
if [ -n "$PAY" ]; then
    kill -9 "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
    SUP=""
    gone=0
    w=0
    while [ "$w" -lt 20 ]; do
        case "$(status_field "$PAY" State)" in
            ""|Z*) gone=1; break ;;
        esac
        w=$((w + 1))
        sleep 0.1 2>/dev/null || sleep 1
    done
    [ "$gone" = 1 ] && pass "q47h-control-default-exit-kill-takes-the-payload" \
        || fail "q47h-control-default-exit-kill-takes-the-payload (still alive)"
else
    fail "q47h-control-default-exit-kill-takes-the-payload (no payload)"
fi
PAY=""
kill_label "$L" 2>/dev/null

echo "################ qa47: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
