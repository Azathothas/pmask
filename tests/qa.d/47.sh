#!/bin/sh
# Issue 47: the documented end states, one case per shape.
#
#   q47a  control: default mode reports TracerPid != 0 (so a 0 below is
#         the flag, not a blind observer)
#   q47b  --detach: TracerPid 0, the label is kept, /proc/<pid>/environ
#         is empty, and the payload is alive
#   q47c  --detach names the release at the point it happens, and --quiet
#         still prints nothing (invariant 13 with the -q opt-out)
#   q47d  --no-follow: the direct child carries the label, the grandchild
#         keeps its real argv (the coverage the flag trades), and the
#         grandchild is still traced
#   q47e  --on-exit detach: a labelled orphan with ppid 1 and TracerPid 0
#   q47f  --on-exit kill: no process carrying the label survives
#   q47g  --no-exit-kill: the payload survives SIGKILL to the supervisor
#   q47h  control: default exit-kill takes the payload with the supervisor
#
# Nothing here changes the default: each shape is asserted as documented.
# Every label is at most 15 bytes, so `comm` is exactly the label and a
# comparison against it cannot be satisfied by a truncated prefix.
set -u
here=$(dirname "$0")
cd "$here/.." || { echo "FATAL: cannot enter tests/"; exit 2; }
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

# 4 digits of the pid keep the labels unique to this run and short enough
# for the 15-byte comm field with a two-character suffix appended.
SHORT=$(printf '%s' "$$" | tail -c 5)
BASE="b2q47-$SHORT"
SUP=""
PAY=""
CLIENT=""
ORPH=""
FAIL=0

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    [ -n "${SUP:-}" ] && kill -9 "$SUP" 2>/dev/null
    [ -n "${PAY:-}" ] && kill -9 "$PAY" 2>/dev/null
    [ -n "${CLIENT:-}" ] && kill -9 "$CLIENT" 2>/dev/null
    [ -n "${ORPH:-}" ] && kill -9 "$ORPH" 2>/dev/null
    # Every label of this run shares BASE, and the label-scoped sweep is
    # exhaustive for them: an abnormal exit must not leave a labelled
    # orphan for a later sweep in the gate to attribute to another case.
    kill_label "$BASE" 2>/dev/null
}
trap cleanup EXIT INT TERM HUP QUIT

status_field() {
    sed -n "s/^$2:[[:space:]]*\(.*\)$/\1/p" "/proc/$1/status" 2>/dev/null
}

# wait_child PID SECONDS -> first child of PID
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

# wait_state PID SECONDS -> true once PID is running (not a zombie, or
# gone)
wait_running() {
    wr_end=$(( $(date +%s 2>/dev/null || echo 0) + $2 ))
    while :; do
        wr_st=$(status_field "$1" State)
        case "$wr_st" in
            R*|S*|D*) return 0 ;;
            "") return 1 ;;
        esac
        wr_now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$wr_now" -ge "$wr_end" ] && return 1
        sleep 0.05 2>/dev/null || sleep 1
    done
}

# wait_gone PID SECONDS -> true when the pid is gone or a zombie
wait_gone() {
    wg_end=$(( $(date +%s 2>/dev/null || echo 0) + $2 ))
    while :; do
        wg_st=$(status_field "$1" State)
        case "$wg_st" in
            ""|Z*) return 0 ;;
        esac
        wg_now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$wg_now" -ge "$wg_end" ] && return 1
        sleep 0.05 2>/dev/null || sleep 1
    done
}

# in_session PID SUP -> true when PID is SUP or descends from it
in_session() {
    is_p="$1"; is_d=0
    while [ "$is_d" -lt 16 ]; do
        [ "$is_p" = "$2" ] && return 0
        is_pp=$(proc_ppid "$is_p")
        [ -n "$is_pp" ] || return 1
        [ "$is_pp" -le 1 ] && return 1
        is_p="$is_pp"
        is_d=$((is_d + 1))
    done
    return 1
}

# comm_count LABEL -> processes whose comm is exactly LABEL, excluding
# this shell.  A process reparented to init is included: the orphan shape
# is one of the end states under test.
comm_count() {
    cc_n=0
    for d in /proc/[0-9]*; do
        [ "${d#/proc/}" = "$$" ] && continue
        [ "$(cat "$d/comm" 2>/dev/null)" = "$1" ] && cc_n=$((cc_n + 1))
    done
    echo "$cc_n"
}

# ------------------------------------------------- q47a: traced by default
L="$BASE-a"
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$L" -- "$CASES" sleeper &
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
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
PAY=""
kill_label "$L" 2>/dev/null

# ------------------------------------------------ q47b: --detach end state
L="$BASE-b"
DET_ERR="${TMPDIR:-/tmp}/b2q47-det.$$"
env -i PATH=/usr/bin:/bin "$TOOL" -q --detach -l "$L" -- "$CASES" sleeper \
    >/dev/null 2>"$DET_ERR" &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
if [ -n "$PAY" ]; then
    wait_running "$PAY" 5
    TP=$(status_field "$PAY" TracerPid)
    PC=$(tr '\0' '|' < "/proc/$PAY/cmdline" 2>/dev/null)
    PB=$(wc -c < "/proc/$PAY/environ" 2>/dev/null | tr -d ' ')
    PS=$(status_field "$PAY" State)
    if [ "$TP" = 0 ]; then
        pass "q47b-detach-tracerpid-is-0 (TracerPid=0)"
    else
        fail "q47b-detach-tracerpid-is-0 (TracerPid=[$TP])"
    fi
    if [ "$PC" = "$L|" ]; then
        pass "q47b2-detach-keeps-the-label (cmdline=[$PC])"
    else
        fail "q47b2-detach-keeps-the-label (cmdline=[$PC] want [$L|])"
    fi
    if [ "${PB:-1}" = 0 ]; then
        pass "q47b3-detach-environ-is-empty (bytes=0)"
    else
        fail "q47b3-detach-environ-is-empty (bytes=[${PB:-unreadable}])"
    fi
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
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
PAY=""
kill_label "$L" 2>/dev/null

# --------------------- q47c: the release is named where it happens
# A detached process's later exec is not redacted and nothing watches for
# it; that is the one gap left in this shape (issue 47).  The warning must
# name the release, sit at the default verbosity, and disappear under
# --quiet.
WERR="${TMPDIR:-/tmp}/b2q47-warn.$$"
WQ="${TMPDIR:-/tmp}/b2q47-warnq.$$"
WN="${TMPDIR:-/tmp}/b2q47-nowarn.$$"
env -i PATH=/usr/bin:/bin "$TOOL" -l "$BASE-w" --detach -- /bin/true \
    >/dev/null 2>"$WERR"
rc=$?
if [ "$rc" = 0 ] && grep -q -- '--detach released pid' "$WERR"; then
    pass "q47c-detach-release-is-named ($(grep -m1 -- '--detach released pid' "$WERR" | cut -c1-70))"
else
    fail "q47c-detach-release-is-named (exit=$rc stderr=$(tr '\n' '|' < "$WERR" | cut -c1-120))"
fi
grep -q 'a later exec in that process is not redacted' "$WERR" \
    && pass "q47c2-release-warning-names-the-consequence" \
    || fail "q47c2-release-warning-names-the-consequence ($(tr '\n' '|' < "$WERR" | cut -c1-120))"
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$BASE-q" --detach -- /bin/true \
    >/dev/null 2>"$WQ"
[ ! -s "$WQ" ] && pass "q47c3-quiet-suppresses-the-release-warning" \
    || fail "q47c3-quiet-suppresses-the-release-warning ($(tr '\n' '|' < "$WQ" | cut -c1-120))"
env -i PATH=/usr/bin:/bin "$TOOL" -l "$BASE-n" -- /bin/true \
    >/dev/null 2>"$WN"
grep -q -- '--detach released pid' "$WN" \
    && fail "q47c4-control-default-mode-has-no-release-warning ($(tr '\n' '|' < "$WN" | cut -c1-120))" \
    || pass "q47c4-control-default-mode-has-no-release-warning"
rm -f "$WERR" "$WQ" "$WN" "$DET_ERR"

# --------------------------------------------- q47d: --no-follow coverage
# The direct child is redacted; the grandchild keeps its real argv.  Both
# stay traced.  That is exactly the coverage the flag gives up.
L="$BASE-d"
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$L" --no-follow \
    -- /bin/sh -c '/bin/sleep 5 & wait' >/dev/null 2>&1 &
SUP=$!
sleep 1
CHILD=""
GRAND=""
for d in /proc/[0-9]*; do
    p=${d#/proc/}
    [ "$p" = "$SUP" ] && continue
    in_session "$p" "$SUP" || continue
    c=$(cat "$d/comm" 2>/dev/null)
    case "$c" in
        "$L") [ -z "$CHILD" ] && CHILD=$p ;;
        sleep) [ -z "$GRAND" ] && GRAND=$p ;;
    esac
done
if [ -n "$CHILD" ]; then
    CC=$(tr '\0' '|' < "/proc/$CHILD/cmdline" 2>/dev/null)
    if [ "$CC" = "$L|" ]; then
        pass "q47d-nofollow-direct-child-is-labelled (cmdline=[$CC])"
    else
        fail "q47d-nofollow-direct-child-is-labelled (cmdline=[$CC] want [$L|])"
    fi
else
    fail "q47d-nofollow-direct-child-is-labelled (no labelled child under $SUP)"
fi
if [ -n "$GRAND" ]; then
    GC=$(tr '\0' '|' < "/proc/$GRAND/cmdline" 2>/dev/null)
    case "$GC" in
        *"/bin/sleep|5|"|*"sleep|5|")
            pass "q47d2-nofollow-grandchild-keeps-real-argv (cmdline=[$GC])" ;;
        *)
            fail "q47d2-nofollow-grandchild-keeps-real-argv (cmdline=[$GC])" ;;
    esac
    GTP=$(status_field "$GRAND" TracerPid)
    if [ -n "$GTP" ] && [ "$GTP" != 0 ]; then
        pass "q47d3-nofollow-grandchild-is-still-traced (TracerPid=$GTP)"
    else
        fail "q47d3-nofollow-grandchild-is-still-traced (TracerPid=[$GTP])"
    fi
else
    fail "q47d2-nofollow-grandchild-keeps-real-argv (no grandchild under $SUP)"
    fail "q47d3-nofollow-grandchild-is-still-traced (no grandchild)"
fi
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
kill_label "$L" 2>/dev/null

# ------------------------------------------- q47e: --on-exit detach orphan
# The orphan is the payload of a session whose master has exited; it is
# reparented to init and keeps the label.  The label is unique to this
# run, so the sweep cannot match a neighbour's process.
L="$BASE-e"
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$L" --on-exit detach \
    -- /bin/sh -c '/bin/sleep 5 & exit 0' >/dev/null 2>&1
rc=$?
ORPH=""
i=0
while [ "$i" -lt 40 ]; do
    for d in /proc/[0-9]*; do
        [ "$(cat "$d/comm" 2>/dev/null)" = "$L" ] && { ORPH=${d#/proc/}; break; }
    done
    [ -n "$ORPH" ] && break
    sleep 0.05 2>/dev/null || sleep 1
    i=$((i + 1))
done
if [ "$rc" = 0 ] && [ -n "$ORPH" ]; then
    OPP=$(proc_ppid "$ORPH")
    OTP=$(status_field "$ORPH" TracerPid)
    OC=$(tr '\0' '|' < "/proc/$ORPH/cmdline" 2>/dev/null)
    [ "$OPP" = 1 ] && pass "q47e-orphan-is-reparented-to-init (ppid=$OPP)" \
        || fail "q47e-orphan-is-reparented-to-init (ppid=[$OPP])"
    [ "$OTP" = 0 ] && pass "q47e2-orphan-tracerpid-is-0 (TracerPid=0)" \
        || fail "q47e2-orphan-tracerpid-is-0 (TracerPid=[$OTP])"
    [ "$OC" = "$L|" ] && pass "q47e3-orphan-keeps-the-label (cmdline=[$OC])" \
        || fail "q47e3-orphan-keeps-the-label (cmdline=[$OC])"
    kill -9 "$ORPH" 2>/dev/null
else
    fail "q47e-orphan-is-reparented-to-init (exit=$rc orphan=[${ORPH:-none}])"
    fail "q47e2-orphan-tracerpid-is-0 (no orphan)"
    fail "q47e3-orphan-keeps-the-label (no orphan)"
fi
kill_label "$L" 2>/dev/null

# --------------------------------------------- q47f: --on-exit kill
L="$BASE-k"
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$L" --on-exit kill \
    -- /bin/sh -c '/bin/sleep 5 & exit 0' >/dev/null 2>&1
sleep 0.5
n=$(comm_count "$L")
if [ "$n" = 0 ]; then
    pass "q47f-onexit-kill-leaves-nothing (survivors=0)"
else
    fail "q47f-onexit-kill-leaves-nothing (survivors=$n)"
    kill_label "$L" 2>/dev/null
fi

# ------------------------------------------ q47g/h: --no-exit-kill
L="$BASE-s"
env -i PATH=/usr/bin:/bin "$TOOL" -q --no-exit-kill -l "$L" \
    -- "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
if [ -z "$PAY" ]; then
    fail "q47g-no-exit-kill-payload-survives (no payload)"
else
    kill -9 "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
    SUP=""
    sleep 0.3
    PS=$(status_field "$PAY" State)
    case "$PS" in
        R*|S*|D*)
            STP=$(status_field "$PAY" TracerPid)
            SC=$(tr '\0' '|' < "/proc/$PAY/cmdline" 2>/dev/null)
            pass "q47g-no-exit-kill-payload-survives (state=$PS TracerPid=$STP cmdline=[$SC])" ;;
        *)
            fail "q47g-no-exit-kill-payload-survives (state=[${PS:-gone}])" ;;
    esac
    kill -9 "$PAY" 2>/dev/null
    PAY=""
fi
kill_label "$L" 2>/dev/null

# Control: the default (PTRACE_O_EXITKILL) takes the payload with the
# supervisor.  Without this pair the survival above could be vacuous.
L="$BASE-x"
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$L" -- "$CASES" sleeper \
    >/dev/null 2>&1 &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
if [ -z "$PAY" ]; then
    skip "q47h-control-default-exit-kill-takes-the-tree (no payload)"
else
    kill -9 "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
    SUP=""
    if wait_gone "$PAY" 3; then
        pass "q47h-control-default-exit-kill-takes-the-tree (pid $PAY gone)"
    else
        PS=$(status_field "$PAY" State)
        fail "q47h-control-default-exit-kill-takes-the-tree (pid $PAY still $PS)"
        kill -9 "$PAY" 2>/dev/null
    fi
    PAY=""
fi
kill_label "$BASE" 2>/dev/null

echo "== VERDICT: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL) failures=$FAIL =="
[ "$FAIL" = 0 ]
