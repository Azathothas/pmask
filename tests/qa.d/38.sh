#!/bin/sh
# Issue 38: the tracer thread is named after the session, not "pmask-tracer".
#
#   q38a  negative control: a task really carrying "pmask-tracer" IS found
#         by the sweep, so a zero count below means the name is gone and
#         not that the observer is blind
#   q38b  a default masked payload runs, and its tracer is a *thread*:
#         Tgid != Pid on it, and its tid is absent from readdir("/proc").
#         That pair is the residual, asserted so a later change cannot
#         claim it is gone
#   q38c  no task of this session carries "pmask-tracer", and no
#         non-leader task of it does
#   q38d  the tracer task comm equals the session label
#   q38e  the payload is alive and its /proc cmdline is still the label
#   q38f  an empty label falls back to the supervisor's own comm
#   q38g  a session labelled with the retired string still leaves no
#         non-leader task carrying it
#   q38h  a long label is cut to the kernel's 15-byte comm limit
#   q38i  the daemon path: a pmaskd job's tracer thread carries the job
#         label, and leaves no fingerprint in that session
#   q38j  the runner path (--secret) creates the thread before the
#         self-mask, so the fallback must use the session comm, not the
#         live pre-mask one
#   q38k  an explicit --comm names the thread, and it agrees with the
#         supervisor's comm
#
# The observer is /proc only: no ptrace of our own, no privilege.  The
# sweeps are scoped to this fragment's own processes, because another run
# on the same host (a neighbour agent's unreleased build, say) is a
# different session and would make a host-wide assertion fail for the
# wrong reason; the host-wide count is printed beside each in-session
# count so a reader can see the difference.
set -u
# `lib.sh` derives BIN_DIR from the cwd and the dispatcher may start this
# fragment from `tests` or from `tests/qa.d`.  Anchor on $0 so both work.
here=$(dirname "$0")
cd "$here/.." || { echo "FATAL: cannot enter tests/"; exit 2; }
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

RETIRED=pmask-tracer
LABEL="b2q38-$$"
LONG="b2q38-abcdefghijklmnopqrstuvwxyz-$$"
JOB_LABEL="b2q38job-$$"
DPID=""
CLIENT=""
SOCKDIR=""
SOCK=""
SUP=""
PAY=""
FAIL=0

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    [ -n "${SUP:-}" ] && kill -9 "$SUP" 2>/dev/null
    [ -n "${PAY:-}" ] && kill -9 "$PAY" 2>/dev/null
    [ -n "${DPID:-}" ] && kill -9 "$DPID" 2>/dev/null
    [ -n "${CLIENT:-}" ] && kill -9 "$CLIENT" 2>/dev/null
    [ -n "${SOCKDIR:-}" ] && rm -rf "$SOCKDIR"
    [ -n "${TOK:-}" ] && rm -f "$TOK" 2>/dev/null
    # Every label this fragment uses, so an abnormal exit cannot leave a
    # parked sleeper behind for a later sweep in the gate to attribute to
    # a different case.
    kill_label "$LABEL" 2>/dev/null
    kill_label "$LONG" 2>/dev/null
    kill_label "$JOB_LABEL" 2>/dev/null
    kill_label "b2q38k-$$" 2>/dev/null
    kill_label "b2q38d-$$" 2>/dev/null
    kill_label "b2q38kc-" 2>/dev/null
    kill_label "$RETIRED" 2>/dev/null
}
trap cleanup EXIT INT TERM HUP QUIT

# status_field PID FIELD -> the value, empty when the process is gone
status_field() {
    sed -n "s/^$2:[[:space:]]*\(.*\)$/\1/p" "/proc/$1/status" 2>/dev/null
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

# retired_count SUP THREADS_ONLY
# Tasks whose comm is the retired name.  SUP empty counts the whole host.
# THREADS_ONLY=1 skips thread-group leaders, which leaves exactly the
# tracer-thread fingerprint this issue is about (an operator may label a
# session with any string, including this one, and that lands on a
# leader).
retired_count() {
    rc_n=0
    for t in /proc/[0-9]*/task/*/comm; do
        [ "$(cat "$t" 2>/dev/null)" = "$RETIRED" ] || continue
        rc_tid=$(basename "$(dirname "$t")")
        rc_tgid=$(basename "$(dirname "$(dirname "$(dirname "$t")")")")
        if [ "$2" = 1 ] && [ "$rc_tid" = "$rc_tgid" ]; then
            continue
        fi
        if [ -n "$1" ] && ! in_session "$rc_tgid" "$1"; then
            continue
        fi
        rc_n=$((rc_n + 1))
    done
    echo "$rc_n"
}

# wait_child PID SECONDS -> the first child of PID
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

# alive PID -> true when the process is not gone and not a zombie
alive() {
    al_st=$(status_field "$1" State)
    case "$al_st" in
        Z*|"") return 1 ;;
    esac
    return 0
}

# ------------------------------------------------- q38a: negative control
# A task that really carries the retired name must be visible to this
# observer.  `sh -c` sets its own comm through procfs, the same path the
# old tracer thread used.
sh -c "echo $RETIRED > /proc/self/comm; sleep 3" &
CTL=$!
sleep 0.4
ctl_n=$(retired_count "" 0)
kill -9 "$CTL" 2>/dev/null
wait "$CTL" 2>/dev/null
if [ "$ctl_n" -ge 1 ]; then
    pass "q38a-control-retired-name-is-observable (sightings=$ctl_n)"
else
    skip "q38a-control-retired-name-is-observable (no task could take the name here)"
fi

# The control above proves the observer can see a task named with the
# retired string.  A stronger control is a binary built before #38: it
# names the thread `pmask-tracer`, so the same observer must find it.
# That binary is not built by the gate (it needs a source checkout at the
# parent commit), so when it is present the control runs; otherwise the
# evidence log from the last run of it is cited instead of claimed.
OLD_BIN="$(cd .. && pwd)/evidence/bteam2/38/negative-control-old-binary.sh"
T38="/tmp/qa38.$$"
mkdir -p "$T38" || { echo "FATAL: cannot create $T38"; exit 2; }
trap 'rm -rf "$T38"' EXIT INT TERM HUP QUIT
if [ -x "$OLD_BIN" ]; then
    if sh "$OLD_BIN" >"$T38/old.log" 2>&1; then
        pass "q38a2-pre-fix-binary-names-the-thread (control for the sweep)"
    else
        skip "q38a2-pre-fix-binary-names-the-thread (evidence script needs a parent-commit build: $(tail -1 "$T38/old.log"))"
    fi
else
    skip "q38a2-pre-fix-binary-names-the-thread (no pre-fix build here; evidence/bteam2/38/negative-control-old-binary.log)"
fi

# ---------------------------------------- q38b..q38e: the default session
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$LABEL" -- "$CASES" sleeper &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
if [ -z "$PAY" ]; then
    fail "q38b-no-payload (supervisor $SUP never forked a child)"
    echo "== VERDICT: FAIL failures=$FAIL =="
    exit 1
fi
# The first exec settles in milliseconds on this host; the VM under TCG is
# slower.  A short settle keeps the sample after the exec.
SL=0.3
[ "$VM_TCG" = 1 ] && SL=1.5
sleep "$SL"

TP=$(status_field "$PAY" TracerPid)
TRACER=""
if [ -n "$TP" ] && [ "$TP" != 0 ] && [ -d "/proc/$TP" ]; then
    TRACER=$TP
fi

if [ -n "$TRACER" ]; then
    TR_TGID=$(status_field "$TRACER" Tgid)
    TR_PID=$(status_field "$TRACER" Pid)
    if [ -n "$TR_TGID" ] && [ -n "$TR_PID" ] && [ "$TR_TGID" != "$TR_PID" ]; then
        pass "q38b-tracer-is-a-thread (TracerPid=$TRACER Pid=$TR_PID Tgid=$TR_TGID)"
    else
        fail "q38b-tracer-is-a-thread (TracerPid=$TRACER Pid=${TR_PID:-none} Tgid=${TR_TGID:-none}, want Tgid != Pid)"
    fi
    # The residual: the tracer id is a task id, not a process id, so it
    # has no row of its own in readdir("/proc") (and none in `ps`, which
    # reads that listing).  Asserted, not asserted away.
    listed=0
    for d in /proc/[0-9]*; do
        [ "${d#/proc/}" = "$TRACER" ] && listed=1
    done
    if [ "$listed" = 0 ]; then
        pass "q38b2-tracer-tid-is-not-a-process (TracerPid=$TRACER absent from readdir /proc)"
    else
        fail "q38b2-tracer-tid-is-not-a-process (TracerPid=$TRACER IS in readdir /proc)"
    fi

    h=$(retired_count "" 0)
    n=$(retired_count "$SUP" 0)
    if [ "$n" = 0 ]; then
        pass "q38c-no-task-comm-is-the-retired-name (in-session=0 host-wide=$h)"
    else
        fail "q38c-no-task-comm-is-the-retired-name (in-session=$n host-wide=$h)"
    fi
    h=$(retired_count "" 1)
    n=$(retired_count "$SUP" 1)
    if [ "$n" = 0 ]; then
        pass "q38c2-no-non-leader-task-carries-the-retired-name (in-session=0 host-wide=$h)"
    else
        fail "q38c2-no-non-leader-task-carries-the-retired-name (in-session=$n host-wide=$h)"
    fi

    TR_COMM=$(cat "/proc/$TRACER/comm" 2>/dev/null | tr -d '\n')
    WANT=$(printf '%s' "$LABEL" | cut -c1-15)
    if [ "$TR_COMM" = "$WANT" ]; then
        pass "q38d-tracer-comm-is-the-label (comm=[$TR_COMM])"
    else
        fail "q38d-tracer-comm-is-the-label (comm=[$TR_COMM] want [$WANT])"
    fi
    if [ -n "$TR_COMM" ] && [ "$TR_COMM" != "$RETIRED" ]; then
        pass "q38d2-tracer-comm-is-not-the-retired-name (comm=[$TR_COMM])"
    else
        fail "q38d2-tracer-comm-is-not-the-retired-name (comm=[$TR_COMM])"
    fi
else
    fail "q38b-tracer-is-a-thread (payload $PAY reports TracerPid=[$TP], no tracer task)"
    fail "q38b2-tracer-tid-is-not-a-process (not decided: no tracer)"
    fail "q38c-no-task-comm-is-the-retired-name (not decided: no tracer)"
    fail "q38c2-no-non-leader-task-carries-the-retired-name (not decided: no tracer)"
    fail "q38d-tracer-comm-is-the-label (not decided: no tracer)"
    fail "q38d2-tracer-comm-is-not-the-retired-name (not decided: no tracer)"
fi

# Liveness: the payload runs and still serves the label.  Without this the
# zero-sighting results above would be satisfied by a dead session.
if alive "$PAY"; then
    PC=$(tr '\0' '|' < "/proc/$PAY/cmdline" 2>/dev/null)
    if [ "$PC" = "$LABEL|" ]; then
        pass "q38e-payload-alive-with-the-label (cmdline=[$PC])"
    else
        fail "q38e-payload-alive-with-the-label (cmdline=[$PC] want [$LABEL|])"
    fi
else
    fail "q38e-payload-alive-with-the-label (pid $PAY is not running)"
fi
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
PAY=""

# --------------------------------------- q38f: the empty-label fallback
env -i PATH=/usr/bin:/bin "$TOOL" -q --label-empty -- "$CASES" sleeper &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
sleep "$SL"
if [ -n "$PAY" ]; then
    TP=$(status_field "$PAY" TracerPid)
    TR_COMM=$(cat "/proc/$TP/comm" 2>/dev/null | tr -d '\n')
    SUP_COMM=$(cat "/proc/$SUP/comm" 2>/dev/null | tr -d '\n')
    if [ -n "$TR_COMM" ] && [ "$TR_COMM" = "$SUP_COMM" ]; then
        pass "q38f-empty-label-falls-back-to-supervisor-comm (comm=[$TR_COMM])"
    else
        fail "q38f-empty-label-falls-back-to-supervisor-comm (tracer=[$TR_COMM] supervisor=[$SUP_COMM])"
    fi
    # The fallback is the *thread's* name.  The payload keeps the blank
    # label, so the blank supervisor comm is not the payload's.
    PC=$(tr '\0' '|' < "/proc/$PAY/cmdline" 2>/dev/null)
    [ "$PC" = "|" ] && pass "q38f2-empty-label-payload-cmdline-blank (cmdline=[$PC])" \
        || fail "q38f2-empty-label-payload-cmdline-blank (cmdline=[$PC])"
else
    fail "q38f-empty-label-falls-back-to-supervisor-comm (no payload)"
    fail "q38f2-empty-label-payload-cmdline-blank (no payload)"
fi
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
PAY=""

# ---------------------------------------- q38g: a label naming the old one
# An operator may label a session with the retired string.  The label then
# lands on the leader comms by the operator's own choice; the thread must
# not add a second, non-leader carrier of it.
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$RETIRED" -- "$CASES" sleeper &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
sleep "$SL"
if [ -n "$PAY" ]; then
    TP=$(status_field "$PAY" TracerPid)
    TR_COMM=$(cat "/proc/$TP/comm" 2>/dev/null | tr -d '\n')
    TR_LEN=$(printf '%s' "$TR_COMM" | wc -c | tr -d ' ')
    if [ -z "$TR_COMM" ]; then
        fail "q38g-retired-label-yields-a-usable-thread-name (empty comm)"
    elif [ "$TR_COMM" = "$RETIRED" ]; then
        fail "q38g-retired-label-yields-a-usable-thread-name (comm=[$TR_COMM])"
    elif [ "$TR_LEN" -gt 15 ]; then
        fail "q38g-retired-label-yields-a-usable-thread-name (comm=[$TR_COMM] $TR_LEN bytes)"
    else
        pass "q38g-retired-label-yields-a-usable-thread-name (comm=[$TR_COMM])"
    fi
    h=$(retired_count "" 1)
    n=$(retired_count "$SUP" 1)
    if [ "$n" = 0 ]; then
        pass "q38g2-retired-label-leaves-no-thread-fingerprint (in-session=0 host-wide=$h)"
    else
        fail "q38g2-retired-label-leaves-no-thread-fingerprint (in-session=$n host-wide=$h)"
    fi
else
    fail "q38g-retired-label-yields-a-usable-thread-name (no payload)"
    fail "q38g2-retired-label-leaves-no-thread-fingerprint (no payload)"
fi
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
PAY=""

# ------------------------------- q38h: a long label and the 15-byte limit
# A thread name longer than 15 bytes is refused whole by the kernel, so
# the thread would silently keep whatever name it inherited.  Prove the
# cut happened rather than the refusal.
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$LONG" -- "$CASES" sleeper &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
sleep "$SL"
if [ -n "$PAY" ]; then
    TP=$(status_field "$PAY" TracerPid)
    TR_COMM=$(cat "/proc/$TP/comm" 2>/dev/null | tr -d '\n')
    WANT=$(printf '%s' "$LONG" | cut -c1-15)
    LEN=$(printf '%s' "$TR_COMM" | wc -c | tr -d ' ')
    if [ "$TR_COMM" = "$WANT" ] && [ "$LEN" -le 15 ]; then
        pass "q38h-long-label-cut-to-15 ($LEN bytes comm=[$TR_COMM])"
    else
        fail "q38h-long-label-cut-to-15 (comm=[$TR_COMM] len=$LEN want [$WANT])"
    fi
else
    fail "q38h-long-label-cut-to-15 (no payload)"
fi
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
PAY=""
kill_label "$LONG" 2>/dev/null

# ------------------------------------- q38j: the runner path (--secret)
# The runner path calls `Mask::spawn` *before* it applies the self-mask to
# the supervisor, so a fallback that read only the live comm would name the
# thread after the pre-mask binary name.  The session's own comm has to win.
TOK="${TMPDIR:-/tmp}/b2q38.tok.$$"
printf 'tok\n' >"$TOK"
chmod 600 "$TOK"
env -i PATH=/usr/bin:/bin "$TOOL" -q --label-empty --secret "T=file:$TOK" \
    -- "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
sleep "$SL"
if [ -n "$PAY" ]; then
    TP=$(status_field "$PAY" TracerPid)
    TR_COMM=$(cat "/proc/$TP/comm" 2>/dev/null | tr -d '\n')
    SUP_COMM=$(cat "/proc/$SUP/comm" 2>/dev/null | tr -d '\n')
    if [ -n "$TR_COMM" ] && [ "$TR_COMM" = "$SUP_COMM" ]; then
        pass "q38j-runner-empty-label-falls-back-to-session-comm (comm=[$TR_COMM])"
    else
        fail "q38j-runner-empty-label-falls-back-to-session-comm (tracer=[$TR_COMM] supervisor=[$SUP_COMM])"
    fi
else
    fail "q38j-runner-empty-label-falls-back-to-session-comm (no payload)"
fi
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
PAY=""
rm -f "$TOK"

# ------------------------------------------- q38k: an explicit --comm
# `--comm` sets the supervisor's comm independently of the label.  The
# thread must agree with the process it belongs to, not with the label.
KC=$(printf 'b2q38kc-%.4s' "$$")
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "b2q38k-$$" --comm "$KC" \
    -- "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
PAY=$(wait_child "$SUP" 10) || PAY=""
sleep "$SL"
if [ -n "$PAY" ]; then
    TP=$(status_field "$PAY" TracerPid)
    TR_COMM=$(cat "/proc/$TP/comm" 2>/dev/null | tr -d '\n')
    SUP_COMM=$(cat "/proc/$SUP/comm" 2>/dev/null | tr -d '\n')
    WANT=$(printf '%s' "$KC" | cut -c1-15)
    if [ "$TR_COMM" = "$WANT" ] && [ "$TR_COMM" = "$SUP_COMM" ]; then
        pass "q38k-explicit-comm-names-the-thread (comm=[$TR_COMM])"
    else
        fail "q38k-explicit-comm-names-the-thread (tracer=[$TR_COMM] supervisor=[$SUP_COMM] want [$WANT])"
    fi
else
    fail "q38k-explicit-comm-names-the-thread (no payload)"
fi
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
PAY=""

# ----------------------------------------------- q38i: the daemon path
# pmaskd runs a job through the same `Mask::spawn`, so the daemon is a
# second call site.  Prove the job's tracer thread carries the job label.
if [ -x "$BIN_DIR/pmaskd" ]; then
    SOCKDIR=$(mktemp -d "${TMPDIR:-/tmp}/pmask-q38.XXXXXX") || SOCKDIR=""
    if [ -n "$SOCKDIR" ]; then
        chmod 700 "$SOCKDIR"
        SOCK="$SOCKDIR/d.sock"
        "$BIN_DIR/pmaskd" -q -l "b2q38d-$$" -S "$SOCK" &
        DPID=$!
        i=0
        while [ ! -S "$SOCK" ] && [ "$i" -lt 100 ]; do
            sleep 0.1
            i=$((i + 1))
        done
        if [ -S "$SOCK" ]; then
            "$TOOL" --daemon "$SOCK" --label "$JOB_LABEL" -- "$CASES" sleeper \
                >/dev/null 2>&1 &
            CLIENT=$!
            JPAY=$(wait_child "$DPID" 10) || JPAY=""
            sleep "$SL"
            if [ -n "$JPAY" ]; then
                TP=$(status_field "$JPAY" TracerPid)
                TR_COMM=$(cat "/proc/$TP/comm" 2>/dev/null | tr -d '\n')
                TR_TGID=$(status_field "$TP" Tgid)
                TR_PID=$(status_field "$TP" Pid)
                WANT=$(printf '%s' "$JOB_LABEL" | cut -c1-15)
                if [ "$TR_COMM" = "$WANT" ] && [ "$TR_TGID" != "$TR_PID" ]; then
                    pass "q38i-daemon-job-tracer-comm-is-the-job-label (comm=[$TR_COMM])"
                else
                    fail "q38i-daemon-job-tracer-comm-is-the-job-label (comm=[$TR_COMM] want [$WANT] Tgid=$TR_TGID Pid=$TR_PID)"
                fi
                h=$(retired_count "" 0)
                n=$(retired_count "$DPID" 0)
                if [ "$n" = 0 ]; then
                    pass "q38i2-daemon-leaves-no-fingerprint (in-session=0 host-wide=$h)"
                else
                    fail "q38i2-daemon-leaves-no-fingerprint (in-session=$n host-wide=$h)"
                fi
            else
                fail "q38i-daemon-job-tracer-comm-is-the-job-label (no job process under $DPID)"
                fail "q38i2-daemon-leaves-no-fingerprint (no job process)"
            fi
            kill -9 "$CLIENT" 2>/dev/null
            wait "$CLIENT" 2>/dev/null
        else
            skip "q38i-daemon-job-tracer-comm-is-the-job-label (daemon did not bind $SOCK)"
            skip "q38i2-daemon-leaves-no-fingerprint (daemon did not bind)"
        fi
        kill -9 "$DPID" 2>/dev/null
        wait "$DPID" 2>/dev/null
        DPID=""
        rm -rf "$SOCKDIR"
        SOCKDIR=""
    else
        skip "q38i-daemon-job-tracer-comm-is-the-job-label (mktemp failed)"
        skip "q38i2-daemon-leaves-no-fingerprint (mktemp failed)"
    fi
else
    skip "q38i-daemon-job-tracer-comm-is-the-job-label (pmaskd not built)"
    skip "q38i2-daemon-leaves-no-fingerprint (pmaskd not built)"
fi
kill_label "$JOB_LABEL" 2>/dev/null

echo "== VERDICT: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL) failures=$FAIL =="
[ "$FAIL" = 0 ]
