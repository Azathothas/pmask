#!/bin/sh
# Issue 46: `--watch-rename` leaves a second seccomp filter and
# `NoNewPrivs=1`, and what a defender can read from that.
#
# The flag's mechanism is a classic BPF filter installed with
# prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER), which also implies
# PR_SET_NO_NEW_PRIVS.  So the flag-specific pair is
# `Seccomp_filters >= 2` AND `NoNewPrivs == 1`, not either one alone:
# --no-new-privs also sets NNP with a single filter, and a sandbox can
# install several filters without being pmask.
#
# Cases:
#   s1  --watch-rename: Seccomp_filters=2, NoNewPrivs=1, comm=label
#   s1b control: the same payload without the flag: 1 filter, NNP=0
#   s1c control: a plain process on this host: 1 filter, NNP=0
#   s2  the redirect: a payload's prctl(PR_SET_NAME,"other") leaves the
#       label as comm with the flag, and "other" without it
#   s3  --no-new-privs alone: NNP=1 with ONE filter (the pair is the
#       discriminator, and this is the control for that)
#   s4  the supervisor itself: 1 filter, NNP=0
#   s5  --watch-rename --no-dumpable: defect #60.  The fix is owned by
#       fix1; this asserts the fixed shape when qa/fix1 carries it (the
#       flag pair is refused), and the current warning+divergence
#       otherwise.  Either branch is a PASS with the branch named; the
#       dependency is reported so it is not read as coverage of #60.
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
skip() { echo "SKIP $*"; }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa46.XXXXXX") || {
    echo "FATAL: cannot create a temp dir"; exit 2
}
SUP=""
cleanup() {
    [ -n "$SUP" ] && kill "$SUP" 2>/dev/null
    kill_label qa46-
    rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

L=qa46-label   # 11 bytes, under COMM_MAX, so comm == label exactly
L2=qa46-sec

# status_field PID FIELD -> the value, empty when absent
status_field() {
    sed -n "s/^$2:[[:space:]]*//p" "/proc/$1/status" 2>/dev/null
}

child_of() {
    for d in /proc/[0-9]*; do
        pp=$(sed -n 's/^PPid:[[:space:]]*//p' "$d/status" 2>/dev/null)
        if [ "$pp" = "$1" ]; then
            echo "${d#/proc/}"
            return 0
        fi
    done
    return 1
}

await_pid() {
    n=0
    while [ "$n" -lt 40 ]; do
        p=$(child_of "$1") && { echo "$p"; return 0; }
        n=$((n + 1))
        sleep 0.1 2>/dev/null || sleep 1
    done
    return 1
}

# wait_report FILE -> the `renamer-comm=` line, once written.
# The renamer prints it after its 700 ms sleep, then parks, so the line is
# the signal that the rename has happened and the payload is still alive.
# The budget is 30 s: the payload needs about 1.2 s, and a loaded host can
# take much longer to schedule it.  The elapsed time goes to a file rather
# than a variable, because the caller captures the return value with a
# command substitution, which runs in a subshell.
wait_report() {
    n=0
    while [ "$n" -lt 300 ]; do
        line=$(sed -n 's/^renamer-comm=//p' "$1" 2>/dev/null | head -n 1)
        if [ -n "$line" ]; then
            echo $((n / 10)) > "$2"
            echo "$line"
            return 0
        fi
        n=$((n + 1))
        sleep 0.1 2>/dev/null || sleep 1
    done
    echo 30 > "$2"
    return 1
}

# row PID -> "filters=N nnp=N comm=NAME"
row() {
    echo "filters=$(status_field "$1" Seccomp_filters) nnp=$(status_field "$1" NoNewPrivs) comm=$(status_field "$1" Name)"
}

# ------------------------------------------------- s1: the flag's shape
"$TOOL" -q -l "$L" --watch-rename -- "$CASES" sleeper >/dev/null 2>"$D/s1.err" &
SUP=$!
PAY=$(await_pid "$SUP") || PAY=""
if [ -z "$PAY" ]; then
    fail "s1-watch-rename-filter-shape (no payload; stderr=$(head -1 "$D/s1.err"))"
    skip "s1b-control-without-the-flag (no payload for s1)"
    kill "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
    SUP=""
else
    r=$(row "$PAY")
    case "$r" in
        "filters=2 nnp=1 comm=$L")
            pass "s1-watch-rename-filter-shape ($r)" ;;
        *)
            fail "s1-watch-rename-filter-shape ($r, want filters=2 nnp=1 comm=$L)" ;;
    esac
    kill "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
    SUP=""

    # s1b: the control.  The observer must read a different shape for the
    # same payload without the flag, or s1's pair proves nothing.
    "$TOOL" -q -l "$L" -- "$CASES" sleeper >/dev/null 2>/dev/null &
    SUP=$!
    PAY=$(await_pid "$SUP") || PAY=""
    if [ -z "$PAY" ]; then
        fail "s1b-control-without-the-flag (no payload)"
    else
        r=$(row "$PAY")
        case "$r" in
            "filters=1 nnp=0 comm=$L")
                pass "s1b-control-without-the-flag ($r)" ;;
            *)
                fail "s1b-control-without-the-flag ($r, want filters=1 nnp=0 comm=$L)" ;;
        esac
    fi
    kill "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
    SUP=""
fi

# s1c: a plain process, so the numbers are this host's baseline and not
# something pmask does to every payload.
/bin/sleep 4 &
PLAIN=$!
sleep 0.3
r=$(row "$PLAIN")
case "$r" in
    "filters=1 nnp=0 comm=sleep")
        pass "s1c-control-plain-process ($r)" ;;
    *)
        fail "s1c-control-plain-process ($r, want filters=1 nnp=0 comm=sleep)" ;;
esac
kill "$PLAIN" 2>/dev/null
wait "$PLAIN" 2>/dev/null

# ------------------------------------ s2: the redirect, and its control
# `testcases renamer` settles, calls prctl(PR_SET_NAME, "other"), sleeps
# 700 ms and parks.  /proc/<pid>/comm is read while it is parked.
"$TOOL" -q -l "$L2" --watch-rename -- "$CASES" renamer >"$D/s2.out" 2>"$D/s2.err" &
SUP=$!
# Wait for the payload's own report first: it is printed after the rename
# and before the payload parks, so a line means the rename has happened.
self=$(wait_report "$D/s2.out" "$D/s2.waited") || self=""
PAY=$(await_pid "$SUP") || PAY=""
comm=""
[ -n "$PAY" ] && comm=$(status_field "$PAY" Name)
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
if [ -z "$PAY" ] || [ -z "$self" ]; then
    fail "s2-redirect-keeps-the-label (payload=[$PAY] self=[$self] waited=$(cat "$D/s2.waited" 2>/dev/null)s stderr=$(head -1 "$D/s2.err"))"
elif [ "$comm" = "$L2" ] && [ "$self" = "$L2" ]; then
    pass "s2-redirect-keeps-the-label (comm=$comm, payload saw $self)"
else
    fail "s2-redirect-keeps-the-label (comm=[$comm] payload=[$self], want $L2 for both)"
fi

"$TOOL" -q -l "$L2" -- "$CASES" renamer >"$D/s2c.out" 2>/dev/null &
SUP=$!
self=$(wait_report "$D/s2c.out" "$D/s2c.waited") || self=""
PAY=$(await_pid "$SUP") || PAY=""
comm=""
[ -n "$PAY" ] && comm=$(status_field "$PAY" Name)
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
if [ -z "$PAY" ] || [ -z "$self" ]; then
    fail "s2b-control-rename-takes-effect (payload=[$PAY] self=[$self] waited=$(cat "$D/s2c.waited" 2>/dev/null)s)"
elif [ "$comm" = "other" ] && [ "$self" = "other" ]; then
    pass "s2b-control-rename-takes-effect (comm=$comm, payload saw $self)"
else
    fail "s2b-control-rename-takes-effect (comm=[$comm] payload=[$self], want other for both: the observer cannot see a rename, so s2 proves nothing)"
fi

# -------------------- s3: --no-new-privs alone is not the discriminator
"$TOOL" -q -l "$L" --no-new-privs -- "$CASES" sleeper >/dev/null 2>/dev/null &
SUP=$!
PAY=$(await_pid "$SUP") || PAY=""
if [ -z "$PAY" ]; then
    fail "s3-no-new-privs-alone (no payload)"
else
    r=$(row "$PAY")
    case "$r" in
        "filters=1 nnp=1 comm=$L")
            pass "s3-no-new-privs-alone-one-filter ($r)" ;;
        *)
            fail "s3-no-new-privs-alone-one-filter ($r, want filters=1 nnp=1: the pair needs the filter count)" ;;
    esac
fi
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""

# --------------------------------------------- s4: the supervisor's row
"$TOOL" -q -l "$L" --watch-rename -- "$CASES" sleeper >/dev/null 2>/dev/null &
SUP=$!
sleep 0.9
if ! kill -0 "$SUP" 2>/dev/null; then
    fail "s4-supervisor-row (supervisor gone)"
else
    r=$(row "$SUP")
    case "$r" in
        "filters=1 nnp=0 comm=$L")
            pass "s4-supervisor-row ($r)" ;;
        *)
            fail "s4-supervisor-row ($r, want filters=1 nnp=0 comm=$L)" ;;
    esac
fi
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""

# ------------------------- s5: --watch-rename --no-dumpable (defect #60)
# The redirect used to need a tracee memory write, and a non-dumpable
# tracee refuses it, so the payload renamed itself and only a warning
# said so.  fix1 owns the fix (redirect to the label already mapped in the
# presentation block, no write); this branch may or may not carry it when
# the reconciler runs, so the case decides from the observed shape and
# names which one it saw.  Three shapes are acceptable:
#   1. the pair is refused before a payload exists, with a message;
#   2. fixed: comm and the payload's own reading are both the label, which
#      proves the payload's PR_SET_NAME("other") was redirected rather than
#      not attempted;
#   3. the open defect: comm and the payload's reading are both "other",
#      with the documented warning.
# A divergence with no warning is a FAIL: that is a silent degradation
# (invariant 13).
# No -q here: the degradation warning is printed at the default
# verbosity only, so a quiet run would hide the evidence.
err="$D/s5.err"
"$TOOL" -l "$L2" --watch-rename --no-dumpable -- "$CASES" renamer \
    >"$D/s5.out" 2>"$err" &
SUP=$!
self=$(wait_report "$D/s5.out" "$D/s5.waited") || self=""
PAY=$(await_pid "$SUP") || PAY=""
comm=""
[ -n "$PAY" ] && comm=$(status_field "$PAY" Name)
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
warn=$(grep -c 'cannot redirect a rename to the label' "$err" 2>/dev/null)
waited=$(cat "$D/s5.waited" 2>/dev/null)
if [ -z "$PAY" ]; then
    if [ -s "$err" ]; then
        pass "s5-watch-rename-no-dumpable (refused before a payload: $(head -1 "$err"))"
        echo "NOTE s5 saw the refusal shape"
    else
        fail "s5-watch-rename-no-dumpable (no payload and no message)"
    fi
elif [ "$comm" = "$L2" ] && [ "$self" = "$L2" ]; then
    pass "s5-watch-rename-no-dumpable (fixed: comm=$comm payload=$self)"
    echo "NOTE s5 saw the fixed shape (issue #60): the redirect needed no write"
elif [ "$comm" = "other" ] && [ "$self" = "other" ] && [ "$warn" != 0 ]; then
    pass "s5-watch-rename-no-dumpable (defect #60 open: comm=$comm payload=$self)"
    echo "NOTE s5 saw the open defect shape (issue #60, fix1 owns the fix):"
    echo "     $(head -1 "$err")"
else
    fail "s5-watch-rename-no-dumpable (comm=[$comm] payload=[$self] waited=${waited}s warn=$warn: neither the fixed shape nor the documented defect)"
fi

echo "== QA46: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
[ "$FAIL" = 0 ] || exit 1
exit 0
