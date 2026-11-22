#!/bin/sh
# Blue-team sweep: the signals an unprivileged observer can read about a
# pmask tree, scored for each mode.
#
# This is the other side of tests/redteam.sh.  Red team asks "does the
# mask hold"; this asks "what is left to see".  A HIT is a signal an
# observer reads without any privilege over the tree, so a mode's value
# is its MISS list.
#
# Two kinds of line come out:
#   BT <mode>: ...   the measurement, one row per heuristic, always printed
#   PASS/FAIL bt-…   the documentation's claims, as assertions
# A hit that no claim covers is reported and does not fail the run: an
# honest weakness is not a defect, a claim that stopped being true is.
#
# Reads only: /proc and the tree's own binaries.
set -u
cd "$(dirname "$0")"
. ./lib.sh

: "${TOOL:?}" "${CASES:?}"

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-bt.XXXXXX") || exit 2
CUR_SUP=""
CUR_PID=""
cleanup() {
    [ -n "$CUR_PID" ] && kill -9 "$CUR_PID" 2>/dev/null
    [ -n "$CUR_SUP" ] && kill -9 "$CUR_SUP" 2>/dev/null
    kill_label bt-
    rm -rf "$D"
}
trap cleanup EXIT INT TERM

# The window an exact-mode payload presents when the caller passed no
# environment through (src/execimg.rs DECOY_ENV).  A detector may know a
# signature by heart; the question this file answers is whether it is
# still there.
DECOY='PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
LANG=C.UTF-8
TERM=xterm-256color'

carriers() {
    for p in /proc/[0-9]*; do
        [ "$(cat "$p/comm" 2>/dev/null)" = "$1" ] && echo "${p#/proc/}"
    done
}

exe_of() {
    e=$(readlink "/proc/$1/exe" 2>/dev/null)
    printf '%s' "${e:-UNREADABLE}"
}

field() {
    sed -n "s/^$2:[[:space:]]*//p" "/proc/$1/status" 2>/dev/null
}

# The sweep an observer actually runs.  A filter is rare on a desktop and
# common in a server sandbox, which is why it identifies a process as
# filtered and not as pmask on its own.
sweep_total() {
    n=0
    for p in /proc/[0-9]*; do
        s=$(field "${p#/proc/}" Seccomp)
        [ -n "$s" ] && [ "$s" != 0 ] && n=$((n + 1))
    done
    echo "$n"
}

# The payload is the carrier the tracer is attached to.  Identifying it by
# exe alone fails under --no-dumpable, where the supervisor's exe is also
# unreadable, so prefer the carrier with a tracer and the higher pid: a
# forked child always has the larger pid.
pick_payload() {
    label=$1
    fallback=''
    for p in $(carriers "$label"); do
        case "$(exe_of "$p")" in */pmask|*/pmaskd) continue ;; esac
        tr=$(field "$p" TracerPid)
        if [ -n "${tr:-}" ] && [ "$tr" != 0 ]; then
            echo "$p"
            return
        fi
        [ -z "$fallback" ] && fallback=$p
    done
    printf '%s' "$fallback"
}

score_mode() {
    name=$1
    label=$2
    shift 2
    # shellcheck disable=SC2086
    "$TOOL" -q -l "$label" "$@" -- "$CASES" sleeper 5 >/dev/null 2>"$D/$name.err" &
    sup=$!
    CUR_SUP=$sup
    sleep 0.9
    h1=miss h2=miss h3=miss h5=miss h6=miss h7=miss
    sup_pid=''
    for p in $(carriers "$label"); do
        case "$(exe_of "$p")" in
            */pmask|*/pmaskd) sup_pid=$p; h1="hit(pid $p exe $(exe_of "$p"))" ;;
        esac
    done
    pid=$(pick_payload "$label")
    CUR_PID=$pid
    if [ -z "$pid" ]; then
        skip "bt-$name (no carrier carries the label: $(head -1 "$D/$name.err"))"
        kill -9 "$sup" 2>/dev/null
        kill_label "$label"
        wait "$sup" 2>/dev/null
        CUR_SUP=""
        CUR_PID=""
        return
    fi
    if [ "$pid" != "$sup_pid" ]; then
        case "$(exe_of "$pid")" in
            /memfd:*|*"(deleted)"*) h5="hit($(exe_of "$pid"))" ;;
        esac
    fi
    st=$(cat "/proc/$pid/status" 2>/dev/null)
    if [ -z "$st" ]; then
        # --no-dumpable refuses the whole file to a same-uid observer,
        # which is stronger than any field inside it reading 0.
        h2="unreadable" h3="unreadable"
    else
        tr=$(field "$pid" TracerPid)
        sc=$(field "$pid" Seccomp)
        [ -n "${tr:-}" ] && [ "$tr" != 0 ] && h2="hit(tracer $tr)"
        [ -n "${sc:-}" ] && [ "$sc" != 0 ] && h3="hit(seccomp $sc)"
    fi
    # The argv an exact-mode run exposes is the label and its NUL.  The
    # --no-exact presentation is the label followed by spaces, which no
    # program passes as argv[0], so a run of spaces in argv0 is the trace.
    argv0=$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | head -1)
    if [ -z "$argv0" ]; then
        h6="unreadable"
    else
        case "$argv0" in
            *"  "*) h6="hit(argv0 padded: [$argv0])" ;;
        esac
    fi
    envb=$(wc -c < "/proc/$pid/environ" 2>/dev/null || echo 0)
    if [ "${envb:-0}" -gt 0 ]; then
        got=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed '/^$/d' | sort | tr '\n' '|')
        want=$(printf '%s\n' "$DECOY" | sort | tr '\n' '|')
        [ "$got" = "$want" ] && h7="hit(fixed decoy, $envb bytes)"
    else
        h7="unreadable"
    fi
    # H7 is reported and never asserted, on purpose.  The bytes are a
    # fixed value (src/execimg.rs DECOY_ENV), so a detector that knows it
    # matches every exact-mode payload.  Randomizing those bytes would not
    # change the finding: with no --keep-env the exposed length is pinned
    # to DECOY_ENV.len(), so the size is as much a signature as the text,
    # and an environment that is not the caller's is visible whatever it
    # says.  --keep-env is the plausible-environment path; this row states
    # what the default leaves behind.
    SWEEP=$(sweep_total)
    echo "BT $name: H1 $h1 | H2 $h2 | H3 $h3 | H5 $h5 | H6 $h6 | H7 $h7 | sweep $SWEEP"

    # The documentation's claims, one assertion each.
    case "$name" in
        default)
            case "$h3" in
                hit*) fail "bt-default-seccomp-is-not-set ($h3)" ;;
                *) pass "bt-default-seccomp-is-not-set (no filter to attribute)" ;;
            esac
            ;;
        watch|strict|stealth)
            # --watch-rename's own help text: the filter is kernel state
            # and status reports it.  Unreadable is the stronger result.
            case "$h3" in
                hit*) pass "bt-$name-carries-a-seccomp-filter ($h3)" ;;
                unreadable) pass "bt-$name-status-is-unreadable (stronger than a filter field)" ;;
                *) fail "bt-$name-carries-a-seccomp-filter (expected the filter, saw $h3)" ;;
            esac
            ;;
        detach)
            # --on-exit detach detaches when the tree exits, so a running
            # payload is traced; qa.d/57 e6 owns the descendant case.
            case "$h2" in
                hit*) pass "bt-detach-keeps-the-tracer-while-the-payload-runs ($h2)" ;;
                *) fail "bt-detach-keeps-the-tracer-while-the-payload-runs ($h2)" ;;
            esac
            ;;
        rexec)
            case "$h5" in
                hit*) pass "bt-rexec-payload-exe-is-a-memfd ($h5)" ;;
                *) fail "bt-rexec-payload-exe-is-a-memfd ($h5)" ;;
            esac
            ;;
    esac
    # Exact mode writes the label into the argv region, so argv0 is the
    # label with no padding.  --no-exact is documented to pad it (issue 74).
    case "$name" in
        noexact)
            case "$h6" in
                hit*) pass "bt-noexact-argv0-shows-the-padding ($h6)" ;;
                *) fail "bt-noexact-argv0-shows-the-padding ($h6)" ;;
            esac
            ;;
        *)
            case "$h6" in
                hit*) fail "bt-$name-argv0-is-unpadded ($h6)" ;;
                unreadable) pass "bt-$name-argv0-is-unreadable (stronger than unpadded)" ;;
                *) pass "bt-$name-argv0-is-unpadded (the label and no padding)" ;;
            esac
            ;;
    esac
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    kill -9 "$sup" 2>/dev/null
    kill_label "$label"
    wait "$sup" 2>/dev/null
    CUR_SUP=""
    CUR_PID=""
    sleep 0.2
}

before=$(sweep_total)
score_mode default bt-default
after_default=$SWEEP
[ "$after_default" -le "$before" ] && pass "bt-fleet-sweep-does-not-rise ($before -> $after_default)" \
    || fail "bt-fleet-sweep-does-not-rise ($before -> $after_default)"
score_mode watch bt-watch --watch-rename
[ "$SWEEP" -gt "$before" ] && pass "bt-fleet-sweep-finds-the-watch-run ($before -> $SWEEP)" \
    || fail "bt-fleet-sweep-finds-the-watch-run ($before -> $SWEEP)"
score_mode strict bt-strict --watch-rename=strict
score_mode stealth bt-stealth --stealth
score_mode detach bt-detach --on-exit detach
score_mode rexec bt-rexec --rexec
score_mode noexact bt-noexact --no-exact

echo "BT: FAIL=$FAIL"
[ "$FAIL" = 0 ] && exit 0
exit 1
