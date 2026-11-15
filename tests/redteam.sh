#!/bin/sh
# Red-team regression suite for the beta.5 audit findings.
#
# The cases in tests/qa.d/65..77 cover the same properties with more
# tooling; this suite is staged into the micro-VM so the gate decides
# them on a kernel with ptrace.  It uses only busybox tools and the
# static test binaries.
set -u
cd "$(dirname "$0")"
. ./lib.sh

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-redteam.XXXXXX") || exit 2
SUP=""
PAY=""
cleanup() {
    [ -n "$PAY" ] && kill -9 "$PAY" 2>/dev/null
    [ -n "$SUP" ] && kill -9 "$SUP" 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT INT TERM

# child_of PID: first direct child
child_of() {
    for d in /proc/[0-9]*; do
        pp=$(awk '/^PPid:/{print $2}' "$d/status" 2>/dev/null)
        [ "$pp" = "$1" ] && { echo "${d#/proc/}"; return 0; }
    done
    return 1
}

# spans PID -> "arg_start arg_end env_start env_end start_stack"
spans() {
    awk '{sub(/.*\) /,""); print $46, $47, $48, $49, $26}' "/proc/$1/stat" 2>/dev/null
}

# field PID N (kernel field number)
field() {
    awk -v n="$2" '{sub(/.*\) /,""); print $(n-2)}' "/proc/$1/stat" 2>/dev/null
}

wait_child() {
    i=0
    while [ "$i" -lt 40 ]; do
        c=$(child_of "$1") && { echo "$c"; return 0; }
        i=$((i + 1)); sleep 0.1
    done
    return 1
}

# ---------------------------------------------------------------- R1 shape
L=rt-label
"$TOOL" -q -l "$L" -- "$CASES" auxvserved 4 >"$D/r1.out" 2>"$D/r1.err" &
SUP=$!
PAY=$(wait_child "$SUP") || true
if [ -z "${PAY:-}" ]; then
    fail R1-no-child
else
    cmdlen=$(wc -c < "/proc/$PAY/cmdline" 2>/dev/null | tr -d ' ')
    set -- $(spans "$PAY")
    as=${1:-0}; ae=${2:-0}; es=${3:-0}; ee=${4:-0}; ss=${5:-0}
    [ "$cmdlen" = "$((ae - as))" ] && pass R1-cmdline-span || fail "R1-cmdline-span cmd=$cmdlen span=$((ae - as))"
    [ "$es" = "$ae" ] && pass R1-no-gap || fail "R1-no-gap arg_end=$ae env_start=$es"
    [ "$ee" -gt "$es" ] && pass R1-env-span || fail "R1-env-span $((ee - es))"
    [ "$ss" -lt "$as" ] && pass R1-start-stack || fail "R1-start-stack stack=$ss arg=$as"
    served=$(sed -n 's/^auxvserved=//p' "$D/r1.out")
    [ "$served" = "$L" ] && pass R1-served-auxv || fail "R1-served-auxv [$served]"
    if grep -q '\[stack\]' "/proc/$PAY/maps" 2>/dev/null; then
        pass R1-stack-vma
    else
        fail R1-stack-vma
    fi
    if awk '
        /^[0-9a-f]+-[0-9a-f]+ / { want = index($0, "[stack]") > 0; next }
        want && /^VmFlags:/ { if (index($0, "gd")) found = 1; want = 0 }
        END { exit found ? 0 : 1 }
    ' "/proc/$PAY/smaps" 2>/dev/null; then
        pass R1-stack-gd
    else
        fail R1-stack-gd
    fi
fi
kill -9 "$SUP" 2>/dev/null; wait "$SUP" 2>/dev/null; SUP=""; PAY=""

# payload's own getauxval agrees with the served view
"$TOOL" -q -l "$L" -- "$CASES" execfn 1 >"$D/r1b.out" 2>/dev/null
if grep -qx "execfn=$L" "$D/r1b.out"; then
    pass R1-inprocess-auxv
else
    fail "R1-inprocess-auxv [$(cat "$D/r1b.out")]"
fi

# ----------------------------------------------------------- R2 --no-exact
"$CASES" execfn 2 >"$D/r2c.out" 2>/dev/null &
CP=$!
sleep 0.5
set -- $(spans "$CP")
cas=${1:-0}; cae=${2:-0}; ces=${3:-0}; cee=${4:-0}
kill -9 "$CP" 2>/dev/null

"$TOOL" -q --no-exact -l rt-ne -- "$CASES" execfn 3 >"$D/r2.out" 2>"$D/r2.err" &
SUP=$!
PAY=$(wait_child "$SUP") || true
if [ -z "${PAY:-}" ]; then
    wait "$SUP" 2>/dev/null; rc=$?
    fail "R2-no-child rc=$rc out=[$(cat "$D/r2.out" 2>/dev/null)] err=[$(cat "$D/r2.err" 2>/dev/null | head -2 | tr '\n' '|')]"
else
    set -- $(spans "$PAY")
    as=${1:-0}; ae=${2:-0}; es=${3:-0}; ee=${4:-0}
    [ $((ae - as)) -eq $((cae - cas)) ] && pass R2-argv-extent || fail "R2-argv-extent $((ae - as)) vs $((cae - cas))"
    [ $((ee - es)) -eq $((cee - ces)) ] && pass R2-env-extent || fail "R2-env-extent $((ee - es)) vs $((cee - ces))"
    paths=$(tr '\0' '\n' < "/proc/$PAY/environ" 2>/dev/null | grep -c '^PATH=')
    [ "${paths:-0}" -le 2 ] && pass R2-env-unique || fail "R2-env-unique PATH=$paths"
    cmd=$(tr '\0' ' ' < "/proc/$PAY/cmdline" 2>/dev/null)
    case "$cmd" in
        "rt-ne "*) pass R2-cmdline-padded ;;
        *) fail "R2-cmdline-padded [$cmd]" ;;
    esac
fi
kill -9 "$SUP" 2>/dev/null; wait "$SUP" 2>/dev/null; SUP=""; PAY=""

# --------------------------------------------------------------- R3 plain
"$TOOL" -q --no-redact -l rt-plain -- "$CASES" execfn 2 >"$D/r3.out" 2>/dev/null &
SUP=$!
sleep 0.6
supcmd=$(tr '\0' ' ' < "/proc/$SUP/cmdline" 2>/dev/null)
case "$supcmd" in
    *pmask*) pass R3-supervisor-argv ;;
    *) fail "R3-supervisor-argv [$supcmd]" ;;
esac
supnul=$(tr -cd '\0' < "/proc/$SUP/cmdline" 2>/dev/null | wc -c | tr -d ' ')
suplen=$(wc -c < "/proc/$SUP/cmdline" 2>/dev/null | tr -d ' ')
[ "$supnul" != "$suplen" ] && pass R3-not-nul-run || fail R3-not-nul-run
kill -9 "$SUP" 2>/dev/null; wait "$SUP" 2>/dev/null; SUP=""

# ------------------------------------------------------ R4 --exec-once self
"$TOOL" -q --exec-once -l rt-eo -- "$CASES" selfexec >"$D/r4.out" 2>"$D/r4.err"
if grep -q 'SELF-SECOND' "$D/r4.out" && grep -q 'selfexec-child=0' "$D/r4.out"; then
    pass R4-self-exec-once
else
    fail "R4-self-exec-once [$(cat "$D/r4.out")]"
fi
if grep -qi 'pmask:' "$D/r4.err"; then
    fail "R4-no-nested-pmask [$(head -1 "$D/r4.err")]"
else
    pass R4-no-nested-pmask
fi

# -------------------------------------------------------- R5 --rexec limit
(
    ulimit -n 64 2>/dev/null || exit 77
    "$TOOL" -q --rexec -l rt-rx -- "$CASES" exe-id >/dev/null 2>"$D/r5.err"
    echo $? >"$D/r5.rc"
) || true
rc=$(cat "$D/r5.rc" 2>/dev/null || echo 0)
case "$rc" in
    126|127) pass R5-rexec-fail-closed ;;
    77) pass R5-rexec-fail-closed-skip ;;
    *) fail "R5-rexec-fail-closed rc=$rc [$(cat "$D/r5.err" 2>/dev/null)]" ;;
esac

# ------------------------------------------------------------ R6 report
(
    "$TOOL" --report-file "$D/report.json" -q -l rt-rp -- /bin/sh -c '
      for f in /proc/$PPID/fd/*; do
        t=$(readlink "$f" 2>/dev/null) || continue
        case "$t" in
          *.json*|*pmask*) printf "{\"forged\":true}" >> "$f" 2>/dev/null ;;
        esac
      done
      test -e '"$D"'/report.json && exit 9
      exit 0' >/dev/null 2>&1
    echo $? >"$D/r6.rc"
) || true
rc=$(cat "$D/r6.rc" 2>/dev/null || echo 255)
[ "$rc" = 0 ] && pass R6-report-absent-during || fail "R6-report-absent-during rc=$rc"
last=$(tr -d '\n' < "$D/report.json" 2>/dev/null | tail -c 1)
if [ -s "$D/report.json" ] && [ "$last" = "}" ] && ! grep -q 'forged' "$D/report.json" 2>/dev/null; then
    pass R6-report-clean
else
    fail "R6-report-clean [$(tail -c 80 "$D/report.json" 2>/dev/null)]"
fi

# ------------------------------------------------------- R7 comm write guard
# Control: without pmask the writer renames itself.  A host that denies
# the write to every process would otherwise make the guard look like it
# worked, so R7 reports a skip there and decides nothing.
"$CASES" commwrite 1 "" >"$D/r7ctl.out" 2>/dev/null
if grep -q '^comm=evil-write' "$D/r7ctl.out"; then
    COMM_WRITE=writes
else
    COMM_WRITE=blocked
fi
no_write() {
    echo "SKIP $1 (host denies the write: $(tr -d '\n' <"$D/r7ctl.out"))"
}

"$TOOL" -q --watch-rename -l rt-cw -- "$CASES" commwrite 3 >"$D/r7.out" 2>/dev/null &
SUP=$!
PAY=$(wait_child "$SUP") || true
sleep 1.2
if [ "$COMM_WRITE" = blocked ]; then
    no_write R7-comm-write-guard
elif [ -n "${PAY:-}" ]; then
    c=$(cat "/proc/$PAY/comm" 2>/dev/null)
    [ "$c" = rt-cw ] && pass R7-comm-write-guard || fail "R7-comm-write-guard [$c]"
else
    fail "R7-comm-write-guard (no child)"
fi
kill -9 "$SUP" 2>/dev/null; wait "$SUP" 2>/dev/null; SUP=""; PAY=""

# strict also catches a write on a descriptor opened before the filter saw
# it; the default filter refuses the write-mode open itself (R7, R7c).
"$TOOL" -q --watch-rename=strict --on-exit wait -l rt-cs -- "$CASES" commwrite 2 >"$D/r7b.out" 2>/dev/null &
SUP=$!
PAY=$(wait_child "$SUP") || true
sleep 1.2
if [ "$COMM_WRITE" = blocked ]; then
    no_write R7b-strict-comm
elif [ -n "${PAY:-}" ]; then
    c=$(cat "/proc/$PAY/comm" 2>/dev/null)
    [ "$c" = rt-cs ] && pass R7b-strict-comm || fail "R7b-strict-comm [$c]"
else
    fail "R7b-strict-comm (no child)"
fi
kill -9 "$SUP" 2>/dev/null; wait "$SUP" 2>/dev/null; SUP=""; PAY=""

# R7c: the same write through a descriptor.  `openat(dirfd, "comm")`
# gives the trap a path with no `/proc/` in it, so the default filter has
# to resolve the dirfd before the shape test (issue 71).
"$TOOL" -q --watch-rename -l rt-cd -- "$CASES" commwrite 2 dirfd >"$D/r7c.out" 2>/dev/null &
SUP=$!
PAY=$(wait_child "$SUP") || true
sleep 1.2
if [ "$COMM_WRITE" = blocked ]; then
    no_write R7c-dirfd-comm-guard
elif [ -n "${PAY:-}" ]; then
    c=$(cat "/proc/$PAY/comm" 2>/dev/null)
    [ "$c" = rt-cd ] && pass R7c-dirfd-comm-guard || fail "R7c-dirfd-comm-guard [$c]"
else
    fail "R7c-dirfd-comm-guard (no child)"
fi
kill -9 "$SUP" 2>/dev/null; wait "$SUP" 2>/dev/null; SUP=""; PAY=""

echo "################ REDTEAM: FAIL=$FAIL"
[ "$FAIL" = 0 ] && exit 0
exit 1
