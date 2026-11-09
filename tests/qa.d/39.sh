#!/bin/sh
# Issue 39: the supervisor's own /proc entry, and PMASK_NO_SELFMASK.
#
# The self-mask is the documented shape: comm == label cut to 15 bytes,
# cmdline == label + one NUL, empty environment window, a tracer task
# task, and PR_SET_DUMPABLE=0 (so a same-uid read of exe/environ fails).
# A same-uid reader gets `0 0 0 0` for stat fields 48-51; only root sees
# the relocated window.
#
# PMASK_NO_SELFMASK is a documented debugging escape and stays.  Two
# measured facts decide what it may claim (evidence/bteam1/39/):
#   - the plain path honours it, so the supervisor's argv is real for the
#     whole run and a `literal:` value in it is readable the whole time;
#   - the redact and isolate paths re-mask after the fork, so the escape
#     is overridden there and the window is the exec-to-selfmask one.
# Either way the run names the exposure instead of staying silent.  On a
# host whose audit subsystem answers, the plain-mode combination is
# refused unless --allow-argv-secret is given, because the supervisor's
# own exec is then also written to the audit log.
#
# Cases:
#   S1  default self-mask shape: comm, cmdline, tracer task, zeros for uid 1000
#   S1b default self-mask window, as root: label+NUL, env span 0
#   S2  default run: the supervisor's environ is not readable (dumpable 0)
#   S3  control: PMASK_NO_SELFMASK serves the real argv on the plain path
#   S4  control: PMASK_NO_SELFMASK + literal secret readable in plain mode
#   S5  plain mode + literal secret warns once, names the exposure
#   S6  redact mode + literal secret says the escape is overridden
#   S7  no secret: no warning (the escape alone is a documented shape)
#   S8  plain + audit reachable + no --allow-argv-secret: refused, 255
#   S9  plain + audit reachable + --allow-argv-secret: runs, 0
#   S10 --allow-argv-secret does not silence the warning
#   S11 the supervised payload is still alive and functional after S5
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

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa39.XXXXXX") || {
    echo "FATAL: cannot create a temp dir"; exit 2
}
SUP=""
cleanup() {
    [ -n "$SUP" ] && kill "$SUP" 2>/dev/null
    kill_label qa39-
    rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

L=qa39-sup
SECRET=QA39-CANARY-hunter2

# Arg and env spans of pid, after the last ') '.  The supervisor is
# non-dumpable, so a same-uid reader gets four zeros; root sees the real
# window.  Both readers are measured because both are part of the shape.
spans_self() {
    awk '{sub(/.*\) /,""); print $47 - $46, $49 - $48}' "/proc/$1/stat" 2>/dev/null
}
have_root=no
sudo -n true 2>/dev/null && have_root=yes
spans_root() {
    sudo -n awk '{sub(/.*\) /,""); print $47 - $46, $49 - $48}' "/proc/$1/stat" 2>/dev/null
}

# ------------------------------------------------- S1: the default shape
"$TOOL" -q -l "$L" -- "$CASES" sleeper QAMARK >/dev/null 2>&1 &
SUP=$!
sleep 0.9
if ! kill -0 "$SUP" 2>/dev/null; then
    fail "s1-self-mask-shape (supervisor $SUP is gone)"
    SUP=""
else
    comm=$(cat "/proc/$SUP/comm" 2>/dev/null)
    cmdline=$(tr '\0' '|' < "/proc/$SUP/cmdline" 2>/dev/null)
    read -r self_as self_es <<EOT
$(spans_self "$SUP")
EOT
    # The tracer task is the narrow part: a process can set its own
    # PR_SET_NAME and PR_SET_MM_MAP, but the session is also a second
    # thread of the supervisor.  Its name is issue 38's channel (asserted
    # there); here it only has to be present and to carry the label, which
    # is the shape this issue measures.
    tracer=no
    for t in /proc/"$SUP"/task/*; do
        [ "$(basename "$t")" = "$SUP" ] && continue
        [ "$(cat "$t/comm" 2>/dev/null)" = "$L" ] && tracer=yes
    done
    if [ "$comm" = "$L" ] && [ "$cmdline" = "$L|" ] \
        && [ "$self_as" = 0 ] && [ "$self_es" = 0 ] && [ "$tracer" = yes ]; then
        pass "s1-self-mask-shape (comm=$comm cmdline=$cmdline self=$self_as/$self_es tracer=$tracer)"
    else
        fail "s1-self-mask-shape (comm=$comm cmdline=$cmdline self=$self_as/$self_es tracer=$tracer)"
    fi
    if [ "$have_root" = no ]; then
        echo "SKIP s1b-self-mask-window (no passwordless sudo: a same-uid reader sees zeros by design)"
    else
        read -r root_as root_es <<EOT
$(spans_root "$SUP")
EOT
        if [ "$root_as" = "$(( ${#L} + 1 ))" ] && [ "$root_es" = 0 ]; then
            pass "s1b-self-mask-window (root: argspan=$root_as envspan=$root_es)"
        else
            fail "s1b-self-mask-window (root: argspan=$root_as envspan=$root_es, want $(( ${#L} + 1 )) and 0)"
        fi
    fi
fi

# ------------------------------- S2: non-dumpable supervisor
# PR_SET_DUMPABLE=0 is what makes a same-uid observer get EACCES on
# exe/environ/maps.  That refusal is itself the second half of the shape.
if [ -n "$SUP" ]; then
    if [ -r "/proc/$SUP/environ" ] && [ -s "/proc/$SUP/environ" ]; then
        fail "s2-supervisor-non-dumpable (environ readable: $(wc -c < "/proc/$SUP/environ") bytes)"
    else
        pass "s2-supervisor-non-dumpable"
    fi
    kill "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
    SUP=""
fi

# ------------------------ S3/S4: control, the escape on the plain path
# Without the fix the observer can see the value: this is the negative
# control that makes S5's warning mean something.  The plain path is the
# one that honours the escape the whole run; the redact path re-masks
# after the fork and is covered by S6.
env PMASK_NO_SELFMASK=1 "$TOOL" -q -l "$L" --no-redact --allow-argv-secret \
    -- "$CASES" sleeper QAMARK >/dev/null 2>&1 &
SUP=$!
sleep 0.9
if kill -0 "$SUP" 2>/dev/null; then
    argv=$(tr '\0' ' ' < "/proc/$SUP/cmdline" 2>/dev/null)
    case "$argv" in
        *QAMARK*) pass "s3-control-no-selfmask-serves-real-argv" ;;
        *) fail "s3-control-no-selfmask-serves-real-argv (argv=[$argv])" ;;
    esac
    kill "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
else
    fail "s3-control-no-selfmask-serves-real-argv (supervisor gone)"
fi
SUP=""

env PMASK_NO_SELFMASK=1 "$TOOL" -q -l "$L" --no-redact --allow-argv-secret \
    --secret T=literal:"$SECRET" -- "$CASES" sleeper QAMARK >/dev/null 2>&1 &
SUP=$!
# The escape leaves this process's own argv real for the whole run, so the
# value appears as soon as it is exec'd.  Poll for it: on a loaded host
# the single sample below could land in the fork/exec window.
s4_i=0
argv=""
while [ "$s4_i" -lt 40 ]; do
    argv=$(tr '\0' ' ' < "/proc/$SUP/cmdline" 2>/dev/null)
    case "$argv" in
        *"$SECRET"*) break ;;
    esac
    kill -0 "$SUP" 2>/dev/null || break
    sleep 0.05 2>/dev/null || sleep 1
    s4_i=$((s4_i + 1))
done
case "$argv" in
    *"$SECRET"*) pass "s4-control-literal-secret-readable-in-argv" ;;
    *) fail "s4-control-literal-secret-readable-in-argv (argv=[$argv])" ;;
esac
pay=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
[ -n "$pay" ] && kill -9 "$pay" 2>/dev/null
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""

# ------------------------------- S5: the warning, plain, literal source
err="$D/s5.err"
PMASK_NO_SELFMASK=1 "$TOOL" -l "$L" --no-redact --allow-argv-secret \
    --secret T=literal:"$SECRET" -- "$CASES" sleeper QAMARK >/dev/null 2>"$err" &
SUP=$!
sleep 0.9
alive=no
kill -0 "$SUP" 2>/dev/null && alive=yes
warn=$(grep -c 'PMASK_NO_SELFMASK=1 leaves' "$err" 2>/dev/null)
named=$(grep -c "'T' (literal:)" "$err" 2>/dev/null)
fdhint=$(grep -c 'args-from-fd' "$err" 2>/dev/null)
if [ "$warn" = 1 ] && [ "$named" = 1 ] && [ "$fdhint" = 1 ] && [ "$alive" = yes ]; then
    pass "s5-literal-warns-once-names-exposure (warn=$warn named=$named fd=$fdhint)"
else
    fail "s5-literal-warns-once-names-exposure (warn=$warn named=$named fd=$fdhint alive=$alive)"
fi
# S11 (liveness): the payload must be alive and functional despite the
# warning; a warning that kills the run would be a feature removal.  The
# plain path does not redact, so the label is not on the payload's comm:
# the check is that the supervisor still has a live child whose argv is
# the real one.
if [ "$alive" = yes ]; then
    pay=$(pgrep -P "$SUP" | head -n 1)
    argv=""
    [ -n "$pay" ] && argv=$(tr '\0' ' ' < "/proc/$pay/cmdline" 2>/dev/null)
    case "$argv" in
        *QAMARK*)
            pass "s11-warned-run-still-supervises (payload=$pay alive)" ;;
        *)
            fail "s11-warned-run-still-supervises (payload=[$pay] argv=[$argv])" ;;
    esac
else
    fail "s11-warned-run-still-supervises (supervisor died)"
fi
pay=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
[ -n "$pay" ] && kill -9 "$pay" 2>/dev/null
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""

# ------------------- S6: redact mode says the escape is overridden
err="$D/s6.err"
PMASK_NO_SELFMASK=1 HUSH="$SECRET" "$TOOL" -l "$L" --secret T=env:HUSH \
    -- "$CASES" sleeper QAMARK >/dev/null 2>"$err" &
SUP=$!
sleep 0.9
warn=$(grep -c 'is overridden in redact mode' "$err" 2>/dev/null)
named=$(grep -c "'T' (env:)" "$err" 2>/dev/null)
if [ "$warn" = 1 ] && [ "$named" = 1 ]; then
    pass "s6-redact-mode-says-overridden (warn=$warn named=$named)"
else
    fail "s6-redact-mode-says-overridden (warn=$warn named=$named; $(tr '\n' '|' < "$err"))"
fi
pay=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
[ -n "$pay" ] && kill -9 "$pay" 2>/dev/null
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""

# --------------------------------- S7: no secret, no warning
err="$D/s7.err"
PMASK_NO_SELFMASK=1 "$TOOL" -l "$L" -- "$CASES" sleeper QAMARK >/dev/null 2>"$err" &
SUP=$!
sleep 0.9
pay=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
[ -n "$pay" ] && kill -9 "$pay" 2>/dev/null
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
warn=$(grep -c 'PMASK_NO_SELFMASK=1' "$err" 2>/dev/null)
if [ "$warn" = 0 ]; then
    pass "s7-no-secret-no-warning"
else
    fail "s7-no-secret-no-warning (warn=$warn; $(tr '\n' '|' < "$err"))"
fi

# ------------------- S8/S9/S10: the audit-reachable refusal and its escape
# PMASK_PROBE_AUDIT=1 is the test hook that reports a reachable audit
# subsystem, so this is decided on any host (this container blocks the
# real one; see evidence/bteam1/39/audit-probe.log).
out=$(PMASK_NO_SELFMASK=1 PMASK_PROBE_AUDIT=1 "$TOOL" -q -l "$L" --no-redact \
    --secret T=literal:"$SECRET" -- "$CASES" sleeper QAMARK 2>&1)
rc=$?
if [ "$rc" = 255 ]; then
    case "$out" in
        *"audit subsystem is reachable"*) pass "s8-audit-reachable-refuses" ;;
        *) fail "s8-audit-reachable-refuses (rc=$rc message=[$out])" ;;
    esac
else
    fail "s8-audit-reachable-refuses (rc=$rc, want 255; [$out])"
fi

out=$(PMASK_NO_SELFMASK=1 PMASK_PROBE_AUDIT=1 "$TOOL" -q -l "$L" --no-redact \
    --allow-argv-secret --secret T=literal:"$SECRET" -- "$CASES" sleepfor 0 2>&1)
rc=$?
case "$out" in
    *"audit subsystem is reachable"*)
        fail "s9-allow-argv-secret-runs (still refused: [$out])" ;;
    *)
        [ "$rc" = 0 ] && pass "s9-allow-argv-secret-runs" \
            || fail "s9-allow-argv-secret-runs (rc=$rc; [$out])" ;;
esac

err="$D/s10.err"
PMASK_NO_SELFMASK=1 PMASK_PROBE_AUDIT=1 "$TOOL" -l "$L" --no-redact \
    --allow-argv-secret --secret T=literal:"$SECRET" \
    -- "$CASES" sleeper QAMARK >/dev/null 2>"$err" &
SUP=$!
sleep 0.9
warn=$(grep -c 'PMASK_NO_SELFMASK=1 leaves' "$err" 2>/dev/null)
pay=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
[ -n "$pay" ] && kill -9 "$pay" 2>/dev/null
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
if [ "$warn" = 1 ]; then
    pass "s10-allow-argv-secret-still-warns"
else
    fail "s10-allow-argv-secret-still-warns (warn=$warn; $(tr '\n' '|' < "$err"))"
fi

echo "== QA39: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
[ "$FAIL" = 0 ] || exit 1
exit 0
