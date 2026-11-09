#!/bin/sh
# Issue 44: `--no-dumpable` answers EACCES on five files and zeroes the
# four stat fields 48-51.
#
# What is asserted, and why it needs both halves:
#
#   44a  control: the same payload without --no-dumpable is readable
#        through open() on environ, maps, auxv, exe and fd.  Without this
#        row a refusal in 44b could be a property of the host, of the
#        observer or of a dead payload.
#   44b  with --no-dumpable every one of the five open()s is refused, and
#        cmdline, comm and stat still open (the refusal is the fingerprint,
#        so the rest of the entry must stay readable for the pair to be
#        discriminating at all).
#   44c  stat fields 48-51 read 0 0 0 0 with the flag and are not zero
#        without it.  The zeros alone are not specific (issue 44 measured
#        twelve such processes with no pmask running), so this row is
#        reported together with 44b, never on its own.
#   44d  the `[ -r ]` trap: access(2) and open(2) can disagree.  The
#        fragment records both and asserts that the open() answer is the
#        one the detector must use.  A host where they agree is a PASS
#        that says so; it is not a SKIP, because the open() answer is
#        always available.
#   44e  liveness: the payload was alive while 44b ran, so 44b is not
#        the EACCES of a process that had already died.
#   44f  the supervisor is in the same refused set and runs a
#        `pmask-tracer` thread: the tree relation the issue names as the
#        specific pair.
#   44g  a mode that cannot apply the flag says so: `--no-redact
#        --no-dumpable` prints the note and leaves the payload dumpable.
#        This is the note half of issue 44; issue 21 owns the report
#        field, so this row asserts the note and the measured
#        dumpability, not `payload_dumpable`.
#
# Nothing here changes `payload_dumpable`; issue 21 (fix2) owns that.
set -u
# lib.sh reads BIN_DIR from the cwd, so run from tests/ (see its header).
cd "$(dirname "$0")/.." || exit 2
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

LABEL="qa44-$$"
T=$(mktemp -d "${TMPDIR:-/tmp}/qa44.XXXXXX") || {
    echo "FATAL: mktemp -d failed"
    exit 2
}
SUP=""
PAY=""
cleanup() {
    [ -n "$SUP" ] && kill -9 "$SUP" 2>/dev/null
    [ -n "$PAY" ] && kill -9 "$PAY" 2>/dev/null
    kill_label "$LABEL" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

# open_ok PATH: exit 0 only when open() succeeds.  A shell redirection is
# open(2); `test -r` is access(2), which the kernel answers differently
# for a non-dumpable tracee (the issue's own warning).
open_ok() { ( : < "$1" ) 2>/dev/null; }

# access_ok PATH: the `[ -r ]` answer, recorded only to compare.
access_ok() { [ -r "$1" ] 2>/dev/null; }

# stat48_51 PID: the four fields, space separated.
stat48_51() {
    sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f46-49 |
        tr -s ' '
}

# await_child SUP: print the pid of SUP's direct child, waiting up to 6 s.
# The tree walk is PPid-based; `pgrep` would match any other sleep on the
# host, and other agents run suites on this machine.
await_child() {
    a_i=0
    while [ "$a_i" -lt 60 ]; do
        for d in /proc/[0-9]*; do
            a_pid=${d#/proc/}
            a_pp=$(sed -n 's/^PPid:[[:space:]]*\([0-9]*\).*/\1/p' \
                "$d/status" 2>/dev/null)
            if [ "$a_pp" = "$1" ]; then
                echo "$a_pid"
                return 0
            fi
        done
        sleep 0.1
        a_i=$((a_i + 1))
    done
    return 1
}

# five_files PID: "name=ok|denied ..." for the issue's five paths.
five_files() {
    ff_out=""
    for ff_f in environ maps auxv exe fd; do
        if open_ok "/proc/$1/$ff_f"; then
            ff_out="$ff_out $ff_f=ok"
        else
            ff_out="$ff_out $ff_f=denied"
        fi
    done
    echo "$ff_out"
}

# refused_count "name=ok|denied ...": how many of the five are refused.
refused_count() {
    rc_n=0
    for rc_t in $1; do
        case "$rc_t" in
            *=denied) rc_n=$((rc_n + 1)) ;;
        esac
    done
    echo "$rc_n"
}

# ------------------------------------------------------------ the control
# Same payload, no flag.  This is the negative control for 44b.
"$TOOL" -q -l "$LABEL" -- /bin/sleep 30 >/dev/null 2>"$T/ctl.err" &
SUP=$!
PAY=$(await_child "$SUP") || PAY=""
if [ -z "$PAY" ]; then
    fail "44a-control-readable (no payload under supervisor $SUP: $(head -1 "$T/ctl.err"))"
    fail "44b-nodumpable-refuses-five (no control payload, so the row is undecidable)"
    fail "44c-stat-zeros (no control payload, so the row is undecidable)"
    skip "44d-access-vs-open (no payload)"
    skip "44e-payload-stayed-alive (no payload)"
    skip "44f-supervisor-in-the-same-set (no payload)"
else
    CTL=$(five_files "$PAY")
    CTL_REFUSED=$(refused_count "$CTL")
    CTL_ZEROS=$(stat48_51 "$PAY")
    CTL_CMDLINE=$(tr '\0' '|' < "/proc/$PAY/cmdline" 2>/dev/null)
    if [ "$CTL_REFUSED" = 0 ]; then
        pass "44a-control-readable$CTL"
    else
        fail "44a-control-readable ($CTL_REFUSED of 5 refused without --no-dumpable:$CTL)"
    fi
    case "$CTL_ZEROS" in
        "0 0 0 0") fail "44c-control-stat-not-zero (stat48_51=$CTL_ZEROS)" ;;
        "") fail "44c-control-stat-not-zero (stat unreadable)" ;;
        *) pass "44c-control-stat-not-zero (stat48_51=$CTL_ZEROS)" ;;
    esac
    if [ -n "$CTL_CMDLINE" ]; then
        pass "44-control-payload-visible (cmdline=[$CTL_CMDLINE])"
    fi
    kill -9 "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
    SUP=""
    PAY=""
fi

# ------------------------------------------------------- the flag's shape
"$TOOL" -q -l "$LABEL" --no-dumpable -- /bin/sleep 30 \
    >/dev/null 2>"$T/nd.err" &
SUP=$!
PAY=$(await_child "$SUP") || PAY=""
if [ -z "$PAY" ]; then
    fail "44b-nodumpable-refuses-five (no payload under supervisor $SUP: $(head -1 "$T/nd.err"))"
    fail "44c-stat-zeros (no payload)"
    skip "44d-access-vs-open (no payload)"
    skip "44e-payload-stayed-alive (no payload)"
    skip "44f-supervisor-in-the-same-set (no payload)"
else
    ND=$(five_files "$PAY")
    ND_REFUSED=$(refused_count "$ND")
    ND_ZEROS=$(stat48_51 "$PAY")
    if [ "$ND_REFUSED" = 5 ]; then
        pass "44b-nodumpable-refuses-five$ND"
    else
        fail "44b-nodumpable-refuses-five ($ND_REFUSED of 5 refused:$ND)"
    fi

    # The rest of the entry must stay readable, or the EACCES set is not
    # the discriminating pair the detector needs.
    ro=""
    for f in cmdline comm stat status; do
        if open_ok "/proc/$PAY/$f"; then ro="$ro $f=ok"; else ro="$ro $f=denied"; fi
    done
    case "$ro" in
        *denied*) fail "44b-rest-of-the-entry-readable ($ro)" ;;
        *) pass "44b-rest-of-the-entry-readable$ro" ;;
    esac

    case "$ND_ZEROS" in
        "0 0 0 0") pass "44c-stat-zeros (stat48_51=$ND_ZEROS)" ;;
        "") fail "44c-stat-zeros (stat unreadable)" ;;
        *) fail "44c-stat-zeros (stat48_51=$ND_ZEROS, want 0 0 0 0)" ;;
    esac

    # 44d: access(2) versus open(2).  The row asserts the open() answer
    # and records whether the host also lets `[ -r ]` say yes, which is
    # the trap the issue warns about.
    trap_hit=0
    cmp_out=""
    for f in environ maps auxv exe fd; do
        if access_ok "/proc/$PAY/$f"; then
            cmp_out="$cmp_out $f=access-yes"
            trap_hit=$((trap_hit + 1))
        else
            cmp_out="$cmp_out $f=access-no"
        fi
    done
    if [ "$trap_hit" -gt 0 ]; then
        pass "44d-access-vs-open (open() refused all five; access() disagrees on $trap_hit:$cmp_out)"
    else
        pass "44d-access-vs-open (open() and access() agree here:$cmp_out)"
    fi

    # 44e: liveness.  The payload must still be alive after every
    # observation above, so none of those refusals is the EACCES of a
    # process that had already died.
    if kill -0 "$PAY" 2>/dev/null; then
        pass "44e-payload-alive-under-the-flag"
    else
        fail "44e-payload-alive-under-the-flag (pid $PAY is gone)"
    fi

    # 44f: the supervisor and its tracer thread.
    SUP_SET=$(five_files "$SUP")
    SUP_REFUSED=$(refused_count "$SUP_SET")
    if [ "$SUP_REFUSED" = 5 ]; then
        pass "44f-supervisor-in-the-same-set$SUP_SET"
    else
        fail "44f-supervisor-in-the-same-set ($SUP_REFUSED of 5 refused:$SUP_SET)"
    fi
    tracer=0
    for t in /proc/"$SUP"/task/*; do
        case "$(cat "$t/comm" 2>/dev/null)" in
            pmask-tracer*) tracer=$((tracer + 1)) ;;
        esac
    done
    if [ "$tracer" -ge 1 ]; then
        pass "44f-tracer-thread-named (pmask-tracer x$tracer)"
    else
        fail "44f-tracer-thread-named (no pmask-tracer thread under $SUP)"
    fi
    kill -9 "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
    SUP=""
    PAY=""
fi

# ------------------------------------------- 44g: a mode that cannot apply it
# `--no-dumpable` is a redaction-mode treatment.  In plain mode the run
# must say so rather than let the report imply it happened.  The report
# field itself is issue 21's; this row asserts the note and the measured
# dumpability of the payload.
out=$("$TOOL" --no-redact --no-dumpable -- /bin/true 2>&1)
rc=$?
case "$out" in
    *"--no-dumpable was not applied"*"plain mode"*)
        note=$(printf '%s' "$out" | sed -n 's/^pmask: note: //p' | head -1 | cut -c1-60)
        pass "44g-plain-mode-note ($note)" ;;
    *)
        fail "44g-plain-mode-note (rc=$rc out=$(printf '%s' "$out" | tr '\n' '|'))" ;;
esac
out=$("$TOOL" --isolate --no-dumpable -- /bin/true 2>&1)
case "$out" in
    *"--no-dumpable was not applied"*"isolate mode"*)
        pass "44g-isolate-mode-note" ;;
    *)
        fail "44g-isolate-mode-note (out=$(printf '%s' "$out" | tr '\n' '|'))" ;;
esac

# The measured half: in plain mode the payload actually is dumpable, so
# the note is true.  A C probe is the only portable way to read
# PR_GET_DUMPABLE; without a compiler the row is a named SKIP.
if command -v cc >/dev/null 2>&1; then
    cat > "$T/dumpable.c" <<'C'
#include <sys/prctl.h>
#include <stdio.h>
int main(void) {
    printf("%d\n", prctl(PR_GET_DUMPABLE, 0, 0, 0, 0));
    return 0;
}
C
    if cc -o "$T/dumpable" "$T/dumpable.c" 2>"$T/cc.err"; then
        d=$("$T/dumpable" 2>/dev/null)
        [ "$d" = 1 ] && pass "44g-plain-payload-is-dumpable (PR_GET_DUMPABLE=1)" \
            || fail "44g-plain-payload-is-dumpable (PR_GET_DUMPABLE=$d, want 1)"
        d=$("$TOOL" -q --no-dumpable -- "$T/dumpable" 2>/dev/null)
        [ "$d" = 0 ] && pass "44g-redact-payload-is-not-dumpable (PR_GET_DUMPABLE=0)" \
            || fail "44g-redact-payload-is-not-dumpable (PR_GET_DUMPABLE=$d, want 0)"
    else
        skip "44g-plain-payload-is-dumpable (cc cannot link: $(head -1 "$T/cc.err"))"
    fi
else
    skip "44g-plain-payload-is-dumpable (no compiler, so PR_GET_DUMPABLE cannot be read)"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
