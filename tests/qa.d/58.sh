#!/bin/sh
# Issue 58: the detector family that does not see pmask.
#
# The family is the rootkit / hidden-pid checkers.  Each compares two views
# of the pid space: a readdir listing, a `ps` table, a direct path, or a
# syscall that needs the pid to exist.  pmask never removes a pid from any
# of those views.  It keeps the pid, the `/proc/<pid>` directory, the parent
# chain and the `readdir` result, and rewrites the *contents* of three
# files.  So the family is blind by construction, and this fragment
# measures the blindness instead of asserting it.
#
# The tools are third-party.  This fragment does not install them and does
# not download anything: a QA case must not add software to a shared host.
# A case whose tool is absent prints SKIP with the `command not found`
# reason.  Set PMASK_QA_TOOLS=DIR to point at a directory of prebuilt
# tools; the evidence run used Debian-archive `.deb` extractions there.
#
# The discriminating assertion for a sweeper is not "the tool prints zero".
# This host's container itself produces a baseline of ids the tool calls
# hidden (measured: 43-47 with no pmask running, because it sees per-thread
# ids that ps does not list).  The assertion is that neither the payload's
# nor the supervisor's pid is in the tool's hidden set, and that the
# payload is alive and visible in all four existence views.
#
# Cases:
#   d1  masked payload seen in getdents64, readdir, stat and kill(0)
#   d2  control: an unmasked canary is seen in the same four
#   d3  sandfly-processdecloak: SKIP when absent
#   d4  unhide (sys / checkkill / checkgetprio): SKIP when absent
#   d5  chkproc: the pid set, not the bulk count, is the assertion
#   d6  rkhunter hidden_procs: SKIP when absent or silently skipped;
#       PMASK_QA_RKHUNTER_CONF names a config file for an extracted copy
#   d7  pspy: a content sampler; its sampling limit is the finding
#   d8  zapper: SKIP (a competitor, not a checker)
#   d9  lsrootkit: SKIP (its gid sweep is a container artefact)
#   d10 strace: the legitimate tracer; control attaches, masked refuses
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

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa58.XXXXXX") || {
    echo "FATAL: cannot create a temp dir"; exit 2
}
SUP=""
PAY=""
CANARY=""
stop() {
    eval "p=\${$1:-}"
    if [ -n "$p" ]; then
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null
        eval "$1=''"
    fi
}
cleanup() {
    stop SUP
    stop PAY
    stop CANARY
    kill_label qa58-
    rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Tools that shell out to their siblings (rkhunter's hidden_procs runs
# `unhide`) find them only through PATH, so a prebuilt directory is
# prepended once here rather than per case.
if [ -n "${PMASK_QA_TOOLS:-}" ]; then
    PATH="$PMASK_QA_TOOLS:$PATH"
    export PATH
fi

L=qa58-label
M=QA58CANARY

find_tool() {
    for cand in "$@"; do
        if [ -n "${PMASK_QA_TOOLS:-}" ] && [ -x "$PMASK_QA_TOOLS/$cand" ]; then
            echo "$PMASK_QA_TOOLS/$cand"
            return 0
        fi
        if command -v "$cand" >/dev/null 2>&1; then
            command -v "$cand"
            return 0
        fi
    done
    return 1
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
    while [ "$n" -lt 50 ]; do
        p=$(child_of "$1") && { echo "$p"; return 0; }
        n=$((n + 1))
        sleep 0.1 2>/dev/null || sleep 1
    done
    return 1
}

start_masked() {
    "$TOOL" -q -l "$L" -- "$CASES" sleeper "$M" >/dev/null 2>&1 &
    SUP=$!
    PAY=$(await_pid "$SUP") || PAY=""
}

start_canary() {
    "$CASES" sleeper "$M" >/dev/null 2>&1 &
    CANARY=$!
    sleep 0.4
}

# hidden_names FILE -> the pid set a tool printed as hidden, one per line.
hidden_names() {
    sed -n -e 's/^PID \([0-9][0-9]*\):.*/\1/p' \
           -e 's/^\([0-9][0-9]*\): .*/\1/p' "$1" 2>/dev/null | sort -u
}

in_hidden() {
    if hidden_names "$1" | grep -qx "$2"; then echo yes; else echo no; fi
}

# --------------------------------------------------- d1/d2: the views
start_masked
if [ -z "$PAY" ]; then
    fail "d1-masked-pid-has-all-four-views (no payload)"
else
    v=$("$CASES" procviews "$PAY" 2>/dev/null)
    case "$v" in
        *"getdents64=present readdir=present stat=present kill0=present"*)
            pass "d1-masked-pid-has-all-four-views ($v)" ;;
        *)
            fail "d1-masked-pid-has-all-four-views ($v)" ;;
    esac
    printf 'NOTE d1 masked payload comm=[%s] cmdline=[%s]; this family\n' \
        "$(cat "/proc/$PAY/comm" 2>/dev/null)" \
        "$(tr '\0' '|' < "/proc/$PAY/cmdline" 2>/dev/null)"
    printf '     never reads them, which is why it cannot fire\n'
fi
stop SUP
stop PAY

start_canary
v=$("$CASES" procviews "$CANARY" 2>/dev/null)
case "$v" in
    *"getdents64=present readdir=present stat=present kill0=present"*)
        pass "d2-control-unmasked-pid-has-the-same-views ($v)" ;;
    *)
        fail "d2-control-unmasked-pid-has-the-same-views ($v)" ;;
esac
stop CANARY

# ------------------------------------------------ d3: processdecloak
if find_tool sandfly-processdecloak processdecloak >/dev/null 2>&1; then
    skip "d3-processdecloak (present, but it takes no marker contract this fragment can drive; see docs/research/bteam-detectors.md)"
else
    skip "d3-processdecloak (sandfly-processdecloak: command not found)"
fi

# --------------------------------------------------------- d4: unhide
if bin=$(find_tool unhide unhide-linux); then
    start_masked
    if [ -z "$PAY" ]; then
        fail "d4-unhide-sees-no-pmaks-pid (no payload)"
    else
        "$bin" sys >"$D/unhide-sys.out" 2>&1
        "$bin" checkkill >"$D/unhide-kill.out" 2>&1
        "$bin" checkgetprio >"$D/unhide-prio.out" 2>&1
        sup_hidden=$(in_hidden "$D/unhide-sys.out" "$SUP")
        pay_hidden=$(in_hidden "$D/unhide-kill.out" "$PAY")
        prio_hidden=$(in_hidden "$D/unhide-prio.out" "$PAY")
        if [ "$sup_hidden" = no ] && [ "$pay_hidden" = no ] && [ "$prio_hidden" = no ]; then
            pass "d4-unhide-sees-no-pmaks-pid (sys=$sup_hidden checkkill=$pay_hidden checkgetprio=$prio_hidden)"
        else
            fail "d4-unhide-sees-no-pmaks-pid (sys=$sup_hidden checkkill=$pay_hidden checkgetprio=$prio_hidden)"
        fi
        if [ -s "$D/unhide-sys.out" ]; then
            pass "d4b-unhide-ran ($(wc -l < "$D/unhide-sys.out") lines of output)"
        else
            fail "d4b-unhide-ran (no output: the tool did not run)"
        fi
    fi
    stop SUP
    stop PAY
else
    skip "d4-unhide-sees-no-pmaks-pid (unhide: command not found)"
fi

# --------------------------------------------------------- d5: chkproc
if bin=$(find_tool chkproc); then
    start_masked
    if [ -z "$PAY" ]; then
        fail "d5-chkproc-does-not-name-the-payload (no payload)"
    else
        "$bin" -v -v -p 'ps -e' >"$D/chkproc.out" 2>&1
        sup_hidden=$(in_hidden "$D/chkproc.out" "$SUP")
        pay_hidden=$(in_hidden "$D/chkproc.out" "$PAY")
        total=$(sed -n 's/^You have \([0-9]*\) process(es) hidden from readdir(3)$/\1/p' \
            "$D/chkproc.out" | tail -1)
        if [ "$sup_hidden" = no ] && [ "$pay_hidden" = no ]; then
            pass "d5-chkproc-does-not-name-the-payload (payload=$pay_hidden supervisor=$sup_hidden bulk=$total)"
        else
            fail "d5-chkproc-does-not-name-the-payload (payload=$pay_hidden supervisor=$sup_hidden bulk=$total)"
        fi
        printf 'NOTE d5 bulk hidden count with one masked tree: %s; the\n' "${total:-unknown}"
        printf '     no-pmask baseline is in docs/research/bteam-detectors.md\n'
    fi
    stop SUP
    stop PAY
else
    skip "d5-chkproc-does-not-name-the-payload (chkproc: command not found)"
fi

# -------------------------------------------------------- d6: rkhunter
if bin=$(find_tool rkhunter); then
    # A system rkhunter reads /etc/rkhunter.conf itself.  An extracted copy
    # has no such file, so PMASK_QA_RKHUNTER_CONF points at one; without it
    # the tool exits before the test and the case is a SKIP.
    if [ -n "${PMASK_QA_RKHUNTER_CONF:-}" ]; then
        rkh_args="--configfile $PMASK_QA_RKHUNTER_CONF"
    else
        rkh_args=""
    fi
    # rkhunter refuses to run as a non-root user.  Use sudo when it is
    # available, and record a SKIP with that reason when it is not: a
    # privilege requirement is not a pass and not a failure of pmask.
    rkh_sudo=""
    if [ "$(id -u)" != 0 ]; then
        if sudo -n true 2>/dev/null; then
            # `sudo` resets PATH to secure_path, so the sibling `unhide`
            # rkhunter shells out to must be passed explicitly.
            rkh_sudo="sudo -n env PATH=$PATH"
        else
            skip "d6-rkhunter-hidden-procs (rkhunter refuses a non-root user and sudo is unavailable)"
            rkh_sudo="unusable"
        fi
    elif [ -n "${PMASK_QA_TOOLS:-}" ]; then
        rkh_sudo="env PATH=$PMASK_QA_TOOLS:$PATH"
    fi
    if [ "$rkh_sudo" = unusable ]; then
        out=""
    else
        out=$(# shellcheck disable=SC2086
            $rkh_sudo "$bin" --check --sk --nocolors --enable hidden_procs $rkh_args 2>&1 \
            | sed -n 's/.*Checking for hidden processes.*\[ \(.*\) \].*/hidden_procs=\1/p' | head -1)
    fi
    case "$out" in
        ""|*Skipped*)
            skip "d6-rkhunter-hidden-procs (test skipped: ${out:-no line}; it needs an unhide binary)" ;;
        *"None found"*)
            pass "d6-rkhunter-hidden-procs ($out)" ;;
        *)
            fail "d6-rkhunter-hidden-procs ($out)" ;;
    esac
else
    skip "d6-rkhunter-hidden-procs (rkhunter: command not found)"
fi

# ------------------------------------------------------------ d7: pspy
if bin=$(find_tool pspy); then
    "$bin" -p -f >"$D/pspy.out" 2>&1 &
    PSPY=$!
    sleep 0.5
    start_masked
    sleep 1.5
    stop SUP
    stop PAY
    kill "$PSPY" 2>/dev/null
    wait "$PSPY" 2>/dev/null
    if grep -q "$L" "$D/pspy.out" 2>/dev/null; then
        pass "d7-pspy-prints-the-label ($(grep -m1 "$L" "$D/pspy.out" | cut -c1-72))"
    else
        fail "d7-pspy-prints-the-label (no $L line; first lines: $(head -2 "$D/pspy.out" | tr '\n' '|'))"
    fi
else
    skip "d7-pspy-prints-the-label (pspy: command not found)"
fi

# ----------------------------------------------------- d8/d9: the rest
if find_tool zapper >/dev/null 2>&1; then
    skip "d8-zapper (present; it is a competing masking tool, not a checker: see docs/research/bteam-detectors.md)"
else
    skip "d8-zapper (zapper: command not found)"
fi
if find_tool lsrootkit >/dev/null 2>&1; then
    skip "d9-lsrootkit (present; its gid sweep is a container artefact here: see docs/research/bteam-detectors.md)"
else
    skip "d9-lsrootkit (lsrootkit: command not found)"
fi

# ---------------------------------------------------------- d10: strace
if command -v strace >/dev/null 2>&1; then
    start_canary
    ctl=$(timeout 4 strace -p "$CANARY" -o /dev/null -e trace=execve 2>&1 | head -1)
    stop CANARY
    start_masked
    msk=""
    [ -n "$PAY" ] && msk=$(timeout 4 strace -p "$PAY" -o /dev/null -e trace=execve 2>&1 | head -1)
    stop SUP
    stop PAY
    case "$ctl" in
        *attached*) ctl_ok=yes ;;
        *) ctl_ok=no ;;
    esac
    case "$msk" in
        *"Operation not permitted"*) msk_ok=yes ;;
        *) msk_ok=no ;;
    esac
    if [ "$ctl_ok" = yes ] && [ "$msk_ok" = yes ]; then
        pass "d10-strace-attaches-to-the-control-only (control=[$(printf '%s' "$ctl" | cut -c1-40)])"
    else
        fail "d10-strace-attaches-to-the-control-only (control=[$ctl] masked=[$msk])"
    fi
else
    skip "d10-strace-attaches-to-the-control-only (strace: command not found)"
fi

echo "== QA58: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
[ "$FAIL" = 0 ] || exit 1
exit 0
