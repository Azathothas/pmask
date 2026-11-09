#!/bin/sh
# QA fragment for issue 60: `--watch-rename` and `--no-dumpable` together
# cannot redirect a rename.
#
# The defect: the redirect wrote a fresh label copy into the tracee
# (`process_vm_writev`, then `PTRACE_POKEDATA`).  A non-dumpable tracee
# refuses both to a non-root tracer, so the write failed, the tracer
# printed `cannot redirect a rename to the label` and continued, and the
# payload's own `prctl(PR_SET_NAME, "evil-name")` took effect: `comm`
# became the payload's chosen name while `cmdline` stayed the label.
#
# The fix points the trapped name argument at the label copy the completion
# stop already leaves in the tracee's presentation block, so the redirect
# needs no write at all.  If no usable block exists the rename is refused
# (EFAULT) rather than let through, and the session summary counts it.
#
# The name is read from /proc by this fragment, not taken from anything the
# payload prints: the payload's own report is the control, not the claim.
#
# Cases:
#   qa60-both-comm-is-label    --watch-rename --no-dumpable: comm == label
#   qa60-both-cmdline-is-label cmdline stays the label
#   qa60-both-payload-alive    the payload is alive after its rename
#   qa60-control-plain         without the flags the rename lands
#                              (`evil-name`): the payload really renames
#   qa60-watch-only            --watch-rename alone still keeps the label
#   qa60-unshare-both          the same under --unshare (the pair composes)
#   qa60-no-warning            the old warning-and-continue path is gone:
#                              with the fix no "cannot redirect" line is
#                              printed for an ordinary run
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa60.XXXXXX") || {
    echo "FAIL qa60-cannot-create-tmp"; exit 2
}
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

cleanup() {
    kill_label qa60 KILL 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT

# child_of SUP -> the direct child of SUP.
#
# The payload is found through its parent, not through its `comm` and its
# `exe`.  Under `--no-dumpable` a same-uid observer cannot read `exe` at
# all, and the supervisor carries the label as its own `comm`, so neither
# of those separates the two.  `PPid` does, and `/proc/<pid>/status` stays
# readable for a non-dumpable process.
child_of() {
    co_n=0
    co_want=""
    while [ "$co_n" -lt 40 ]; do
        for d in /proc/[0-9]*; do
            cp=${d#/proc/}
            [ "$cp" = "$$" ] && continue
            [ "$(sed -n 's/^PPid:[[:space:]]*//p' "$d/status" 2>/dev/null)" = "$1" ] || continue
            co_want=$cp
            break
        done
        [ -n "$co_want" ] && break
        co_n=$((co_n + 1))
        sleep 0.1
    done
    echo "$co_want"
}

# run_rename NAME LABEL SECONDS [OPTIONS...]
run_rename() {
    rn_name="$1"
    rn_label="$2"
    rn_secs="$3"
    shift 3
    # No `-q` on purpose: the old warning-and-continue path printed
    # `cannot redirect a rename to the label` at the default verbosity, and
    # the fragment has to be able to see it.
    ( "$TOOL" -l "$rn_label" "$@" -- "$CASES" evilrename "$rn_secs" \
        >"$D/$rn_name.out" 2>"$D/$rn_name.err" ) &
    rn_sup=$!
    # `evilrename` sleeps 300ms before the rename; wait for the rename to
    # have happened by polling the payload's own output line.
    rn_n=0
    while [ "$rn_n" -lt 40 ]; do
        grep -q '^rename-rc=' "$D/$rn_name.out" 2>/dev/null && break
        rn_n=$((rn_n + 1))
        sleep 0.1
    done
    RUN_SUP=$rn_sup
    RUN_PID=$(child_of "$rn_sup")
    [ -n "$RUN_PID" ] || RUN_PID=""
}

check_kept() {  # check_kept NAME LABEL PID
    ck_name="$1"
    ck_label="$2"
    ck_pid="$3"
    if [ -z "$ck_pid" ]; then
        fail "$ck_name-payload-found (no testcase process with comm $ck_label)"
        return
    fi
    ck_comm=$(cat "/proc/$ck_pid/comm" 2>/dev/null)
    ck_cmd=$(tr '\0' '|' < "/proc/$ck_pid/cmdline" 2>/dev/null)
    ck_state=$(sed -n 's/^State:[[:space:]]*//p' "/proc/$ck_pid/status" 2>/dev/null)
    if [ "$ck_comm" = "$ck_label" ]; then
        pass "$ck_name-comm-is-label"
    else
        fail "$ck_name-comm-is-label (comm=[$ck_comm] want=[$ck_label])"
    fi
    if [ "$ck_cmd" = "$ck_label|" ]; then
        pass "$ck_name-cmdline-is-label"
    else
        fail "$ck_name-cmdline-is-label (cmdline=[$ck_cmd])"
    fi
    case "$ck_state" in
        ""|[Zz]*) fail "$ck_name-payload-alive (state=[$ck_state])" ;;
        *) pass "$ck_name-payload-alive" ;;
    esac
}

# ---------------------------------------------------------- the flag pair
run_rename both qa60both 3 --watch-rename --no-dumpable
BOTH_SUP=$RUN_SUP
BOTH_PID=$RUN_PID
check_kept qa60-both qa60both "$BOTH_PID"
if grep -q 'cannot redirect a rename' "$D/both.err" 2>/dev/null; then
    fail "qa60-no-warning (the old warning-and-continue path fired: $(grep -m1 'cannot redirect' "$D/both.err"))"
else
    pass qa60-no-warning
fi
# The payload's own report is the control for "the rename was attempted and
# the kernel accepted it".
if grep -q '^rename-rc=0' "$D/both.out" 2>/dev/null; then
    pass qa60-both-rename-accepted
else
    fail "qa60-both-rename-accepted (payload: $(head -2 "$D/both.out" | tr '\n' ' '))"
fi
kill -9 "$BOTH_SUP" "$BOTH_PID" 2>/dev/null
wait "$BOTH_SUP" 2>/dev/null

# ------------------------------------- control: without the flags it lands
run_rename ctl qa60ctl 2
CTL_SUP=$RUN_SUP
CTL_PID=$RUN_PID
if [ -n "$CTL_PID" ]; then
    ctl_comm=$(cat "/proc/$CTL_PID/comm" 2>/dev/null)
else
    ctl_comm="<no pid>"
fi
if [ "$ctl_comm" = "evil-name" ]; then
    pass qa60-control-plain-rename-lands
else
    fail "qa60-control-plain-rename-lands (comm=[$ctl_comm] want=[evil-name]; the payload did not rename, so the case above proves nothing)"
fi
kill -9 "$CTL_SUP" "$CTL_PID" 2>/dev/null
wait "$CTL_SUP" 2>/dev/null

# ------------------------------------------------- --watch-rename alone
run_rename watch qa60watch 2 --watch-rename
W_SUP=$RUN_SUP
W_PID=$RUN_PID
check_kept qa60-watch qa60watch "$W_PID"
kill -9 "$W_SUP" "$W_PID" 2>/dev/null
wait "$W_SUP" 2>/dev/null

# ------------------------------------------------------- the pair + unshare
if unshare -Urn true 2>/dev/null; then
    run_rename ns qa60ns 2 --unshare --watch-rename --no-dumpable
    NS_SUP=$RUN_SUP
    NS_PID=$RUN_PID
    check_kept qa60-unshare qa60ns "$NS_PID"
    kill -9 "$NS_SUP" "$NS_PID" 2>/dev/null
    wait "$NS_SUP" 2>/dev/null
else
    echo "SKIP qa60-unshare (user namespaces refused here)"
fi

exit "$FAIL"
