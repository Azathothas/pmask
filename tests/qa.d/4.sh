#!/bin/sh
# QA fragment for issue 4: `--unshare` / `--redact --isolate` silently
# disabled redaction.
#
# The defect: the child/tracer handshake was `libc::raise(SIGSTOP)` in the
# child.  A `--unshare` child is pid 1 of its own pid namespace, and the
# kernel discards a job-control stop such a process sends itself.  The
# stop never arrived, `wait_master_stop()` returned whatever stop came
# next, and `supervise()` returned without redacting anything: the payload
# kept its real cmdline, environ and comm.
#
# This fragment asserts, from the host, that a `--unshare` payload shows
# the label in cmdline and comm, zero bytes of environ, is still alive, and
# is init of a private pid namespace.  `--redact --isolate` is the
# composed spelling and gets the same assertions.
#
# A SKIP is printed when the kernel refuses user namespaces; the run then
# falls back to a plain fork and the case is undecidable here.
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
T="${TMPDIR:-/tmp}/qa4.$$"
mkdir -p "$T" || { echo "FAIL qa4-cannot-create-tmp"; exit 1; }

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    kill_label qa4 KILL 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT

# Does this kernel give us unprivileged user namespaces at all?
if ! unshare -Urn true 2>/dev/null; then
    skip "qa4-unshare-available (unshare -Urn true refused here)"
    exit 0
fi

MARK="QA4MARK$$"

# payload_pid LABEL -> the pid of the payload process (comm == LABEL and
# an exe that is not pmask itself).  The supervisor carries the label too,
# so the exe filter is what separates them.
payload_pid() {
    pp_label="$1"
    pp_want=""
    pp_n=0
    while [ "$pp_n" -lt 40 ]; do
        for d in /proc/[0-9]*; do
            pp=${d#/proc/}
            [ "$pp" = "$$" ] && continue
            [ "$(cat "$d/comm" 2>/dev/null)" = "$pp_label" ] || continue
            case "$(readlink "$d/exe" 2>/dev/null)" in
                */pmask|*/pmaskd|"") continue ;;
            esac
            pp_want=$pp
            break
        done
        [ -n "$pp_want" ] && break
        pp_n=$((pp_n + 1))
        sleep 0.1
    done
    echo "$pp_want"
}

# nspid_last PID -> the pid of PID in its innermost pid namespace.
# `/proc/<pid>/status` `NSpid:` lists the pid in every namespace, outermost
# first; a payload that is init of a private namespace ends in `1`.
nspid_last() {
    sed -n 's/^NSpid:[[:space:]]*//p' "/proc/$1/status" 2>/dev/null |
        awk '{print $NF}'
}

# check_payload NAME LABEL PID
check_payload() {
    cp_name="$1"
    cp_label="$2"
    cp_pid="$3"
    if [ -z "$cp_pid" ]; then
        fail "$cp_name-payload-found (no pid with comm $cp_label)"
        return
    fi
    cp_cmd=$(tr '\0' '|' < "/proc/$cp_pid/cmdline" 2>/dev/null)
    cp_com=$(cat "/proc/$cp_pid/comm" 2>/dev/null)
    cp_envsz=$(wc -c < "/proc/$cp_pid/environ" 2>/dev/null | tr -d ' ')

    if [ "$cp_cmd" = "$cp_label|" ]; then
        pass "$cp_name-cmdline-is-label"
    else
        fail "$cp_name-cmdline-is-label (cmdline=[$cp_cmd] want=[$cp_label|])"
    fi
    if [ "$cp_envsz" = "0" ]; then
        pass "$cp_name-environ-empty"
    else
        fail "$cp_name-environ-empty (environ=[$cp_envsz] bytes)"
    fi
    if [ "$cp_com" = "$cp_label" ]; then
        pass "$cp_name-comm-is-label"
    else
        fail "$cp_name-comm-is-label (comm=[$cp_com] want=[$cp_label])"
    fi
    # The argument the payload was given is not visible.
    case "$cp_cmd" in
        *"$MARK"*) fail "$cp_name-marker-not-in-cmdline (argument is visible)" ;;
        *) pass "$cp_name-marker-not-in-cmdline" ;;
    esac
    # Alive: not a zombie and not gone.
    cp_state=$(sed -n 's/^State:[[:space:]]*//p' "/proc/$cp_pid/status" 2>/dev/null)
    case "$cp_state" in
        ""|[Zz]*) fail "$cp_name-payload-alive (state=[$cp_state])" ;;
        *) pass "$cp_name-payload-alive" ;;
    esac
}

# run_case NAME LABEL [OPTIONS...]
run_case() {
    rc_name="$1"
    rc_label="$2"
    shift 2
    ( "$TOOL" -l "$rc_label" "$@" -- /bin/sh -c "sleep 30" "$MARK" \
        >"$T/$rc_name.out" 2>"$T/$rc_name.err" ) &
    rc_sup=$!
    rc_pid=$(payload_pid "$rc_label")

    check_payload "$rc_name" "$rc_label" "$rc_pid"

    # The namespace is private and the payload is its init: NSpid ends in
    # 1 and the namespace id differs from the observer's.
    rc_ns=$(readlink "/proc/$rc_pid/ns/pid" 2>/dev/null)
    rc_hostns=$(readlink "/proc/self/ns/pid" 2>/dev/null)
    rc_last=$(nspid_last "$rc_pid")
    if [ "$rc_last" = "1" ]; then
        pass "$rc_name-is-pid1"
    else
        fail "$rc_name-is-pid1 (NSpid ends in [$rc_last])"
    fi
    if [ -n "$rc_ns" ] && [ "$rc_ns" != "$rc_hostns" ]; then
        pass "$rc_name-private-pidns"
    else
        fail "$rc_name-private-pidns (payload ns=[$rc_ns] host ns=[$rc_hostns])"
    fi

    kill -9 "$rc_sup" "$rc_pid" 2>/dev/null
    wait "$rc_sup" 2>/dev/null
}

# ---- control: the plain mask path redacts the same payload.  Without it
# ---- a "label visible" result above could come from the observer, not
# ---- from the handshake.
( "$TOOL" -q -l qa4ctl -- /bin/sh -c 'sleep 30' "$MARK" \
    >"$T/ctl.out" 2>"$T/ctl.err" ) &
CTL_SUP=$!
CTL_PID=$(payload_pid qa4ctl)
check_payload qa4-control-plain qa4ctl "$CTL_PID"
kill -9 "$CTL_SUP" "$CTL_PID" 2>/dev/null
wait "$CTL_SUP" 2>/dev/null

# ---- negative control: without any mask the marker IS visible.  A run
# ---- that never saw the marker would make every absence vacuous.
MARK_OUT=$("$TOOL" -q --no-redact -- /bin/sh -c 'tr "\0" "|" < /proc/self/cmdline' "$MARK" 2>/dev/null)
case "$MARK_OUT" in
    *"$MARK"*) pass qa4-negative-control-marker-visible ;;
    *) fail "qa4-negative-control-marker-visible (no-redact cmdline=[$MARK_OUT])" ;;
esac

# ---- the two real cases
run_case qa4-unshare qa4uns --unshare
run_case qa4-isolate qa4iso --redact --isolate

# ---- the mechanism: the handshake is the tracer's own PTRACE_INTERRUPT
# ---- stop, not a stop the child sent itself.  This is the property that
# ---- makes the outcome above hold on a kernel that discards a namespace
# ---- init's self-stop, and it is checkable on a kernel that does not.
# ---- A run whose handshake is the child's SIGSTOP reports the other
# ---- string, so this case fails on a build that still raises it.
out=$("$TOOL" -v -l qa4hs --unshare -- /bin/true 2>&1)
case "$out" in
    *"handshake is the PTRACE_INTERRUPT stop"*)
        pass qa4-handshake-is-tracer-interrupt ;;
    *)
        fail "qa4-handshake-is-tracer-interrupt (verbose handshake line absent)" ;;
esac

exit "$FAIL"
