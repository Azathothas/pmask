#!/bin/sh
# ============================================================================
# pmaskd: the job runs with the secret, and nothing on the machine can
# read it back out of /proc.
#
#   D1  negative control: a secret in a plain shell's environment IS
#       visible in /proc/<pid>/environ (the observer can detect it)
#   D2  the job started by the daemon receives the secret (length check,
#       so the value is never printed)
#   D3  while that job runs, the secret appears in no /proc cmdline or
#       environ: not the daemon's, not the client's, not the job's
#   D4  the daemon's own /proc entry carries the label, not its argv
#   D5  exit status and stdout pass through the daemon
#   D6  a job that cannot exec fails with 127 and the daemon survives it
#   D7  the CLI --secret path: one execve, the child's cmdline is the
#       label; D7b adds the same-uid environ view of the child and the
#       supervisor, with a plain process as the control
#       label, the sealed descriptor sits where the delivery pointer
#       names it, the value is in no /proc entry, the write is refused
#   D8  that descriptor, once the child has exec'd, is readable by a
#       same-uid process through /proc (the documented hazard)
#   D9  --help promises no /tmp socket fallback and names --socket
#   D11 a root daemon with --run-as-uid runs the job as the client, and
#       the control without the flag runs it as root
#       default verbosity (invariant 13), and --quiet is the opt-out
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

DAEMON="$BIN_DIR/pmaskd"
# The daemon refuses a socket in a directory it does not own, and /tmp
# belongs to root.  A private directory is what a real deployment uses.
# mktemp gives a name no other run can collide with, and the trap removes
# it on every exit path, including the early one below.
SOCKDIR=""
SOCK=""
ENVF=""
DPID=""
D3B_CLIENT=""
D7SUP=""
D7CHILD=""
RD_PID=""
cleanup() {
    [ -n "$DPID" ] && kill -9 "$DPID" 2>/dev/null
    [ -n "$D3B_CLIENT" ] && kill -9 "$D3B_CLIENT" 2>/dev/null
    [ -n "$D7SUP" ] && kill -9 "$D7SUP" 2>/dev/null
    [ -n "$D7CHILD" ] && kill -9 "$D7CHILD" 2>/dev/null
    [ -n "$RD_PID" ] && kill -9 "$RD_PID" 2>/dev/null
    [ -n "$SOCKDIR" ] && rm -rf "$SOCKDIR"
}
trap cleanup EXIT INT TERM
SOCKDIR=$(mktemp -d "${TMPDIR:-/tmp}/pmask-test.XXXXXX") || {
    echo "FATAL: mktemp -d failed"; exit 2; }
chmod 700 "$SOCKDIR"
SOCK="$SOCKDIR/daemon.sock"
ENVF="$SOCKDIR/env"
SECRET="PMK-$(fresh_marker)"
LABEL="cm-test-$$"
LABEL15=$(printf '%s' "$LABEL" | cut -c1-15)
FAIL=0

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

[ -x "$DAEMON" ] || { echo "FATAL: pmaskd missing"; exit 2; }

printf 'CI_TOKEN=%s\n' "$SECRET" > "$ENVF"
chmod 600 "$ENVF"

# ------------------------------------------------- D1: negative control
D1_SLEEP=1
[ "$VM_TCG" = 1 ] && D1_SLEEP=3
CI_TOKEN="$SECRET" /bin/sh -c "sleep $D1_SLEEP" &
CTL=$!
sleep 0.3
seen=0
for d in /proc/[0-9]*; do
    if cat "$d/environ" 2>/dev/null | tr '\0' '\n' | grep -qF -- "$SECRET"; then
        seen=1
        break
    fi
done
kill "$CTL" 2>/dev/null
[ "$seen" = 1 ] && pass d1-control-secret-is-detectable \
    || fail "d1-control (the observer cannot see an unmasked environment)"

# ------------------------------------------------------------ start daemon
"$DAEMON" -q -l "$LABEL" -S "$SOCK" -e "$ENVF" &
DPID=$!
i=0
while [ ! -S "$SOCK" ] && [ "$i" -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done
[ -S "$SOCK" ] || { fail "d0-daemon-did-not-start"; echo "== VERDICT: FAIL=$FAIL =="; exit 1; }

# ------------------------------------- D2/D3: job runs, secret stays hidden
LEN=$(printf '%s' "$SECRET" | wc -c | tr -d ' ')
OUT=$( "$TOOL" --daemon "$SOCK" --label "$LABEL" -- /bin/sh -c 'echo ${#CI_TOKEN}; sleep 1' 2>/dev/null )
# The job prints the length and nothing else, so the answer is the number
# itself: a substring match would also accept 10 in 100.
if [ "$OUT" = "$LEN" ]; then
    pass "d2-job-received-secret (length $LEN)"
else
    fail "d2-job-received-secret (got '$OUT', want exactly '$LEN')"
fi

# The job has exited by now; run a long one and sweep /proc while it lives.
"$TOOL" --daemon "$SOCK" --label "$LABEL" -- /bin/sh -c 'sleep 2' >/dev/null 2>&1 &
CLIENT=$!
sleep 0.6
leaks=0
for d in /proc/[0-9]*; do
    for f in cmdline environ; do
        if cat "$d/$f" 2>/dev/null | tr '\0' '\n' | grep -qF -- "$SECRET"; then
            leaks=$((leaks + 1))
        fi
    done
done
[ "$leaks" = 0 ] && pass d3-secret-in-no-proc-entry \
    || fail "d3-secret-in-no-proc-entry ($leaks sightings)"

# ------------------------------------- D3b: the composed daemon path, environ
# The rows above cover the label and the descriptor.  This one covers the
# environ view of a daemon job: the payload's window is redacted, the
# daemon itself is non-dumpable, and a plain process's environ is
# readable.  The last is the control: without it a refused read would
# pass for a blind observer.  The label differs from D3's because the
# daemon runs one job at a time: D3's payload is still alive when this
# request arrives, and a shared label would observe that job instead.
D3B_LABEL="cm-d3b-$$"
D3B_LABEL15=$(printf '%s' "$D3B_LABEL" | cut -c1-15)
"$TOOL" --daemon "$SOCK" --label "$D3B_LABEL" -- /bin/sh -c 'sleep 4' >/dev/null 2>&1 &
D3B_CLIENT=$!
n=0
d3b_pid=""
while [ "$n" -lt 60 ]; do
    n=$((n + 1))
    d3b_pid=""
    for d in /proc/[0-9]*; do
        [ "${d#/proc/}" = "$DPID" ] && continue
        [ "$(cat "$d/comm" 2>/dev/null)" = "$D3B_LABEL15" ] || continue
        d3b_pid=${d#/proc/}
        break
    done
    [ -n "$d3b_pid" ] && break
    sleep 0.1
done
/bin/sleep 5 &
d3b_ctl=$!
sleep 0.2
ctl_len=$(wc -c < "/proc/$d3b_ctl/environ" 2>/dev/null | tr -d ' ')
if [ -n "$ctl_len" ] && [ "$ctl_len" -gt 0 ]; then
    pass "d3b-control-environ-is-readable ($ctl_len bytes)"
else
    fail "d3b-control-environ-is-readable (len=[$ctl_len])"
fi
if [ -n "$d3b_pid" ]; then
    job_len=$(wc -c < "/proc/$d3b_pid/environ" 2>/dev/null | tr -d ' ')
    [ "$job_len" = 0 ] && pass "d3b-daemon-job-environ-is-redacted" \
        || fail "d3b-daemon-job-environ-is-redacted ($job_len bytes, want 0)"
else
    fail "d3b-daemon-job-not-found (no payload with comm $D3B_LABEL15)"
fi
daemon_err=$(cat "/proc/$DPID/environ" 2>&1 >/dev/null)
daemon_rc=$?
if [ "$(id -u)" = 0 ]; then
    # root reads a non-dumpable process's environ; it is not the same-uid
    # peer this row is about.
    skip "d3b-daemon-environ-is-refused (root is not a same-uid peer)"
elif [ "$daemon_rc" != 0 ] && printf '%s' "$daemon_err" | grep -qi 'permission denied'; then
    pass "d3b-daemon-environ-is-refused"
else
    fail "d3b-daemon-environ-is-refused (rc=$daemon_rc err=[$daemon_err])"
fi
kill "$d3b_ctl" 2>/dev/null
wait "$d3b_ctl" 2>/dev/null
[ -n "$d3b_pid" ] && kill -9 "$d3b_pid" 2>/dev/null
kill "$D3B_CLIENT" 2>/dev/null
wait "$D3B_CLIENT" 2>/dev/null
D3B_CLIENT=""

# ------------------------------------------------- D4: daemon self-mask
dc=""
dtxt=""
for d in /proc/[0-9]*; do
    [ "${d#/proc/}" = "$DPID" ] || continue
    dc=$(cat "$d/comm" 2>/dev/null)
    dtxt=$(tr -d '\000' < "$d/cmdline" 2>/dev/null)
done
# The daemon zeroes its own argv block and writes the label into it, so
# its cmdline reads back as exactly the label (issue #19).
if [ "$dc" = "$LABEL15" ] && [ "$dtxt" = "$LABEL" ]; then
    pass d4-daemon-selfmask
else
    fail "d4-daemon-selfmask (comm=[$dc] cmdline=[$dtxt])"
fi

wait "$CLIENT" 2>/dev/null

# --------------------------------------------- D5: status and stdout pass
OUT=$("$TOOL" --daemon "$SOCK" -- /bin/sh -c 'echo hello-from-job; exit 7' 2>/dev/null)
rc=$?
if [ "$OUT" = "hello-from-job" ] && [ "$rc" = 7 ]; then
    pass d5-stdio-and-exit-status
else
    fail "d5-stdio-and-exit-status (out='$OUT' rc=$rc)"
fi

# --------------------------------------- D6: a failed job keeps the daemon
"$TOOL" --daemon "$SOCK" -- /nonexistent/pmask-job >/dev/null 2>&1
rc=$?
OUT=$("$TOOL" --daemon "$SOCK" -- /bin/sh -c 'echo alive' 2>/dev/null)
if [ "$rc" = 127 ] && [ "$OUT" = "alive" ]; then
    pass d6-failed-job-keeps-daemon
else
    fail "d6-failed-job-keeps-daemon (rc=$rc out='$OUT')"
fi

# ------------------------------------- D11: --run-as-uid (root daemon)
# A root daemon started with --run-as-uid runs each job with the client's
# uid.  The client is uid 1000; the control is the same daemon without the
# flag, which runs the job as root.  The native gate is uid 1000, so this
# case runs in the VM's root pass and skips elsewhere.
if [ "$(id -u)" = 0 ] && "$CASES" as-uid 1000 true 2>/dev/null; then
    RUNDIR=$(mktemp -d "${TMPDIR:-/tmp}/pmask-runas.XXXXXX") || RUNDIR=""
    if [ -n "$RUNDIR" ]; then
        chmod 755 "$RUNDIR"
        RSOCK="$RUNDIR/runas.sock"
        "$DAEMON" --allow-uid 1000 --run-as-uid --socket-mode 666 -l "$LABEL" -S "$RSOCK" -e "$ENVF"             >/dev/null 2>"$RUNDIR/runas.err" &
        RPID=$!
        i=0
        while [ ! -S "$RSOCK" ] && [ "$i" -lt 50 ]; do
            sleep 0.1
            i=$((i + 1))
        done
        if [ -S "$RSOCK" ]; then
            out=$("$CASES" as-uid 1000 "$TOOL" --daemon "$RSOCK" -- "$CASES" whoami 2>&1)
            case "$out" in
                *uid=1000*euid=1000*)
                    pass "d11-run-as-uid-runs-the-job-as-the-client ($out)" ;;
                *)
                    fail "d11-run-as-uid-runs-the-job-as-the-client (out=[$out])" ;;
            esac
        else
            fail "d11-run-as-uid (the daemon did not start: $(head -2 "$RUNDIR/runas.err" | tr '\n' '|'))"
        fi
        kill -9 "$RPID" 2>/dev/null
        wait "$RPID" 2>/dev/null

        # Control: the same daemon without the flag runs the job as root.
        RSOCK0="$RUNDIR/root.sock"
        "$DAEMON" --allow-uid 1000 --socket-mode 666 -l "$LABEL" -S "$RSOCK0" -e "$ENVF"             >/dev/null 2>"$RUNDIR/root.err" &
        RPID0=$!
        i=0
        while [ ! -S "$RSOCK0" ] && [ "$i" -lt 50 ]; do
            sleep 0.1
            i=$((i + 1))
        done
        if [ -S "$RSOCK0" ]; then
            out=$("$CASES" as-uid 1000 "$TOOL" --daemon "$RSOCK0" -- "$CASES" whoami 2>&1)
            case "$out" in
                *uid=0*)
                    pass "d11-control-without-the-flag-runs-as-root ($out)" ;;
                *)
                    fail "d11-control-without-the-flag-runs-as-root (out=[$out])" ;;
            esac
        else
            fail "d11-control (the control daemon did not start)"
        fi
        kill -9 "$RPID0" 2>/dev/null
        wait "$RPID0" 2>/dev/null
        rm -rf "$RUNDIR"
    else
        fail "d11-run-as-uid (mktemp -d failed)"
    fi
else
    skip "d11-run-as-uid (needs root to start the daemon and switch to uid 1000)"
fi

# ------------------------------------------------ D7/D8: CLI --secret path
# This is the local command line path, not the daemon: the runner loads
# the secret, hardens itself and starts the labelled session; the
# descriptor is written into the child between fork and exec.  One case
# checks what the exec'd child sees, one checks what a same-uid observer
# can collect from /proc while the child is parked.
D7OUT="$SOCKDIR/d7.out"
D7LBL="cm-cli-$$"
D7LBL15=$(printf '%s' "$D7LBL" | cut -c1-15)
"$TOOL" -q -l "$D7LBL" --secret "CID_TOKEN=literal:$SECRET" -- \
    "$CASES" secretfd CID_TOKEN 30 >"$D7OUT" 2>/dev/null &
D7SUP=$!
n=0
while [ "$n" -lt 40 ]; do
    [ -s "$D7OUT" ] && break
    sleep 0.1
    n=$((n + 1))
done
# Both the supervisor and the exec'd child show exactly the label as their
# cmdline; the child is the one whose parent is another label cmdline.
cands=""
for d in /proc/[0-9]*; do
    txt=$(tr -d '\000' < "$d/cmdline" 2>/dev/null)
    [ "$txt" = "$D7LBL" ] || continue
    cands="$cands ${d#/proc/}"
done
d7_child=""
for c in $cands; do
    pp=$(awk '/^PPid:/{print $2}' "/proc/$c/status" 2>/dev/null)
    case " $cands " in
        *" $pp "*) d7_child=$c ;;
    esac
done
D7CHILD=$d7_child

# D7: no /proc entry carries the secret while the job runs (the daemon
# case D3 covers the daemon path; the supervisor has zeroed its own copy).
leaks=0
for d in /proc/[0-9]*; do
    for f in cmdline environ; do
        if cat "$d/$f" 2>/dev/null | tr '\0' '\n' | grep -qF -- "$SECRET"; then
            leaks=$((leaks + 1))
        fi
    done
done
[ "$leaks" = 0 ] && pass d7-cli-secret-in-no-proc-entry \
    || fail "d7-cli-secret-in-no-proc-entry ($leaks sightings)"

if [ -n "$d7_child" ]; then
    # D7: the visible cmdline of the exec'd child is the label.
    ctxt=$(cat "/proc/$d7_child/cmdline" 2>/dev/null)
    [ "$ctxt" = "$D7LBL" ] && pass d7-cli-child-cmdline-is-label \
        || fail "d7-cli-child-cmdline-is-label ([$(printf '%s' "$ctxt" | head -c 60)])"

    # D8: a same-uid process can open that descriptor through /proc and
    # read the whole value.  This is the documented hazard: the child is
    # dumpable after exec, so a peer of the same uid can read the value
    # of any descriptor it keeps open.  The seal only stops mutations.
    SZ=$(cat "/proc/$d7_child/fd/3" 2>/dev/null | wc -c | tr -d ' ')
    if [ "$SZ" = "$LEN" ]; then
        pass d8-same-uid-can-read-fd3-documented-hazard
    else
        fail "d8-same-uid-can-read-fd3-documented-hazard (read $SZ bytes, want $LEN)"
    fi

    # D7b: the same-uid environ view.  The payload's environ window is
    # redacted, the supervisor is non-dumpable, and a plain process's
    # environ is readable.  The last one is the control: without it a
    # refused read would pass for a blind observer.
    /bin/sleep 5 &
    d7_ctl=$!
    sleep 0.2
    ctl_len=$(wc -c < "/proc/$d7_ctl/environ" 2>/dev/null | tr -d ' ')
    child_len=$(wc -c < "/proc/$d7_child/environ" 2>/dev/null | tr -d ' ')
    sup_err=$(cat "/proc/$D7SUP/environ" 2>&1 >/dev/null)
    sup_rc=$?
    kill "$d7_ctl" 2>/dev/null
    wait "$d7_ctl" 2>/dev/null
    if [ -n "$ctl_len" ] && [ "$ctl_len" -gt 0 ]; then
        pass "d7b-control-environ-is-readable ($ctl_len bytes)"
    else
        fail "d7b-control-environ-is-readable (len=[$ctl_len])"
    fi
    [ "$child_len" = 0 ] && pass "d7b-payload-environ-is-redacted" \
        || fail "d7b-payload-environ-is-redacted ($child_len bytes, want 0)"
    if [ "$(id -u)" = 0 ]; then
        # root reads a non-dumpable process's environ; it is not the
        # same-uid peer the row is about.  The payload row above still
        # holds, because its window is empty.
        skip "d7b-supervisor-environ-is-refused (root is not a same-uid peer)"
    elif [ "$sup_rc" != 0 ] && printf '%s' "$sup_err" | grep -qi 'permission denied'; then
        pass "d7b-supervisor-environ-is-refused"
    else
        fail "d7b-supervisor-environ-is-refused (rc=$sup_rc err=[$sup_err])"
    fi
else
    fail "d7-cli-payload-not-found (no parked payload with label cmdline)"
fi
kill "$D7SUP" 2>/dev/null
sleep 0.3
kill "$d7_child" 2>/dev/null

# D7: what the payload itself reported, after it exits.
wait "$D7SUP" 2>/dev/null
# Clear the pids the trap would otherwise re-kill at exit: a recycled pid
# must not be signalled by a stale variable.
D7SUP=""
D7CHILD=""
D7TXT=$(cat "$D7OUT" 2>/dev/null)
printf '%s\n' "$D7TXT" | grep -q '^fd=3$' \
    && pass d7-cli-descriptor-at-3 || fail "d7-cli-descriptor-at-3 ($D7TXT)"
printf '%s\n' "$D7TXT" | grep -q "^bytes=$LEN\$" \
    && pass d7-cli-bytes-reach-child || fail "d7-cli-bytes-reach-child ($D7TXT)"
printf '%s\n' "$D7TXT" | grep -q '^path=/memfd:pmask-secret' \
    && pass d7-cli-memfd-backing || fail "d7-cli-memfd-backing ($D7TXT)"
printf '%s\n' "$D7TXT" | grep -q '^write-errno=1$' \
    && pass d7-cli-sealed-against-write || fail "d7-cli-sealed-against-write ($D7TXT)"
printf '%s\n' "$D7TXT" | grep -qF -- "$SECRET" \
    && fail "d7-cli-report-names-the-secret" \
    || pass d7-cli-report-names-the-secret
rm -f "$D7OUT"

# ------------------------------------- D9: help text matches the code
# The default socket has no /tmp fallback: a world-writable directory cannot
# be checked for ownership, and src/daemon.rs refuses to serve from one.  A
# help text that promises the fallback sends the operator to a path the
# daemon will never bind.
HELP=$("$DAEMON" --help 2>&1)
if printf '%s\n' "$HELP" | grep -q '/tmp/pmask'; then
    fail "d9-help-has-no-tmp-fallback (the help still promises /tmp/pmask-<uid>.sock)"
elif ! printf '%s\n' "$HELP" | grep -q -- '--socket'; then
    fail "d9-help-has-no-tmp-fallback (the help does not name --socket)"
else
    pass "d9-help-has-no-tmp-fallback"
fi

# ------------------- D10: a degraded job is visible at default verbosity
# A job whose exec takes the post-exec path (a `#!` script) is counted as
# a degradation, and invariant 13 says a degradation is warned about at
# the default verbosity.  The daemon here runs without --quiet and
# without --verbose, which is the default deployment.
#
# The test-only fault hooks cannot drive this: they are read from the
# daemon's own environment, and the daemon zeroes that block before it
# serves (invariant 12), so /proc/<daemon>/environ is empty and
# `std::env::var` finds nothing.  A script job is a real degradation that
# needs no hook.
DEGDIR="$SOCKDIR/degraded"
mkdir -p "$DEGDIR"
chmod 700 "$DEGDIR"
printf '#!/bin/sh\nexit 0\n' > "$DEGDIR/job.sh"
chmod 755 "$DEGDIR/job.sh"

# session_lines FILE -> number of lines the masking session wrote
session_lines() {
    grep -c '^pmask: ' "$1" 2>/dev/null || true
}

# session_lines_with FILE PATTERN -> of those, the ones matching PATTERN
session_lines_with() {
    grep '^pmask: ' "$1" 2>/dev/null | grep -c -- "$2" 2>/dev/null || true
}

# run_deg_daemon SOCK LOG [extra daemon options...]
run_deg_daemon() {
    rd_sock="$1"; rd_log="$2"; shift 2
    "$DAEMON" -l "$LABEL" -S "$rd_sock" -e "$ENVF" "$@" \
        >"$rd_log.out" 2>"$rd_log" &
    RD_PID=$!
    rd_i=0
    while [ ! -S "$rd_sock" ] && [ "$rd_i" -lt 50 ]; do
        sleep 0.1
        rd_i=$((rd_i + 1))
    done
    [ -S "$rd_sock" ]
}

# Control: a clean ELF job prints nothing.  The base tree printed
# `pmask: N of M execs unredacted (...)` for a degraded exec, so a
# clean run that still prints that wording is the old behaviour, not this
# one.
if run_deg_daemon "$DEGDIR/clean.sock" "$DEGDIR/clean.err"; then
    "$TOOL" --daemon "$DEGDIR/clean.sock" -- /bin/true >/dev/null 2>&1
    sleep 0.2
    old=$(session_lines_with "$DEGDIR/clean.err" 'execs unredacted')
    deg=$(session_lines_with "$DEGDIR/clean.err" 'degraded')
    warn=$(session_lines_with "$DEGDIR/clean.err" 'warning:')
    if [ "$old" = 0 ] && [ "$deg" = 0 ] && [ "$warn" = 0 ]; then
        pass "d10-clean-job-is-silent"
    else
        fail "d10-clean-job-is-silent (old=$old degraded=$deg warning=$warn: $(tr '\n' '|' < "$DEGDIR/clean.err"))"
    fi
else
    fail "d10-clean-job-is-silent (the daemon did not start)"
fi
kill "$RD_PID" 2>/dev/null

# The degraded job, at the default verbosity.  The line must say what
# happened: `degraded` (the summary) or `warning:` (the per-pid line).
# Counting any `pmask: ` line would also accept the base tree's
# `execs unredacted` wording, which is the behaviour this case exists to
# distinguish.
if run_deg_daemon "$DEGDIR/deg.sock" "$DEGDIR/deg.err"; then
    "$TOOL" --daemon "$DEGDIR/deg.sock" -- "$DEGDIR/job.sh" >/dev/null 2>&1
    i=0
    while [ "$i" -lt 50 ]; do
        deg=$(session_lines_with "$DEGDIR/deg.err" 'degraded')
        warn=$(session_lines_with "$DEGDIR/deg.err" 'warning:')
        { [ "$deg" -ge 1 ] || [ "$warn" -ge 1 ]; } && break
        sleep 0.1
        i=$((i + 1))
    done
    if [ "$deg" -ge 1 ] || [ "$warn" -ge 1 ]; then
        pass "d10-degraded-job-is-reported ($(grep '^pmask: ' "$DEGDIR/deg.err" | head -1))"
    else
        fail "d10-degraded-job-is-reported (no degraded/warning line on stderr: $(tr '\n' '|' < "$DEGDIR/deg.err"))"
    fi
else
    fail "d10-degraded-job-is-reported (the daemon did not start)"
fi
kill "$RD_PID" 2>/dev/null

# --quiet is the operator asking for silence, and it is the only setting
# that suppresses a degradation report.
if run_deg_daemon "$DEGDIR/quiet.sock" "$DEGDIR/quiet.err" -q; then
    "$TOOL" --daemon "$DEGDIR/quiet.sock" -- "$DEGDIR/job.sh" >/dev/null 2>&1
    sleep 0.3
    n=$(session_lines "$DEGDIR/quiet.err")
    [ "$n" = 0 ] && pass "d10-quiet-daemon-stays-quiet" \
        || fail "d10-quiet-daemon-stays-quiet ($n session lines with --quiet)"
else
    fail "d10-quiet-daemon-stays-quiet (the daemon did not start)"
fi
kill "$RD_PID" 2>/dev/null

kill "$DPID" 2>/dev/null
DPID=""
RD_PID=""
rm -f "$SOCK" "$ENVF"
# The trap owns $SOCKDIR: it removes the directory on every exit path,
# including the early one above.

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ]
