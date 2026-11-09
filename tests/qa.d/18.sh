#!/bin/sh
# QA fragment for issue 18: `--job-timeout` overflowed and panicked the
# daemon on the first job.
#
# The defect: `Instant::now() + Duration::from_secs(cfg.job_timeout_secs)`
# panics when the operator passes a value near u64::MAX.  The daemon
# aborts while serving, and the client sees `failed to fill whole buffer`
# instead of an exit status.
#
# Cases:
#   qa18-huge-timeout-refused      `--job-timeout 9223372036854775807`
#                                  exits 255 at parse time, without
#                                  binding a socket
#   qa18-refusal-names-the-flag    the message names the flag and the cap
#   qa18-no-socket-left            a refused start leaves nothing behind
#   qa18-huge-io-timeout-refused   the same for `--io-timeout`
#   qa18-boundary-accepted         `315360000` (ten years) still starts
#                                  and serves a job: the cap is not a
#                                  silent narrowing of everything
#   qa18-just-over-refused         `315360001` is refused, so the
#                                  boundary is the documented one
#   qa18-control-normal-timeout    a normal `--job-timeout 5` starts,
#                                  runs a job and returns its status
#   qa18-client-sees-a-status      the client gets a real status, not
#                                  the truncated-response error (the
#                                  defect's own symptom)
#   qa18-socket-removed-on-shutdown  SIGTERM removes the socket
#
# Every daemon start is polled for its socket and for its exit, so a build
# that refuses and a build that accepts are both decided without a sleep
# that has to guess, and neither can hang the gate.
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
DAEMON="$BIN_DIR/pmaskd"
[ -x "$TOOL" ] || { echo "FATAL: $TOOL is missing"; exit 2; }
[ -x "$DAEMON" ] || { echo "FATAL: $DAEMON is missing"; exit 2; }
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa18.XXXXXX") || {
    echo "FATAL: mktemp -d failed"; exit 2; }
chmod 700 "$D"
DPID=""
cleanup() {
    [ -n "$DPID" ] && kill -9 "$DPID" 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT INT TERM

MAX=315360000   # ten years, the documented cap

# start_daemon SOCK ARGS...
# Sets START_UP=1 when the daemon bound SOCK and is still running,
# START_UP=0 when it exited first (START_RC is then its status).  The
# poll is bounded at 10 s, far past either outcome.
START_UP=0
START_RC=""
start_daemon() {
    sd_sock="$1"
    shift
    "$DAEMON" -q -S "$sd_sock" "$@" >"$D/sd.out" 2>"$D/sd.err" &
    sd_pid=$!
    DPID=$sd_pid
    START_UP=0
    START_RC=""
    sd_i=0
    while [ "$sd_i" -lt 200 ]; do
        if [ -S "$sd_sock" ]; then
            START_UP=1
            return
        fi
        if ! kill -0 "$sd_pid" 2>/dev/null; then
            wait "$sd_pid" 2>/dev/null
            START_RC=$?
            DPID=""
            return
        fi
        sleep 0.05
        sd_i=$((sd_i + 1))
    done
    # Still running but never bound: a refusal or a hang.  Kill it so the
    # case can report.
    kill -9 "$sd_pid" 2>/dev/null
    wait "$sd_pid" 2>/dev/null
    START_RC="timeout"
    DPID=""
}

stop_daemon() {
    if [ -n "$DPID" ]; then
        kill -TERM "$DPID" 2>/dev/null
        wait "$DPID" 2>/dev/null
        DPID=""
    fi
}

# ---------------------------------------------- the issue's own value
SOCK="$D/j.sock"
start_daemon "$SOCK" --job-timeout 9223372036854775807
if [ "$START_UP" = 0 ] && [ "$START_RC" = 255 ]; then
    pass "qa18-huge-timeout-refused (rc=$START_RC, $(head -1 "$D/sd.err" | cut -c1-70))"
elif [ "$START_UP" = 1 ]; then
    fail "qa18-huge-timeout-refused (the daemon bound a socket, so the value was accepted)"
    # Fall through to the survival case below with this daemon, which is
    # exactly the baseline's state: a huge timeout in force and a job to
    # run.
else
    fail "qa18-huge-timeout-refused (rc=$START_RC, want 255; err=$(head -1 "$D/sd.err"))"
fi

# The invariant behind the fix, decided on whichever build is running:
# a daemon that holds a huge timeout must still answer a job cleanly and
# still be alive afterwards.  A build that refuses the value establishes
# it by construction; a build that accepts it has to survive the first
# job, which is the defect.
if [ "$START_UP" = 1 ]; then
    out=$("$TOOL" --daemon "$SOCK" -- /bin/true 2>"$D/job.err")
    rc=$?
    alive=0
    kill -0 "$DPID" 2>/dev/null && alive=1
    if [ "$rc" = 0 ] && [ "$alive" = 1 ]; then
        pass "qa18-huge-timeout-daemon-survives (rc=$rc, daemon alive)"
    else
        fail "qa18-huge-timeout-daemon-survives (rc=$rc, alive=$alive, err=$(head -1 "$D/job.err"))"
    fi
    # The defect's own symptom, on the same daemon.
    if grep -q "failed to fill whole buffer" "$D/job.err"; then
        fail "qa18-client-sees-a-status (the client reported the truncated-response error)"
    else
        pass "qa18-client-sees-a-status"
    fi
    stop_daemon
else
    pass "qa18-huge-timeout-daemon-survives (the value is refused, so no job can reach the deadline)"
    pass "qa18-client-sees-a-status (no daemon accepted the value, so no client can be left waiting)"
fi

# The refusal has to name the flag and the cap, or an operator cannot
# tell a typo from a policy change.
if grep -q -- "--job-timeout" "$D/sd.err" && grep -q "$MAX" "$D/sd.err"; then
    pass "qa18-refusal-names-the-flag ($(head -1 "$D/sd.err" | cut -c1-70))"
else
    fail "qa18-refusal-names-the-flag ($(head -1 "$D/sd.err"))"
fi

# Nothing was bound: a refused start must not leave a socket a client
# could connect to and hang on.
if [ -e "$SOCK" ]; then
    fail "qa18-no-socket-left ($SOCK exists after a refused start)"
else
    pass "qa18-no-socket-left"
fi

# ------------------------------------------------- the same for io-timeout
start_daemon "$D/i.sock" --io-timeout 18446744073709551615
if [ "$START_UP" = 0 ] && [ "$START_RC" = 255 ] && grep -q -- "--io-timeout" "$D/sd.err"; then
    pass "qa18-huge-io-timeout-refused (rc=$START_RC)"
elif [ "$START_UP" = 1 ]; then
    fail "qa18-huge-io-timeout-refused (the daemon bound a socket)"
    stop_daemon
else
    fail "qa18-huge-io-timeout-refused (rc=$START_RC, err=$(head -1 "$D/sd.err"))"
fi

# ------------------------------------------------------- the boundary
start_daemon "$D/max.sock" --job-timeout "$MAX"
if [ "$START_UP" = 1 ]; then
    # The cap itself must still serve: a bound that only refuses is not
    # the same feature.
    out=$("$TOOL" --daemon "$D/max.sock" -- /bin/sh -c 'exit 3' 2>"$D/max.client.err")
    rc=$?
    if [ "$rc" = 3 ]; then
        pass "qa18-boundary-accepted ($MAX s starts and serves, rc=$rc)"
    else
        fail "qa18-boundary-accepted (started but the job gave rc=$rc, want 3)"
    fi
    stop_daemon
else
    fail "qa18-boundary-accepted (the cap itself was refused: $(head -1 "$D/sd.err"))"
fi

start_daemon "$D/over.sock" --job-timeout $((MAX + 1))
if [ "$START_UP" = 0 ] && [ "$START_RC" = 255 ]; then
    pass "qa18-just-over-refused (rc=$START_RC)"
elif [ "$START_UP" = 1 ]; then
    fail "qa18-just-over-refused (the daemon bound a socket at $((MAX + 1)) s)"
    stop_daemon
else
    fail "qa18-just-over-refused (rc=$START_RC, want 255)"
fi

# ------------------------------------------- the normal path still works
# A normal timeout must still start, run a job, pass its exit status and
# leave no socket.  This is the control: the cap must not break the
# feature it bounds.
SOCK2="$D/normal.sock"
start_daemon "$SOCK2" --job-timeout 5
if [ "$START_UP" = 0 ]; then
    fail "qa18-control-normal-timeout (daemon did not start: $(head -1 "$D/sd.err"))"
else
    out=$("$TOOL" --daemon "$SOCK2" -- /bin/sh -c 'exit 7' 2>"$D/client.err")
    rc=$?
    if [ "$rc" = 7 ]; then
        pass "qa18-control-normal-timeout (rc=$rc passes through)"
    else
        fail "qa18-control-normal-timeout (rc=$rc, want 7; stderr=$(head -1 "$D/client.err"))"
    fi
    stop_daemon
    if [ -e "$SOCK2" ]; then
        fail "qa18-socket-removed-on-shutdown ($SOCK2 still exists)"
    else
        pass "qa18-socket-removed-on-shutdown"
    fi
fi

echo "== VERDICT: $FAIL failure(s) =="
exit "$FAIL"
