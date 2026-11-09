#!/bin/sh
# QA fragment for issue 22: SIGTERM could not stop a single-job daemon
# while a client was silent and `--io-timeout 0` was in force.
#
# The defect: with `jobs <= 1` the daemon serves the connection inline.
# While it was blocked in a request read from a client that never sent
# anything, the `SHUTDOWN` flag set by SIGTERM was observed only after
# that read returned.  With `--io-timeout 0` there is no deadline, so the
# read never returned and the daemon appeared to ignore the signal.
#
# Cases:
#   qa22-control-ordinary-job      a normal job runs and its status passes
#                                  through (the fix must not break the
#                                  inline path)
#   qa22-sigterm-with-silent-client  SIGTERM stops the daemon while a
#                                  client is connected and silent with
#                                  --io-timeout 0, within a bounded time
#   qa22-socket-removed            the socket file is gone afterwards
#   qa22-daemon-exit-zero          the daemon exits 0 (its documented
#                                  shutdown status)
#   qa22-worker-model-unaffected   the same with `--jobs 2`, so the forked
#                                  worker path still stops too
#   qa22-client-unblocked          the silent client's connection is
#                                  closed by the daemon, not left open
#   qa22-io-timeout-drops-stall    `--io-timeout 2` still drops a stalled
#                                  client (the timeout feature is intact)
#
# A build without the fix hangs here; the case is bounded so the gate
# reports a FAIL rather than stalling.
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
skip() { echo "SKIP $*"; }

# The socket directory must be private: pmaskd refuses one it does not own
# or one group or other can write.
D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa22.XXXXXX") || {
    echo "FATAL: mktemp -d failed"; exit 2; }
chmod 700 "$D"
DPID=""
CLPID=""
cleanup() {
    [ -n "$DPID" ] && kill -9 "$DPID" 2>/dev/null
    [ -n "$CLPID" ] && kill -9 "$CLPID" 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT INT TERM

SOCK="$D/d.sock"

start_daemon() {  # start_daemon ARGS...
    "$DAEMON" -q -S "$SOCK" "$@" >"$D/d.out" 2>"$D/d.err" &
    DPID=$!
    sd_i=0
    while [ ! -S "$SOCK" ] && [ "$sd_i" -lt 100 ]; do
        if ! kill -0 "$DPID" 2>/dev/null; then
            return 1
        fi
        sleep 0.05
        sd_i=$((sd_i + 1))
    done
    [ -S "$SOCK" ]
}

# wait_gone PID SECONDS: 0 when the process exits inside the window.
wait_gone() {
    wg_pid="$1"
    wg_s="$2"
    wg_i=0
    wg_n=$((wg_s * 10))
    while [ "$wg_i" -lt "$wg_n" ]; do
        kill -0 "$wg_pid" 2>/dev/null || return 0
        sleep 0.1
        wg_i=$((wg_i + 1))
    done
    return 1
}

# A silent client: it connects and sends nothing.  Python is used because
# the shell cannot express "connect and hold" without a helper binary.
# When python3 is absent the case is a SKIP, never a pass.
if ! command -v python3 >/dev/null 2>&1; then
    skip "qa22-silent-client (python3 is not installed, so the silent client cannot be built)"
    echo "== VERDICT: $FAIL failure(s) =="
    exit "$FAIL"
fi

# A client that connects, waits `hold` seconds, and reports whether the
# daemon closed the connection early.
silent_client() {  # silent_client SOCK HOLD_OUT_FILE
    sc_sock="$1"
    sc_out="$2"
    python3 - "$sc_sock" "$sc_out" <<'PY' &
import socket, sys, time
sock, out = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX)
s.settimeout(30.0)
s.connect(sock)
t0 = time.time()
try:
    # Send nothing: this is the stalled-request case.
    data = s.recv(1)
    closed = len(data) == 0
except Exception:
    closed = True
with open(out, "w") as f:
    f.write("closed=%s elapsed=%.2f\n" % ("yes" if closed else "no", time.time() - t0))
PY
    CLPID=$!
}

# ---------------------------------- control: the inline path still works
if start_daemon --io-timeout 0; then
    out=$("$TOOL" --daemon "$SOCK" -- /bin/sh -c 'echo inline; exit 4' 2>"$D/c.err")
    rc=$?
    if [ "$rc" = 4 ] && [ "$out" = "inline" ]; then
        pass "qa22-control-ordinary-job (rc=$rc passes through)"
    else
        fail "qa22-control-ordinary-job (rc=$rc out=[$out] err=$(head -1 "$D/c.err"))"
    fi
    kill -TERM "$DPID" 2>/dev/null
    wait "$DPID" 2>/dev/null
    DPID=""
else
    fail "qa22-control-ordinary-job (the daemon did not start: $(head -1 "$D/d.err"))"
fi

# ------------------------------------- SIGTERM with a silent client
rm -f "$SOCK"
if start_daemon --io-timeout 0; then
    silent_client "$SOCK" "$D/stall.out"
    # Wait for the client to have connected.  `ss` is not guaranteed, so
    # the daemon's own accept is what the case waits for: the client's
    # connect returns as soon as the backlog takes it, and the inline
    # handler is the only reader, so a short sleep is enough on a host
    # this gate runs on.  The assertion does not depend on the timing:
    # the daemon must exit whether or not the request was read.
    sleep 0.8
    t0=$(date +%s)
    kill -TERM "$DPID" 2>/dev/null
    if wait_gone "$DPID" 10; then
        t1=$(date +%s)
        pass "qa22-sigterm-with-silent-client ($((t1 - t0))s)"
        wait "$DPID" 2>/dev/null
        rc=$?
        if [ "$rc" = 0 ]; then
            pass "qa22-daemon-exit-zero (rc=$rc)"
        else
            fail "qa22-daemon-exit-zero (rc=$rc, want 0)"
        fi
    else
        fail "qa22-sigterm-with-silent-client (still alive 10s after SIGTERM)"
        fail "qa22-daemon-exit-zero (undecidable: the daemon had to be killed)"
        kill -9 "$DPID" 2>/dev/null
    fi
    DPID=""
    if [ -e "$SOCK" ]; then
        fail "qa22-socket-removed ($SOCK still exists)"
    else
        pass "qa22-socket-removed"
    fi
    # The client's read must have returned because the daemon closed the
    # socket, not because this fragment eventually killed the daemon:
    # hence the elapsed bound.  A build that needs the SIGKILL reports a
    # ten-second wait here and fails.
    cl_i=0
    while [ ! -s "$D/stall.out" ] && [ "$cl_i" -lt 50 ]; do
        sleep 0.1
        cl_i=$((cl_i + 1))
    done
    if [ -s "$D/stall.out" ]; then
        cl_line=$(cat "$D/stall.out")
        cl_secs=$(printf '%s' "$cl_line" | sed -n 's/.*elapsed=\([0-9]*\)\..*/\1/p')
        case "$cl_line" in
            closed=yes*)
                if [ -n "$cl_secs" ] && [ "$cl_secs" -le 5 ]; then
                    pass "qa22-client-unblocked ($cl_line)"
                else
                    fail "qa22-client-unblocked ($cl_line; the close came from the harness kill, not the daemon)"
                fi
                ;;
            *) fail "qa22-client-unblocked ($cl_line)" ;;
        esac
    else
        fail "qa22-client-unblocked (the client never reported: its read did not return)"
    fi
    kill -9 "$CLPID" 2>/dev/null
    wait "$CLPID" 2>/dev/null
    CLPID=""
else
    fail "qa22-sigterm-with-silent-client (the daemon did not start)"
fi

# -------------------------------------- the same with the worker model
rm -f "$SOCK"
if start_daemon --jobs 2 --io-timeout 0; then
    silent_client "$SOCK" "$D/worker.out"
    sleep 0.8
    kill -TERM "$DPID" 2>/dev/null
    if wait_gone "$DPID" 15; then
        pass "qa22-worker-model-unaffected (jobs=2 stopped)"
    else
        fail "qa22-worker-model-unaffected (jobs=2 still alive 15s after SIGTERM)"
        kill -9 "$DPID" 2>/dev/null
    fi
    wait "$DPID" 2>/dev/null
    DPID=""
    kill -9 "$CLPID" 2>/dev/null
    wait "$CLPID" 2>/dev/null
    CLPID=""
else
    fail "qa22-worker-model-unaffected (the daemon did not start)"
fi

# -------------------------------- the timeout feature is still intact
rm -f "$SOCK"
if start_daemon --io-timeout 2; then
    t0=$(date +%s)
    python3 - "$SOCK" <<'PY' >"$D/to.out" 2>&1
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(30.0)
s.connect(sys.argv[1])
print("recv=%r" % (s.recv(1),))
PY
    t1=$(date +%s)
    d=$((t1 - t0))
    # A dropped client sees a clean end of stream after about the timeout.
    if [ "$d" -ge 2 ] && [ "$d" -le 15 ]; then
        pass "qa22-io-timeout-drops-stall (${d}s)"
    else
        fail "qa22-io-timeout-drops-stall (${d}s, want 2..15; $(head -1 "$D/to.out"))"
    fi
    # The daemon must still serve after dropping it.
    out=$("$TOOL" --daemon "$SOCK" -- /bin/echo after-stall 2>/dev/null)
    if [ "$out" = "after-stall" ]; then
        pass "qa22-daemon-serves-after-drop"
    else
        fail "qa22-daemon-serves-after-drop (out=[$out])"
    fi
    kill -TERM "$DPID" 2>/dev/null
    wait "$DPID" 2>/dev/null
    DPID=""
else
    fail "qa22-io-timeout-drops-stall (the daemon did not start)"
fi

echo "== VERDICT: $FAIL failure(s) =="
exit "$FAIL"
