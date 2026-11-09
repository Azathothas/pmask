#!/bin/sh
# Issue 51: pmaskd is discoverable: the socket table, the 0600 node and
# the PING oracle.
#
# What is asserted:
#   51a  the socket node is 0600 and the name is in /proc/net/unix (and
#        in `ss -x` when ss exists).  This is the residual: the kernel
#        socket table is not filtered by the directory mode, so the
#        name stays visible.  The fragment pins that state rather than
#        pretending it is closed.
#   51b  a PING from the daemon's own uid gets the full body, with no
#        `limits=` documentation sentence.
#   51c  a PING from another allowed uid gets the reduced body: the
#        protocol version and what a client needs to frame a job, and
#        none of env_vars, allow_uids, jobs, socket_mode, the timeouts,
#        max_job_bytes, peer_identity or peer_uid.
#   51d  root gets the full body from the same daemon (the control that
#        proves the reduced body is a choice, not a broken reply).
#   51e  a uid that is not allowed is still refused, with the stable
#        `uid N is not allowed` line.
#   51f  the reduced reply did not change authorisation: a job from the
#        other allowed uid still runs.
#
# The two-uid half needs a root daemon.  Without passwordless sudo (or
# when this fragment already runs as root) the half is a named SKIP.
set -u
# lib.sh reads BIN_DIR from the cwd, so run from tests/ (see its header).
cd "$(dirname "$0")/.." || exit 2
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

DAEMON="$BIN_DIR/pmaskd"
TOOL="$BIN_DIR/pmask"
PROTO="$BIN_DIR/protocases"
MY_UID=$(id -u)

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

if [ ! -x "$PROTO" ]; then
    echo "SKIP 51-ping (no $PROTO: build with --features testbins)"
    exit 0
fi

LABEL="qa51-$$"
SOCKDIR=$(mktemp -d "${TMPDIR:-/tmp}/qa51.XXXXXX") || {
    echo "FATAL: mktemp -d failed"; exit 2; }
chmod 700 "$SOCKDIR"
SOCK="$SOCKDIR/d.sock"
DPID=""
ROOTPIDF="$SOCKDIR/root.pid"
ROOTERR="$SOCKDIR/root.err"
ROOTDIR=""
RSOCK=""
cleanup() {
    [ -n "$DPID" ] && kill -9 "$DPID" 2>/dev/null
    if [ -f "$ROOTPIDF" ]; then
        rp=$(cat "$ROOTPIDF" 2>/dev/null)
        [ -n "$rp" ] && kill -9 "$rp" 2>/dev/null
    fi
    if [ -n "$ROOTDIR" ]; then
        if [ "$MY_UID" = 0 ]; then
            rm -rf "$ROOTDIR"
        else
            sudo rm -rf "$ROOTDIR"
        fi
    fi
    rm -rf "$SOCKDIR"
}
trap cleanup EXIT INT TERM

wait_sock() {
    i=0
    while [ ! -S "$1" ] && [ "$i" -lt 100 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    [ -S "$1" ]
}

# ---------------------------------------------------------------- 51a node
"$DAEMON" -q -l "$LABEL" -S "$SOCK" &
DPID=$!
if ! wait_sock "$SOCK"; then
    fail "51-daemon-start (no socket at $SOCK)"
    echo "== VERDICT: FAIL=$FAIL =="
    exit 1
fi
mode=$(stat -c %a "$SOCK" 2>/dev/null)
if [ "$mode" = 600 ]; then
    pass "51-socket-node-0600"
else
    fail "51-socket-node-0600 (mode=$mode)"
fi
if grep -qF -- "$SOCK" /proc/net/unix 2>/dev/null; then
    pass "51-socket-name-in-proc-net-unix (residual: the table is world readable)"
else
    fail "51-socket-name-in-proc-net-unix (the name is absent from /proc/net/unix)"
fi
if command -v ss >/dev/null 2>&1; then
    # The listener is a listening socket: plain `ss -x` prints connected
    # sockets only, so ask for the listening table.
    if ss -xl 2>/dev/null | grep -qF -- "$SOCK" \
        || ss -x state listening 2>/dev/null | grep -qF -- "$SOCK"; then
        pass "51-socket-name-in-ss-x (residual)"
    else
        fail "51-socket-name-in-ss-x (ss does not list the name)"
    fi
else
    skip "51-socket-name-in-ss-x (no ss)"
fi

# ------------------------------------------------------- 51b own-uid PING
out=$("$PROTO" ping "$SOCK" 2>&1)
case "$out" in
    *"code=0"*"protocol=2"*"detail=full"*"jobs="*"env_vars="*"peer_identity="*)
        pass "51-ping-full-for-own-uid" ;;
    *)
        fail "51-ping-full-for-own-uid (out=$out)" ;;
esac
case "$out" in
    *"limits="*) fail "51-ping-has-no-limits-sentence (limits= is still served)" ;;
    *) pass "51-ping-has-no-limits-sentence" ;;
esac
# The full body still names the caller's own uid and the pinning method.
case "$out" in
    *"peer_uid=$MY_UID"*) pass "51-ping-full-carries-peer-uid" ;;
    *) fail "51-ping-full-carries-peer-uid (out=$out)" ;;
esac

kill -9 "$DPID" 2>/dev/null
wait "$DPID" 2>/dev/null
DPID=""

# --------------------------------------- 51c/51d/51e/51f: the other uid
# A daemon that runs as root and allows this uid.  The socket directory
# is root owned and 0755 so this uid can traverse it; the socket is 0666
# so the connect is possible and the uid check is what decides.
start_root_daemon() {
    ROOTDIR=$(mktemp -d "${TMPDIR:-/tmp}/qa51root.XXXXXX") || return 1
    chmod 755 "$ROOTDIR"
    # A root daemon refuses a socket directory owned by another uid, which
    # is the right behaviour and would fail this fixture: hand the
    # directory to root before it starts.
    if [ "$MY_UID" != 0 ]; then
        sudo chown root:root "$ROOTDIR" || return 1
    fi
    RSOCK="$ROOTDIR/d.sock"
    if [ "$MY_UID" = 0 ]; then
        "$DAEMON" -q -l "$LABEL" -S "$RSOCK" --allow-uid "$OTHER_UID" \
            --socket-mode 666 2>"$ROOTERR" &
        DPID=$!
    else
        sudo sh -c "echo \$\$ > '$ROOTPIDF'; exec '$DAEMON' -q -l '$LABEL' \
            -S '$RSOCK' --allow-uid '$OTHER_UID' --socket-mode 666" \
            2>"$ROOTERR" &
    fi
    wait_sock "$RSOCK"
}

# other_ping: a PING as OTHER_UID (never the daemon uid, never root).
other_ping() {
    if [ "$MY_UID" = 0 ]; then
        "$PROTO" as-uid "$OTHER_UID" ping "$RSOCK" 2>&1
    else
        "$PROTO" ping "$RSOCK" 2>&1
    fi
}

# root_ping: a PING as root.
root_ping() {
    if [ "$MY_UID" = 0 ]; then
        "$PROTO" ping "$RSOCK" 2>&1
    else
        sudo "$PROTO" ping "$RSOCK" 2>&1
    fi
}

# root_proto ARGS...: run the protocol client as root.
root_proto() {
    if [ "$MY_UID" = 0 ]; then
        "$PROTO" "$@" 2>&1
    else
        sudo "$PROTO" "$@" 2>&1
    fi
}

if [ "$MY_UID" = 0 ]; then
    OTHER_UID=1000
    HAVE_ROOT=1
elif sudo -n true 2>/dev/null; then
    OTHER_UID=$MY_UID
    HAVE_ROOT=1
else
    HAVE_ROOT=0
fi

if [ "$HAVE_ROOT" = 0 ]; then
    skip "51-ping-reduced-for-other-uid (no passwordless sudo: cannot start a root daemon)"
    skip "51-ping-full-for-root (no passwordless sudo)"
    skip "51-ping-refused-uid (no passwordless sudo: cannot drop to another uid)"
    skip "51-job-from-other-uid (no passwordless sudo)"
else
    if start_root_daemon; then
        # 51c: the other allowed uid sees the reduced body.
        out=$(other_ping)
        case "$out" in
            *"code=0"*"protocol=2"*"detail=reduced"*"label=$LABEL"*)
                pass "51-ping-reduced-for-other-uid" ;;
            *)
                fail "51-ping-reduced-for-other-uid (out=$out)" ;;
        esac
        missing=0
        for key in env_vars= allow_uids= jobs= socket_mode= io_timeout= \
                   job_timeout= max_job_bytes= peer_identity= peer_uid= limits=; do
            case "$out" in
                *"$key"*) missing=$((missing + 1)) ;;
            esac
        done
        if [ "$missing" = 0 ]; then
            pass "51-ping-reduced-omits-policy-fields"
        else
            fail "51-ping-reduced-omits-policy-fields ($missing of 10 keys present: $out)"
        fi

        # 51d: the same daemon, asked by root, still gives the full body.
        out=$(root_ping)
        case "$out" in
            *"code=0"*"detail=full"*"jobs="*"env_vars="*"allow_uids=$OTHER_UID"*"peer_identity="*)
                pass "51-ping-full-for-root" ;;
            *)
                fail "51-ping-full-for-root (out=$out)" ;;
        esac

        # 51e: a uid that is not allowed is refused before any body.
        out=$(root_proto as-uid 12345 "$RSOCK" ping)
        case "$out" in
            *"code=255"*"uid 12345 is not allowed"*)
                pass "51-ping-refused-uid" ;;
            *)
                fail "51-ping-refused-uid (out=$out)" ;;
        esac

        # 51f: the reduced reply did not weaken authorisation: a job from
        # the other allowed uid still runs and its status passes through.
        out=$("$TOOL" --daemon "$RSOCK" -- /bin/true 2>&1)
        rc=$?
        if [ "$rc" = 0 ]; then
            pass "51-job-from-other-uid"
        else
            fail "51-job-from-other-uid (rc=$rc out=$out)"
        fi
    else
        fail "51-root-daemon-start (no socket at $RSOCK)"
        skip "51-ping-reduced-for-other-uid (root daemon did not start)"
        skip "51-ping-full-for-root (root daemon did not start)"
        skip "51-ping-refused-uid (root daemon did not start)"
        skip "51-job-from-other-uid (root daemon did not start)"
    fi
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
