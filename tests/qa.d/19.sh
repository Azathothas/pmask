#!/bin/sh
# QA fragment for issue 19: `--redact --isolate=net` discarded the list
# and applied `--unshare`.
#
# The defect: `main` rewrote `--redact --isolate` into `cli.mask.unshare()`
# and set `cli.isolate = None` before the mode was chosen, so the parsed
# `net` selection was never read and a user+pid+mount set was created.
#
# Cases:
#   qa19-control-host-ns         the observer's own namespaces, so the
#                                comparison is against the real host
#   qa19-net-private             `--redact --isolate=net` puts the payload
#                                in a private network namespace
#   qa19-pid-is-the-host         ...and leaves the payload in the host's
#                                pid namespace (the defect created one)
#   qa19-redaction-still-applied the tree is still redacted: label as
#                                comm and exactly the label as cmdline
#   qa19-unshare-control         `--unshare` really does create a pid
#                                namespace, so the pid row can fail
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa19.$$"
mkdir -p "$D" || { echo "FAIL qa19-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    kill_label qa19 KILL 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT

# User namespaces are what `--isolate` needs at all.
if ! unshare -Ur true 2>/dev/null; then
    skip "qa19-user-namespaces (unshare -Ur true refused here)"
    echo "== VERDICT: SKIP =="
    exit 0
fi
# The net namespace probe: the payload must be able to create one.
if ! unshare -Urn true 2>/dev/null; then
    skip "qa19-net-namespace (unshare -Urn true refused here)"
    echo "== VERDICT: SKIP =="
    exit 0
fi

HOST_NET=$(readlink /proc/self/ns/net 2>/dev/null)
HOST_PID=$(readlink /proc/self/ns/pid 2>/dev/null)
case "$HOST_NET$HOST_PID" in
    "") skip "qa19-host-namespaces (readlink /proc/self/ns/* failed)"; exit 0 ;;
esac
pass "qa19-control-host-ns (net=$HOST_NET pid=$HOST_PID)"

# A payload that sleeps, so the observer reads the namespaces of a live
# process and not of a finished one.
"$TOOL" -q --redact --isolate=net -l qa19 -- /bin/sh -c 'sleep 20' >"$D/out" 2>"$D/err" &
SUP=$!
PID=""
i=0
while [ "$i" -lt 60 ]; do
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ "$p" = "$$" ] && continue
        [ "$(cat "$d/comm" 2>/dev/null)" = "qa19" ] || continue
        case "$(readlink "$d/exe" 2>/dev/null)" in
            */pmask|*/pmaskd|"") continue ;;
        esac
        PID=$p
        break
    done
    [ -n "$PID" ] && break
    i=$((i + 1))
    sleep 0.1
done

if [ -z "$PID" ]; then
    fail "qa19-payload-found (no live process with comm qa19; $(tr '\n' '|' <"$D/err"))"
else
    IN_NET=$(readlink "/proc/$PID/ns/net" 2>/dev/null)
    IN_PID=$(readlink "/proc/$PID/ns/pid" 2>/dev/null)
    if [ -n "$IN_NET" ] && [ "$IN_NET" != "$HOST_NET" ]; then
        pass "qa19-net-private (inside=$IN_NET host=$HOST_NET)"
    else
        fail "qa19-net-private (inside=[$IN_NET] host=[$HOST_NET])"
    fi
    if [ -n "$IN_PID" ] && [ "$IN_PID" = "$HOST_PID" ]; then
        pass "qa19-pid-is-the-host ($IN_PID)"
    else
        fail "qa19-pid-is-the-host (inside=[$IN_PID] host=[$HOST_PID]: --isolate=net must not create a pid namespace)"
    fi
    # The redaction half is the point of the composed spelling.
    CMDLINE=$(tr '\0' '|' <"/proc/$PID/cmdline" 2>/dev/null)
    if [ "$CMDLINE" = "qa19|" ]; then
        pass "qa19-cmdline-is-exactly-the-label"
    else
        fail "qa19-cmdline-is-exactly-the-label (cmdline=[$CMDLINE])"
    fi
    ENVSZ=$(wc -c <"/proc/$PID/environ" 2>/dev/null | tr -d ' ')
    if [ "$ENVSZ" = "0" ]; then
        pass "qa19-environ-empty"
    else
        fail "qa19-environ-empty (environ=[$ENVSZ] bytes)"
    fi
fi
kill -9 "$SUP" ${PID:+"$PID"} 2>/dev/null
wait "$SUP" 2>/dev/null

# Control: `--unshare` DOES create a pid namespace, so the pid row above
# can distinguish the two spellings rather than always passing.
ctl_pid=$("$TOOL" -q --unshare -- /bin/sh -c 'readlink /proc/self/ns/pid' 2>/dev/null)
if [ -n "$ctl_pid" ] && [ "$ctl_pid" != "$HOST_PID" ]; then
    pass "qa19-unshare-control-creates-a-pid-namespace ($ctl_pid)"
elif printf '%s' "$ctl_pid" | grep -q . ; then
    fail "qa19-unshare-control-creates-a-pid-namespace (inside=[$ctl_pid] host=[$HOST_PID])"
else
    skip "qa19-unshare-control-creates-a-pid-namespace (--unshare fell back to a plain fork)"
fi

# A host that refuses the user namespace must say that the namespace half
# was dropped; it must not run the redaction path silently with no note.
# `PMASK_PROBE_USERNS=0` makes the probe answer, which is the only way to
# test the branch on a host that grants them.
nog=$(PMASK_PROBE_USERNS=0 "$TOOL" --redact --isolate=net --report=json -- /bin/true 2>/dev/null)
case "$nog" in
    *'"mode": "redact"'*"isolate_unavailable"*"--isolate was requested but this host has no unprivileged user namespaces"*)
        pass "qa19-refused-namespace-set-is-reported" ;;
    *)
        fail "qa19-refused-namespace-set-is-reported ($(printf '%s' "$nog" | tr '\n' '|' | cut -c1-300))" ;;
esac

# --unshare and --redact --isolate=net compose: the pid namespace comes
# from --unshare, the net namespace from the list.  Taking one request and
# dropping the other is the defect issue 19 removed from the CLI, and it
# is just as silent inside the fork helper.
both=$("$TOOL" -q --unshare --redact --isolate=net -- /bin/sh -c \
    'echo "net=$(readlink /proc/self/ns/net) pid=$(readlink /proc/self/ns/pid)"' 2>/dev/null)
b_net=$(printf '%s' "$both" | tr ' ' '\n' | sed -n 's/^net=//p')
b_pid=$(printf '%s' "$both" | tr ' ' '\n' | sed -n 's/^pid=//p')
if [ -n "$b_net" ] && [ "$b_net" != "$HOST_NET" ] \
    && [ -n "$b_pid" ] && [ "$b_pid" != "$HOST_PID" ]; then
    pass "qa19-unshare-composes-with-the-isolate-list (net=$b_net pid=$b_pid)"
else
    fail "qa19-unshare-composes-with-the-isolate-list (net=[$b_net] host-net=[$HOST_NET] pid=[$b_pid] host-pid=[$HOST_PID])"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
