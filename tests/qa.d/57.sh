#!/bin/sh
# Issue 57: eBPF sensors and the process connector against a masked exec.
#
# This host is an LXC container: `bpf(2)`, `perf_event_open(TRACEPOINT)`,
# tracefs writes and the `cn_proc` connector are all refused, even for
# root (see evidence/bteam5/57/probe.log and docs/research/bteam-ebpf.md).
# So the cases that need a tracepoint print SKIP with the exact refusal,
# and the cases that are decidable from /proc still run:
#
#   e1  eBPF program load: SKIP on this host, with the errno
#   e2  process connector subscribe: SKIP with the errno
#   e3  the substitute channel: the payload's TracerPid names a task of
#       the tree, and the supervisor's task set has a second thread
#   e4  control: a plain payload has TracerPid 0 and no `pmask-tracer`
#   e5  the kernel's exec record cannot carry argv: a `sched_process_exec`
#       reader needs tracefs; SKIP when it is absent, and the source fact
#       is recorded in docs/research/bteam-ebpf.md
#   e6  --detach removes TracerPid from the payload (the channel that
#       survives eBPF is the seize, not the lingering relation)
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

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa57.XXXXXX") || {
    echo "FATAL: cannot create a temp dir"; exit 2
}
SUP=""
cleanup() {
    [ -n "$SUP" ] && kill "$SUP" 2>/dev/null
    kill_label qa57-
    rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

L=qa57-label

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
    while [ "$n" -lt 40 ]; do
        p=$(child_of "$1") && { echo "$p"; return 0; }
        n=$((n + 1))
        sleep 0.1 2>/dev/null || sleep 1
    done
    return 1
}

# ---------------------------------------------------------- e1: bpf(2)
# The probe is a C program, not a tool: a missing bpftool must not read
# as "eBPF is unavailable" when the syscall itself would work.
CC=""
for c in cc gcc clang; do command -v "$c" >/dev/null 2>&1 && { CC=$c; break; }; done
bpf_note=""
if [ -z "$CC" ]; then
    skip "e1-ebpf-map-create (no C compiler, so the syscall cannot be probed)"
else
    cat >"$D/bpf.c" <<'C'
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
int main(void){
    union bpf_attr a; memset(&a, 0, sizeof a);
    a.map_type = BPF_MAP_TYPE_ARRAY; a.key_size = 4; a.value_size = 4; a.max_entries = 1;
    long r = syscall(SYS_bpf, BPF_MAP_CREATE, &a, sizeof a);
    printf("%s%ld errno=%d\n", r < 0 ? "refused " : "ok ", r, errno);
    return r < 0 ? 1 : 0;
}
C
    if "$CC" -O0 -o "$D/bpf" "$D/bpf.c" 2>"$D/cc.err"; then
        out=$("$D/bpf" 2>&1)
        rc=$?
        [ "$rc" = 0 ] && out_root=$(sudo -n "$D/bpf" 2>&1) || out_root=""
        if [ "$rc" = 0 ]; then
            pass "e1-ebpf-map-create ($out)"
        else
            skip "e1-ebpf-map-create (bpf(BPF_MAP_CREATE) refused as uid $(id -u): $out)"
        fi
        case "${out_root:-}" in
            refused*)
                echo "NOTE e1b-ebpf-map-create-root refused as root too: $out_root" ;;
            ok*)
                echo "NOTE e1b-ebpf-map-create-root reachable as root: $out_root" ;;
        esac
    else
        skip "e1-ebpf-map-create (the C probe did not compile: $(head -1 "$D/cc.err"))"
    fi
fi

# ------------------------------------------------ e2: the connector
if [ -z "$CC" ]; then
    skip "e2-process-connector (no C compiler)"
else
    cat >"$D/cn.c" <<'C'
/* Subscribe to CN_IDX_PROC and poll for one event with a 2 s timeout, so
 * the read cannot hang (the defect the issue's own listener had). */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
int main(void){
    int s = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (s < 0) { printf("socket refused errno=%d\n", errno); return 1; }
    struct sockaddr_nl sa; memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK; sa.nl_groups = CN_IDX_PROC; sa.nl_pid = getpid();
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("bind refused errno=%d\n", errno); return 1;
    }
    struct { struct nlmsghdr nl; struct cn_msg cn; enum proc_cn_mcast_op op; } m;
    memset(&m, 0, sizeof m);
    m.nl.nlmsg_len = sizeof m; m.nl.nlmsg_type = NLMSG_DONE; m.nl.nlmsg_pid = getpid();
    m.cn.id.idx = CN_IDX_PROC; m.cn.id.val = CN_VAL_PROC;
    m.cn.len = sizeof(enum proc_cn_mcast_op); m.op = PROC_CN_MCAST_LISTEN;
    if (send(s, &m, sizeof m, 0) < 0) {
        printf("subscribe refused errno=%d\n", errno); return 1;
    }
    struct pollfd p = { s, POLLIN, 0 };
    int pr = poll(&p, 1, 2000);
    printf("subscribe ok poll=%d revents=%#x\n", pr, p.revents);
    return pr > 0 ? 0 : 1;
}
C
    if "$CC" -O0 -o "$D/cn" "$D/cn.c" 2>"$D/cc2.err"; then
        # A concurrent exec gives the listener something to report.
        ( sleep 0.3; "$CASES" echoargs qa57-conn >/dev/null 2>&1 ) &
        out=$("$D/cn" 2>&1)
        rc=$?
        if [ "$rc" = 0 ]; then
            pass "e2-process-connector ($out)"
        else
            skip "e2-process-connector ($out)"
        fi
    else
        skip "e2-process-connector (the C probe did not compile: $(head -1 "$D/cc2.err"))"
    fi
fi

# ------------------------- e3: the channel a sensor can still read
"$TOOL" -q -l "$L" -- "$CASES" sleepfor 4 >/dev/null 2>&1 &
SUP=$!
PAY=$(await_pid "$SUP") || PAY=""
if [ -z "$PAY" ]; then
    fail "e3-tracer-pid-names-the-tree (no payload)"
    fail "e3b-supervisor-has-the-tracer-task (no payload)"
else
    tracer=$(sed -n 's/^TracerPid:[[:space:]]*//p' "/proc/$PAY/status" 2>/dev/null)
    if [ -n "$tracer" ] && [ "$tracer" != 0 ] && [ -d "/proc/$tracer" ]; then
        pass "e3-tracer-pid-names-the-tree (payload TracerPid=$tracer)"
    else
        fail "e3-tracer-pid-names-the-tree (TracerPid=[$tracer])"
    fi
    # The tracer is a thread of the supervisor, and the payload's
    # TracerPid names it.  The thread's *name* is issue 38's channel and
    # is asserted by tests/qa.d/38.sh; this case asserts the relation,
    # which survives any name the session chooses.
    found=no
    for t in /proc/"$SUP"/task/*; do
        tid=$(basename "$t")
        [ "$tid" = "$SUP" ] && continue
        [ "$tid" = "$tracer" ] && found=yes
    done
    if [ "$found" = yes ]; then
        pass "e3b-supervisor-has-the-tracer-task (tid=$tracer name=$(cat /proc/$tracer/comm 2>/dev/null))"
    else
        fail "e3b-supervisor-has-the-tracer-task (TracerPid=[$tracer] is not a task of $SUP)"
    fi
fi
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""

# --------------------------------------------- e4: the plain control
/bin/sleep 4 &
PLAIN=$!
sleep 0.3
tracer=$(sed -n 's/^TracerPid:[[:space:]]*//p' "/proc/$PLAIN/status" 2>/dev/null)
found=no
for t in /proc/"$PLAIN"/task/*; do
    [ "$(basename "$t")" = "$PLAIN" ] && continue
    found=yes
done
if [ "$tracer" = 0 ] && [ "$found" = no ]; then
    pass "e4-control-plain-process-has-no-tracer"
else
    fail "e4-control-plain-process-has-no-tracer (TracerPid=[$tracer] pmask-tracer=$found)"
fi
kill "$PLAIN" 2>/dev/null
wait "$PLAIN" 2>/dev/null

# --------------------------------- e5: the tracepoint's argv field
# A `sched_process_exec` program needs tracefs and a writable
# tracepoint; both are refused here.  The decision is SKIP, not a pass:
# the source fact is recorded in docs/research/bteam-ebpf.md and nothing
# on this host can confirm or refute it.
if [ ! -r /sys/kernel/tracing/events/sched/sched_process_exec/id ] && \
   [ ! -r /sys/kernel/debug/tracing/events/sched/sched_process_exec/id ]; then
    skip "e5-sched-process-exec-has-no-argv (tracefs not readable: $(ls /sys/kernel/tracing 2>&1 | head -1))"
else
    skip "e5-sched-process-exec-has-no-argv (tracefs readable; no bpf loader on this host)"
fi

# ------------------------------------------- e6: --detach drops it
"$TOOL" -q -l "$L" --detach -- "$CASES" sleepfor 4 >/dev/null 2>&1 &
SUP=$!
PAY=$(await_pid "$SUP") || PAY=""
tracer=""
[ -n "$PAY" ] && tracer=$(sed -n 's/^TracerPid:[[:space:]]*//p' "/proc/$PAY/status" 2>/dev/null)
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
if [ -z "$PAY" ]; then
    fail "e6-detach-zeroes-tracerpid (no payload)"
elif [ "$tracer" = 0 ]; then
    pass "e6-detach-zeroes-tracerpid"
else
    fail "e6-detach-zeroes-tracerpid (TracerPid=[$tracer], want 0)"
fi
echo "NOTE e6 does not make the tree invisible: the PTRACE_SEIZE that a"
echo "     sys_enter_ptrace sensor would record already happened, and the"
echo "     supervisor's tracer thread remains."

echo "== QA57: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
[ "$FAIL" = 0 ] || exit 1
exit 0
