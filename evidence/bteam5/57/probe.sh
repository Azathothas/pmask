#!/bin/sh
# Issue 57: what this host allows of the eBPF and connector channels.
# Every command is run as uid 1000 and, where it needs privilege, under
# passwordless sudo; the refusal is captured verbatim.
set -u
echo "== host =="
uname -a
id
echo "container hint: $(cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -c container)"
echo "kernel.unprivileged_bpf_disabled=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>&1)"
echo

echo "== 1. is tracefs mounted, and can this uid read it =="
ls -ld /sys/kernel/tracing /sys/kernel/debug/tracing 2>&1
ls /sys/kernel/tracing 2>&1 | head -3
echo "-- as root --"
sudo -n ls /sys/kernel/tracing 2>&1 | head -5
echo

echo "== 2. mount tracefs fresh =="
sudo -n mkdir -p /tmp/b57-trace 2>&1
sudo -n mount -t tracefs tracefs /tmp/b57-trace 2>&1
echo "mount-exit=$?"
sudo -n umount /tmp/b57-trace 2>&1
echo

echo "== 3. remount debugfs/tracefs =="
sudo -n mount -o remount,mode=755 /sys/kernel/tracing 2>&1
echo "remount-exit=$?"
echo

echo "== 4. tools =="
for t in bpftool bpftrace perf; do
    printf '%-10s ' "$t"
    command -v "$t" 2>/dev/null || echo MISSING
done
echo

echo "== 5. bpftool feature probe (as root), when it exists =="
if command -v bpftool >/dev/null 2>&1; then
    sudo -n bpftool feature probe 2>&1 | head -20
else
    echo "bpftool: not installed; the container image has no bpftool"
fi
echo

echo "== 6. bpftrace tracepoint load (as root), when it exists =="
if command -v bpftrace >/dev/null 2>&1; then
    sudo -n timeout 20 bpftrace -e 'tracepoint:sched:sched_process_exec { printf("x\n"); }' 2>&1 | head -20
    echo "bpftrace-exit=$?"
else
    echo "bpftrace: not installed"
fi
echo

echo "== 7. raw bpf(2) from a tiny C program =="
CC=""
for c in cc gcc clang; do command -v $c >/dev/null 2>&1 && { CC=$c; break; }; done
if [ -n "$CC" ]; then
    cat >/tmp/b57-bpf.c <<'C'
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
int main(void){
    union bpf_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4; attr.value_size = 4; attr.max_entries = 1;
    long r = syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof attr);
    printf("bpf(BPF_MAP_CREATE) = %ld errno=%d (%s)\n", r, errno, strerror(errno));
    return 0;
}
C
    $CC -O0 -o /tmp/b57-bpf /tmp/b57-bpf.c 2>&1 | head -3
    [ -x /tmp/b57-bpf ] && { echo "-- as uid 1000 --"; /tmp/b57-bpf; }
    [ -x /tmp/b57-bpf ] && { echo "-- as root --"; sudo -n /tmp/b57-bpf; }
else
    echo "no C compiler"
fi
echo

echo "== 8. perf_event_open for a tracepoint =="
if [ -n "${CC:-}" ]; then
    cat >/tmp/b57-perf.c <<'C'
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
int main(void){
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof pe);
    pe.type = PERF_TYPE_TRACEPOINT;
    pe.size = sizeof pe;
    pe.config = 1;
    pe.sample_period = 1;
    pe.wakeup_events = 1;
    long r = syscall(SYS_perf_event_open, &pe, -1, 0, -1, 0);
    printf("perf_event_open(tracepoint) = %ld errno=%d (%s)\n", r, errno, strerror(errno));
    return 0;
}
C
    $CC -O0 -o /tmp/b57-perf /tmp/b57-perf.c 2>&1 | head -3
    [ -x /tmp/b57-perf ] && { echo "-- as uid 1000 --"; /tmp/b57-perf; }
    [ -x /tmp/b57-perf ] && { echo "-- as root --"; sudo -n /tmp/b57-perf; }
fi
echo

echo "== 9. the process connector =="
ls /proc/net/netlink 2>&1 | head -2
modinfo cn_proc 2>&1 | head -3
lsmod 2>/dev/null | grep -c cn_proc
if [ -n "${CC:-}" ]; then
    cat >/tmp/b57-cn.c <<'C'
/* A minimal NETLINK_CONNECTOR subscriber: subscribe to CN_IDX_PROC with
 * PROC_CN_MCAST_LISTEN and report the first event, with a poll() timeout
 * so the read cannot hang (the defect the issue's guest listener had). */
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
    if (s < 0) { printf("socket = -1 errno=%d (%s)\n", errno, strerror(errno)); return 1; }
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = CN_IDX_PROC;
    sa.nl_pid = getpid();
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("bind = -1 errno=%d (%s)\n", errno, strerror(errno)); return 1;
    }
    struct {
        struct nlmsghdr nl;
        struct cn_msg cn;
        enum proc_cn_mcast_op op;
    } msg;
    memset(&msg, 0, sizeof msg);
    msg.nl.nlmsg_len = sizeof msg;
    msg.nl.nlmsg_type = NLMSG_DONE;
    msg.nl.nlmsg_pid = getpid();
    msg.cn.id.idx = CN_IDX_PROC;
    msg.cn.id.val = CN_VAL_PROC;
    msg.cn.len = sizeof(enum proc_cn_mcast_op);
    msg.op = PROC_CN_MCAST_LISTEN;
    if (send(s, &msg, sizeof msg, 0) < 0) {
        printf("subscribe send = -1 errno=%d (%s)\n", errno, strerror(errno)); return 1;
    }
    printf("subscribe ok; waiting 3 s for an exec event\n");
    struct pollfd p = { s, POLLIN, 0 };
    int pr = poll(&p, 1, 3000);
    printf("poll = %d revents=%#x errno=%d (%s)\n", pr, p.revents, errno, strerror(errno));
    if (pr > 0) {
        char buf[4096];
        ssize_t n = recv(s, buf, sizeof buf, 0);
        printf("recv = %zd\n", n);
    }
    return 0;
}
C
    $CC -O0 -o /tmp/b57-cn /tmp/b57-cn.c 2>&1 | head -3
    if [ -x /tmp/b57-cn ]; then
        echo "-- as uid 1000 --"
        (/tmp/b57-cn) & CP=$!
        sleep 0.5
        /bin/true
        wait $CP
        echo "-- as root --"
        (sudo -n /tmp/b57-cn) & CP=$!
        sleep 0.5
        /bin/true
        wait $CP
    fi
fi
echo

echo "== 10. kernel config rows =="
for k in CONFIG_BPF_SYSCALL CONFIG_BPF_EVENTS CONFIG_FTRACE CONFIG_TRACEPOINTS CONFIG_CONNECTOR CONFIG_PROC_EVENTS; do
    if [ -r /boot/config-"$(uname -r)" ]; then
        grep -E "^$k=" /boot/config-"$(uname -r)" 2>/dev/null || echo "$k=unknown"
    else
        echo "$k=(no /boot/config-$(uname -r))"
    fi
done
ls /sys/kernel/tracing/events/sched/sched_process_exec/id 2>&1
sudo -n cat /sys/kernel/tracing/events/sched/sched_process_exec/id 2>&1
