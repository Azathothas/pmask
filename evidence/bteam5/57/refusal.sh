#!/bin/sh
# The exact refusals, in the order a reader would try them.
set -u
echo "## uname / identity"
uname -r; id; printf 'uid_map: '; cat /proc/self/uid_map | tr '\n' ' '; echo
printf 'unprivileged_bpf_disabled='; cat /proc/sys/kernel/unprivileged_bpf_disabled
printf 'perf_event_paranoid='; cat /proc/sys/kernel/perf_event_paranoid
echo

echo "## tracefs: read as uid 1000"
ls /sys/kernel/tracing 2>&1 | head -2
echo "## tracefs: read as root"
sudo -n ls /sys/kernel/tracing 2>&1 | head -2
echo "## tracefs: write enable, as root"
sudo -n sh -c 'echo 1 > /sys/kernel/tracing/events/sched/sched_process_exec/enable' 2>&1
echo "rc=$?"
echo "## tracefs: kprobe_events, as root"
sudo -n sh -c 'echo "p:b57 __x64_sys_execve" >> /sys/kernel/tracing/kprobe_events' 2>&1
echo "rc=$?"
echo "## tracefs: fresh mount in a new mount namespace, as root"
sudo -n unshare -m sh -c 'mkdir -p /tmp/b57t && mount -t tracefs tracefs /tmp/b57t' 2>&1
echo "rc=$?"
echo "## tracefs: remount /sys/kernel/tracing, as root"
sudo -n mount -o remount,mode=755 /sys/kernel/tracing 2>&1
echo "rc=$?"
echo

echo "## tools"
for t in bpftool bpftrace perf trace-cmd; do
    printf '%-10s ' "$t"
    if command -v "$t" >/dev/null 2>&1; then command -v "$t"; else echo "not installed (command not found)"; fi
done
echo

echo "## raw bpf(2), uid 1000 then root"
if [ -x /tmp/b57-bpf ]; then /tmp/b57-bpf; sudo -n /tmp/b57-bpf; else echo "probe absent"; fi
echo "## raw perf_event_open(TRACEPOINT), uid 1000 then root"
if [ -x /tmp/b57-perf ]; then /tmp/b57-perf; sudo -n /tmp/b57-perf; else echo "probe absent"; fi
echo "## raw perf_event_open(SOFTWARE CPU_CLOCK), uid 1000 then root"
cat >/tmp/b57-perfsw.c <<'C'
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
int main(void){
    struct perf_event_attr pe; memset(&pe,0,sizeof pe);
    pe.type = PERF_TYPE_SOFTWARE; pe.size = sizeof pe;
    pe.config = PERF_COUNT_SW_CPU_CLOCK; pe.sample_period = 1;
    long r = syscall(SYS_perf_event_open, &pe, -1, 0, -1, 0);
    printf("perf_event_open(software) = %ld errno=%d (%s)\n", r, errno, strerror(errno));
    return 0;
}
C
cc -O0 -o /tmp/b57-perfsw /tmp/b57-perfsw.c 2>&1 | head -2
/tmp/b57-perfsw; sudo -n /tmp/b57-perfsw
echo

echo "## process connector: subscribe as uid 1000 and as root"
if [ -x /tmp/b57-cn ]; then
    /tmp/b57-cn
    sudo -n /tmp/b57-cn
else
    echo "probe absent"
fi
echo

echo "## substitute observation: the ptrace relation is readable without eBPF"
cd /workspace/wt/bteam5
./tests/pmask -q -l b57tracer ./tests/testcases sleepfor 3 >/dev/null 2>&1 &
S=$!
sleep 0.5
P=$(pgrep -P "$S" | head -n 1)
echo "supervisor=$S payload=$P"
echo "supervisor TracerPid=$(sed -n 's/^TracerPid:[[:space:]]*//p' "/proc/$S/status")"
echo "payload    TracerPid=$(sed -n 's/^TracerPid:[[:space:]]*//p' "/proc/$P/status")"
echo "supervisor task names:"
for t in /proc/"$S"/task/*; do printf '  %s %s\n' "${t##*/}" "$(cat "$t/comm" 2>/dev/null)"; done
kill "$S" 2>/dev/null
wait "$S" 2>/dev/null
