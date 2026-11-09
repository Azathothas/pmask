#!/bin/sh
# eBPF cannot be loaded here (see probe.log).  The strongest channel the
# issue names is the tracer's own syscalls: sys_enter_ptrace and
# sys_enter_process_vm_writev.  strace reads those from the same kernel
# tracepoints through a different plumbing (ptrace, not bpf), so it is a
# substitute for the *observation* and not for the eBPF channel itself.
#
# What this establishes: the tracer's PTRACE_SEIZE and the string shuttle
# are visible to any process that may ptrace the supervisor.  What it does
# not establish: that a root eBPF program sees the same fields (the guest
# measurement in the issue is what covers that).
set -u
cd /workspace/wt/bteam5
PM=./tests/pmask
TC=./tests/testcases

echo "== control: strace on a plain exec =="
strace -f -e trace=execve -o /tmp/b57-ctl.strace /bin/true 2>/dev/null
grep -c 'execve(' /tmp/b57-ctl.strace

echo
echo "== pmask --rexec: ptrace and process_vm_writev from the tracer =="
strace -f -e trace=ptrace,process_vm_writev,process_vm_readv \
    -o /tmp/b57-pmask.strace -s 0 \
    "$PM" -q -l b57audit --rexec -- "$TC" sleepfor 1 2>/dev/null
echo "rc=$?"
echo "ptrace calls:"
sed -n 's/.*ptrace(\([A-Z_0-9]*\).*/\1/p' /tmp/b57-pmask.strace | sort | uniq -c | sort -rn | head -12
echo "process_vm_writev calls:"
grep -c 'process_vm_writev' /tmp/b57-pmask.strace
echo "process_vm_readv calls:"
grep -c 'process_vm_readv' /tmp/b57-pmask.strace
echo
echo "the PTRACE_SEIZE line (tracer -> payload):"
grep -m2 'PTRACE_SEIZE' /tmp/b57-pmask.strace
echo
echo "the first PTRACE_POKEDATA / PTRACE_SETREGSET line:"
grep -m1 -E 'PTRACE_POKEDATA|PTRACE_SETREGSET' /tmp/b57-pmask.strace
echo
echo "== what a sys_enter_execve reader sees for a masked exec =="
# strace -e trace=execve shows the argv the kernel was given at syscall
# entry, which is the swapped array for an entry-swap exec.
strace -f -e trace=execve -o /tmp/b57-exec.strace -s 200 \
    "$PM" -q -l b57label -- "$TC" echoargs B57CANARY-ARG 2>/dev/null
echo "rc=$?"
grep -E 'execve\(' /tmp/b57-exec.strace | head -4
echo
echo "-- control: the same exec without pmask --"
strace -f -e trace=execve -o /tmp/b57-execctl.strace -s 200 \
    "$TC" echoargs B57CANARY-ARG >/dev/null 2>&1
grep -E 'execve\(' /tmp/b57-execctl.strace | head -2
