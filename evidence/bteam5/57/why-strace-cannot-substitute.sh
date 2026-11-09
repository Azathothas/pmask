#!/bin/sh
# Why `strace` is not a stand-in for the eBPF tracer-syscall channels.
#
# `strace -f` attaches to every child of the process it starts.  A child
# that is already traced refuses a second PTRACE_SEIZE with EPERM, so pmask
# started under `strace -f` cannot seize its own payload.  The failure is
# pmask's `session error`, and its cause is the second tracer, not pmask.
set -u
cd /workspace/wt/bteam5

echo "== 1. pmask under strace -f =="
strace -f -e trace=ptrace -o /tmp/b57-under-strace.log \
    ./tests/pmask -q -l b57strace ./tests/testcases sleepfor 1 2>&1 | head -3
echo "rc=$?"
echo "-- the seize line strace recorded --"
grep -m1 PTRACE_SEIZE /tmp/b57-under-strace.log
echo

echo "== 2. the same failure without pmask: a minimal C probe =="
cat >/tmp/b57/seize.c <<'C'
/* Fork a child, optionally let an external tracer attach, then seize it
 * with the option mask pmask uses.  Separates "the target is traced" from
 * "pmask's seize call is wrong". */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

static const unsigned long OPTS =
    PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
    PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;

int main(int argc, char **argv) {
    int wait_first = (argc > 1 && strcmp(argv[1], "wait") == 0);
    pid_t c = fork();
    if (c == 0) { for (;;) pause(); _exit(0); }
    if (wait_first) usleep(300000);
    long r = ptrace(PTRACE_SEIZE, c, NULL, (void *)OPTS);
    printf("PTRACE_SEIZE(pid %d) = %ld errno=%d (%s)\n",
           (int)c, r, errno, strerror(errno));
    if (r == 0) ptrace(PTRACE_DETACH, c, NULL, NULL);
    kill(c, 9); waitpid(c, NULL, 0);
    return 0;
}
C
cc -O0 -o /tmp/b57/seize /tmp/b57/seize.c || exit 1
echo "-- plain: no other tracer --"
/tmp/b57/seize
echo "-- under strace -f: strace is the first tracer of the child --"
strace -f -e trace=ptrace -o /dev/null /tmp/b57/seize 2>&1 | grep PTRACE_SEIZE
echo

echo "== 3. what a userland observer can read instead =="
./tests/pmask -q -l b57obs ./tests/testcases sleepfor 3 >/dev/null 2>&1 &
S=$!
sleep 0.5
P=$(for d in /proc/[0-9]*; do
        pp=$(sed -n 's/^PPid:[[:space:]]*//p' "$d/status" 2>/dev/null)
        [ "$pp" = "$S" ] && echo "${d#/proc/}"
    done | head -1)
echo "supervisor=$S payload=$P"
echo "payload TracerPid=$(sed -n 's/^TracerPid:[[:space:]]*//p' "/proc/$P/status")"
echo "supervisor tasks:"
for t in /proc/"$S"/task/*; do printf '  %s %s\n' "${t##*/}" "$(cat "$t/comm")"; done
echo "-- a second tracer on the masked payload --"
timeout 4 strace -p "$P" -o /dev/null -e trace=execve 2>&1 | head -2
kill "$S" 2>/dev/null
wait "$S" 2>/dev/null
