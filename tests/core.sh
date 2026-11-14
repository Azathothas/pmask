#!/bin/sh
# ============================================================================
# pmask tracer core suite.  One case per defect of the exec/session core.
# Every case names the defect it catches; a planted defect must turn it red.
#
#   K1   exec from a non-leader thread keeps the real argv         (#1)
#   K2   strings of 5010 and 100010 bytes: fidelity, no tail leak  (#2)
#   K3   10001 arguments: full argv, no sighting                   (#3)
#   K4   32-bit program: loud refusal, program still correct       (#4)
#   K5   session end: detach (default), kill, wait                 (#5)
#   K6   job control: SIGSTOP holds, SIGCONT resumes               (#6)
#   K8   failed exec keeps the retry on the entry-swap path        (#8)
#   K9   failed repoint write: warning, nothing visible, alive     (#9)
#   K10  summary line for the script path, silent when quiet       (#29)
#   K11  completion stop: reads per exec with a 4000-entry env     (#33)
#   K12  thread comm, setproctitle-style rewrite, no-vDSO degradation
#   K13  AT_EXECFN, set-uid gains nothing, execveat/fexecve        (#16)
#   K14  a settled group's new thread starts in Run, not Slow
#   K15  refused window relocation: reported, extent kept; K15b drives
#        the same arm with a real seccomp filter that refuses PR_SET_MM
#   K16  a failed redaction leaves no sighting in the visible spans
#   K17  an empty argv element reaches the program unchanged
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

L='core-label-x'
SE='se-label-core'
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }
T=/tmp/pmask-core.$$
mkdir -p "$T"
cleanup() {
    kill_label "$L" 2>/dev/null
    kill_label "$SE" 2>/dev/null
    kill_comm sleeper KILL 2>/dev/null
    kill_comm testcases KILL 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

waitfile() { # file seconds: wait until the file exists and is non-empty
    i=0
    while [ ! -s "$1" ] && [ "$i" -lt $(($2 * 20)) ]; do sleep 0.05 2>/dev/null || sleep 1; i=$((i + 1)); done
    [ -s "$1" ]
}

# ------------------------------------------------ K1: non-leader exec thread
# Defect: the completion path read the label back as the program's argv.
out=$("$TOOL" -q -l "$L" "$CASES" threadexec "$CASES" echoargs MK-K1-REAL 2>&1)
case "$out" in
    *"arg2=[MK-K1-REAL]"*) pass k1-thread-exec-keeps-argv ;;
    *) fail "k1-thread-exec (want arg2=[MK-K1-REAL], got: $(printf '%s' "$out" | cut -c1-160))" ;;
esac

# --------------------------------------------------------- K2: long strings
# Defect: strings were cut at 4095 bytes and the tail stayed visible.
for n in 5000 100000; do
    pad=$(head -c "$n" /dev/zero | tr '\0' 'a')
    mk="TAILMARKK2N$n"
    rm -f "$T/k2.out"
    # control: the observer must see the tail without pmask
    "$CASES" holdargs "$T/k2c.out" "${pad}${mk}" &
    cp=$!
    waitfile "$T/k2c.out" 5 >/dev/null
    c=$(sightings "$mk")
    kill -9 $cp 2>/dev/null
    [ "$c" -ge 1 ] && pass "k2-control-sees-tail-$n ($c)" || fail "k2-control-$n: observer blind"
    "$TOOL" -q -l "$L" "$CASES" holdargs "$T/k2.out" "${pad}${mk}" &
    waitfile "$T/k2.out" 8 >/dev/null
    arg="${pad}${mk}"
    want=$((n + ${#mk}))
    want_tail=$(printf '%s' "$arg" | tail -c 12)
    if grep -q "len=$want tail=$want_tail$" "$T/k2.out" 2>/dev/null; then
        pass "k2-fidelity-$n (len=$want byte-exact tail)"
    else
        fail "k2-fidelity-$n: $(cat "$T/k2.out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    fi
    s=$(sightings "$mk")
    [ "$s" = 0 ] && pass "k2-no-tail-leak-$n" || fail "k2-tail-leak-$n: $s sighting(s)"
    kill_comm "$L" KILL 2>/dev/null; kill_comm testcases KILL 2>/dev/null
    sleep 0.3
done

# ------------------------------------------------------------ K3: 10001 args
# Defect: argc above 8192 ran with the real command line in /proc.
rm -f "$T/k3.out"
# 10000 argument entries built once and handed over with --args-from-fd,
# so the exec of the program that reads them is the FIRST exec of the
# child (the zero-exposure path).  A re-exec of a settled process would
# take the post-exec path and could show the argv in the sampled window.
: > "$T/k3.args"
printf '%s\0' "$CASES" holdargs "$T/k3.out" >> "$T/k3.args"
i=1
while [ "$i" -le 10000 ]; do
    printf '%s\0' "$i" >> "$T/k3.args"
    i=$((i + 1))
done
printf '%s\0' MKK3SECRET >> "$T/k3.args"
"$TOOL" -q -l "$L" --args-from-fd 3 3<"$T/k3.args" >/dev/null 2>&1 &
waitfile "$T/k3.out" 60 >/dev/null
if grep -q '^argc=10004$' "$T/k3.out" 2>/dev/null \
    && grep -q '^arg10003 len=10 tail=MKK3SECRET$' "$T/k3.out"; then
    pass k3-argv-complete-10000
else
    fail "k3-argv: $(head -2 "$T/k3.out" 2>/dev/null | tr '\n' ' ')"
fi
s=$(sightings MKK3SECRET)
[ "$s" = 0 ] && pass k3-no-sighting || fail "k3-sighting: $s"
kill_comm "$L" KILL 2>/dev/null; kill_comm testcases KILL 2>/dev/null
sleep 0.3

# ------------------------------------------------------------ K4: 32-bit
# A 32-bit image cannot be redacted by the 64-bit tracer, so the default
# refuses it before it runs.  `--allow-foreign` is the explicit opt-in and
# the run is counted as a foreign-arch degradation.
if [ -x ./testcases32 ]; then
    out=$("$TOOL" -l "$L" ./testcases32 echoargs MK-K4 2>"$T/k4.err")
    rc=$?
    if [ "$rc" = 137 ] && [ -z "$out" ] && grep -q '32-bit.*refused' "$T/k4.err"; then
        pass "k4-32bit-refused-by-default (rc=$rc)"
    else
        fail "k4-32bit-refused-by-default (rc=$rc out: $(printf '%s' "$out" | cut -c1-120))"
    fi
    grep -q '32-bit (foreign ABI) exec(s) refused' "$T/k4.err" \
        && pass k4-summary-names-foreign-refused \
        || fail "k4-summary-missing-foreign-refused ($(tail -1 "$T/k4.err"))"
    out=$("$TOOL" -l "$L" --allow-foreign ./testcases32 echoargs MK-K4 2>"$T/k4b.err")
    rc=$?
    case "$out" in
        *"arg2=[MK-K4]"*) pass k4-32bit-allow-foreign-runs ;;
        *) fail "k4-32bit-allow-foreign-runs (rc=$rc out: $(printf '%s' "$out" | cut -c1-120))" ;;
    esac
    grep -q 'foreign-arch' "$T/k4b.err" && pass k4-summary-names-foreign-arch \
        || fail "k4-summary-missing-foreign-arch ($(tail -1 "$T/k4b.err"))"
else
    skip "k4-32bit (tests/testcases32 absent: the i686 build is part of vm/run.sh)"
fi

# -------------------------------------------------------- K5: session end
# Defect: descendants were frozen (library) or killed (CLI) when the master exited.
# (SE is defined with the other constants so the exit trap can use it.)
# The supervisor must return on its own once the master is gone.  Bound
# the run: a session-end deadlock used to block the supervisor in wait4
# and wedge the whole suite, so a hang is a failure, not a wait.
t0=$(date +%s)
timeout 10 "$TOOL" -q -l "$SE" /bin/sh -c "'$CASES' sleeper MK-K5 & exit 0" >/dev/null 2>&1
rc=$?
t1=$(date +%s)
if [ "$rc" = 124 ]; then
    fail "k5-supervisor-exits (hung $((t1 - t0))s: session-end deadlock)"
else
    pass "k5-supervisor-exits (rc=$rc in $((t1 - t0))s)"
fi
# Poll rather than sleep: under KVM on a loaded host the fork, the exec
# and the relocation can take longer than a fixed 0.5s, and a fixed sleep
# turns a slow guest into a false failure.  The claim is that the
# background job survives with the label, not that it appears in 0.5s.
n=0
s=0
i=0
while [ "$i" -lt 100 ]; do
    i=$((i + 1))
    n=$(comm_count "$SE")
    s=$(sightings MK-K5)
    if [ "$n" -ge 1 ] && [ "$s" = 0 ]; then break; fi
    sleep 0.05
done
if [ "$n" -ge 1 ] && [ "$s" = 0 ]; then pass "k5-detach-keeps-background-job ($n alive with the label, $s sightings)"
else fail "k5-detach (alive=$n sightings=$s after $i polls)"; fi
kill_label "$SE"; kill_comm sleeper KILL 2>/dev/null
# Wait for the detach case's tree to be gone before the kill case starts:
# a process still dying from the previous case would be counted here.
i=0
while [ "$i" -lt 40 ] && [ "$(comm_count "$SE")" != 0 ]; do i=$((i + 1)); sleep 0.05 2>/dev/null || sleep 1; done

# The kill is asynchronous: the supervisor returns after SIGKILLing the
# tree, and the tracee is reaped by its own parent.  Poll the observable
# for up to 2 s and pass only when the count reaches 0; a fixed sleep
# turns a slow guest into either a false failure or, worse, a pass that
# never saw the tree die.
"$TOOL" -q -l "$SE" --on-exit kill /bin/sh -c "'$CASES' sleeper MK-K5K & exit 0" >/dev/null 2>&1
n=1
i=0
while [ "$i" -lt 40 ]; do
    i=$((i + 1))
    n=$(comm_count "$SE")
    [ "$n" = 0 ] && break
    sleep 0.05 2>/dev/null || sleep 1
done
[ "$n" = 0 ] && pass "k5-on-exit-kill-terminates-tree (0 alive after $i polls)" || fail "k5-on-exit-kill ($n still alive after 2s)"
kill_label "$SE"; kill_comm sleeper KILL 2>/dev/null

t0=$(date +%s)
"$TOOL" -q -l "$SE" --on-exit wait /bin/sh -c "'$CASES' sleepfor 2 & exit 0" >/dev/null 2>&1
t1=$(date +%s)
[ $((t1 - t0)) -ge 2 ] && pass "k5-on-exit-wait-waits ($((t1 - t0))s)" || fail "k5-on-exit-wait (returned after $((t1 - t0))s, want >= 2)"

# ------------------------------------------------------- K6: job control
# Defect: the group-stop was swallowed: SIGSTOP never held the tree.
rm -f "$T/k6.f"
"$TOOL" -q -l "$L" "$CASES" touchloop "$T/k6.f" >/dev/null 2>&1 &
sup=$!
waitfile "$T/k6.f" 5 >/dev/null
tp=""
for d in /proc/[0-9]*; do
    p=${d#/proc/}
    [ "$(proc_ppid "$p")" = "$sup" ] && tp=$p
done
if [ -z "$tp" ]; then
    fail "k6-job-control: tracee pid not found"
else
    # A traced tracee shows state 't' in a ptrace-stop and in a
    # group-stop, so the state letter alone proves nothing.  The
    # observable claim is that the tree stops making progress.
    kill -STOP "$tp"
    sleep 0.4
    a=$(wc -c < "$T/k6.f"); sleep 0.6; b=$(wc -c < "$T/k6.f")
    if [ "$a" -gt 0 ] && [ "$a" = "$b" ]; then pass "k6-sigstop-holds (file frozen at $a bytes)"
    else fail "k6-sigstop (size $a -> $b, want equal and non-zero)"; fi
    kill -CONT "$tp"
    sleep 0.6
    c=$(wc -c < "$T/k6.f")
    if [ "$c" -gt "$b" ]; then pass "k6-sigcont-resumes (size $b -> $c)"
    else fail "k6-sigcont (size $b -> $c, want growth)"; fi
fi
kill -9 "$sup" 2>/dev/null; kill_comm "$L" KILL 2>/dev/null; kill_comm testcases KILL 2>/dev/null; sleep 0.2

# --------------------------------------------- K8: failed exec then a retry
# Defect: the failed exec settled to Run; the retry took the post-exec path.
log=$("$TOOL" -v -l "$L" "$CASES" forkretry /nonexistent/pmask-k8 "$CASES" echoargs MK-K8 2>&1)
nswap=$(printf '%s\n' "$log" | grep -c 'entry pointer-swap (ELF)')
nre=$(printf '%s\n' "$log" | grep -c 'exec-done reread=1')
if [ "$nswap" -ge 2 ] && [ "$nre" = 0 ]; then pass "k8-retry-keeps-entry-swap (swaps=$nswap rereads=$nre)"
else fail "k8-retry (swaps=$nswap rereads=$nre, want >=2 and 0)"; fi

# ------------------------------------------------ K9: failed repoint write
# Defect: a failed repoint left a kernel-copy pointer without any message,
# and the return skipped the register restore after the injected mmap, so
# the tracee resumed at the wrong instruction and died.  Zero sightings
# alone cannot see that: a dead tracee has no sightings either.  The
# second run checks the resume itself: a program that ignores its argv
# must still exit 0.
PMASK_FAULT_POKE=1 "$TOOL" -l "$L" "$CASES" sleeper MK-K9 >/dev/null 2>"$T/k9.err" &
k9sup=$!
sleep 1
s=$(sightings MK-K9)
if grep -q 'repoint failed' "$T/k9.err" && [ "$s" = 0 ]; then
    pass "k9-failed-repoint-zeroes-and-warns ($s sightings)"
else
    fail "k9-failed-repoint (sightings=$s err: $(head -2 "$T/k9.err" | tr '\n' '|'))"
fi
kill -9 "$k9sup" 2>/dev/null
kill_comm "$L" KILL 2>/dev/null; kill_comm sleeper KILL 2>/dev/null; sleep 0.2
PMASK_FAULT_POKE=1 "$TOOL" -q -l "$L" "$CASES" >/dev/null 2>"$T/k9b.err"
rc=$?
if [ "$rc" = 0 ]; then
    pass "k9-failed-repoint-resumes-cleanly (exit $rc)"
else
    fail "k9-failed-repoint-resume (exit $rc: $(head -2 "$T/k9b.err" | tr '\n' '|'))"
fi

# ----------------------------------------------------- K10: summary line
# Defect: a script exec degraded silently, and the line called every
# degradation "unredacted" while counting a skipped comm with it.
printf '#!/bin/sh\n/bin/true\n' > "$T/k10.sh"; chmod 755 "$T/k10.sh"
"$TOOL" -l "$L" "$T/k10.sh" >/dev/null 2>"$T/k10.err"
if grep -Eq '^pmask: [0-9]+ of [0-9]+ execs degraded \(post-exec( x[0-9]+)?\)' "$T/k10.err"; then
    pass "k10-summary-names-post-exec ($(grep 'execs degraded' "$T/k10.err"))"
else fail "k10-summary (stderr: $(head -3 "$T/k10.err" | tr '\n' '|'))"; fi
# The script path was redacted, with a short window: the line must not
# call it "unredacted".
grep -q 'execs unredacted' "$T/k10.err" && fail "k10-script-is-not-called-unredacted" \
    || pass k10-script-is-not-called-unredacted
"$TOOL" -q -l "$L" "$T/k10.sh" >/dev/null 2>"$T/k10q.err"
[ ! -s "$T/k10q.err" ] && pass k10-quiet-prints-nothing || fail "k10-quiet ($(head -1 "$T/k10q.err"))"
"$TOOL" -l "$L" "$CASES" echoargs a >/dev/null 2>"$T/k10e.err"
grep -q 'execs degraded' "$T/k10e.err" && fail "k10-clean-run-prints-summary" || pass k10-clean-elf-run-is-silent
# The runner path prints one report.  A clean `--secret` run used to add a
# second `N of M execs unredacted` line after the tracer's (absent)
# summary, even with nothing degraded.
printf 'k10-token\n' > "$T/k10.tok"; chmod 600 "$T/k10.tok"
"$TOOL" -l "$L" --secret T=file:"$T/k10.tok" "$CASES" echoargs a >/dev/null 2>"$T/k10s.err"
grep -q 'execs degraded' "$T/k10s.err" && fail "k10-clean-secret-run-prints-summary" || pass k10-clean-secret-run-is-silent
grep -q 'execs unredacted' "$T/k10s.err" && fail "k10-clean-run-prints-the-duplicate-line" || pass k10-clean-run-has-no-duplicate-line

# --------------------------------------- K15: refused window relocation
# Defect: a lone `PR_SET_MM_MAP` refusal printed nothing.  The summary
# returned early when no other degradation was counted, so the headline
# promise ("a refused window is reported") held only when something else
# had already degraded.  There was also no way to reach the refusal path
# on a kernel that accepts the call, so the counter had no test at all.
PMASK_FAULT_REFUSE_MAP=1 "$TOOL" -l "$L" "$CASES" echoargs MK-K15 >/dev/null 2>"$T/k15.err"
if grep -Eq '^pmask: [0-9]+ of [0-9]+ execs kept the kernel.s argv and environ windows \(PR_SET_MM_MAP refused\)$' "$T/k15.err"; then
    pass "k15-refused-window-is-reported ($(grep 'environ windows' "$T/k15.err"))"
else fail "k15-window-summary (stderr: $(head -3 "$T/k15.err" | tr '\n' '|'))"; fi
PMASK_FAULT_REFUSE_MAP=1 "$TOOL" -q -l "$L" "$CASES" echoargs MK-K15 >/dev/null 2>"$T/k15q.err"
[ ! -s "$T/k15q.err" ] && pass k15-quiet-prints-nothing || fail "k15-quiet ($(head -1 "$T/k15q.err"))"
"$TOOL" -l "$L" "$CASES" echoargs MK-K15 >/dev/null 2>"$T/k15c.err"
grep -q 'environ windows' "$T/k15c.err" && fail "k15-control-reports-a-refusal" || pass k15-accepted-window-is-silent
# The observable the message promises: the text is the label, the kernel
# window keeps the label plus one NUL per argv entry, and environ is a
# NUL block instead of empty.  The label is its own, because `-l` erases
# the marker from the cmdline and the process can then only be found by
# comm.
K15L='k15-win-label'
PMASK_FAULT_REFUSE_MAP=1 "$TOOL" -l "$K15L" "$CASES" sleeper MK-K15 >/dev/null 2>"/dev/null" &
k15bg=$!
i=0
k15pid=""
while [ "$i" -lt 100 ]; do
        i=$((i + 1))
        # The supervisor carries the label too, so take the labelled pid
        # whose parent is itself labelled: that is the exec'd child.
        k15all=""
        for c in /proc/[0-9]*/comm; do
                [ "$(cat "$c" 2>/dev/null)" = "$K15L" ] || continue
                q=${c#/proc/}
                k15all="$k15all ${q%/comm}"
        done
        for a in $k15all; do
                pp=$(sed -n 's/^PPid:[[:space:]]*//p' "/proc/$a/status" 2>/dev/null)
                case " $k15all " in *" $pp "*) k15pid=$a ;; esac
        done
        [ -n "$k15pid" ] && break
        sleep 0.05
done
if [ -n "$k15pid" ]; then
        # Without the relocation the kernel's own window stays.  The
        # presentation is the label, spaces, and one final NUL, so the
        # cmdline length equals the stat span and has no NUL run.  The
        # environment is a decoy, not an all-NUL block.
        k15got=$(sed 's/^.*) //' "/proc/$k15pid/stat" 2>/dev/null | awk '{ print $47 - $46 }')
        k15text=$(head -c "${#K15L}" "/proc/$k15pid/cmdline" 2>/dev/null)
        k15len=$(wc -c < "/proc/$k15pid/cmdline" 2>/dev/null | tr -d ' ')
        k15nuls=$(tr -cd '\0' < "/proc/$k15pid/cmdline" 2>/dev/null | wc -c)
        k15env=$(wc -c < "/proc/$k15pid/environ" 2>/dev/null | tr -d ' ')
        k15envnuls=$(tr -cd '\0' < "/proc/$k15pid/environ" 2>/dev/null | wc -c)
        if [ "$k15got" = "$k15len" ] && [ "$k15text" = "$K15L" ] && [ "$k15nuls" = 1 ] \
            && [ "${k15env:-0}" -gt 0 ] && [ "${k15envnuls:-0}" -lt "${k15env:-0}" ]; then
                pass "k15-window-kept (arg extent $k15got = cmdline length, one NUL, environ ${k15env} bytes with a decoy)"
        else fail "k15-window (stat $k15got, cmdline $k15len nuls $k15nuls, environ ${k15env:-?} nuls ${k15envnuls:-?}, text is not the label)"; fi
else fail "k15-window: no labelled process appeared after $i polls"; fi
kill_comm "$K15L" KILL 2>/dev/null; kill_comm sleeper KILL 2>/dev/null; wait "$k15bg" 2>/dev/null; sleep 0.2

# ------------------------------------- K15b: a real PR_SET_MM refusal
# The fault hook proves the reporting path, not the detection of a real
# refusal.  This wrapper installs a seccomp filter that returns EPERM for
# prctl(PR_SET_MM, ...) and allows every other call, then execs pmask.
# The filter is inherited by the supervisor and the payload, so the
# window relocation is refused by the kernel rather than by the hook.
cat > "$T/deny_mm.c" <<'C'
#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stddef.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_MM, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog p = { .len = sizeof(f) / sizeof(f[0]), .filter = f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 1;
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &p)) return 1;
    execv(argv[1], &argv[1]);
    return 1;
}
C
if cc -O1 -o "$T/deny_mm" "$T/deny_mm.c" 2>/dev/null; then
    K15BL='k15b-label'
    "$T/deny_mm" "$TOOL" -l "$K15BL" "$CASES" echoargs MK-K15B >"$T/k15b.out" 2>"$T/k15b.err"
    rc=$?
    if [ "$rc" = 0 ] && grep -q 'arg2=\[MK-K15B\]' "$T/k15b.out" \
        && grep -q 'kept the kernel.s argv and environ windows (PR_SET_MM_MAP refused)' "$T/k15b.err"; then
        pass "k15b-real-prctl-refusal-is-reported (rc=$rc)"
    else
        fail "k15b-real-prctl-refusal (rc=$rc out=$(tr '\n' '|' < "$T/k15b.out") err=$(head -2 "$T/k15b.err" | tr '\n' '|'))"
    fi
    "$T/deny_mm" "$TOOL" -l "$K15BL" "$CASES" sleeper MK-K15B >/dev/null 2>/dev/null &
    k15bbg=$!
    i=0
    k15bpid=""
    while [ "$i" -lt 100 ]; do
        i=$((i + 1))
        k15ball=""
        for c in /proc/[0-9]*/comm; do
            [ "$(cat "$c" 2>/dev/null)" = "$K15BL" ] || continue
            q=${c#/proc/}
            k15ball="$k15ball ${q%/comm}"
        done
        for a in $k15ball; do
            pp=$(sed -n 's/^PPid:[[:space:]]*//p' "/proc/$a/status" 2>/dev/null)
            case " $k15ball " in *" $pp "*) k15bpid=$a ;; esac
        done
        [ -n "$k15bpid" ] && break
        sleep 0.05
    done
    if [ -n "$k15bpid" ]; then
        k15bgot=$(sed 's/^.*) //' "/proc/$k15bpid/stat" 2>/dev/null | awk '{ print $47 - $46 }')
        k15btext=$(head -c "${#K15BL}" "/proc/$k15bpid/cmdline" 2>/dev/null)
        k15blen=$(wc -c < "/proc/$k15bpid/cmdline" 2>/dev/null | tr -d ' ')
        k15bnuls=$(tr -cd '\0' < "/proc/$k15bpid/cmdline" 2>/dev/null | wc -c)
        k15benv=$(wc -c < "/proc/$k15bpid/environ" 2>/dev/null | tr -d ' ')
        k15benvnuls=$(tr -cd '\0' < "/proc/$k15bpid/environ" 2>/dev/null | wc -c)
        if [ "$k15bgot" = "$k15blen" ] && [ "$k15btext" = "$K15BL" ] && [ "$k15bnuls" = 1 ] \
            && [ "${k15benv:-0}" -gt 0 ] && [ "${k15benvnuls:-0}" -lt "${k15benv:-0}" ]; then
            pass "k15b-real-refusal-keeps-the-window (extent $k15bgot = cmdline length, one NUL)"
        else
            fail "k15b-window (stat $k15bgot, cmdline $k15blen nuls $k15bnuls, environ ${k15benv:-?} nuls ${k15benvnuls:-?}, text is not the label)"
        fi
    else
        fail "k15b-window: no labelled process appeared after $i polls"
    fi
    kill_comm "$K15BL" KILL 2>/dev/null
    kill_comm sleeper KILL 2>/dev/null
    wait "$k15bbg" 2>/dev/null
    sleep 0.2
else
    skip "k15b-real-prctl-refusal (no C compiler for the seccomp wrapper)"
fi

# ------------------------------------------ K11: completion stop, big env
# Defect: the completion stop re-read every environment string to infer
# the span (one process_vm_readv per entry, more for long strings).
vars=$(seq 1 4000 | sed 's/^/PMKV/;s/$/=value/')
log=$(env $vars "$TOOL" -v -l "$L" "$CASES" echoargs a 2>&1)
line=$(printf '%s\n' "$log" | grep 'completion-stop' | head -1)
reads=$(printf '%s' "$line" | sed -n 's/.*reads=\([0-9]*\).*/\1/p')
us=$(printf '%s' "$line" | sed -n 's/.*completion-stop \([0-9]*\)us.*/\1/p')
if [ -n "$reads" ] && [ "$reads" -lt 200 ]; then
    pass "k11-completion-reads-bounded (reads=$reads for a 4000-entry environment)"
else fail "k11-completion-reads (line: $line)"; fi
accel="${PMASK_VM_ACCEL:-}"
[ -n "$accel" ] || { [ -r /tmp/accel ] && accel=$(cat /tmp/accel); }
[ -n "$accel" ] || accel="bare metal"
echo "INFO completion-stop ${us:-?}us reads=${reads:-?} (4000-entry env, kernel $(uname -r), $(uname -m), accel $accel)"

# ----------------------------------------- K12: comm, rename, no-vDSO
# Defect: per-thread comm unset, setproctitle clobbered the program's argv,
# and a missing syscall site degraded without a report.
LC=threadlabelxyza
out=$("$TOOL" -q -l "${LC}bcd" "$CASES" threadnames 2>&1)
n=$(printf '%s\n' "$out" | grep -c "^thread-comm=$LC\$")
o=$(printf '%s\n' "$out" | grep -c '^thread-comm=')
[ "$n" = "$o" ] && [ "$n" -ge 4 ] && pass "k12-thread-comm-is-label ($n of $o threads)" || fail "k12-thread-comm ($n of $o: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-150))"

out=$("$TOOL" -q -l "$L" "$CASES" proctitle MK-K12 2>&1)
case "$out" in
    *"args-same=true path-same=true"*) pass k12-setproctitle-rewrite-keeps-args ;;
    *) fail "k12-setproctitle ($(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160))" ;;
esac
# Control: without pmask, the same rewrite is visible to `std::env::args()`
# because std re-reads the saved argv pointers.  This is the contract an
# embedder must know: snapshot argv before `mask_self`.
out=$("$CASES" proctitle MK-K12C 2>&1)
case "$out" in
    *"args-same=false"*) pass k12-control-std-args-read-the-kernel-block ;;
    *) fail "k12-control-std-args-read-the-kernel-block ($(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160))" ;;
esac

PMASK_FAULT_NOVDSO=1 "$TOOL" -l "$L" "$CASES" sleeper MK-K12V >/dev/null 2>"$T/k12v.err"
rc=$?
# The fault hook withholds the vDSO route and the maps fallback, so the
# completion stop cannot build the redaction block: the exec is counted as
# unredacted and the warning names it.  The entry swap already replaced
# the real argv, so the marker was never in the new image.
if grep -q 'exec not redacted' "$T/k12v.err" \
    && grep -Eq '^pmask: [0-9]+ of [0-9]+ execs degraded \(unredacted\)' "$T/k12v.err"; then
    pass "k12-no-vdso-elf-degradation-is-visible-and-counted (rc=$rc)"
else
    fail "k12-no-vdso (rc=$rc err: $(head -3 "$T/k12v.err" | tr '\n' '|'))"
fi
kill_comm "$L" KILL 2>/dev/null; kill_comm sleeper KILL 2>/dev/null; sleep 0.2

# ------------------------------------------------- K13: documented claims
out=$("$TOOL" -q -l "$L" "$CASES" execfn 2>&1)
case "$out" in
    "execfn=$CASES") pass "k13-at-execfn-is-the-real-path ($out)" ;;
    *) fail "k13-at-execfn (got: $out, want execfn=$CASES)" ;;
esac

if [ "$(id -u)" = 0 ]; then
    cp "$CASES" "$T/suidprobe"; chmod 4755 "$T/suidprobe"; chmod 755 "$T"
    ctl=$("$CASES" dropto 1000 "$T/suidprobe" suidprobe 2>&1)
    out=$("$CASES" dropto 1000 "$TOOL" -q -l "$L" "$T/suidprobe" suidprobe 2>&1)
    case "$ctl" in
        *euid=0*) pass "k13-control-setuid-works-unsupervised ($ctl)" ;;
        *) skip "k13-setuid-control ($ctl): filesystem may be nosuid" ;;
    esac
    case "$out" in
        *"uid=1000 euid=1000"*) pass "k13-setuid-gains-nothing-under-supervision ($out)" ;;
        *) fail "k13-setuid ($out)" ;;
    esac
else
    skip "k13-setuid (needs root to create a set-uid file)"
fi

for kind in execveat fexecve; do
    log=$("$TOOL" -v -l "$L" "$CASES" $kind "$CASES" echoargs MK-K13 2>&1)
    nswap=$(printf '%s\n' "$log" | grep -c 'entry pointer-swap (ELF)')
    case "$log" in
        *"arg2=[MK-K13]"*) pass "k13-$kind-argv-intact (entry swaps: $nswap)" ;;
        *) fail "k13-$kind ($(printf '%s' "$log" | tail -3 | tr '\n' '|' | cut -c1-200))" ;;
    esac
done

# K13b: the two AT_EXECFN readings diverge in the same run.  The payload's
# own getauxval returns the real path; the AT_EXECFN string that
# /proc/<pid>/auxv points at is the label.  A change that makes them agree
# is an exposure change, not a fix.
"$TOOL" -q -l "$L" "$CASES" execfn 3 >"$T/k13b.out" 2>/dev/null &
k13b_sup=$!
k13b_pid=""
k13b_i=0
while [ "$k13b_i" -lt 30 ]; do
    for d in /proc/[0-9]*; do
        case "$(cat "$d/comm" 2>/dev/null)" in
            "$L"*)
                case "$(readlink "$d/exe" 2>/dev/null)" in
                    */testcases) k13b_pid=${d#/proc/}; break 2 ;;
                esac
                ;;
        esac
    done
    sleep 0.1
    k13b_i=$((k13b_i + 1))
done
k13b_own=$(sed -n 's/^execfn=//p' "$T/k13b.out" 2>/dev/null | head -1)
k13b_aux=""
if [ -n "$k13b_pid" ]; then
    k13b_ptr=$(od -An -v -t x8 "/proc/$k13b_pid/auxv" 2>/dev/null | tr -s ' ' '\n' |
        awk 'NF { if (++n % 2 == 1) t = $1; else if (t ~ /^0*1f$/) print $1 }')
    if [ -n "$k13b_ptr" ]; then
        k13b_aux=$(dd if="/proc/$k13b_pid/mem" bs=1 skip=$((0x$k13b_ptr)) count=512 2>/dev/null |
            tr '\0' '\n' | head -1)
    fi
fi
kill -9 "$k13b_pid" "$k13b_sup" 2>/dev/null
wait "$k13b_sup" 2>/dev/null
if [ -z "$k13b_pid" ] || [ -z "$k13b_aux" ]; then
    skip "k13b-at-execfn-diverges (pid=[$k13b_pid] auxv=[$k13b_aux])"
elif [ "$k13b_own" = "$CASES" ] && [ "$k13b_aux" = "$L" ]; then
    pass "k13b-at-execfn-diverges (payload=$k13b_own auxv=$k13b_aux)"
elif [ "$k13b_own" = "$k13b_aux" ]; then
    fail "k13b-at-execfn-diverges (both readings agree at [$k13b_own])"
else
    fail "k13b-at-execfn-diverges (payload=[$k13b_own] auxv=[$k13b_aux], want payload=$CASES auxv=$L)"
fi

# ------------------------------------------------ K16: failed redaction
# Defect: a failure after the kernel copied the real strings returned
# without zeroing the visible argv/environ spans.  A script exec is the
# case where the real strings are in that region: the repoint fault fires
# on its first argv pointer, and the visible span must be zeroed before
# the tracer returns.  The program cannot keep running with an empty
# interpreter line, so the assertion is the warning plus zero sightings,
# not liveness.
printf '#!/bin/sh\nsleep 2\n' > "$T/k16.sh"; chmod 755 "$T/k16.sh"
PMASK_FAULT_POKE=1 "$TOOL" -l "$L" "$T/k16.sh" MK-D5-POKE >/dev/null 2>"$T/k16.err" </dev/null &
k16p=$!
waitfile "$T/k16.err" 5 >/dev/null
# The warning is written before the zeroing, so the sample must give the
# walk time to finish.  Poll the observable instead of sleeping a fixed
# time: a regression that skips the zeroing leaves the marker visible for
# the script's whole 2 s life, so the deadline cannot hide it.
s=1
i=0
while [ "$i" -lt 40 ]; do
    s=$(sightings MK-D5-POKE)
    [ "$s" = 0 ] && break
    i=$((i + 1))
    sleep 0.05 2>/dev/null || sleep 1
done
if grep -q 'repoint failed' "$T/k16.err" && [ "$s" = 0 ]; then
    pass "k16-failed-repoint-zeroes-the-visible-spans ($s sightings)"
else
    fail "k16-failed-repoint (sightings=$s err: $(head -2 "$T/k16.err" | tr '\n' '|'))"
fi
kill -9 "$k16p" 2>/dev/null
kill_comm "$L" KILL 2>/dev/null; kill_comm sleeper KILL 2>/dev/null
wait "$k16p" 2>/dev/null
# With `--keep-env` the environment is the caller's to keep: the same
# failure zeroes the argv span and leaves the environment alone.  The
# test binary with an empty argv prints the environment, so the check
# does not depend on an argument that the failure removed.
out=$(PMASK_FAULT_POKE=1 "$TOOL" -q -l "$L" --keep-env "$CASES" 2>"$T/k16b.err")
case "$out" in
    "env=") fail "k16b-failed-repoint-environ (the environment was zeroed)" ;;
    env=*) pass "k16b-failed-repoint-keeps-an-environ-the-caller-kept" ;;
    *) fail "k16b-failed-repoint-environ (got: $(printf '%s' "$out" | cut -c1-160))" ;;
esac
# The block-build branch itself: `PMASK_FAULT_NOVDSO` withholds the
# vDSO route and the maps fallback, so no syscall instruction is found and
# the block build fails.  The same zeroing applies; the warning is the
# proof the failure path was reached, and zero sightings is the proof the
# visible spans were cleared.
PMASK_FAULT_NOVDSO=1 "$TOOL" -l "$L" "$T/k16.sh" MK-D5-BLOCK >/dev/null 2>"$T/k16c.err" </dev/null &
k16bg=$!
waitfile "$T/k16c.err" 2 >/dev/null
if grep -q 'exec not redacted' "$T/k16c.err"; then
    s=$(sightings MK-D5-BLOCK)
    if [ "$s" = 0 ]; then
        pass "k16c-failed-block-zeroes-the-visible-spans ($(grep 'exec not redacted' "$T/k16c.err" | head -1))"
    else
        fail "k16c-failed-block-leaks ($s sighting(s))"
    fi
else
    fail "k16c-failed-block (PMASK_FAULT_NOVDSO did not reach the failure path: $(head -2 "$T/k16c.err" | tr '\n' '|'))"
fi
kill_comm "$L" KILL 2>/dev/null; wait "$k16bg" 2>/dev/null; sleep 0.2

# --------------------------------------------- K17: empty argv elements
# Defect: `snapshot_argv` dropped every empty element, so `argv[0]=""` and
# an empty argument in the middle shifted the program's arguments.
out=$("$TOOL" -q -l "$L" "$CASES" echoargs a "" b 2>&1)
case "$out" in
    *"arg3=[] arg4=[b]"*) pass "k17-empty-argv-element-is-forwarded" ;;
    *) fail "k17-empty-argv-element (got: $(printf '%s' "$out" | cut -c1-200))" ;;
esac

# --------------------------------------- K14: thread syscall-stop cost
# Defect caught: a CLONE_THREAD newcomer enters syscall supervision, so
# every thread pays two ptrace stops per system call for the life of the
# process.  A settled group's new thread must start in Run, which the
# tracer reports as "thread, group already settled" rather than a plain
# newcomer line.  The probe makes 2000 getpid() calls per thread, so a
# thread left in Slow would also be measurable as a stalled or very slow
# run, but the assertion is on the engine's own classification.
T14="$T/k14"
mkdir -p "$T14"
"$TOOL" -v -l mk-k14 "$CASES" spinthreads 4 2000 >"$T14/out" 2>"$T14/err" &
P=$!
waited=0
while [ "$waited" -lt 100 ]; do
    [ -s "$T14/out" ] && break
    kill -0 "$P" 2>/dev/null || break
    waited=$((waited + 1))
    sleep 0.1
done
wait "$P" 2>/dev/null
# grep -c already prints 0 on no match, so || echo 0 would print twice
settled=$(grep -c 'thread, group already settled' "$T14/err" 2>/dev/null)
slow=$(grep -c 'new tracee$' "$T14/err" 2>/dev/null)
ok=$(grep -c 'out=ok' "$T14/out" 2>/dev/null)
[ -n "$settled" ] || settled=0
[ -n "$slow" ] || slow=0
[ -n "$ok" ] || ok=0
if [ "$ok" -ge 1 ] && [ "$settled" -ge 4 ] && [ "$slow" = 0 ]; then
    pass "k14-thread-starts-settled (settled=$settled slow=$slow)"
else
    fail "k14-thread-starts-settled (settled=$settled slow=$slow out=$ok)"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ]
