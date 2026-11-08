#!/bin/sh
# Regression cases for two fixed defects:
#
#   R1  --rexec must not fall back to the on-disk file when the memfd exec
#       is refused.  The ordered chain reports the refused step and runs
#       the same image through /proc/self/fd; when every carrier fails it
#       exits 126 (127 for ENOENT) and the program never runs from the
#       path the caller left out.
#   R2  --secret-close-on-exec must withhold the descriptor from a child
#       at its fork, not at its exec.  The payload keeps it for its whole
#       life; a child that has forked and not yet exec'd does not have it.
#
# Each case prints what it observed and the verdict, so a regression flips
# the line rather than requiring a reader to trust a comment.
#
# POSIX sh only.  Needs a C compiler for the seccomp probe.  Without one
# the R1 control cannot run, and the verdict fails rather than reporting a
# green run in which the rexec refusal was never exercised: this suite is
# the only regression test for it.
set -u
cd "$(dirname "$0")" || exit 2
TOOL="$(pwd)/pmask"
CASES="$(pwd)/testcases"
[ -x "$TOOL" ] || { echo "FATAL: $TOOL missing"; exit 2; }
[ -x "$CASES" ] || { echo "FATAL: $CASES missing"; exit 2; }

T="${TMPDIR:-/tmp}/pmask-regress.$$"
mkdir -p "$T"
chmod 700 "$T"
trap 'rm -rf "$T"' EXIT INT TERM
FAIL=0
R1_DECIDED=0
pass() { echo "PASS $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL $*"; }
skip() { echo "SKIP $*"; }

# ---------------------------------------------------------------- R1
# A filter that refuses execveat and permits execve.  The wrapper installs
# it and then execs pmask, so the filter is inherited by pmask's
# child: its execveat of the sealed image is refused while the ordinary
# execve still works.  That is the only shape that reaches pmask's own
# rexec path; a payload cannot install a filter before the first exec.
cat > "$T/deny.c" <<'C'
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stddef.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog p = { .len = sizeof(f)/sizeof(f[0]), .filter = f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 1;
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &p)) return 1;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 1;
    syscall(__NR_execveat, fd, "", &argv[1], environ, AT_EMPTY_PATH);
    /* The refusal is the control's evidence, so say it out loud. */
    perror("execveat");
    execv(argv[1], &argv[1]);
    return 1;
}
C
if cc -O1 -o "$T/deny" "$T/deny.c" 2>/dev/null; then
    # The filter really refuses execveat: the error line appears and the
    # fallback still runs, which is the control for this case.
    "$T/deny" /bin/echo ctl >"$T/ctl.out" 2>"$T/ctl.err"
    if grep -q 'Operation not permitted' "$T/ctl.err" && grep -q ctl "$T/ctl.out"; then
        pass "r1-control-execveat-refused-execve-allowed"
        R1_DECIDED=1
    else
        skip "r1-control (the seccomp filter did not behave as expected)"
    fi

    # Two arms.  r1: the refusal is reported and the run continues on the
    # next carrier, so the exit status is 0 and the exe link names the
    # memfd.  r1b: when every image carrier is refused the child exits 126
    # and the on-disk file never runs; the control below runs the same
    # wrapper without --rexec to show the refusal is the memfd exec.
    "$T/deny" "$TOOL" --rexec --label cm-r1 -- "$CASES" exe-id \
        >"$T/r1.out" 2>"$T/r1.err"
    rc=$?
    if [ "$rc" = 0 ] && grep -q 'exe=/memfd:' "$T/r1.out" \
        && grep -q 'execveat refused' "$T/r1.err" \
        && grep -q -- '--rexec fallback' "$T/r1.err"; then
        pass "r1-refused-execveat-reports-and-uses-the-next-carrier (rc=$rc)"
    else
        fail "r1-refused-execveat (rc=$rc out=$(tr '\n' '|' < "$T/r1.out") err=$(tr '\n' '|' < "$T/r1.err"))"
    fi

    # The second arm: when every image carrier is refused, the child must
    # exit 126 and must not run the on-disk file.  The fault hook drives
    # the same arm on a host where a real carrier would succeed.
    PMASK_FAULT_REXEC_FAIL=1 "$T/deny" "$TOOL" --rexec --label cm-r1 -- \
        /bin/echo MK-R1-FAULT >"$T/r1b.out" 2>"$T/r1b.err"
    rc=$?
    if [ "$rc" = 126 ] && grep -qi 'rexec' "$T/r1b.err" \
        && ! grep -q 'MK-R1-FAULT' "$T/r1b.out"; then
        pass "r1b-refused-image-is-reported (rc=$rc)"
    else
        fail "r1b-refused-image (rc=$rc out=$(tr '\n' '|' < "$T/r1b.out") err=$(tr '\n' '|' < "$T/r1b.err"))"
    fi
    # The control: the same wrapper without --rexec runs the program, so
    # the refusal above is the memfd exec and not the filter breaking the
    # payload.
    "$T/deny" "$TOOL" --label cm-r1 -- /bin/echo MK-R1-CTL >"$T/r1b.out" 2>/dev/null
    if grep -q 'MK-R1-CTL' "$T/r1b.out"; then
        pass "r1-control-the-payload-runs-without-rexec"
    else
        fail "r1-control-the-payload-did-not-run ($(tr '\n' '|' < "$T/r1b.out"))"
    fi
else
    skip "r1 (no C compiler for the seccomp probe)"
fi

# ---------------------------------------------------------------- R2
# A child that has forked from the payload and not yet exec'd must not hold
# the descriptor.  A subshell is a fork without an exec, and `[ -r ]` is a
# shell builtin, so the check runs in the forked child itself, before any
# exec could close anything.  The payload must still hold it.
TOK="$T/token"
printf 'regress-token' > "$TOK"
chmod 600 "$TOK"
"$TOOL" --secret-close-on-exec --secret T=file:"$TOK" \
    -- /bin/sh -c 'if [ -r /proc/self/fd/3 ]; then echo master-has-fd; fi
                   ( if [ -r /proc/self/fd/3 ]; then echo child-has-fd; else echo child-no-fd; fi )' \
    >"$T/r2.out" 2>"$T/r2.err"
if grep -q 'master-has-fd' "$T/r2.out" && grep -q 'child-no-fd' "$T/r2.out"; then
    pass "r2-forked-child-does-not-hold-the-descriptor"
else
    fail "r2-forked-child-holds-the-descriptor ($(tr '\n' '|' < "$T/r2.out"))"
fi
# The control: without the flag the same forked child does hold it.
"$TOOL" --secret T=file:"$TOK" \
    -- /bin/sh -c '( if [ -r /proc/self/fd/3 ]; then echo child-has-fd; else echo child-no-fd; fi )' \
    >"$T/r2b.out" 2>/dev/null
grep -q 'child-has-fd' "$T/r2b.out" \
    && pass "r2-control-without-the-flag-it-is-held" \
    || fail "r2-control-the-observer-cannot-see-the-descriptor"

# The verdict requires the R1 control to have run.  A SKIP there means the
# seccomp probe did not behave (or there is no compiler), so the rexec
# refusal was never exercised; reporting that as a green run would hide
# the one regression test this suite exists for.
if [ "$R1_DECIDED" != 1 ]; then
    fail "r1-not-exercised (the seccomp control did not run, so the rexec refusal was never tested)"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ]
