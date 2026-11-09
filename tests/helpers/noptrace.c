/*
 * Run a command with a seccomp filter that refuses ptrace(2) with EPERM.
 *
 * The quality gate needs a host where `PTRACE_SEIZE` fails with EPERM and
 * the failure is *not* the kernel's global policy: that is the shape of a
 * sandboxed CI runner, and it is what issue 34 is about.  This helper
 * installs the same filter such a sandbox installs, then execs the
 * command, so `pmask` can be tested end to end without a probe override
 * that would only lie about the host.
 *
 *   cc -O0 -o noptrace helpers/noptrace.c
 *   ./noptrace pmask -l x -- /bin/true
 *
 * Exit status is the command's.  A failure to install the filter exits
 * 125 with one line on stderr, so a suite can SKIP rather than pass on a
 * host that silently ran unfiltered.
 *
 * Linux only; x86-64 and aarch64 share the ptrace syscall number 101.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "noptrace: usage: noptrace COMMAND [ARGS...]\n");
        return 125;
    }
    struct sock_filter filter[] = {
        /* Load the syscall number. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* ptrace -> EPERM, whatever the request. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ptrace, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("noptrace: PR_SET_NO_NEW_PRIVS");
        return 125;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        perror("noptrace: PR_SET_SECCOMP");
        return 125;
    }
    execvp(argv[1], &argv[1]);
    perror("noptrace: execvp");
    return 125;
}
