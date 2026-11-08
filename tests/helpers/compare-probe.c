/* Small probes for tests/compare.sh and tests/conformance.sh.
 *
 * Subcommands:
 *   seals NAME     read PMASK_SECRET_<NAME>, print the descriptor, the
 *                  F_GET_SEALS mask and the result of a one-byte write
 *   sealsfd N      the same for descriptor N, which lets a test point the
 *                  reader at a plain file
 *   dumpable       print PR_GET_DUMPABLE of this process
 *   execfn         print AT_EXECFN from /proc/self/auxv
 *   corelim        print the RLIMIT_CORE soft and hard values
 *
 * The program deliberately runs no child, so the pid the tests observe is
 * the pid that ran it.
 *
 * Build: cc -O0 -o cfprobe compare-probe.c
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

/* The environment name pmask uses for a secret called NAME: every
 * non-alphanumeric byte becomes '_' and letters are upper-cased. */
static void secret_env_name(const char *name, char *out, size_t cap)
{
    size_t i;
    const char *p;
    snprintf(out, cap, "PMASK_SECRET_");
    i = strlen(out);
    for (p = name; *p && i + 1 < cap; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            out[i++] = (char)(c >= 'a' && c <= 'z' ? c - 32 : c);
        } else {
            out[i++] = '_';
        }
    }
    out[i] = '\0';
}

static int cmd_seals(int fd)
{
    int seals, wrc;
    printf("fd=%d\n", fd);
    errno = 0;
    seals = fcntl(fd, F_GET_SEALS);
    printf("seals=%d\n", seals);
    if (seals < 0) {
        printf("seals_errno=%d\n", errno);
    }
    errno = 0;
    wrc = (int)write(fd, "x", 1);
    printf("write_rc=%d\n", wrc);
    printf("write_errno=%d\n", wrc < 0 ? errno : 0);
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        /* a pipe or a socket is not seekable; the caller sees the errno */
        printf("seek_errno=%d\n", errno);
    }
    return 0;
}

/* `seals NAME` uses the descriptor pmask published in
 * PMASK_SECRET_<NAME>; `sealsfd N` uses N directly, which lets a test
 * point the same reader at a plain file. */
static int cmd_seals_named(const char *name)
{
    char envname[256];
    const char *val;
    secret_env_name(name, envname, sizeof envname);
    val = getenv(envname);
    if (val == NULL) {
        printf("fd=none\n");
        return 1;
    }
    return cmd_seals(atoi(val));
}

/* Find one auxv entry by type. Returns the value, or 0 when absent. */
static unsigned long auxv_get(unsigned long type)
{
    FILE *f = fopen("/proc/self/auxv", "rb");
    unsigned long pair[2];
    unsigned long want = 0;
    if (f == NULL) {
        return 0;
    }
    while (fread(pair, sizeof pair, 1, f) == 1) {
        if (pair[0] == type) {
            want = pair[1];
            break;
        }
        if (pair[0] == 0 && pair[1] == 0) {
            break;
        }
    }
    fclose(f);
    return want;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: cfprobe seals NAME | dumpable | execfn | corelim\n");
        return 2;
    }
    if (strcmp(argv[1], "seals") == 0) {
        if (argc < 3) {
            fprintf(stderr, "cfprobe seals NAME\n");
            return 2;
        }
        return cmd_seals_named(argv[2]);
    }
    if (strcmp(argv[1], "sealsfd") == 0) {
        if (argc < 3) {
            fprintf(stderr, "cfprobe sealsfd N\n");
            return 2;
        }
        return cmd_seals(atoi(argv[2]));
    }
    if (strcmp(argv[1], "dumpable") == 0) {
        printf("dumpable=%ld\n", (long)prctl(PR_GET_DUMPABLE, 0, 0, 0, 0));
        return 0;
    }
    if (strcmp(argv[1], "execfn") == 0) {
        unsigned long p = auxv_get(31 /* AT_EXECFN */);
        char buf[512];
        ssize_t n;
        int fd;
        if (p == 0) {
            printf("execfn=none\n");
            return 1;
        }
        fd = open("/proc/self/mem", O_RDONLY);
        if (fd < 0) {
            printf("execfn=unreadable errno=%d\n", errno);
            return 1;
        }
        n = pread(fd, buf, sizeof buf - 1, (off_t)p);
        close(fd);
        if (n <= 0) {
            printf("execfn=unreadable n=%ld errno=%d\n", (long)n, errno);
            return 1;
        }
        buf[n] = '\0';
        printf("execfn=%s\n", buf);
        return 0;
    }
    if (strcmp(argv[1], "corelim") == 0) {
        struct rlimit rl;
        if (getrlimit(RLIMIT_CORE, &rl) != 0) {
            printf("corelim=unreadable errno=%d\n", errno);
            return 1;
        }
        printf("core_soft=%llu\n", (unsigned long long)rl.rlim_cur);
        printf("core_hard=%llu\n", (unsigned long long)rl.rlim_max);
        return 0;
    }
    fprintf(stderr, "cfprobe: unknown subcommand %s\n", argv[1]);
    return 2;
}
