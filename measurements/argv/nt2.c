/* nt2.c - isolate the kernel's arg_end-1 special case.
 * Argv block is zero-filled and a SHORT title written; the only difference
 * between modes is the byte at arg_end-1.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
extern char **environ;

static void dump(const char *path, const char *label, const char *tag)
{
    int fd = open(path, O_RDONLY);
    static unsigned char b[16384];
    ssize_t n = fd < 0 ? -1 : read(fd, b, sizeof b);
    if (fd >= 0) close(fd);
    if (n < 0) n = 0;
    long nul = 0, run = 0, maxrun = 0;
    for (ssize_t i = 0; i < n; i++) {
        if (!b[i]) { nul++; if (++run > maxrun) maxrun = run; } else run = 0;
    }
    printf("%-14s %-8s len=%-6zd nul=%-6ld maxrun=%-6ld first16=[", tag, label, n, nul, maxrun);
    for (ssize_t i = 0; i < n && i < 16; i++) b[i] ? putchar(b[i]) : putchar('.');
    printf("]\n");
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "short_zero";
    char *astart = argv[0];
    char *aend   = argv[argc - 1] + strlen(argv[argc - 1]) + 1;   /* kernel arg_end */
    char *estart = environ[0];
    char *eend   = environ[0];
    int i;
    for (i = 0; environ[i]; i++) eend = environ[i] + strlen(environ[i]) + 1;

    unsigned long ab = (unsigned long)(aend - astart);
    unsigned long eb = (unsigned long)(eend - estart);
    printf("mode=%s arg_start=%p arg_end=%p argblock=%lu  envblock=%lu  gap=%ld\n",
           mode, (void *)astart, (void *)aend, ab, eb, (long)(estart - aend));

    const char *title = "cat";
    memset(astart, 0, ab);
    memcpy(astart, title, strlen(title));
    memset(estart, 0, eb);
    if (!strcmp(mode, "short_endnz"))
        astart[ab - 1] = 'Z';          /* keep arg_end-1 non-zero */
    else if (!strcmp(mode, "long"))
        { size_t k; for (k = 0; k < ab; k++) astart[k] = 'x'; }

    fflush(stdout);
    dump("/proc/self/cmdline", "cmdline", mode);
    dump("/proc/self/environ", "environ", mode);

    char p[64]; snprintf(p, sizeof p, "/proc/%d/cmdline", (int)getpid());
    printf("%-14s pid=%d file=%s\n", mode, (int)getpid(), p);
    fflush(stdout);
    sleep(1);
    return 0;
}
