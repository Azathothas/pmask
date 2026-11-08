/* nt3.c - how /proc/self/cmdline renders a rewritten argv block.
 * Modes:
 *   short      : zero block, title at arg_start (classic naive rewrite)
 *   endnz      : short, plus arg_end-1 forced non-zero (kernel "setproctitle" special case)
 *   spill      : title longer than the block, NUL placed past arg_end
 *   wellformed : block filled with NUL-separated fake args, last NUL exactly at arg_end-1
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
extern char **environ;

static void report(const char *mode, unsigned long ab, int endnz)
{
    int fd = open("/proc/self/cmdline", O_RDONLY);
    static unsigned char b[16384];
    ssize_t n = fd < 0 ? -1 : read(fd, b, sizeof b);
    if (fd >= 0) close(fd);
    if (n < 0) n = 0;
    long nul = 0, run = 0, maxrun = 0;
    for (ssize_t i = 0; i < n; i++) {
        if (!b[i]) { nul++; if (++run > maxrun) maxrun = run; } else run = 0;
    }
    printf("%-11s block=%-4lu endnz=%d  cmdline: len=%-5zd nul=%-4ld maxrun=%-4ld args=",
           mode, ab, endnz, n, nul, maxrun);
    /* render as ps would: split on NUL, skip empties */
    int shown = 0;
    for (ssize_t i = 0; i < n; ) {
        ssize_t j = i;
        while (j < n && b[j]) j++;
        if (j > i) { printf("[%.*s]", (int)(j - i), b + i); shown++; }
        else printf("[<empty>]");
        if (shown > 6) { printf("..."); break; }
        i = j + 1;
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    char modebuf[32];
    snprintf(modebuf, sizeof modebuf, "%s", argc > 1 ? argv[1] : "short");
    const char *mode = modebuf;
    char *as = argv[0];
    char *ae = argv[argc - 1] + strlen(argv[argc - 1]) + 1;
    char *es = environ[0];
    char *ee = environ[0];
    int i;
    for (i = 0; environ[i]; i++) ee = environ[i] + strlen(environ[i]) + 1;
    unsigned long ab = (unsigned long)(ae - as);
    unsigned long eb = (unsigned long)(ee - es);

    memset(as, 0, ab);
    memset(es, 0, eb);
    int endnz = 0;

    if (!strcmp(mode, "short")) {
        memcpy(as, "cat", 3);
    } else if (!strcmp(mode, "endnz")) {
        memcpy(as, "cat", 3);
        as[ab - 1] = 'Z';
        endnz = 1;
    } else if (!strcmp(mode, "spill")) {
        /* title one byte longer than the block: NUL lands past arg_end */
        for (unsigned long k = 0; k < ab; k++) as[k] = 'a' + (k % 26);
        as[ab] = 0;
        endnz = 1;
    } else if (!strcmp(mode, "wellformed")) {
        /* fake argv list that exactly fills [arg_start,arg_end) */
        const char *args[] = { "/usr/sbin/crond", "-f", "-n" };
        unsigned long need = 0, k;
        int a;
        for (a = 0; a < 3; a++) need += strlen(args[a]) + 1;
        if (need > ab) { /* cannot fit: fall back to one short arg */
            printf("(need %lu > block %lu)\n", need, ab);
            memcpy(as, "crond", 5);
        } else {
            unsigned long p = 0;
            for (a = 0; a < 3; a++) {
                memcpy(as + p, args[a], strlen(args[a]));
                p += strlen(args[a]);
                as[p++] = 0;
            }
            /* pad the tail with extra single-char args so the last NUL sits at ab-1 */
            while (p < ab) { as[p++] = 'x'; if (p < ab) as[p++] = 0; }
            as[ab - 1] = 0;
        }
        endnz = (as[ab - 1] != 0);
    }
    fflush(stdout);
    report(mode, ab, endnz);
    sleep(1);
    return 0;
}
