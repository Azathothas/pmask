/* nt5.c - stack layout + three rewriting strategies, byte-level results. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/auxv.h>
extern char **environ;

static void stats(const char *tag, unsigned long block)
{
    int fd = open("/proc/self/cmdline", O_RDONLY);
    static unsigned char b[32768];
    ssize_t n = fd < 0 ? -1 : read(fd, b, sizeof b);
    if (fd >= 0) close(fd);
    if (n < 0) n = 0;
    long nul = 0, run = 0, mrun = 0, args = 0;
    for (ssize_t i = 0; i < n; i++) {
        if (!b[i]) { nul++; if (++run > mrun) mrun = run; } else run = 0;
    }
    for (ssize_t i = 0; i < n; ) { ssize_t j = i; while (j < n && b[j]) j++; if (j > i) args++; i = j + 1; }
    printf("%-11s block=%-4lu len=%-5zd nonempty_args=%ld nul=%-4ld maxrun=%-3ld ps_shows=[",
           tag, block, n, args, nul, mrun);
    ssize_t o = 0; while (o < n && b[o]) o++;
    printf("%.*s]\n", (int)o, b);
}

int main(int argc, char **argv)
{
    char modebuf[32];
    snprintf(modebuf, sizeof modebuf, "%s", argc > 1 ? argv[1] : "wellformed");
    char *as = argv[0];
    char *ae = argv[argc - 1] + strlen(argv[argc - 1]) + 1;
    char *es = environ[0], *ee = environ[0];
    int i;
    for (i = 0; environ[i]; i++) ee = environ[i] + strlen(environ[i]) + 1;
    char *execfn = (char *)getauxval(AT_EXECFN);
    unsigned long ab = (unsigned long)(ae - as);

    printf("arg_start=%p arg_end=%p env_start=%p env_end=%p execfn=%p (execfn-env_end=%ld)\n",
           (void *)as, (void *)ae, (void *)es, (void *)ee, (void *)execfn, (long)(execfn - ee));
    printf("block=%lu execfn_str=[%s] len=%zu\n", ab, execfn, strlen(execfn));

    if (!strcmp(modebuf, "naive")) {
        memset(as, 0, ab);
        memcpy(as, "cat", 3);
    } else if (!strcmp(modebuf, "endnz")) {
        memset(as, 0, ab);
        memcpy(as, "cat", 3);
        as[ab - 1] = 'Z';
    } else {  /* wellformed: plausible argv list, last arg padded to fill, final NUL at arg_end-1 */
        const char *a0 = "/usr/bin/curl";
        const char *a1 = "--config";
        const char *a2 = "/root/.curlrc";   /* padded with filler */
        unsigned long used = 0;
        memset(as, 0, ab);
        memcpy(as, a0, strlen(a0)); used += strlen(a0) + 1;
        memcpy(as + used, a1, strlen(a1)); used += strlen(a1) + 1;
        unsigned long room = ab - used - 1;            /* leave final NUL at ab-1 */
        memcpy(as + used, a2, strlen(a2));
        unsigned long p = used + strlen(a2);
        while (p < ab - 1) as[p++] = 'A';              /* filler inside the last arg */
        as[ab - 1] = 0;
    }
    fflush(stdout);
    stats(modebuf, ab);
    sleep(6);
    return 0;
}
