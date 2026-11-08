/* nt4.c - what the other /proc surfaces say after an argv rewrite.
 * Applies the arg_end-1 trick, then reports:
 *   AT_EXECFN (auxv) pointer + string, /proc/self/exe, comm, cmdline bytes.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
extern char **environ;

int main(int argc, char **argv)
{
    char modebuf[32];
    snprintf(modebuf, sizeof modebuf, "%s", argc > 1 ? argv[1] : "keep");
    char *as = argv[0];
    char *ae = argv[argc - 1] + strlen(argv[argc - 1]) + 1;
    char *es = environ[0], *ee = environ[0];
    int i;
    for (i = 0; environ[i]; i++) ee = environ[i] + strlen(environ[i]) + 1;
    unsigned long ab = (unsigned long)(ae - as);

    if (!strcmp(modebuf, "rewrite")) {
        char *execfn = (char *)getauxval(AT_EXECFN);
        printf("before: AT_EXECFN ptr=%p str=[%s]\n", (void *)execfn, execfn);
        memset(as, 0, ab);
        memcpy(as, "cat", 3);
        as[ab - 1] = 'Z';                    /* arg_end-1 non-zero -> kernel setproctitle path */
        /* keep AT_EXECFN string consistent with the new argv[0] */
        if (execfn && strlen(execfn) >= 3) { memcpy(execfn, "cat", 3); execfn[3] = 0; }
        printf("after : AT_EXECFN ptr=%p str=[%s]\n", (void *)execfn, execfn);
    }
    char cl[256];
    int fd = open("/proc/self/cmdline", O_RDONLY);
    ssize_t n = read(fd, cl, sizeof cl); close(fd);
    printf("cmdline: n=%zd bytes: ", n);
    for (ssize_t k = 0; k < n; k++) cl[k] ? putchar(cl[k]) : putchar('.');
    printf("\n");
    char ex[512]; ssize_t m = readlink("/proc/self/exe", ex, sizeof ex - 1);
    if (m > 0) ex[m] = 0; else strcpy(ex, "?");
    char cm[64] = {0}; FILE *f = fopen("/proc/self/comm", "r");
    if (f) { if (fgets(cm, sizeof cm, f)) cm[strcspn(cm, "\n")] = 0; fclose(f); }
    printf("exe=[%s] comm=[%s] pid=%d\n", ex, cm, (int)getpid());
    fflush(stdout);
    sleep(8);
    return 0;
}
