/* nt.c - benign self-test: how /proc/self/cmdline reports an argv rewrite.
 * Modes:
 *   zerofill   : memset(argv block,0); write short title at argv[0]  (naive rewriter)
 *   keependbyte: same, but leave the original byte at arg_end-1 non-zero
 *   longfill   : continuous write spanning past arg_end, setproctitle style
 * Prints byte-level dump + NUL stats of /proc/self/cmdline and environ.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
extern char **environ;

static void dump(const char *path, const char *label)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("%s: <open failed>\n", label); return; }
    static unsigned char buf[8192];
    ssize_t n = read(fd, buf, sizeof buf);
    close(fd);
    if (n < 0) n = 0;
    long nul = 0, run = 0, maxrun = 0;
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == 0) { nul++; run++; if (run > maxrun) maxrun = run; }
        else run = 0;
    }
    printf("%s: len=%zd nul_bytes=%ld longest_nul_run=%ld\n", label, n, nul, maxrun);
    printf("  hex  : ");
    for (ssize_t i = 0; i < n && i < 96; i++) printf("%02x ", buf[i]);
    printf("\n  text : ");
    for (ssize_t i = 0; i < n && i < 96; i++) putchar(buf[i] ? buf[i] : '.');
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *mode = (argc > 1) ? argv[1] : "zerofill";
    char *start = argv[0], *end = argv[0];
    int i;
    for (i = 0; i < argc; i++) if (argv[i]) end = argv[i] + strlen(argv[i]) + 1;
    for (i = 0; environ[i]; i++) end = environ[i] + strlen(environ[i]) + 1;
    unsigned long avail = (unsigned long)(end - start);
    unsigned char lastbyte = (unsigned char)*(end - 1);

    printf("mode=%s arg_block=%lu bytes  byte[arg_end-1]=0x%02x (%s)\n",
           mode, avail, lastbyte, lastbyte ? "NONZERO" : "zero");

    const char *title = "cat resolv.conf";
    memset(start, 0, avail);
    if (!strcmp(mode, "longfill")) {
        size_t tl = strlen(title);
        size_t k;
        for (k = 0; k < avail - 1; k++) start[k] = title[k % tl];
        start[avail - 1] = 'X';
    } else {
        memcpy(start, title, strlen(title));
        start[strlen(title)] = 0;
        if (!strcmp(mode, "keependbyte"))
            *(unsigned char *)(end - 1) = lastbyte ? lastbyte : 'Z';
    }
    fflush(stdout);
    dump("/proc/self/cmdline", "cmdline");
    dump("/proc/self/environ", "environ");
    printf("(sleeping 1s)\n"); fflush(stdout);
    sleep(1);
    return 0;
}
