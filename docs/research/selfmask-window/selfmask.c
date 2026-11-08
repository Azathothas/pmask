/* reproducible: yes (sh docs/research/selfmask-window/run.sh) */
/* Self-mask at the first user instruction: set comm, then report the
 * monotonic time so the harness can see how late the mask ran. */
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/prctl.h>
#include <time.h>
static long long ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}
int main(void) {
    long long t0 = ns();
    prctl(PR_SET_NAME, "smask", 0, 0, 0);
    fprintf(stderr, "masked_ns=%lld\n", ns() - t0);
    return 0;
}
