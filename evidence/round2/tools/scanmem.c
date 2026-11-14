// Scan the readable address space of one pid for literal byte strings.
// Usage: scanmem PID NEEDLE [NEEDLE...]
// Reads /proc/PID/mem; needs root or a dumpable target owned by the caller.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHUNK (1u << 20)

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s PID NEEDLE [NEEDLE...]\n", argv[0]);
        return 2;
    }
    int pid = atoi(argv[1]);
    int nneedles = argc - 2;
    char **needles = argv + 2;
    size_t *lens = calloc(nneedles, sizeof(size_t));
    long *hits = calloc(nneedles, sizeof(long));
    for (int i = 0; i < nneedles; i++) lens[i] = strlen(needles[i]);

    char maps_path[64], mem_path[64];
    snprintf(maps_path, sizeof maps_path, "/proc/%d/maps", pid);
    snprintf(mem_path, sizeof mem_path, "/proc/%d/mem", pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        printf("scanmem pid=%d maps=ERR:%s\n", pid, strerror(errno));
        return 1;
    }
    int mem = open(mem_path, O_RDONLY);
    if (mem < 0) {
        printf("scanmem pid=%d mem=ERR:%s\n", pid, strerror(errno));
        fclose(maps);
        return 1;
    }

    unsigned char *buf = malloc(CHUNK + 65536);
    unsigned long long scanned = 0;
    unsigned long regions = 0;
    size_t maxneedle = 0;
    for (int i = 0; i < nneedles; i++) if (lens[i] > maxneedle) maxneedle = lens[i];
    char line[512];
    while (fgets(line, sizeof line, maps)) {
        unsigned long long lo, hi;
        char perms[8];
        if (sscanf(line, "%llx-%llx %7s", &lo, &hi, perms) != 3) continue;
        if (perms[0] != 'r') continue;
        regions++;
        unsigned long long len = hi - lo;
        for (unsigned long long off = 0; off < len; off += CHUNK) {
            size_t want = (len - off < CHUNK) ? (size_t)(len - off) : CHUNK;
            // Read a little past the chunk so a needle straddling the
            // boundary is found; only starts inside `want` are counted.
            size_t extra = (maxneedle > 1) ? maxneedle - 1 : 0;
            if (extra > 65536) extra = 65536;
            if ((unsigned long long)want + extra > len - off)
                extra = (size_t)(len - off - want);
            ssize_t got = pread(mem, buf, want + extra, (off_t)(lo + off));
            if (got <= 0) break;
            scanned += (unsigned long long)got;
            for (int i = 0; i < nneedles; i++) {
                if (lens[i] == 0 || (size_t)got < lens[i]) continue;
                size_t limit = want;
                if ((size_t)got < limit + lens[i] - 1) limit = (size_t)got - lens[i] + 1;
                for (size_t p = 0; p < limit; p++) {
                    if (buf[p] == (unsigned char)needles[i][0] &&
                        memcmp(buf + p, needles[i], lens[i]) == 0) {
                        hits[i]++;
                        if (hits[i] <= 3)
                            printf("hit needle=%s region=%llx-%llx off=%llx\n",
                                   needles[i], lo, hi, off + p);
                    }
                }
            }
        }
    }
    printf("scanmem pid=%d regions=%lu scanned_bytes=%llu\n", pid, regions, scanned);
    for (int i = 0; i < nneedles; i++)
        printf("needle=%s hits=%ld\n", needles[i], hits[i]);
    fclose(maps);
    close(mem);
    free(buf);
    free(lens);
    free(hits);
    return 0;
}
