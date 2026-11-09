#!/bin/sh
# Issue 50 reproducer: the real argv in the payload's memory, the
# supervisor's memory refused, and --no-dumpable closing the channel.
# POSIX sh.  Run from the worktree root:
#   sh evidence/bteam2/50/repro-50.sh
set -u
PM=${PM:-./target/release/pmask}
CC=""
for c in cc gcc clang; do
    command -v "$c" >/dev/null 2>&1 && { CC="$c"; break; }
done
T=$(mktemp -d "${TMPDIR:-/tmp}/b2-50.XXXXXX") || exit 2
chmod 700 "$T"
trap 'rm -rf "$T"' EXIT INT TERM

echo "pmask=$PM kernel=$(uname -r) uid=$(id -u) cc=${CC:-none}"
[ -n "$CC" ] || { echo "SKIP (no C compiler)"; exit 0; }

cat >"$T/scan.c" <<'EOF'
/* scan PID NEEDLE: read every readable mapping through /proc/PID/mem and
 * report the mappings that contain NEEDLE. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    long pid = atol(argv[1]);
    const char *needle = argv[2];
    size_t nlen = strlen(needle);
    char path[64], line[4096];
    snprintf(path, sizeof path, "/proc/%ld/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps) { fprintf(stderr, "REFUSED maps: %s\n", strerror(errno)); return 3; }
    snprintf(path, sizeof path, "/proc/%ld/mem", pid);
    int mem = open(path, O_RDONLY);
    if (mem < 0) { fprintf(stderr, "REFUSED mem: %s\n", strerror(errno)); return 3; }
    unsigned char *buf = malloc(64u * 1024 * 1024);
    long hits = 0, scanned = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long a, b;
        char perms[8], rest[1024];
        rest[0] = 0;
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %1023[^\n]", &a, &b, perms, rest) < 3)
            continue;
        if (perms[0] != 'r') continue;
        if (rest[0] == '[' && strstr(rest, "[vvar]")) continue;
        unsigned long len = b - a;
        if (len == 0 || len > 64UL * 1024 * 1024) continue;
        ssize_t got = pread(mem, buf, len, (off_t)a);
        if (got <= 0) { if (errno == EIO) continue; break; }
        scanned++;
        for (ssize_t i = 0; i + (ssize_t)nlen <= got; i++) {
            if (memcmp(buf + i, needle, nlen) == 0) {
                printf("HIT region=%lx-%lx %s\n", a, b, rest);
                hits++;
                break;
            }
        }
    }
    printf("SCAN mappings_read=%ld hits=%ld\n", scanned, hits);
    free(buf); close(mem); fclose(maps);
    return 0;
}
EOF
"$CC" -O2 -o "$T/scan" "$T/scan.c" || exit 2

MARK="REALARG$$-$(date +%s)"
TC=${TESTBIN:-./tests/testcases}

wait_child() {
    wc_i=0
    while [ "$wc_i" -lt 100 ]; do
        for d in /proc/[0-9]*; do
            [ "$(sed -n 's/^PPid:[[:space:]]*\([0-9]*\).*/\1/p' "$d/status" 2>/dev/null)" = "$1" ] && {
                echo "${d#/proc/}"; return 0; }
        done
        sleep 0.05 2>/dev/null || sleep 1
        wc_i=$((wc_i + 1))
    done
    return 1
}

echo "================ control: a plain process holds its argv"
env -i PATH=/usr/bin:/bin "$TC" holdargs "$T/plain.out" "$MARK" >/dev/null 2>&1 &
C=$!
sleep 0.5
"$T/scan" "$C" "$MARK"
kill -9 "$C" 2>/dev/null

echo "================ default mode"
env -i PATH=/usr/bin:/bin "$PM" -q -l b2-50-lab -- "$TC" holdargs "$T/d.out" "$MARK" >/dev/null 2>&1 &
S=$!
P=$(wait_child "$S") || P=""
sleep 0.4
echo "payload=$P cmdline=$(tr '\0' '|' < "/proc/$P/cmdline" 2>/dev/null)"
echo "payload mem:"; "$T/scan" "$P" "$MARK"
echo "supervisor=$S mem:"; "$T/scan" "$S" "$MARK"
kill -9 "$S" 2>/dev/null
kill -9 "$P" 2>/dev/null

echo "================ --no-dumpable"
env -i PATH=/usr/bin:/bin "$PM" -q -l b2-50-lab --no-dumpable -- "$TC" holdargs "$T/n.out" "$MARK" >/dev/null 2>&1 &
S=$!
P=$(wait_child "$S") || P=""
sleep 0.4
echo "payload=$P cmdline=$(tr '\0' '|' < "/proc/$P/cmdline" 2>/dev/null) state=$(sed -n 's/^State:[[:space:]]*//p' "/proc/$P/status" 2>/dev/null)"
echo "payload mem:"; "$T/scan" "$P" "$MARK"
echo "supervisor=$S mem:"; "$T/scan" "$S" "$MARK"
echo "payload work: $(test -s "$T/n.out" && echo "holdargs wrote its report" || echo "NO REPORT")"
kill -9 "$S" 2>/dev/null
kill -9 "$P" 2>/dev/null
exit 0
