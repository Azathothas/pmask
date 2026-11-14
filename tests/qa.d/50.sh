#!/bin/sh
# Issue 50: the real argv stays in the payload's memory.
#
#   q50a  negative control: a plain process's own argv IS recoverable from
#         /proc/<pid>/mem by the same uid, so a zero result below means the
#         mask, not a blind reader
#   q50b  default mode: the served cmdline is the label, and the real argv
#         is still recoverable from the payload's memory.  This is the
#         documented residual, asserted so nobody reports it as closed
#   q50c  the supervisor's own memory is readable at rest but carries no
#         marker: it scrubs the at-rest copies, so it can stay dumpable
#         and out of the hidden-pid family on a hidepid=invisible host
#   q50d  --no-dumpable: the same read is refused for the payload and the
#         payload still runs and works
#   q50e  the supervisor's maps are unreadable in both modes (control for
#         q50c in the --no-dumpable case)
#
# The reader is a C helper: it walks the readable mappings of
# /proc/<pid>/maps, reads each through /proc/<pid>/mem, and reports whether
# a needle is present.  A shell loop cannot do this at a usable speed and
# would time out on a real payload.
#
# The needle is a unique marker argument, not a program name: the point is
# the *real argument vector*, and a marker makes the hit unambiguous.
set -u
here=$(dirname "$0")
cd "$here/.." || { echo "FATAL: cannot enter tests/"; exit 2; }
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

T="${TMPDIR:-/tmp}/pmask-q50.$$"
mkdir -p "$T" || { echo "FATAL: mktemp"; exit 2; }
chmod 700 "$T"
SUP=""
PAY=""
FAIL=0
# Every process this fragment starts, so an abnormal exit (a timeout, a
# signal, a failed assertion that ends the shell early) cannot leave a
# parked payload behind.  A stale `holdargs` carries a real argv, and any
# world-wide sweep in the gate would then report it as a leak that belongs
# to this fragment.
PIDS=""

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    if [ -n "$PIDS" ]; then
        for p in $PIDS; do
            kill -9 "$p" 2>/dev/null
        done
    fi
    rm -rf "$T"
}
trap cleanup EXIT INT TERM HUP QUIT

status_field() {
    sed -n "s/^$2:[[:space:]]*\\(.*\\)$/\\1/p" "/proc/$1/status" 2>/dev/null
}

# wait_child PID SECONDS -> the first child of PID
wait_child() {
    wc_end=$(( $(date +%s 2>/dev/null || echo 0) + $2 ))
    while :; do
        for d in /proc/[0-9]*; do
            [ "$(proc_ppid "${d#/proc/}")" = "$1" ] && { echo "${d#/proc/}"; return 0; }
        done
        wc_now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$wc_now" -ge "$wc_end" ] && break
        sleep 0.05 2>/dev/null || sleep 1
    done
    return 1
}

# ------------------------------------------------------------- the reader
CC=""
for c in cc gcc clang; do
    command -v "$c" >/dev/null 2>&1 && { CC="$c"; break; }
done
SCAN=""
if [ -n "$CC" ]; then
    cat >"$T/scan.c" <<'EOF'
/* scan PID NEEDLE [MAXMB]
 * Read every readable private mapping of PID through /proc/PID/mem and
 * report the mappings that contain NEEDLE.  Exit 0 when the read worked
 * (hit or not), 3 when the kernel refused the initial open, 4 when it
 * refused a mapping mid-scan.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: scan PID NEEDLE [MAXMB]\n"); return 2; }
    long pid = atol(argv[1]);
    const char *needle = argv[2];
    long maxmb = argc > 3 ? atol(argv[3]) : 64;
    size_t nlen = strlen(needle);
    char path[64], line[4096];
    snprintf(path, sizeof path, "/proc/%ld/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps) { fprintf(stderr, "REFUSED maps: %s\n", strerror(errno)); return 3; }
    snprintf(path, sizeof path, "/proc/%ld/mem", pid);
    int mem = open(path, O_RDONLY);
    if (mem < 0) { fclose(maps); fprintf(stderr, "REFUSED mem: %s\n", strerror(errno)); return 3; }
    char *buf = malloc((size_t)maxmb * 1024 * 1024);
    if (!buf) { close(mem); fclose(maps); return 2; }
    long hits = 0, scanned = 0, skipped = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long a, b;
        char perms[8], rest[1024];
        rest[0] = 0;
        /* start-end perms offset dev inode [path] */
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %1023[^\n]", &a, &b, perms, rest) < 3)
            continue;
        if (perms[0] != 'r') continue;
        if (rest[0] == '[' && strstr(rest, "[vvar]")) { skipped++; continue; }
        unsigned long len = b - a;
        if (len == 0) continue;
        if (len > (unsigned long)maxmb * 1024UL * 1024UL) { skipped++; continue; }
        ssize_t got = pread(mem, buf, len, (off_t)a);
        if (got <= 0) {
            if (errno == EIO) { skipped++; continue; } /* unbacked page */
            fprintf(stderr, "REFUSED read %lx: %s\n", a, strerror(errno));
            free(buf); close(mem); fclose(maps); return 4;
        }
        scanned++;
        for (ssize_t i = 0; i + (ssize_t)nlen <= got; i++) {
            if (memcmp(buf + i, needle, nlen) == 0) {
                printf("HIT region=%lx-%lx %s\n", a, b, rest);
                hits++;
                break;
            }
        }
    }
    printf("SCAN ok=1 mappings_read=%ld skipped=%ld hits=%ld\n", scanned, skipped, hits);
    free(buf); close(mem); fclose(maps);
    return 0;
}
EOF
    "$CC" -O2 -o "$T/scan" "$T/scan.c" 2>"$T/cc.err" && SCAN="$T/scan"
fi

if [ -z "$SCAN" ]; then
    # No reader means no case was decided: say SKIP and do not print a
    # PASS verdict over an empty fragment.
    skip "q50-memory-reader (no C compiler: $(head -1 "$T/cc.err" 2>/dev/null))"
    echo "== VERDICT: SKIP (the memory reader is unavailable) =="
    exit 0
fi

# scan PID NEEDLE
# Sets OUT to the reader's output and SCAN_RC to its exit code.  Both are
# set in this shell: a `$(...)` capture would drop the exit code, and the
# exit code is half the finding (a refusal and a miss are different
# results).
scan() {
    "$SCAN" "$1" "$2" 64 >"$T/scan.out" 2>&1
    SCAN_RC=$?
    OUT=$(cat "$T/scan.out")
}

# needle_from STRING -> the marker, printable and unique to this run
MARK="Q50MK$$-$( (dd if=/dev/urandom bs=4 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n') 2>/dev/null || echo fallback)"

# ------------------------------------------------- q50a: negative control
# A plain process holds its argv in its own memory.  If the reader cannot
# see that, every zero below is a blind reader rather than a masked one.
env -i PATH=/usr/bin:/bin "$CASES" holdargs "$T/plain.out" "$MARK" \
    >/dev/null 2>&1 &
CTL=$!
PIDS="$PIDS $CTL"
sleep 0.5
scan "$CTL" "$MARK"
ctl_rc=$SCAN_RC
echo "CONTROL pid=$CTL rc=$ctl_rc $(printf '%s' "$OUT" | tr '\n' '|' | cut -c1-160)"
case "$OUT" in
    *HIT*)
        pass "q50a-control-plain-argv-is-readable (hits=$(printf '%s' "$OUT" | sed -n 's/.*hits=\([0-9]*\).*/\1/p'))" ;;
    *)
        fail "q50a-control-plain-argv-is-readable (rc=$ctl_rc out=$(printf '%s' "$OUT" | tr '\n' '|' | cut -c1-120))" ;;
esac
kill -9 "$CTL" 2>/dev/null
wait "$CTL" 2>/dev/null
rm -f "$T/plain.out"

# -------------------------------------- q50b/q50c: default mode residuals
L="b2q50-d-$$"
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$L" -- "$CASES" holdargs "$T/d.out" "$MARK" \
    >/dev/null 2>&1 &
SUP=$!
PIDS="$PIDS $SUP"
PAY=$(wait_child "$SUP" 10) || PAY=""
[ -n "$PAY" ] && PIDS="$PIDS $PAY"
if [ -z "$PAY" ]; then
    fail "q50b-default-payload-memory-is-readable (no payload)"
    fail "q50b2-default-cmdline-is-the-label (no payload)"
    fail "q50c-supervisor-memory-is-refused (no payload)"
else
    sleep 0.4
    # The served cmdline is the label, so the *reason* the memory read is
    # a leak is the disagreement between the two views.
    PC=$(tr '\0' '|' < "/proc/$PAY/cmdline" 2>/dev/null)
    [ "$PC" = "$L|" ] && pass "q50b2-default-cmdline-is-the-label (cmdline=[$PC])" \
        || fail "q50b2-default-cmdline-is-the-label (cmdline=[$PC])"

    scan "$PAY" "$MARK"
    d_rc=$SCAN_RC
    echo "DEFAULT pid=$PAY rc=$d_rc $(printf '%s' "$OUT" | tr '\n' '|' | cut -c1-200)"
    case "$OUT" in
        *HIT*)
            pass "q50b-default-payload-memory-is-readable (the documented residual: $(printf '%s' "$OUT" | sed -n 's/.*hits=\([0-9]*\).*/hits=\1/p'))" ;;
        *REFUSED*)
            # A refusal here is not a defect: it means this host or this
            # build closed the channel by another route.  It is not the
            # default's documented behaviour, so it cannot be reported as
            # a pass of the residual either.
            fail "q50b-default-payload-memory-is-readable (refused, so the residual cannot be shown: $(printf '%s' "$OUT" | head -1))" ;;
        *)
            fail "q50b-default-payload-memory-is-readable (rc=$d_rc no hit: $(printf '%s' "$OUT" | head -1))" ;;
    esac

    # The supervisor is dumpable at rest, but it has scrubbed the real
    # argv and environment: the scan must find no marker.
    scan "$SUP" "$MARK"
    s_rc=$SCAN_RC
    echo "SUPERVISOR pid=$SUP rc=$s_rc $(printf '%s' "$OUT" | tr '\n' '|' | cut -c1-160)"
    case "$OUT" in
        *HIT*)
            fail "q50c-supervisor-memory-has-no-marker (the supervisor's memory carried the marker)" ;;
        *REFUSED*)
            fail "q50c-supervisor-memory-has-no-marker (refused: the supervisor is non-dumpable, so it is a hidden pid on hidepid=invisible)" ;;
        *)
            pass "q50c-supervisor-memory-has-no-marker (rc=$s_rc readable, no hit)" ;;
    esac
fi
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
PAY=""
rm -f "$T/d.out"

# ------------------------------------------- q50d: --no-dumpable closes it
L="b2q50-n-$$"
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$L" --no-dumpable \
    -- "$CASES" holdargs "$T/n.out" "$MARK" >/dev/null 2>&1 &
SUP=$!
PIDS="$PIDS $SUP"
PAY=$(wait_child "$SUP" 10) || PAY=""
[ -n "$PAY" ] && PIDS="$PIDS $PAY"
if [ -z "$PAY" ]; then
    fail "q50d-nodumpable-refuses-the-read (no payload)"
    fail "q50d2-nodumpable-payload-still-runs (no payload)"
    fail "q50d3-nodumpable-cmdline-is-the-label (no payload)"
    fail "q50e-nodumpable-supervisor-memory-is-refused (no payload)"
else
    sleep 0.4
    scan "$PAY" "$MARK"
    n_rc=$SCAN_RC
    echo "NODUMPABLE pid=$PAY rc=$n_rc $(printf '%s' "$OUT" | tr '\n' '|' | cut -c1-200)"
    case "$OUT" in
        *REFUSED*)
            pass "q50d-nodumpable-refuses-the-read (rc=$n_rc $(printf '%s' "$OUT" | head -1))" ;;
        *HIT*)
            fail "q50d-nodumpable-refuses-the-read (the marker was still readable)" ;;
        *)
            fail "q50d-nodumpable-refuses-the-read (rc=$n_rc no refusal: $(printf '%s' "$OUT" | head -1))" ;;
    esac
    # Liveness and function: a refusal that also breaks the payload would
    # be a different (worse) change.
    PS=$(status_field "$PAY" State)
    case "$PS" in
        R*|S*|D*)
            pass "q50d2-nodumpable-payload-still-runs (state=$PS)" ;;
        *)
            fail "q50d2-nodumpable-payload-still-runs (state=[${PS:-gone}])" ;;
    esac
    PC=$(tr '\0' '|' < "/proc/$PAY/cmdline" 2>/dev/null)
    [ "$PC" = "$L|" ] && pass "q50d3-nodumpable-cmdline-is-the-label (cmdline=[$PC])" \
        || fail "q50d3-nodumpable-cmdline-is-the-label (cmdline=[$PC])"
    scan "$SUP" "$MARK"
    e_rc=$SCAN_RC
    case "$OUT" in
        *REFUSED*)
            pass "q50e-nodumpable-supervisor-memory-is-refused (rc=$e_rc)" ;;
        *)
            fail "q50e-nodumpable-supervisor-memory-is-refused (rc=$e_rc $(printf '%s' "$OUT" | head -1))" ;;
    esac
fi
# The payload must have finished its work: `holdargs` writes its report
# file before parking, so the --no-dumpable run's file proves the program
# ran rather than merely survived.  Checked before the cleanup removes it.
if [ -s "$T/n.out" ]; then
    pass "q50d4-nodumpable-payload-did-its-work ($(wc -l < "$T/n.out" | tr -d ' ') lines written)"
else
    fail "q50d4-nodumpable-payload-did-its-work (no report file)"
fi
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
PAY=""

echo "== VERDICT: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL) failures=$FAIL =="
[ "$FAIL" = 0 ]
