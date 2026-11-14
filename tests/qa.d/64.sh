#!/bin/sh
# QA fragment for --encrypt-memory.
#
# The flag seals the supervisor's at-rest argv/environment copies with
# XChaCha20-Poly1305 and keeps the payload's redaction block anonymous
# with MADV_DONTDUMP.  It does not encrypt the payload's own heap or
# stack, so the test asserts both halves: the supervisor's memory has no
# canary, the payload's does.
#
# Cases:
#   qa64-report            encrypt_memory=true, hardening encrypted,
#                          block_anonymous=1, block_secretmem=false
#   qa64-scanner-control   the same-pid control: the label is readable
#   qa64-supervisor        the supervisor's memory has no canary
#   qa64-payload           the payload's memory still has the canary (limit)
#   qa64-block-anonymous   when memfd_secret is active, the payload block
#                          has no /secretmem VMA
#   qa64-supervisor-secret the delivered value is not in the holder
#   qa64-daemon-refused    --daemon refuses the flag instead of running
#   qa64-noreadact         --encrypt-memory with --no-redact is refused
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa64.XXXXXX") || {
    echo "FATAL: cannot create a temp dir"; exit 2
}
PIDS=""
cleanup() {
    for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
    kill_label qa64 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT INT TERM HUP QUIT

have_root=no
sudo -n true 2>/dev/null && have_root=yes
CC=""
for c in cc gcc clang; do
    command -v "$c" >/dev/null 2>&1 && { CC="$c"; break; }
done

# ---------------------------------------------------------- the scanner
SCAN=""
if [ -n "$CC" ]; then
    cat > "$D/scan.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    long pid = atol(argv[1]);
    const char *needle = argv[2];
    size_t nlen = strlen(needle);
    char path[64], line[4096];
    snprintf(path, sizeof path, "/proc/%ld/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps) return 3;
    snprintf(path, sizeof path, "/proc/%ld/mem", pid);
    int mem = open(path, O_RDONLY);
    if (mem < 0) { fclose(maps); return 3; }
    static char buf[1 << 20];
    long hits = 0;
    unsigned long long bytes = 0, unread = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long a, b;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s", &a, &b, perms) < 3) continue;
        if (perms[0] != 'r') continue;
        unsigned long len = b - a;
        for (unsigned long off = 0; off < len; off += sizeof buf) {
            size_t want = len - off;
            if (want > sizeof buf) want = sizeof buf;
            ssize_t k = pread(mem, buf, want, a + off);
            if (k <= 0) { unread += want; continue; }
            bytes += (unsigned long long)k;
            for (ssize_t i = 0; i + (ssize_t)nlen <= k; i++) {
                if (!memcmp(buf + i, needle, nlen)) { hits++; break; }
            }
        }
    }
    close(mem);
    fclose(maps);
    printf("hits=%ld bytes=%llu unreadable=%llu\n", hits, bytes, unread);
    return 0;
}
EOF
    if "$CC" -O2 -o "$D/scan" "$D/scan.c" 2>/dev/null; then
        SCAN="$D/scan"
    fi
fi

# ---------------------------------------------------------- the report
"$TOOL" --encrypt-memory --report=json -l qa64rep -- /bin/true >"$D/rep.json" 2>"$D/rep.err"
rc=$?
if [ "$rc" = 0 ] && grep -q '"encrypt_memory": true' "$D/rep.json" \
    && grep -q '"hardening": ".*encrypted' "$D/rep.json" \
    && grep -q '"block_secretmem": false' "$D/rep.json" \
    && grep -q '"block_anonymous": 1' "$D/rep.json"; then
    pass "qa64-report"
else
    fail "qa64-report (rc=$rc out=$(tr '\n' '|' < "$D/rep.json" | cut -c1-200) err=$(tr '\n' '|' < "$D/rep.err" | cut -c1-120))"
fi

# ---------------------------------------------------------- the memory rows
CAN="QA64-CANARY-$$"
"$TOOL" -q -l qa64mem --encrypt-memory -- "$CASES" sleeper "$CAN" >/dev/null 2>"$D/mem.err" &
SUP=$!
PIDS="$PIDS $SUP"
sleep 0.8
PAY=""
for d in /proc/[0-9]*; do
    [ "$(cat "$d/comm" 2>/dev/null)" = "qa64mem" ] || continue
    q=${d#/proc/}
    [ "$q" = "$SUP" ] && continue
    PAY=$q
done
if [ -z "$PAY" ]; then
    fail "qa64-supervisor (no payload)"
    fail "qa64-payload (no payload)"
    skip "qa64-block-anonymous (no payload)"
else
    if [ -n "$SCAN" ] && [ "$have_root" = yes ]; then
        # A negative on a different process is not a control.  Read the
        # supervisor's own label first, so bytes=0 (unreadable) cannot
        # pass as "the canary is absent".
        ctl_line=$(sudo -n "$SCAN" "$SUP" qa64mem 2>/dev/null)
        ctl_hits=$(printf '%s\n' "$ctl_line" | sed -n 's/^hits=\([0-9]*\) .*/\1/p')
        ctl_bytes=$(printf '%s\n' "$ctl_line" | sed -n 's/^hits=[0-9]* bytes=\([0-9]*\).*/\1/p')
        if [ -n "$ctl_hits" ] && [ "$ctl_hits" -gt 0 ] && [ "${ctl_bytes:-0}" -gt 0 ]; then
            pass "qa64-scanner-control (same pid: label seen, bytes=$ctl_bytes)"
        else
            fail "qa64-scanner-control (the scanner cannot see the supervisor's own label: $ctl_line)"
        fi
        sup_line=$(sudo -n "$SCAN" "$SUP" "$CAN" 2>/dev/null)
        sup_hits=$(printf '%s\n' "$sup_line" | sed -n 's/^hits=\([0-9]*\) .*/\1/p')
        sup_bytes=$(printf '%s\n' "$sup_line" | sed -n 's/^hits=[0-9]* bytes=\([0-9]*\).*/\1/p')
        if [ "$sup_hits" = 0 ] && [ "${sup_bytes:-0}" -gt 0 ]; then
            pass "qa64-supervisor (no canary in $sup_bytes bytes read)"
        else
            fail "qa64-supervisor ($sup_line)"
        fi
        pay_line=$(sudo -n "$SCAN" "$PAY" "$CAN" 2>/dev/null)
        pay_hits=$(printf '%s\n' "$pay_line" | sed -n 's/^hits=\([0-9]*\) .*/\1/p')
        if [ -n "$pay_hits" ] && [ "$pay_hits" -gt 0 ]; then
            pass "qa64-payload (the payload's memory still has the canary: $pay_line)"
        else
            fail "qa64-payload ($pay_line, the documented limit was not shown)"
        fi
    else
        skip "qa64-supervisor (needs root and a C compiler)"
        skip "qa64-payload (needs root and a C compiler)"
        skip "qa64-scanner-control (needs root and a C compiler)"
    fi
    if "$TOOL" probe 2>/dev/null | grep -q 'memory encryption  *active'; then
        # The session key may use memfd_secret, but the payload's
        # redaction block must not: a /secretmem VMA in the payload is a
        # fingerprint no ordinary process has.
        if grep -q 'secretmem' "/proc/$PAY/maps" 2>/dev/null; then
            fail "qa64-block-anonymous (the payload block has a /secretmem VMA)"
        else
            pass "qa64-block-anonymous (memfd_secret is active and the payload block stays anonymous)"
        fi
    else
        skip "qa64-block-anonymous (memfd_secret is not active on this host)"
    fi
fi
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
PIDS=""

# --------------------------------------------------- the supervisor's copy
# A delivered secret must not be readable in the supervisor's memory.  The
# scanner is the same one that found the payload canary, so the negative
# result is a control that can see a value when it is there.
SEC="QA64-SECRET-$$"
"$TOOL" -q -l qa64sec --secret "S=literal:$SEC" -- "$CASES" sleeper "$SEC" \
    >/dev/null 2>"$D/sec.err" &
SUP2=$!
PIDS="$PIDS $SUP2"
sleep 0.8
if [ -n "$SCAN" ] && [ "$have_root" = yes ]; then
    sctl_line=$(sudo -n "$SCAN" "$SUP2" qa64sec 2>/dev/null)
    sctl_hits=$(printf '%s\n' "$sctl_line" | sed -n 's/^hits=\([0-9]*\) .*/\1/p')
    sctl_bytes=$(printf '%s\n' "$sctl_line" | sed -n 's/^hits=[0-9]* bytes=\([0-9]*\).*/\1/p')
    if [ -n "$sctl_hits" ] && [ "$sctl_hits" -gt 0 ] && [ "${sctl_bytes:-0}" -gt 0 ]; then
        pass "qa64-supervisor-secret-control (same pid: label seen, bytes=$sctl_bytes)"
    else
        fail "qa64-supervisor-secret-control (the scanner cannot see the holder's own label: $sctl_line)"
    fi
    sec_line=$(sudo -n "$SCAN" "$SUP2" "$SEC" 2>/dev/null)
    sec_hits=$(printf '%s\n' "$sec_line" | sed -n 's/^hits=\([0-9]*\) .*/\1/p')
    sec_bytes=$(printf '%s\n' "$sec_line" | sed -n 's/^hits=[0-9]* bytes=\([0-9]*\).*/\1/p')
    if [ "$sec_hits" = 0 ] && [ "${sec_bytes:-0}" -gt 0 ]; then
        pass "qa64-supervisor-secret (not in $sec_bytes bytes read)"
    else
        fail "qa64-supervisor-secret ($sec_line)"
    fi
else
    skip "qa64-supervisor-secret (needs root and a C compiler)"
    skip "qa64-supervisor-secret-control (needs root and a C compiler)"
fi
kill -9 "$SUP2" 2>/dev/null
wait "$SUP2" 2>/dev/null
PIDS=""

# ---------------------------------------------------------- no-redact refusal
"$TOOL" --encrypt-memory --no-redact -l qa64nr -- /bin/true >/dev/null 2>"$D/nr.err"
rc=$?
if [ "$rc" = 255 ] && grep -q -- 'needs the redaction mode' "$D/nr.err"; then
    pass "qa64-noreadact ($(head -1 "$D/nr.err" | cut -c1-100))"
else
    fail "qa64-noreadact (rc=$rc err=$(tr '\n' '|' < "$D/nr.err" | cut -c1-160))"
fi

# ------------------------------------------------ --daemon cannot honour it
"$TOOL" -q --daemon /nonexistent.sock --encrypt-memory -l qa64dm -- /bin/true \
    >/dev/null 2>"$D/dm.err"
rc=$?
if [ "$rc" = 255 ] && grep -q -- '--daemon cannot be combined with --encrypt-memory' "$D/dm.err"; then
    pass "qa64-daemon-refused"
else
    fail "qa64-daemon-refused (rc=$rc err=$(head -1 "$D/dm.err"))"
fi

echo "== VERDICT: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL) failures=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
