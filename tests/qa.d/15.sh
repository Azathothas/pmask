#!/bin/sh
# QA fragment for issue 15: the supervisor's `memfd_secret` buffer is not
# `MFD_CLOEXEC`, so the plaintext leaks into the tree.
#
# The defect: `--secret` copies the value into a `memfd_secret` created
# with flags 0, and `--secret-close-on-exec` closes only the *delivered*
# descriptor.  The supervisor's own descriptor survived every `fork` and
# `exec`, so a grandchild still held it and could `mmap` the plaintext.
#
# The fix creates every `memfd_secret` through one helper that passes
# `MFD_CLOEXEC`, and the capability probe uses that same helper.
#
# Cases:
#   qa15-control-base-style  the mechanism is real: a memfd_secret made
#                            with flags 0 IS visible in an exec'd child
#                            (the probe binary, on this kernel)
#   qa15-payload-fds         the delivered payload holds no secretmem fd
#                            after its own exec
#   qa15-grandchild-fds      a grandchild under --secret-close-on-exec
#                            holds no secretmem fd
#   qa15-secret-still-works  the payload still reads the value from its
#                            descriptor: the flag change did not break
#                            delivery
#   qa15-probe-agrees        `pmask probe` still reports memfd_secret as
#                            available where the raw syscall works
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa15.XXXXXX") || {
    echo "FAIL qa15-cannot-create-tmp"; exit 2
}
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    kill_label qa15 KILL 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT

printf 'FILETOP-QA15\n' > "$D/sec"
chmod 600 "$D/sec"

# Is memfd_secret usable here at all?  Without it the leak cannot exist and
# the fragment has nothing to decide.  The gate reads the memfd_secret row's
# own state word: a window over the following lines can match "active" from
# the next row (mlock), which would let every case below run on a host where
# the mechanism does not exist and pass without a descriptor to find.
probe_out=$("$TOOL" probe 2>/dev/null)
case "$probe_out" in
    *memfd_secret*) : ;;
    *) skip "qa15-memfd-secret-available (pmask probe does not name it)" ; exit 0 ;;
esac
probe_state=$(printf '%s\n' "$probe_out" | awk '$1 == "memfd_secret" { print $2; exit }')
case "$probe_state" in
    active|degraded) : ;;
    *)
        # A host where the mechanism is unavailable: nothing to leak.
        skip "qa15-memfd-secret-available (probe reports it [$probe_state])"
        exit 0
        ;;
esac

# A tiny C probe is the negative control: memfd_secret(flags=0), then exec
# a shell that lists its own descriptors.  If the descriptor is inherited
# the marker appears; that is exactly the defect.  It needs a compiler.
if command -v cc >/dev/null 2>&1; then
    cat > "$D/leak.c" <<'CEOF'
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(void) {
    long fd = syscall(447, 0);   /* flags 0: the pre-fix shape */
    if (fd < 0) return 3;
    execl("/bin/sh", "sh", "-c", "ls -l /proc/self/fd", (char *)0);
    return 4;
}
CEOF
    if cc -o "$D/leak" "$D/leak.c" 2>/dev/null; then
        n=$("$D/leak" 2>/dev/null | grep -c secretmem)
        if [ "$n" -ge 1 ]; then
            pass qa15-control-flags0-leaks
        else
            fail qa15-control-flags0-leaks "(flags=0 descriptor was not inherited; the control cannot fire)"
        fi
    else
        skip "qa15-control-flags0-leaks (cc cannot build the probe)"
    fi
else
    skip "qa15-control-flags0-leaks (no cc)"
fi

# The delivered payload after its own exec.  The run must succeed and the
# listing must be non-empty before a zero count means anything: an empty
# run would make `grep -c` print 0 and pass without having looked.
out=$("$TOOL" -q --secret S=file:"$D/sec" --secret-close-on-exec -- \
    /bin/sh -c 'ls -l /proc/self/fd' 2>"$D/p.err")
rc=$?
if [ "$rc" != 0 ] || [ -z "$out" ]; then
    fail "qa15-payload-fds (rc=$rc, no fd listing: $(head -1 "$D/p.err"))"
else
    n=$(printf '%s\n' "$out" | grep -c secretmem)
    if [ "$n" = "0" ]; then
        pass qa15-payload-fds
    else
        fail "qa15-payload-fds ($n secretmem descriptor(s) in the payload)"
    fi
fi

# A grandchild: the descriptor must not survive the second exec either.
out=$("$TOOL" -q --secret S=file:"$D/sec" --secret-close-on-exec -- \
    /bin/sh -c '/bin/sh -c "ls -l /proc/self/fd"' 2>"$D/g.err")
rc=$?
if [ "$rc" != 0 ] || [ -z "$out" ]; then
    fail "qa15-grandchild-fds (rc=$rc, no fd listing: $(head -1 "$D/g.err"))"
else
    n=$(printf '%s\n' "$out" | grep -c secretmem)
    if [ "$n" = "0" ]; then
        pass qa15-grandchild-fds
    else
        fail "qa15-grandchild-fds ($n secretmem descriptor(s) in the grandchild)"
    fi
fi

# Delivery still works: the payload reads the value from descriptor 3.
got=$("$TOOL" -q --secret S=file:"$D/sec" --secret-close-on-exec -- \
    "$CASES" secretfd S 1 2>/dev/null | sed -n 's/^bytes=//p')
if [ "$got" = "12" ]; then
    pass qa15-secret-still-works
else
    fail "qa15-secret-still-works (bytes=[$got], want 12)"
fi

# The capability probe agrees with an independent creation attempt.  The
# probe's own string was already required by the availability gate above,
# so matching it again decides nothing; the C control calls
# memfd_secret(447,0) directly and its status is the independent answer.
if [ -x "$D/leak" ]; then
    "$D/leak" >"$D/leak2.out" 2>&1
    leak_rc=$?
    case "$leak_rc" in
        0) pass "qa15-probe-agrees (the raw memfd_secret(447,0) worked; the probe says [$probe_state])" ;;
        3) fail "qa15-probe-agrees (the raw memfd_secret(447,0) failed, but the probe says [$probe_state])" ;;
        *) fail "qa15-probe-agrees (the control probe exited $leak_rc: $(head -1 "$D/leak2.out"))" ;;
    esac
else
    skip "qa15-probe-agrees (no independent creation attempt: cc could not build the control)"
fi

exit "$FAIL"
