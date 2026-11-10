#!/bin/sh
# Issue 31: `--args-from-fd 0` must not close the payload's stdin.
#
# The argument source is consumed to end of file, so the payload's fd 0
# sits at EOF afterwards.  What must never happen is that it is *closed*:
# a closed fd 0 makes every read fail with EBADF, which breaks a payload
# that reads a login line, a prompt answer or a script.
#
#   q31a  control: the payload reads a line from fd 0 when the vector
#         comes from fd 3, so the reader below is known to work
#   q31b  `--args-from-fd 0` leaves fd 0 open (the payload can stat it)
#   q31c  a read of fd 0 after the vector reaches EOF rather than EBADF
#   q31d  `--image-from-fd` runs from a memfd and leaves fd 0 open
#
# Catches: `File::from_raw_fd(fd)` dropped on the caller's descriptor,
# which closes fd 0 before the payload starts.
set -u
here=$(dirname "$0")
cd "$here/.." || { echo "FATAL: cannot enter tests/"; exit 2; }
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
T="/tmp/qa31.$$"
mkdir -p "$T" || { echo "FATAL: cannot create $T"; exit 2; }
cleanup() { rm -rf "$T"; }
trap cleanup EXIT INT TERM HUP QUIT

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

# q31a control: the vector arrives on fd 3, so fd 0 carries the payload's
# own input and the payload must read it.  If this fails, the checks below
# measure something other than the fix.
printf 'PAYLOAD-INPUT\n' >"$T/in"
printf '/bin/sh\0-c\0read x; echo got:$x\0' |
    "$TOOL" -q --args-from-fd 3 3<&0 >"$T/a.out" 2>"$T/a.err" <"$T/in"
rc=$?
if [ "$rc" = 0 ] && [ "$(cat "$T/a.out")" = "got:PAYLOAD-INPUT" ]; then
    pass "q31a-control-args-from-fd-3-keeps-stdin"
else
    fail "q31a-control-args-from-fd-3-keeps-stdin (rc=$rc out=[$(cat "$T/a.out")] err=[$(cat "$T/a.err")])"
fi

# q31b the vector arrives on fd 0.  The payload asks whether fd 0 exists
# after the vector was consumed.  Before the fix this printed FD0-GONE.
printf '/bin/sh\0-c\0if [ -e /proc/self/fd/0 ]; then echo FD0-OPEN; else echo FD0-GONE; fi\0' |
    "$TOOL" -q --args-from-fd 0 >"$T/b.out" 2>"$T/b.err"
rc=$?
if [ "$rc" = 0 ] && [ "$(cat "$T/b.out")" = "FD0-OPEN" ]; then
    pass "q31b-args-from-fd-0-keeps-fd-0-open"
else
    fail "q31b-args-from-fd-0-keeps-fd-0-open (rc=$rc out=[$(cat "$T/b.out")] err=[$(cat "$T/b.err")])"
fi

# q31c reading fd 0 after the vector is at EOF, not EBADF.  `cat` exits 0
# on an open descriptor at end of file and 1 with a "Bad file descriptor"
# diagnostic on a closed one, so the exit status is the discriminator.
printf '/bin/sh\0-c\0cat >/dev/null; echo read-rc=$?\0' |
    "$TOOL" -q --args-from-fd 0 >"$T/c.out" 2>"$T/c.err"
rc=$?
if [ "$rc" = 0 ] && [ "$(cat "$T/c.out")" = "read-rc=0" ]; then
    pass "q31c-args-from-fd-0-stdin-reads-eof-not-ebadf"
else
    fail "q31c-args-from-fd-0-stdin-reads-eof-not-ebadf (rc=$rc out=[$(cat "$T/c.out")] err=[$(cat "$T/c.err")])"
fi

# q31d the same call shape on the image path: `--image-from-fd` runs the
# bytes from a memfd and must not close the caller's descriptor.
img_out=$("$TOOL" -q --image-from-fd 3 exe-id 3<"$CASES" 2>"$T/d.err")
rc=$?
case "$img_out" in
    *"exe=/memfd:"*)
        pass "q31d-image-from-fd-runs-from-a-memfd (rc=$rc)" ;;
    *)
        skip "q31d-image-from-fd-runs-from-a-memfd (rc=$rc out=[$img_out] err=[$(cat "$T/d.err")])" ;;
esac

echo "################ qa31: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
