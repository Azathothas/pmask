#!/bin/sh
# Issue 25: `--isolate` must give the payload a usable `/dev`.
#
#   q25a  control: the same `/dev` checks outside `--isolate`, so a pty
#         and a non-empty /dev/pts are known to work on this host
#   q25b  `pty.openpty()` succeeds under `--isolate`
#   q25c  `ls /dev/pts` under `--isolate` is non-empty
#   q25d  /dev/shm exists and is mode 1777
#   q25e  the six original nodes and the /dev/fd, /dev/stdin, /dev/stdout,
#         /dev/stderr links are present and /dev/null is writable
#   q25f  the report counts what it got: no "no /dev/pts" or "no /dev/shm"
#         degradation line when the members are there, and the `dev` entry
#         is applied
#   q25g  a degradation is named when the host lacks a member (or a SKIP
#         when this host has all three)
#
# Catches: a fresh /dev that is a tmpfs with six nodes and nothing else,
# while the report claims `dev` applied with no degradation.
set -u
here=$(dirname "$0")
cd "$here/.." || { echo "FATAL: cannot enter tests/"; exit 2; }
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
T="/tmp/qa25.$$"
mkdir -p "$T" || { echo "FATAL: cannot create $T"; exit 2; }
cleanup() { kill_comm qa25 KILL 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT INT TERM HUP QUIT

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

PY=$(command -v python3 2>/dev/null)
iso() {
    # iso OUT ERR -- ARGS...
    io_out=$1
    io_err=$2
    shift 3
    "$TOOL" -q --isolate -l qa25 -- "$@" >"$io_out" 2>"$io_err" </dev/null
}

# q25a control: the same probes without --isolate.  Without this, a host
# with no ptys at all would make q25b meaningless.
if [ -n "$PY" ]; then
    "$PY" -c 'import pty; pty.openpty()' >"$T/c1.out" 2>"$T/c1.err"
    rc=$?
    if [ "$rc" = 0 ]; then
        pass "q25a-control-pty-openpty-works-outside-isolate"
    else
        skip "q25a-control-pty-openpty-works-outside-isolate (this host has no usable pty: $(cat "$T/c1.err"))"
    fi
else
    skip "q25a-control-pty-openpty-works-outside-isolate (no python3)"
fi

# q25b: openpty under --isolate.
if [ -n "$PY" ]; then
    iso "$T/b.out" "$T/b.err" -- "$PY" -c 'import pty; pty.openpty(); print("PTY-OK")'
    rc=$?
    if [ "$rc" = 0 ] && [ "$(cat "$T/b.out")" = "PTY-OK" ]; then
        pass "q25b-pty-openpty-works-under-isolate"
    else
        fail "q25b-pty-openpty-works-under-isolate (rc=$rc out=[$(cat "$T/b.out")] err=[$(head -3 "$T/b.err")])"
    fi
else
    skip "q25b-pty-openpty-works-under-isolate (no python3)"
fi

# q25c: /dev/pts is non-empty under --isolate.
iso "$T/c.out" "$T/c.err" -- /bin/sh -c 'ls /dev/pts'
rc=$?
n=$(sed '/^$/d' "$T/c.out" | wc -l | tr -d ' ')
if [ "$rc" = 0 ] && [ "$n" -ge 1 ]; then
    pass "q25c-dev-pts-is-non-empty-under-isolate (entries=$n)"
else
    fail "q25c-dev-pts-is-non-empty-under-isolate (rc=$rc entries=$n err=[$(head -3 "$T/c.err")])"
fi

# q25d: /dev/shm exists, is a directory and carries mode 1777.
iso "$T/d.out" "$T/d.err" -- /bin/sh -c '[ -d /dev/shm ] && ls -ld /dev/shm'
rc=$?
case "$(cat "$T/d.out")" in
    *drwxrwxrwt*) pass "q25d-dev-shm-is-a-1777-directory" ;;
    *) fail "q25d-dev-shm-is-a-1777-directory (rc=$rc out=[$(cat "$T/d.out")] err=[$(head -3 "$T/d.err")])" ;;
esac

# q25e: the original nodes and the stdio links.  Writing /dev/null proves
# the bind is a usable device and not an ordinary file.
iso "$T/e.out" "$T/e.err" -- /bin/sh -c '
ok=1
for n in null zero full random urandom; do [ -e "/dev/$n" ] || { echo "missing:$n"; ok=0; }; done
for n in fd stdin stdout stderr; do [ -e "/dev/$n" ] || { echo "missing:$n"; ok=0; }; done
echo written >/dev/null || { echo "unwritable:null"; ok=0; }
[ "$ok" = 1 ] && echo ALL-NODES-OK
'
if grep -q "ALL-NODES-OK" "$T/e.out"; then
    pass "q25e-basic-nodes-and-stdio-links-are-usable"
else
    fail "q25e-basic-nodes-and-stdio-links-are-usable (out=[$(cat "$T/e.out")])"
fi

# q25f: the report says dev applied and names no missing optional member
# this host supplies.  A "fresh /dev has no /dev/pts" line while the host
# has /dev/pts is the false claim this issue is about.
if grep -q "isolation: .*dev" "$T/c.err"; then
    if grep -q "fresh /dev has no /dev/pts" "$T/c.err" && [ -d /dev/pts ]; then
        fail "q25f-report-does-not-disclaim-a-present-member (host has /dev/pts, report says it is absent)"
    else
        pass "q25f-report-does-not-disclaim-a-present-member"
    fi
else
    skip "q25f-report-does-not-disclaim-a-present-member (no dev entry in the report: $(head -1 "$T/c.err"))"
fi

# q25g: a degradation is named for a member this host lacks.  When the
# host has all three, the only honest answer is a SKIP.
missing=""
for n in pts ptmx shm; do
    [ -e "/dev/$n" ] || missing="$missing $n"
done
if [ -z "$missing" ]; then
    skip "q25g-degradation-is-named-for-a-missing-member (this host has /dev/pts, /dev/ptmx and /dev/shm)"
else
    hit=0
    for n in $missing; do
        grep -q "fresh /dev has no /dev/$n" "$T/c.err" && hit=$((hit + 1))
    done
    if [ "$hit" -eq $(echo $missing | wc -w | tr -d ' ') ]; then
        pass "q25g-degradation-is-named-for-a-missing-member ($missing)"
    else
        fail "q25g-degradation-is-named-for-a-missing-member (missing:$missing named=$hit)"
    fi
fi

echo "################ qa25: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
