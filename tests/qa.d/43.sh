#!/bin/sh
# Issue 43: AT_EXECFN in /proc/<pid>/auxv versus the payload's own getauxval.
#
# pmask rewrites AT_EXECFN in the kernel's saved auxv.  On this build the
# rewritten pointer lands on the second label copy at `env_end`, so the
# relation `/proc/<pid>/auxv` reports is the same one an ordinary exec
# has: AT_EXECFN == env_end.  Measured three times with labels of 4, 8
# and 12 bytes, and once more here with a 4th.  A rule written as
# "AT_EXECFN == arg_start" produces no hit, which is the correction the
# issue records.
#
# The payload's own `getauxval(AT_EXECFN)` is not served by that rewrite:
# the kernel built the process stack from the real exec, so the payload
# reads the real exec path.  The disagreement between the two is the
# signal and it is the documented boundary, not a defect.
#
# The auxv pointer is resolved through /proc/<pid>/mem, which needs
# CAP_SYS_PTRACE-equivalent access to a same-uid process.  That works
# here.  Where it does not, the pointer half prints SKIP and the
# in-payload half still decides.
#
# Cases:
#   A1 control: a plain process reports AT_EXECFN == its real path,
#      and AT_EXECFN == env_end
#   A2 masked: /proc/<pid>/auxv resolves AT_EXECFN to the label
#   A3 masked: AT_EXECFN == env_end (the relation the issue measures)
#   A4 masked: AT_EXECFN != arg_start (the rule that does not fire)
#   A5 masked: the payload's own getauxval returns the real path
#   A6 the in-payload and served views disagree (the signal)
#   A7 the second label copy sits at 1 + len(label) + argc from arg_start
#   A10 --no-exact does not rewrite the auxv at all: both views agree
#   A11 --keep-env leaves AT_EXECFN in the block, so it != env_end
set -u
cd "$(dirname "$0")"
. ../lib.sh

# lib.sh derives BIN_DIR from the cwd, which for a fragment is tests/qa.d.
# The binaries live in tests/; point the helpers at them.
BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP qa43 (python3 is required to parse auxv)"
    exit 0
fi

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa43.XXXXXX") || {
    echo "FATAL: cannot create a temp dir"; exit 2
}
SUP=""
cleanup() {
    [ -n "$SUP" ] && kill "$SUP" 2>/dev/null
    kill_label qa43-
    rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# auxv_report PID  -> one line per field the caller asks about, using
# /proc/<pid>/auxv and /proc/<pid>/mem.  The AT_EXECFN key is 31 on both
# x86-64 and aarch64 (`#define AT_EXECFN 31`).  A failure to open mem is
# reported as `mem=denied`; nothing else is guessed.
cat > "$D/auxv.py" <<'PY'
import struct
import sys

pid = sys.argv[1]
want = int(sys.argv[2]) if len(sys.argv) > 2 else 31
path = "/proc/%s/auxv" % pid
try:
    data = open(path, "rb").read()
except OSError as e:
    print("auxv=unreadable errno=%s" % e.errno)
    sys.exit(3)

ptr = None
for off in range(0, len(data) - 15, 16):
    k, v = struct.unpack("<QQ", data[off:off + 16])
    if k == want:
        ptr = v
        break
if ptr is None:
    print("execfn=absent")
    sys.exit(3)

print("execfn_ptr=%d" % ptr)
try:
    with open("/proc/%s/mem" % pid, "rb", buffering=0) as mem:
        mem.seek(ptr)
        out = b""
        while len(out) < 4096:
            b = mem.read(1)
            if not b or b == b"\0":
                break
            out += b
except OSError as e:
    print("mem=denied errno=%s" % e.errno)
    sys.exit(4)
print("execfn_str=%s" % out.decode("utf-8", "replace"))
PY

stop_sup() {
    [ -n "${SUP:-}" ] && kill "$SUP" 2>/dev/null
    wait "$SUP" 2>/dev/null
    SUP=""
}

# spans PID  -> "arg_start arg_end env_start env_end"
spans() {
    awk '{sub(/.*\) /,""); print $46, $47, $48, $49}' "/proc/$1/stat" 2>/dev/null
}

# ------------------------------------------- A1: control, plain process
env -i PATH=/usr/bin:/bin "$CASES" execfn 20 > "$D/plain.out" 2>&1 &
plain=$!
sleep 0.6
if kill -0 "$plain" 2>/dev/null; then
    rep=$(python3 "$D/auxv.py" "$plain" 2>&1)
    served=$(printf '%s\n' "$rep" | sed -n 's/^execfn_str=//p')
    ptr=$(printf '%s\n' "$rep" | sed -n 's/^execfn_ptr=//p')
    # arg_start arg_end env_start env_end
    read -r pa pe pss pee <<EOT
$(spans "$plain")
EOT
    case "$served" in
        */testcases)
            pass "a1-control-plain-execfn-is-the-real-path ($served)" ;;
        *)
            fail "a1-control-plain-execfn-is-the-real-path (served=[$served] rep=[$rep])" ;;
    esac
    if [ -n "$ptr" ] && [ "$ptr" = "$pee" ]; then
        pass "a1b-control-plain-execfn-equals-env-end"
    else
        fail "a1b-control-plain-execfn-equals-env-end (ptr=[$ptr] env_end=[$pee])"
    fi
    kill "$plain" 2>/dev/null
    wait "$plain" 2>/dev/null
else
    fail "a1-control-plain-execfn-is-the-real-path (no process)"
fi

# ------------------------------ A2..A6: a masked payload
L=qa43
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$L" -- "$CASES" execfn 20 \
    > "$D/masked.out" 2>&1 &
SUP=$!
PAY=""
i=0
while [ $i -lt 40 ]; do
    sleep 0.05
    PAY=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
    [ -n "$PAY" ] && break
    i=$((i + 1))
done
if [ -n "$PAY" ]; then
    rep=$(python3 "$D/auxv.py" "$PAY" 2>&1)
    served=$(printf '%s\n' "$rep" | sed -n 's/^execfn_str=//p')
    ptr=$(printf '%s\n' "$rep" | sed -n 's/^execfn_ptr=//p')
    denied=$(printf '%s\n' "$rep" | grep -c '^mem=denied')
    read -r as ae es ee <<EOT
$(spans "$PAY")
EOT
    exe=$(readlink "/proc/$PAY/exe" 2>/dev/null)

    if [ "$denied" = 1 ]; then
        echo "SKIP a2-auxv-serves-the-label (a same-uid reader cannot open /proc/$PAY/mem here)"
        echo "SKIP a3-execfn-equals-env-end (same reason)"
        echo "SKIP a4-execfn-differs-from-arg-start (same reason)"
    else
        if [ "$served" = "$L" ]; then
            pass "a2-auxv-serves-the-label ($served)"
        else
            fail "a2-auxv-serves-the-label (served=[$served] rep=[$rep])"
        fi
        if [ -n "$ptr" ] && [ "$ptr" = "$ee" ] && [ "$ee" != 0 ]; then
            pass "a3-execfn-equals-env-end (ptr=$ptr env_end=$ee)"
        else
            fail "a3-execfn-equals-env-end (ptr=[$ptr] env_end=[$ee])"
        fi
        if [ -n "$ptr" ] && [ "$ptr" != "$as" ]; then
            pass "a4-execfn-differs-from-arg-start (ptr=$ptr arg_start=$as)"
        else
            fail "a4-execfn-differs-from-arg-start (ptr=[$ptr] arg_start=[$as])"
        fi
        # A7: the offset of the second label copy from arg_start.  The
        # formula is 1 + len(label) + argc, and this payload's argv is
        # `testcases execfn 20`, so argc is 3.
        want=$(( 1 + ${#L} + 3 ))
        if [ -n "$ptr" ]; then
            got=$(( ptr - as ))
            if [ "$got" = "$want" ]; then
                pass "a7-second-copy-offset (offset=$got = 1+label+argc)"
            else
                fail "a7-second-copy-offset (offset=$got, want $want = 1+${#L}+3)"
            fi
        fi
    fi

    # A5: the payload's own view, printed on its stdout before it sleeps.
    real=$(sed -n 's/^execfn=//p' "$D/masked.out" 2>/dev/null | head -n 1)
    case "$real" in
        */testcases)
            pass "a5-payload-getauxval-real-path ($real)" ;;
        *)
            fail "a5-payload-getauxval-real-path (got [${real}] out=$(tr '\n' '|' < "$D/masked.out"))" ;;
    esac
    # A6: the two views disagree.  Only decidable when the auxv pointer
    # was resolvable.
    if [ "$denied" = 1 ]; then
        echo "SKIP a6-served-and-in-payload-disagree (a same-uid reader cannot open /proc/$PAY/mem here)"
    elif [ -n "$served" ] && [ -n "$real" ] && [ "$served" != "$real" ]; then
        pass "a6-served-and-in-payload-disagree (served=$served real=$real)"
    else
        fail "a6-served-and-in-payload-disagree (served=[$served] real=[$real])"
    fi
    # The real binary is not the label: this is what makes "the label" a
    # signal rather than the program's own name.
    case "$exe" in
        */testcases) pass "a8-exe-still-names-the-real-binary ($exe)" ;;
        *) fail "a8-exe-still-names-the-real-binary (exe=[$exe])" ;;
    esac
else
    fail "a2-auxv-serves-the-label (no payload; $(tr '\n' '|' < "$D/masked.out"))"
fi
stop_sup

# ------------------- A9: the same relation at three label lengths
# The issue measured labels of 4, 8 and 12 bytes.  Re-measure two of them
# here so a change in the layout is visible without reading the note.
for n in 4 12; do
    lab=$(printf 'q%.0s' $(seq "$n"))
    env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$lab" -- "$CASES" execfn 20 \
        >/dev/null 2>&1 &
    SUP=$!
    PAY=""
    i=0
    while [ $i -lt 40 ]; do
        sleep 0.05
        PAY=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
        [ -n "$PAY" ] && break
        i=$((i + 1))
    done
    if [ -z "$PAY" ]; then
        fail "a9-layout-label-$n (no payload)"
        stop_sup
        continue
    fi
    rep=$(python3 "$D/auxv.py" "$PAY" 2>&1)
    ptr=$(printf '%s\n' "$rep" | sed -n 's/^execfn_ptr=//p')
    read -r as ae es ee <<EOT
$(spans "$PAY")
EOT
    if printf '%s\n' "$rep" | grep -q '^mem=denied'; then
        echo "SKIP a9-layout-label-$n (a same-uid reader cannot open /proc/mem here)"
    elif [ -n "$ptr" ] && [ "$ptr" = "$ee" ]; then
        pass "a9-layout-label-$n (execfn==env_end)"
    else
        fail "a9-layout-label-$n (ptr=[$ptr] env_end=[$ee])"
    fi
    stop_sup
done

# ------------- A10: --no-exact does not rewrite the auxv at all
# The issue says "under --no-exact the block layout differs and the offset
# formula does not describe the second copy; the dissent still holds".
# Measured on this build that is wrong: the auxv rewrite lives in the
# PR_SET_MM_MAP call that --no-exact skips, so the served view is the real
# exec path and the two views agree.  That is a correction to the issue,
# not a defect, and it is asserted here so a future change is visible.
env -i PATH=/usr/bin:/bin "$TOOL" -q --no-exact -l "$L" -- "$CASES" execfn 20 \
    > "$D/ne.out" 2>&1 &
SUP=$!
PAY=""
i=0
while [ $i -lt 40 ]; do
    sleep 0.05
    PAY=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
    [ -n "$PAY" ] && break
    i=$((i + 1))
done
if [ -z "$PAY" ]; then
    fail "a10-no-exact-does-not-rewrite-auxv (no payload)"
elif python3 "$D/auxv.py" "$PAY" 2>&1 | grep -q '^mem=denied'; then
    echo "SKIP a10-no-exact-does-not-rewrite-auxv (a same-uid reader cannot open /proc/mem here)"
else
    rep=$(python3 "$D/auxv.py" "$PAY" 2>&1)
    served=$(printf '%s\n' "$rep" | sed -n 's/^execfn_str=//p')
    real=$(sed -n 's/^execfn=//p' "$D/ne.out" | head -n 1)
    case "$served" in
        */testcases)
            if [ "$served" = "$real" ]; then
                pass "a10-no-exact-does-not-rewrite-auxv (both views agree: $served)"
            else
                fail "a10-no-exact-does-not-rewrite-auxv (served=$served real=$real)"
            fi
            ;;
        *)
            fail "a10-no-exact-does-not-rewrite-auxv (served=[$served], expected the real path)" ;;
    esac
fi
stop_sup

# ------------- A11: --keep-env leaves AT_EXECFN in the block
# With --keep-env the environment window keeps its addresses, so
# `env_end != AT_EXECFN`.  The issue's rule "AT_EXECFN == env_end" holds
# only when the environment is redacted; this asserts the exception so a
# detector author does not inherit a rule that misses the mode.
env -i PATH=/usr/bin:/bin "$TOOL" -q --keep-env -l "$L" -- "$CASES" execfn 20 \
    >/dev/null 2>&1 &
SUP=$!
PAY=""
i=0
while [ $i -lt 40 ]; do
    sleep 0.05
    PAY=$(pgrep -P "$SUP" 2>/dev/null | head -n 1)
    [ -n "$PAY" ] && break
    i=$((i + 1))
done
if [ -z "$PAY" ]; then
    fail "a11-keep-env-moves-execfn-off-env-end (no payload)"
elif python3 "$D/auxv.py" "$PAY" 2>&1 | grep -q '^mem=denied'; then
    echo "SKIP a11-keep-env-moves-execfn-off-env-end (a same-uid reader cannot open /proc/mem here)"
else
    rep=$(python3 "$D/auxv.py" "$PAY" 2>&1)
    ptr=$(printf '%s\n' "$rep" | sed -n 's/^execfn_ptr=//p')
    read -r as ae es ee <<EOT
$(spans "$PAY")
EOT
    if [ -n "$ptr" ] && [ "$ptr" != "$ee" ]; then
        pass "a11-keep-env-moves-execfn-off-env-end (ptr=$ptr env_end=$ee)"
    else
        fail "a11-keep-env-moves-execfn-off-env-end (ptr=[$ptr] env_end=[$ee], want different)"
    fi
fi
stop_sup

echo "== QA43: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
[ "$FAIL" = 0 ] || exit 1
exit 0
