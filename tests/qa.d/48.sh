#!/bin/sh
# Issue 48: the launch window, the timing side channel, and the documented
# mitigation.
#
#   q48a  the measurement harness exists, is POSIX sh, and runs
#   q48b  it reports a masked/plain spawn ratio above 1 on this host
#   q48c  it reports the launch window for a masked script payload, and
#         reports no such window for the plain control
#   q48d  it reports the syscall signature (or SKIPs with the refusal)
#   q48e  --args-from-fd keeps the payload vector out of the launcher's
#         own argv: the documented mitigation for the launch window
#   q48f  control: the same vector passed on the command line IS visible in
#         the launcher's argv, so q48e is not vacuous
#
# Nothing here changes the launch window: it is a property of ptrace
# supervision.  The fragment pins the measurement and the mitigation.
set -u
here=$(dirname "$0")
cd "$here/.." || { echo "FATAL: cannot enter tests/"; exit 2; }
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

ROOT=$(pwd)/..
MEAS="$ROOT/measurements/launch-window.sh"
SUP=""
FAIL=0
T="${TMPDIR:-/tmp}/pmask-q48.$$"
mkdir -p "$T" || { echo "FATAL: mktemp"; exit 2; }
chmod 700 "$T"

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    [ -n "${SUP:-}" ] && kill -9 "$SUP" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

# A short run: this fragment runs inside the gate, and the full-length
# numbers belong in measurements/ and the research note, not in the gate.
WINDOW_ROUNDS=1 WINDOW_N=8 WINDOW_SUSTAINED_SECS=1 \
    timeout 300 sh "$MEAS" >"$T/measure.log" 2>&1
m_rc=$?

# ------------------------------------------------------ q48a: the harness
if [ -f "$MEAS" ]; then
    if sh -n "$MEAS" 2>/dev/null; then
        pass "q48a-harness-is-present-and-parses"
    else
        fail "q48a-harness-is-present-and-parses (sh -n failed)"
    fi
else
    fail "q48a-harness-is-present-and-parses (measurements/launch-window.sh missing)"
fi

if [ "$m_rc" = 0 ] && grep -q '^DONE (issue 48 measurement)$' "$T/measure.log"; then
    pass "q48a2-harness-runs-to-completion ($(grep -c . "$T/measure.log") lines)"
else
    fail "q48a2-harness-runs-to-completion (rc=$m_rc: $(tail -2 "$T/measure.log" | tr '\n' '|'))"
fi

# The POSIX sh rule: the harness must not use bash-only constructs.  Only
# unambiguous markers are searched for: a bare `[[` matches the `[[` in a
# character class such as `[[:space:]]`, so the marker carries its space.
bashism=$(grep -nE '(^|[^[:alnum:]_])\[\[ |(^|[;[:space:]])local [a-zA-Z_]|(^|[;[:space:]])function [a-zA-Z_]|\{[0-9]+\.\.[0-9]+\}' "$MEAS" | head -1)
if [ -n "$bashism" ]; then
    fail "q48a3-harness-is-posix-sh ($bashism)"
else
    pass "q48a3-harness-is-posix-sh"
fi

# ------------------------------------------------- q48b: the timing ratio
RATIO=$(sed -n 's/^SPAWN-RATIO masked_over_plain=\([0-9.]*\).*/\1/p' "$T/measure.log" | head -1)
if [ -n "$RATIO" ]; then
    # A ratio of exactly 1 would mean the mask costs nothing measurable,
    # which contradicts every measurement in the issue.  Anything above 1
    # is the channel; the exact number is in the log.
    if awk -v r="$RATIO" 'BEGIN{ exit !(r > 1.0) }'; then
        pass "q48b-spawn-latency-ratio-above-1 (masked/plain=$RATIO)"
    else
        fail "q48b-spawn-latency-ratio-above-1 (masked/plain=$RATIO)"
    fi
    # And the plain row must exist: a ratio computed against a missing
    # baseline would be meaningless.
    grep -q '^SPAWN variant=plain ' "$T/measure.log" \
        && pass "q48b2-baseline-row-present" \
        || fail "q48b2-baseline-row-present (no SPAWN plain row)"
else
    skip "q48b-spawn-latency-ratio-above-1 ($(grep -m1 '^SKIP spawn' "$T/measure.log" || echo 'no SPAWN-RATIO line'))"
    skip "q48b2-baseline-row-present (no ratio)"
fi

# ------------------------------------------------- q48c: the launch window
# The masked script row must report a window and a sequence in which the
# process carried a comm other than the label; the plain control must
# report that the label never appeared at all.
MW=$(sed -n 's/^WINDOW variant=masked payload=script .*off_label_total_us=\([0-9.]*\).*/\1/p' "$T/measure.log" | head -1)
if [ -n "$MW" ]; then
    if awk -v w="$MW" 'BEGIN{ exit !(w > 0) }'; then
        pass "q48c-masked-script-payload-shows-a-window (off_label_us=$MW)"
    else
        fail "q48c-masked-script-payload-shows-a-window (off_label_us=$MW)"
    fi
    grep -q '^WINDOW variant=masked payload=script .*sequence=[^ ]*>' "$T/measure.log" \
        && pass "q48c2-masked-window-is-a-comm-sequence" \
        || fail "q48c2-masked-window-is-a-comm-sequence (no transition in the sequence)"
else
    skip "q48c-masked-script-payload-shows-a-window ($(grep -m1 '^SKIP launch-window' "$T/measure.log" || echo 'no WINDOW row'))"
    skip "q48c2-masked-window-is-a-comm-sequence (no window row)"
fi
# The control: a plain launch never carries the masked run's label, so its
# row must say so.  If it claimed a window, the observer would be measuring
# something other than the mask.
if grep -q '^WINDOW variant=plain payload=script ' "$T/measure.log"; then
    grep -q '^WINDOW variant=plain payload=script .*label_never_seen=1' "$T/measure.log" \
        && pass "q48c3-plain-control-never-carries-the-label" \
        || fail "q48c3-plain-control-never-carries-the-label ($(grep -m1 '^WINDOW variant=plain payload=script ' "$T/measure.log"))"
else
    skip "q48c3-plain-control-never-carries-the-label (no plain WINDOW row)"
fi

# ------------------------------------------------ q48d: syscall signature
if grep -q '^SYSCALL-STARTUP prctl(PR_SET_MM' "$T/measure.log"; then
    pass "q48d-startup-signature-names-PR_SET_MM_MAP"
else
    fail "q48d-startup-signature-names-PR_SET_MM_MAP ($(grep -m1 '^SKIP syscall' "$T/measure.log" || echo 'no SYSCALL-STARTUP line'))"
fi
if grep -q '^SYSCALL-STARTUP prctl(PR_SET_NAME' "$T/measure.log"; then
    pass "q48d2-startup-signature-names-PR_SET_NAME"
else
    fail "q48d2-startup-signature-names-PR_SET_NAME"
fi
if grep -q '^SYSCALL-STARTUP prctl(PR_SET_DUMPABLE' "$T/measure.log"; then
    pass "q48d3-startup-signature-names-PR_SET_DUMPABLE"
else
    fail "q48d3-startup-signature-names-PR_SET_DUMPABLE"
fi
# The sustained row either produced counts or said why not.  Both are
# acceptable; silence would not be.
if grep -q '^SYSCALL-SUSTAINED ' "$T/measure.log"; then
    pass "q48d4-sustained-traffic-was-counted ($(grep -m1 '^SYSCALL-SUSTAINED ' "$T/measure.log" | cut -c1-70))"
elif grep -q '^SKIP syscall-sustained' "$T/measure.log"; then
    skip "q48d4-sustained-traffic-was-counted ($(grep -m1 '^SKIP syscall-sustained' "$T/measure.log" | cut -c1-90))"
else
    fail "q48d4-sustained-traffic-was-counted (neither a row nor a SKIP)"
fi
# The failcheck row is a finding, not a pass/fail of the tool: it must
# either show the EPERM or say the host behaved differently.
if grep -q '^FAILCHECK ' "$T/measure.log"; then
    pass "q48d5-strace-f-finding-is-recorded ($(grep -m1 '^FAILCHECK ' "$T/measure.log" | cut -c1-60))"
else
    fail "q48d5-strace-f-finding-is-recorded (no FAILCHECK line)"
fi

# ------------------------------------------ q48e/f: the documented escape
# `--args-from-fd` reads the vector from a descriptor.  The payload's
# arguments must not appear in the launcher's own /proc/<pid>/cmdline.
VEC_MARK="Q48VEC$$"
printf '%s\0%s\0%s\0' "$CASES" holdargs "$VEC_MARK" >"$T/args.bin"
# holdargs wants an output path as its first argument.
printf '%s\0%s\0%s\0%s\0' "$CASES" holdargs "$T/argv.out" "$VEC_MARK" >"$T/args.bin"
env -i PATH=/usr/bin:/bin "$TOOL" -q -l "b2q48-$$" --args-from-fd 3 -- \
    <"$T/args.bin" >/dev/null 2>&1 3<"$T/args.bin" &
SUP=$!
sleep 0.8
LL=$(tr '\0' '|' < "/proc/$SUP/cmdline" 2>/dev/null)
if [ -z "$LL" ]; then
    fail "q48e-args-from-fd-keeps-the-vector-out-of-argv (the supervisor is gone or unreadable)"
else
    case "$LL" in
        *"$VEC_MARK"*)
            fail "q48e-args-from-fd-keeps-the-vector-out-of-argv (marker in cmdline=[$LL])" ;;
        *)
            pass "q48e-args-from-fd-keeps-the-vector-out-of-argv (cmdline=[$LL])" ;;
    esac
fi
PAY=$(pgrep -P "$SUP" 2>/dev/null | head -1)
if [ -n "$PAY" ]; then
    PAYC=$(tr '\0' '|' < "/proc/$PAY/cmdline" 2>/dev/null)
    # The payload is masked too, so its cmdline is the label and not the
    # vector.  That is the second half of the mitigation: with
    # --args-from-fd the vector is in no /proc cmdline at all.
    case "$PAYC" in
        *"$VEC_MARK"*)
            fail "q48e2-args-from-fd-leaves-no-cmdline-anywhere (payload cmdline carries the marker: [$PAYC])" ;;
        "b2q48-$$|")
            pass "q48e2-args-from-fd-leaves-no-cmdline-anywhere (payload cmdline is the label)" ;;
        *)
            fail "q48e2-args-from-fd-leaves-no-cmdline-anywhere (payload cmdline=[$PAYC])" ;;
    esac
else
    fail "q48e2-args-from-fd-leaves-no-cmdline-anywhere (no payload under $SUP)"
fi
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
# holdargs writes its report from the vector it received, which is the
# functional half of the same case.
# holdargs reports argc, each argument's length and its last 12 bytes, so
# the check is against the tail of the marker, not the whole string.
TAIL=$(printf '%s' "$VEC_MARK" | tail -c 12)
if [ -s "$T/argv.out" ]; then
    if grep -q "argc=4" "$T/argv.out" && grep -q "$TAIL" "$T/argv.out"; then
        pass "q48e3-args-from-fd-vector-arrived-intact (argc=4, tail=$TAIL)"
    else
        fail "q48e3-args-from-fd-vector-arrived-intact ($(head -3 "$T/argv.out" | tr '\n' '|'))"
    fi
else
    fail "q48e3-args-from-fd-vector-arrived-intact (no report file)"
fi

# Control: the same vector passed on the command line IS in the launcher's
# argv until the self-mask runs.  The self-mask rewrites it, so the control
# is the *payload's* real argv, which is what the launch window leaks: a
# plain process started with the marker carries it for its whole life.
env -i PATH=/usr/bin:/bin "$CASES" holdargs "$T/plain2.out" "$VEC_MARK" \
    >/dev/null 2>&1 &
CTL=$!
sleep 0.4
CC=$(tr '\0' '|' < "/proc/$CTL/cmdline" 2>/dev/null)
case "$CC" in
    *"$VEC_MARK"*) pass "q48f-control-command-line-vector-is-visible (cmdline carries the marker)" ;;
    *) fail "q48f-control-command-line-vector-is-visible (cmdline=[$CC])" ;;
esac
kill -9 "$CTL" 2>/dev/null
wait "$CTL" 2>/dev/null

echo "== VERDICT: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL) failures=$FAIL =="
[ "$FAIL" = 0 ]
