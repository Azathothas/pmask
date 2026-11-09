#!/bin/sh
# QA fragment for issue 34: a ptrace-denied host gave a cryptic session
# error for a mask run.
#
# The defect: a mask run on a host that seccomp-bans ptrace printed
# `pmask: session error: Operation not permitted (os error 1)`.  `probe`
# and `doctor` knew the reason and the secret-side advice; the run path
# did not use them.
#
# Two ways to reach the state:
#   1. the real thing: helpers/noptrace.c installs a seccomp filter that
#      refuses ptrace(2) with EPERM, then execs pmask (needs a C compiler);
#   2. the probe override PMASK_PROBE_PTRACE=0, used when there is no
#      compiler.  The override replaces the probe's answer, not the
#      syscall, so it can only be trusted when the host really refuses.
#
# Cases:
#   qa34-session-still-fails     the run exits 255 (nothing is masked)
#   qa34-error-names-the-reason  the output carries the probe's reason
#   qa34-error-points-at-secret  the output names --secret with file: and
#                                agent: sources
#   qa34-secret-run-still-works  --secret with a file: source runs under
#                                the same filter, so the advice is true
#   qa34-control-host-can-redact the unfiltered host redacts, so the filtered
#                                run is a real refusal and not a broken build
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa34.$$"
mkdir -p "$D" || { echo "FAIL qa34-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() { rm -rf "$D"; }
trap cleanup EXIT

printf 'qa34-token\n' >"$D/tok"
chmod 600 "$D/tok"

# Build the filter helper when a compiler is present.
NOPTRACE=""
for cand in cc gcc clang; do
    if command -v "$cand" >/dev/null 2>&1; then
        if "$cand" -O0 -o "$D/noptrace" ../helpers/noptrace.c 2>"$D/cc.err"; then
            NOPTRACE="$D/noptrace"
        fi
        break
    fi
done

# The wrapper: RUN WRAPPER... -- the command under the filter, or a
# no-op when there is no helper.
if [ -n "$NOPTRACE" ]; then
    WRAP="real seccomp filter"
    RUN_MASK() { "$NOPTRACE" "$TOOL" "$@"; }
    RUN_SECRET() { "$NOPTRACE" "$TOOL" "$@"; }
    # The helper must not silently refuse to install: a filtered `true`
    # has to exit 0.
    if ! "$NOPTRACE" true >/dev/null 2>&1; then
        skip "qa34-filter-installed ($(cat "$D/cc.err" 2>/dev/null))"
        echo "== VERDICT: SKIP =="
        exit 0
    fi
elif command -v python3 >/dev/null 2>&1; then
    WRAP="PMASK_PROBE_PTRACE=0"
    RUN_MASK() { PMASK_PROBE_PTRACE=0 "$TOOL" "$@"; }
    RUN_SECRET() { PMASK_PROBE_PTRACE=0 "$TOOL" "$@"; }
    # The override only makes sense where the host really refuses ptrace.
    if "$TOOL" probe 2>/dev/null | grep -q "^  metadata redaction *active"; then
        skip "qa34-ptrace-denied-host (this host permits ptrace and no C compiler built the filter)"
        echo "== VERDICT: SKIP =="
        exit 0
    fi
else
    skip "qa34-ptrace-denied-host (no C compiler and no python3)"
    echo "== VERDICT: SKIP =="
    exit 0
fi
echo "INFO qa34-wrapper: $WRAP"

RUN_MASK -q -l qa34 -- /bin/true >"$D/m.out" 2>"$D/m.err"
rc=$?
if [ "$rc" = 255 ]; then
    pass "qa34-session-still-fails (exit 255)"
else
    fail "qa34-session-still-fails (rc=$rc out=[$(cat "$D/m.out")])"
fi
if grep -qi "ptrace" "$D/m.err"; then
    pass "qa34-error-names-the-reason ($(head -1 "$D/m.err"))"
else
    fail "qa34-error-names-the-reason (err=$(tr '\n' '|' <"$D/m.err"))"
fi
if grep -q -- "--secret NAME=file:PATH" "$D/m.err" \
    && grep -q -- "agent:NAME" "$D/m.err"; then
    pass "qa34-error-points-at-secret"
else
    fail "qa34-error-points-at-secret (err=$(tr '\n' '|' <"$D/m.err"))"
fi
# The bare errno line is still there, so a reader who greps for it is not
# left without it.
if grep -q "session error" "$D/m.err"; then
    pass "qa34-keeps-the-session-error-line"
else
    fail "qa34-keeps-the-session-error-line (err=$(tr '\n' '|' <"$D/m.err"))"
fi

RUN_SECRET -q --secret S=file:"$D/tok" -- /bin/sh -c "exec '$TOOL' read S" \
    >"$D/s.out" 2>"$D/s.err"
rc=$?
if [ "$rc" = 0 ] && [ "$(cat "$D/s.out" 2>/dev/null)" = "qa34-token" ]; then
    pass "qa34-secret-run-still-works (the advice is true)"
else
    fail "qa34-secret-run-still-works (rc=$rc out=[$(cat "$D/s.out")] err=$(tr '\n' '|' <"$D/s.err"))"
fi

# Control: without the wrapper the same host redacts.  If it does not,
# this fragment is measuring a broken build, not a refuted ptrace.
if "$TOOL" -q -l qa34ctl -- /bin/sh -c 'tr "\0" "|" < /proc/self/cmdline' \
    >"$D/c.out" 2>"$D/c.err" && [ "$(cat "$D/c.out")" = "qa34ctl|" ]; then
    pass "qa34-control-the-unfiltered-host-redacts"
else
    fail "qa34-control-the-unfiltered-host-redacts (out=[$(cat "$D/c.out")] err=$(tr '\n' '|' <"$D/c.err"))"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
