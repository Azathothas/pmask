#!/bin/sh
# QA fragment for issue 32: `--audit` was silently inert when the host
# selected plain mode.
#
# The defect: the refusal in `main` looked only at an explicit
# `--no-redact`/`--isolate`.  When the host cannot ptrace, the selected
# mode is Plain, `--audit` produced zero rows and no note.
#
# Cases:
#   qa32-host-plain-audit-refused   PMASK_PROBE_PTRACE=0 + --audit exits 255
#   qa32-refusal-names-the-mode     the message names plain mode
#   qa32-refusal-names-the-reason   the message says there is no tracer
#   qa32-explicit-plain-refused     --no-redact + --audit is refused too
#   qa32-isolate-refused            --isolate + --audit is refused
#   qa32-control-redact-audit-ok    on a ptrace host --audit still produces
#                                   rows, so the refusals are not blanket
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa32.$$"
mkdir -p "$D" || { echo "FAIL qa32-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() { rm -rf "$D"; }
trap cleanup EXIT

printf 'qa32-token\n' >"$D/tok"
chmod 600 "$D/tok"

PMASK_PROBE_PTRACE=0 "$TOOL" -q --audit --secret S=file:"$D/tok" -- /bin/true \
    >"$D/hp.out" 2>"$D/hp.err"
rc=$?
if [ "$rc" = 255 ]; then
    pass "qa32-host-plain-audit-refused (exit 255)"
else
    fail "qa32-host-plain-audit-refused (rc=$rc out=[$(cat "$D/hp.out")])"
fi
if grep -q "selected mode is plain" "$D/hp.err"; then
    pass "qa32-refusal-names-the-mode"
else
    fail "qa32-refusal-names-the-mode (err=$(tr '\n' '|' <"$D/hp.err"))"
fi
if grep -q "no tracer" "$D/hp.err"; then
    pass "qa32-refusal-names-the-reason"
else
    fail "qa32-refusal-names-the-reason (err=$(tr '\n' '|' <"$D/hp.err"))"
fi
# Nothing ran: --audit must not be half-applied.
if ! grep -q "^pmask audit:" "$D/hp.out"; then
    pass "qa32-no-audit-rows-before-the-refusal"
else
    fail "qa32-no-audit-rows-before-the-refusal ($(head -2 "$D/hp.out"))"
fi

"$TOOL" -q --no-redact --audit -- /bin/true >"$D/p.out" 2>"$D/p.err"
rc=$?
if [ "$rc" = 255 ] && grep -q -- "--audit needs the redaction mode" "$D/p.err"; then
    pass "qa32-explicit-plain-refused"
else
    fail "qa32-explicit-plain-refused (rc=$rc err=$(tr '\n' '|' <"$D/p.err"))"
fi

"$TOOL" -q --isolate --audit -- /bin/true >"$D/i.out" 2>"$D/i.err"
rc=$?
if [ "$rc" = 255 ] && grep -q -- "--audit needs the redaction mode" "$D/i.err"; then
    pass "qa32-isolate-refused"
else
    fail "qa32-isolate-refused (rc=$rc err=$(tr '\n' '|' <"$D/i.err"))"
fi

# Control: on a host that can ptrace the flag still works.  A build that
# refused --audit unconditionally would pass every row above.
if "$TOOL" probe 2>/dev/null | grep -q "^  metadata redaction *active"; then
    "$TOOL" -q --audit -- /bin/true >"$D/c.out" 2>"$D/c.err"
    rc=$?
    if [ "$rc" = 0 ] && grep -q "^pmask audit: residue:" "$D/c.out"; then
        pass "qa32-control-redact-audit-ok"
    else
        fail "qa32-control-redact-audit-ok (rc=$rc out=$(tr '\n' '|' <"$D/c.out" | cut -c1-200))"
    fi
else
    skip "qa32-control-redact-audit-ok (this host cannot redact)"
fi

# `--redact --isolate=LIST` composes to the redaction mode (issue 19), so
# it keeps its tracer and the audit rows are produced.  A check that only
# looked at `isolate.is_some()` refused it and named a mode the run would
# not take.
"$TOOL" -q --redact --isolate=pid --audit -- /bin/true >"$D/ci.out" 2>"$D/ci.err"
rc=$?
if [ "$rc" = 0 ] && grep -q "^pmask audit: residue:" "$D/ci.out"; then
    pass "qa32-composed-isolate-keeps-the-audit"
else
    fail "qa32-composed-isolate-keeps-the-audit (rc=$rc out=$(tr '\n' '|' <"$D/ci.out" | cut -c1-200) err=$(tr '\n' '|' <"$D/ci.err" | cut -c1-200))"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
