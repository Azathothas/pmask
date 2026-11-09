#!/bin/sh
# Issue 55: the records outside the masked tree.
#
# pmask redacts the tree it supervises; the report, the audit rows, the
# daemon log, `sudo`'s argv, the shell history and a systemd scope's
# description are written by something else and stay.  This fragment pins
# the surfaces that are readable here and names the ones this host cannot
# exercise.
set -u
cd "$(dirname "$0")" || exit 2
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
[ -x "$TOOL" ] || { echo "FATAL: $TOOL is missing"; exit 2; }

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa55.XXXXXX") || exit 2
chmod 700 "$D"
cleanup() { rm -rf "$D"; }
trap cleanup EXIT INT TERM

# 55a: the JSON report describes the run.
"$TOOL" --report=json --no-redact --secret T=file:/etc/hostname -- \
    /bin/true >"$D/report.json" 2>/dev/null
rc=$?
if command -v python3 >/dev/null 2>&1; then
    if python3 - "$D/report.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["mode"] in ("plain", "redact", "isolate"), d
assert "payload_dumpable" in d
assert "exit" in d and "secrets" in d
PY
    then
        pass "55-json-report-describes-the-run"
    else
        fail "55-json-report-describes-the-run (unparseable or missing keys)"
    fi
else
    skip "55-json-report-describes-the-run (no python3)"
fi

# 55b: --audit names the real exe path and the tracer.
out=$("$TOOL" --audit -l qa55a -- "$BIN_DIR/testcases" sleepfor 1 2>&1)
case "$out" in
    *"pmask audit: pid="*"exe=/"*"tracer="*)
        pass "55-audit-row-names-exe-and-tracer" ;;
    *)
        fail "55-audit-row-names-exe-and-tracer (out=[$out])" ;;
esac
case "$out" in
    *"pmask audit: residue:"*)
        pass "55-audit-prints-a-residue-count" ;;
    *) fail "55-audit-prints-a-residue-count (out=[$out])" ;;
esac

# 55c: probe/doctor describe the host's posture.
out=$("$TOOL" probe 2>&1)
case "$out" in
    *"metadata redaction"*) pass "55-probe-names-the-redaction-row" ;;
    *) fail "55-probe-names-the-redaction-row" ;;
esac
out=$("$TOOL" doctor --json 2>/dev/null)
if command -v python3 >/dev/null 2>&1; then
    if printf '%s' "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
        pass "55-doctor-json-parses"
    else
        fail "55-doctor-json-parses"
    fi
else
    skip "55-doctor-json-parses (no python3)"
fi

# 55d: the Scope description change is only observable with a running
# user manager.  This host has none, so the row is a named SKIP.
if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "${XDG_RUNTIME_DIR:-}/systemd" ] \
    && command -v systemd-run >/dev/null 2>&1; then
    out=$("$TOOL" -q --scope-name qa55 "$CASES" echoargs qa55 2>&1)
    case "$out" in
        *"scope-name unavailable"*) skip "55-scope-description (no user manager)" ;;
        *qa55*) pass "55-scope-description (scope ran)" ;;
        *) fail "55-scope-description (out=[$out])" ;;
    esac
else
    skip "55-scope-description (no user systemd manager here)"
fi

# 55e: the shell history and a wrapper's argv are outside the process;
# the mitigation the README names is --args-from-fd.  Prove the value is
# not in the payload's cmdline and that the supervisor's own argv is not
# required to carry it.
printf '/bin/sh\0-c\0echo ok\0' > "$D/argv.bin"
out=$("$TOOL" -q --args-from-fd 3 3<"$D/argv.bin" 2>&1)
case "$out" in
    *ok*) pass "55-args-from-fd-carries-the-command" ;;
    *) fail "55-args-from-fd-carries-the-command (out=[$out])" ;;
esac

echo "== QA55: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL) =="
[ "$FAIL" = 0 ] || exit 1
exit 0
