#!/bin/sh
# QA fragment for issue 9: `--report=json` is not one JSON object when the
# payload writes to stdout.
#
# The defect: the report is written after the payload on the same fd 1, so
# a payload's own output lands before the document and a JSON consumer
# fails.  The fix keeps the payload on fd 1 and adds two ways to get the
# document elsewhere: `--report-file PATH` and `--report-fd N`.
#
# Cases:
#   qa9-control-stdout-interleaves  the raw defect, reproduced: the payload
#                                   output is in the same stream, so `jq .`
#                                   fails (this is the documented control)
#   qa9-report-file-parses          --report-file produces one JSON object
#   qa9-report-file-keeps-payload   the payload's stdout is untouched
#   qa9-report-fd-parses            --report-fd produces one JSON object
#   qa9-report-fd-keeps-payload     the payload's stdout is untouched
#   qa9-bad-path-refused            a bad --report-file is a usage error and
#                                   the payload does not run
#   qa9-bad-fd-refused              a closed --report-fd is a usage error
#   qa9-no-report-without-flag      the payload-only run writes no document
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa9.$$"
mkdir -p "$D" || { echo "FAIL qa9-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() { rm -rf "$D"; }
trap cleanup EXIT

# jq when present, python3's json module otherwise.
parse_json() {
    if command -v jq >/dev/null 2>&1; then
        jq -e . "$1" >/dev/null 2>&1
        return $?
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$1" >/dev/null 2>&1
        return $?
    fi
    return 2
}
if ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
    skip "qa9-json-parser (neither jq nor python3 is installed)"
    echo "== VERDICT: SKIP =="
    exit 0
fi

PAYLOAD='echo payload-line'

# ---- control: the stdout interleaving the issue reports.  A payload that
# ---- writes to stdout shares fd 1 with the report, so the output is not
# ---- one JSON document.  This must FAIL to parse, or the cases below
# ---- prove nothing about where the document went.
"$TOOL" -q --no-redact --report=json -- sh -c "$PAYLOAD" >"$D/inter.json" 2>"$D/inter.err"
if [ "$(head -1 "$D/inter.json")" = "payload-line" ]; then
    pass "qa9-control-stdout-carries-the-payload-first"
else
    fail "qa9-control-stdout-carries-the-payload-first (first line: $(head -1 "$D/inter.json"))"
fi
if parse_json "$D/inter.json"; then
    fail "qa9-control-interleaving-breaks-json (the interleaved stream parsed as JSON)"
else
    rc=$?
    if [ "$rc" = 2 ]; then
        skip "qa9-control-interleaving-breaks-json (no parser ran)"
    else
        pass "qa9-control-interleaving-breaks-json"
    fi
fi

# ---- --report-file: the document is the file; fd 1 is the payload's.
"$TOOL" -q --no-redact --report-file "$D/rep.json" -- sh -c "$PAYLOAD" \
    >"$D/rf.out" 2>"$D/rf.err"
rc=$?
if [ "$rc" = 0 ]; then
    pass "qa9-report-file-run-exits-zero"
else
    fail "qa9-report-file-run-exits-zero (rc=$rc err=$(tr '\n' '|' <"$D/rf.err"))"
fi
if parse_json "$D/rep.json"; then
    pass "qa9-report-file-parses"
else
    fail "qa9-report-file-parses ($(head -c 200 "$D/rep.json" 2>/dev/null))"
fi
if [ "$(cat "$D/rf.out")" = "payload-line" ]; then
    pass "qa9-report-file-keeps-payload"
else
    fail "qa9-report-file-keeps-payload (stdout=[$(cat "$D/rf.out")])"
fi
# The document does not merely exist; it is the run report.
mode=$(sed -n 's/^[[:space:]]*"mode": "\([^"]*\)".*/\1/p' "$D/rep.json" | head -1)
if [ "$mode" = "plain" ]; then
    pass "qa9-report-file-carries-the-mode"
else
    fail "qa9-report-file-carries-the-mode (mode=[$mode])"
fi

# ---- --report-fd: the document is the descriptor.
"$TOOL" -q --no-redact --report-fd 3 -- sh -c "$PAYLOAD" \
    >"$D/fd.out" 2>"$D/fd.err" 3>"$D/fd.json"
rc=$?
if [ "$rc" = 0 ]; then
    pass "qa9-report-fd-run-exits-zero"
else
    fail "qa9-report-fd-run-exits-zero (rc=$rc err=$(tr '\n' '|' <"$D/fd.err"))"
fi
if parse_json "$D/fd.json"; then
    pass "qa9-report-fd-parses"
else
    fail "qa9-report-fd-parses ($(head -c 200 "$D/fd.json" 2>/dev/null))"
fi
if [ "$(cat "$D/fd.out")" = "payload-line" ]; then
    pass "qa9-report-fd-keeps-payload"
else
    fail "qa9-report-fd-keeps-payload (stdout=[$(cat "$D/fd.out")])"
fi

# ---- a bad target is a usage error and the payload does not run.
"$TOOL" -q --no-redact --report-file "$D/no/such/dir/r.json" -- sh -c 'echo RAN' \
    >"$D/bad.out" 2>"$D/bad.err"
rc=$?
if [ "$rc" = 255 ] && ! grep -q RAN "$D/bad.out"; then
    pass "qa9-bad-path-refused"
else
    fail "qa9-bad-path-refused (rc=$rc out=[$(cat "$D/bad.out")])"
fi
"$TOOL" -q --no-redact --report-fd 60 -- sh -c 'echo RAN' >"$D/badfd.out" 2>"$D/badfd.err" 60>&-
rc=$?
if [ "$rc" = 255 ] && ! grep -q RAN "$D/badfd.out"; then
    pass "qa9-bad-fd-refused"
else
    fail "qa9-bad-fd-refused (rc=$rc out=[$(cat "$D/badfd.out")])"
fi

# ---- no flag: no document anywhere.  A build that always wrote the file
# ---- would pass the rows above.
rm -f "$D/none.json"
"$TOOL" -q --no-redact -- sh -c "$PAYLOAD" >"$D/none.out" 2>"$D/none.err"
if [ "$(cat "$D/none.out")" = "payload-line" ] && [ ! -e "$D/none.json" ]; then
    pass "qa9-no-report-without-flag"
else
    fail "qa9-no-report-without-flag (stdout=[$(cat "$D/none.out")])"
fi

# ---- A report nobody reads must not change the run's status (issue 17's
# ---- class on the report path): `| head -1` closes the pipe after the
# ---- first line, and the payload's status must still be the run's.
# POSIX sh has no `PIPESTATUS`, so the status is recorded by the
# subshell on the left side of the pipe, which is the process that runs
# the tool.  `head -1` closes the pipe on the next write.
( "$TOOL" -q --report=json --secret T=file:/etc/hostname -- \
    /bin/sh -c 'exit 5' 2>/dev/null; echo $? > "$D/rc" ) | head -1 >/dev/null
rc=$(cat "$D/rc" 2>/dev/null)
if [ "$rc" = 5 ]; then
    pass "qa9-closed-pipe-keeps-the-payload-status"
else
    fail "qa9-closed-pipe-keeps-the-payload-status (rc=$rc, want 5)"
fi

# ---- The payload must not inherit the report descriptor: a shell
# ---- redirect is not close-on-exec, so without the flag the payload
# ---- could write into the document a consumer parses.
"$TOOL" -q --report-fd 9 --secret T=file:/etc/hostname -- \
    /bin/sh -c 'echo FORGED >&9 2>/dev/null || echo closed' \
    9>"$D/fd.json" >"$D/fd.out" 2>/dev/null
if [ "$(cat "$D/fd.out")" = closed ] \
    && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$D/fd.json" 2>/dev/null; then
    pass "qa9-report-fd-is-not-inherited"
else
    fail "qa9-report-fd-is-not-inherited (out=[$(cat "$D/fd.out")])"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
