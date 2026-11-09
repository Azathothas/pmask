#!/bin/sh
# QA fragment for issue 14: CLI/UX nits N1-N8.
#
#   N1 plain and isolate errors named no program; the redaction path did
#   N2 --comm over 15 bytes is refused in every mode
#   N3 `--keep-env PATH` (space form) keeps the environment and treats
#      PATH as the program; the parser must not silently accept that
#   N4 a non-numeric descriptor value is named, not just "needs a number"
#   N5 `--help=short` and `pmask help <topic>` exist for the 13 KB text
#   N6 the examples say ptrace is needed
#   N7 `-v` lines carry a timestamp offset
#   N8 vm/run.sh builds with --locked --offline
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa14.$$"
mkdir -p "$D" || { echo "FAIL qa14-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    kill_label qa14 KILL 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT

ROOT=$(cd .. && cd .. && pwd)

# ------------------------------------------------------------------ N1
# The redaction path is the reference: it names the program.
"$TOOL" -q -- /nonexistent/qa14 >"$D/n1r.out" 2>"$D/n1r.err"
if grep -q "/nonexistent/qa14" "$D/n1r.err"; then
    pass "qa14-n1-control-redact-names-the-program"
else
    fail "qa14-n1-control-redact-names-the-program (err=$(tr '\n' '|' <"$D/n1r.err"))"
fi
"$TOOL" -q --no-redact -- /nonexistent/qa14 >"$D/n1p.out" 2>"$D/n1p.err"
rc=$?
if grep -q "/nonexistent/qa14" "$D/n1p.err"; then
    pass "qa14-n1-plain-names-the-program (rc=$rc)"
else
    fail "qa14-n1-plain-names-the-program (err=$(tr '\n' '|' <"$D/n1p.err"))"
fi
"$TOOL" -q --isolate -- /nonexistent/qa14 >"$D/n1i.out" 2>"$D/n1i.err"
rc=$?
if grep -q "/nonexistent/qa14" "$D/n1i.err"; then
    pass "qa14-n1-isolate-names-the-program (rc=$rc)"
else
    fail "qa14-n1-isolate-names-the-program (err=$(tr '\n' '|' <"$D/n1i.err"))"
fi

# ------------------------------------------------------------------ N2
# --comm over 15 bytes is refused in redaction mode; the parser-level
# check makes plain and isolate agree instead of dropping it silently.
for mode in "" "--no-redact" "--isolate"; do
    # shellcheck disable=SC2086
    "$TOOL" -q $mode --comm 1234567890123456 -- /bin/true >"$D/n2.out" 2>"$D/n2.err"
    rc=$?
    label=redact
    [ "$mode" = "--no-redact" ] && label=plain
    [ "$mode" = "--isolate" ] && label=isolate
    if [ "$rc" != 0 ] && grep -q "comm must be at most 15 bytes" "$D/n2.err"; then
        pass "qa14-n2-long-comm-refused-$label"
    else
        fail "qa14-n2-long-comm-refused-$label (rc=$rc err=$(tr '\n' '|' <"$D/n2.err"))"
    fi
done

# ------------------------------------------------------------------ N3
# `--keep-env PATH -- true` used to keep the whole environment and run
# PATH as the program, failing with the generic "No such file or
# directory".  When a `--` separator and a command follow the value, the
# operator wrote the inline form with a space; the parser names it.
"$TOOL" -q --keep-env PATH -- true >"$D/n3.out" 2>"$D/n3.err"
rc=$?
if [ "$rc" = 255 ] && grep -q -- "--keep-env=PATH" "$D/n3.err"; then
    pass "qa14-n3-keep-env-space-form-before-a-command-is-refused"
else
    fail "qa14-n3-keep-env-space-form-before-a-command-is-refused (rc=$rc err=$(tr '\n' '|' <"$D/n3.err"))"
fi
# Control: `--keep-env` with no value is still the whole-environment
# switch, and a bare `--keep-env PATH` still runs a program named PATH
# (there is no separator, so the word is the command).
"$TOOL" -q --keep-env -- env >"$D/n3b.out" 2>"$D/n3b.err"
rc=$?
if [ "$rc" = 0 ] && grep -q "^PATH=" "$D/n3b.out"; then
    pass "qa14-n3-control-bare-keep-env-keeps-everything"
else
    fail "qa14-n3-control-bare-keep-env-keeps-everything (rc=$rc err=$(tr '\n' '|' <"$D/n3b.err"))"
fi
# Control: the inline form keeps one name and still runs.
"$TOOL" -q --keep-env=PATH -- env >"$D/n3c.out" 2>"$D/n3c.err"
rc=$?
if [ "$rc" = 0 ] && grep -q "^PATH=" "$D/n3c.out"; then
    pass "qa14-n3-control-inline-form-keeps-one-name"
else
    fail "qa14-n3-control-inline-form-keeps-one-name (rc=$rc out=$(head -2 "$D/n3c.out" | tr '\n' '|'))"
fi

# ------------------------------------------------------------------ N4
"$TOOL" --args-from-fd abc >"$D/n4a.out" 2>"$D/n4a.err"
rc=$?
if [ "$rc" = 255 ] && grep -q "abc" "$D/n4a.err"; then
    pass "qa14-n4-args-from-fd-names-the-value"
else
    fail "qa14-n4-args-from-fd-names-the-value (rc=$rc err=$(tr '\n' '|' <"$D/n4a.err"))"
fi
"$TOOL" --image-from-fd xyz >"$D/n4b.out" 2>"$D/n4b.err"
rc=$?
if [ "$rc" = 255 ] && grep -q "xyz" "$D/n4b.err"; then
    pass "qa14-n4-image-from-fd-names-the-value"
else
    fail "qa14-n4-image-from-fd-names-the-value (rc=$rc err=$(tr '\n' '|' <"$D/n4b.err"))"
fi

# ------------------------------------------------------------------ N5
full=$("$TOOL" --help 2>&1 | wc -c | tr -d ' ')
short=$("$TOOL" --help=short 2>&1 | wc -c | tr -d ' ')
if [ "$short" -gt 0 ] && [ "$short" -lt "$full" ]; then
    pass "qa14-n5-help-short-is-smaller (short=$short full=$full)"
else
    fail "qa14-n5-help-short-is-smaller (short=$short full=$full)"
fi
if "$TOOL" --help=short 2>&1 | grep -q -- "--isolate"; then
    pass "qa14-n5-help-short-lists-the-options"
else
    fail "qa14-n5-help-short-lists-the-options"
fi
if "$TOOL" help isolate 2>&1 | grep -q -- "--isolate"; then
    pass "qa14-n5-help-topic-isolate"
else
    fail "qa14-n5-help-topic-isolate"
fi
"$TOOL" help no-such-topic >"$D/n5.out" 2>"$D/n5.err"
rc=$?
if [ "$rc" = 255 ]; then
    pass "qa14-n5-unknown-topic-is-refused"
else
    fail "qa14-n5-unknown-topic-is-refused (rc=$rc)"
fi

# ------------------------------------------------------------------ N6
missing=""
for ex in basic_mask env_redaction supervise; do
    f="$ROOT/examples/$ex.rs"
    [ -r "$f" ] || { missing="$missing $ex(absent)"; continue; }
    grep -qi "ptrace" "$f" || missing="$missing $ex"
done
if [ -z "$missing" ]; then
    pass "qa14-n6-examples-name-ptrace"
else
    fail "qa14-n6-examples-name-ptrace (no ptrace note:$missing)"
fi

# ------------------------------------------------------------------ N7
"$TOOL" -v -l qa14v -- /bin/true >"$D/n7.out" 2>"$D/n7.err"
if [ ! -s "$D/n7.err" ]; then
    skip "qa14-n7-verbose-lines-carry-a-timestamp (no -v lines on this host)"
elif grep -Eq '^\[pmask [0-9]+ \+[0-9]+\.[0-9]{6}s\] ' "$D/n7.err"; then
    pass "qa14-n7-verbose-lines-carry-a-timestamp ($(head -1 "$D/n7.err" | cut -c1-40))"
else
    fail "qa14-n7-verbose-lines-carry-a-timestamp ($(head -1 "$D/n7.err"))"
fi

# ------------------------------------------------------------------ N8
if [ -r "$ROOT/vm/run.sh" ]; then
    if grep -q -- "--offline" "$ROOT/vm/run.sh" \
        && grep -q -- "--locked" "$ROOT/vm/run.sh"; then
        pass "qa14-n8-vm-run-builds-offline"
    else
        fail "qa14-n8-vm-run-builds-offline (no --locked --offline in the build line)"
    fi
else
    skip "qa14-n8-vm-run-builds-offline (vm/run.sh not staged)"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
