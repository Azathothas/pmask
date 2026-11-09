#!/bin/sh
# QA fragment for issue 10: plain and isolate modes silently dropped mask
# options.
#
# The defect: `run.rs` named only the label and `--no-dumpable` as not
# applied; `--comm`, `--argv0`, `--no-exact`, `--detach`, `--watch-rename`,
# `--rexec`, `--exec-once`, `--hugetlb`, `--on-exit`, `--no-follow`,
# `--unshare` and `--no-new-privs` vanished without a word, contrary to
# AGENTS.md invariant 13.
#
# Cases: one case per option, asserting the note names it.  Plus a control
# that the same option in redaction mode produces no "was not applied"
# note, so the row cannot pass on a build that always prints it.
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa10.$$"
mkdir -p "$D" || { echo "FAIL qa10-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() { rm -rf "$D"; }
trap cleanup EXIT

# note_for MODE OPTION... -> 0 when one note names OPTION as not applied.
note_for() {
    nf_mode="$1"
    shift
    "$TOOL" --no-redact --report=json "$@" -- /bin/true >"$D/n.json" 2>"$D/n.err"
    grep -q -- "$nf_mode was not applied" "$D/n.json"
}

check() {
    ch_opt="$1"
    shift
    if "$TOOL" --no-redact --report=json "$@" -- /bin/true >"$D/o.json" 2>"$D/o.err"; then
        if grep -q -- "$ch_opt was not applied" "$D/o.json"; then
            pass "qa10-plain-notes-$ch_opt"
        else
            fail "qa10-plain-notes-$ch_opt (notes: $(tr '\n' '|' <"$D/o.json" | cut -c1-400))"
        fi
    else
        fail "qa10-plain-notes-$ch_opt (the run failed: $(tr '\n' '|' <"$D/o.err"))"
    fi
}

check --comm --comm qa10
check --argv0 --argv0 qa10
check --no-exact --no-exact
check --detach --detach
check --watch-rename --watch-rename
check --rexec --rexec
check --exec-once --exec-once
check --hugetlb --hugetlb
check --on-exit --on-exit wait
check --no-follow --no-follow
check --unshare --unshare
check --no-new-privs --no-new-privs

# Isolate mode is the other mode that cannot redact; it must say the same.
"$TOOL" --isolate --report=json --comm qa10b -- /bin/true >"$D/i.json" 2>"$D/i.err"
if grep -q -- "--comm was not applied" "$D/i.json"; then
    pass "qa10-isolate-notes---comm"
else
    fail "qa10-isolate-notes---comm (report: $(tr '\n' '|' <"$D/i.json" | cut -c1-300))"
fi

# Control: in redaction mode the options are applied, so no note says they
# were dropped.  Without this, a build that always printed the notes would
# pass every row above.
printf 'tok\n' >"$D/tok"
chmod 600 "$D/tok"
"$TOOL" -q --report=json --secret T=file:"$D/tok" --comm qa10c --no-exact -- /bin/true \
    >"$D/c.json" 2>"$D/c.err"
if ! grep -q "was not applied" "$D/c.json"; then
    pass "qa10-control-redact-mode-has-no-dropped-notes"
else
    fail "qa10-control-redact-mode-has-no-dropped-notes ($(tr '\n' '|' <"$D/c.json" | cut -c1-300))"
fi

# The report must stay reachable: the same run as one JSON document.
if [ -s "$D/o.json" ]; then
    pass "qa10-report-json-is-produced"
else
    fail "qa10-report-json-is-produced (empty report)"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
