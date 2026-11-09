#!/bin/sh
# QA fragment for issue 6: `pmask store --help` and `pmask get --help`
# did not print help.
#
# The defect: `cmd_store` took `args.first()` as the verb before it looked
# for `-h/--help`, so `store --help` resolved a passphrase (and failed with
# "no terminal" under the gate), and `cmd_get` turned every non-option
# token into the secret name, so `get --help` tried to reach an agent.
#
# Cases:
#   qa6-control-a-verb-without-a-passphrase-prompts
#                            the probe can see the failure: `store list`
#                            with no tty does print the passphrase error
#   qa6-store-help           `store --help` and `store -h` exit 0, print
#                            usage, and never mention a passphrase
#   qa6-get-help             `get --help` and `get -h` exit 0 and print
#                            usage
#   qa6-unknown-verb-refused before the passphrase: names the verb and
#                            does not ask for a passphrase
#   qa6-help-then-verb       `store get --help` still prints help
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa6.$$"
mkdir -p "$D" || { echo "FAIL qa6-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

cleanup() { rm -rf "$D"; }
trap cleanup EXIT

# The gate runs without a controlling terminal, so a verb that needs a
# passphrase prints the "no terminal" error.  That is the control: it
# proves this fragment can tell "asked for a passphrase" from "printed
# help".
XDG_DATA_HOME="$D/data" "$TOOL" store list </dev/null >"$D/ctl.out" 2>"$D/ctl.err"
ctl_rc=$?
if [ "$ctl_rc" != 0 ] && grep -q "passphrase" "$D/ctl.err"; then
    pass "qa6-control-a-verb-without-a-passphrase-prompts (rc=$ctl_rc)"
else
    fail "qa6-control-a-verb-without-a-passphrase-prompts (rc=$ctl_rc err=[$(cat "$D/ctl.err")])"
fi

# store --help / store -h: exit 0, usage on stdout, no passphrase error.
for form in --help -h; do
    XDG_DATA_HOME="$D/data" "$TOOL" store "$form" </dev/null >"$D/store.out" 2>"$D/store.err"
    rc=$?
    if [ "$rc" = 0 ] && grep -q "pmask store init" "$D/store.out" \
        && ! grep -qi "passphrase:" "$D/store.err"; then
        pass "qa6-store-help-$form"
    else
        fail "qa6-store-help-$form (rc=$rc out=[$(head -1 "$D/store.out")] err=[$(cat "$D/store.err")])"
    fi
done

for form in --help -h; do
    "$TOOL" get "$form" </dev/null >"$D/get.out" 2>"$D/get.err"
    rc=$?
    if [ "$rc" = 0 ] && grep -q "pmask get NAME" "$D/get.out"; then
        pass "qa6-get-help-$form"
    else
        fail "qa6-get-help-$form (rc=$rc out=[$(head -1 "$D/get.out")] err=[$(cat "$D/get.err")])"
    fi
done

# An unknown verb is refused before any passphrase work, and the refusal
# names the token so a typo is obvious.
XDG_DATA_HOME="$D/data" "$TOOL" store frobnicate </dev/null >"$D/bad.out" 2>"$D/bad.err"
rc=$?
if [ "$rc" = 255 ] && grep -q "frobnicate" "$D/bad.err" \
    && ! grep -q "no terminal to ask for a passphrase" "$D/bad.err"; then
    pass "qa6-unknown-verb-refused-before-the-passphrase"
else
    fail "qa6-unknown-verb-refused (rc=$rc err=[$(cat "$D/bad.err")])"
fi

XDG_DATA_HOME="$D/data" "$TOOL" store --nonsense </dev/null >"$D/opt.out" 2>"$D/opt.err"
rc=$?
if [ "$rc" = 255 ] && grep -q -- "--nonsense" "$D/opt.err"; then
    pass "qa6-unknown-store-option-named"
else
    fail "qa6-unknown-store-option-named (rc=$rc err=[$(cat "$D/opt.err")])"
fi

# `store get --help` must print help, not try to read a passphrase for the
# verb `get`.
XDG_DATA_HOME="$D/data" "$TOOL" store get --help </dev/null >"$D/vh.out" 2>"$D/vh.err"
rc=$?
if [ "$rc" = 0 ] && grep -q "pmask store init" "$D/vh.out"; then
    pass "qa6-help-after-the-verb"
else
    fail "qa6-help-after-the-verb (rc=$rc err=[$(cat "$D/vh.err")])"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
