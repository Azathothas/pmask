#!/bin/sh
# Issue 59: the supervisor's own exec writes the payload argv and any
# `literal:` secret into the kernel audit log.
#
# pmask cannot rewrite its own exec's argument vector: the exec that
# creates the process doing the rewriting is the one the kernel records.
# `literal:` and `env:` sources therefore leave a copy in artefacts pmask
# cannot reach: the kernel audit log (`type=EXECVE` and `PROCTITLE`), the
# shell history, and any wrapper's argv.
#
# What is asserted:
#
#   59a  a `literal:` source at the default verbosity prints exactly one
#        warning, and it names all four things an operator needs: the
#        kernel audit log, the shell history, a wrapper's argv, and the
#        two ways out (`--args-from-fd`, and a non-argv source).
#   59b  the warning never contains the value.  A warning that leaks the
#        secret into stderr would be worse than the exposure it describes.
#   59c  `-q` suppresses it, and nothing else does.  `-q` is the
#        documented way to silence diagnostics and it must keep working.
#   59d  the secret still works: the payload reads it from the delivered
#        descriptor.  A warning that broke delivery would be a regression.
#   59e  a `file:` source prints no warning, so the warning is not noise
#        on every run with a secret.
#   59f  an `env:` source warns about the environment, and does not claim
#        a kernel exec record (the EXECVE record carries argv, not envp).
#   59g  the wording is stronger when the host reports the audit
#        subsystem enabled.  `PMASK_PROBE_AUDIT=1` drives that branch
#        without an auditd host; a real enabled host is the same code
#        path.
#   59h  `--args-from-fd` still warns while a literal secret remains in
#        pmask's argv, and the payload still runs.  The flag removes the
#        payload's arguments from argv, not the secret.
#
# What this fragment cannot assert: the record itself.  Reading it needs
# a host with a working audit subsystem; on this container `auditctl -s`
# is refused (see tests/qa.d/56.sh and docs/research/bteam-audit.md).
set -u
# lib.sh reads BIN_DIR from the cwd, so run from tests/ (see its header).
cd "$(dirname "$0")/.." || exit 2
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

LABEL="qa59-$$"
CANARY="QA59-CANARY-$$"
T=$(mktemp -d "${TMPDIR:-/tmp}/qa59.XXXXXX") || {
    echo "FATAL: mktemp -d failed"
    exit 2
}
cleanup() { kill_label "$LABEL" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT INT TERM

# warn_count FILE: number of lines carrying the audit-log warning.
warn_count() {
    grep -c 'puts the value in pmask' "$1" 2>/dev/null || true
}

# ------------------------------------------------- 59a: the warning appears
"$TOOL" -l "$LABEL" --secret "S=literal:$CANARY" -- /bin/true \
    >/dev/null 2>"$T/a.err"
rc=$?
n=$(warn_count "$T/a.err")
if [ "$rc" = 0 ] && [ "${n:-0}" = 1 ]; then
    pass "59a-one-warning ($(sed -n 's/^pmask: warning: //p' "$T/a.err" | cut -c1-60)...)"
else
    fail "59a-one-warning (rc=$rc warnings=$n stderr=$(head -3 "$T/a.err" | tr '\n' '|'))"
fi
missing=""
for phrase in "kernel audit log" "shell history" "wrapper's argv" \
              "--args-from-fd" "file:PATH" "agent:NAME" "stdin"; do
    grep -qF -- "$phrase" "$T/a.err" || missing="$missing [$phrase]"
done
if [ -z "$missing" ]; then
    pass "59a-warning-names-the-artefacts-and-the-way-out"
else
    fail "59a-warning-names-the-artefacts-and-the-way-out (missing:$missing)"
fi

# --------------------------------------------- 59b: the value never leaks
if grep -qF -- "$CANARY" "$T/a.err"; then
    fail "59b-warning-hides-the-value (the canary is in the warning)"
else
    pass "59b-warning-hides-the-value"
fi

# --------------------------------------------------- 59c: -q still silences
"$TOOL" -q -l "$LABEL" --secret "S=literal:$CANARY" -- /bin/true \
    >/dev/null 2>"$T/q.err"
rc=$?
n=$(warn_count "$T/q.err")
if [ "$rc" = 0 ] && [ "${n:-0}" = 0 ]; then
    pass "59c-quiet-suppresses-the-warning"
else
    fail "59c-quiet-suppresses-the-warning (rc=$rc warnings=$n stderr=$(head -2 "$T/q.err" | tr '\n' '|'))"
fi

# ------------------------------------------------ 59d: the secret still works
if [ -x ./testcases ]; then
    out=$("$TOOL" -q -l "$LABEL" --secret "S=literal:$CANARY" -- \
        ./testcases secretfd S 2>"$T/d.err")
    rc=$?
    case "$out" in
        *"fd=3"*"bytes=${#CANARY}"*)
            pass "59d-literal-secret-delivered (the payload read ${#CANARY} bytes from fd 3)" ;;
        *)
            fail "59d-literal-secret-delivered (rc=$rc out=$(printf '%s' "$out" | tr '\n' '|') err=$(head -2 "$T/d.err" | tr '\n' '|'))" ;;
    esac
else
    skip "59d-literal-secret-delivered (no tests/testcases: build with --features testbins)"
fi

# --------------------------------------- 59e: a file: source is quiet
# `grep -c` prints 0 for a missing or empty file, so a failed run would
# "pass" without a warning ever being possible.  The run must succeed and
# the default-verbosity summary must be on stderr before the count means
# anything.
printf '%s\n' "$CANARY" >"$T/tok"
chmod 600 "$T/tok"
"$TOOL" -l "$LABEL" --secret "S=file:$T/tok" -- /bin/true >/dev/null 2>"$T/e.err"
rc=$?
n=$(warn_count "$T/e.err")
if [ "$rc" != 0 ]; then
    fail "59e-file-source-is-quiet (rc=$rc: the run failed, so a zero count proves nothing: $(head -3 "$T/e.err" | tr '\n' '|'))"
elif [ ! -s "$T/e.err" ]; then
    fail "59e-file-source-is-quiet (empty stderr: the default-verbosity summary is missing, so a zero count is vacuous)"
elif [ "${n:-0}" = 0 ]; then
    pass "59e-file-source-is-quiet"
else
    fail "59e-file-source-is-quiet (warnings=$n: $(head -3 "$T/e.err" | tr '\n' '|'))"
fi

# --------------------------------------------- 59f: env: claims no record
QA59_ENV="$CANARY" "$TOOL" -l "$LABEL" --secret "S=env:QA59_ENV" -- /bin/true \
    >/dev/null 2>"$T/f.err"
n=$(warn_count "$T/f.err")
if [ "${n:-0}" = 1 ] && grep -q 'environment' "$T/f.err"; then
    pass "59f-env-source-warns-about-the-environment"
else
    fail "59f-env-source-warns-about-the-environment (warnings=$n: $(head -3 "$T/f.err" | tr '\n' '|'))"
fi
if grep -q 'type=EXECVE' "$T/f.err"; then
    fail "59f-env-source-claims-no-exec-record (the warning claims type=EXECVE for an env: source)"
else
    pass "59f-env-source-claims-no-exec-record"
fi

# ------------------------------ 59g: the enabled-audit wording is stronger
PMASK_PROBE_AUDIT=1 "$TOOL" -l "$LABEL" --secret "S=literal:$CANARY" -- /bin/true \
    >/dev/null 2>"$T/g.err"
if grep -q 'has already written' "$T/g.err" && grep -q 'type=EXECVE' "$T/g.err"; then
    pass "59g-enabled-audit-wording-is-stronger"
else
    fail "59g-enabled-audit-wording-is-stronger (stderr=$(head -2 "$T/g.err" | tr '\n' '|'))"
fi
# The disabled wording must not claim the record exists.
PMASK_PROBE_AUDIT=0 "$TOOL" -l "$LABEL" --secret "S=literal:$CANARY" -- /bin/true \
    >/dev/null 2>"$T/g0.err"
if ! grep -q 'has already written' "$T/g0.err" && grep -q 'would hold it too' "$T/g0.err"; then
    pass "59g-disabled-audit-wording-does-not-claim-the-record"
else
    fail "59g-disabled-audit-wording-does-not-claim-the-record (stderr=$(head -2 "$T/g0.err" | tr '\n' '|'))"
fi

# --------------------------------- 59h: --args-from-fd still needs the warning
printf '/bin/true\0' >"$T/args.bin"
"$TOOL" -l "$LABEL" --secret "S=literal:$CANARY" --args-from-fd 3 \
    >/dev/null 2>"$T/h.err" 3<"$T/args.bin"
rc=$?
n=$(warn_count "$T/h.err")
if [ "$rc" = 0 ] && [ "${n:-0}" = 1 ]; then
    pass "59h-args-from-fd-still-warns-for-the-secret"
else
    fail "59h-args-from-fd-still-warns-for-the-secret (rc=$rc warnings=$n stderr=$(head -3 "$T/h.err" | tr '\n' '|'))"
fi
# ... and the payload ran, so the descriptor was consumed correctly.
if [ "$rc" = 0 ]; then
    pass "59h-args-from-fd-payload-ran"
else
    fail "59h-args-from-fd-payload-ran (rc=$rc)"
fi

# ----------------------------- 59i: the JSON report carries the exposure too
# A CI job that asserts on the report must see this without parsing stderr.
"$TOOL" --report=json --secret "S=literal:$CANARY" -- /bin/true \
    >"$T/i.json" 2>/dev/null
if grep -q 'kernel audit log, the shell history and any wrapper' "$T/i.json"; then
    pass "59i-json-report-records-the-exposure"
else
    fail "59i-json-report-records-the-exposure (notes=$(sed -n 's/.*"notes": \[//p' "$T/i.json" | head -1))"
fi
if grep -qF -- "$CANARY" "$T/i.json"; then
    fail "59i-json-report-hides-the-value (the canary is in the report)"
else
    pass "59i-json-report-hides-the-value"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
