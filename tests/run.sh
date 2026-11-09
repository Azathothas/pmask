#!/bin/sh
# Full-suite orchestrator.
#
# Binaries (see refresh_bins in lib.sh):
#   TESTBIN_DIR=DIR   copy prebuilt binaries from DIR
#   cargo present     always `cargo build --release --bins --features testbins`;
#                     cargo decides what is stale
#   no cargo          use the binaries already in tests/ (the VM case)
#
# Works on any Linux with ptrace allowed.  On ptrace-free hosts use
# vm/run.sh, which runs this script inside a QEMU micro-VM.
set -u
cd "$(dirname "$0")"
. ./lib.sh

refresh_bins || { echo "################ FINAL: FAILURES (binaries)"; exit 2; }
PMASK_BINS_READY=1
export PMASK_BINS_READY

FAIL=0
echo "################ unwrap-audit"
if command -v python3 >/dev/null 2>&1 && [ -f "$BIN_DIR/../scripts/unwrap_audit.py" ]; then
    python3 "$BIN_DIR/../scripts/unwrap_audit.py" || FAIL=1
else
    echo "SKIP unwrap-audit (no python3 or scripts/ staged)"
fi
# The completions are static tables for a hand-written parser, so the only
# way they stay correct is a check that reads the parser.  It needs no
# binary and no host capability, so a missing script is a failure.
echo "################ completions"
if [ -f "$BIN_DIR/../scripts/check-completions.sh" ]; then
    sh "$BIN_DIR/../scripts/check-completions.sh" || FAIL=1
else
    echo "FAIL completions (scripts/check-completions.sh is absent)"
    FAIL=1
fi
# The per-issue QA fragments.  run.sh orchestrates the suites and qa.sh
# orchestrates the fragments, so one gate cannot silently skip the other.
echo "################ qa fragments"
if [ -f qa.sh ]; then
    sh qa.sh || FAIL=1
else
    echo "FAIL qa fragments (tests/qa.sh is absent)"
    FAIL=1
fi
# compare.sh and conformance.sh are measurements and honesty checks rather
# than pass/fail suites, so they run near the end and their verdict line
# decides.  The speed and zapper comparisons live in measurements/ and are
# not part of this gate.
for suite in validate suite stress edge daemon daemon_neg options core audit store isolation lease secrets compare conformance regressions; do
    if [ ! -f "$suite.sh" ]; then
        echo "SKIP $suite (absent)"
        continue
    fi
    echo "################ $suite.sh"
    sh "$suite.sh" || FAIL=1
done
echo "################ FINAL: $([ $FAIL = 0 ] && echo ALL-PASS || echo FAILURES)"
exit $FAIL
