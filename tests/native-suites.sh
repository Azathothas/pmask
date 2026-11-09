#!/bin/sh
# Native suite runner for CI: run a named list of suites and fail when one
# is absent.
#
# `tests/run.sh` prints `SKIP <suite> (absent)` so the micro-VM, which
# stages only nine suites, can run the same orchestrator.  That SKIP is
# correct there and wrong in a native CI job: a suite that was deleted,
# renamed or never staged must fail the job rather than disappear from it.
# This script is the difference.  It is the name `run.sh` used to give an
# absent suite only when the caller asked for it explicitly.
#
# Usage:  sh tests/native-suites.sh SUITE...
#
# Each SUITE is `tests/<name>.sh`.  Binaries must already be in tests/;
# this script never builds, so a build failure is reported by the step
# that builds and not masked here.
set -u
cd "$(dirname "$0")" || exit 2

if [ "$#" -eq 0 ]; then
    echo "usage: sh tests/native-suites.sh SUITE..." >&2
    exit 2
fi

FAIL=0
RAN=0
MISSING=""
for suite in "$@"; do
    if [ ! -f "$suite.sh" ]; then
        echo "FAIL $suite (tests/$suite.sh is absent; a missing suite is a failure in this gate)"
        MISSING="$MISSING $suite"
        FAIL=1
        continue
    fi
    echo "################ $suite.sh"
    RAN=$((RAN + 1))
    sh "$suite.sh" || FAIL=1
done

if [ -n "$MISSING" ]; then
    echo "################ MISSING:$MISSING"
fi
echo "################ NATIVE: $([ "$FAIL" = 0 ] && echo ALL-PASS || echo FAILURES) ran=$RAN missing=$(printf '%s' "$MISSING" | wc -w | tr -d ' ')"
exit "$FAIL"
