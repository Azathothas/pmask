#!/bin/sh
# QA fragment dispatcher.
#
# Each tests/qa.d/<issue>.sh case runs in its own shell, so one failure
# cannot poison another. A fragment prints PASS/FAIL/SKIP lines and exits
# nonzero when a case fails. Empty fragments are a SKIP, never a pass.
set -u
cd "$(dirname "$0")"

FAIL=0
N=0
for c in qa.d/*.sh; do
    [ -f "$c" ] || continue
    N=$((N + 1))
    echo "################ qa: $c"
    sh "$c" || FAIL=1
done

if [ "$N" = 0 ]; then
    echo "SKIP qa (no fragments)"
    exit 0
fi
echo "################ QA: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL) cases=$N"
exit "$FAIL"