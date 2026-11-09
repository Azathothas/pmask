#!/bin/sh
# QA fragment dispatcher.
#
# Each tests/qa.d/<issue>.sh case runs in its own shell, so one failure
# cannot poison another. A fragment prints PASS/FAIL/SKIP lines and exits
# nonzero when a case fails. Empty fragments are a SKIP, never a pass.
#
# A fragment that starts a payload in a mode that does not redact it (plain
# mode has no label to kill by) can leave that payload behind when it only
# kills the supervisor.  A leftover `testcases` process with a real argv
# then makes the /proc sweep in tests/edge.sh and in the secret-name
# fragment fail on the next run, which is a false finding attributed to a
# different case.  Every fragment is therefore followed by a scoped sweep:
# a `testcases` process of this tree that was not running before the
# fragment started, and is still running after it returned, is killed here.
# The scope is this checkout's own path, so a parallel worktree is never
# touched.
set -u
cd "$(dirname "$0")"

TESTS_DIR=$(pwd)
FAIL=0
N=0

# live_tree_procs: pids whose argv names this tree's testcases binary.
live_tree_procs() {
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ "$p" = "$$" ] && continue
        case "$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)" in
            *"$TESTS_DIR/testcases"*) echo "$p" ;;
        esac
    done
}

# reap_new_since BEFORE_PIDS
reap_new_since() {
    keep=" $1 "
    for p in $(live_tree_procs); do
        case "$keep" in
            *" $p "*) continue ;;
        esac
        # A payload that outlived its supervisor is reparented to init; a
        # live one still under a fragment's shell is the fragment's to
        # reap, and killing it after the fragment returned is the same
        # cleanup the fragment owed.
        kill -9 "$p" 2>/dev/null
    done
}

for c in qa.d/*.sh; do
    [ -f "$c" ] || continue
    N=$((N + 1))
    before=$(live_tree_procs | tr '\n' ' ')
    echo "################ qa: $c"
    sh "$c" || FAIL=1
    reap_new_since "$before"
done

if [ "$N" = 0 ]; then
    echo "SKIP qa (no fragments)"
    exit 0
fi
echo "################ QA: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL) cases=$N"
exit "$FAIL"
