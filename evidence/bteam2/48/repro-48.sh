#!/bin/sh
# Issue 48 reproducer: the statistical channels, in one run of the harness.
# POSIX sh.  Run from the worktree root:
#   sh evidence/bteam2/48/repro-48.sh
#
# The numbers are this host's, produced by measurements/launch-window.sh.
# The full-length run is evidence/bteam2/48/launch-window.log; this wrapper
# runs the same harness at gate size so the file is cheap to regenerate.
set -u
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT" || exit 2
echo "pmask=$(ls -l target/release/pmask 2>/dev/null | wc -l) kernel=$(uname -r) uid=$(id -u)"
WINDOW_ROUNDS=${WINDOW_ROUNDS:-1} WINDOW_N=${WINDOW_N:-20} \
    WINDOW_SUSTAINED_SECS=${WINDOW_SUSTAINED_SECS:-2} \
    sh measurements/launch-window.sh
