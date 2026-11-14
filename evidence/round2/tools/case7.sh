#!/bin/bash
# Case 7: --hide-pid under a private /proc with hidepid=invisible and
# hidepid=ptraceable. The measurement runs inside the namespace.
source "$(dirname "$0")/lib.sh"
LOG="$EVID/r2-hidepid.log"
: >"$LOG"
exec >>"$LOG" 2>&1

header "HOST /proc policy (outside the namespace)"
grep ' /proc ' /proc/mounts
cat /proc/sys/kernel/yama/ptrace_scope

for round in 1 2; do
  for mode in invisible ptraceable; do
    header "NAMESPACE RUN round=$round hidepid=$mode"
    sudo TMPDIR=/tmp unshare -m -p --fork --mount-proc \
      bash "$EVID/tools/case7_inner.sh" "$mode" "$LOG"
    echo "unshare_exit=$?"
    echo "-- host-side residue for the round --"
    ps -eo pid,ppid,user,comm | grep -E 'r2-hid' || echo none
  done
done

header "RESIDUE CHECK"
ps -eo pid,ppid,user,comm | grep -E 'r2-hid|pmask-testcases' || echo "none"
