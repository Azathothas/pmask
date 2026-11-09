#!/bin/sh
# Issue 38 reproducer: the tracer thread's name and the TracerPid shape.
# POSIX sh.  Run from the worktree root: sh evidence/bteam2/38/repro-38.sh
set -u
PM=${PM:-./target/release/pmask}
LABEL=${LABEL:-b2-38-proc-evid}
echo "pmask=$PM"
echo "kernel=$(uname -r) uid=$(id -u)"

env -i PATH=/usr/bin:/bin "$PM" -q -l "$LABEL" -- /bin/sleep 8 &
sup=$!
sleep 0.8
pay=$(pgrep -P "$sup" | head -n 1)
echo "supervisor=$sup payload=$pay"
if [ -z "$pay" ]; then
    echo "FAIL no payload under supervisor $sup"
    kill "$sup" 2>/dev/null
    exit 1
fi
echo "--- payload status (TracerPid)"
awk '/^TracerPid:/{print}' "/proc/$pay/status"
tid=$(awk '/^TracerPid:/{print $2}' "/proc/$pay/status")
echo "tracer_tid=$tid"
echo "--- tracer status (Name/Tgid/Pid)"
grep -E '^(Name|Tgid|Pid):' "/proc/$tid/status"
echo "--- tracer comm"
cat "/proc/$tid/comm"
echo "--- tracer task dirs of supervisor"
for t in "/proc/$sup"/task/*; do
    echo "$(basename "$t") $(cat "$t/comm" 2>/dev/null)"
done
echo "--- sweep for the fixed name, whole host and this session"
# The host-wide count is printed but not asserted: another agent's
# unreleased build running on the same machine is a different session.
# Each host-wide sighting is attributed so a reader can tell them apart.
host=0
ses=0
for t in /proc/[0-9]*/task/*/comm; do
    [ "$(cat "$t" 2>/dev/null)" = pmask-tracer ] || continue
    tgid=$(basename "$(dirname "$(dirname "$(dirname "$t")")")")
    tid=$(basename "$(dirname "$t")")
    host=$((host + 1))
    if [ "$tgid" = "$sup" ] || [ "$tgid" = "$pay" ]; then
        ses=$((ses + 1))
        echo "IN-SESSION supervisor: $tgid tid: $tid"
    else
        echo "OTHER-RUN supervisor: $tgid tid: $tid cmd: $(tr '\0' ' ' < "/proc/$tgid/cmdline" 2>/dev/null | cut -c1-40)"
    fi
done
echo "pmask-tracer sightings: in-session=$ses host-wide=$host"
echo "--- payload comm/cmdline"
tr '\0' '|' < "/proc/$pay/cmdline"; echo
cat "/proc/$pay/comm"
kill "$sup" 2>/dev/null
wait "$sup" 2>/dev/null
exit 0
