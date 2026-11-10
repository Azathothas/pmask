#!/bin/sh
# The negative control for tests/qa.d/38.sh: the *same* /proc observer,
# run against a binary built from the pre-fix `src/mask.rs`, must FIND the
# retired name.  Without this, "0 sightings" after the fix could mean a
# blind observer rather than a removed fingerprint.
#
# Build the pre-fix binary in a scratch copy of the worktree:
#   git show d2f331a:src/mask.rs > src/mask.rs && cargo build --release --bin pmask
#
#   sh evidence/bteam2/38/negative-control-old-binary.sh OLD_BINARY
set -u
PM=${1:?usage: $0 /path/to/pre-fix/pmask}
LABEL="neg38-$$"
echo "pmask=$PM kernel=$(uname -r) uid=$(id -u)"
env -i PATH=/usr/bin:/bin "$PM" -q -l "$LABEL" -- /bin/sleep 4 &
sup=$!
sleep 0.8
pay=$(pgrep -P "$sup" | head -n 1)
tid=$(awk '/^TracerPid:/{print $2}' "/proc/$pay/status" 2>/dev/null)
echo "payload=$pay tracer_tid=$tid"
echo "tracer comm=[$(cat "/proc/$tid/comm" 2>/dev/null)]"
n=0
for t in /proc/[0-9]*/task/*/comm; do
    [ "$(cat "$t" 2>/dev/null)" = pmask-tracer ] && n=$((n + 1))
done
echo "retired_name_sightings=$n"
kill -9 "$sup" 2>/dev/null
wait "$sup" 2>/dev/null
if [ "$n" -ge 1 ]; then
    echo "NEGATIVE-CONTROL: PASS (the observer sees the old name)"
    exit 0
fi
echo "NEGATIVE-CONTROL: FAIL (the observer is blind; the q38 cases prove nothing)"
exit 1
