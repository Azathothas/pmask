#!/bin/sh
# Issue 38, second call-order check: the runner path (`--secret`) calls
# `Mask::spawn` before the self-mask, so the tracer thread's fallback must
# use the session's comm rather than the live pre-mask one.
#
#   sh evidence/bteam2/38/repro-runner.sh
set -u
PM=${PM:-./target/release/pmask}
TC=${TESTBIN:-./tests/testcases}
TOK="${TMPDIR:-/tmp}/b2-38.tok.$$"
printf 'token\n' >"$TOK"
chmod 600 "$TOK"
trap 'rm -f "$TOK"' EXIT INT TERM
echo "pmask=$PM kernel=$(uname -r) uid=$(id -u)"

show() { # SUP LABEL-DESC
    echo "--- $2 (supervisor $1)"
    for t in "/proc/$1"/task/*; do
        [ -d "$t" ] || continue
        echo "  task $(basename "$t") comm=[$(cat "$t/comm" 2>/dev/null)]"
    done
}

run() { # FLAGS DESC
    r_flags="$1"; r_desc="$2"
    # shellcheck disable=SC2086
    env -i PATH=/usr/bin:/bin "$PM" -q $r_flags --secret "T=file:$TOK" \
        -- "$TC" sleeper >/dev/null 2>&1 &
    r_sup=$!
    sleep 1
    show "$r_sup" "$r_desc"
    kill -9 "$r_sup" 2>/dev/null
    wait "$r_sup" 2>/dev/null
    echo
}

run "-l b2-runner-label" "runner, plain label"
run "--label-empty" "runner, empty label (the fallback case)"
run "-l pmask-tracer" "runner, retired-name label"

echo "--- CLI path for comparison (spawn after the self-mask)"
env -i PATH=/usr/bin:/bin "$PM" -q --label-empty -- "$TC" sleeper >/dev/null 2>&1 &
S=$!
sleep 1
show "$S" "CLI, empty label"
kill -9 "$S" 2>/dev/null
wait "$S" 2>/dev/null

echo "--- retired-name sightings in this run"
n=0
for t in /proc/[0-9]*/task/*/comm; do
    [ "$(cat "$t" 2>/dev/null)" = pmask-tracer ] && n=$((n + 1))
done
echo "pmask-tracer sightings host-wide: $n (a neighbour run may account for one)"
exit 0
