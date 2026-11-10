#!/bin/sh
# Baseline capture for issue 45 on qa-base + d2f331a.
# Every observer is a plain read of /proc; no pmask internals are trusted.
set -u
cd /workspace/wt/bteam5
PM=./tests/pmask
TC=./tests/testcases

echo "== host =="
uname -a
echo "uid=$(id -u) kernel=$(uname -r)"
echo

echo "== 1. secret family: --secret TOK=literal:XYZZY123 =="
env -i PATH=/usr/bin:/bin "$PM" -q --secret TOK=literal:XYZZY123 -- "$TC" secretfd TOK 6 >/tmp/b45-s.out 2>/tmp/b45-s.err &
SP=$!
sleep 0.9
PAY=$(pgrep -P "$SP" | head -n 1)
echo "supervisor=$SP payload=$PAY"
if [ -n "${PAY:-}" ]; then
    echo "-- fd links --"
    for f in "/proc/$PAY"/fd/*; do
        t=$(readlink "$f" 2>/dev/null) || continue
        echo "$f -> $t"
    done
    echo "-- count of links naming pmask-secret --"
    n=0
    for f in "/proc/$PAY"/fd/*; do
        case "$(readlink "$f" 2>/dev/null)" in *pmask-secret*) n=$((n+1));; esac
    done
    echo "pmask-secret-links=$n"
    echo "-- environ PMASK_SECRET_ lines --"
    tr '\0' '\n' < "/proc/$PAY/environ" 2>/dev/null | grep '^PMASK_SECRET_' || echo "(none readable)"
fi
echo "-- payload stdout --"
cat /tmp/b45-s.out 2>/dev/null
wait "$SP" 2>/dev/null
echo

echo "== 2. image family: --rexec -l sshd =="
env -i PATH=/usr/bin:/bin "$PM" -q --rexec -l sshd -- "$TC" sleeper >/dev/null 2>/tmp/b45-r.err &
RP=$!
sleep 0.9
PAY=$(pgrep -P "$RP" | head -n 1)
echo "supervisor=$RP payload=$PAY"
[ -n "${PAY:-}" ] && echo "exe=$(readlink "/proc/$PAY/exe" 2>/dev/null)"
[ -n "${PAY:-}" ] && echo "maps:" && grep memfd "/proc/$PAY/maps" 2>/dev/null | head -3
kill "$RP" 2>/dev/null
wait "$RP" 2>/dev/null
echo "stderr: $(head -2 /tmp/b45-r.err | tr '\n' '|')"
echo

echo "== 3. image family: --image PATH with no -l =="
env -i PATH=/usr/bin:/bin "$PM" -q --image "$TC" sleeper >/dev/null 2>/tmp/b45-i.err &
IP=$!
sleep 0.9
PAY=$(pgrep -P "$IP" | head -n 1)
echo "supervisor=$IP payload=$PAY"
[ -n "${PAY:-}" ] && echo "exe=$(readlink "/proc/$PAY/exe" 2>/dev/null)"
kill "$IP" 2>/dev/null
wait "$IP" 2>/dev/null
echo

echo "== 4. --exec-once: the carrier while the session runs =="
env -i PATH=/usr/bin:/bin "$PM" -q --rexec --exec-once -l eonce -- \
    /bin/sh -c 'i=0; while [ $i -lt 6 ]; do "$1" exe-id; i=$((i+1)); done; sleep 4' \
    sh ./tests/testcases >/tmp/b45-e.out 2>/tmp/b45-e.err &
EP=$!
sleep 2
echo "carriers under /dev/shm and /tmp:"
ls -la /dev/shm/.pmask-rexec-* /tmp/.pmask-rexec-* 2>/dev/null || echo "(none)"
echo "payload stdout:"
cat /tmp/b45-e.out 2>/dev/null
wait "$EP" 2>/dev/null
echo "carriers after the session:"
ls -la /dev/shm/.pmask-rexec-* /tmp/.pmask-rexec-* 2>/dev/null || echo "(none)"
echo

echo "== 5. supervisor's own secret buffer: --audit residue rows =="
env -i PATH=/usr/bin:/bin "$PM" --audit --secret TOK=literal:XYZZY123 -- "$TC" secretfd TOK 3 2>&1 | grep -E 'secretmem|memfd|residue' | head -12
echo

echo "== 6. host-wide sweep for the literal name =="
for l in /proc/[0-9]*/fd/*; do
    readlink "$l" 2>/dev/null | grep -q 'pmask-secret' && echo "$l"
done | head
echo "(sweep done)"
