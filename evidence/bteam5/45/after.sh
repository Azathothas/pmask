#!/bin/sh
# Post-fix capture for issue 45: the same observations as baseline.sh,
# with the two name options in play.
set -u
cd /workspace/wt/bteam5
PM=./tests/pmask
TC=./tests/testcases

echo "== host =="
uname -a
echo "uid=$(id -u)"
echo "build=$(./tests/pmask -V)"
echo

echo "== 1. default secret name is unchanged =="
env -i PATH=/usr/bin:/bin "$PM" -q --secret TOK=literal:XYZZY123 -- "$TC" secretfd TOK 0 2>/dev/null
echo

echo "== 2. --secret-fd-name secret-deadbeef =="
env -i PATH=/usr/bin:/bin "$PM" -q --secret TOK=literal:XYZZY123 \
    --secret-fd-name secret-deadbeef -- "$TC" secretfd TOK 0 2>/dev/null
echo

echo "== 3. live descriptor link, default and named, plus the sweep =="
env -i PATH=/usr/bin:/bin "$PM" -q -l e45 --secret TOK=literal:XYZZY123 -- "$TC" secretfd TOK 6 >/tmp/a45-def.out 2>/dev/null &
SP=$!
sleep 0.9
PAY=$(pgrep -P "$SP" | head -n 1)
echo "default: supervisor=$SP payload=$PAY"
if [ -n "${PAY:-}" ]; then
    for f in "/proc/$PAY"/fd/*; do
        t=$(readlink "$f" 2>/dev/null) || continue
        echo "$f -> $t"
    done
    echo -n "sweep for pmask-secret while alive: "
    n=0
    for l in /proc/[0-9]*/fd/*; do
        readlink "$l" 2>/dev/null | grep -q 'pmask-secret' && n=$((n+1))
    done
    echo "$n link(s)"
fi
wait "$SP" 2>/dev/null
env -i PATH=/usr/bin:/bin "$PM" -q -l e45 --secret TOK=literal:XYZZY123 \
    --secret-fd-name secret-deadbeef -- "$TC" secretfd TOK 6 >/tmp/a45-nam.out 2>/dev/null &
SP=$!
sleep 0.9
PAY=$(pgrep -P "$SP" | head -n 1)
echo "named: supervisor=$SP payload=$PAY"
if [ -n "${PAY:-}" ]; then
    for f in "/proc/$PAY"/fd/*; do
        t=$(readlink "$f" 2>/dev/null) || continue
        echo "$f -> $t"
    done
    echo -n "sweep for pmask-secret while alive: "
    n=0
    for l in /proc/[0-9]*/fd/*; do
        readlink "$l" 2>/dev/null | grep -q 'pmask-secret' && n=$((n+1))
    done
    echo "$n link(s)"
fi
wait "$SP" 2>/dev/null
echo

echo "== 4. image family, default and named =="
for mode in default named; do
    if [ "$mode" = named ]; then
        env -i PATH=/usr/bin:/bin "$PM" -q --rexec -l sshd --memfd-name image-1a2b3c4d \
            -- "$TC" sleeper >/dev/null 2>/dev/null &
    else
        env -i PATH=/usr/bin:/bin "$PM" -q --rexec -l sshd -- "$TC" sleeper >/dev/null 2>/dev/null &
    fi
    RP=$!
    sleep 0.9
    PAY=$(pgrep -P "$RP" | head -n 1)
    echo "$mode: exe=$(readlink "/proc/$PAY/exe" 2>/dev/null)"
    echo "  maps:"
    grep memfd "/proc/$PAY/maps" 2>/dev/null | head -2 | sed 's/^/    /'
    kill "$RP" 2>/dev/null
    wait "$RP" 2>/dev/null
done
echo

echo "== 5. --image PATH with --memfd-name =="
env -i PATH=/usr/bin:/bin "$PM" -q --image "$TC" --memfd-name blobs-9f8e7d6c -- sleeper >/dev/null 2>/dev/null &
IP=$!
sleep 0.9
PAY=$(pgrep -P "$IP" | head -n 1)
echo "exe=$(readlink "/proc/$PAY/exe" 2>/dev/null)"
kill "$IP" 2>/dev/null
wait "$IP" 2>/dev/null
echo

echo "== 6. --exec-once carrier tag =="
PMASK_FAULT_REXEC_NO_PROC=1 env -i PATH=/usr/bin:/bin "$PM" -q --label eonce \
    --memfd-name img-deadbeef --rexec "$TC" exe-id 2>&1
echo

echo "== 7. name validation =="
for bad in "" "a/b" "$(printf 'a\nb')" "$(printf 'a\rb')"; do
    err=$(env -i PATH=/usr/bin:/bin "$PM" -q --secret T=literal:x --secret-fd-name "$bad" -- true 2>&1 >/dev/null)
    echo "name=[$bad] rc=$? err=[$err]"
done
long200=$(printf '%0200d' 0 | tr '0' 'n')
long201="$long200"n
err=$(env -i PATH=/usr/bin:/bin "$PM" -q --secret T=literal:x --secret-fd-name "$long201" -- true 2>&1 >/dev/null)
echo "201-byte name rc=$? err=[$err]"
out=$(env -i PATH=/usr/bin:/bin "$PM" -q --secret T=literal:x --secret-fd-name "$long200" -- "$TC" secretfd T 0 2>/dev/null)
echo "200-byte name path=$(printf '%s\n' "$out" | sed -n 's/^path=//p' | cut -c1-40)..."
echo

echo "== 8. unix-socket exception: names cannot reach /secretmem =="
echo "the supervisor's memfd_secret name is the kernel's '/secretmem';"
echo "neither option changes it.  Confirmed by the audit row below."
env -i PATH=/usr/bin:/bin "$PM" --audit --secret TOK=literal:XYZZY123 -- "$TC" secretfd TOK 1 2>&1 \
    | grep -E 'secretmem|residue' | head -4
