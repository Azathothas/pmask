#!/bin/sh
# Issue 47 end-state reproducer, one section per shape.  POSIX sh.
# Run from the worktree root: sh evidence/bteam2/47/repro-47.sh
set -u
PM=${PM:-./target/release/pmask}
echo "pmask=$PM kernel=$(uname -r) uid=$(id -u)"

wait_child() { # SUP SECONDS -> first child pid
    wc_i=0
    while [ "$wc_i" -lt 60 ]; do
        for d in /proc/[0-9]*; do
            p=${d#/proc/}
            pp=$(sed -n 's/^PPid:[[:space:]]*\([0-9]*\).*/\1/p' "$d/status" 2>/dev/null)
            [ "$pp" = "$1" ] && { echo "$p"; return 0; }
        done
        sleep 0.05 2>/dev/null || sleep 1
        wc_i=$((wc_i + 1))
    done
    return 1
}

echo "================ --detach end state"
env -i PATH=/usr/bin:/bin "$PM" -q --detach -l b2-47-detach -- /bin/sleep 5 2>/tmp/b2-47-detach.err &
sup=$!
sleep 0.8
pay=$(wait_child "$sup")
echo "payload=$pay"
echo "cmdline: $(tr '\0' '|' < "/proc/$pay/cmdline")"
awk '/^TracerPid:/{print}' "/proc/$pay/status"
echo "comm: $(cat "/proc/$pay/comm")"
echo "environ bytes: $(wc -c < "/proc/$pay/environ")"
echo "stderr while running: $(cat /tmp/b2-47-detach.err)"
wait "$sup"
echo "exit=$?"
echo "stderr after exit:"; cat /tmp/b2-47-detach.err

echo "================ --no-follow"
env -i PATH=/usr/bin:/bin "$PM" -q -l b2-47-nofollow --no-follow -- /bin/sh -c '/bin/sleep 5 & wait' 2>/tmp/b2-47-nf.err &
sup=$!
sleep 1
for d in /proc/[0-9]*; do
    c=$(cat "$d/comm" 2>/dev/null) || continue
    case "$c" in
        b2-47-nofollow|sleep)
            echo "pid=${d#/proc/} comm=$c cmdline=$(tr '\0' '|' < "$d/cmdline") tracer=$(awk '/^TracerPid:/{print $2}' "$d/status")"
            ;;
    esac
done
kill "$sup" 2>/dev/null
wait "$sup" 2>/dev/null
echo "stderr:"; cat /tmp/b2-47-nf.err

echo "================ --on-exit detach (orphan)"
env -i PATH=/usr/bin:/bin "$PM" -q -l b2-47-orphan --on-exit detach -- /bin/sh -c '/bin/sleep 6 & exit 0'
echo "supervisor exit=$?"
sleep 0.5
for d in /proc/[0-9]*; do
    c=$(cat "$d/comm" 2>/dev/null) || continue
    [ "$c" = b2-47-orphan ] || continue
    echo "orphan pid=${d#/proc/} ppid=$(sed -n 's/^PPid:[[:space:]]*\([0-9]*\).*/\1/p' "$d/status") cmdline=$(tr '\0' '|' < "$d/cmdline") tracer=$(awk '/^TracerPid:/{print $2}' "$d/status")"
    kill -9 "${d#/proc/}" 2>/dev/null
done

echo "================ --on-exit kill (control)"
env -i PATH=/usr/bin:/bin "$PM" -q -l b2-47-kill --on-exit kill -- /bin/sh -c '/bin/sleep 6 & exit 0'
echo "supervisor exit=$?"
sleep 0.5
n=0
for d in /proc/[0-9]*; do
    c=$(cat "$d/comm" 2>/dev/null) || continue
    [ "$c" = b2-47-kill ] && n=$((n + 1))
done
echo "survivors=$n"

echo "================ default exit-kill: SIGKILL the supervisor"
env -i PATH=/usr/bin:/bin "$PM" -q -l b2-47-exitkill -- /bin/sleep 6 &
sup=$!
sleep 0.8
pay=$(wait_child "$sup")
echo "payload=$pay before kill"
kill -9 "$sup"
wait "$sup" 2>/dev/null
sleep 0.5
if [ -d "/proc/$pay" ]; then echo "payload ALIVE after supervisor SIGKILL"; kill -9 "$pay" 2>/dev/null; else echo "payload gone after supervisor SIGKILL"; fi

echo "================ --no-exit-kill: SIGKILL the supervisor"
env -i PATH=/usr/bin:/bin "$PM" -q --no-exit-kill -l b2-47-survive -- /bin/sleep 6 &
sup=$!
sleep 0.8
pay=$(wait_child "$sup")
echo "payload=$pay before kill"
kill -9 "$sup"
wait "$sup" 2>/dev/null
sleep 0.5
if [ -d "/proc/$pay" ]; then
    echo "payload ALIVE after supervisor SIGKILL; tracer=$(awk '/^TracerPid:/{print $2}' "/proc/$pay/status") cmdline=$(tr '\0' '|' < "/proc/$pay/cmdline")"
    kill -9 "$pay" 2>/dev/null
else
    echo "payload gone"
fi
exit 0
