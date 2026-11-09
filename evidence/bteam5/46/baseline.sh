#!/bin/sh
# Issue 46 baseline: the seccomp filter count, NoNewPrivs and comm for
# --watch-rename against the same payload without the flag, a plain
# process, and the supervisor.
set -u
cd /workspace/wt/bteam5
PM=./tests/pmask
TC=./tests/testcases

row() {  # row LABEL STATUSFILE
    f=$2
    printf '%-22s Seccomp=%s Seccomp_filters=%s NoNewPrivs=%s Name=%s TracerPid=%s Tgid=%s Pid=%s\n' \
        "$1" \
        "$(sed -n 's/^Seccomp:[[:space:]]*//p' "$f" 2>/dev/null)" \
        "$(sed -n 's/^Seccomp_filters:[[:space:]]*//p' "$f" 2>/dev/null)" \
        "$(sed -n 's/^NoNewPrivs:[[:space:]]*//p' "$f" 2>/dev/null)" \
        "$(sed -n 's/^Name:[[:space:]]*//p' "$f" 2>/dev/null)" \
        "$(sed -n 's/^TracerPid:[[:space:]]*//p' "$f" 2>/dev/null)" \
        "$(sed -n 's/^Tgid:[[:space:]]*//p' "$f" 2>/dev/null)" \
        "$(sed -n 's/^Pid:[[:space:]]*//p' "$f" 2>/dev/null)"
}

echo "== host =="
uname -r
echo "uid=$(id -u)"
echo

echo "== 1. --watch-rename -l proc-evid -- testcases renamer =="
"$PM" -q -l proc-evid --watch-rename "$TC" renamer >/tmp/b46-w.out 2>/tmp/b46-w.err &
W=$!
sleep 0.9
PAY=$(pgrep -P "$W" | head -n 1)
echo "supervisor=$W payload=$PAY"
row "with --watch-rename" "/proc/$PAY/status"
echo "renamer reported: $(sed -n 's/^renamer-comm=//p' /tmp/b46-w.out)"
kill "$W" 2>/dev/null; wait "$W" 2>/dev/null
echo "stderr: $(head -2 /tmp/b46-w.err | tr '\n' '|')"
echo

echo "== 2. control: the same payload without --watch-rename =="
"$PM" -q -l proc-evid "$TC" renamer >/tmp/b46-c.out 2>/tmp/b46-c.err &
C=$!
sleep 0.9
PAY=$(pgrep -P "$C" | head -n 1)
echo "supervisor=$C payload=$PAY"
row "without the flag" "/proc/$PAY/status"
echo "renamer reported: $(sed -n 's/^renamer-comm=//p' /tmp/b46-c.out)"
kill "$C" 2>/dev/null; wait "$C" 2>/dev/null
echo

echo "== 3. plain /bin/sleep 5 =="
/bin/sleep 5 &
P=$!
sleep 0.3
row "plain sleep" "/proc/$P/status"
kill "$P" 2>/dev/null; wait "$P" 2>/dev/null
echo

echo "== 4. supervisor row (the pmask process itself) =="
"$PM" -q -l proc-evid --watch-rename "$TC" sleeper >/dev/null 2>&1 &
W=$!
sleep 0.9
row "supervisor" "/proc/$W/status"
PAY=$(pgrep -P "$W" | head -n 1)
row "payload of that run" "/proc/$PAY/status"
kill "$W" 2>/dev/null; wait "$W" 2>/dev/null
echo

echo "== 5. the flag-specific pair, repeated three times =="
for i in 1 2 3; do
    "$PM" -q -l proc-evid --watch-rename "$TC" sleeper >/dev/null 2>&1 &
    W=$!
    sleep 0.7
    PAY=$(pgrep -P "$W" | head -n 1)
    printf 'run %s: ' "$i"
    sed -n -e 's/^Seccomp_filters:[[:space:]]*/filters=/p' \
           -e 's/^NoNewPrivs:[[:space:]]*/nnp=/p' \
           -e 's/^Name:[[:space:]]*/comm=/p' "/proc/$PAY/status" 2>/dev/null | tr '\n' ' '
    echo
    kill "$W" 2>/dev/null; wait "$W" 2>/dev/null
done
echo

echo "== 6. --no-new-privs alone (one filter, NNP=1) =="
"$PM" -q -l proc-evid --no-new-privs "$TC" sleeper >/dev/null 2>&1 &
W=$!
sleep 0.7
PAY=$(pgrep -P "$W" | head -n 1)
row "--no-new-privs" "/proc/$PAY/status"
kill "$W" 2>/dev/null; wait "$W" 2>/dev/null
echo

echo "== 7. --watch-rename --no-dumpable (defect #60) =="
"$PM" -q -l proc-evid --watch-rename --no-dumpable "$TC" renamer >/tmp/b46-nd.out 2>/tmp/b46-nd.err &
W=$!
sleep 1.0
PAY=$(pgrep -P "$W" | head -n 1)
echo "supervisor=$W payload=$PAY"
row "watch+nodumpable" "/proc/$PAY/status"
echo "renamer reported: $(sed -n 's/^renamer-comm=//p' /tmp/b46-nd.out)"
kill "$W" 2>/dev/null; wait "$W" 2>/dev/null
echo "stderr:"
sed -n '1,6p' /tmp/b46-nd.err
