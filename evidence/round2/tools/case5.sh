#!/bin/bash
# Case 5: --exec-once --on-exit wait with forkexec / /bin/echo ONE TWO.
source "$(dirname "$0")/lib.sh"
LOG="$EVID/r2-once.log"
: >"$LOG"
exec >>"$LOG" 2>&1

header "HOST"
uname -a; id

header "RUN A1/A2: exact command, no report support, with a status sampler"
for n in 1 2; do
  echo "-- A$n --"
  python3 "$EVID/tools/sample_status.py" r2-once 1.0 >"$EVID/.sampler$n.out" 2>&1 &
  sp=$!
  sleep 0.05
  out=$("$PMASK" -q -l r2-once --exec-once --on-exit wait -- "$TC" forkexec / /bin/echo ONE TWO 2>"$EVID/.once$n.err")
  rc=$?
  wait "$sp"
  echo "exit=$rc"
  echo "stdout_hex=$(printf %s "$out" | od -An -tx1 | tr -d ' \n')"
  echo "stdout=<<<$out>>>"
  echo "stderr=<<<$(cat "$EVID/.once$n.err")>>>"
  echo "sampler observations:"
  cat "$EVID/.sampler$n.out"
done

header "RUN B: exact command plus --secret/--report-file (report needs a secret side)"
"$PMASK" -q -l r2-once-b --exec-once --on-exit wait --secret S=literal:R2ONCE \
  --report-file "$EVID/r2-once.report.json" -- "$TC" forkexec / /bin/echo ONE TWO \
  >"$EVID/.once-b.out" 2>"$EVID/.once-b.err"
echo "exit=$?"
echo "stdout_hex=$(od -An -tx1 < "$EVID/.once-b.out" | tr -d ' \n')"
echo "stdout=<<<$(cat "$EVID/.once-b.out")>>>"
echo "stderr=<<<$(cat "$EVID/.once-b.err")>>>"
cat "$EVID/r2-once.report.json"

header "RUN C: same flags, long-lived child so the status line is certainly observable"
pgid=$(start_bg_raw r2-once-c -q -l r2-once-c --exec-once --on-exit wait -- "$TC" forkexec / /bin/sleep 2)
echo "started pgid=$pgid"
sleep 0.6
find_pids r2-once-c
for p in $(find_pids r2-once-c | awk '{print $1}'); do
  echo "-- status of label pid $p --"
  grep -E 'TracerPid|Seccomp_filters|NoNewPrivs|Uid' "/proc/$p/status"
  echo "exe=$(readlink /proc/$p/exe 2>&1) comm=$(cat /proc/$p/comm 2>&1) cmdline=$(tr '\0' '|' < /proc/$p/cmdline 2>&1)"
  python3 "$EVID/tools/procdump.py" "$p" "once-c-$p" | grep -E '^(###|cmdline.text|comm=|environ.open|environ.len|environ.keys|auxv.open|auxv.execfn|mem.open|exe.readlink|exe.open|maps.open|maps.lines|status\.|fd.open|fd.count|fd\|)'
done
stop_pgid "$pgid" r2-once-c
echo "STOP verified: $(find_pids r2-once-c | wc -l) label processes remain"

header "RESIDUE CHECK"
ps -eo pid,comm | grep -E 'r2-once|sleep 2' || echo "none"
