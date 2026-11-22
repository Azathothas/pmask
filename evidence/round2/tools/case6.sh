#!/bin/bash
# Case 6: --watch-rename. comm before/after a payload self-rename; seccomp count.
source "$(dirname "$0")/lib.sh"
LOG="$EVID/r2-rename.log"
CANARY=CANARY_R2_RENAME_d4a1
: >"$LOG"
exec >>"$LOG" 2>&1

run_rename() {
  local label="$1"
  header "MASKED RUN --watch-rename label=$label"
  local pgid; pgid=$(start_bg "$label" --watch-rename -- "$TC" renamer "$CANARY")
  echo "started pgid=$pgid"
  if ! wait_pids "$label"; then echo "SETTLE=FAIL"; find_pids "$label"; return; fi
  find_pids "$label"
  local pay; pay=$(payload_pid "$label")
  echo "comm@0.2s=$(cat /proc/$pay/comm 2>&1)"
  sleep 1.5
  echo "comm@1.7s=$(cat /proc/$pay/comm 2>&1)"
  echo "-- status of payload $pay --"
  grep -E 'TracerPid|Seccomp_filters|NoNewPrivs' "/proc/$pay/status"
  echo "-- same-uid dump of payload $pay --"
  python3 "$EVID/tools/procdump.py" "$pay" "payload-$label" | grep -vE '^maps\| '
  echo "-- same-uid memory scan of payload $pay for the canary --"
  "$EVID/tools/scanmem" "$pay" "$CANARY"
  echo "-- captured payload output --"
  cat "$EVID/.$label.out"
  stop_pgid "$pgid" "$label"
  echo "STOP verified: $(find_pids "$label" | wc -l) label processes remain"
}

run_control() {
  local n="$1"
  header "CONTROL RUN $n (no pmask): renamer changes comm to other"
  setsid "$TC" renamer >"$EVID/.rename-control$n.out" 2>&1 &
  local pid=$!
  sleep 0.2; echo "comm@0.2s=$(cat /proc/$pid/comm 2>&1)"
  sleep 1.5; echo "comm@1.7s=$(cat /proc/$pid/comm 2>&1)"
  echo "-- status of the plain process --"
  grep -E 'Seccomp_filters|NoNewPrivs' "/proc/$pid/status"
  echo "-- payload output --"; cat "$EVID/.rename-control$n.out"
  kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

run_rename r2-rename
run_rename r2-rename-b
run_control 1
run_control 2

header "RESIDUE CHECK"
ps -eo pid,comm | grep -E 'r2-rename' || echo "none"
