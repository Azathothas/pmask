#!/bin/bash
# Case 1: default redaction surface, with a no-pmask control run twice.
source "$(dirname "$0")/lib.sh"
LOG="$EVID/r2-def.log"
CANARY=CANARY_R2_DEF_7f3a
: >"$LOG"
exec >>"$LOG" 2>&1

run_masked() {
  local label="$1"
  header "MASKED RUN label=$label"
  local pgid; pgid=$(start_bg "$label" -- "$TC" sleeper "$CANARY")
  echo "started pmask pgid=$pgid"
  if ! wait_pids "$label"; then echo "SETTLE=FAIL"; find_pids "$label"; return; fi
  find_pids "$label"
  local sup pay; sup=$(supervisor_pid "$label"); pay=$(payload_pid "$label")
  echo "supervisor=$sup payload=$pay"
  echo "-- same-uid (uid 1000) dump of payload $pay --"
  python3 "$EVID/tools/procdump.py" "$pay" "sameuid-$label"
  echo "-- root dump of payload $pay (for AT_EXECFN through /proc/pid/mem) --"
  sudo python3 "$EVID/tools/procdump.py" "$pay" "root-$label"
  echo "-- same-uid memory scan of payload $pay for the canary --"
  "$EVID/tools/scanmem" "$pay" "$CANARY"
  echo "-- root memory scan of supervisor $sup for the canary --"
  sudo "$EVID/tools/scanmem" "$sup" "$CANARY"
  echo "-- same-uid dump of supervisor $sup --"
  python3 "$EVID/tools/procdump.py" "$sup" "sup-$label"
  stop_pgid "$pgid" "$label"
  echo "STOP verified: $(find_pids "$label" | wc -l) label processes remain"
}

run_control() {
  local n="$1"
  header "CONTROL RUN $n (no pmask)"
  setsid env R2_ENV_CANARY="$CANARY" "$TC" sleeper "$CANARY" \
    >"$EVID/.control$n.out" 2>&1 &
  local pid=$!
  sleep 0.5
  echo "control pid=$pid"
  echo "-- same-uid dump --"
  python3 "$EVID/tools/procdump.py" "$pid" "control$n"
  echo "-- root dump of auxv AT_EXECFN --"
  sudo python3 "$EVID/tools/procdump.py" "$pid" "root-control$n" | grep -E 'auxv|cmdline.text|comm|environ.len|exe.readlink'
  kill -9 "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
}

header "HOST"
uname -a
id
grep -E ' /proc ' /proc/mounts

run_masked r2-def
run_masked r2-def-b
run_control 1
run_control 2

header "RESIDUE CHECK"
ps -eo pid,comm | grep -E 'r2-def|pmask-testcases' || echo "none"
