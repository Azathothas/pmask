#!/bin/bash
# Case 8: secret source scrub. The literal from --secret must not be in the
# supervisor's memory at rest; the payload canary is the positive control.
source "$(dirname "$0")/lib.sh"
LOG="$EVID/r2-secret.log"
SECRET=CANARY_R2_SEC_LITERAL_3e57
CANARY=CANARY_R2_SEC_PAYLOAD_b82c
: >"$LOG"
exec >>"$LOG" 2>&1

run_secret() {
  local label="$1"
  header "MASKED RUN secret label=$label"
  local pgid; pgid=$(start_bg_raw "$label" -q -l "$label" \
      --secret "S=literal:$SECRET" -- "$TC" sleeper "$CANARY")
  echo "started pgid=$pgid"
  if ! wait_pids "$label"; then echo "SETTLE=FAIL"; find_pids "$label"; return; fi
  find_pids "$label"
  local sup pay; sup=$(supervisor_pid "$label"); pay=$(payload_pid "$label")
  echo "supervisor=$sup payload=$pay"
  echo "-- same-uid open shape: supervisor $sup --"
  python3 "$EVID/tools/procdump.py" "$sup" "sup-$label" | grep -E '^(###|cmdline.text|comm=|environ.open|auxv.open|mem.open|exe.readlink|exe.open|maps.open|fd.open|fd.count)'
  echo "-- same-uid open shape: payload $pay --"
  python3 "$EVID/tools/procdump.py" "$pay" "pay-$label" | grep -E '^(###|cmdline.text|comm=|environ.open|auxv.open|mem.open|exe.readlink|exe.open|maps.open|fd.open|fd.count)'
  echo "-- payload fd list --"
  sudo ls -l "/proc/$pay/fd"
  echo "-- ROOT scan of supervisor $sup for literal secret and payload canary --"
  sudo "$EVID/tools/scanmem" "$sup" "$SECRET" "$CANARY"
  echo "-- ROOT scan of payload $pay (positive control for the canary) --"
  sudo "$EVID/tools/scanmem" "$pay" "$SECRET" "$CANARY"
  stop_pgid "$pgid" "$label"
  echo "STOP verified: $(find_pids "$label" | wc -l) label processes remain"
}

run_control() {
  local n="$1"
  header "CONTROL RUN $n: plain sleeper holding BOTH strings in argv + env"
  setsid env R2_SECRET="$SECRET" "$TC" sleeper "$SECRET" "$CANARY" \
      >"$EVID/.secret-control$n.out" 2>&1 &
  local pid=$!; sleep 0.4
  echo "control pid=$pid"
  echo "cmdline=$(tr '\0' '|' < /proc/$pid/cmdline)"
  echo "-- ROOT scan of the plain process (scanner positive control) --"
  sudo "$EVID/tools/scanmem" "$pid" "$SECRET" "$CANARY"
  kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

run_secret r2-sec
run_secret r2-sec-b
run_control 1
run_control 2

header "RESIDUE CHECK"
ps -eo pid,comm | grep -E 'r2-sec|pmask-testcases' || echo "none"
