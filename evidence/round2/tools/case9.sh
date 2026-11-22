#!/bin/bash
# Case 9: --report-file on the default redaction path.
source "$(dirname "$0")/lib.sh"
LOG="$EVID/r2-report.log"
: >"$LOG"
exec >>"$LOG" 2>&1

run_report() {
  local label="$1" rep="$EVID/r2-report.$1.json"
  header "MASKED RUN report-file label=$label"
  local pgid; pgid=$(start_bg_raw "$label" -q -l "$label" \
      --secret S=literal:CANARY_R2_REPORT_1f9c --report-file "$rep" \
      -- "$TC" sleeper CANARY_R2_REPORT_PAYLOAD_7a2e)
  echo "started pgid=$pgid"
  if ! wait_pids "$label"; then echo "SETTLE=FAIL"; find_pids "$label"; return; fi
  local pay; pay=$(payload_pid "$label")
  echo "payload=$pay cmdline=$(tr '\0' '|' < /proc/$pay/cmdline) comm=$(cat /proc/$pay/comm)"
  echo "-- same-uid dump of payload $pay --"
  python3 "$EVID/tools/procdump.py" "$pay" "payload-$label" | grep -vE '^maps\| '
  echo "-- same-uid memory scan of payload $pay for the payload canary --"
  "$EVID/tools/scanmem" "$pay" CANARY_R2_REPORT_PAYLOAD_7a2e
  sudo kill -9 "$pay" 2>/dev/null
  for i in $(seq 1 50); do [ -s "$rep" ] && break; sleep 0.1; done
  echo "report.path=$rep"
  cat "$rep" 2>&1
  stop_pgid "$pgid" "$label"
  echo "STOP verified: $(find_pids "$label" | wc -l) label processes remain"
}

run_report r2-rep
run_report r2-rep-b

header "RESIDUE CHECK"
ps -eo pid,comm | grep -E 'r2-rep' || echo "none"
