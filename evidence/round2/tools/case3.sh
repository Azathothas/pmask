#!/bin/bash
# Case 3: --stealth on this hidepid=0 host. renamer payload.
source "$(dirname "$0")/lib.sh"
LOG="$EVID/r2-stealth.log"
CANARY=CANARY_R2_STEALTH_91be
: >"$LOG"
exec >>"$LOG" 2>&1

run_stealth() {
  local label="$1"
  header "MASKED RUN --stealth label=$label (no -q, to capture the trade line)"
  local pgid; pgid=$(start_bg_raw "$label" --stealth -l "$label" -- "$TC" renamer "$CANARY")
  echo "started pmask pgid=$pgid"
  sleep 0.6
  find_pids "$label"
  local sup pay; sup=$(supervisor_pid "$label"); pay=$(payload_pid "$label")
  echo "supervisor=$sup payload=$pay"
  echo "-- comm samples around the payload's self-rename --"
  echo "comm@0.6s=$(cat /proc/$pay/comm 2>&1)"
  sleep 1.2
  echo "comm@1.8s=$(cat /proc/$pay/comm 2>&1)"
  echo "-- same-uid dump of payload $pay --"
  python3 "$EVID/tools/procdump.py" "$pay" "sameuid-$label"
  echo "-- root dump of payload $pay (AT_EXECFN) --"
  sudo python3 "$EVID/tools/procdump.py" "$pay" "root-$label" | grep -E '^(###|cmdline|comm=|environ|auxv|mem.open|exe|maps.lines|maps\|.*memfd|status\.|fd.open|fd.count)'
  echo "-- stderr/stdout captured from the run so far (trade line, renamer print) --"
  cat "$EVID/.$label.out"
  stop_pgid "$pgid" "$label"
  echo "STOP verified: $(find_pids "$label" | wc -l) label processes remain"
  echo "-- captured output after stop --"
  cat "$EVID/.$label.out"
}

run_control() {
  local n="$1"
  header "CONTROL RUN $n (no pmask): renamer self-rename is visible"
  setsid "$TC" renamer >"$EVID/.stealth-control$n.out" 2>&1 &
  local pid=$!
  sleep 0.2
  echo "comm@0.2s=$(cat /proc/$pid/comm 2>&1)"
  sleep 1.5
  echo "comm@1.7s=$(cat /proc/$pid/comm 2>&1)"
  echo "-- same-uid open shape of the plain process --"
  python3 "$EVID/tools/uidprobe.py" "$pid" "control$n" 2>&1 | grep -vE 'readlink\(.*exe\)=OK$' 
  echo "-- payload output --"
  cat "$EVID/.stealth-control$n.out"
  kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

run_stealth r2-stealth
run_stealth r2-stealth-b
run_control 1
run_control 2

header "RESIDUE CHECK"
ps -eo pid,comm | grep -E 'r2-stealth' || echo "none"
