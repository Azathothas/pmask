#!/bin/bash
# Case 2: --no-dumpable. Same-uid open results for the six sensitive paths,
# with a no-pmask control twice.
source "$(dirname "$0")/lib.sh"
LOG="$EVID/r2-nodump.log"
CANARY=CANARY_R2_NODUMP_5c21
: >"$LOG"
exec >>"$LOG" 2>&1

run_masked() {
  local label="$1"
  header "MASKED RUN --no-dumpable label=$label"
  local pgid; pgid=$(start_bg "$label" --no-dumpable -- "$TC" sleeper "$CANARY")
  echo "started pmask pgid=$pgid"
  if ! wait_pids "$label"; then echo "SETTLE=FAIL"; find_pids "$label"; return; fi
  find_pids "$label"
  local sup pay; sup=$(supervisor_pid "$label"); pay=$(payload_pid "$label")
  echo "supervisor=$sup payload=$pay"
  echo "-- same-uid opens on payload $pay --"
  python3 "$EVID/tools/procdump.py" "$pay" "sameuid-$label"
  echo "-- same-uid opens on supervisor $sup --"
  python3 "$EVID/tools/procdump.py" "$sup" "sup-$label" | grep -E '^(###|cmdline.text|comm=|environ.open|environ.len|auxv.open|mem.open|exe.readlink|exe.open|maps.open|status\.|fd.open|fd.count)'
  echo "-- root opens on payload $pay (contrast) --"
  sudo python3 "$EVID/tools/procdump.py" "$pay" "root-$label" | grep -E '^(###|cmdline.text|comm=|environ.open|environ.len|auxv.open|mem.open|exe.readlink|exe.open|maps.open|status\.|fd.open|fd.count)'
  stop_pgid "$pgid" "$label"
  echo "STOP verified: $(find_pids "$label" | wc -l) label processes remain"
}

run_control() {
  local n="$1"
  header "CONTROL RUN $n (no pmask)"
  setsid env R2_ENV_CANARY="$CANARY" "$TC" sleeper "$CANARY" >"$EVID/.control-nodump$n.out" 2>&1 &
  local pid=$!; sleep 0.5
  python3 "$EVID/tools/procdump.py" "$pid" "control$n" | grep -E '^(###|cmdline.text|comm=|environ.open|environ.len|auxv.open|mem.open|exe.readlink|exe.open|maps.open|status\.|fd.open|fd.count)'
  kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

run_masked r2-nodump
run_masked r2-nodump-b
run_control 1
run_control 2

header "RESIDUE CHECK"
ps -eo pid,comm | grep -E 'r2-nodump|pmask-testcases' || echo "none"
