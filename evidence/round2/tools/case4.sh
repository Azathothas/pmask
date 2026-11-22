#!/bin/bash
# Case 4: --encrypt-memory. Payload maps must carry no /secretmem VMA;
# supervisor must. Root scans supervisor and payload memory for the literal
# secret and the payload canary.
source "$(dirname "$0")/lib.sh"
LOG="$EVID/r2-encrypt.log"
SECRET=CANARY_R2_ENC_SECRET_a4d9
CANARY=CANARY_R2_ENC_PAYLOAD_6b17
: >"$LOG"
exec >>"$LOG" 2>&1

run_enc() {
  local label="$1" rep="$EVID/r2-encrypt.$1.report.json"
  header "MASKED RUN --encrypt-memory label=$label"
  local pgid; pgid=$(start_bg_raw "$label" -q -l "$label" --encrypt-memory \
      --secret "S=literal:$SECRET" --report-file "$rep" -- "$TC" sleeper "$CANARY")
  echo "started pmask pgid=$pgid"
  if ! wait_pids "$label"; then echo "SETTLE=FAIL"; find_pids "$label"; return; fi
  find_pids "$label"
  local sup pay; sup=$(supervisor_pid "$label"); pay=$(payload_pid "$label")
  echo "supervisor=$sup payload=$pay"
  echo "-- supervisor /secretmem VMA count --"
  sudo grep -c secretmem "/proc/$sup/maps"
  sudo grep secretmem "/proc/$sup/maps"
  echo "-- payload /secretmem VMA count (expected 0) --"
  n=$(sudo grep -c secretmem "/proc/$pay/maps"); echo "$n"
  echo "payload.secretmem_count=$n"
  echo "-- payload maps (non-library lines) --"
  sudo grep -vE '\.so|\[vvar\]|\[vdso\]|\[heap\]|^[0-9a-f]+-[0-9a-f]+ ---p' "/proc/$pay/maps"
  echo "-- root memory scan: supervisor $sup --"
  sudo "$EVID/tools/scanmem" "$sup" "$SECRET" "$CANARY"
  echo "-- root memory scan: payload $pay --"
  sudo "$EVID/tools/scanmem" "$pay" "$SECRET" "$CANARY"
  echo "-- payload fd list (secret descriptor) --"
  sudo ls -l "/proc/$pay/fd" 2>&1
  echo "-- terminate payload, collect report --"
  sudo kill -9 "$pay" 2>/dev/null
  for i in $(seq 1 50); do [ -s "$rep" ] && break; sleep 0.1; done
  echo "report.path=$rep"
  cat "$rep" 2>&1
  stop_pgid "$pgid" "$label"
  echo "STOP verified: $(find_pids "$label" | wc -l) label processes remain"
}

run_enc r2-enc
run_enc r2-enc-b

header "RESIDUE CHECK"
ps -eo pid,comm | grep -E 'r2-enc' || echo "none"
