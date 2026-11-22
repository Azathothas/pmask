#!/bin/bash
# Shared helpers for the round-2 evidence runs. No set -e: every probe is
# recorded even when it fails, so a failure is evidence rather than an abort.
EVID=/workspace/pmask-work/evidence/round2
PMASK=/workspace/pmask-work/target/release/pmask
TC=/workspace/pmask-work/target/release/pmask-testcases
export TMPDIR=/tmp

# start_bg LABEL -- ARGS...
# Starts pmask detached in its own session and echoes its pid (the pgid).
start_bg() {
  local label="$1"; shift
  [ "$1" = "--" ] && shift
  setsid "$PMASK" -q -l "$label" "$@" >"$EVID/.$label.out" 2>&1 &
  echo $!
}

# start_bg_raw LABEL ARGS... : no implicit -q/-l, caller passes everything
start_bg_raw() {
  local label="$1"; shift
  setsid "$PMASK" "$@" >"$EVID/.$label.out" 2>&1 &
  echo $!
}

# find_pids LABEL : one line per process whose comm starts with LABEL
# fields: pid ppid comm exe tracerpid
find_pids() {
  local label="$1" p pid c exe tp
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    c=$(cat "$p/comm" 2>/dev/null) || continue
    case "$c" in "$label"*) ;; *) continue;; esac
    exe=$(readlink "$p/exe" 2>/dev/null || echo "?")
    tp=$(awk '/^TracerPid:/{print $2}' "$p/status" 2>/dev/null)
    echo "$pid $(awk '{print $4}' "$p/stat" 2>/dev/null) $c $exe $tp"
  done
}

# supervisor_pid LABEL : the label process that is the parent of another
# label process. Does not depend on `exe`, which --no-dumpable refuses.
supervisor_pid() {
  local label="$1" pid pids
  pids=$(find_pids "$label" | awk '{print $1}')
  for pid in $pids; do
    if find_pids "$label" | awk -v p="$pid" '$2==p{found=1} END{exit !found}'; then
      echo "$pid"; return
    fi
  done
}

# payload_pid LABEL : the label process whose parent is the supervisor
payload_pid() {
  local label="$1" sup
  sup=$(supervisor_pid "$label")
  [ -n "$sup" ] && find_pids "$label" | awk -v s="$sup" '$2==s{print $1; exit}'
}

# wait_pids LABEL : wait up to 5s for supervisor and payload to appear
wait_pids() {
  local label="$1" i
  for i in $(seq 1 50); do
    if [ -n "$(supervisor_pid "$label")" ] && [ -n "$(payload_pid "$label")" ]; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# stop_pgid PID : kill the session/group, then verify nothing with LABEL remains
stop_pgid() {
  local pid="$1" label="$2" i
  kill -9 -"$pid" 2>/dev/null
  kill -9 "$pid" 2>/dev/null
  for i in $(seq 1 30); do
    [ -z "$(find_pids "$label")" ] && return 0
    sleep 0.1
  done
  find_pids "$label"
  return 1
}

# header TEXT : section marker used in every log
header() { echo; echo "===== $* ====="; }
