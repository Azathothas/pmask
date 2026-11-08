#!/bin/sh
# reproducible: yes (this script is the harness)
# Measure the window between a payload's exec and its first self-mask.
#
# The observer samples /proc/<pid>/comm every 0.1 ms until it reads
# "smask".  The number is the time from the shell's fork to the first
# sample that saw the mask, so it includes the exec and the observer's
# sampling resolution.  It is a lower bound on the window for a payload
# that has not masked yet, not an upper bound.
#
#   sh run.sh
set -u
cd "$(dirname "$0")"
T=$(mktemp -d "${TMPDIR:-/tmp}/selfmask-window.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT INT TERM
CC=${CC:-cc}
command -v "$CC" >/dev/null || { echo "SKIP: no C compiler"; exit 2; }
"$CC" -O2 -o "$T/selfmask-c" selfmask.c || exit 2
python3 -c 'import ctypes' 2>/dev/null || { echo "SKIP: no python3 ctypes"; exit 2; }
cp selfmask.py "$T/selfmask-py"
chmod +x "$T/selfmask-py"

measure() {  # LABEL PAYLOAD [ARGS...]
    m_label=$1; shift
    m_start=$(date +%s%N)
    "$@" >/dev/null 2>"$T/$m_label.err" &
    m_pid=$!
    m_i=0
    m_seen=""
    while [ "$m_i" -lt 20000 ]; do
        m_i=$((m_i + 1))
        m_comm=$(cat "/proc/$m_pid/comm" 2>/dev/null)
        if [ "$m_comm" = "smask" ]; then
            m_seen=1
            break
        fi
        # No sleep: the loop's own cost is the sampling interval.
    done
    m_end=$(date +%s%N)
    wait "$m_pid" 2>/dev/null
    m_inner=$(sed -n 's/^masked_ns=//p' "$T/$m_label.err" | head -1)
    if [ -n "$m_seen" ]; then
        echo "WINDOW payload=$m_label window_us=$(( (m_end - m_start) / 1000 )) samples=$m_i inner_mask_us=$(( ${m_inner:-0} / 1000 ))"
    else
        echo "WINDOW payload=$m_label window_us=SKIP samples=$m_i inner_mask_us=${m_inner:-SKIP}"
    fi
}

echo "HOST kernel=$(uname -r) arch=$(uname -m) uid=$(id -u)"
measure c "$T/selfmask-c"
measure python "$T/selfmask-py"
