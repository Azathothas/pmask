#!/bin/bash
# Runs INSIDE the new mount+pid namespace created by case7.sh. Must be root
# (the unshare child), remounts /proc, then runs pmask as uid 1000 and probes
# the payload as uid 1000.
mode="$1"
LOG="$2"
EVID=/workspace/pmask-work/evidence/round2
PMASK=/workspace/pmask-work/target/release/pmask
TC=/workspace/pmask-work/target/release/pmask-testcases
case "$mode" in
  invisible) LABEL="r2-hid" ;;
  ptraceable) LABEL="r2-hidp" ;;
  *) LABEL="r2-hid" ;;
esac
REP="$EVID/r2-hid.$mode.report.json"
export TMPDIR=/tmp
exec >>"$LOG" 2>&1

header() { echo; echo "===== $* ====="; }

header "INNER host before remount"
uname -a; id; grep ' /proc ' /proc/mounts

mount -o remount,hidepid="$mode" /proc
echo "remount_rc=$?"
grep ' /proc ' /proc/mounts
cat /proc/self/status | grep -E '^(Uid|NSpid)'

header "CONTROL: plain dumpable process as uid 1000 inside the same namespace"
setpriv --reuid=1000 --regid=1000 --clear-groups -- \
  "$TC" sleeper CANARY_R2_HID_CONTROL >/dev/null 2>&1 &
ctl=$!
sleep 0.4
echo "control_pid=$ctl comm=$(cat /proc/$ctl/comm 2>&1) exe=$(readlink /proc/$ctl/exe 2>&1)"
echo "-- control: same-uid probe must see an ordinary dumpable process --"
setpriv --reuid=1000 --regid=1000 --clear-groups -- \
  python3 "$EVID/tools/uidprobe.py" "$ctl" "uid1000-control-$mode"
kill -9 "$ctl" 2>/dev/null

header "START pmask as uid 1000 with --hide-pid (label $LABEL)"
rm -f "$REP"
setpriv --reuid=1000 --regid=1000 --clear-groups -- \
  "$PMASK" -q -l "$LABEL" --hide-pid --secret S=literal:R2HIDSECRET \
  --report-file "$REP" -- "$TC" sleeper CANARY_R2_HID_2f81 &
launcher=$!
echo "launcher_pid=$launcher"

# Root inside this namespace finds the payload pid by comm+parent shape.
pay=""
for i in $(seq 1 50); do
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    [ "$pid" = "$launcher" ] && continue
    c=$(cat "$p/comm" 2>/dev/null) || continue
    case "$c" in "$LABEL"*) ;; *) continue;; esac
    ppid=$(awk '{print $4}' "$p/stat" 2>/dev/null)
    # payload is a child of a label process
    pc=$(cat "/proc/$ppid/comm" 2>/dev/null)
    if case "$pc" in "$LABEL"*) true;; *) false;; esac; then pay="$pid"; break; fi
  done
  [ -n "$pay" ] && break
  sleep 0.1
done
echo "payload_pid_root_view=$pay"
find_label() {
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    c=$(cat "$p/comm" 2>/dev/null) || continue
    case "$c" in
      "$LABEL"*) echo "$pid $(awk '{print $4}' "$p/stat") $(readlink "$p/exe" 2>&1)" ;;
    esac
  done
}
echo "-- root view of label processes --"
find_label

header "SAME-UID PROBE as uid 1000 (dentry not pre-instantiated by this uid)"
setpriv --reuid=1000 --regid=1000 --clear-groups -- \
  python3 "$EVID/tools/uidprobe.py" "$pay" "uid1000-$mode-first"
setpriv --reuid=1000 --regid=1000 --clear-groups -- \
  "$TC" procviews "$pay"

header "ROOT PROBE (contrast: root still sees the pid)"
python3 "$EVID/tools/uidprobe.py" "$pay" "root-$mode"

header "SAME-UID PROBE AGAIN after root instantiated the dentry"
setpriv --reuid=1000 --regid=1000 --clear-groups -- \
  python3 "$EVID/tools/uidprobe.py" "$pay" "uid1000-$mode-second"
setpriv --reuid=1000 --regid=1000 --clear-groups -- \
  "$TC" procviews "$pay"

header "TERMINATE payload and collect report"
kill -9 "$pay" 2>/dev/null
for i in $(seq 1 50); do [ -s "$REP" ] && break; sleep 0.1; done
echo "report=$REP"
cat "$REP" 2>&1
kill -9 "$launcher" 2>/dev/null
sleep 0.3
echo "remaining label procs: $(find_label | wc -l)"
find_label
