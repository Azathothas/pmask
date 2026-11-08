#!/bin/sh
# Empirical comparison: THC zapper v1.1 (normal + stealth) vs pmask,
# viewed by the same blue detector.
set -u

TOKEN="CANARY-COMPARE-001"
LABEL="ci-runner"

start() { echo; echo "=== $1 ==="; }

start "A. zapper v1.1 (normal build)"
cat > /tmp/job.sh <<'EOS'
#!/bin/sh
sleep 60
EOS
chmod +x /tmp/job.sh
/tmp/zapper-linux-x86_64 -a ci-runner -- /tmp/job.sh --token "$TOKEN" >/dev/null 2>&1 &
sleep 2
ps -eo pid,ppid,comm,args --no-headers 2>/dev/null | grep -iE "zapper|job\.sh|$LABEL" | grep -v grep | head -4
echo "  canary in cmdline/environ: $(grep -l "$TOKEN" /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null | wc -l)"
echo "  traced pids: $(awk '/^TracerPid:/ && $2!=0 {c++} END{print c+0}' /proc/[0-9]*/status 2>/dev/null)"
pkill -f zapper-linux 2>/dev/null; pkill -f job.sh 2>/dev/null; sleep 1

start "B. zapper stealth build"
/tmp/zapper-stealth -a ci-runner -- /tmp/job.sh --token "$TOKEN" >/dev/null 2>&1 &
sleep 2
ps -eo pid,ppid,comm,args --no-headers 2>/dev/null | grep -iE "stealth|job\.sh|$LABEL" | grep -v grep | head -4
echo "  canary in cmdline/environ: $(grep -l "$TOKEN" /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null | wc -l)"
echo "  traced pids: $(awk '/^TracerPid:/ && $2!=0 {c++} END{print c+0}' /proc/[0-9]*/status 2>/dev/null)"
pkill -f zapper-stealth 2>/dev/null; pkill -f job.sh 2>/dev/null; sleep 1

start "C. pmask 0.1.0-beta.1"
if [ -x /tmp/pmask ]; then
	/tmp/pmask --label "$LABEL" -- /tmp/job.sh --token "$TOKEN" >/dev/null 2>&1 &
	sleep 2
	ps -eo pid,ppid,comm,args --no-headers 2>/dev/null | grep -iE "pmask|job\.sh|$LABEL" | grep -v grep | head -4
	echo "  canary in cmdline/environ: $(grep -l "$TOKEN" /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null | wc -l)"
	echo "  traced pids: $(awk '/^TracerPid:/ && $2!=0 {c++} END{print c+0}' /proc/[0-9]*/status 2>/dev/null)"
	for p in $(pgrep -f "$LABEL" 2>/dev/null); do
		echo "  pid $p exe=$(readlink /proc/$p/exe 2>/dev/null) cmdline_bytes=$(wc -c < /proc/$p/cmdline 2>/dev/null)"
	done
	pkill -f "pmask --label" 2>/dev/null; pkill -f job.sh 2>/dev/null
else
	echo "  pmask not present on this sandbox"
fi

sleep 1
echo
echo "=== D. survivor check after cleanup ==="
echo "  canary anywhere: $(grep -l "$TOKEN" /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null | wc -l)"
echo "  traced pids: $(awk '/^TracerPid:/ && $2!=0 {c++} END{print c+0}' /proc/[0-9]*/status 2>/dev/null)"
