#!/bin/sh
# Clean comparison. One tool at a time, unique canary per run, full observation,
# full cleanup between. zapper v1.1 (normal + stealth) vs pmask.
set -u
C="CANARY-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"

cat > /tmp/job.sh <<'EOS'
#!/bin/sh
sleep 40
EOS
chmod +x /tmp/job.sh

observe() {
	tag=$1
	echo "  --- ps view ---"
	ps -eo pid,ppid,comm,args --no-headers 2>/dev/null | grep -E "$tag" | grep -v grep | head -3 | sed 's/^/    /'
	echo "  --- per-pid ---"
	for p in $(pgrep -x "$tag" 2>/dev/null; pgrep -f "$tag" 2>/dev/null | head -3); do
		[ -r /proc/$p/status ] || continue
		printf "    pid %-6s comm=%-12s exe=%-30s tracer=%s bytes=%s\n" \
			"$p" "$(cat /proc/$p/comm 2>/dev/null)" "$(readlink /proc/$p/exe 2>/dev/null)" \
			"$(awk '/^TracerPid:/{print $2}' /proc/$p/status 2>/dev/null)" \
			"$(wc -c < /proc/$p/cmdline 2>/dev/null)"
	done
	echo "  --- canary ---"
	n=$(grep -l "$C" /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null | grep -v "$$" | wc -l)
	echo "    canary sightings: $n"
	echo "  --- tracer census ---"
	awk '/^TracerPid:/ && $2 != 0 {c++} END{print "    pids under a tracer: " c+0}' /proc/[0-9]*/status 2>/dev/null
}

echo "canary for this run: (redacted, ${#C} chars)"

echo
echo "=== 1. baseline: plain process, nothing hiding it ==="
/tmp/job.sh --token "$C" >/dev/null 2>&1 &
sleep 1
observe job.sh
pkill -9 -f job.sh 2>/dev/null; sleep 1

echo
echo "=== 2. zapper v1.1 normal ==="
/tmp/zapper-linux-x86_64 -a ci-runner -- /tmp/job.sh --token "$C" >/dev/null 2>&1 &
sleep 2
observe ci-runner
pkill -9 -f zapper-linux 2>/dev/null; pkill -9 -f job.sh 2>/dev/null; pkill -9 -f ci-runner 2>/dev/null; sleep 1

echo
echo "=== 3. zapper v1.1 stealth build ==="
/tmp/zapper-stealth -a ci-runner -- /tmp/job.sh --token "$C" >/dev/null 2>&1 &
sleep 2
observe ci-runner
pkill -9 -f zapper-stealth 2>/dev/null; pkill -9 -f job.sh 2>/dev/null; pkill -9 -f ci-runner 2>/dev/null; sleep 1

echo
echo "=== 4. pmask ==="
if [ -x /tmp/pmask ]; then
	/tmp/pmask --label ci-runner -- /tmp/job.sh --token "$C" >/dev/null 2>&1 &
	sleep 2
	observe ci-runner
	pkill -9 -f "pmask --label" 2>/dev/null; pkill -9 -f job.sh 2>/dev/null; pkill -9 -f ci-runner 2>/dev/null
else
	echo "  pmask missing"
fi
sleep 1

echo
echo "=== 5. survivors after cleanup ==="
echo "  canary: $(grep -l "$C" /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null | wc -l)"
echo "  procs:  $(ps -eo comm --no-headers | grep -cE 'zapper|job\.sh|pmask')"
rm -f /tmp/job.sh
