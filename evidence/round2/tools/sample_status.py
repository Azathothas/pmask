#!/usr/bin/env python3
"""Sample every process whose comm starts with LABEL for DURATION seconds.

Usage: sample_status.py LABEL DURATION
Prints one line per distinct (pid, ppid, Seccomp_filters, NoNewPrivs, exe)
observation with the monotonic time it was first seen. A short-lived payload
(an echo exec) can outlive a single `ps`, and this is the cheap way to catch
its status line while it exists.
"""
import os
import sys
import time

label = sys.argv[1]
duration = float(sys.argv[2])
end = time.monotonic() + duration
seen = {}
while time.monotonic() < end:
    now = time.monotonic()
    try:
        pids = os.listdir("/proc")
    except OSError:
        break
    for e in pids:
        if not e.isdigit():
            continue
        base = "/proc/" + e
        try:
            with open(base + "/comm", "rb") as f:
                comm = f.read().decode(errors="replace").rstrip("\n")
        except OSError:
            continue
        if not comm.startswith(label):
            continue
        try:
            st = {}
            with open(base + "/status") as f:
                for ln in f:
                    k, _, v = ln.partition(":")
                    if k in ("TracerPid", "Seccomp_filters", "NoNewPrivs", "Uid"):
                        st[k] = v.strip()
            ppid = 0
            with open(base + "/stat") as f:
                t = f.read()
            rest = t[t.rfind(")") + 2:].split()
            ppid = rest[1]
            try:
                exe = os.readlink(base + "/exe")
            except OSError:
                exe = "?"
        except OSError:
            continue
        key = (e, ppid, st.get("Seccomp_filters"), st.get("NoNewPrivs"), exe)
        if key not in seen:
            seen[key] = now
            print("t=%.4f pid=%s ppid=%s comm=%s seccomp=%s nnp=%s tracer=%s exe=%s" % (
                now, e, ppid, comm, st.get("Seccomp_filters"),
                st.get("NoNewPrivs"), st.get("TracerPid"), exe))
    time.sleep(0.0005)
print("sampler.done observations=%d" % len(seen))
