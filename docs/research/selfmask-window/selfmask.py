#!/usr/bin/env python3
# reproducible: yes (sh docs/research/selfmask-window/run.sh)
"""Self-mask at the first Python statement: set comm, then report."""
import ctypes
import time

t0 = time.monotonic_ns()
ctypes.CDLL(None).prctl(15, ctypes.c_char_p(b"smask"), 0, 0, 0)
print(f"masked_ns={time.monotonic_ns() - t0}", file=__import__("sys").stderr)
