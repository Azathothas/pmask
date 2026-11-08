#!/usr/bin/env python3
"""Probe one process interface against a live pid.

Used by tests/isolation.sh for the rows of the micro-VM gap table that
need a syscall: pidfd_getfd, process_vm_readv, process_vm_writev,
PTRACE_ATTACH, PTRACE_SEIZE and kcmp.  Prints one line:

  ok ...          the operation was permitted
  errno=EPERM     the kernel refused it for this reader
  errno=...       another errno, which the caller treats as a failure

The target must be a live process of the same uid.  process_vm_readv and
process_vm_writev aim at the target's arg_start, read from /proc/<pid>/stat
fields 48 to 51, so a permitted read has a valid address and a refused one
fails before the address matters.  process_vm_writev writes back the bytes
it read, so a permitted probe does not change the target.
"""

import ctypes
import errno
import os
import platform
import sys

libc = ctypes.CDLL(None, use_errno=True)

MACH = platform.machine()
if MACH in ("x86_64", "amd64"):
    NR_KCMP = 312
elif MACH in ("aarch64", "arm64"):
    NR_KCMP = 272
else:
    NR_KCMP = None

NR_PIDFD_OPEN = 434
NR_PIDFD_GETFD = 438

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207

KCMP_FILE = 0


class IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


def errname():
    e = ctypes.get_errno()
    return errno.errorcode.get(e, "errno%d" % e)


def syscall(nr, *args):
    ctypes.set_errno(0)
    rc = libc.syscall(nr, *args)
    return rc, ctypes.get_errno()


def arg_start(pid):
    """Field 48 of /proc/<pid>/stat, the start of the argv block."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            data = f.read()
    except OSError:
        return 0
    # comm may hold spaces and parentheses; the fields start after the last ')'.
    tail = data.rsplit(b")", 1)[-1].split()
    try:
        return int(tail[45])
    except (IndexError, ValueError):
        return 0


def pidfd_getfd(pid):
    rc, e = syscall(NR_PIDFD_OPEN, pid, 0)
    if rc < 0:
        return "pidfd_open errno=%s" % errno.errorcode.get(e, "errno%d" % e)
    fd = rc
    rc, e = syscall(NR_PIDFD_GETFD, fd, 1, 0)
    os.close(fd)
    if rc < 0:
        return "errno=%s" % errno.errorcode.get(e, "errno%d" % e)
    os.close(rc)
    return "ok"


def process_vm(pid, write):
    addr = arg_start(pid)
    buf = ctypes.create_string_buffer(8)
    local = IOVec(ctypes.cast(buf, ctypes.c_void_p), 8)
    remote = IOVec(ctypes.c_void_p(addr), 8)
    fn = libc.process_vm_writev if write else libc.process_vm_readv
    fn.restype = ctypes.c_ssize_t
    fn.argtypes = [ctypes.c_int, ctypes.POINTER(IOVec), ctypes.c_ulong,
                   ctypes.POINTER(IOVec), ctypes.c_ulong, ctypes.c_ulong]
    if write:
        # Read the same span first and write those bytes back, so a permitted
        # probe leaves the target unchanged.
        ctypes.set_errno(0)
        rc = libc.process_vm_readv(pid, ctypes.byref(local), 1,
                                   ctypes.byref(remote), 1, 0)
        if rc < 0:
            return "read errno=%s" % errname()
        local.iov_base = ctypes.cast(buf, ctypes.c_void_p)
    ctypes.set_errno(0)
    rc = fn(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    if rc < 0:
        return "errno=%s" % errname()
    return "ok bytes=%d" % rc


def ptrace(pid, seize):
    libc.ptrace.restype = ctypes.c_long
    req = PTRACE_SEIZE if seize else PTRACE_ATTACH
    ctypes.set_errno(0)
    rc = libc.ptrace(ctypes.c_ulong(req), ctypes.c_ulong(pid), None, None)
    if rc < 0:
        return "errno=%s" % errname()
    if seize:
        ctypes.set_errno(0)
        rc = libc.ptrace(ctypes.c_ulong(PTRACE_INTERRUPT),
                         ctypes.c_ulong(pid), None, None)
        if rc < 0:
            return "interrupt errno=%s" % errname()
    os.waitpid(pid, 0)
    ctypes.set_errno(0)
    rc = libc.ptrace(ctypes.c_ulong(PTRACE_DETACH),
                     ctypes.c_ulong(pid), None, None)
    if rc < 0:
        return "detach errno=%s" % errname()
    return "ok"


def kcmp(pid):
    if NR_KCMP is None:
        return "unsupported-arch"
    rc, e = syscall(NR_KCMP, pid, pid, KCMP_FILE, 0, 0)
    if rc < 0:
        return "errno=%s" % errno.errorcode.get(e, "errno%d" % e)
    return "ok result=%d" % rc


def main():
    if len(sys.argv) != 3:
        print("usage: procprobe.py OP PID", file=sys.stderr)
        return 2
    op, pid = sys.argv[1], int(sys.argv[2])
    if op == "pidfd_getfd":
        print(pidfd_getfd(pid))
    elif op == "process_vm_readv":
        print(process_vm(pid, False))
    elif op == "process_vm_writev":
        print(process_vm(pid, True))
    elif op == "ptrace_attach":
        print(ptrace(pid, False))
    elif op == "ptrace_seize":
        print(ptrace(pid, True))
    elif op == "kcmp":
        print(kcmp(pid))
    else:
        print("unknown op %s" % op, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
