#!/usr/bin/env python3
"""Probe /proc/PID as the calling uid and print the exact errno of each shape.

Usage: uidprobe.py PID TAG
Read-only. Used inside the hidepid namespace as uid 1000, and as root for the
contrast.
"""
import errno
import os
import sys

pid = sys.argv[1]
tag = sys.argv[2] if len(sys.argv) > 2 else ""
base = "/proc/" + pid


def err():
    return errno.errorcode.get(errno.geterrno(0), "?")


def res(fn):
    try:
        fn()
        return "OK"
    except OSError as e:
        return "ERR:" + errno.errorcode.get(e.errno, str(e.errno))


print("uidprobe tag=%s pid=%s uid=%d" % (tag, pid, os.getuid()))
try:
    names = os.listdir("/proc")
    print("readdir.present=%s" % (pid in names))
except OSError as e:
    print("readdir=ERR:%s" % errno.errorcode.get(e.errno, e.errno))

print("stat(/proc/PID)=%s" % res(lambda: os.stat(base)))
print("open(/proc/PID/status)=%s" % res(lambda: open(base + "/status").close()))
print("open(/proc/PID/cmdline)=%s" % res(lambda: open(base + "/cmdline").close()))
print("open(/proc/PID/environ)=%s" % res(lambda: open(base + "/environ").close()))
print("open(/proc/PID/maps)=%s" % res(lambda: open(base + "/maps").close()))
print("open(/proc/PID/auxv)=%s" % res(lambda: open(base + "/auxv").close()))
print("open(/proc/PID/mem)=%s" % res(lambda: open(base + "/mem").close()))
print("readlink(/proc/PID/exe)=%s" % res(lambda: os.readlink(base + "/exe")))
print("listdir(/proc/PID/fd)=%s" % res(lambda: os.listdir(base + "/fd")))
try:
    os.kill(int(pid), 0)
    print("kill(pid,0)=OK")
except OSError as e:
    print("kill(pid,0)=ERR:%s" % errno.errorcode.get(e.errno, str(e.errno)))
