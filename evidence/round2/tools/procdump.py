#!/usr/bin/env python3
"""Dump the /proc surface of one pid exactly as the calling uid sees it.

Usage: procdump.py PID [TAG]
Prints delimited blocks; every open is attempted and its result recorded so a
refusal is evidence rather than an absent line.
"""
import errno
import os
import struct
import sys

PID = int(sys.argv[1])
TAG = sys.argv[2] if len(sys.argv) > 2 else ""


def errname(e):
    return errno.errorcode.get(e, str(e))


def slurp(path, limit=None):
    try:
        with open(path, "rb") as f:
            data = f.read() if limit is None else f.read(limit)
        return ("OK", data)
    except OSError as e:
        return ("ERR", errname(e))


def open_result(path):
    try:
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)
        return "OK"
    except OSError as e:
        return "ERR:" + errname(e)


def show_bytes(b, maxlen=400):
    if len(b) > maxlen:
        return b[:maxlen] + b"...[%d bytes total]" % len(b)
    return b


def main():
    base = "/proc/%d" % PID
    print("### procdump tag=%s pid=%d uid=%d" % (TAG, PID, os.getuid()))

    st, data = slurp(base + "/cmdline")
    if st == "OK":
        print("cmdline.len=%d" % len(data))
        print("cmdline.hex=%s" % data.hex())
        print("cmdline.text=%r" % data.replace(b"\0", b"|").decode("utf-8", "backslashreplace"))
    else:
        print("cmdline=ERR:%s" % data)

    st, data = slurp(base + "/comm")
    print("comm=%r" % (data.decode(errors="replace").rstrip("\n") if st == "OK" else "ERR:" + data))

    print("environ.open=%s" % open_result(base + "/environ"))
    st, data = slurp(base + "/environ")
    if st == "OK":
        # Never print environment values: the inherited environment can hold
        # live credentials. Length and variable names are the evidence.
        keys = []
        for ent in data.split(b"\0"):
            if b"=" in ent:
                k = ent.split(b"=", 1)[0].decode("utf-8", "backslashreplace")
                if k not in keys:
                    keys.append(k)
        print("environ.len=%d" % len(data))
        print("environ.keys=%s" % ",".join(keys))
    else:
        print("environ=ERR:%s" % data)

    st, data = slurp(base + "/stat")
    if st == "OK":
        text = data.decode(errors="replace")
        rp = text.rfind(")")
        rest = text[rp + 2:].split()
        # rest[0] is field 3
        f = {n: rest[n - 3] for n in range(48, 52) if n - 3 < len(rest)}
        print("stat.48_arg_start=%s" % f.get(48))
        print("stat.49_arg_end=%s" % f.get(49))
        print("stat.50_env_start=%s" % f.get(50))
        print("stat.51_env_end=%s" % f.get(51))
    else:
        print("stat=ERR:%s" % data)

    print("auxv.open=%s" % open_result(base + "/auxv"))
    print("mem.open=%s" % open_result(base + "/mem"))
    st, data = slurp(base + "/auxv")
    execfn_ptr = None
    if st == "OK":
        pairs = []
        for i in range(0, len(data) - 15, 16):
            t, v = struct.unpack_from("<QQ", data, i)
            pairs.append((t, v))
            if t == 31:  # AT_EXECFN
                execfn_ptr = v
        print("auxv.entries=%d AT_EXECFN=0x%x" % (len(pairs), execfn_ptr or 0))
    else:
        print("auxv=ERR:%s" % data)

    if execfn_ptr is not None:
        opened = open_result(base + "/mem")
        if opened != "OK":
            print("auxv.execfn_string=ERR:mem:%s" % opened)
        else:
            try:
                fd = os.open(base + "/mem", os.O_RDONLY)
                try:
                    buf = os.pread(fd, 4096, execfn_ptr)
                finally:
                    os.close(fd)
                s = buf.split(b"\0", 1)[0]
                print("auxv.execfn_string=%r" % s.decode("utf-8", "backslashreplace"))
            except OSError as e:
                print("auxv.execfn_string=ERR:%s" % errname(e))

    try:
        rl = os.readlink(base + "/exe")
    except OSError as e:
        rl = "ERR:" + errname(e)
    print("exe.readlink=%r" % rl)
    print("exe.open=%s" % open_result(base + "/exe"))

    st, data = slurp(base + "/maps")
    if st == "OK":
        lines = data.decode(errors="replace").splitlines()
        print("maps.lines=%d" % len(lines))
        for ln in lines:
            print("maps| " + ln)
    else:
        print("maps=ERR:%s" % data)
    print("maps.open=%s" % open_result(base + "/maps"))

    st, data = slurp(base + "/status")
    if st == "OK":
        keep = ("TracerPid", "Seccomp_filters", "NoNewPrivs", "Uid", "CoreDumping")
        for ln in data.decode(errors="replace").splitlines():
            if ln.split(":")[0] in keep:
                print("status." + ln)
    else:
        print("status=ERR:%s" % data)

    print("fd.open=%s" % open_result(base + "/fd"))
    try:
        entries = sorted(os.listdir(base + "/fd"), key=lambda x: (len(x), x))
        print("fd.count=%d" % len(entries))
        for e in entries:
            try:
                tgt = os.readlink(base + "/fd/" + e)
            except OSError as ex:
                tgt = "ERR:" + errname(ex)
            print("fd| %s -> %s" % (e, tgt))
    except OSError as e:
        print("fd.list=ERR:%s" % errname(e))

    print("### end tag=%s pid=%d" % (TAG, PID))


if __name__ == "__main__":
    main()
