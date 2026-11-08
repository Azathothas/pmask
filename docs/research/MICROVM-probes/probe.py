#!/usr/bin/env python3
# reproducible: yes (this script is run by docs/research/MICROVM-probes/run.sh)
"""Measure what one unprivileged process can learn about another.

Run by docs/research/MICROVM-probes/run.sh.  It prints one line per
interface, for two subjects: a plain sibling process and a pmask
masked sibling.  Every line names the errno, so a refusal is a result
rather than a skip.

No repository file is touched.  Subjects are throwaway children that
this script kills before it exits.
"""

import ctypes
import errno
import os
import signal
import socket
import sys
import time

libc = ctypes.CDLL("libc.so.6", use_errno=True)
SYS = {
    "pidfd_open": 434,
    "pidfd_getfd": 438,
    "process_vm_readv": 310,
    "process_vm_writev": 311,
    "kcmp": 312,
    "perf_event_open": 298,
    "userfaultfd": 323,
    "inotify_init": 253,
}
PTRACE_ATTACH = 16
PTRACE_SEIZE = 0x4206
PTRACE_DETACH = 17


def syscall(name, *args):
    fn = libc.syscall
    fn.restype = ctypes.c_long
    rc = fn(ctypes.c_long(SYS[name]), *[ctypes.c_long(a) for a in args])
    if rc < 0:
        return -ctypes.get_errno()
    return rc


def errname(e):
    if e is None:
        return "ok"
    return "%s (%d)" % (errno.errorcode.get(e, "E?"), e)


def read_file(path):
    try:
        with open(path, "rb") as f:
            return f.read(), None
    except OSError as e:
        return None, e.errno


def stat_file(path):
    try:
        return os.stat(path), None
    except OSError as e:
        return None, e.errno


def listdir(path):
    try:
        return os.listdir(path), None
    except OSError as e:
        return None, e.errno


class Subject:
    def __init__(self, argv):
        self.argv = argv
        self.pid = None

    def start(self):
        self.pid = os.fork()
        if self.pid == 0:
            os.setpgid(0, 0)
            try:
                os.execv(self.argv[0], self.argv)
            except OSError:
                os._exit(127)
        time.sleep(0.4)

    def stop(self):
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                os.waitpid(self.pid, 0)
            except OSError:
                pass


def probe_proc_files(pid, results):
    for name in (
        "cmdline", "environ", "comm", "stat", "status", "maps", "smaps",
        "fd", "fdinfo", "exe", "cwd", "root", "ns", "cgroup", "auxv",
        "syscall", "stack", "wchan", "io", "limits", "loginuid",
        "sessionid", "mountinfo", "mem",
    ):
        data, err = read_file("/proc/%d/%s" % (pid, name))
        if err is None:
            results.append(("proc file %s" % name, "readable", "%d bytes" % len(data)))
        else:
            results.append(("proc file %s" % name, "refused", errname(err)))
    listing, err = listdir("/proc/%d" % pid)
    if err is None:
        results.append(("proc dir listing", "readable", "%d entries" % len(listing)))
    else:
        results.append(("proc dir listing", "refused", errname(err)))


def probe_pidfs(pid, results):
    fd = syscall("pidfd_open", pid, 0)
    if fd < 0:
        results.append(("pidfd_open", "refused", errname(-fd)))
        return
    results.append(("pidfd_open", "ok", "fd %d" % fd))
    g = syscall("pidfd_getfd", fd, 1, 0)
    results.append(("pidfd_getfd", "ok" if g >= 0 else "refused",
                    "fd %d" % g if g >= 0 else errname(-g)))
    if g >= 0:
        os.close(g)
    os.close(fd)


class IOV(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


def first_mapped_addr(pid):
    """Start address of the first readable private mapping, for a probe
    that must not fault."""
    try:
        with open("/proc/%d/maps" % pid) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith("r"):
                    return int(parts[0].split("-")[0], 16)
    except OSError:
        pass
    return None


def first_writable_addr(pid):
    """Start address of the first writable private mapping."""
    try:
        with open("/proc/%d/maps" % pid) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith("rw"):
                    return int(parts[0].split("-")[0], 16)
    except OSError:
        pass
    return None


def probe_crossproc(pid, results):
    local = ctypes.create_string_buffer(8)
    liov = IOV(ctypes.cast(local, ctypes.c_void_p), 8)
    addr = first_mapped_addr(pid)
    if addr is None:
        results.append(("process_vm_readv", "not attempted", "no readable mapping"))
    else:
        riov = IOV(ctypes.c_void_p(addr), 8)
        rc = syscall("process_vm_readv", pid,
                     ctypes.addressof(liov), 1, ctypes.addressof(riov), 1, 0)
        results.append(("process_vm_readv", "ok" if rc >= 0 else "refused",
                        "%d bytes from 0x%x" % (rc, addr) if rc >= 0 else errname(-rc)))
    waddr = first_writable_addr(pid)
    if waddr is None:
        results.append(("process_vm_writev", "not attempted", "no writable mapping"))
    else:
        riov = IOV(ctypes.c_void_p(waddr), 8)
        rc = syscall("process_vm_writev", pid,
                     ctypes.addressof(liov), 1, ctypes.addressof(riov), 1, 0)
        results.append(("process_vm_writev", "ok" if rc >= 0 else "refused",
                        "%d bytes to 0x%x" % (rc, waddr) if rc >= 0 else errname(-rc)))
    rc = libc.ptrace(PTRACE_ATTACH, pid, None, None)
    if rc == 0:
        time.sleep(0.2)
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
        libc.ptrace(PTRACE_DETACH, pid, None, None)
        results.append(("PTRACE_ATTACH", "ok", "attached and detached"))
    else:
        results.append(("PTRACE_ATTACH", "refused", errname(ctypes.get_errno())))
    rc = libc.ptrace(PTRACE_SEIZE, pid, None, None)
    if rc == 0:
        libc.ptrace(PTRACE_DETACH, pid, None, None)
        results.append(("PTRACE_SEIZE", "ok", "seized and detached"))
    else:
        results.append(("PTRACE_SEIZE", "refused", errname(ctypes.get_errno())))
    rc = syscall("kcmp", pid, pid, 0, 0, 0)
    results.append(("kcmp", "ok" if rc >= 0 else "refused",
                    "rc %d" % rc if rc >= 0 else errname(-rc)))


class PerfEventAttr(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("size", ctypes.c_uint),
        ("config", ctypes.c_ulonglong),
        ("sample_period", ctypes.c_ulonglong),
        ("sample_type", ctypes.c_ulonglong),
        ("read_format", ctypes.c_ulonglong),
        ("flags", ctypes.c_ulonglong),
        ("wakeup_events", ctypes.c_ulonglong),
    ]


def probe_kernel_objects(results):
    for path in ("/dev/kvm", "/dev/mem", "/dev/kcore", "/proc/kcore",
                 "/proc/net/tcp", "/proc/net/unix",
                 "/sys/kernel/mm/transparent_hugepage"):
        st, err = stat_file(path)
        if err is not None:
            results.append(("kernel file %s" % path, "refused", errname(err)))
            continue
        data, rerr = read_file(path)
        if rerr is not None:
            results.append(("kernel file %s" % path, "stat ok, read refused",
                            "mode %o %s" % (st.st_mode & 0o7777, errname(rerr))))
        else:
            results.append(("kernel file %s" % path, "readable",
                            "mode %o, %d bytes" % (st.st_mode & 0o7777, len(data))))
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 11)
        s.close()
        results.append(("netlink NETLINK_CONNECTOR socket", "ok", "created"))
    except OSError as e:
        results.append(("netlink NETLINK_CONNECTOR socket", "refused", errname(e.errno)))
    attr = PerfEventAttr(0, 0, 0, 0, 0, 0, 0, 0)
    rc = syscall("perf_event_open", ctypes.addressof(attr), 0, -1, -1, 0)
    results.append(("perf_event_open", "ok" if rc >= 0 else "refused",
                    "fd %d" % rc if rc >= 0 else errname(-rc)))
    rc = syscall("userfaultfd", 0)
    results.append(("userfaultfd", "ok" if rc >= 0 else "refused",
                    "fd %d" % rc if rc >= 0 else errname(-rc)))
    rc = syscall("inotify_init")
    if rc >= 0:
        results.append(("inotify_init", "ok", "fd %d" % rc))
        os.close(rc)
    else:
        results.append(("inotify_init", "refused", errname(-rc)))


def probe_socket_auth(results):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        cred = a.getsockopt(socket.SOL_SOCKET, 17, 12)
        pid = int.from_bytes(cred[0:4], "little")
        uid = int.from_bytes(cred[4:8], "little")
        gid = int.from_bytes(cred[8:12], "little")
        results.append(("SO_PEERCRED", "ok",
                        "peer pid %d uid %d gid %d" % (pid, uid, gid)))
    except OSError as e:
        results.append(("SO_PEERCRED", "refused", errname(e.errno)))
    try:
        fd = a.getsockopt(socket.SOL_SOCKET, 77, 4)
        results.append(("SO_PEERPIDFD", "ok",
                        "fd %d" % int.from_bytes(fd, "little")))
    except OSError as e:
        results.append(("SO_PEERPIDFD", "refused", errname(e.errno)))
    a.close()
    b.close()


def read_tracerpid(pid):
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    return line.split()[1]
    except OSError:
        return "unreadable"
    return "absent"


def dump(results):
    for name, state, detail in results:
        print("  %-34s %-20s %s" % (name, state, detail))


def find_children(pid):
    """Pids whose PPid is pid, from /proc/<pid>/stat."""
    out = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % entry) as f:
                data = f.read()
        except OSError:
            continue
        tail = data[data.rfind(")") + 1:].split()
        if len(tail) > 1 and tail[1] == str(pid):
            out.append(int(entry))
    return out


def run_subject(title, argv, results, probe_payload=False):
    sub = Subject(argv)
    sub.start()
    print("--- %s (pid %d)" % (title, sub.pid))
    try:
        probe_proc_files(sub.pid, results)
        probe_pidfs(sub.pid, results)
        probe_crossproc(sub.pid, results)
        data, _ = read_file("/proc/%d/cmdline" % sub.pid)
        print("TracerPid=%s cmdline=%r" % (read_tracerpid(sub.pid), data))
        if probe_payload:
            kids = find_children(sub.pid)
            for kid in kids:
                print("--- payload of the session (pid %d)" % kid)
                sub_results = []
                probe_proc_files(kid, sub_results)
                probe_pidfs(kid, sub_results)
                probe_crossproc(kid, sub_results)
                data, _ = read_file("/proc/%d/cmdline" % kid)
                print("TracerPid=%s cmdline=%r" % (read_tracerpid(kid), data))
                dump(sub_results)
    finally:
        sub.stop()
    dump(results)


def main():
    print("== caller's own access to kernel objects and sockets")
    own = []
    probe_kernel_objects(own)
    probe_socket_auth(own)
    dump(own)
    print()
    run_subject("plain sibling, same uid, dumpable",
                ["/bin/sleep", "30"], [])
    print()
    tool = os.environ.get("PMASK_BIN", "./target/release/pmask")
    run_subject("pmask masked sibling: --detach --no-dumpable",
                [tool, "--detach", "--no-dumpable", "-l", "microvm-probe",
                 "--", "/bin/sleep", "30"], [], probe_payload=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
