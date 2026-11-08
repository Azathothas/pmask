//! Opportunistic user, PID and mount namespaces with a private `/proc`.
//!
//! `available` probes whether the kernel lets this process create a user
//! namespace. `fork_in_userns` forks a child into new user, PID and mount
//! namespaces. `child_setup_proc` runs in that child and mounts a private
//! `/proc`.
//!
//! Limits:
//! - Availability depends on the kernel and on distribution policy. Some
//!   systems refuse unprivileged user namespaces or gate them with a
//!   security module. Callers must treat every function here as optional.
//! - The child maps only the caller's effective uid and gid, each to itself.
//! - The kernel can refuse a `/proc` mount with `hidepid=2` inside a user
//!   namespace. `child_setup_proc` then tries `subset=pid`, then a plain
//!   mount, and reports which one worked.
//! - The module does not change what processes outside the namespace see.
//!
//! `fork_in_userns` uses `clone` with `CLONE_NEWUSER`. The kernel allows
//! this from a multi-threaded process. `unshare(CLONE_NEWUSER)` fails in a
//! multi-threaded process. Only `available` uses `unshare`, in a
//! single-threaded throwaway child.
//!
//! The functions that run after the fork call only raw system calls. They
//! do not allocate and do not take locks.

use std::io;

const CLONE_NEWNS: libc::c_ulong = 0x0002_0000;
const CLONE_NEWUSER: libc::c_ulong = 0x1000_0000;
const CLONE_NEWPID: libc::c_ulong = 0x2000_0000;

/// Which `/proc` mount worked in the namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcMode {
    /// Mounted with `hidepid=2`.
    Hidepid2,
    /// Mounted with `subset=pid`.
    SubsetPid,
    /// Mounted without options.
    Plain,
}

fn wait_for(pid: libc::pid_t) -> io::Result<libc::c_int> {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a valid out pointer.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return Ok(status);
        }
        let err = io::Error::last_os_error();
        if rc < 0 && err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(err);
    }
}

/// Return true when this process can create a user namespace.
///
/// The probe forks a child that calls `unshare(CLONE_NEWUSER)`. The child
/// sets a 5 second alarm so that it cannot hang. Return false on any error.
pub fn available() -> bool {
    // SAFETY: the child calls only async-signal-safe functions and then
    // exits without returning.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // SAFETY: alarm, unshare and _exit are async-signal-safe.
        unsafe {
            libc::alarm(5);
            let rc = libc::unshare(CLONE_NEWUSER as libc::c_int);
            libc::_exit(if rc == 0 { 0 } else { 1 });
        }
    }
    match wait_for(pid) {
        Ok(status) => libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        Err(_) => false,
    }
}

fn write_proc_file(path: &str, content: &str) -> io::Result<()> {
    std::fs::write(path, content.as_bytes())
        .map_err(|e| io::Error::new(e.kind(), format!("write {}: {}", path, e)))
}

fn write_maps(child: libc::pid_t, uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
    write_proc_file(&format!("/proc/{}/setgroups", child), "deny")?;
    write_proc_file(
        &format!("/proc/{}/uid_map", child),
        &format!("{} {} 1\n", uid, uid),
    )?;
    write_proc_file(
        &format!("/proc/{}/gid_map", child),
        &format!("{} {} 1\n", gid, gid),
    )?;
    Ok(())
}

fn close_quiet(fd: libc::c_int) {
    // SAFETY: the descriptor belongs to the caller of this helper, which
    // does not use it again.
    unsafe {
        libc::close(fd);
    }
}

/// Fork like `fork()` into new user, PID and mount namespaces.
///
/// Return 0 in the child and the child pid in the parent. The child is pid 1
/// of the new PID namespace. The child waits on a pipe until the parent has
/// written `setgroups`, `uid_map` and `gid_map`. If a write fails, the parent
/// kills the child with SIGKILL, reaps it, and returns the error.
pub fn fork_in_userns() -> io::Result<libc::pid_t> {
    // Two pipes: `go` releases the child after the parent has written the
    // id maps, and `rdy` says the child has restored its dumpable flag so
    // the parent can open /proc/<pid>/setgroups at all.
    let mut go = [0 as libc::c_int; 2];
    let mut rdy = [0 as libc::c_int; 2];
    // SAFETY: both arrays have room for two descriptors.
    unsafe {
        if libc::pipe2(go.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::pipe2(rdy.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            let err = io::Error::last_os_error();
            close_quiet(go[0]);
            close_quiet(go[1]);
            return Err(err);
        }
    }
    let (go_r, go_w) = (go[0], go[1]);
    let (rdy_r, rdy_w) = (rdy[0], rdy[1]);
    // SAFETY: geteuid and getegid cannot fail.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };

    let flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | libc::SIGCHLD as libc::c_ulong;
    // SAFETY: a raw clone without CLONE_VM behaves like fork. All other
    // arguments are zero: the stack, parent_tid, child_tid and tls arguments
    // appear in a different order on x86_64 and aarch64, and zeros make the
    // order irrelevant.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone,
            flags,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        close_quiet(go_r);
        close_quiet(go_w);
        close_quiet(rdy_r);
        close_quiet(rdy_w);
        return Err(io::Error::new(
            err.kind(),
            format!("clone(CLONE_NEWUSER): {}", err),
        ));
    }

    if rc == 0 {
        // Child. Only raw system calls from here.
        // SAFETY: close, read, write and _exit are async-signal-safe.
        // `byte` is a valid one byte buffer.
        unsafe {
            libc::close(go_w);
            libc::close(rdy_r);
            // The parent writes this child's id maps after the handshake.
            // A caller that hardened itself for secret material passes
            // dumpable 0 across the fork, and a non-dumpable child's
            // /proc/<pid>/setgroups cannot be opened by the parent.
            // Restore it before the readiness byte; the payload's own
            // dumpability is the default and `--no-dumpable` is a
            // redaction-mode treatment.
            libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
            let ready = 1u8;
            libc::write(rdy_w, &ready as *const u8 as *const libc::c_void, 1);
            libc::close(rdy_w);
            let mut byte = 0u8;
            let n = loop {
                let n = libc::read(go_r, &mut byte as *mut u8 as *mut libc::c_void, 1);
                if n < 0 && *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                break n;
            };
            libc::close(go_r);
            if n != 1 {
                libc::_exit(1);
            }
        }
        return Ok(0);
    }

    let child = rc as libc::pid_t;
    close_quiet(go_r);
    close_quiet(rdy_w);
    // Wait for the child to restore its dumpable flag before opening its
    // /proc entries.  Without this handshake the parent races the child
    // and the setgroups write fails with EACCES on a hardened supervisor.
    let mut ready = 0u8;
    // SAFETY: `ready` is a valid one byte buffer.
    let n = unsafe { libc::read(rdy_r, &mut ready as *mut u8 as *mut libc::c_void, 1) };
    close_quiet(rdy_r);
    if n != 1 {
        close_quiet(go_w);
        kill_and_reap(child);
        return Err(io::Error::other("the namespace child did not become ready"));
    }
    match write_maps(child, uid, gid) {
        Ok(()) => {
            let byte = 1u8;
            // SAFETY: `byte` is a valid one byte buffer.
            let n = unsafe { libc::write(go_w, &byte as *const u8 as *const libc::c_void, 1) };
            let write_err = io::Error::last_os_error();
            close_quiet(go_w);
            if n != 1 {
                kill_and_reap(child);
                return Err(with_context(write_err, "release the namespace child"));
            }
            Ok(child)
        }
        Err(err) => {
            close_quiet(go_w);
            kill_and_reap(child);
            Err(err)
        }
    }
}

fn with_context(err: io::Error, what: &str) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {}", what, err))
}

fn kill_and_reap(child: libc::pid_t) {
    // SAFETY: kill with a pid this module created.
    unsafe {
        libc::kill(child, libc::SIGKILL);
    }
    let _ = wait_for(child);
}

fn mount_proc(data: *const libc::c_void) -> libc::c_int {
    // SAFETY: all string arguments are NUL-terminated constants. `data` is
    // null or a NUL-terminated constant.
    unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            data,
        )
    }
}

/// Make the mount tree private and mount a private `/proc`.
///
/// Call this in the child that `fork_in_userns` returned 0 to. Try
/// `hidepid=2`, then `subset=pid`, then a plain mount. A refusal with EPERM
/// or EINVAL moves to the next mode. Any other error is returned at once.
/// The function does not allocate. It returns the bare OS error, without
/// context text, for that reason.
pub fn child_setup_proc() -> io::Result<ProcMode> {
    // SAFETY: "/" is a NUL-terminated constant. Null source, fstype and data
    // are valid for a propagation change.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let attempts: [(&[u8], ProcMode); 3] = [
        (&b"hidepid=2\0"[..], ProcMode::Hidepid2),
        (&b"subset=pid\0"[..], ProcMode::SubsetPid),
        (&b"\0"[..], ProcMode::Plain),
    ];
    let mut last = io::Error::from_raw_os_error(libc::EINVAL);
    for (data, mode) in attempts.iter() {
        let ptr = if mode == &ProcMode::Plain {
            std::ptr::null()
        } else {
            data.as_ptr() as *const libc::c_void
        };
        if mount_proc(ptr) == 0 {
            return Ok(*mode);
        }
        let err = io::Error::last_os_error();
        let code = err.raw_os_error();
        if code != Some(libc::EPERM) && code != Some(libc::EINVAL) {
            return Err(err);
        }
        last = err;
    }
    Err(last)
}

/// `CLONE_NEWUTS`.
pub const NS_UTS: libc::c_int = libc::CLONE_NEWUTS;
/// `CLONE_NEWIPC`.
pub const NS_IPC: libc::c_int = libc::CLONE_NEWIPC;
/// `CLONE_NEWCGROUP`.
pub const NS_CGROUP: libc::c_int = libc::CLONE_NEWCGROUP;

/// Create one namespace in the calling process.
///
/// `isolate` calls this after the parent has written the id maps, so the
/// new namespace owns the payload and not the caller.  One flag per call is
/// deliberate: `unshare` with several flags fails as a whole, so a single
/// refusal would hide which namespaces the kernel granted and which it did
/// not.
///
/// The function does not allocate, so it is safe between `fork` and `exec`.
pub fn child_unshare(flags: libc::c_int) -> io::Result<()> {
    // SAFETY: unshare(2) on the calling process; no buffer is touched.
    let rc = unsafe { libc::unshare(flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Set the hostname of the calling process's UTS namespace.
///
/// `libc` does not declare `sethostname(2)` for Linux, so the syscall is
/// made directly.  The caller must already be in its own UTS namespace:
/// without one this changes the host's hostname, and an unprivileged caller
/// is refused with `EPERM`.
pub fn child_set_hostname(name: &[u8]) -> io::Result<()> {
    // SAFETY: `name` is a live buffer and its length is passed alongside,
    // which is the whole contract of the syscall.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_sethostname,
            name.as_ptr() as *const libc::c_char,
            name.len() as libc::c_int,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_does_not_panic() {
        let _ = available();
    }

    // Mutation control: without CLONE_NEWUTS the child names the host's UTS
    // namespace, and `child_set_hostname` is then either refused or, as
    // root, changes the host's hostname.  The test calls it only after both
    // namespaces were created, so a host that grants neither cannot be
    // changed by it.
    #[test]
    fn child_set_hostname_stays_inside_a_uts_namespace() {
        // SAFETY: the child only unshares and _exits.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return;
        }
        if pid == 0 {
            let code =
                if child_unshare(libc::CLONE_NEWUSER).is_err() || child_unshare(NS_UTS).is_err() {
                    3
                } else if child_set_hostname(b"pmask-test").is_ok() {
                    0
                } else {
                    1
                };
            // SAFETY: the child exits immediately.
            unsafe { libc::_exit(code) };
        }
        let status = match wait_for(pid) {
            Ok(s) => s,
            Err(_) => return,
        };
        assert!(libc::WIFEXITED(status), "status {:#x}", status);
        match libc::WEXITSTATUS(status) {
            0 => {}
            3 => eprintln!("skip: user or UTS namespaces are not available here"),
            other => panic!(
                "child_set_hostname failed in its own UTS namespace: exit {}",
                other
            ),
        }
    }

    // Mutation control: a refused unshare must report an error rather than
    // claim success.  A second `CLONE_NEWUSER` is refused on every host, so
    // the case decides on any machine that allows the first.
    #[test]
    fn child_unshare_reports_a_refusal() {
        // SAFETY: the child only unshares and _exits.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return;
        }
        if pid == 0 {
            let first = child_unshare(libc::CLONE_NEWUSER);
            let second = child_unshare(libc::CLONE_NEWUSER);
            let code = match (first.is_ok(), second.is_ok()) {
                (false, _) => 3,
                (true, true) => 1,
                (true, false) => 0,
            };
            // SAFETY: the child exits immediately.
            unsafe { libc::_exit(code) };
        }
        let status = match wait_for(pid) {
            Ok(s) => s,
            Err(_) => return,
        };
        assert!(libc::WIFEXITED(status), "status {:#x}", status);
        match libc::WEXITSTATUS(status) {
            0 => {}
            3 => eprintln!("skip: user namespaces are not available here"),
            other => panic!("a refused unshare was not reported: exit {}", other),
        }
    }

    // Mutation control: a clone without CLONE_NEWPID makes the child see its
    // real pid, exit with 0, and fail the assertion.
    #[test]
    fn fork_in_userns_child_is_pid_one() {
        if !available() {
            eprintln!("skip: user namespaces are not available here");
            return;
        }
        let pid = match fork_in_userns() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("skip: fork_in_userns refused: {}", e);
                return;
            }
        };
        if pid == 0 {
            // SAFETY: getpid and _exit are async-signal-safe.
            unsafe {
                libc::_exit(if libc::getpid() == 1 { 7 } else { 0 });
            }
        }
        let status = wait_for(pid).expect("waitpid");
        assert!(libc::WIFEXITED(status), "status {:#x}", status);
        assert_eq!(libc::WEXITSTATUS(status), 7);
    }
}
