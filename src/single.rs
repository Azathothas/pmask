//! Single-process in-place exec masking engine (`--profile single`).
//!
//! Instead of keeping a long-lived supervisor process attached for the whole
//! lifetime of the payload, [`exec_single`] uses a transient double-forked
//! helper `G` that:
//!
//! 1. Seizes the main process `P` (permitted even under `yama.ptrace_scope=1`
//!    via `prctl(PR_SET_PTRACER, G_pid)`),
//! 2. Intercepts `P`'s `execve`/`execveat` entry stop for zero-exposure ELF
//!    argument/environment redaction (or handles `#!` scripts post-exec),
//! 3. Completes the full `execimg` rewrite at `PTRACE_EVENT_EXEC` (anonymous
//!    redaction block, batched `argv`/`envp` repoint, `DECOY_ENV`, `AT_EXECFN`,
//!    `PR_SET_MM_MAP`, `PR_SET_NAME`, `MADV_DONTDUMP`, `RLIMIT_CORE=0`,
//!    `PR_SET_DUMPABLE=0`),
//! 4. Unlinks any staged [`crate::rexec::RexecMode::Path`] carrier and removes
//!    its private `0700` directory,
//! 5. Immediately calls `PTRACE_DETACH(P, 0)` and `_exit(0)`.
//!
//! Once `execve` completes, the payload runs IN PLACE in `P`'s original PID
//! with zero supervisor process, `TracerPid: 0`, `Threads: 1`, `Seccomp: 0`,
//! and `NoNewPrivs: 0` (unless explicitly requested).

use crate::arch;
use crate::inject;
use crate::mask::{Mask, Prepared};
use crate::tracer::{ExitState, Tracer};
use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;

/// `PR_SET_PTRACER` (`"Yama"` in ASCII) from `<linux/prctl.h>`.
const PR_SET_PTRACER: libc::c_int = 0x5961_6d61;
/// `PR_SET_NO_NEW_PRIVS` from `<linux/prctl.h>`.
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
/// `AT_EMPTY_PATH` for `execveat(2)`.
const AT_EMPTY_PATH: libc::c_long = 0x1000;
/// `close_range(2)` syscall number (unified across x86_64, aarch64, i386).
const SYS_CLOSE_RANGE: libc::c_long = 436;

/// Options controlling [`exec_single_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SingleOptions {
    /// When `true`, double-fork so the masked payload is reparented to PID 1
    /// (or the nearest subreaper) and return `Ok(ExitState::plain(0, None))`
    /// once the masked `exec` completes and detaches.
    ///
    /// When `false` (default), replace the calling process in place via
    /// `execve`/`execveat` (never returning on success).
    pub reparent: bool,
}

impl SingleOptions {
    /// Create default single-process options (`reparent = false`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable reparenting the payload to PID 1.
    pub fn reparent(mut self, on: bool) -> Self {
        self.reparent = on;
        self
    }
}

/// Return `true` when `err` came from the transient helper failing
/// `PTRACE_SEIZE` (for example under a seccomp filter or `ptrace_scope >= 2`).
pub fn is_ptrace_refused(err: &io::Error) -> bool {
    err.to_string().contains("ptrace refused")
}

fn ptrace_refused_error(errno: i32) -> io::Error {
    let raw = io::Error::from_raw_os_error(errno);
    let kind = match errno {
        libc::EPERM | libc::EACCES => io::ErrorKind::PermissionDenied,
        libc::ENOSYS => io::ErrorKind::Unsupported,
        _ => raw.kind(),
    };
    io::Error::new(kind, format!("ptrace refused (errno {}): {}", errno, raw))
}

/// Execute `program` with `args` under `mask` using the single-process
/// in-place masking engine (`--profile single`).
///
/// - When `reparent == false`: replaces the calling process image in place on
///   success (never returns `Ok`); returns `Err` on validation failure,
///   ptrace refusal (detectable via [`is_ptrace_refused`]), or `execve` error.
/// - When `reparent == true`: double-forks so the masked payload runs detached
///   under PID 1, waits until the masked `exec` completes (or fails), and
///   returns `Ok(ExitState::plain(0, None))` on launch or `Err` if launch
///   failed.
pub fn exec_single(
    mask: &Mask,
    program: &OsStr,
    args: &[OsString],
    reparent: bool,
) -> io::Result<ExitState> {
    exec_single_with(mask, program, args, &SingleOptions { reparent })
}

/// [`exec_single`] accepting [`SingleOptions`].
pub fn exec_single_with(
    mask: &Mask,
    program: &OsStr,
    args: &[OsString],
    opts: &SingleOptions,
) -> io::Result<ExitState> {
    if mask.watch_rename_enabled() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--watch-rename installs an unremovable seccomp filter that requires a live tracer; \
             use --profile tree instead of --profile single",
        ));
    }
    if crate::testhooks::bool_opt("PMASK_PROBE_PTRACE") == Some(false) {
        return Err(ptrace_refused_error(libc::EPERM));
    }

    let mut prepared = mask.prepare(program, args)?;
    // Single-process mode detaches explicitly right after the first exec
    // completes; disable tree-only flags and exit-kill so the transient helper
    // exiting never kills the payload.
    prepared.cfg.detach = false;
    prepared.cfg.exit_kill = false;
    prepared.cfg.follow_tree = false;
    prepared.cfg.watch_prctl = false;
    prepared.cfg.watch_strict = false;
    prepared.cfg.fast_exec = false;
    prepared.cfg.rexec_per_exec = false;

    if opts.reparent {
        exec_single_reparented(prepared)
    } else {
        exec_single_inplace(&mut prepared, None)
    }
}

#[derive(Clone, Copy)]
enum ExecTarget {
    Path(*const libc::c_char),
    Memfd(RawFd),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SingleTargetKind {
    Native64,
    Foreign32,
    Script,
}

fn classify_single_target(target: ExecTarget) -> SingleTargetKind {
    let mut hdr = [0u8; 5];
    let got = match target {
        ExecTarget::Path(ptr) => unsafe {
            let fd = libc::open(ptr, libc::O_RDONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return SingleTargetKind::Script;
            }
            let n = libc::read(fd, hdr.as_mut_ptr().cast(), hdr.len());
            libc::close(fd);
            n
        },
        ExecTarget::Memfd(fd) => unsafe { libc::pread(fd, hdr.as_mut_ptr().cast(), hdr.len(), 0) },
    };
    if got < 5 || &hdr[0..4] != b"\x7fELF" {
        return SingleTargetKind::Script;
    }
    #[cfg(target_pointer_width = "64")]
    const NATIVE_CLASS: u8 = 2; // ELFCLASS64
    #[cfg(target_pointer_width = "32")]
    const NATIVE_CLASS: u8 = 1; // ELFCLASS32
    if hdr[4] == NATIVE_CLASS {
        SingleTargetKind::Native64
    } else {
        SingleTargetKind::Foreign32
    }
}

fn unlink_staged_paths(priv_file_c: Option<&CString>, priv_dir_c: Option<&CString>) {
    // SAFETY: valid NUL-terminated paths owned by this session.
    unsafe {
        if let Some(f) = priv_file_c {
            libc::unlink(f.as_ptr());
        }
        if let Some(d) = priv_dir_c {
            libc::rmdir(d.as_ptr());
        }
    }
}

/// Double-fork so the payload runs reparented to PID 1 while the caller waits
/// on a status pipe until the masked `exec` completes (and detaches) or fails.
fn exec_single_reparented(mut prepared: Prepared) -> io::Result<ExitState> {
    let mut status_pipe = [0 as libc::c_int; 2];
    let mut reap_pipe = [0 as libc::c_int; 2];
    // SAFETY: `pipe2` initializes two descriptors in each 2-element array.
    if unsafe { libc::pipe2(status_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::pipe2(reap_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        unsafe {
            libc::close(status_pipe[0]);
            libc::close(status_pipe[1]);
        }
        return Err(io::Error::last_os_error());
    }
    let (st_r, st_w) = (status_pipe[0], status_pipe[1]);
    let (rp_r, rp_w) = (reap_pipe[0], reap_pipe[1]);

    // SAFETY: intermediate child only forks the grandchild and exits.
    let c1 = unsafe { libc::fork() };
    if c1 < 0 {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(st_r);
            libc::close(st_w);
            libc::close(rp_r);
            libc::close(rp_w);
        }
        return Err(e);
    }
    if c1 == 0 {
        // Prevent forked children (`c1`, `c2`) from running `Drop` on
        // parent-owned buffers (`SecBuf`, staged `Image` handles) before
        // calling `_exit`.
        let mut prepared = std::mem::ManuallyDrop::new(prepared);
        unsafe {
            libc::close(st_r);
            libc::close(rp_w);
        }
        // SAFETY: grandchild becomes the reparented payload process.
        let c2 = unsafe { libc::fork() };
        if c2 < 0 {
            let e = last_errno();
            write_reparent_error(st_w, false, e);
            unsafe {
                libc::close(st_w);
                libc::close(rp_r);
                libc::_exit(1);
            }
        }
        if c2 > 0 {
            // Intermediate child exits immediately so `c2` is reparented to
            // PID 1 (or the nearest subreaper).
            unsafe {
                libc::close(st_w);
                libc::close(rp_r);
                libc::_exit(0);
            }
        }

        // In `c2`: wait for parent to reap `c1` (EOF on `rp_r`) so our ppid
        // is already reparented before we exec.
        wait_pipe_eof(rp_r);
        unsafe { libc::close(rp_r) };

        // Move `st_w` above the secret-fd and preserved-fd ranges so
        // `install_fds` cannot overwrite it.
        let min_fd = min_helper_fd(&prepared.preserved_fds, prepared.secret_fds.len());
        let done_fd = match move_fd_above(st_w, min_fd) {
            Ok(fd) => fd,
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(libc::EMFILE);
                write_reparent_error(st_w, false, errno);
                unsafe {
                    libc::close(st_w);
                    libc::_exit(126);
                }
            }
        };

        let res = exec_single_inplace(&mut prepared, Some(done_fd));
        if let Err(e) = res {
            let refused = is_ptrace_refused(&e);
            let errno =
                e.raw_os_error()
                    .unwrap_or(if refused { libc::EPERM } else { libc::EACCES });
            write_reparent_error(done_fd, refused, errno);
            unsafe {
                libc::close(done_fd);
                libc::_exit(if errno == libc::ENOENT { 127 } else { 126 });
            }
        }
        unsafe { libc::_exit(0) };
    }

    // Parent side: close child ends, reap `c1`, release `c2`, then wait for
    // `st_r` EOF (success) or error payload.
    unsafe {
        libc::close(st_w);
        libc::close(rp_r);
    }
    reap_child(c1);
    unsafe { libc::close(rp_w) };

    let mut buf = [0u8; 5];
    let got = read_exact_or_eof(st_r, &mut buf);
    unsafe { libc::close(st_r) };
    if got == 0 {
        // `c2`/`G` succeeded and already unlinked or took ownership of any
        // staged `RexecMode::Path` file; disarm parent cleanup on drop.
        disarm_rexec_cleanup(&mut prepared);
        Ok(ExitState::plain(0, None))
    } else if got == 5 {
        let errno = i32::from_ne_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if buf[0] == b'P' {
            Err(ptrace_refused_error(errno))
        } else {
            Err(io::Error::from_raw_os_error(errno))
        }
    } else {
        Err(io::Error::other("reparented single-mode launch failed"))
    }
}

fn write_reparent_error(fd: RawFd, ptrace_refused: bool, errno: i32) {
    let tag = if ptrace_refused { b'P' } else { b'E' };
    let eb = errno.to_ne_bytes();
    let msg = [tag, eb[0], eb[1], eb[2], eb[3]];
    write_all_raw(fd, &msg);
}

/// Remove `path` and `private_dir` ownership from `prepared`'s `Image` handles
/// in the parent of a reparented launch so `Drop` does not race the child.
fn disarm_rexec_cleanup(prepared: &mut Prepared) {
    for opt in [&mut prepared.rexec_image, &mut prepared.rexec_temp] {
        if let Some(arc) = opt.as_mut() {
            if let Some(img) = std::sync::Arc::get_mut(arc) {
                img.path = None;
                img.private_dir = None;
            }
        }
    }
}

/// Execute `prepared` in place inside the current process using a transient
/// double-forked tracer `G`.
fn exec_single_inplace(prepared: &mut Prepared, done_fd: Option<RawFd>) -> io::Result<ExitState> {
    if prepared.cfg.no_dumpable || prepared.no_core_dump {
        let zero_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `setrlimit` on our own process with owned `rlimit`.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero_core) } == 0 {
            prepared.cfg.core_limit_applied = true;
        }
    }
    if prepared.no_new_privs {
        // SAFETY: standard prctl with constant arguments.
        unsafe {
            libc::prctl(PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0);
        }
    }
    if let Some(cwd) = &prepared.cwd_c {
        // SAFETY: `cwd` is NUL-terminated; `prog_c` was already resolved and
        // absolutized in `Mask::prepare` before this point.
        if unsafe { libc::chdir(cwd.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let priv_file_c: Option<CString> = prepared
        .rexec_image
        .as_ref()
        .filter(|i| matches!(i.backing, crate::rexec::Backing::PrivatePath { .. }))
        .and_then(|i| i.path.as_ref())
        .and_then(|p| CString::new(p.as_os_str().as_bytes()).ok());
    let priv_dir_c: Option<CString> = prepared
        .rexec_image
        .as_ref()
        .and_then(|i| i.private_dir.as_ref())
        .and_then(|p| CString::new(p.as_os_str().as_bytes()).ok());

    // Primary exec target.
    if let Some(image) = prepared.rexec_image.clone() {
        let quiet = prepared.cfg.quiet;
        let fault_rexec_fail = crate::testhooks::flag("PMASK_FAULT_REXEC_FAIL");
        let fault_rexec_disk = crate::testhooks::flag("PMASK_FAULT_REXEC_DISK");
        let fault_rexec_no_proc = crate::testhooks::flag("PMASK_FAULT_REXEC_NO_PROC");
        if fault_rexec_fail {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "--rexec: the sealed image could not be executed (fault injected)",
            ));
        }
        let skip_to_disk = fault_rexec_disk && prepared.rexec_allow_disk;
        let mut last_err = io::Error::from_raw_os_error(libc::EACCES);

        if !skip_to_disk {
            if let Some(priv_path) = &prepared.rexec_private_path {
                let err = attempt_masked_exec(
                    prepared,
                    ExecTarget::Path(priv_path.as_ptr()),
                    priv_file_c.as_ref(),
                    priv_dir_c.as_ref(),
                    done_fd,
                )?;
                unlink_staged_paths(priv_file_c.as_ref(), priv_dir_c.as_ref());
                if is_ptrace_refused(&err) {
                    return Err(err);
                }
                if !quiet {
                    eprintln!(
                        "pmask: --rexec: temporary-file exec refused; errno {}",
                        err.raw_os_error().unwrap_or(0)
                    );
                }
                last_err = err;
            } else {
                // Step 1: `execveat(image.fd, "", ..., AT_EMPTY_PATH)`
                if !fault_rexec_no_proc {
                    let err1 = attempt_masked_exec(
                        prepared,
                        ExecTarget::Memfd(image.fd),
                        None,
                        None,
                        done_fd,
                    )?;
                    if is_ptrace_refused(&err1) {
                        return Err(err1);
                    }
                    if !quiet {
                        eprintln!(
                            "pmask: --rexec: execveat refused, trying /proc/self/fd; errno {}",
                            err1.raw_os_error().unwrap_or(0)
                        );
                        eprintln!(
                            "pmask: --rexec fallback: execveat refused, trying /proc/self/fd"
                        );
                    }
                    last_err = err1;
                }

                // Step 2: `/proc/self/fd/N`
                if !fault_rexec_no_proc && !prepared.rexec_proc_path.as_bytes().is_empty() {
                    let err2 = attempt_masked_exec(
                        prepared,
                        ExecTarget::Path(prepared.rexec_proc_path.as_ptr()),
                        None,
                        None,
                        done_fd,
                    )?;
                    if is_ptrace_refused(&err2) {
                        return Err(err2);
                    }
                    if !quiet {
                        eprintln!(
                            "pmask: --rexec: /proc/self/fd refused, trying a temporary file; errno {}",
                            err2.raw_os_error().unwrap_or(0)
                        );
                    }
                    last_err = err2;
                }

                // Step 3: temporary file carrier (pre-built when `fault_rexec_no_proc`
                // or `vm.memfd_noexec`, otherwise built lazily only after memfd fails).
                if let Some(temp) = &prepared.rexec_temp {
                    if !fault_rexec_no_proc && temp.fd >= 0 {
                        let e = attempt_masked_exec(
                            prepared,
                            ExecTarget::Memfd(temp.fd),
                            None,
                            None,
                            done_fd,
                        )?;
                        if is_ptrace_refused(&e) {
                            return Err(e);
                        }
                        if !quiet {
                            eprintln!(
                                "pmask: --rexec: temporary-file exec refused; errno {}",
                                e.raw_os_error().unwrap_or(0)
                            );
                        }
                        last_err = e;
                    }
                    if !fault_rexec_no_proc && temp.fd >= 0 {
                        if let Ok(proc_c) = CString::new(format!("/proc/self/fd/{}", temp.fd)) {
                            let e = attempt_masked_exec(
                                prepared,
                                ExecTarget::Path(proc_c.as_ptr()),
                                None,
                                None,
                                done_fd,
                            )?;
                            if is_ptrace_refused(&e) {
                                return Err(e);
                            }
                            if !quiet {
                                eprintln!(
                                    "pmask: --rexec: temporary-file exec refused; errno {}",
                                    e.raw_os_error().unwrap_or(0)
                                );
                            }
                            last_err = e;
                        }
                    }
                    if let Some(path_c) = temp
                        .path
                        .as_ref()
                        .and_then(|p| CString::new(p.as_os_str().as_bytes()).ok())
                    {
                        let e = attempt_masked_exec(
                            prepared,
                            ExecTarget::Path(path_c.as_ptr()),
                            None,
                            None,
                            done_fd,
                        )?;
                        if is_ptrace_refused(&e) {
                            return Err(e);
                        }
                        if !quiet {
                            eprintln!(
                                "pmask: --rexec: temporary-file exec refused; errno {}",
                                e.raw_os_error().unwrap_or(0)
                            );
                        }
                        last_err = e;
                    }
                } else {
                    let label_text = String::from_utf8_lossy(&prepared.cfg.label).into_owned();
                    if let Ok(temp) = crate::rexec::prepare_temp(
                        &image,
                        &label_text,
                        &prepared.cfg.rexec_memfd_name,
                    ) {
                        let path_c = temp
                            .path
                            .as_ref()
                            .and_then(|p| CString::new(p.as_os_str().as_bytes()).ok());
                        let t = match &path_c {
                            Some(c) => ExecTarget::Path(c.as_ptr()),
                            None => ExecTarget::Memfd(temp.fd),
                        };
                        let err3 =
                            attempt_masked_exec(prepared, t, path_c.as_ref(), None, done_fd)?;
                        if is_ptrace_refused(&err3) {
                            return Err(err3);
                        }
                        if !quiet {
                            eprintln!(
                                "pmask: --rexec: temporary-file exec refused; errno {}",
                                err3.raw_os_error().unwrap_or(0)
                            );
                        }
                        last_err = err3;
                    }
                }
            }
        }

        // Step 4: explicit on-disk last resort (never silent).
        if prepared.rexec_allow_disk {
            unlink_staged_paths(priv_file_c.as_ref(), priv_dir_c.as_ref());
            if !quiet {
                eprintln!(
                    "pmask: --rexec: falling back to the on-disk path (explicit last resort)"
                );
            }
            let err4 = attempt_masked_exec(
                prepared,
                ExecTarget::Path(prepared.prog_c.as_ptr()),
                None,
                None,
                done_fd,
            )?;
            return Err(err4);
        }
        return Err(io::Error::new(
            last_err.kind(),
            format!("--rexec: {}", last_err),
        ));
    }

    // Standard non-rexec in-place masked exec.
    let err = attempt_masked_exec(
        prepared,
        ExecTarget::Path(prepared.prog_c.as_ptr()),
        None,
        None,
        done_fd,
    )?;
    Err(err)
}

/// Run one in-place masked exec attempt.
///
/// Uses a zero-`PTRACE_INTERRUPT`, zero-entry-stop fast path: for native ELFs,
/// `P` pre-swaps `argv`/`envp` to zero-exposure label/decoy buffers before
/// calling `execve`/`execveat`, while `G` seizes `P` with `PTRACE_O_TRACEEXEC`
/// and waits straight for `PTRACE_EVENT_EXEC`, restoring the real `argv`/`envp`
/// directly from its fork-inherited `Prepared` vectors.
///
/// Never returns on a successful `execve`/`execveat`.  Returns:
/// - `Err(ptrace_refused_error(..))` if `G` could not seize `P`;
/// - `Ok(exec_err)` if `G` seized `P`, `execve`/`execveat` returned an error,
///   and `G` detached cleanly.
fn attempt_masked_exec(
    prepared: &Prepared,
    target: ExecTarget,
    priv_file_c: Option<&CString>,
    priv_dir_c: Option<&CString>,
    done_fd: Option<RawFd>,
) -> io::Result<io::Error> {
    let target_kind = classify_single_target(target);
    if target_kind == SingleTargetKind::Foreign32 && !prepared.cfg.allow_foreign {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "32-bit (foreign ABI) program refused; pass --allow-foreign to run it unredacted",
        ));
    }
    if prepared.cfg.strict_exec && target_kind != SingleTargetKind::Native64 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "--strict-exec refuses non-ELF or script exec in single profile",
        ));
    }
    let (sw_argv_c, sw_envp_c, env_swapped) = if target_kind == SingleTargetKind::Native64 {
        crate::execimg::build_single_swapped_args(
            &prepared.cfg,
            &prepared.argv_c,
            &prepared.envp_c,
            prepared.run_as.map(|(uid, _)| uid),
        )
    } else {
        (Vec::new(), Vec::new(), false)
    };
    let sw_argv_ptr: Vec<*const libc::c_char> = if target_kind == SingleTargetKind::Native64 {
        sw_argv_c
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect()
    } else {
        Vec::new()
    };
    let sw_envp_ptr: Vec<*const libc::c_char> = if target_kind == SingleTargetKind::Native64 {
        sw_envp_c
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect()
    } else {
        Vec::new()
    };

    let mut pid_pipe = [0 as libc::c_int; 2];
    let mut go_pipe = [0 as libc::c_int; 2];
    let mut ack_pipe = [0 as libc::c_int; 2];
    let mut fail_pipe = [0 as libc::c_int; 2];

    // SAFETY: `pipe2` initializes 2 descriptors per array with `O_CLOEXEC`.
    if unsafe { libc::pipe2(pid_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::pipe2(go_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        unsafe {
            libc::close(pid_pipe[0]);
            libc::close(pid_pipe[1]);
        }
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::pipe2(ack_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        unsafe {
            libc::close(pid_pipe[0]);
            libc::close(pid_pipe[1]);
            libc::close(go_pipe[0]);
            libc::close(go_pipe[1]);
        }
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::pipe2(fail_pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        unsafe {
            libc::close(pid_pipe[0]);
            libc::close(pid_pipe[1]);
            libc::close(go_pipe[0]);
            libc::close(go_pipe[1]);
            libc::close(ack_pipe[0]);
            libc::close(ack_pipe[1]);
        }
        return Err(io::Error::last_os_error());
    }

    let parent_pid = unsafe { libc::getpid() };
    // SAFETY: `P` is single-threaded; `H` immediately forks `G` and `_exit`s.
    let h_pid = unsafe { libc::fork() };
    if h_pid < 0 {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(pid_pipe[0]);
            libc::close(pid_pipe[1]);
            libc::close(go_pipe[0]);
            libc::close(go_pipe[1]);
            libc::close(ack_pipe[0]);
            libc::close(ack_pipe[1]);
            libc::close(fail_pipe[0]);
            libc::close(fail_pipe[1]);
        }
        return Err(e);
    }

    if h_pid == 0 {
        // Intermediate child `H`.  Close any inherited carrier-reaper pipe
        // write-end immediately so neither `H` nor `G` keeps the reaper alive
        // if `P` is `SIGKILL`ed before `execve` (or once `P`'s `O_CLOEXEC`
        // closes it after `execve` maps the binary).
        for img in [&prepared.rexec_image, &prepared.rexec_temp]
            .into_iter()
            .flatten()
        {
            if let Some(fd) = img.reaper_fd() {
                // SAFETY: closing an inherited descriptor inside `H`.
                unsafe { libc::close(fd) };
            }
        }
        unsafe {
            libc::close(pid_pipe[0]);
            libc::close(go_pipe[1]);
            libc::close(ack_pipe[0]);
            libc::close(fail_pipe[1]);
        }
        // SAFETY: grandchild `G` becomes our transient ptrace helper.
        let g_pid = unsafe { libc::fork() };
        if g_pid < 0 {
            let fail_pid: libc::pid_t = -1;
            write_all_raw(pid_pipe[1], &fail_pid.to_ne_bytes());
            unsafe {
                libc::close(pid_pipe[1]);
                libc::close(go_pipe[0]);
                libc::close(ack_pipe[1]);
                libc::close(fail_pipe[0]);
                libc::_exit(1);
            }
        }
        if g_pid > 0 {
            write_all_raw(pid_pipe[1], &g_pid.to_ne_bytes());
            unsafe {
                libc::close(pid_pipe[1]);
                libc::close(go_pipe[0]);
                libc::close(ack_pipe[1]);
                libc::close(fail_pipe[0]);
                libc::_exit(0);
            }
        }

        // Grandchild `G` (transient single-process tracer).
        unsafe { libc::close(pid_pipe[1]) };
        run_helper_tracer(
            parent_pid,
            prepared,
            target_kind,
            env_swapped,
            go_pipe[0],
            ack_pipe[1],
            fail_pipe[0],
            priv_file_c,
            priv_dir_c,
            done_fd,
        );
    }

    // Main process `P`.
    unsafe {
        libc::close(pid_pipe[1]);
        libc::close(go_pipe[0]);
        libc::close(ack_pipe[1]);
        libc::close(fail_pipe[0]);
    }

    let mut g_pid_bytes = [0u8; 4];
    let got_pid = read_exact_or_eof(pid_pipe[0], &mut g_pid_bytes);
    unsafe { libc::close(pid_pipe[0]) };

    // Reap intermediate child `H` BEFORE `execve` so `P` has zero zombies.
    reap_child(h_pid);

    if got_pid != 4 {
        unsafe {
            libc::close(go_pipe[1]);
            libc::close(ack_pipe[0]);
            libc::close(fail_pipe[1]);
        }
        return Err(io::Error::other("single-mode helper failed to start"));
    }
    let g_pid = libc::pid_t::from_ne_bytes(g_pid_bytes);
    if g_pid <= 0 {
        unsafe {
            libc::close(go_pipe[1]);
            libc::close(ack_pipe[0]);
            libc::close(fail_pipe[1]);
        }
        return Err(io::Error::other("single-mode helper fork failed"));
    }

    // Apply untraced pre-exec setup before signaling `G` to seize us:
    // - Clear `FD_CLOEXEC` on caller-preserved `--secret-fd` descriptors.
    // - Set `comm` early, ensure `P` is dumpable for the microsecond seize
    //   window (G re-applies `PR_SET_DUMPABLE=0` at `PTRACE_EVENT_EXEC`),
    //   grant Yama `PR_SET_PTRACER`, and unblock `G`.
    unsafe {
        for &fd in &prepared.preserved_fds {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 && (flags & libc::FD_CLOEXEC) != 0 {
                libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            }
        }
        libc::prctl(
            libc::PR_SET_NAME,
            prepared.comm_z.as_ptr() as libc::c_ulong,
            0,
            0,
            0,
        );
        libc::prctl(libc::PR_SET_DUMPABLE, 1 as libc::c_ulong, 0, 0, 0);
        // Allow `G` to trace `P` even under `kernel.yama.ptrace_scope = 1`.
        // Ignore `EINVAL` on kernels without Yama.
        libc::prctl(PR_SET_PTRACER, g_pid as libc::c_ulong, 0, 0, 0);
        // Unblock `G`.
        libc::close(go_pipe[1]);
    }

    // Read a single tag byte: `b'K'` means `G` seized `P` with
    // `PTRACE_O_TRACEEXEC` and is already waiting for `PTRACE_EVENT_EXEC`.
    let mut tag = [0u8; 1];
    let got_tag = read_exact_or_eof(ack_pipe[0], &mut tag);
    if got_tag == 0 {
        unsafe {
            libc::close(ack_pipe[0]);
            libc::close(fail_pipe[1]);
        }
        return Err(ptrace_refused_error(libc::EPERM));
    }
    if tag[0] == b'E' {
        let mut eb = [0u8; 4];
        let got_eb = read_exact_or_eof(ack_pipe[0], &mut eb);
        unsafe {
            libc::close(ack_pipe[0]);
            libc::close(fail_pipe[1]);
        }
        let errno = if got_eb == 4 {
            i32::from_ne_bytes(eb)
        } else {
            libc::EPERM
        };
        return Err(ptrace_refused_error(errno));
    }
    if tag[0] != b'K' {
        unsafe {
            libc::close(ack_pipe[0]);
            libc::close(fail_pipe[1]);
        }
        return Err(ptrace_refused_error(libc::EPERM));
    }

    let exec_argv = if target_kind == SingleTargetKind::Native64 {
        sw_argv_ptr.as_ptr()
    } else {
        prepared.argv_ptr.as_ptr()
    };
    let exec_envp = if target_kind == SingleTargetKind::Native64 {
        sw_envp_ptr.as_ptr()
    } else {
        prepared.envp_ptr.as_ptr()
    };

    // `P` is seized by `G` with `PTRACE_O_TRACEEXEC`.  Go straight into
    // `execve`/`execveat` with zero `PTRACE_SYSCALL` entry stops.
    let mut ack_open = true;
    unsafe {
        if let Some((uid, gid)) = prepared.run_as {
            if libc::setgroups(0, std::ptr::null()) == -1
                || libc::setgid(gid as libc::gid_t) == -1
                || libc::setuid(uid as libc::uid_t) == -1
            {
                let err = io::Error::last_os_error();
                signal_helper_detach(fail_pipe[1]);
                libc::close(fail_pipe[1]);
                libc::close(ack_pipe[0]);
                return Ok(err);
            }
        }
        if !prepared.secret_fds.is_empty() {
            // Close `ack_pipe[0]` and move `fail_pipe[1]` above the secret-fd
            // range before `install_fds` so `dup2` cannot collide with them.
            libc::close(ack_pipe[0]);
            ack_open = false;
            let min_fd = min_helper_fd(&prepared.preserved_fds, prepared.secret_fds.len());
            match move_fd_above(fail_pipe[1], min_fd) {
                Ok(hi) => fail_pipe[1] = hi,
                Err(err) => {
                    signal_helper_detach(fail_pipe[1]);
                    libc::close(fail_pipe[1]);
                    return Err(err);
                }
            }
            crate::secret::install_fds(&prepared.secret_fds, false);
        }

        match target {
            ExecTarget::Path(path_ptr) => {
                libc::execve(path_ptr, exec_argv, exec_envp);
            }
            ExecTarget::Memfd(fd) => {
                let empty: [u8; 1] = [0];
                libc::syscall(
                    libc::SYS_execveat,
                    fd as libc::c_long,
                    empty.as_ptr(),
                    exec_argv,
                    exec_envp,
                    AT_EMPTY_PATH,
                );
            }
        }
        let err = io::Error::last_os_error();
        // Signal `G` to detach cleanly (without delivering `SIGTRAP`) before
        // returning the exec error to `P`.
        signal_helper_detach(fail_pipe[1]);
        libc::close(fail_pipe[1]);
        if ack_open {
            libc::close(ack_pipe[0]);
        }
        Ok(err)
    }
}

/// Body of the transient grandchild helper `G`.  Never returns.
#[allow(clippy::too_many_arguments)]
fn run_helper_tracer(
    parent_pid: libc::pid_t,
    prepared: &Prepared,
    target_kind: SingleTargetKind,
    env_swapped: bool,
    go_r: RawFd,
    ack_w: RawFd,
    fail_r: RawFd,
    priv_file_c: Option<&CString>,
    priv_dir_c: Option<&CString>,
    done_fd: Option<RawFd>,
) -> ! {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0);
        libc::prctl(
            libc::PR_SET_NAME,
            prepared.comm_z.as_ptr() as libc::c_ulong,
            0,
            0,
            0,
        );
    }

    // Redirect stdin/stdout (and stderr when quiet) to `/dev/null` and close
    // all unrelated descriptors >= 3 so `G` never holds caller pipes, secret
    // fds, or memfd handles open.
    harden_helper_fds(go_r, ack_w, fail_r, done_fd, prepared.cfg.quiet);

    // Build `Tracer` while `P` is reaping `H` so there are zero allocations
    // on the critical path after `PTRACE_SEIZE`.
    let mut tracer = Tracer::new(prepared.cfg.clone());
    // Single helper owns staged cleanup on its own path; prevent `Tracer::drop`
    // from racing a recoverable `execve` failure where `P` still owns `Image`.
    tracer.cfg.staged_private_path = None;
    match target_kind {
        SingleTargetKind::Native64 => {
            let real_argv: Vec<Vec<u8>> = prepared
                .argv_c
                .iter()
                .map(|c| c.as_bytes().to_vec())
                .collect();
            let real_envp: Vec<Vec<u8>> = prepared
                .envp_c
                .iter()
                .map(|c| c.as_bytes().to_vec())
                .collect();
            tracer.register_single_swapped(parent_pid, real_argv, real_envp, env_swapped);
        }
        SingleTargetKind::Foreign32 => {
            tracer.register_single_foreign(parent_pid);
        }
        SingleTargetKind::Script => {
            tracer.register_single_script(parent_pid);
        }
    }

    // Wait for `P` to finish `waitpid(H)` and `prctl(PR_SET_PTRACER, G)`.
    wait_pipe_eof(go_r);
    unsafe { libc::close(go_r) };

    let opts: libc::c_long =
        (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_TRACESYSGOOD) as libc::c_long;
    // SAFETY: seizing `parent_pid` which granted us `PR_SET_PTRACER`.
    // `PTRACE_SEIZE` attaches WITHOUT stopping `P`, eliminating both the
    // `PTRACE_INTERRUPT` stop and the `execve` entry stop.
    let rc = unsafe {
        libc::ptrace(
            arch::PTRACE_SEIZE as _,
            parent_pid,
            std::ptr::null_mut::<libc::c_void>(),
            opts as *mut libc::c_void,
        )
    };
    if rc == -1 {
        let e = last_errno();
        if e == libc::ESRCH {
            // `P` died (e.g. `SIGKILL`) before seize: clean up staged files.
            unlink_staged_paths(priv_file_c, priv_dir_c);
        }
        let eb = e.to_ne_bytes();
        write_all_raw(ack_w, &[b'E', eb[0], eb[1], eb[2], eb[3]]);
        unsafe {
            libc::close(ack_w);
            libc::close(fail_r);
            if let Some(fd) = done_fd {
                libc::close(fd);
            }
            libc::_exit(1);
        }
    }

    // Signal `P` that seizing succeeded (`P` is already running, ready for exec).
    write_all_raw(ack_w, b"K");
    unsafe { libc::close(ack_w) };

    const PTRACE_EVENT_EXEC: u32 = 4;
    let mut exec_failed_detached = false;
    while let Ok((_, status)) = inject::wait_stop(parent_pid) {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            break;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let sig = libc::WSTOPSIG(status);
        let event = (status as u32) >> 16;

        if sig == libc::SIGTRAP && event == PTRACE_EVENT_EXEC {
            unsafe { libc::close(fail_r) };
            finish_single_exec(&mut tracer, parent_pid, priv_file_c, priv_dir_c, done_fd);
        }

        if sig == libc::SIGTRAP && event == 0 {
            let mut fb = [0u8; 1];
            // SAFETY: non-blocking 1-byte read from `fail_r`.
            let n = unsafe { libc::read(fail_r, fb.as_mut_ptr().cast(), 1) };
            if n == 1 && fb[0] == b'F' {
                // `execve`/`execveat` returned an error in `P`: detach cleanly
                // without delivering `SIGTRAP` so `P` receives the exact errno.
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_DETACH,
                        parent_pid,
                        std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>(),
                    );
                }
                exec_failed_detached = true;
                break;
            }
            let _ = inject::ptrace_cont(parent_pid, sig);
            continue;
        }

        if event == arch::PTRACE_EVENT_STOP {
            let deliver = if sig == libc::SIGTRAP {
                0
            } else {
                libc::SIGCONT
            };
            let _ = inject::ptrace_cont(parent_pid, deliver);
            continue;
        }

        // Forward real signals to `parent_pid`.
        let _ = inject::ptrace_cont(parent_pid, sig);
    }

    if !exec_failed_detached {
        // `P` exited or was killed (e.g. `SIGKILL`) before `PTRACE_EVENT_EXEC`:
        // remove any staged `RexecMode::Path` file + `.rt-*` dir so zero
        // leftovers remain on disk.
        unlink_staged_paths(priv_file_c, priv_dir_c);
    }

    drop(tracer);
    unsafe {
        libc::close(fail_r);
        if let Some(fd) = done_fd {
            libc::close(fd);
        }
        libc::_exit(0);
    }
}

/// Complete exec redaction, remove any staged private path, detach `P`,
/// zeroize buffers, and `_exit(0)`.
fn finish_single_exec(
    tracer: &mut Tracer,
    parent_pid: libc::pid_t,
    priv_file_c: Option<&CString>,
    priv_dir_c: Option<&CString>,
    done_fd: Option<RawFd>,
) -> ! {
    let (killed_foreign, pending_stop) = tracer.on_exec_complete_single(parent_pid);

    // Unlink any staged `RexecMode::Path` file + empty `0700` dir right after
    // `PTRACE_EVENT_EXEC` so zero files are left on disk even if `P` is later
    // killed with `SIGKILL`.
    unlink_staged_paths(priv_file_c, priv_dir_c);

    if killed_foreign {
        let _ = inject::ptrace_cont(parent_pid, 0);
    } else {
        // SAFETY: `parent_pid` is stopped in our ptrace session.
        unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                parent_pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            );
        }
        if let Some(psig) = pending_stop {
            // SAFETY: re-raise group-stop signal that arrived during injection.
            unsafe { libc::kill(parent_pid, psig) };
        }
    }

    // Explicitly zeroize and drop scratch/key references before `_exit`.
    if let Some(t) = tracer.table.get_mut(&parent_pid) {
        t.clear_exec_state();
    }
    unsafe {
        if let Some(fd) = done_fd {
            libc::close(fd);
        }
        libc::_exit(0);
    }
}

/// Redirect stdin/stdout (and stderr if `quiet`) to `/dev/null` and close all
/// extra descriptors >= 3 except the helper's own pipe descriptors.
fn harden_helper_fds(
    go_r: RawFd,
    ack_w: RawFd,
    fail_r: RawFd,
    done_fd: Option<RawFd>,
    quiet: bool,
) {
    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        let max_std = if quiet { 2 } else { 1 };
        if devnull >= 0 {
            for std_fd in 0..=max_std {
                if std_fd != go_r
                    && std_fd != ack_w
                    && std_fd != fail_r
                    && done_fd != Some(std_fd)
                    && devnull != std_fd
                {
                    libc::dup2(devnull, std_fd);
                }
            }
            if devnull > 2
                && devnull != go_r
                && devnull != ack_w
                && devnull != fail_r
                && done_fd != Some(devnull)
            {
                libc::close(devnull);
            }
        }
        // Collect sorted list of fds >= 3 to keep open.
        let mut keep = [0 as RawFd; 4];
        let mut nkeep = 0usize;
        for fd in [Some(go_r), Some(ack_w), Some(fail_r), done_fd]
            .into_iter()
            .flatten()
        {
            if fd >= 3 {
                keep[nkeep] = fd;
                nkeep += 1;
            }
        }
        keep[..nkeep].sort_unstable();

        // Try `close_range` over each gap between kept fds.
        let mut ok = true;
        let mut start: usize = 3;
        for &k in &keep[..nkeep] {
            let ku = k as usize;
            if ku > start && libc::syscall(SYS_CLOSE_RANGE, start, ku - 1, 0usize) != 0 {
                ok = false;
                break;
            }
            start = ku.saturating_add(1);
        }
        if ok && libc::syscall(SYS_CLOSE_RANGE, start, u32::MAX as usize, 0usize) != 0 {
            ok = false;
        }
        if !ok {
            for fd in 3..1024 {
                if !keep[..nkeep].contains(&fd) {
                    libc::close(fd);
                }
            }
        }
    }
}

/// Signal the transient helper `G` that `execve`/`setuid` failed and trigger
/// a clean detach stop, temporarily unblocking `SIGTRAP` in case the caller
/// masked it.
unsafe fn signal_helper_detach(fail_fd: RawFd) {
    write_all_raw(fail_fd, b"F");
    let mut trap_set: libc::sigset_t = std::mem::zeroed();
    let mut old_set: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut trap_set);
    libc::sigaddset(&mut trap_set, libc::SIGTRAP);
    let unblocked = libc::sigprocmask(libc::SIG_UNBLOCK, &trap_set, &mut old_set) == 0;
    libc::raise(libc::SIGTRAP);
    if unblocked {
        libc::sigprocmask(libc::SIG_SETMASK, &old_set, std::ptr::null_mut());
    }
}

fn min_helper_fd(preserved_fds: &[libc::c_int], secret_fd_count: usize) -> RawFd {
    let max_preserved = preserved_fds.iter().copied().max().unwrap_or(0);
    let max_secret = crate::secret::FIRST_FD.saturating_add(secret_fd_count as libc::c_int);
    max_preserved.max(max_secret).saturating_add(1).max(3)
}

fn move_fd_above(fd: RawFd, min_fd: RawFd) -> io::Result<RawFd> {
    if fd >= min_fd {
        return Ok(fd);
    }
    // SAFETY: duplicating our own descriptor with `O_CLOEXEC`.
    let hi = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min_fd) };
    if hi < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` has been duplicated to `hi`.
    unsafe { libc::close(fd) };
    Ok(hi)
}

fn reap_child(pid: libc::pid_t) {
    let mut status = 0i32;
    loop {
        // SAFETY: reaping our own child process.
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        if w == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
}

fn wait_pipe_eof(fd: RawFd) {
    let mut b = [0u8; 1];
    loop {
        // SAFETY: reading 1 byte from our own pipe end.
        let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), 1) };
        if n < 0 && last_errno() == libc::EINTR {
            continue;
        }
        if n <= 0 {
            break;
        }
    }
}

fn read_exact_or_eof(fd: RawFd, buf: &mut [u8]) -> usize {
    let mut have = 0usize;
    while have < buf.len() {
        // SAFETY: reading into our owned buffer slice.
        let n = unsafe { libc::read(fd, buf[have..].as_mut_ptr().cast(), buf.len() - have) };
        if n < 0 {
            if last_errno() == libc::EINTR {
                continue;
            }
            break;
        }
        if n == 0 {
            break;
        }
        have += n as usize;
    }
    have
}

fn write_all_raw(fd: RawFd, data: &[u8]) {
    let mut off = 0usize;
    while off < data.len() {
        // SAFETY: writing from our owned byte slice.
        let n = unsafe { libc::write(fd, data[off..].as_ptr().cast(), data.len() - off) };
        if n < 0 {
            if last_errno() == libc::EINTR {
                continue;
            }
            break;
        }
        if n == 0 {
            break;
        }
        off += n as usize;
    }
}

fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Caps;
    use crate::mask::RexecMode;
    use std::path::PathBuf;

    /// Fork a child that runs `exec_single` and capture its stdout + exit code.
    fn run_in_forked_child<F>(f: F) -> (libc::pid_t, i32, String)
    where
        F: FnOnce(),
    {
        let mut out_pipe = [0 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::pipe2(out_pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(out_pipe[0]);
                libc::dup2(out_pipe[1], 1);
                libc::close(out_pipe[1]);
            }
            f();
            unsafe { libc::_exit(99) };
        }
        unsafe { libc::close(out_pipe[1]) };
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = unsafe { libc::read(out_pipe[0], chunk.as_mut_ptr().cast(), chunk.len()) };
            if n <= 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n as usize]);
        }
        unsafe { libc::close(out_pipe[0]) };
        let mut status = 0i32;
        loop {
            let w = unsafe { libc::waitpid(pid, &mut status, 0) };
            if w == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            128 + libc::WTERMSIG(status)
        };
        (pid, code, String::from_utf8_lossy(&buf).into_owned())
    }

    #[test]
    fn single_options_builder() {
        let o = SingleOptions::new().reparent(true);
        assert!(o.reparent);
        assert!(!SingleOptions::default().reparent);
    }

    #[test]
    fn exec_single_rejects_watch_rename() {
        let mask = Mask::new()
            .label("worker")
            .watch_rename()
            .session_end(crate::SessionEnd::WaitTree);
        let err = exec_single(&mask, OsStr::new("/bin/true"), &[], false)
            .expect_err("watch_rename must be rejected in single mode");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn exec_single_missing_binary_returns_enoent() {
        if !Caps::ptrace_usable_fast() {
            eprintln!("skip: ptrace unavailable");
            return;
        }
        // Run inside a forked child so the test does not toggle PR_SET_DUMPABLE
        // on the shared cargo test runner process.
        let (_, code, _) = run_in_forked_child(|| {
            let mask = Mask::new().label("worker").quiet();
            let err = exec_single(
                &mask,
                OsStr::new("/nonexistent/pmask-single-missing-bin"),
                &[],
                false,
            )
            .expect_err("missing binary must fail");
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
            assert!(!is_ptrace_refused(&err));
            unsafe { libc::_exit(0) };
        });
        assert_eq!(code, 0);
    }

    #[test]
    fn exec_single_inplace_masks_cmdline_comm_environ_and_detaches() {
        if !Caps::ptrace_usable_fast() {
            eprintln!("skip: ptrace unavailable");
            return;
        }
        // Inspect `/proc/$$/...` (the shell itself, NOT `/proc/self` of `cat`/`tr`).
        let script = concat!(
            "printf 'PID=%s\\n' \"$$\";",
            "printf 'ARG1=%s\\n' \"$1\";",
            "printf 'ENV=%s\\n' \"$SINGLE_TEST_SECRET\";",
            "printf 'COMM=%s\\n' \"$(cat /proc/$$/comm)\";",
            "printf 'CMD=%s\\n' \"$(tr '\\0' '|' < /proc/$$/cmdline)\";",
            "printf 'ENVPROC=%s\\n' \"$(tr '\\0' '|' < /proc/$$/environ)\";",
            "awk '/^(TracerPid|Threads|Seccomp|NoNewPrivs):/{print $1 $2}' /proc/$$/status"
        );
        let (child_pid, code, out) = run_in_forked_child(|| {
            let mask = Mask::new()
                .label("single-worker")
                .env("SINGLE_TEST_SECRET", "ENV_CANARY_9876")
                .quiet();
            let args = [
                OsString::from("-c"),
                OsString::from(script),
                OsString::from("_"),
                OsString::from("ARGV_CANARY_1234"),
            ];
            let _ = exec_single(&mask, OsStr::new("/bin/sh"), &args, false);
            unsafe { libc::_exit(126) };
        });
        assert_eq!(code, 0, "output:\n{}", out);
        assert!(
            out.contains(&format!("PID={}\n", child_pid)),
            "must exec IN PLACE with the exact child pid:\n{}",
            out
        );
        assert!(out.contains("ARG1=ARGV_CANARY_1234\n"), "{}", out);
        assert!(out.contains("ENV=ENV_CANARY_9876\n"), "{}", out);
        assert!(out.contains("COMM=single-worker\n"), "{}", out);
        assert!(out.contains("CMD=single-worker|\n"), "{}", out);
        assert!(
            !out.contains("CMD=single-worker|ARGV_CANARY_1234"),
            "{}",
            out
        );
        assert!(
            !out.lines()
                .any(|l| l.starts_with("ENVPROC=") && l.contains("ENV_CANARY_9876")),
            "environ leaked secret:\n{}",
            out
        );
        assert!(out.contains("TracerPid:0\n"), "{}", out);
        assert!(out.contains("Threads:1\n"), "{}", out);
    }

    #[test]
    fn exec_single_rexec_path_has_no_memfd_and_cleans_up_staged_file() {
        if !Caps::ptrace_usable_fast() {
            eprintln!("skip: ptrace unavailable");
            return;
        }
        let script = "printf 'EXE=%s\\n' \"$(readlink /proc/$$/exe)\"";
        let (_, code, out) = run_in_forked_child(|| {
            let mask = Mask::new()
                .label("path-worker")
                .rexec()
                .rexec_mode(RexecMode::Path)
                .quiet();
            let args = [OsString::from("-c"), OsString::from(script)];
            let _ = exec_single(&mask, OsStr::new("/bin/sh"), &args, false);
            unsafe { libc::_exit(126) };
        });
        assert_eq!(code, 0, "output:\n{}", out);
        let exe_line = out
            .lines()
            .find_map(|l| l.strip_prefix("EXE="))
            .expect("EXE line");
        assert!(
            !exe_line.starts_with("/memfd:"),
            "RexecMode::Path must not have /memfd: prefix: {}",
            exe_line
        );
        assert!(
            exe_line.contains("path-worker"),
            "exe should carry sanitized label: {}",
            exe_line
        );
        // Strip trailing " (deleted)" if present and verify neither the file nor
        // its parent `.rt-*` dir remains on disk.
        let raw_path = exe_line.strip_suffix(" (deleted)").unwrap_or(exe_line);
        let p = PathBuf::from(raw_path);
        assert!(!p.exists(), "staged file leaked on disk: {}", raw_path);
        if let Some(parent) = p.parent() {
            if parent
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.starts_with(".rt-"))
            {
                assert!(
                    !parent.exists(),
                    "private staging dir leaked on disk: {}",
                    parent.display()
                );
            }
        }
    }

    #[test]
    fn exec_single_no_dumpable_sets_rlimit_core_zero_and_encrypt_memory_works() {
        if !Caps::ptrace_usable_fast() {
            eprintln!("skip: ptrace unavailable");
            return;
        }
        let script = concat!(
            "printf 'ARG=%s\\n' \"$1\";",
            "grep 'Max core file size' /proc/$$/limits;",
            "grep '^TracerPid:' /proc/$$/status"
        );
        let (_, code, out) = run_in_forked_child(|| {
            let mask = Mask::new()
                .label("hardened-worker")
                .no_dumpable()
                .encrypt_memory(true)
                .quiet();
            let args = [
                OsString::from("-c"),
                OsString::from(script),
                OsString::from("_"),
                OsString::from("ENCRYPTED_ARG_OK"),
            ];
            let _ = exec_single(&mask, OsStr::new("/bin/sh"), &args, false);
            unsafe { libc::_exit(126) };
        });
        assert_eq!(code, 0, "output:\n{}", out);
        assert!(out.contains("ARG=ENCRYPTED_ARG_OK\n"), "{}", out);
        let core_line = out
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .expect("limits line");
        let nums: Vec<&str> = core_line
            .trim_start_matches("Max core file size")
            .split_whitespace()
            .collect();
        assert_eq!(nums.get(0..2), Some(["0", "0"].as_slice()), "{}", core_line);
        assert!(out.contains("TracerPid:\t0"), "{}", out);
    }

    #[test]
    fn exec_single_shebang_script_is_masked_cleanly() {
        if !Caps::ptrace_usable_fast() {
            eprintln!("skip: ptrace unavailable");
            return;
        }
        let script_path =
            std::env::temp_dir().join(format!("pmask-single-shebang-{}.sh", std::process::id()));
        std::fs::write(
            &script_path,
            "#!/bin/sh\nprintf 'ARG=%s\\nCOMM=%s\\nCMD=%s\\n' \"$1\" \"$(cat /proc/$$/comm)\" \"$(tr '\\0' '|' < /proc/$$/cmdline)\"\n",
        )
        .expect("write script");
        // SAFETY: setting 0o700 on our own temp script.
        let c = CString::new(script_path.as_os_str().as_bytes()).expect("no nul");
        unsafe { libc::chmod(c.as_ptr(), 0o700) };

        let (_, code, out) = run_in_forked_child(|| {
            let mask = Mask::new().label("script-worker").quiet();
            let args = [OsString::from("SHEBANG_SECRET_ARG")];
            let _ = exec_single(&mask, script_path.as_os_str(), &args, false);
            unsafe { libc::_exit(126) };
        });
        let _ = std::fs::remove_file(&script_path);
        assert_eq!(code, 0, "output:\n{}", out);
        assert!(out.contains("ARG=SHEBANG_SECRET_ARG\n"), "{}", out);
        assert!(out.contains("COMM=script-worker\n"), "{}", out);
        assert!(out.contains("CMD=script-worker|\n"), "{}", out);
        assert!(
            !out.contains("CMD=script-worker|SHEBANG_SECRET_ARG"),
            "{}",
            out
        );
    }

    #[test]
    fn exec_single_cwd_and_secret_fd_preserved() {
        if !Caps::ptrace_usable_fast() {
            eprintln!("skip: ptrace unavailable");
            return;
        }
        let (_, code, out) = run_in_forked_child(|| {
            let mut p = [0 as libc::c_int; 2];
            assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            write_all_raw(p[1], b"FD_SECRET_PAYLOAD");
            unsafe { libc::close(p[1]) };
            let secret_fd = move_fd_above(p[0], 11).expect("move_fd_above");
            let script = format!(
                "printf 'PWD=%s\\nFD=%s\\n' \"$(pwd)\" \"$(cat /proc/self/fd/{})\"",
                secret_fd
            );
            let mask = Mask::new()
                .label("cwd-worker")
                .cwd("/tmp")
                .secret_fd(secret_fd)
                .quiet();
            let args = [OsString::from("-c"), OsString::from(script)];
            let _ = exec_single(&mask, OsStr::new("/bin/sh"), &args, false);
            unsafe { libc::_exit(126) };
        });
        assert_eq!(code, 0, "output:\n{}", out);
        assert!(out.contains("PWD=/tmp\n"), "{}", out);
        assert!(out.contains("FD=FD_SECRET_PAYLOAD\n"), "{}", out);
    }

    #[test]
    fn exec_single_reparent_launches_and_detaches() {
        if !Caps::ptrace_usable_fast() {
            eprintln!("skip: ptrace unavailable");
            return;
        }
        let out_file =
            std::env::temp_dir().join(format!("pmask-reparent-test-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&out_file);
        let script = format!(
            "printf '%s:%s:%s\\n' \"$PPID\" \"$(cat /proc/$$/comm)\" \"$(awk '/^TracerPid:/{{print $2}}' /proc/$$/status)\" > '{}'",
            out_file.display()
        );
        let mask = Mask::new().label("reparent-worker").quiet();
        let args = [OsString::from("-c"), OsString::from(script)];
        let st = exec_single(&mask, OsStr::new("/bin/sh"), &args, true)
            .expect("reparented launch must succeed");
        assert_eq!(st.code, 0);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut content = String::new();
        while std::time::Instant::now() < deadline {
            if let Ok(s) = std::fs::read_to_string(&out_file) {
                if !s.is_empty() {
                    content = s;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = std::fs::remove_file(&out_file);
        assert!(
            content.ends_with(":reparent-worker:0\n"),
            "unexpected reparent output: {:?}",
            content
        );
        let ppid: u32 = content
            .split(':')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        assert_ne!(
            ppid,
            std::process::id(),
            "reparented payload must not have test runner as ppid"
        );
    }

    #[test]
    fn min_helper_fd_avoids_arbitrary_floor_and_collisions() {
        assert_eq!(min_helper_fd(&[], 0), crate::secret::FIRST_FD + 1);
        assert_eq!(min_helper_fd(&[], 4), crate::secret::FIRST_FD + 4 + 1);
        assert_eq!(min_helper_fd(&[11, 7], 2), 12);
    }

    #[test]
    fn exec_single_strict_exec_refuses_script_before_forking() {
        let script_path = std::env::temp_dir().join(format!(
            "pmask-single-strict-script-{}.sh",
            std::process::id()
        ));
        std::fs::write(&script_path, "#!/bin/sh\nexit 0\n").expect("write script");
        let c = CString::new(script_path.as_os_str().as_bytes()).expect("no nul");
        unsafe { libc::chmod(c.as_ptr(), 0o700) };

        let mask = Mask::new().label("strict-worker").strict_exec().quiet();
        let err = exec_single(&mask, script_path.as_os_str(), &[], false)
            .expect_err("--strict-exec must refuse script in single profile");
        let _ = std::fs::remove_file(&script_path);
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("--strict-exec"), "{}", err);
    }
}
