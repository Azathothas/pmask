//! Program images for `--rexec`: a sealed memfd, a hugetlb memfd, or an
//! unlinked temporary file on a filesystem that allows execution.
//!
//! `prepare` opens the program, checks the ELF magic, copies the bytes into
//! a memfd, and adds all four seals.  The caller then runs
//! `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`.
//! `/proc/<pid>/exe` then shows `/memfd:<name>` and the maps show no
//! on-disk path.
//!
//! # Fallback carriers
//!
//! A kernel can refuse the descriptor exec (`vm.memfd_noexec`, a seccomp
//! filter).  The child then tries `/proc/self/fd/N` with an ordinary
//! `execve`, and finally a temporary file in a directory whose mount
//! allows execution.  [`prepare_temp`] builds that carrier in the parent,
//! before the fork, so the child only has to exec it.  The on-disk path
//! is never used unless the caller asks for it explicitly.
//!
//! # Limits
//!
//! - `/proc/<pid>/map_files` still resolves the mapped file.
//! - The kernel copies the whole file.  A large binary costs memory.
//! - Only ELF files work.  A script needs the interpreter to open the path
//!   of a close-on-exec descriptor, which fails.  `prepare` refuses such
//!   input.
//! - A kernel with `vm.memfd_noexec` hardening can refuse `memfd_create` or
//!   the later exec.  `prepare` returns the kernel error in that case.
//! - Tools that look for `memfd:` executables can flag the process.  The
//!   label sets the memfd name by default; `--memfd-name NAME` replaces it
//!   with any name that passes [`crate::mem::validate_memfd_name`], so a
//!   run can carry an opaque `/memfd:secret-1a2b3c4d` instead of the label.
//!
//! The memfd keeps `FD_CLOEXEC`.  The fd stays open across `fork` and closes
//! at the exec.  The `Image` type closes the fd on drop.

use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const F_ADD_SEALS: libc::c_int = 1033; // F_LINUX_SPECIFIC_BASE + 9
const F_SEAL_SEAL: libc::c_int = 1;
const F_SEAL_SHRINK: libc::c_int = 2;
const F_SEAL_GROW: libc::c_int = 4;
const F_SEAL_WRITE: libc::c_int = 8;

const MFD_CLOEXEC: libc::c_uint = 1;
const MFD_ALLOW_SEALING: libc::c_uint = 2;
const MFD_HUGETLB: libc::c_uint = 0x0004;
const MFD_HUGE_2MB: libc::c_uint = 21 << 26;

/// The 2 MiB huge page size this module asks for.
pub const HUGETLB_PAGE: u64 = 2 * 1024 * 1024;

/// Longest memfd name that the kernel accepts, without the NUL byte.
const MEMFD_NAME_MAX: usize = 249;

/// Highest descriptor the image is moved to, so the secret install at 3,
/// 4, ... cannot clobber it before the exec.
const IMAGE_FD_MIN: RawFd = 200;

/// Carrier mode for `--rexec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RexecMode {
    /// Sealed anonymous `memfd_create` image (`execveat(AT_EMPTY_PATH)`).
    #[default]
    Memfd,
    /// Private `0500` executable copy named `<sanitized_label>` inside a
    /// private `0700` staging directory (`$XDG_RUNTIME_DIR`, `/dev/shm`,
    /// or `/tmp`), leaving zero `/memfd:` fingerprint in `exe` and `maps`.
    Path,
    /// Unnamed `O_TMPFILE` executable on an executable mount executed via
    /// `execveat(fd, "", AT_EMPTY_PATH)`: zero directory entry is ever
    /// linked on disk (immune to `SIGKILL` at any microsecond) and zero
    /// `/memfd:` fingerprint.
    Tmpfile,
    /// Prefer [`RexecMode::Path`] when a writable executable staging
    /// directory is available; otherwise fall back to [`RexecMode::Memfd`].
    Auto,
}

/// A sealed program image.
#[derive(Debug)]
pub struct Image {
    /// The descriptor.  `Image` closes it on drop.
    pub fd: RawFd,
    /// What holds the bytes.
    pub backing: Backing,
    /// A line the caller must show at the default verbosity, when the
    /// requested backing was not available.
    pub note: Option<String>,
    /// The named temporary file, when the carrier needed a name.
    pub path: Option<PathBuf>,
    /// Private `0700` staging directory created for [`RexecMode::Path`],
    /// removed after [`Self::path`] is unlinked.
    pub private_dir: Option<PathBuf>,
    /// `(ctime, ctime_nsec)` of the carrier inode at the moment its bytes
    /// were finished.  A same-uid writer can rewrite the named carrier in
    /// place without changing its device, inode or length, and both readers
    /// in `verify_carrier` then see the same modified bytes; the status
    /// change time is the only record that the bytes moved.  An unprivileged
    /// writer cannot set it back.
    pub stamp: Option<(i64, i64)>,
    /// Write end of the carrier reaper pipe, when a named carrier spawned a
    /// double-forked reaper.  Closing it on drop signals the reaper to
    /// unlink the carrier (if still present) and exit cleanly.
    pub(crate) reaper_fd: Option<RawFd>,
}

impl Image {
    /// Spawn and attach a double-forked reaper for a named carrier path (and
    /// optional private staging directory) if one is not already attached.
    pub fn attach_reaper(&mut self) -> io::Result<()> {
        if self.reaper_fd.is_some() {
            return Ok(());
        }
        let Some(ref p) = self.path else {
            return Ok(());
        };
        let wr = spawn_carrier_reaper(p, self.private_dir.as_deref())?;
        self.reaper_fd = Some(wr);
        Ok(())
    }

    /// Return the attached reaper pipe write descriptor, if any.
    pub fn reaper_fd(&self) -> Option<RawFd> {
        self.reaper_fd
    }

    /// Take ownership of the reaper pipe write descriptor, disarming
    /// `Image::drop` from closing it.
    pub fn take_reaper_fd(&mut self) -> Option<RawFd> {
        self.reaper_fd.take()
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: the descriptor is owned by this value.
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
        if let Some(dir) = &self.private_dir {
            let _ = std::fs::remove_dir(dir);
        }
        if let Some(wr) = self.reaper_fd.take() {
            if wr >= 0 {
                // SAFETY: the reaper pipe write end is owned by this value.
                unsafe {
                    libc::close(wr);
                }
            }
        }
    }
}

/// What backs a prepared image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backing {
    /// An ordinary `memfd_create` file.
    Memfd,
    /// A hugetlbfs-backed memfd, with the page size in bytes.
    HugeTlb { page_size: u64 },
    /// An `O_TMPFILE` or named temporary file on an executable mount.
    TempFile { dir: PathBuf, named: bool },
    /// A private `0500` copy inside a private `0700` directory ([`RexecMode::Path`]).
    PrivatePath { dir: PathBuf },
}

impl Backing {
    /// One word for a report line.
    pub fn describe(&self) -> String {
        match self {
            Backing::Memfd => "memfd".to_string(),
            Backing::HugeTlb { page_size } => {
                format!("hugetlb {} KiB pages", page_size / 1024)
            }
            Backing::TempFile { dir, named } => {
                if *named {
                    format!("named temporary file in {}", dir.display())
                } else {
                    format!("O_TMPFILE in {}", dir.display())
                }
            }
            Backing::PrivatePath { dir } => {
                format!("private path in {}", dir.display())
            }
        }
    }
}

/// Where the image bytes come from.
#[derive(Debug, Clone)]
pub enum Source {
    /// Read a path.
    Path(std::ffi::OsString),
    /// Read an open descriptor from its current offset.  The descriptor
    /// is not closed.
    Fd(RawFd),
    /// Read standard input to end of file.
    Stdin,
}

/// Knobs for one image.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Ask for a hugetlbfs-backed memfd.
    pub hugetlb: bool,
    /// Name the image memfd this instead of the label (`--memfd-name`).
    ///
    /// `None` keeps the historical behaviour: the presentation label,
    /// sanitised by [`sanitize_name`].  `Some` is validated by the caller
    /// when the option is parsed and re-validated by [`create_image`], so
    /// a name that reaches this field through the library API is checked
    /// too.  The memfd carriers use it as given.  The temporary-file
    /// carrier has to stay one path component, so its tag is the same
    /// name sanitised and cut to 64 bytes.
    pub memfd_name: Option<String>,
    /// Avoid staging private path carriers under `/tmp` (required when the
    /// child mounts a fresh private `tmpfs` over `/tmp` before `execve`, such
    /// as `--profile tee` or `--redact --isolate=tmp`).
    pub avoid_tmp: bool,
    /// Target `(uid, gid)` when dropping privileges (`Mask::run_as`).  When
    /// `geteuid() == 0` and `uid != 0`, `Source::Path` is opened under
    /// thread-local `setfsuid`/`setfsgid` and validated as a non-setuid,
    /// executable regular file so root never stages a root-only binary.
    pub run_as: Option<(u32, u32)>,
}

impl Options {
    /// The memfd name a new image gets for `label`.
    ///
    /// The temporary-file carrier derives its tag from the same string, so
    /// a caller who chose an opaque name gets an opaque carrier too; the
    /// tag is sanitised and cut to 64 bytes because it is one path
    /// component.
    pub fn image_name(&self, label: &str) -> String {
        match &self.memfd_name {
            Some(n) => n.clone(),
            None => sanitize_name(label),
        }
    }
}

/// Turn a label into a memfd name: printable ASCII except `/`, at most
/// 249 bytes, never empty.
///
/// A byte outside 0x20..=0x7e, and `/`, becomes `_`.  The kernel rejects a
/// slash in a memfd name and a temporary-file name must stay one path
/// component.  An empty result becomes `x`.
pub fn sanitize_name(label: &str) -> String {
    let mut out = String::new();
    for &b in label.as_bytes() {
        if out.len() >= MEMFD_NAME_MAX {
            break;
        }
        if (0x20..=0x7e).contains(&b) && b != b'/' {
            out.push(b as char);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('x');
    }
    out
}

/// Return true when a `readlink` target names a memfd.
pub fn is_memfd_path(path: &str) -> bool {
    path.starts_with("/memfd:")
}

/// Return true when `/proc/self/exe` points to a memfd.
///
/// Return false when the link cannot be read.
#[cfg(test)]
pub fn already_in_memfd() -> bool {
    match std::fs::read_link("/proc/self/exe") {
        Ok(target) => match std::str::from_utf8(target.as_os_str().as_bytes()) {
            Ok(s) => is_memfd_path(s),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

fn with_context(err: io::Error, what: &str) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {}", what, err))
}

/// Read exactly `buf.len()` bytes or fewer at end of file.
fn read_some(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `buf` is a valid writable slice of the length passed.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(err);
    }
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `buf` is a valid readable slice of the length passed.
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "image write returned 0",
            ));
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// Check the ELF magic at offset 0 without moving the file offset.
fn check_elf_magic(fd: RawFd) -> io::Result<()> {
    let mut magic = [0u8; 4];
    loop {
        // SAFETY: `magic` is a valid writable buffer of 4 bytes.
        let n = unsafe { libc::pread(fd, magic.as_mut_ptr() as *mut libc::c_void, 4, 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(with_context(err, "read program header"));
        }
        if n == 4 && magic == [0x7f, b'E', b'L', b'F'] {
            return Ok(());
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not an ELF image",
        ));
    }
}

fn copy_into(src: RawFd, dst: RawFd) -> io::Result<()> {
    // Fast path: in-kernel `copy_file_range(2)` avoids userspace copies and
    // enables CoW reflinks on supported filesystems.  Fall back cleanly to a
    // 64 KiB read/write loop on pipes, cross-fs `EXDEV`, or older kernels.
    loop {
        // SAFETY: copying between two open descriptors we own with NULL offsets.
        let n = unsafe {
            libc::copy_file_range(
                src,
                std::ptr::null_mut(),
                dst,
                std::ptr::null_mut(),
                1 << 24,
                0,
            )
        };
        if n > 0 {
            continue;
        }
        if n == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(
                libc::EXDEV
                | libc::EINVAL
                | libc::ENOSYS
                | libc::EOPNOTSUPP
                | libc::EPERM
                | libc::EBADF,
            ) => break,
            _ => return Err(with_context(e, "copying the image failed")),
        }
    }
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = read_some(src, &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        write_all_fd(dst, &buf[..n])?;
    }
}

fn seal(fd: RawFd) -> io::Result<()> {
    let seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    // SAFETY: `fd` is a valid file. F_ADD_SEALS takes an int argument.
    let rc = unsafe { libc::fcntl(fd, F_ADD_SEALS, seals) };
    if rc != 0 {
        return Err(with_context(
            io::Error::last_os_error(),
            "sealing the image refused",
        ));
    }
    Ok(())
}

fn memfd(name: &[u8], flags: libc::c_uint) -> io::Result<RawFd> {
    // SAFETY: `name` is NUL-terminated and outlives the call. The flags are
    // valid memfd_create flags. The raw syscall avoids a missing libc
    // wrapper.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr() as *const libc::c_char,
            flags,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(raw as RawFd)
}

/// Build an empty image carrier and return it with its backing.
///
/// With `hugetlb`, a hugetlb memfd is tried first.  A refusal is returned
/// as a note and the ordinary memfd is used instead, so `--hugetlb` never
/// makes a run fail for lack of huge pages.  The name is the caller's
/// `--memfd-name` when one was given, otherwise the sanitised label; both
/// are validated here, so a name that would corrupt the `/memfd:` link is
/// refused before a descriptor exists.
fn create_image(label: &str, opts: &Options) -> io::Result<(RawFd, Backing, Option<String>)> {
    let name = opts.image_name(label);
    crate::mem::validate_memfd_name(&name)?;
    let mut name = name.into_bytes();
    name.push(0);
    if opts.hugetlb {
        match memfd(
            &name,
            MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_HUGE_2MB,
        ) {
            Ok(fd) => {
                return Ok((
                    fd,
                    Backing::HugeTlb {
                        page_size: HUGETLB_PAGE,
                    },
                    None,
                ))
            }
            Err(e) => {
                let note = format!("--hugetlb unavailable: {}; using an ordinary memfd", e);
                let fd = memfd(&name, MFD_CLOEXEC | MFD_ALLOW_SEALING)
                    .map_err(|e| with_context(e, "memfd_create refused"))?;
                return Ok((fd, Backing::Memfd, Some(note)));
            }
        }
    }
    let fd = memfd(&name, MFD_CLOEXEC | MFD_ALLOW_SEALING)
        .map_err(|e| with_context(e, "memfd_create refused"))?;
    Ok((fd, Backing::Memfd, None))
}

/// Fill a carrier from `src` and seal it.
fn fill(fd: RawFd, src: RawFd) -> io::Result<()> {
    copy_into(src, fd)?;
    seal(fd)
}

/// Copy `program` into a sealed image memfd. The name is `label` unless
/// `opts.memfd_name` supplied another.
///
/// Returns InvalidInput with "not an ELF image" when the file does not start
/// with the ELF magic. Returns the kernel error when `memfd_create` or the
/// sealing call fails, and InvalidInput when the requested name is invalid.
#[cfg(test)]
pub fn prepare(program: &CStr, label: &str) -> io::Result<Image> {
    prepare_path(program, label, Options::default())
}

/// RAII guard that switches thread-local `fsuid`/`fsgid` to `(uid, gid)` when
/// `geteuid() == 0` and `uid != 0`, restoring the previous IDs on drop.
pub(crate) struct FsCredGuard {
    prev_uid: libc::uid_t,
    prev_gid: libc::gid_t,
    active: bool,
}

impl FsCredGuard {
    /// Temporarily drop thread-local filesystem credentials to `(uid, gid)`
    /// when running as root (`geteuid() == 0`) on behalf of a non-root user.
    pub(crate) fn enter(uid: u32, gid: u32) -> io::Result<Self> {
        // SAFETY: geteuid(2) is always safe and cannot fail.
        if unsafe { libc::geteuid() } != 0 || uid == 0 {
            return Ok(Self {
                prev_uid: 0,
                prev_gid: 0,
                active: false,
            });
        }
        let target_uid = uid as libc::uid_t;
        let target_gid = gid as libc::gid_t;
        // Set `fsgid` before `fsuid` because changing `fsuid` away from 0
        // clears `CAP_DAC_OVERRIDE` from the effective capability set.
        // SAFETY: setfsgid(2) returns the previous fsgid.
        let prev_gid = unsafe { libc::setfsgid(target_gid) } as libc::gid_t;
        // SAFETY: second call confirms the active fsgid.
        let cur_gid = unsafe { libc::setfsgid(target_gid) } as libc::gid_t;
        if cur_gid != target_gid {
            // SAFETY: restore previous fsgid.
            unsafe { libc::setfsgid(prev_gid) };
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("setfsgid({}) did not take effect", gid),
            ));
        }
        // SAFETY: setfsuid(2) returns the previous fsuid.
        let prev_uid = unsafe { libc::setfsuid(target_uid) } as libc::uid_t;
        // SAFETY: second call confirms the active fsuid.
        let cur_uid = unsafe { libc::setfsuid(target_uid) } as libc::uid_t;
        if cur_uid != target_uid {
            // SAFETY: restore previous fsuid and fsgid.
            unsafe {
                libc::setfsuid(prev_uid);
                libc::setfsgid(prev_gid);
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("setfsuid({}) did not take effect", uid),
            ));
        }
        Ok(Self {
            prev_uid,
            prev_gid,
            active: true,
        })
    }
}

impl Drop for FsCredGuard {
    fn drop(&mut self) {
        if self.active {
            // Restore `fsuid` (0) first so root filesystem capabilities return
            // before restoring `fsgid`.
            // SAFETY: restoring previously saved fsuid/fsgid values.
            unsafe {
                libc::setfsuid(self.prev_uid);
                libc::setfsgid(self.prev_gid);
            }
            self.active = false;
        }
    }
}

/// Check Unix DAC execute permission bits for `(job_uid, job_gid)` against a
/// file owned by `(file_uid, file_gid)` with `mode` (assuming no supplementary
/// groups, matching `setgroups([])` in `child_exec`).
pub(crate) fn mode_allows_exec(
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    job_uid: u32,
    job_gid: u32,
) -> bool {
    if job_uid == 0 {
        (mode & 0o111) != 0
    } else if job_uid == file_uid {
        (mode & 0o100) != 0
    } else if job_gid == file_gid {
        (mode & 0o010) != 0
    } else {
        (mode & 0o001) != 0
    }
}

/// Open `program` for `--rexec`, enforcing `run_as` filesystem credentials
/// (`FsCredGuard`) and rejecting non-regular, setuid/setgid, or non-executable
/// files when dropping privileges.
fn open_source_path(program: &CStr, run_as: Option<(u32, u32)>) -> io::Result<RawFd> {
    let src = {
        let _guard = match run_as {
            Some((uid, gid)) => Some(FsCredGuard::enter(uid, gid)?),
            None => None,
        };
        // SAFETY: `program` is a valid NUL-terminated string; `O_NONBLOCK`
        // prevents blocking if the path names a FIFO.
        let fd = unsafe {
            libc::open(
                program.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(with_context(
                io::Error::last_os_error(),
                "open program for rexec",
            ));
        }
        fd
    };
    if let Some((uid, gid)) = run_as {
        // SAFETY: `libc::stat` is plain old data; `fstat` initializes it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `src` is an open descriptor owned here.
        if unsafe { libc::fstat(src, &mut st) } != 0 {
            let e = io::Error::last_os_error();
            // SAFETY: `src` is owned here.
            unsafe { libc::close(src) };
            return Err(with_context(e, "stat program for rexec"));
        }
        let mode = st.st_mode as u32;
        if (mode & libc::S_IFMT) != libc::S_IFREG {
            // SAFETY: `src` is owned here.
            unsafe { libc::close(src) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rexec target is not a regular file",
            ));
        }
        if (mode & (libc::S_ISUID | libc::S_ISGID)) != 0 {
            // SAFETY: `src` is owned here.
            unsafe { libc::close(src) };
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "setuid/setgid binary is not staged under --rexec",
            ));
        }
        if (mode & 0o111) == 0 || !mode_allows_exec(mode, st.st_uid, st.st_gid, uid, gid) {
            // SAFETY: `src` is owned here.
            unsafe { libc::close(src) };
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "program is not executable for target uid/gid",
            ));
        }
    }
    Ok(src)
}

/// Copy the file at `program` into a sealed image.
pub fn prepare_path(program: &CStr, label: &str, opts: Options) -> io::Result<Image> {
    let src = open_source_path(program, opts.run_as)?;
    if let Err(err) = check_elf_magic(src) {
        // SAFETY: the descriptor is ours.
        unsafe { libc::close(src) };
        return Err(err);
    }
    let result = fill_from(src, label, opts);
    // SAFETY: the descriptor is ours.
    unsafe { libc::close(src) };
    result
}

/// Build an ordinary memfd to retry a failed hugetlb write on, with the
/// degradation note that names `cause`.
///
/// A hugetlb memfd can be created while the pool is empty; the write then
/// fails (EINVAL or ENOSPC).  `--hugetlb` is documented never to fail a run
/// for lack of huge pages, so every carrier-creation site retries here and
/// reports the note at the default verbosity.
///
/// `name` is already the carrier name (`Options::image_name`, checked where
/// it was decided), so it is used byte-for-byte: a retry must not change
/// what `/proc/<pid>/exe` reads.
fn ordinary_retry(name: &str, cause: &io::Error) -> io::Result<(RawFd, Option<String>)> {
    let mut name = name.as_bytes().to_vec();
    name.push(0);
    let fd = memfd(&name, MFD_CLOEXEC | MFD_ALLOW_SEALING)
        .map_err(|e| with_context(e, "memfd_create refused"))?;
    Ok((
        fd,
        Some(format!(
            "--hugetlb unavailable: {}; using an ordinary memfd",
            cause
        )),
    ))
}

/// Create a hugetlb memfd named `name`.
///
/// The name was decided by [`Options::image_name`] and checked where it was
/// chosen (the path carrier) or is the sanitised label, so it is used
/// byte-for-byte: the huge-page carrier must read the same `/memfd:`
/// string as the ordinary one.
fn huge_memfd(name: &str) -> io::Result<RawFd> {
    let mut name = name.as_bytes().to_vec();
    name.push(0);
    memfd(
        &name,
        MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_HUGE_2MB,
    )
}

/// Copy a seekable source from offset 0.
fn copy_from_start(src: RawFd, dst: RawFd) -> io::Result<()> {
    // SAFETY: the source is one of our own memfds.
    let start = unsafe { libc::lseek(src, 0, libc::SEEK_SET) };
    if start != 0 {
        return Err(io::Error::last_os_error());
    }
    copy_into(src, dst)
}

/// Copy the bytes readable from `fd` into a sealed image.  The descriptor
/// is not closed and its offset advances to end of file.
///
/// A hugetlb carrier that cannot be filled falls back to an ordinary
/// memfd, as [`fill_from`] does: `--hugetlb` never fails a run for lack of
/// huge pages.  The bytes are spooled into an ordinary memfd first,
/// because a source that cannot seek (a pipe, a socket, `--image -`)
/// cannot be read twice: the spool is what makes the retry possible, and
/// it becomes the image itself when the huge pages are refused.  A
/// successful hugetlb run therefore copies the image twice, which costs
/// one image of memory for the duration of the prepare.
pub fn prepare_fd(fd: RawFd, label: &str, opts: Options) -> io::Result<Image> {
    let mut magic = [0u8; 4];
    let mut got = 0usize;
    while got < magic.len() {
        let n = read_some(fd, &mut magic[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    if got != 4 || magic != [0x7f, b'E', b'L', b'F'] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not an ELF image",
        ));
    }
    // The image name is the operator's choice when `--memfd-name` was
    // given, exactly as on the path carrier: `/proc/<pid>/exe` must read
    // the same string whichever way the bytes arrived.  Sanitising a
    // validated name is what made a non-ASCII one differ by carrier, so
    // the name is checked and then used byte-for-byte, like
    // `create_image`.
    let image_name = opts.image_name(label);
    crate::mem::validate_memfd_name(&image_name)?;
    let mut name = image_name.as_bytes().to_vec();
    name.push(0);
    let spool = memfd(&name, MFD_CLOEXEC | MFD_ALLOW_SEALING)
        .map_err(|e| with_context(e, "memfd_create refused"))?;
    let filled = write_all_fd(spool, &magic).and_then(|()| copy_into(fd, spool));
    if let Err(e) = filled {
        // SAFETY: the descriptor is ours.
        unsafe { libc::close(spool) };
        return Err(e);
    }
    if opts.hugetlb {
        return finish_hugetlb(&image_name, spool);
    }
    if let Err(e) = seal(spool) {
        // SAFETY: the descriptor is ours.
        unsafe { libc::close(spool) };
        return Err(e);
    }
    Ok(Image {
        fd: spool,
        backing: Backing::Memfd,
        note: None,
        path: None,
        private_dir: None,
        stamp: None,
        reaper_fd: None,
    })
}

/// Seal `spool`, closing it if the seal is refused.
fn seal_spool(spool: RawFd) -> io::Result<RawFd> {
    match seal(spool) {
        Ok(()) => Ok(spool),
        Err(e) => {
            // SAFETY: the descriptor is ours.
            unsafe { libc::close(spool) };
            Err(e)
        }
    }
}

/// Move a fully filled `spool` onto huge pages, or return it as the image.
///
/// A huge memfd can be created while the pool is empty; the copy then
/// fails part-way.  `spool` still holds the whole image, so the ordinary
/// memfd returned here is complete.  Every failure is a note, never an
/// error: `--hugetlb` does not fail a run for lack of huge pages.
fn finish_hugetlb(name: &str, spool: RawFd) -> io::Result<Image> {
    let fallback = |cause: String| -> io::Result<Image> {
        Ok(Image {
            fd: seal_spool(spool)?,
            backing: Backing::Memfd,
            note: Some(format!(
                "--hugetlb unavailable: {}; using an ordinary memfd",
                cause
            )),
            path: None,
            private_dir: None,
            stamp: None,
            reaper_fd: None,
        })
    };
    let huge = match huge_memfd(name) {
        Ok(fd) => fd,
        Err(e) => return fallback(e.to_string()),
    };
    let moved = copy_from_start(spool, huge).and_then(|()| seal(huge));
    match moved {
        Ok(()) => {
            // SAFETY: the descriptor is ours.
            unsafe { libc::close(spool) };
            Ok(Image {
                fd: huge,
                backing: Backing::HugeTlb {
                    page_size: HUGETLB_PAGE,
                },
                note: None,
                path: None,
                private_dir: None,
                stamp: None,
                reaper_fd: None,
            })
        }
        Err(e) => {
            // SAFETY: the descriptor is ours.
            unsafe { libc::close(huge) };
            fallback(e.to_string())
        }
    }
}

/// Copy an already open source into a fresh image.
fn fill_from(src: RawFd, label: &str, opts: Options) -> io::Result<Image> {
    let (fd, backing, note) = create_image(label, &opts)?;
    match fill(fd, src) {
        Ok(()) => Ok(Image {
            fd,
            backing,
            note,
            path: None,
            private_dir: None,
            stamp: None,
            reaper_fd: None,
        }),
        Err(e) if matches!(backing, Backing::HugeTlb { .. }) => {
            // A hugetlb memfd can be created while the pool is empty; the
            // write then fails with ENOSPC.  Fall back rather than fail.
            // SAFETY: the descriptor is ours.
            unsafe { libc::close(fd) };
            // The fallback keeps the same name: a hugetlb refusal must
            // not change what `/memfd:` reads.
            let (fd, note) = ordinary_retry(&opts.image_name(label), &e)?;
            // SAFETY: the source offset is reset for the retry.
            unsafe { libc::lseek(src, 0, libc::SEEK_SET) };
            let filled = fill(fd, src);
            if let Err(e2) = filled {
                // SAFETY: the descriptor is ours.
                unsafe { libc::close(fd) };
                return Err(e2);
            }
            Ok(Image {
                fd,
                backing: Backing::Memfd,
                note,
                path: None,
                private_dir: None,
                stamp: None,
                reaper_fd: None,
            })
        }
        Err(e) => {
            // SAFETY: the descriptor is ours.
            unsafe { libc::close(fd) };
            Err(e)
        }
    }
}

/// Prepare the image bytes named by `source`.
pub fn prepare_source(source: &Source, label: &str, opts: Options) -> io::Result<Image> {
    match source {
        Source::Path(p) => {
            let c = CString::new(p.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in image path"))?;
            prepare_path(&c, label, opts)
        }
        Source::Fd(fd) => prepare_fd(*fd, label, opts),
        Source::Stdin => prepare_fd(0, label, opts),
    }
}

/// Prepare the image according to [`RexecMode`].
///
/// - [`RexecMode::Memfd`]: sealed `memfd_create` carrier.
/// - [`RexecMode::Path`]: private `0500` executable inside a `0700` staging
///   directory (no `/memfd:` fingerprint in `exe` or `maps`).
/// - [`RexecMode::Tmpfile`]: unnamed `O_TMPFILE` executable on an executable
///   mount (zero directory entry ever created on disk, zero `/memfd:` prefix).
/// - [`RexecMode::Auto`]: prefers [`RexecMode::Path`] when an executable
///   staging directory is available, falling back to [`RexecMode::Memfd`]
///   when staging mounts are `noexec` or unavailable.
pub fn prepare_for_mode(
    source: &Source,
    label: &str,
    opts: Options,
    mode: RexecMode,
) -> io::Result<Image> {
    match mode {
        RexecMode::Memfd => prepare_source(source, label, opts),
        RexecMode::Path => prepare_private_path(source, label, &opts),
        RexecMode::Tmpfile => prepare_tmpfile(source, &opts),
        RexecMode::Auto => match prepare_private_path(source, label, &opts) {
            Ok(img) => Ok(img),
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => Err(e),
            Err(_) => prepare_source(source, label, opts),
        },
    }
}

/// Stage `source` into an unnamed `O_TMPFILE` inode on the first writable
/// executable mount and reopen it `O_RDONLY | O_CLOEXEC` (closing the write fd
/// so `execveat(AT_EMPTY_PATH)` never hits `ETXTBSY`).  No directory entry is
/// ever linked on disk, so `SIGKILL` at any microsecond leaves zero files.
pub fn prepare_tmpfile(source: &Source, opts: &Options) -> io::Result<Image> {
    let mut last_err: Option<io::Error> = None;
    let tmp_canon = if opts.avoid_tmp {
        Some(std::fs::canonicalize("/tmp").unwrap_or_else(|_| PathBuf::from("/tmp")))
    } else {
        None
    };
    let mut opened: Option<(PathBuf, RawFd)> = None;
    for base in private_stage_bases() {
        let dir = if let Some(ref tmp) = tmp_canon {
            let Ok(canon) = std::fs::canonicalize(&base) else {
                continue;
            };
            if canon == *tmp || canon.starts_with(tmp) {
                continue;
            }
            canon
        } else {
            base
        };
        if !mount_allows_exec(&dir) {
            continue;
        }
        let Ok(c) = CString::new(dir.as_os_str().as_bytes()) else {
            continue;
        };
        // SAFETY: `c` is a valid NUL-terminated directory path.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                0o700 as libc::mode_t,
            )
        };
        if fd >= 0 {
            opened = Some((dir, fd));
            break;
        }
        last_err = Some(io::Error::last_os_error());
    }
    let (dir, dst) = opened.ok_or_else(|| {
        last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "no writable executable directory supports O_TMPFILE",
            )
        })
    })?;

    let copy_res = match source {
        Source::Path(p) => {
            let src_c = CString::new(p.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in image path"))?;
            match open_source_path(&src_c, opts.run_as) {
                Ok(src) => {
                    let r = check_elf_magic(src).and_then(|()| copy_into(src, dst));
                    // SAFETY: `src` is owned here.
                    unsafe { libc::close(src) };
                    r
                }
                Err(e) => Err(e),
            }
        }
        Source::Fd(fd) => copy_elf_stream(*fd, dst),
        Source::Stdin => copy_elf_stream(0, dst),
    };
    if let Err(e) = copy_res {
        // SAFETY: `dst` is owned here.
        unsafe { libc::close(dst) };
        return Err(e);
    }
    // SAFETY: `dst` is owned here.
    let chmod_rc = unsafe { libc::fchmod(dst, 0o500) };
    if chmod_rc != 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(dst) };
        return Err(with_context(e, "chmod 0500 O_TMPFILE rexec image"));
    }
    let ro = reopen_readonly(dst, &None);
    // SAFETY: close the writable descriptor so `execveat` never sees ETXTBSY.
    unsafe { libc::close(dst) };
    let ro = ro?;
    Ok(Image {
        fd: ro,
        backing: Backing::TempFile { dir, named: false },
        note: None,
        path: None,
        private_dir: None,
        stamp: None,
        reaper_fd: None,
    })
}

/// Return `true` when `vm.memfd_noexec` is set (`>= 1`), meaning `execveat`
/// on a memfd will be refused by the kernel.  Zero forks.
pub fn memfd_noexec_active() -> bool {
    std::fs::read_to_string("/proc/sys/vm/memfd_noexec")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .is_some_and(|v| v >= 1)
}

/// Sanitize a label into one safe filename component for [`RexecMode::Path`].
pub fn sanitize_path_filename(label: &str) -> String {
    let mut out = String::new();
    for &b in label.as_bytes() {
        if out.len() >= 64 {
            break;
        }
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
            out.push(b as char);
        } else {
            out.push('_');
        }
    }
    while out.starts_with('.') {
        out.remove(0);
    }
    if out.is_empty() {
        "worker".to_string()
    } else {
        out
    }
}

/// Candidate base directories for [`RexecMode::Path`], in priority order:
/// `$XDG_RUNTIME_DIR`, `/dev/shm`, `/tmp`, then `$TMPDIR` and `/var/tmp`.
fn private_stage_bases() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !d.is_empty() {
            dirs.push(PathBuf::from(d));
        }
    }
    dirs.push(PathBuf::from("/dev/shm"));
    dirs.push(PathBuf::from("/tmp"));
    if let Some(d) = std::env::var_os("TMPDIR") {
        if !d.is_empty() {
            let p = PathBuf::from(d);
            if !dirs.contains(&p) {
                dirs.push(p);
            }
        }
    }
    dirs.push(PathBuf::from("/var/tmp"));
    dirs
}

/// Create a private `0700` staging directory under the first writable
/// executable base directory, arming the carrier reaper **before** `mkdir` so
/// `SIGKILL` at any nanosecond — even right after `mkdir` or mid-copy — cleans
/// up both the staged file and its `.rt-*` directory.
///
/// When `avoid_tmp` is set (the child will overmount `/tmp` with a private
/// `tmpfs` before `execve`), candidate directories inside `/tmp` are skipped
/// so the staged executable does not vanish with `ENOENT` in the child's mount
/// namespace.
fn create_private_stage_dir_with_reaper(
    avoid_tmp: bool,
    file_name: &str,
) -> io::Result<(PathBuf, PathBuf, Option<RawFd>, Option<String>)> {
    let mut last_err: Option<io::Error> = None;
    let tmp_canon = if avoid_tmp {
        Some(std::fs::canonicalize("/tmp").unwrap_or_else(|_| PathBuf::from("/tmp")))
    } else {
        None
    };
    for base in private_stage_bases() {
        let dir_base = if let Some(ref tmp) = tmp_canon {
            let Ok(canon) = std::fs::canonicalize(&base) else {
                continue;
            };
            if canon == *tmp || canon.starts_with(tmp) {
                continue;
            }
            canon
        } else {
            base
        };
        if !mount_allows_exec(&dir_base) {
            continue;
        }
        for _ in 0..16 {
            let dir = dir_base.join(format!(".rt-{}", random_tag()));
            let file_path = dir.join(file_name);
            let c = CString::new(dir.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in staging path"))?;
            // Validate file_path contains no NUL before spawning the reaper.
            if file_path.as_os_str().as_bytes().contains(&0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NUL in staging path",
                ));
            }
            // Arm the carrier reaper BEFORE `mkdir` so even a `SIGKILL` right
            // after `mkdir` or mid-`copy_into` never leaves `.rt-*` on disk.
            let (reaper_fd, note) = match spawn_carrier_reaper(&file_path, Some(&dir)) {
                Ok(wr) => (Some(wr), None),
                Err(e) => (
                    None,
                    Some(format!(
                        "private-path carrier reaper could not be started ({}); {} may remain after SIGKILL",
                        e,
                        dir.display()
                    )),
                ),
            };
            // SAFETY: `c` is a valid NUL-terminated path.
            if unsafe { libc::mkdir(c.as_ptr(), 0o700) } == 0 {
                // Override process umask so the directory is strictly 0700.
                // SAFETY: `c` is the directory we just created.
                unsafe { libc::chmod(c.as_ptr(), 0o700) };
                return Ok((dir, file_path, reaper_fd, note));
            }
            let e = io::Error::last_os_error();
            if let Some(wr) = reaper_fd {
                // SAFETY: `wr` is our owned pipe write-end; closing it exits the unused reaper.
                unsafe { libc::close(wr) };
            }
            if e.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            last_err = Some(e);
            break;
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no writable executable directory for private rexec staging",
        )
    }))
}

/// Stage `source` as a private `0500` executable named `<sanitized_label>`
/// inside a fresh `0700` directory (no `/memfd:` fingerprint in `exe`/`maps`).
pub fn prepare_private_path(source: &Source, label: &str, opts: &Options) -> io::Result<Image> {
    let image_name = opts.image_name(label);
    crate::mem::validate_memfd_name(&image_name)?;
    let file_name = sanitize_path_filename(&image_name);
    // Create the staging dir (with carrier reaper armed before `mkdir`) BEFORE
    // consuming any non-seekable source so `RexecMode::Auto` can fall back
    // cleanly to `Memfd` if mounts are noexec or if `avoid_tmp` skips `/tmp`
    // and no other executable mount exists.
    let (dir, file_path, reaper_fd, note) =
        create_private_stage_dir_with_reaper(opts.avoid_tmp, &file_name)?;
    let close_reaper = |fd: Option<RawFd>| {
        if let Some(wr) = fd {
            // SAFETY: `wr` is owned here until moved into `Image`.
            unsafe { libc::close(wr) };
        }
    };
    let file_c = CString::new(file_path.as_os_str().as_bytes()).map_err(|_| {
        let _ = std::fs::remove_dir(&dir);
        close_reaper(reaper_fd);
        io::Error::new(io::ErrorKind::InvalidInput, "NUL in staging path")
    })?;

    // Open destination `0600` exclusively, then chmod to `0500` once filled.
    // SAFETY: `file_c` is a valid NUL-terminated path inside our `0700` dir.
    let dst = unsafe {
        libc::open(
            file_c.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600 as libc::mode_t,
        )
    };
    if dst < 0 {
        let e = io::Error::last_os_error();
        let _ = std::fs::remove_dir(&dir);
        close_reaper(reaper_fd);
        return Err(with_context(e, "create private rexec image"));
    }

    let copy_res = match source {
        Source::Path(p) => {
            let src_c = CString::new(p.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in image path"))?;
            match open_source_path(&src_c, opts.run_as) {
                Ok(src) => {
                    let r = check_elf_magic(src).and_then(|()| copy_into(src, dst));
                    // SAFETY: `src` is owned here.
                    unsafe { libc::close(src) };
                    r
                }
                Err(e) => Err(e),
            }
        }
        Source::Fd(fd) => copy_elf_stream(*fd, dst),
        Source::Stdin => copy_elf_stream(0, dst),
    };

    if let Err(e) = copy_res {
        // SAFETY: `dst` is owned here.
        unsafe { libc::close(dst) };
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&dir);
        close_reaper(reaper_fd);
        return Err(e);
    }

    // Make read+execute only (`0500`) and close the write fd so execve never
    // sees `ETXTBSY`.
    // SAFETY: `dst` is owned here.
    let chmod_rc = unsafe { libc::fchmod(dst, 0o500) };
    // SAFETY: `dst` is owned here.
    unsafe { libc::close(dst) };
    if chmod_rc != 0 {
        let e = io::Error::last_os_error();
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&dir);
        close_reaper(reaper_fd);
        return Err(with_context(e, "chmod 0500 private rexec image"));
    }

    Ok(Image {
        fd: -1,
        backing: Backing::PrivatePath { dir: dir.clone() },
        note,
        path: Some(file_path),
        private_dir: Some(dir),
        stamp: None,
        reaper_fd,
    })
}

fn copy_elf_stream(src: RawFd, dst: RawFd) -> io::Result<()> {
    let mut magic = [0u8; 4];
    let mut got = 0usize;
    while got < magic.len() {
        let n = read_some(src, &mut magic[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    if got != 4 || magic != [0x7f, b'E', b'L', b'F'] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not an ELF image",
        ));
    }
    write_all_fd(dst, &magic)?;
    copy_into(src, dst)
}

/// Move the image descriptor above the secret-install range and set
/// close-on-exec.  The original descriptor is closed.
pub fn relocate(image: &mut Image, min: RawFd) -> io::Result<()> {
    if image.fd >= min {
        // SAFETY: the descriptor is ours.
        let rc = unsafe { libc::fcntl(image.fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        if rc < 0 {
            return Err(with_context(
                io::Error::last_os_error(),
                "cannot set close-on-exec on the image descriptor",
            ));
        }
        return Ok(());
    }
    // SAFETY: duplicating our own descriptor.
    let hi = unsafe { libc::fcntl(image.fd, libc::F_DUPFD, min) };
    if hi < 0 {
        let e = io::Error::last_os_error();
        // `F_DUPFD` fails `EINVAL` when `min` is at or above the limit.
        // Naming the limit and the required value is the difference
        // between a usable diagnosis and "the secret descriptors".
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes into our struct.
        let have = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0;
        let detail = if have && e.raw_os_error() == Some(libc::EINVAL) {
            format!(
                "cannot place the image at fd {}: RLIMIT_NOFILE is {}, need at least {}",
                min,
                lim.rlim_cur,
                min as u64 + 1
            )
        } else {
            "cannot move the image above the secret descriptors".to_string()
        };
        return Err(with_context(e, &detail));
    }
    // SAFETY: the duplicate is ours.
    let rc = unsafe { libc::fcntl(hi, libc::F_SETFD, libc::FD_CLOEXEC) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        // SAFETY: both descriptors are ours.
        unsafe {
            libc::close(hi);
        }
        return Err(with_context(
            e,
            "cannot set close-on-exec on the image descriptor",
        ));
    }
    // SAFETY: the duplicate replaces the original.
    unsafe { libc::close(image.fd) };
    image.fd = hi;
    Ok(())
}

/// Maximum number of cached images.  A session that executes many distinct
/// programs keeps the most recent ones; the rest are closed.
const CACHE_MAX: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    path: PathBuf,
    dev: u64,
    ino: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    size: u64,
    hugetlb: bool,
    /// `--memfd-name`.  Two sessions sharing one cache with different
    /// names must not share an image, or the second run would inherit the
    /// first one's `/memfd:` string.
    memfd_name: Option<String>,
}

impl Key {
    fn from_metadata(path: &Path, md: &std::fs::Metadata, opts: &Options) -> Key {
        Key {
            path: path.to_path_buf(),
            dev: md.dev(),
            ino: md.ino(),
            mtime: (md.mtime(), md.mtime_nsec()),
            ctime: (md.ctime(), md.ctime_nsec()),
            size: md.size(),
            hugetlb: opts.hugetlb,
            memfd_name: opts.memfd_name.clone(),
        }
    }
}

/// A bounded cache of sealed images keyed by resolved path, inode identity,
/// timestamps and size.
///
/// The cache is shared by the builder (the first exec) and the tracer
/// (later execs under `--exec-once`).  It holds the image descriptors
/// open, so a later exec of the same file reuses the same inode instead
/// of copying the bytes again.  The tracer uses [`Cache::get_temp`] for a
/// later exec: the image descriptor is `FD_CLOEXEC` and the tracee has
/// no copy after its first exec, so the cached bytes are materialised as
/// a guarded temporary file the tracee can name.
#[derive(Debug, Default)]
pub struct Cache {
    #[cfg(test)]
    entries: HashMap<Key, Arc<Image>>,
    #[cfg(test)]
    order: VecDeque<Key>,
    temp_entries: HashMap<Key, Arc<Image>>,
    temp_order: VecDeque<Key>,
}

impl Cache {
    /// An empty cache.
    pub fn new() -> Cache {
        Cache::default()
    }

    /// Return the cached image for `path`, or prepare and cache one.
    ///
    /// The path is the file as the tracee sees it; the caller resolves
    /// `/proc/<pid>/root` and `/proc/<pid>/cwd` first.  The key binds the
    /// path, device, inode, mtime, ctime and size, so replacing a source
    /// binary even with an identical size and forged mtime produces a new
    /// image.
    #[cfg(test)]
    pub fn get(&mut self, path: &Path, label: &str, opts: Options) -> io::Result<Arc<Image>> {
        let md = std::fs::metadata(path).map_err(|e| with_context(e, "stat program for rexec"))?;
        let key = Key::from_metadata(path, &md, &opts);
        if let Some(img) = self.entries.get(&key) {
            return Ok(img.clone());
        }
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in program path"))?;
        let mut img = prepare_path(&c, label, opts)?;
        relocate(&mut img, IMAGE_FD_MIN)?;
        let img = Arc::new(img);
        self.entries.insert(key.clone(), img.clone());
        self.order.push_back(key);
        while self.order.len() > CACHE_MAX {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
        Ok(img)
    }

    /// Return the cached temporary-file carrier for `path`, or prepare
    /// one.
    ///
    /// This is the carrier `--exec-once` uses for a later exec: the
    /// supervisor is non-dumpable, so the tracee cannot follow
    /// `/proc/<tracer>/fd/N`, and a named file on an executable mount is
    /// the step the chain can hand to a process the tracer does not
    /// control.  The file is mode 0700 and is removed with the cache
    /// entry.
    pub fn get_temp(&mut self, path: &Path, label: &str, opts: Options) -> io::Result<Arc<Image>> {
        let md = std::fs::metadata(path).map_err(|e| with_context(e, "stat program for rexec"))?;
        let key = Key::from_metadata(path, &md, &opts);
        if let Some(img) = self.temp_entries.get(&key) {
            // The path is the identity a later exec uses, and a same-uid
            // process can rename over it.  A cache hit that no longer
            // names these bytes is a refusal, not a reason to run
            // attacker bytes under the label (issue 001).
            verify_carrier(img)?;
            return Ok(img.clone());
        }
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in program path"))?;
        let name = opts.memfd_name.clone();
        let mut primary = prepare_path(&c, label, opts)?;
        relocate(&mut primary, IMAGE_FD_MIN)?;
        let image = Arc::new(prepare_temp_named(&primary, label, &name)?);
        self.temp_entries.insert(key.clone(), image.clone());
        self.temp_order.push_back(key);
        while self.temp_order.len() > CACHE_MAX {
            if let Some(old) = self.temp_order.pop_front() {
                self.temp_entries.remove(&old);
            }
        }
        Ok(image)
    }

    /// Remove every named temporary carrier now.
    ///
    /// The session calls this before it returns: `std::process::exit`
    /// does not run destructors, so a temp file held only by the cache
    /// would otherwise outlive the run.
    pub fn remove_temp_files(&mut self) {
        for img in self.temp_entries.values() {
            if let Some(path) = &img.path {
                let _ = std::fs::remove_file(path);
            }
        }
        self.temp_entries.clear();
        self.temp_order.clear();
    }

    /// Number of images currently cached.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Refuse a carrier whose path no longer names the cached inode and
/// bytes.
///
/// The check is deliberately two-part.  The inode comparison catches a
/// `rename` of a different file over the path; the byte comparison
/// catches a write through a descriptor that keeps the inode.  A missing
/// path is the same refusal: the image the session promised is gone.
/// The status change time of an open carrier descriptor, as `verify_carrier`
/// compares it.  `None` when the descriptor cannot be stat'ed; the carrier
/// is then verified by identity and bytes alone.
fn stamp_of(fd: RawFd) -> Option<(i64, i64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(format!("/proc/self/fd/{fd}")).ok()?;
    Some((m.ctime(), m.ctime_nsec()))
}

fn verify_carrier(img: &Image) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;
    let Some(path) = &img.path else {
        return Ok(());
    };
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "--exec-once carrier {} is not readable: {}",
                    path.display(),
                    e
                ),
            )
        })?;
    let by_path = opened.metadata()?;
    let by_fd = std::fs::metadata(format!("/proc/self/fd/{}", img.fd))?;
    if by_path.dev() != by_fd.dev() || by_path.ino() != by_fd.ino() || by_path.len() != by_fd.len()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "--exec-once carrier {} was replaced; refusing to exec it",
                path.display()
            ),
        ));
    }
    // A writer that modifies this inode in place leaves the device, the
    // inode and the length alone, and both reads below would then compare
    // the same new bytes.  The status change time is written by the kernel
    // on every modification and cannot be set back without privilege.  A
    // filesystem with coarse timestamps can hide a rewrite inside one tick;
    // the identity comparison above still catches every change of file.
    if let Some((ctime, ctime_nsec)) = img.stamp {
        if by_path.ctime() != ctime || by_path.ctime_nsec() != ctime_nsec {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "--exec-once carrier {} was modified after it was written; refusing to exec it",
                    path.display()
                ),
            ));
        }
    }
    let mut a = std::fs::File::open(format!("/proc/self/fd/{}", img.fd))?;
    let mut b = opened;
    let mut ba = [0u8; 65536];
    let mut bb = [0u8; 65536];
    loop {
        let na = read_full(&mut a, &mut ba)?;
        let nb = read_full(&mut b, &mut bb)?;
        if na != nb || ba[..na] != bb[..nb] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "--exec-once carrier {} changed its bytes; refusing to exec it",
                    path.display()
                ),
            ));
        }
        if na == 0 {
            return Ok(());
        }
    }
}

/// Read until the buffer is full or EOF.
fn read_full(f: &mut std::fs::File, buf: &mut [u8]) -> io::Result<usize> {
    use std::io::Read;
    let mut done = 0;
    while done < buf.len() {
        match f.read(&mut buf[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

/// The `--exec-once` carrier is refused when the file at its path is no
/// longer the bytes the descriptor holds.  Issue 64: the old cache bound
/// metadata, so a same-uid writer could rewrite the carrier's contents
/// without changing the file's device, inode or length.
#[cfg(test)]
mod carrier_tests {
    use super::{verify_carrier, Backing, Image};
    use std::io::Write;
    use std::os::fd::IntoRawFd;
    use std::path::{Path, PathBuf};

    /// A directory holding one carrier file, removed on drop.
    struct Carrier {
        dir: PathBuf,
        path: PathBuf,
    }

    impl Carrier {
        fn new(tag: &str, bytes: &[u8]) -> Carrier {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "pmask-carrier-{}-{}-{}",
                tag,
                std::process::id(),
                nanos
            ));
            std::fs::create_dir_all(&dir).expect("temp dir");
            let path = dir.join("carrier");
            std::fs::write(&path, bytes).expect("write carrier");
            Carrier { dir, path }
        }

        /// An `Image` naming this file.  It owns the descriptor and unlinks
        /// the file when it drops.
        fn image(&self) -> Image {
            use std::os::fd::AsRawFd;
            let f = std::fs::OpenOptions::new()
                .read(true)
                .open(&self.path)
                .expect("open carrier");
            let stamp = super::stamp_of(f.as_raw_fd());
            Image {
                fd: f.into_raw_fd(),
                backing: Backing::Memfd,
                note: None,
                path: Some(self.path.clone()),
                private_dir: None,
                stamp,
                reaper_fd: None,
            }
        }
    }

    impl Drop for Carrier {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn an_untouched_carrier_verifies() {
        let c = Carrier::new("ok", b"#!/bin/sh\necho carried\n");
        let img = c.image();
        verify_carrier(&img).expect("an unmodified carrier verifies");
    }

    #[test]
    fn a_replaced_inode_is_refused() {
        let c = Carrier::new("swap", b"payload-bytes");
        let img = c.image();
        // A new inode at the same path, with the same length.
        std::fs::remove_file(&c.path).expect("unlink");
        std::fs::write(&c.path, b"evil-bytes!!!").expect("write replacement");
        let e = verify_carrier(&img).expect_err("a replaced carrier is refused");
        assert!(format!("{e}").contains("replaced"), "{e}");
    }

    #[test]
    fn a_carrier_rewritten_in_place_is_refused() {
        let c = Carrier::new("inplace", b"payload-bytes");
        let img = c.image();
        // Same inode and same length: the device, inode and size all match,
        // so only the byte comparison can tell this from the original.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&c.path)
            .expect("reopen carrier");
        f.write_all(b"evil-bytes!!!").expect("rewrite");
        f.sync_all().expect("sync");
        drop(f);
        let e = verify_carrier(&img).expect_err("an in-place rewrite is refused");
        assert!(
            format!("{e}").contains("modified after it was written"),
            "{e}"
        );
    }

    #[test]
    fn a_symlinked_carrier_is_refused() {
        let c = Carrier::new("link", b"payload-bytes");
        let img = c.image();
        let other = c.dir.join("other");
        std::fs::write(&other, b"payload-bytes").expect("write other");
        std::fs::remove_file(&c.path).expect("unlink");
        std::os::unix::fs::symlink(&other, &c.path).expect("symlink");
        let e = verify_carrier(&img).expect_err("a symlinked carrier is refused");
        // O_NOFOLLOW refuses the link itself rather than following it.
        assert!(format!("{e}").contains("not readable"), "{e}");
    }

    /// The path is optional: a memfd carrier has no file to re-read.
    #[test]
    fn a_carrier_without_a_path_verifies() {
        let f = std::fs::File::open(Path::new("/dev/null")).expect("open /dev/null");
        let img = Image {
            fd: f.into_raw_fd(),
            backing: Backing::Memfd,
            note: None,
            path: None,
            private_dir: None,
            stamp: None,
            reaper_fd: None,
        };
        verify_carrier(&img).expect("a carrier with no path verifies");
    }
}

/// A cache shared by a `Mask` and the tracer of its sessions.
pub type SharedCache = Arc<Mutex<Cache>>;

/// A new empty shared cache.
pub fn shared_cache() -> SharedCache {
    Arc::new(Mutex::new(Cache::new()))
}

/// Prepare a temporary-file carrier for the same bytes as `primary`.
///
/// The file lives on a mount that allows execution and is either an
/// `O_TMPFILE` inode or a named file with mode 0600 that is removed when
/// the `Image` drops.  The descriptor is moved above the secret-install
/// range.  The name comes from `opts`, so `--memfd-name` covers the
/// carrier as well as the memfd it was copied from.
pub fn prepare_temp(primary: &Image, label: &str, name: &Option<String>) -> io::Result<Image> {
    let dir = choose_temp_dir()?;
    let (fd, named, path) = create_temp_file(&dir, &temp_tag(label, name), false)?;
    fill_temp(primary, fd, dir, named, path)
}

/// Prepare a named temporary-file carrier.  A later exec needs a path the
/// tracee can resolve without reading the supervisor's descriptors, so
/// the unnamed `O_TMPFILE` form is not usable there.
pub fn prepare_temp_named(
    primary: &Image,
    label: &str,
    name: &Option<String>,
) -> io::Result<Image> {
    let dir = choose_temp_dir()?;
    let (fd, named, path) = create_temp_file(&dir, &temp_tag(label, name), true)?;
    fill_temp(primary, fd, dir, named, path)
}

/// The tag a temporary carrier's name starts with: the image name when
/// one was chosen, otherwise the label.
fn temp_tag(label: &str, name: &Option<String>) -> String {
    match name {
        Some(n) => n.clone(),
        None => label.to_string(),
    }
}

fn fill_temp(
    primary: &Image,
    fd: RawFd,
    dir: PathBuf,
    named: bool,
    path: Option<PathBuf>,
) -> io::Result<Image> {
    // The primary may have been read to EOF by an earlier copy.
    // SAFETY: the descriptor is ours.
    unsafe { libc::lseek(primary.fd, 0, libc::SEEK_SET) };
    if let Err(e) = copy_into(primary.fd, fd) {
        // SAFETY: the descriptor is ours.
        unsafe { libc::close(fd) };
        if let Some(p) = &path {
            let _ = std::fs::remove_file(p);
        }
        return Err(e);
    }
    // Sealing is best effort on filesystems that do not support it; the
    // O_TMPFILE inode or the 0700 named file and runtime verification are
    // the guards there.  Record the failure as a note so callers can report
    // the degradation visibly instead of dropping it silently (Invariant 13).
    let mut note = match seal(fd) {
        Ok(()) => None,
        Err(e) => Some(format!(
            "temporary-file carrier in {} could not be sealed ({}); guarded by mode 0700 and runtime verification",
            dir.display(),
            e
        )),
    };
    // A file open for writing refuses to exec (ETXTBSY), so the carrier
    // the child receives must be a read-only descriptor.
    let ro = match reopen_readonly(fd, &path) {
        Ok(ro) => ro,
        Err(e) => {
            // SAFETY: the descriptor is ours.
            unsafe { libc::close(fd) };
            if let Some(p) = &path {
                let _ = std::fs::remove_file(p);
            }
            return Err(e);
        }
    };
    // SAFETY: the write descriptor is ours and no longer needed.
    unsafe { libc::close(fd) };
    let mut img = Image {
        fd: ro,
        backing: Backing::TempFile { dir, named },
        note: None,
        path,
        private_dir: None,
        stamp: stamp_of(ro),
        reaper_fd: None,
    };
    relocate(&mut img, IMAGE_FD_MIN + 10)?;
    if let Some(p) = &img.path {
        // A namespace init or a shell does not clean up after SIGKILL.
        // The reaper holds only the path and a pipe, and it is
        // double-forked so it is not a child of this process and cannot
        // be mistaken for the payload by the session's `waitpid(-1)`.
        // `img.reaper_fd` owns the write end so dropping `img` closes it
        // and terminates the reaper cleanly.
        match spawn_carrier_reaper(p, None) {
            Ok(wr) => img.reaper_fd = Some(wr),
            Err(e) => {
                let msg = format!(
                    "temporary-file carrier reaper could not be started ({}); {} may remain after SIGKILL",
                    e,
                    p.display()
                );
                note = Some(match note {
                    Some(prev) => format!("{}; {}", prev, msg),
                    None => msg,
                });
            }
        }
    }
    img.note = note;
    Ok(img)
}

/// Unlink `path` (and remove optional `dir` via `rmdir`) when the supervisor's
/// pipe closes.
///
/// The intermediate child exits immediately; the grandchild is
/// reparented to init and holds the read end.  The caller stores the
/// returned write end (close-on-exec) on `Image` (or transfers it to `Tracer`),
/// so dropping `Image`, `SIGKILL`, or an abort closes it and the reaper removes
/// the carrier (and its private staging directory, if any) and exits.  A clean
/// session removes the file first and the reaper's `unlink`/`rmdir` are
/// harmless `ENOENT`s.
fn spawn_carrier_reaper(path: &Path, dir: Option<&Path>) -> io::Result<RawFd> {
    // Unified Linux syscall number for `close_range` (Linux >= 5.9) across
    // x86_64, aarch64 and i386.
    const SYS_CLOSE_RANGE: libc::c_long = 436;

    let mut fds = [0i32; 2];
    // SAFETY: pipe2 writes two descriptors into a two-element array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (rd, wr) = (fds[0], fds[1]);
    let mut bytes = path.as_os_str().as_bytes().to_vec();
    bytes.push(0);
    let dir_bytes: Option<Vec<u8>> = dir.map(|d| {
        let mut v = d.as_os_str().as_bytes().to_vec();
        v.push(0);
        v
    });
    let dir_ptr: *const libc::c_char = dir_bytes
        .as_ref()
        .map_or(std::ptr::null(), |v| v.as_ptr().cast());
    // SAFETY: the child only calls async-signal-safe syscalls.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            libc::close(wr);
            // Move `rd` above stdio if the caller ran with closed fds 0..=2.
            let mut rd = rd;
            if rd <= 2 {
                let moved = libc::fcntl(rd, libc::F_DUPFD_CLOEXEC, 3);
                if moved >= 0 {
                    libc::close(rd);
                    rd = moved;
                }
            }
            // Redirect stdin/stdout/stderr to `/dev/null` so the detached
            // reaper never pins a caller's stdout/stderr pipe open.
            let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            if devnull >= 0 {
                for std_fd in 0..=2 {
                    if std_fd != rd && devnull != std_fd {
                        libc::dup2(devnull, std_fd);
                    }
                }
                if devnull > 2 && devnull != rd {
                    libc::close(devnull);
                }
            } else {
                for std_fd in 0..=2 {
                    if std_fd != rd {
                        libc::close(std_fd);
                    }
                }
            }
            // The child must not keep the supervisor's descriptors: they
            // can name secrets, the payload or the report.  Keep only
            // `/dev/null` on stdio and the read end.
            let closed_via_range = if rd > 3 {
                let r1 = libc::syscall(SYS_CLOSE_RANGE, 3usize, (rd - 1) as usize, 0usize);
                let r2 = libc::syscall(
                    SYS_CLOSE_RANGE,
                    (rd + 1) as usize,
                    u32::MAX as usize,
                    0usize,
                );
                r1 == 0 && r2 == 0
            } else {
                libc::syscall(
                    SYS_CLOSE_RANGE,
                    (rd + 1) as usize,
                    u32::MAX as usize,
                    0usize,
                ) == 0
            };
            if !closed_via_range {
                for fd in 3..4096 {
                    if fd != rd {
                        libc::close(fd);
                    }
                }
            }
            // Detach from the session's process group and lose the
            // intermediate parent.
            libc::setsid();
            if libc::fork() != 0 {
                libc::_exit(0);
            }
            let mut b = 0u8;
            loop {
                let n = libc::read(rd, (&mut b as *mut u8).cast(), 1);
                if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if n <= 0 {
                    break;
                }
            }
            libc::unlink(bytes.as_ptr().cast());
            if !dir_ptr.is_null() {
                libc::rmdir(dir_ptr);
            }
            libc::_exit(0);
        }
    }
    drop(dir_bytes);
    unsafe { libc::close(rd) };
    let mut status = 0i32;
    loop {
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        if w == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    Ok(wr)
}

/// Reopen `fd` read-only, through the procfs magic link or the name.
fn reopen_readonly(fd: RawFd, path: &Option<PathBuf>) -> io::Result<RawFd> {
    let proc = format!("/proc/self/fd/{}", fd);
    let c = CString::new(proc)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
    // SAFETY: `c` is a valid NUL-terminated path.
    let mut ro = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if ro < 0 {
        if let Some(p) = path {
            let pc = CString::new(p.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
            // SAFETY: `pc` is a valid NUL-terminated path.
            ro = unsafe { libc::open(pc.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        }
    }
    if ro < 0 {
        return Err(with_context(
            io::Error::last_os_error(),
            "cannot reopen the temporary image read-only",
        ));
    }
    Ok(ro)
}

/// Candidate directories for the temporary carrier, most private first.
fn temp_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(d) = std::env::var_os("TMPDIR") {
        if !d.is_empty() {
            dirs.push(PathBuf::from(d));
        }
    }
    // The per-user runtime directory is mode 0700 and is the least
    // exposed place a carrier can live; `/dev/shm` is world-writable
    // (sticky) and is the first place a same-uid scanner looks.
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !d.is_empty() {
            dirs.push(PathBuf::from(d));
        }
    }
    for d in ["/dev/shm", "/tmp", "/var/tmp", "."] {
        dirs.push(PathBuf::from(d));
    }
    dirs
}

/// True when `dir` exists and the mount holding it allows execution and writes.
///
/// Uses a single `statvfs(2)` syscall (checking `ST_NOEXEC | ST_RDONLY`)
/// instead of reading and parsing `/proc/self/mounts`.
fn mount_allows_exec(dir: &Path) -> bool {
    let Ok(c) = CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a NUL-terminated path and `st` is owned output storage.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return false;
    }
    (st.f_flag & (libc::ST_NOEXEC | libc::ST_RDONLY)) == 0
}

/// Pick the first candidate directory whose mount allows execution.
fn choose_temp_dir() -> io::Result<PathBuf> {
    let mut last: Option<io::Error> = None;
    for d in temp_dirs() {
        let Ok(canon) = std::fs::canonicalize(&d) else {
            continue;
        };
        if !mount_allows_exec(&canon) {
            continue;
        }
        match std::fs::metadata(&canon) {
            Ok(md) if md.is_dir() => return Ok(canon),
            Ok(_) => continue,
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no writable directory on a mount that allows execution",
        )
    }))
}

/// A per-carrier 32-bit tag, used to make the temporary-file name unique
/// across runs of the same pid and label.
///
/// Uses `getrandom(2)` (1 syscall, no `/dev/urandom` open); falls back to
/// the clock and pid if `getrandom` is unavailable (`O_EXCL` remains the
/// authority on the name).
fn random_tag() -> String {
    let mut bytes = [0u8; 4];
    // SAFETY: `bytes` is a valid writable 4-byte buffer.
    let got = unsafe {
        libc::getrandom(
            bytes.as_mut_ptr() as *mut libc::c_void,
            bytes.len(),
            libc::GRND_NONBLOCK,
        )
    } == 4;
    let v = if got {
        u32::from_le_bytes(bytes)
    } else {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        (nanos ^ (std::process::id() << 16)).wrapping_mul(0x9e37_79b9)
    };
    format!("{:08x}", v)
}

/// Create the temporary carrier in `dir`: `O_TMPFILE` first, then a
/// guarded named file.
///
/// The named form is `.pmask-rexec-<tag>-<pid>-<run>-<n>`: the `--memfd-name`
/// value (or the label) makes the carrier recognisable to its owner, and the
/// per-create 32-bit run tag keeps two sessions, and two carriers of one
/// session, from sharing a name.  `O_EXCL` still decides the race.
fn create_temp_file(
    dir: &Path,
    tag: &str,
    named_only: bool,
) -> io::Result<(RawFd, bool, Option<PathBuf>)> {
    let c = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in directory"))?;
    let mut tmp_err = io::Error::from_raw_os_error(libc::EOPNOTSUPP);
    if !named_only {
        // SAFETY: `c` is a valid NUL-terminated path.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                0o700 as libc::mode_t,
            )
        };
        if fd >= 0 {
            // SAFETY: the descriptor is ours.
            unsafe { libc::fchmod(fd, 0o700) };
            return Ok((fd, false, None));
        }
        tmp_err = io::Error::last_os_error();
    }
    let tag: String = sanitize_name(tag)
        .chars()
        .take(64)
        .map(|c| if c == '/' { '_' } else { c })
        .collect();
    let run = random_tag();
    for n in 0..16u32 {
        let name = format!(".pmask-rexec-{}-{}-{}-{}", tag, std::process::id(), run, n);
        let mut path = dir.to_path_buf();
        path.push(&name);
        let pc = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
        // SAFETY: `pc` is a valid NUL-terminated path.
        let fd = unsafe {
            libc::open(
                pc.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC,
                0o600 as libc::mode_t,
            )
        };
        if fd >= 0 {
            // SAFETY: the descriptor is ours.
            unsafe { libc::fchmod(fd, 0o700) };
            return Ok((fd, true, Some(path)));
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            return Err(with_context(e, "cannot create a temporary image file"));
        }
        tmp_err = e;
    }
    Err(with_context(
        tmp_err,
        "cannot create a temporary image file",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn sanitize_keeps_printable_ascii() {
        assert_eq!(sanitize_name("web server 1"), "web server 1");
    }

    // Mutation control: removing the empty-name fallback makes this fail.
    #[test]
    fn sanitize_never_returns_empty() {
        assert_eq!(sanitize_name(""), "x");
    }

    #[test]
    fn sanitize_replaces_control_and_non_ascii_bytes() {
        assert_eq!(sanitize_name("a\nb\u{e9}"), "a_b__");
    }

    // A slash would split the memfd name or the temporary-file name into
    // two path components.
    #[test]
    fn sanitize_replaces_slash() {
        assert_eq!(sanitize_name("ci/runner"), "ci_runner");
    }

    // Mutation control: raising the limit above 249 makes this fail.
    #[test]
    fn sanitize_clips_to_249_bytes() {
        let long = "a".repeat(1000);
        assert_eq!(sanitize_name(&long).len(), 249);
    }

    #[test]
    fn memfd_path_detection() {
        assert!(is_memfd_path("/memfd:label (deleted)"));
        assert!(is_memfd_path("/memfd:"));
        assert!(!is_memfd_path("/usr/bin/memfd:x"));
        assert!(!is_memfd_path("memfd:label"));
        assert!(!is_memfd_path(""));
    }

    #[test]
    fn already_in_memfd_is_false_for_the_test_binary() {
        assert!(!already_in_memfd());
    }

    fn skip_on_memfd_refusal(err: &io::Error) -> bool {
        // `with_context` keeps the error kind but not the raw errno.
        matches!(
            err.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
        ) || matches!(
            err.raw_os_error(),
            Some(libc::ENOSYS) | Some(libc::EPERM) | Some(libc::EACCES)
        )
    }

    #[test]
    fn prepare_copies_and_seals() {
        let exe = std::env::current_exe().expect("current_exe");
        let path = CString::new(exe.as_os_str().as_bytes()).expect("no NUL");
        let image = match prepare(&path, "round trip") {
            Ok(i) => i,
            Err(e) if skip_on_memfd_refusal(&e) => {
                eprintln!("skip: memfd refused: {}", e);
                return;
            }
            Err(e) => panic!("prepare failed: {}", e),
        };

        // The content equals the file. Mutation control: a copy loop that
        // drops a short read or stops early makes this fail.
        let original = std::fs::read(&exe).expect("read exe");
        let mut copy = Vec::with_capacity(original.len());
        let mut off: libc::off_t = 0;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            // SAFETY: `buf` is a valid writable slice.
            let n = unsafe {
                libc::pread(
                    image.fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    off,
                )
            };
            assert!(n >= 0, "pread: {}", io::Error::last_os_error());
            if n == 0 {
                break;
            }
            copy.extend_from_slice(&buf[..n as usize]);
            off += n as libc::off_t;
        }
        assert!(copy == original, "memfd content differs from the file");

        // Sealing blocks a write. Mutation control: omitting F_SEAL_WRITE
        // makes the write succeed and this assertion fail.
        // SAFETY: valid fd and a one byte buffer.
        let n = unsafe { libc::write(image.fd, b"x".as_ptr() as *const libc::c_void, 1) };
        assert_eq!(n, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));

        // The link target is a memfd.
        let link = std::fs::read_link(format!("/proc/self/fd/{}", image.fd)).expect("readlink");
        let link = link.to_string_lossy().into_owned();
        assert!(is_memfd_path(&link), "link was {}", link);
    }

    #[test]
    fn prepare_uses_the_requested_memfd_name() {
        let exe = std::env::current_exe().expect("current_exe");
        let path = CString::new(exe.as_os_str().as_bytes()).expect("no NUL");
        let opts = Options {
            hugetlb: false,
            memfd_name: Some("image-1a2b3c4d".to_string()),
            avoid_tmp: false,
            run_as: None,
        };
        let image = match prepare_path(&path, "the label", opts) {
            Ok(i) => i,
            Err(e) if skip_on_memfd_refusal(&e) => {
                eprintln!("skip: memfd refused: {}", e);
                return;
            }
            Err(e) => panic!("prepare failed: {}", e),
        };
        let link = std::fs::read_link(format!("/proc/self/fd/{}", image.fd)).unwrap();
        assert_eq!(
            link.to_string_lossy(),
            "/memfd:image-1a2b3c4d (deleted)",
            "the label leaked into the memfd name"
        );
    }

    // Mutation control: falling back to `sanitize_name(label)` in
    // `create_image` makes this fail.
    #[test]
    fn prepare_without_a_name_uses_the_label() {
        let exe = std::env::current_exe().expect("current_exe");
        let path = CString::new(exe.as_os_str().as_bytes()).expect("no NUL");
        let image = match prepare(&path, "the label") {
            Ok(i) => i,
            Err(e) if skip_on_memfd_refusal(&e) => {
                eprintln!("skip: memfd refused: {}", e);
                return;
            }
            Err(e) => panic!("prepare failed: {}", e),
        };
        let link = std::fs::read_link(format!("/proc/self/fd/{}", image.fd)).unwrap();
        assert_eq!(link.to_string_lossy(), "/memfd:the label (deleted)");
    }

    #[test]
    fn prepare_refuses_an_invalid_memfd_name() {
        let exe = std::env::current_exe().expect("current_exe");
        let path = CString::new(exe.as_os_str().as_bytes()).expect("no NUL");
        let opts = Options {
            hugetlb: false,
            memfd_name: Some("a/b".to_string()),
            avoid_tmp: false,
            run_as: None,
        };
        let err =
            prepare_path(&path, "label", opts).expect_err("a slash in the memfd name was accepted");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn prepare_refuses_non_elf() {
        let dir = std::env::temp_dir().join(format!("pmask-rexec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("script.sh");
        std::fs::write(&file, b"#!/bin/sh\nexit 0\n").expect("write");
        let path = CString::new(file.as_os_str().as_bytes()).expect("no NUL");
        let result = prepare(&path, "script");
        let _ = std::fs::remove_dir_all(&dir);
        match result {
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
                assert!(e.to_string().contains("not an ELF image"));
            }
            Ok(i) => {
                drop(i);
                panic!("script was accepted");
            }
        }
    }

    #[test]
    fn prepare_fd_reads_from_the_current_offset() {
        let exe = std::env::current_exe().expect("current_exe");
        let data = std::fs::read(&exe).expect("read exe");
        let dir = std::env::temp_dir().join(format!("pmask-rexec-fd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("image.bin");
        std::fs::write(&file, &data).expect("write");
        let c = CString::new(file.as_os_str().as_bytes()).expect("no NUL");
        // SAFETY: `c` is a valid path.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        let image = match prepare_fd(fd, "fd round trip", Options::default()) {
            Ok(i) => i,
            Err(e) if skip_on_memfd_refusal(&e) => {
                // SAFETY: the descriptor is ours.
                unsafe { libc::close(fd) };
                eprintln!("skip: memfd refused: {}", e);
                return;
            }
            Err(e) => panic!("prepare_fd failed: {}", e),
        };
        // SAFETY: the descriptor is ours.
        unsafe { libc::close(fd) };
        assert_eq!(
            std::fs::read(format!("/proc/self/fd/{}", image.fd)).unwrap(),
            data
        );
    }

    #[test]
    fn cache_reuses_the_same_image_for_the_same_mtime() {
        let exe = std::env::current_exe().expect("current_exe");
        let mut cache = Cache::new();
        let first = match cache.get(&exe, "cache", Options::default()) {
            Ok(i) => i,
            Err(e) if skip_on_memfd_refusal(&e) => {
                eprintln!("skip: memfd refused: {}", e);
                return;
            }
            Err(e) => panic!("cache get failed: {}", e),
        };
        let second = cache
            .get(&exe, "cache", Options::default())
            .expect("second get");
        assert_eq!(first.fd, second.fd);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_key_includes_the_mtime() {
        let exe = std::env::current_exe().expect("current_exe");
        let dir = std::env::temp_dir().join(format!("pmask-rexec-mtime-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("prog");
        std::fs::copy(&exe, &file).expect("copy");
        let mut cache = Cache::new();
        let first = match cache.get(&file, "mtime", Options::default()) {
            Ok(i) => i,
            Err(e) if skip_on_memfd_refusal(&e) => {
                let _ = std::fs::remove_dir_all(&dir);
                eprintln!("skip: memfd refused: {}", e);
                return;
            }
            Err(e) => panic!("cache get failed: {}", e),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock");
        let t = libc::timespec {
            tv_sec: (now.as_secs() + 10) as _,
            tv_nsec: 0,
        };
        let c = CString::new(file.as_os_str().as_bytes()).expect("no NUL");
        // SAFETY: `c` is a valid path and both timespecs are initialized.
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), [t, t].as_ptr(), 0) };
        assert_eq!(rc, 0, "utimensat: {}", io::Error::last_os_error());
        let second = cache
            .get(&file, "mtime", Options::default())
            .expect("second get");
        assert_ne!(first.fd, second.fd, "a changed mtime must be a new image");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Issue 64: replacing a source binary with another file of identical size
    // and forged mtime must not serve a stale cached image.
    #[test]
    fn cache_key_catches_replaced_file_with_same_size_and_mtime() {
        let exe = std::env::current_exe().expect("current_exe");
        let dir = std::env::temp_dir().join(format!("pmask-rexec-ino-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("prog");
        let replacement = dir.join("prog.new");
        std::fs::copy(&exe, &file).expect("copy");
        let md1 = std::fs::metadata(&file).expect("stat first");
        let mut cache = Cache::new();
        let first = match cache.get(&file, "ino", Options::default()) {
            Ok(i) => i,
            Err(e) if skip_on_memfd_refusal(&e) => {
                let _ = std::fs::remove_dir_all(&dir);
                eprintln!("skip: memfd refused: {}", e);
                return;
            }
            Err(e) => panic!("cache get failed: {}", e),
        };
        // Create a distinct inode of identical size and stamp it with the
        // exact same mtime before atomically renaming it into place.
        std::fs::copy(&exe, &replacement).expect("copy replacement");
        let ts = libc::timespec {
            tv_sec: md1.mtime() as _,
            tv_nsec: md1.mtime_nsec() as _,
        };
        let c = CString::new(replacement.as_os_str().as_bytes()).expect("no NUL");
        // SAFETY: `c` is a valid path and both timespecs are initialized.
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), [ts, ts].as_ptr(), 0) };
        assert_eq!(rc, 0, "utimensat: {}", io::Error::last_os_error());
        std::fs::rename(&replacement, &file).expect("rename replacement");
        let md2 = std::fs::metadata(&file).expect("stat second");
        assert_eq!(md1.size(), md2.size());
        assert_eq!(
            (md1.mtime(), md1.mtime_nsec()),
            (md2.mtime(), md2.mtime_nsec())
        );
        assert_ne!(md1.ino(), md2.ino());
        let second = cache
            .get(&file, "ino", Options::default())
            .expect("second get");
        assert_ne!(
            first.fd, second.fd,
            "a replaced inode with matching size and mtime must not reuse the stale cache entry"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Issue 64: dropping a named carrier Image must close its reaper pipe
    // write end so the double-forked reaper wakes up, unlinks the carrier,
    // and exits instead of leaking descriptors and processes.
    #[test]
    fn dropping_image_terminates_its_carrier_reaper() {
        let dir = std::env::temp_dir().join(format!("pmask-reaper-drop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let target = dir.join("carrier");
        std::fs::write(&target, b"carrier-bytes").expect("write");
        let wr = spawn_carrier_reaper(&target, None).expect("spawn reaper");
        // Keep `path: None` on the synthetic Image so `Image::drop` does NOT
        // unlink `target` itself; only closing `reaper_fd` can cause the
        // reaper to wake up, unlink `target`, and exit.
        let img = Image {
            fd: -1,
            backing: Backing::Memfd,
            note: None,
            path: None,
            private_dir: None,
            stamp: None,
            reaper_fd: Some(wr),
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            target.exists(),
            "reaper unlinked the carrier while Image was still alive"
        );
        drop(img);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while target.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let existed_after = target.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            !existed_after,
            "reaper did not wake up and unlink the carrier after Image was dropped"
        );
    }

    #[test]
    fn temp_carrier_is_on_an_executable_mount() {
        let exe = std::env::current_exe().expect("current_exe");
        let path = CString::new(exe.as_os_str().as_bytes()).expect("no NUL");
        let primary = match prepare(&path, "temp") {
            Ok(i) => i,
            Err(e) if skip_on_memfd_refusal(&e) => {
                eprintln!("skip: memfd refused: {}", e);
                return;
            }
            Err(e) => panic!("prepare failed: {}", e),
        };
        let temp = match prepare_temp(&primary, "temp", &None) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("skip: no temporary carrier: {}", e);
                return;
            }
        };
        match &temp.backing {
            Backing::TempFile { dir, .. } => assert!(mount_allows_exec(dir)),
            other => panic!("unexpected backing {:?}", other),
        }
        assert_eq!(
            std::fs::read(format!("/proc/self/fd/{}", temp.fd)).unwrap(),
            std::fs::read(&exe).unwrap()
        );
    }

    // Issue 28: a source that cannot seek (a pipe) must not lose the
    // hugetlb fallback.  `prepare_fd` carries the bytes it already read
    // into the ordinary memfd, so the retry does not depend on `lseek`.
    // Mutation control: returning the hugetlb write error instead of
    // retrying makes the `Ok` arm unreachable on a host without huge
    // pages, which is the defect this guards.
    #[test]
    fn prepare_fd_falls_back_on_a_pipe_source() {
        let data = std::fs::read(std::env::current_exe().expect("current_exe")).expect("read exe");
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: a pipe pair of our own.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe: {}", io::Error::last_os_error());
        let (read_fd, write_fd) = (fds[0], fds[1]);
        // A pipe holds 64 KiB, so the writer must run beside the reader:
        // a single-threaded fill would block on the image bytes.
        let to_write = data.clone();
        let writer = std::thread::spawn(move || {
            let mut off = 0usize;
            while off < to_write.len() {
                // SAFETY: writing the image bytes into our own pipe.
                let n = unsafe {
                    libc::write(
                        write_fd,
                        to_write[off..].as_ptr() as *const libc::c_void,
                        to_write.len() - off,
                    )
                };
                if n <= 0 {
                    break;
                }
                off += n as usize;
            }
            // SAFETY: our own descriptor; the reader sees the end of file.
            unsafe { libc::close(write_fd) };
        });

        let opts = Options {
            hugetlb: true,
            ..Options::default()
        };
        let image = match prepare_fd(read_fd, "pipe hugetlb", opts) {
            Ok(i) => i,
            Err(e) if skip_on_memfd_refusal(&e) => {
                // SAFETY: our own descriptor.
                unsafe { libc::close(read_fd) };
                let _ = writer.join();
                eprintln!("skip: memfd refused: {}", e);
                return;
            }
            Err(e) => {
                // SAFETY: our own descriptor.
                unsafe { libc::close(read_fd) };
                let _ = writer.join();
                panic!("prepare_fd on a pipe with --hugetlb failed: {}", e);
            }
        };
        // SAFETY: our own descriptor.
        unsafe { libc::close(read_fd) };
        writer.join().expect("writer thread");
        assert_eq!(
            std::fs::read(format!("/proc/self/fd/{}", image.fd)).unwrap(),
            data,
            "the fallback lost bytes the first carrier had already taken"
        );
        // On a host without huge pages the note must say what happened;
        // on one with them the backing stays hugetlb and there is no note.
        match (&image.backing, &image.note) {
            (Backing::HugeTlb { .. }, None) => {}
            (Backing::Memfd, Some(note)) => {
                assert!(
                    note.contains("--hugetlb unavailable") && note.contains("ordinary memfd"),
                    "note was {:?}",
                    note
                );
            }
            (b, n) => panic!("backing {:?} does not match note {:?}", b, n),
        }
    }

    // `ordinary_retry` is the single place the fallback note is built, so
    // both carriers that can lose their huge pages name the run the same
    // way.  Mutation control: dropping the cause from the note makes this
    // fail.
    #[test]
    fn ordinary_retry_builds_the_fallback_note() {
        let cause = io::Error::from_raw_os_error(libc::EINVAL);
        let (fd, note) = match ordinary_retry("fallback", &cause) {
            Ok(v) => v,
            Err(e) if skip_on_memfd_refusal(&e) => {
                eprintln!("skip: memfd refused: {}", e);
                return;
            }
            Err(e) => panic!("memfd refused: {}", e),
        };
        // SAFETY: the descriptor is ours.
        unsafe { libc::close(fd) };
        let note = note.expect("a fallback carries a note");
        assert!(note.contains("--hugetlb unavailable"), "{}", note);
        assert!(note.contains("ordinary memfd"), "{}", note);
    }

    #[test]
    fn sanitize_path_filename_produces_clean_component() {
        assert_eq!(sanitize_path_filename("ci-runner"), "ci-runner");
        assert_eq!(sanitize_path_filename("../bad/name"), "_bad_name");
        assert_eq!(sanitize_path_filename("..."), "worker");
        assert_eq!(sanitize_path_filename(""), "worker");
        assert_eq!(sanitize_path_filename("worker 1"), "worker_1");
    }

    #[test]
    fn prepare_private_path_stages_0500_file_in_0700_dir_and_cleans_up() {
        let exe = std::env::current_exe().expect("current_exe");
        let src = Source::Path(exe.as_os_str().to_os_string());
        let img = match prepare_private_path(&src, "ci-worker", &Options::default()) {
            Ok(i) => i,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                eprintln!("skip: no executable staging mount: {}", e);
                return;
            }
            Err(e) => panic!("prepare_private_path failed: {}", e),
        };
        let path = img.path.clone().expect("path set");
        let dir = img.private_dir.clone().expect("private_dir set");
        assert!(!is_memfd_path(&path.to_string_lossy()));
        assert_eq!(path.file_name().and_then(|s| s.to_str()), Some("ci-worker"));
        let dir_mode = std::fs::metadata(&dir).expect("stat dir").mode() & 0o777;
        let file_mode = std::fs::metadata(&path).expect("stat file").mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o500);
        assert_eq!(
            std::fs::read(&path).expect("read staged"),
            std::fs::read(&exe).expect("read exe")
        );
        drop(img);
        assert!(!path.exists(), "staged file must be unlinked on drop");
        assert!(!dir.exists(), "private staging dir must be removed on drop");
    }

    #[test]
    fn prepare_private_path_avoids_tmp_when_requested() {
        let exe = std::env::current_exe().expect("current_exe");
        let src = Source::Path(exe.as_os_str().to_os_string());
        let opts = Options {
            avoid_tmp: true,
            ..Options::default()
        };
        let tmp_canon = std::fs::canonicalize("/tmp").unwrap_or_else(|_| PathBuf::from("/tmp"));
        match prepare_private_path(&src, "tee-worker", &opts) {
            Ok(img) => {
                let path = img.path.clone().expect("path set");
                let dir = img.private_dir.clone().expect("private_dir set");
                assert!(
                    !dir.starts_with(&tmp_canon),
                    "staging dir {} must not be under {}",
                    dir.display(),
                    tmp_canon.display()
                );
                assert!(
                    !path.starts_with(&tmp_canon),
                    "staged file {} must not be under {}",
                    path.display(),
                    tmp_canon.display()
                );
                drop(img);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // On minimal hosts with only `/tmp` available, skipping `/tmp`
                // returns NotFound so `RexecMode::Auto` falls back to `Memfd`.
            }
            Err(e) => panic!("unexpected prepare_private_path(avoid_tmp) error: {}", e),
        }
    }

    #[test]
    fn private_path_reaper_cleans_file_and_dir_on_fd_close() {
        let exe = std::env::current_exe().expect("current_exe");
        let src = Source::Path(exe.as_os_str().to_os_string());
        let mut img = match prepare_private_path(&src, "reaper-worker", &Options::default()) {
            Ok(i) => i,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                eprintln!("skip: no executable staging mount: {}", e);
                return;
            }
            Err(e) => panic!("prepare_private_path failed: {}", e),
        };
        img.attach_reaper().expect("attach_reaper");
        let path = img.path.take().expect("path set");
        let dir = img.private_dir.take().expect("private_dir set");
        let reaper_fd = img.take_reaper_fd().expect("reaper_fd set");
        // Drop `img` with `path`, `private_dir`, and `reaper_fd` cleared so
        // `Image::drop` cannot clean anything up itself; only closing
        // `reaper_fd` triggers the reaper.
        drop(img);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            path.exists(),
            "reaper unlinked staged file while reaper_fd was open"
        );
        assert!(
            dir.exists(),
            "reaper removed staging dir while reaper_fd was open"
        );
        // SAFETY: `reaper_fd` is owned here.
        unsafe { libc::close(reaper_fd) };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while (path.exists() || dir.exists()) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let file_left = path.exists();
        let dir_left = dir.exists();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
        assert!(
            !file_left,
            "reaper did not unlink staged file after reaper_fd close"
        );
        assert!(
            !dir_left,
            "reaper did not remove .rt-* dir after reaper_fd close"
        );
    }
}
