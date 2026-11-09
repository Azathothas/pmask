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
//!   label sets the memfd name.
//!
//! The memfd keeps `FD_CLOEXEC`.  The fd stays open across `fork` and closes
//! at the exec.  The `Image` type closes the fd on drop.

use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString, OsStr};
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
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Ask for a hugetlbfs-backed memfd.
    pub hugetlb: bool,
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
/// makes a run fail for lack of huge pages.
fn create_image(label: &str, hugetlb: bool) -> io::Result<(RawFd, Backing, Option<String>)> {
    let mut name = sanitize_name(label).into_bytes();
    name.push(0);
    if hugetlb {
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

/// Copy `program` into a sealed memfd named after `label`.
///
/// Returns InvalidInput with "not an ELF image" when the file does not start
/// with the ELF magic. Returns the kernel error when `memfd_create` or the
/// sealing call fails.
#[cfg(test)]
pub fn prepare(program: &CStr, label: &str) -> io::Result<Image> {
    prepare_path(program, label, Options::default())
}

/// Copy the file at `program` into a sealed image.
pub fn prepare_path(program: &CStr, label: &str, opts: Options) -> io::Result<Image> {
    // SAFETY: `program` is a valid NUL-terminated string.
    let src = unsafe { libc::open(program.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if src < 0 {
        return Err(with_context(
            io::Error::last_os_error(),
            "open program for rexec",
        ));
    }
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
fn ordinary_retry(label: &str, cause: &io::Error) -> io::Result<(RawFd, Option<String>)> {
    let mut name = sanitize_name(label).into_bytes();
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

/// Write `bytes` to `dst`; on error, append the bytes not yet written to
/// `pending`, so a retry on another carrier replays them instead of
/// losing them.
fn write_tracking(dst: RawFd, bytes: &[u8], pending: &mut Vec<u8>) -> io::Result<()> {
    let mut off = 0;
    while off < bytes.len() {
        // SAFETY: `bytes` is a valid readable slice of the length passed.
        let n = unsafe {
            libc::write(
                dst,
                bytes[off..].as_ptr() as *const libc::c_void,
                bytes.len() - off,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            pending.extend_from_slice(&bytes[off..]);
            return Err(err);
        }
        if n == 0 {
            pending.extend_from_slice(&bytes[off..]);
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "image write returned 0",
            ));
        }
        off += n as usize;
    }
    Ok(())
}

/// Copy `src` into `dst`, leaving any bytes read but not written in
/// `pending`.
fn copy_tracking(src: RawFd, dst: RawFd, pending: &mut Vec<u8>) -> io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = read_some(src, &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        write_tracking(dst, &buf[..n], pending)?;
    }
}

/// Copy the bytes readable from `fd` into a sealed image.  The descriptor
/// is not closed and its offset advances to end of file.
///
/// A hugetlb carrier that fails on its first write falls back to an
/// ordinary memfd, as [`fill_from`] does: `--hugetlb` never fails a run
/// for lack of huge pages.  The bytes already read from a source that
/// cannot rewind (a pipe, a socket) are carried into the retry, so the
/// fallback does not depend on `lseek`.
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
    let (mut image_fd, mut backing, mut note) = create_image(label, opts.hugetlb)?;
    let mut pending: Vec<u8> = magic.to_vec();
    let mut fell_back = false;
    loop {
        let this_round = std::mem::take(&mut pending);
        let outcome = write_tracking(image_fd, &this_round, &mut pending).and_then(|()| {
            copy_tracking(fd, image_fd, &mut pending)?;
            seal(image_fd)
        });
        match outcome {
            Ok(()) => {
                return Ok(Image {
                    fd: image_fd,
                    backing,
                    note,
                    path: None,
                })
            }
            Err(e) if matches!(backing, Backing::HugeTlb { .. }) && !fell_back => {
                fell_back = true;
                // SAFETY: the descriptor is ours.
                unsafe { libc::close(image_fd) };
                let (retry_fd, retry_note) = ordinary_retry(label, &e)?;
                image_fd = retry_fd;
                backing = Backing::Memfd;
                note = retry_note;
            }
            Err(e) => {
                // SAFETY: the descriptor is ours.
                unsafe { libc::close(image_fd) };
                return Err(e);
            }
        }
    }
}

/// Copy an already open source into a fresh image.
fn fill_from(src: RawFd, label: &str, opts: Options) -> io::Result<Image> {
    let (fd, backing, note) = create_image(label, opts.hugetlb)?;
    match fill(fd, src) {
        Ok(()) => Ok(Image {
            fd,
            backing,
            note,
            path: None,
        }),
        Err(e) if matches!(backing, Backing::HugeTlb { .. }) => {
            // A hugetlb memfd can be created while the pool is empty; the
            // write then fails with ENOSPC.  Fall back rather than fail.
            // SAFETY: the descriptor is ours.
            unsafe { libc::close(fd) };
            let (fd, note) = ordinary_retry(label, &e)?;
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
        return Err(with_context(
            io::Error::last_os_error(),
            "cannot move the image above the secret descriptors",
        ));
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
    mtime: (i64, i64),
    size: u64,
    hugetlb: bool,
}

/// A bounded cache of sealed images keyed by resolved path and mtime.
///
/// The cache is shared by the builder (the first exec) and the tracer
/// (later execs under `--exec-once`).  It holds the image descriptors
/// open, so a later exec of the same file reuses the same inode instead
/// of copying the bytes again.  The tracer uses [`Cache::get_temp`],
/// because the non-dumpable supervisor cannot hand its memfd to the
/// tracee.
#[derive(Debug, Default)]
pub struct Cache {
    entries: HashMap<Key, Arc<Image>>,
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
    /// `/proc/<pid>/root` and `/proc/<pid>/cwd` first.  The key is the
    /// path plus the file's mtime and size, so a replaced file gets a new
    /// image.
    pub fn get(&mut self, path: &Path, label: &str, opts: Options) -> io::Result<Arc<Image>> {
        let md = std::fs::metadata(path).map_err(|e| with_context(e, "stat program for rexec"))?;
        let key = Key {
            path: path.to_path_buf(),
            mtime: (md.mtime(), md.mtime_nsec()),
            size: md.size(),
            hugetlb: opts.hugetlb,
        };
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
        let key = Key {
            path: path.to_path_buf(),
            mtime: (md.mtime(), md.mtime_nsec()),
            size: md.size(),
            hugetlb: opts.hugetlb,
        };
        if let Some(img) = self.temp_entries.get(&key) {
            return Ok(img.clone());
        }
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in program path"))?;
        let mut primary = prepare_path(&c, label, opts)?;
        relocate(&mut primary, IMAGE_FD_MIN)?;
        let image = Arc::new(prepare_temp_named(&primary, label)?);
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
/// range.
pub fn prepare_temp(primary: &Image, label: &str) -> io::Result<Image> {
    let dir = choose_temp_dir()?;
    let (fd, named, path) = create_temp_file(&dir, label, false)?;
    fill_temp(primary, fd, dir, named, path)
}

/// Prepare a named temporary-file carrier.  A later exec needs a path the
/// tracee can resolve without reading the supervisor's descriptors, so
/// the unnamed `O_TMPFILE` form is not usable there.
pub fn prepare_temp_named(primary: &Image, label: &str) -> io::Result<Image> {
    let dir = choose_temp_dir()?;
    let (fd, named, path) = create_temp_file(&dir, label, true)?;
    fill_temp(primary, fd, dir, named, path)
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
    // O_TMPFILE inode or the 0600 named file is the guard there.
    let _ = seal(fd);
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
    };
    relocate(&mut img, IMAGE_FD_MIN + 10)?;
    Ok(img)
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
    for d in ["/dev/shm", "/tmp", "/var/tmp", "."] {
        dirs.push(PathBuf::from(d));
    }
    dirs
}

/// True when the mount that holds `dir` allows execution and is writable.
fn mount_allows_exec(dir: &Path) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") else {
        return true;
    };
    let mut best: Option<(usize, bool)> = None;
    for line in mounts.lines() {
        let mut f = line.split_whitespace();
        let _source = f.next();
        let Some(mp) = f.next() else { continue };
        let Some(opts) = f.nth(1) else { continue }; // fstype is next
        let mp = unescape_mount(mp);
        if !dir.starts_with(&mp) {
            continue;
        }
        let noexec = opts.split(',').any(|o| o == "noexec");
        let ro = opts.split(',').any(|o| o == "ro");
        let bad = noexec || ro;
        match best {
            Some((len, _)) if len >= mp.as_os_str().len() => {}
            _ => best = Some((mp.as_os_str().len(), bad)),
        }
    }
    !best.map(|(_, bad)| bad).unwrap_or(false)
}

/// Decode the octal escapes `/proc/self/mounts` uses for spaces and tabs.
fn unescape_mount(s: &str) -> PathBuf {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            let oct = &b[i + 1..i + 4];
            if oct.iter().all(|c| (b'0'..=b'7').contains(c)) {
                let v = (oct[0] - b'0') * 64 + (oct[1] - b'0') * 8 + (oct[2] - b'0');
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    PathBuf::from(OsStr::from_bytes(&out))
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

/// Create the temporary carrier in `dir`: `O_TMPFILE` first, then a
/// guarded named file.
fn create_temp_file(
    dir: &Path,
    label: &str,
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
    let tag: String = sanitize_name(label)
        .chars()
        .take(64)
        .map(|c| if c == '/' { '_' } else { c })
        .collect();
    for n in 0..16u32 {
        let name = format!(".pmask-rexec-{}-{}-{}", tag, std::process::id(), n);
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
            tv_sec: (now.as_secs() + 10) as libc::time_t,
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
        let temp = match prepare_temp(&primary, "temp") {
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
}
