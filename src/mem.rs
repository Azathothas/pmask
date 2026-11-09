//! Memory hygiene for secret material.
//!
//! Three things a secret in a normal `Vec<u8>` does not survive on a shared
//! host, all fixed here:
//!
//! * it is written to swap, where it outlives the process;
//! * it lands in a core dump (or in `/proc/<pid>/mem` of anything that can
//!   read the process's memory);
//! * it is readable through the kernel's direct map if the kernel is
//!   compromised, which `memfd_secret` removes by unmapping the pages from
//!   the direct map entirely.
//!
//! [`SecBuf`] is a byte buffer that is `mlock`ed (no swap), marked
//! `MADV_DONTDUMP` (no core), zeroised on drop, and backed by
//! `memfd_secret` when the kernel offers it.  When it does not, the
//! buffer is ordinary memory with the first two properties — which is
//! still strictly better than a `Vec`, and the capability report says
//! which one you got.

use std::io;
use zeroize::Zeroize;

const PAGE: usize = 4096;

/// `memfd_secret(2)`.  Same number on x86-64 and aarch64 (it is in the
/// generic syscall table); not in the `libc` crate's constants yet.
const SYS_MEMFD_SECRET: libc::c_long = 447;

const MFD_CLOEXEC: u32 = 0x0001;
const MFD_ALLOW_SEALING: u32 = 0x0002;

/// Create a `memfd_secret(2)` descriptor that the kernel closes at the
/// next `exec` of any process that inherits it.
///
/// Every `memfd_secret` in this crate is created here.  The descriptor is
/// an open handle on the plaintext, so a copy that survives an `exec`
/// hands the secret to a descendant no matter what the delivery policy
/// did to the delivered descriptor.  One creation site is what makes the
/// flag impossible to forget (issue 15).
pub(crate) fn secret_memfd() -> io::Result<libc::c_int> {
    // SAFETY: plain syscall with constant arguments.
    let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, MFD_CLOEXEC as libc::c_long) as libc::c_int };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Is `memfd_secret(2)` usable here?  Probes through [`secret_memfd`], so
/// the capability check creates the descriptor exactly the way the real
/// buffers do, and closes it immediately.
pub(crate) fn secret_memfd_available() -> bool {
    match secret_memfd() {
        Ok(fd) => {
            // SAFETY: fd is ours and not used further.
            unsafe { libc::close(fd) };
            true
        }
        Err(_) => false,
    }
}

const F_ADD_SEALS: libc::c_int = 1033;
/// `F_GET_SEALS`.  Not in the `libc` crate's constants yet.
const F_GET_SEALS: libc::c_int = 1034;
const F_SEAL_SEAL: libc::c_int = 0x0001;
const F_SEAL_SHRINK: libc::c_int = 0x0002;
const F_SEAL_GROW: libc::c_int = 0x0004;
const F_SEAL_WRITE: libc::c_int = 0x0008;

enum Backing {
    /// Locked, dump-excluded heap memory.
    Heap(Vec<u8>),
    /// `memfd_secret` mapping: the pages are absent from the kernel's
    /// direct map, so no kernel-side read of physical memory reaches them.
    SecretMmap {
        ptr: *mut u8,
        len: usize,
        fd: libc::c_int,
    },
}

/// A byte buffer for secret material.
pub struct SecBuf {
    inner: Backing,
    /// Logical length; the `memfd_secret` backing rounds the mapping up to
    /// a page, so allocation size and buffer length are not the same.
    len: usize,
    locked: bool,
    secret_mem: bool,
}

// SAFETY: the buffer owns its pages exclusively and hands out `&[u8]` /
// `&mut [u8]` only; nothing is shared between threads without a lock.
unsafe impl Send for SecBuf {}
// SAFETY: `&SecBuf` only ever yields `&[u8]`, and every mutation goes
// through `&mut self`, so a shared reference is safe to hand to another
// thread (this is what lets a daemon serve one unlocked store).
unsafe impl Sync for SecBuf {}

fn round_down(x: usize) -> usize {
    x & !(PAGE - 1)
}

fn round_up(x: usize) -> usize {
    (x + PAGE - 1) & !(PAGE - 1)
}

/// Lock and dump-exclude the pages covering `[ptr, ptr+len)`.
fn lock_range(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let lo = round_down(ptr as usize);
    let hi = round_up(ptr as usize + len);
    unsafe {
        let rc = libc::mlock(lo as *const libc::c_void, hi - lo);
        let _ = libc::madvise(lo as *mut libc::c_void, hi - lo, libc::MADV_DONTDUMP);
        rc == 0
    }
}

fn unlock_range(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let lo = round_down(ptr as usize);
    let hi = round_up(ptr as usize + len);
    unsafe {
        libc::munlock(lo as *const libc::c_void, hi - lo);
    }
}

/// `RLIMIT_MEMLOCK` in bytes, or 0 when it cannot be read.
///
/// A `memfd_secret` mapping is charged to this limit, and a mapping larger
/// than the limit does not fail at `mmap`: it faults with `SIGBUS` at the
/// first store.  So the limit has to be read before the mapping is made,
/// not after a write fails.
fn memlock_limit() -> u64 {
    // SAFETY: getrlimit writes into a struct we own.
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) == 0 {
            lim.rlim_cur as u64
        } else {
            0
        }
    }
}

impl SecBuf {
    /// Allocate `len` zeroed bytes, preferring `memfd_secret`.
    pub fn new(len: usize) -> io::Result<SecBuf> {
        if let Some(buf) = SecBuf::try_secret(len)? {
            return Ok(buf);
        }
        let v = vec![0u8; len];
        let locked = lock_range(v.as_ptr(), v.len());
        Ok(SecBuf {
            inner: Backing::Heap(v),
            len,
            locked,
            secret_mem: false,
        })
    }

    fn try_secret(len: usize) -> io::Result<Option<SecBuf>> {
        let want = if len == 0 { PAGE } else { round_up(len) };
        // The mapping is charged to RLIMIT_MEMLOCK and faults at the first
        // store when the limit is smaller, so skip it up front and let the
        // caller lock ordinary heap memory instead.
        if want as u64 > memlock_limit() {
            return Ok(None);
        }
        // A plain `memfd_secret` descriptor is inherited across every
        // `fork` and survives every `exec` in the tree.  The descriptor is
        // an open handle on the plaintext, so a descendant that keeps it
        // can `mmap` the secret no matter what `--secret-close-on-exec`
        // did to the delivered descriptor.  `secret_memfd` creates it
        // `MFD_CLOEXEC`, so the kernel closes it at the first exec of
        // anything that does not belong to the supervisor (issue 15).
        let fd = match secret_memfd() {
            Ok(fd) => fd,
            Err(_) => return Ok(None),
        };
        // A fresh memfd_secret has zero length; mapping more than the file
        // holds faults with SIGBUS on first touch, so size it first.
        // SAFETY: ftruncate on our own anonymous file.
        if unsafe { libc::ftruncate(fd, want as libc::off_t) } == -1 {
            // SAFETY: fd is ours.
            unsafe { libc::close(fd) };
            return Ok(None);
        }
        // SAFETY: fd is a fresh anonymous file we own.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                want,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            let e = io::Error::last_os_error();
            // SAFETY: fd is ours and not used further.
            unsafe { libc::close(fd) };
            // A kernel that has memfd_secret compiled out, or a policy that
            // forbids the mapping, is a normal fallback, not an error.
            if e.raw_os_error() == Some(libc::EPERM) || e.raw_os_error() == Some(libc::ENOSYS) {
                return Ok(None);
            }
            return Ok(None);
        }
        Ok(Some(SecBuf {
            inner: Backing::SecretMmap {
                ptr: ptr as *mut u8,
                len: want,
                fd,
            },
            len,
            locked: true,
            secret_mem: true,
        }))
    }

    /// Copy `bytes` into a new [`SecBuf`].
    pub fn from_slice(bytes: &[u8]) -> io::Result<SecBuf> {
        let mut b = SecBuf::new(bytes.len())?;
        b.as_mut_slice().copy_from_slice(bytes);
        Ok(b)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True when the pages live in a `memfd_secret` mapping.
    pub fn is_secret_mem(&self) -> bool {
        self.secret_mem
    }

    /// True when the pages are locked (not swappable).
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn as_slice(&self) -> &[u8] {
        match &self.inner {
            Backing::Heap(v) => &v[..self.len],
            // SAFETY: we own `len` readable bytes at `ptr`.
            Backing::SecretMmap { ptr, .. } => unsafe {
                std::slice::from_raw_parts(*ptr, self.len)
            },
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len;
        match &mut self.inner {
            Backing::Heap(v) => &mut v[..len],
            // SAFETY: as above; `&mut self` makes the access exclusive.
            Backing::SecretMmap { ptr, .. } => unsafe { std::slice::from_raw_parts_mut(*ptr, len) },
        }
    }

    /// Make the bytes unrecoverable, keeping the allocation.
    pub fn wipe(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl Drop for SecBuf {
    fn drop(&mut self) {
        self.as_mut_slice().zeroize();
        match &mut self.inner {
            Backing::Heap(v) => {
                unlock_range(v.as_ptr(), v.len());
            }
            Backing::SecretMmap { ptr, len, fd } => {
                // Wipe the whole mapping, not just the logical length.
                // SAFETY: the mapping is ours and is unmapped once.
                unsafe {
                    std::ptr::write_bytes(*ptr, 0, *len);
                    libc::munmap(*ptr as *mut libc::c_void, *len);
                    libc::close(*fd);
                }
            }
        }
    }
}

impl std::fmt::Debug for SecBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the contents, not even truncated.
        f.debug_struct("SecBuf")
            .field("len", &self.len())
            .field("locked", &self.locked)
            .field("secret_mem", &self.secret_mem)
            .finish()
    }
}

/// The name a delivered secret's memfd carries when the caller does not
/// choose one.
///
/// `/proc/<pid>/fd/N` then reads `/memfd:pmask-secret (deleted)`, which is
/// a pmask-specific literal: a host-wide sweep for it finds every delivery
/// of this build.  [`SealedFd::new_named`] lets a caller replace it.
pub const DEFAULT_SECRET_FD_NAME: &str = "pmask-secret";

/// Longest accepted memfd name, in bytes.
///
/// The kernel accepts 249 bytes and silently truncates past that; a limit
/// below the kernel's means a name that passes this check is carried
/// whole, and a name that would have been truncated is refused instead.
pub const MAX_MEMFD_NAME_LEN: usize = 200;

/// Check a name for a `memfd_create` call.
///
/// A `/` is refused because it splits a `/memfd:` link into two path
/// components in every renderer; NUL, LF and CR are refused because they
/// corrupt the `/proc/<pid>/fd` symlink text a reader parses.  An empty
/// name is refused because the kernel then shows a bare `/memfd:`.
pub fn validate_memfd_name(name: &str) -> io::Result<()> {
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "memfd name must not be empty",
        ));
    }
    if name.len() > MAX_MEMFD_NAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "memfd name is {} bytes; the limit is {}",
                name.len(),
                MAX_MEMFD_NAME_LEN
            ),
        ));
    }
    if name
        .bytes()
        .any(|b| b == b'/' || b == 0 || b == b'\n' || b == b'\r')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "memfd name must not contain '/', NUL, LF or CR bytes",
        ));
    }
    Ok(())
}

/// A read-only anonymous file holding `bytes`, sealed against writes and
/// size changes, to be inherited by a child as a file descriptor.
///
/// This is how a secret reaches a program without ever being an argument
/// or an environment value: `/proc/<pid>/fd/N` is a symlink readable only
/// by the process owner, and the contents are only obtainable by reading
/// the descriptor.
///
/// Two seal sets are available.  [`SealedFd::new`] sets all four seals, so
/// the file can neither grow, nor shrink, nor be written: the value stays
/// readable for as long as the descriptor is open.  [`SealedFd::new_burn`]
/// omits `F_SEAL_SHRINK` and keeps `F_SEAL_SEAL`, so the holder can
/// truncate the file to zero length once but cannot then grow it back or
/// make it writable.  `F_SEAL_SEAL` freezes the set, so the two shapes
/// cannot be converted into one another and a burn descriptor must be
/// created as one.
pub struct SealedFd {
    fd: libc::c_int,
}

/// The four seals: no further seals, no shrink, no grow, no write.
const SEALS_READ_ONLY: libc::c_int = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;

/// The burn set: no further seals, no grow, no write, shrink allowed.
const SEALS_BURN: libc::c_int = F_SEAL_SEAL | F_SEAL_GROW | F_SEAL_WRITE;

impl SealedFd {
    /// A sealed descriptor whose value cannot change: the reader gets the
    /// bytes and no process can truncate, grow or write them.
    pub fn new(bytes: &[u8]) -> io::Result<SealedFd> {
        SealedFd::new_named(DEFAULT_SECRET_FD_NAME, bytes)
    }

    /// A sealed descriptor that the reader may truncate exactly once, to
    /// zero length, after reading it.  The truncate cannot be undone: the
    /// file cannot be grown and cannot be written.
    pub fn new_burn(bytes: &[u8]) -> io::Result<SealedFd> {
        SealedFd::new_burn_named(DEFAULT_SECRET_FD_NAME, bytes)
    }

    /// [`SealedFd::new`] under a caller-chosen memfd name.
    ///
    /// The name is what `/proc/<pid>/fd/N` shows next to `/memfd:`, so a
    /// name that does not contain the program name keeps the descriptor
    /// out of a sweep for that literal.
    pub fn new_named(name: &str, bytes: &[u8]) -> io::Result<SealedFd> {
        SealedFd::create(name, bytes, SEALS_READ_ONLY)
    }

    /// [`SealedFd::new_burn`] under a caller-chosen memfd name.
    pub fn new_burn_named(name: &str, bytes: &[u8]) -> io::Result<SealedFd> {
        SealedFd::create(name, bytes, SEALS_BURN)
    }

    fn create(name: &str, bytes: &[u8], seals: libc::c_int) -> io::Result<SealedFd> {
        validate_memfd_name(name)?;
        let name = std::ffi::CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "memfd name contains NUL"))?;
        // SAFETY: `name` is a valid NUL-terminated string we own for the call.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), MFD_ALLOW_SEALING | MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut off = 0usize;
        while off < bytes.len() {
            // SAFETY: writing to our own memfd from a valid slice.
            let n = unsafe {
                libc::write(
                    fd,
                    bytes[off..].as_ptr() as *const libc::c_void,
                    bytes.len() - off,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                // SAFETY: fd is ours.
                unsafe { libc::close(fd) };
                return Err(e);
            }
            off += n as usize;
        }
        // SAFETY: sealing our own memfd.
        let rc = unsafe { libc::fcntl(fd, F_ADD_SEALS, seals) };
        if rc == -1 {
            let e = io::Error::last_os_error();
            // SAFETY: fd is ours.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        // Rewind so a reader sees the whole secret.
        // SAFETY: lseek on our own fd.
        unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
        Ok(SealedFd { fd })
    }

    pub fn raw(&self) -> libc::c_int {
        self.fd
    }

    /// The seal set of this descriptor (`F_GET_SEALS`), or -1 when the
    /// kernel refuses the query.
    pub fn seals(&self) -> libc::c_int {
        // SAFETY: F_GET_SEALS on a descriptor we own.
        unsafe { libc::fcntl(self.fd, F_GET_SEALS) }
    }

    /// Hand ownership of the descriptor to the caller (it will not be
    /// closed here).
    pub fn into_raw(mut self) -> libc::c_int {
        let fd = self.fd;
        self.fd = -1;
        fd
    }
}

impl Drop for SealedFd {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: fd is ours.
            unsafe { libc::close(self.fd) };
        }
    }
}

impl std::fmt::Debug for SealedFd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedFd").field("fd", &self.fd).finish()
    }
}

/// Stop this process (and anything it forks) from being dumped, traced by
/// non-root, or read through `/proc/<pid>/mem` by another process.
pub fn set_non_dumpable() -> io::Result<()> {
    // SAFETY: plain prctl.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Best-effort hardening for a process that will hold secrets: no core
/// dumps, no ptrace by non-root.  Failures are reported, never fatal —
/// a host that forbids `PR_SET_DUMPABLE` still gets the locked buffers.
pub fn harden_self() -> Vec<String> {
    let mut notes = Vec::new();
    if let Err(e) = set_non_dumpable() {
        notes.push(format!("PR_SET_DUMPABLE: {}", e));
    }
    // SAFETY: constant rlimit.
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &lim) == -1 {
            notes.push(format!("RLIMIT_CORE: {}", io::Error::last_os_error()));
        }
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wipe() {
        let mut b = SecBuf::from_slice(b"hello-secret").unwrap();
        assert_eq!(b.as_slice(), b"hello-secret");
        assert_eq!(b.len(), 12);
        b.wipe();
        assert_eq!(b.as_slice()[..12], [0u8; 12]);
    }

    #[test]
    fn sealed_fd_roundtrip() {
        use std::io::Read;
        let s = SealedFd::new(b"abc123").unwrap();
        let mut f = unsafe {
            use std::os::unix::io::FromRawFd;
            std::fs::File::from_raw_fd(s.into_raw())
        };
        let mut out = String::new();
        f.read_to_string(&mut out).unwrap();
        assert_eq!(out, "abc123");
    }

    #[test]
    fn sealed_fd_is_write_sealed() {
        let s = SealedFd::new(b"abc").unwrap();
        // SAFETY: writing to our own sealed fd must fail.
        let n = unsafe { libc::write(s.raw(), b"x".as_ptr() as *const libc::c_void, 1) };
        assert_eq!(n, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn sealed_fd_is_shrink_sealed() {
        let s = SealedFd::new(b"abc").unwrap();
        // SAFETY: truncating our own sealed fd must fail.
        let rc = unsafe { libc::ftruncate(s.raw(), 0) };
        assert_eq!(rc, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn burn_fd_can_be_truncated_once() {
        let s = SealedFd::new_burn(b"abc").unwrap();
        // SAFETY: plain calls on a descriptor we own.
        unsafe {
            assert_eq!(libc::lseek(s.raw(), 0, libc::SEEK_SET), 0);
            let mut buf = [0u8; 8];
            assert_eq!(
                libc::read(s.raw(), buf.as_mut_ptr() as *mut libc::c_void, 8),
                3
            );
            assert_eq!(libc::ftruncate(s.raw(), 0), 0);
            assert_eq!(libc::lseek(s.raw(), 0, libc::SEEK_SET), 0);
            assert_eq!(
                libc::read(s.raw(), buf.as_mut_ptr() as *mut libc::c_void, 8),
                0
            );
            // The burn cannot be undone and the file cannot be rewritten.
            assert_eq!(libc::ftruncate(s.raw(), 3), -1);
            assert_eq!(
                libc::write(s.raw(), b"x".as_ptr() as *const libc::c_void, 1),
                -1
            );
        }
    }

    #[test]
    fn memfd_name_validation_matrix() {
        for ok in ["pmask-secret", "secret-deadbeef", "a", &"n".repeat(200)[..]] {
            assert!(validate_memfd_name(ok).is_ok(), "{} was refused", ok);
        }
        for bad in ["", "a/b", "a\0b", "a\nb", "a\rb"] {
            assert!(validate_memfd_name(bad).is_err(), "{:?} was accepted", bad);
        }
        let long = "n".repeat(MAX_MEMFD_NAME_LEN + 1);
        let err = validate_memfd_name(&long).unwrap_err();
        assert!(err.to_string().contains(&MAX_MEMFD_NAME_LEN.to_string()));
    }

    #[test]
    fn sealed_fd_carries_the_requested_name() {
        let want = format!("secret-{:08x}", 0xdead_beefu32);
        let s = SealedFd::new_named(&want, b"abc").unwrap();
        let link = std::fs::read_link(format!("/proc/self/fd/{}", s.raw())).unwrap();
        let link = link.to_string_lossy().into_owned();
        assert_eq!(link, format!("/memfd:{} (deleted)", want));
    }

    // Mutation control: hard-coding the old name in `create` makes this
    // fail, which is the whole point of the option.
    #[test]
    fn sealed_fd_default_name_is_the_documented_literal() {
        let s = SealedFd::new(b"abc").unwrap();
        let link = std::fs::read_link(format!("/proc/self/fd/{}", s.raw())).unwrap();
        let link = link.to_string_lossy().into_owned();
        assert_eq!(link, format!("/memfd:{} (deleted)", DEFAULT_SECRET_FD_NAME));
    }

    #[test]
    fn burn_fd_has_the_smaller_seal_set() {
        let read_only = SealedFd::new(b"abc").unwrap();
        let burn = SealedFd::new_burn(b"abc").unwrap();
        assert_eq!(read_only.seals(), SEALS_READ_ONLY);
        assert_eq!(burn.seals(), SEALS_BURN);
        assert_ne!(read_only.seals(), burn.seals());
    }

    #[test]
    fn secret_backing_falls_back_below_the_memlock_limit() {
        // The mapping is charged to RLIMIT_MEMLOCK and faults on first
        // store when it does not fit, so a buffer bigger than the limit
        // must not pick the secret mapping.
        let limit = memlock_limit();
        if limit > (64 << 20) {
            // The limit is effectively unlimited here, so the buffer this
            // test would need is too large to allocate.
            return;
        }
        let big = SecBuf::new(limit as usize + PAGE).unwrap();
        assert!(!big.is_secret_mem());
        assert!(big.len() > limit as usize);
    }
}
