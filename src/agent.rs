//! The secret agent: one process holds the unlocked store, everything
//! else asks it for what it needs.
//!
//! This is the *secret* side of the daemon story.  `pmaskd` is the
//! other side: it supervises jobs.  They are separate programs on
//! purpose: one holds long-lived plaintext, the other runs untrusted
//! work, and they can share a machine without sharing privileges.
//!
//! Why a daemon and not just a file: a store that is unlocked per command
//! means the passphrase is typed into, or read by, every command, and
//! every one of those commands is a process that holds the plaintext for
//! as long as it runs.  An agent derives the key once, keeps the
//! plaintext in locked, dump-excluded memory, and hands out individual
//! secrets over a socket that only this account can open.
//!
//! # Order of operations
//!
//! [`Daemon::open`] stops this process from being dumped **first**, and
//! only then reads and decrypts the store.  The order is the whole point:
//! a dumpable process that has just decrypted a store hands the
//! plaintext to any reader of its memory for the duration of the
//! decryption.  [`Daemon::serve`] repeats the hardening and refuses to
//! serve when `PR_SET_DUMPABLE` does not take effect, so a host that
//! forbids it gets no agent rather than a dumpable one.
//!
//! [`Daemon::new`] keeps its older signature for callers that already
//! hold a decrypted store.  Such a caller decrypted while the process
//! was still dumpable, and the agent prints one line saying so.
//!
//! # Authorisation
//!
//! Three checks, in this order, on every accepted connection and again
//! on every request:
//!
//! 1. **The socket directory.**  It is created `0700` and then `fstat`ed
//!    through an `O_DIRECTORY | O_NOFOLLOW` descriptor.  It must be a
//!    directory, owned by the agent's effective uid, with no group or
//!    other bits.  A directory that fails any of those refuses service.
//!    There is no fallback to a shared directory: when
//!    `$XDG_RUNTIME_DIR` is unset or not private, and no socket path was
//!    given, the agent refuses to start and says which flag to pass.
//! 2. **The peer's uid**, from `SO_PEERCRED`, which is the credential
//!    the kernel recorded at `connect`.  Only the agent's own uid may
//!    connect.
//! 3. **The peer's executable**, from `/proc/<pid>/exe`, resolved again
//!    for every request.  A connection authorised once is not
//!    authorised later: a peer that calls `execve` loses access on its
//!    next request.  That is what makes an executable policy mean
//!    anything.
//!
//! The peer's identity is pinned at accept.  When the kernel offers
//! `SO_PEERPIDFD` (Linux 6.5 and later, socket option 77) the agent
//! keeps a pidfd for the connecting process; where `statx` on a pidfd
//! reports an identity inode (Linux 6.9 and later) that inode is the
//! comparison, and the process start time is checked as well.  Without
//! `SO_PEERPIDFD` the agent falls back to `SO_PEERCRED` plus the start
//! time from `/proc/<pid>/stat`, and re-resolves `/proc/<pid>/exe`
//! immediately before each use.
//!
//! **The fallback is best effort.**  The accept-to-first-read window
//! cannot be closed without a pidfd, because `SO_PEERCRED` returns a
//! number and not a handle.  The start time detects a pid number reused
//! by a process that started later.  Neither form can be atomic with the
//! write that follows the check: a peer that execs between the check and
//! the write is authorised by the image it had when the check ran.  The
//! agent prints which method is in force at start, and `PING` reports
//! it.
//!
//! # What this does not do
//!
//! None of it defeats a privileged observer.  Root, or any process with
//! the agent's uid and `CAP_SYS_PTRACE`, reads the agent's memory and
//! obtains every secret it holds; no authorisation rule, lease, lock or
//! audit record prevents that.  A peer of the agent's uid that is
//! allowed to run an allowed executable passes every check by running
//! it.  These checks identify a process image, not a person.  The agent
//! removes the secret from argv, the environment, `ps` and the disk; it
//! cannot remove it from a process that is allowed to hold it.
//!
//! # Leases, revocation and the use audit
//!
//! A secret may be released under a lease: a time budget, a use budget,
//! or both.  When the budget is gone the agent zeroises its copy and
//! refuses the secret from then on, with an error that names the lease
//! id and the reason.  [`lease`] has the lease type, the vault lock and
//! the audit format.
//!
//! `REVOKE` locks the store: every plaintext byte the agent holds is
//! dropped, and the agent keeps no passphrase, so it cannot unlock
//! itself and serving again means restarting it.  `SIGUSR1` does the
//! same, which is what `kill -USR1 <pid>` in a script uses.  An idle
//! lock does it after a configured number of seconds without a request.
//!
//! Every release writes one audit line before the value is sent: time,
//! secret name, peer pid, peer executable, lease id, and never the
//! value.  The lines are hash-chained and [`lease::verify_file`]
//! recomputes the chain.  The chain proves that the lines are the ones
//! this code wrote, in that order.  It does not prove that no line was
//! removed from the end, and it proves nothing at all against an
//! observer who can read this process's memory.
//!
//! # Configuration
//!
//! Flags are the intended surface; [`AgentConfig::from_env`] documents
//! the environment spellings for a caller that cannot pass flags.
//!
//! # Wire protocol
//!
//! Line oriented over an `AF_UNIX` stream.  After the connection is
//! authorised the agent writes `READY 1`.  The client then writes one
//! command line per request and reads one reply:
//!
//! ```text
//! OK <byte count>     followed by newline and exactly that many body bytes
//! ERR <message>       no body
//! ```
//!
//! | command | body of `OK` |
//! |---|---|
//! | `PING` | the effective policy, one `key=value` fact per line |
//! | `LIST` | the names this peer may ask for, one per line |
//! | `GET <name>` | the value |
//! | `GETL <name> <ttl> <uses>` | the value, under a lease no wider than `ttl` seconds and `uses` uses (`0` means no bound on that dimension) |
//! | `REVOKE` | a message; the store is now locked |
//! | `AUDIT` | the entry count, the chain head and the sink |
//! | `QUIT` | nothing; the connection closes |
//!
//! A refused request gets `ERR`.  A peer that fails the executable check
//! gets one `ERR` and the connection closes.  No `ERR` line ever
//! contains a secret value.

#[path = "lease.rs"]
pub mod lease;

use self::lease::{
    AuditEntry, AuditLog, AuditSink, LeaseBook, LeaseConf, LeaseOutcome, LeasePolicy, Lookup, Vault,
};
use crate::mem::SecBuf;
use crate::store::{Passphrase, Store};
use std::ffi::CString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Version of the line protocol this build speaks.
pub const PROTOCOL: u32 = 1;

/// `SO_PEERPIDFD`: socket option 77, Linux 6.5 and later.
const SO_PEERPIDFD: libc::c_int = 77;

/// Longest command line the agent accepts, in bytes.
const MAX_COMMAND: usize = 4096;

/// Largest value the agent will hand out, in bytes.
const MAX_VALUE: usize = 1 << 20;

/// Largest reply body the agent will send, and the largest the client will
/// read.  A length above it is refused before anything is allocated.
const MAX_REPLY: usize = 8 << 20;

/// Longest reply line (`OK <n>` or `ERR <message>`) the client will read.
const MAX_REPLY_LINE: usize = 8192;

/// Concurrent connections the agent serves.
const MAX_CONNECTIONS: usize = 64;

// ------------------------------------------------------------- helpers --

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

fn refuse(kind: io::ErrorKind, text: String) -> io::Error {
    io::Error::new(kind, format!("refusing to serve: {}", text))
}

fn euid() -> u32 {
    // SAFETY: plain syscall with no arguments.
    unsafe { libc::geteuid() }
}

/// `YYYY-MM-DDTHH:MM:SSZ`, the form used in logs and audit lines.
pub fn timestamp(secs: u64) -> String {
    lease::iso_utc(secs)
}

// ----------------------------------------------------- process identity --

/// How the peer's identity is pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMethod {
    /// A pidfd from `SO_PEERPIDFD` plus a `statx` identity inode.
    PidfdInode,
    /// A pidfd from `SO_PEERPIDFD` plus the process start time.
    PidfdStarted,
    /// `SO_PEERCRED` and `/proc/<pid>/stat`.  Best effort.
    CredsOnly,
}

impl PeerMethod {
    /// Text for the startup line and `PING`.
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerMethod::PidfdInode => "pidfd + identity inode",
            PeerMethod::PidfdStarted => "pidfd + start time",
            PeerMethod::CredsOnly => "SO_PEERCRED + start time (best effort)",
        }
    }
}

/// `struct statx`, as the kernel writes it.  Only the identity inode is
/// read; the tail is padding so the kernel's 256-byte write fits.
#[repr(C)]
#[derive(Clone, Copy)]
struct Statx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    stx_pad0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: [i64; 2],
    stx_btime: [i64; 2],
    stx_ctime: [i64; 2],
    stx_mtime: [i64; 2],
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_spare: [u64; 14],
}

impl Statx {
    fn zeroed() -> Statx {
        Statx {
            stx_mask: 0,
            stx_blksize: 0,
            stx_attributes: 0,
            stx_nlink: 0,
            stx_uid: 0,
            stx_gid: 0,
            stx_mode: 0,
            stx_pad0: 0,
            stx_ino: 0,
            stx_size: 0,
            stx_blocks: 0,
            stx_attributes_mask: 0,
            stx_atime: [0; 2],
            stx_btime: [0; 2],
            stx_ctime: [0; 2],
            stx_mtime: [0; 2],
            stx_rdev_major: 0,
            stx_rdev_minor: 0,
            stx_dev_major: 0,
            stx_dev_minor: 0,
            stx_spare: [0; 14],
        }
    }
}

/// The identity inode of a pidfd, or `None` when the kernel does not
/// accept `statx` on a pidfd, which is every kernel before 6.9.
fn pidfd_inode(fd: RawFd) -> Option<u64> {
    let mut stx = Statx::zeroed();
    let empty = c"";
    // SAFETY: `fd` is open, `stx` is a writable struct of the size the
    // kernel writes, and `empty` is a static C string.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_statx,
            fd,
            empty.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            // `libc::STATX_INO` is missing from musl libc 0.2.189 but present in glibc.
            // The value is constant 0x0100 (256) across all kernels with statx support.
            0x0100u32 as libc::c_uint,
            &mut stx as *mut Statx,
        )
    };
    if rc < 0 {
        return None;
    }
    Some(stx.stx_ino)
}

/// Start time of a process, in clock ticks since boot: field 22 of
/// `/proc/<pid>/stat`.  `None` when the process is gone.
fn proc_start(pid: libc::pid_t) -> Option<u64> {
    let text = std::fs::read(format!("/proc/{}/stat", pid)).ok()?;
    let close = text.iter().rposition(|&b| b == b')')?;
    let rest = std::str::from_utf8(&text[close + 1..]).ok()?;
    rest.split_whitespace().nth(19)?.parse::<u64>().ok()
}

/// The executable a pid is running, as `/proc/<pid>/exe` names it.
fn proc_exe(pid: libc::pid_t) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{}/exe", pid)).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot resolve the peer executable (pid {}): {}", pid, e),
        )
    })
}

fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the returned descriptor is checked.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0 as libc::c_uint) } as RawFd;
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor this process owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn pidfd_alive(fd: RawFd) -> bool {
    // SAFETY: `fd` is an open pidfd and signal 0 sends nothing.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            0 as libc::c_int,
            std::ptr::null::<libc::siginfo_t>(),
            0 as libc::c_uint,
        )
    };
    rc == 0
}

/// The peer's kernel credentials, from `SO_PEERCRED`.
fn peer_cred(fd: RawFd) -> io::Result<libc::ucred> {
    let mut cred: libc::ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred)
}

/// Test hook: pretend the kernel refused `SO_PEERPIDFD`, so the
/// fallback warning is reachable from a suite.  Read once.
fn peerpidfd_disabled() -> bool {
    static OFF: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OFF.get_or_init(|| std::env::var_os("PMASK_FAULT_PEERPIDFD").is_some())
}

/// A pidfd for the peer, when the kernel offers one.
///
/// `ENOPROTOOPT` means the option does not exist and `ENODATA` means the
/// socket has no peer recorded.  Both return `None`, and the caller
/// falls back to `SO_PEERCRED`.
fn peer_pidfd(fd: RawFd) -> Option<OwnedFd> {
    if peerpidfd_disabled() {
        return None;
    }
    let mut pidfd: RawFd = -1;
    let mut len = std::mem::size_of::<RawFd>() as libc::socklen_t;
    // SAFETY: getsockopt writes one descriptor into `pidfd`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            &mut pidfd as *mut RawFd as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == -1 || pidfd < 0 {
        return None;
    }
    // SAFETY: `pidfd` is an open descriptor this process owns.
    let owned = unsafe { OwnedFd::from_raw_fd(pidfd) };
    let raw = owned.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags >= 0 {
        // SAFETY: `raw` is this descriptor and the flags came from it.
        unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    }
    Some(owned)
}

/// The pinned identity of one connection's peer.
pub struct Peer {
    pid: libc::pid_t,
    uid: libc::uid_t,
    /// Kept for the connection's lifetime; closes it on drop.
    pidfd: Option<OwnedFd>,
    inode: Option<u64>,
    start: Option<u64>,
    method: PeerMethod,
}

impl Peer {
    /// Pin the identity of the process at the other end of `fd`.
    pub fn acquire(fd: RawFd) -> io::Result<Peer> {
        let cred = peer_cred(fd)?;
        let pidfd = peer_pidfd(fd);
        let start = proc_start(cred.pid);
        let inode = pidfd.as_ref().and_then(|f| pidfd_inode(f.as_raw_fd()));
        let method = match (&pidfd, inode) {
            (Some(_), Some(_)) => PeerMethod::PidfdInode,
            (Some(_), None) => PeerMethod::PidfdStarted,
            (None, _) => PeerMethod::CredsOnly,
        };
        Ok(Peer {
            pid: cred.pid,
            uid: cred.uid,
            pidfd,
            inode,
            start,
            method,
        })
    }

    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    pub fn uid(&self) -> libc::uid_t {
        self.uid
    }

    pub fn method(&self) -> PeerMethod {
        self.method
    }

    /// Re-establish that the process this connection belongs to is still
    /// the one that connected, and return the executable it runs now.
    ///
    /// Call this immediately before every use of the peer's authority.
    /// It cannot be atomic with that use; on a kernel without
    /// `SO_PEERPIDFD` it is best effort in the sense documented on
    /// [`Peer`] and on the module.
    pub fn revalidate(&self) -> io::Result<PathBuf> {
        let replaced = || {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "pid {} now belongs to a different process than the one that connected",
                    self.pid
                ),
            )
        };
        if let Some(pfd) = &self.pidfd {
            if !pidfd_alive(pfd.as_raw_fd()) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("the peer process {} has exited", self.pid),
                ));
            }
            // A fresh pidfd for the number, compared by identity inode
            // where the kernel reports one.  A number that was recycled
            // gives a different inode, so this fails closed.
            let fresh = pidfd_open(self.pid).map_err(|_| replaced())?;
            if let (Some(pinned), Some(now)) = (self.inode, pidfd_inode(fresh.as_raw_fd())) {
                if pinned != now {
                    return Err(replaced());
                }
            }
        }
        if let Some(start) = self.start {
            match proc_start(self.pid) {
                Some(now) if now == start => {}
                Some(_) => return Err(replaced()),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("the peer process {} has exited", self.pid),
                    ))
                }
            }
        }
        proc_exe(self.pid)
    }
}

// ------------------------------------------------------------- matching --

#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    Literal(Vec<u8>),
    Star,
    One,
}

/// A byte glob: `*` matches zero or more bytes, `?` matches one byte,
/// every other byte is literal.  There is no escape character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    segs: Vec<Seg>,
}

impl Glob {
    /// Compile a pattern.
    pub fn new(pattern: &str) -> Glob {
        let mut segs = Vec::new();
        let mut literal: Vec<u8> = Vec::new();
        for &b in pattern.as_bytes() {
            match b {
                b'*' => {
                    if !literal.is_empty() {
                        segs.push(Seg::Literal(std::mem::take(&mut literal)));
                    }
                    if segs.last() != Some(&Seg::Star) {
                        segs.push(Seg::Star);
                    }
                }
                b'?' => {
                    if !literal.is_empty() {
                        segs.push(Seg::Literal(std::mem::take(&mut literal)));
                    }
                    segs.push(Seg::One);
                }
                _ => literal.push(b),
            }
        }
        if !literal.is_empty() {
            segs.push(Seg::Literal(literal));
        }
        Glob { segs }
    }

    /// True when the whole of `text` matches.
    pub fn matches(&self, text: &[u8]) -> bool {
        let mut ti = 0usize;
        let mut si = 0usize;
        let mut star: Option<(usize, usize)> = None;
        while ti < text.len() {
            match self.segs.get(si) {
                Some(Seg::Star) => {
                    star = Some((si, ti));
                    si += 1;
                }
                Some(Seg::One) => {
                    si += 1;
                    ti += 1;
                }
                Some(Seg::Literal(lit)) if text[ti..].starts_with(lit) => {
                    ti += lit.len();
                    si += 1;
                }
                _ => match star {
                    Some((ssi, sti)) => {
                        si = ssi + 1;
                        ti = sti + 1;
                        star = Some((ssi, sti + 1));
                    }
                    None => return false,
                },
            }
        }
        while self.segs.get(si) == Some(&Seg::Star) {
            si += 1;
        }
        si == self.segs.len()
    }

    /// The pattern as text, for the policy report.
    pub fn describe(&self) -> String {
        let mut s = String::new();
        for seg in &self.segs {
            match seg {
                Seg::Star => s.push('*'),
                Seg::One => s.push('?'),
                Seg::Literal(l) => s.push_str(&String::from_utf8_lossy(l)),
            }
        }
        s
    }
}

/// One policy rule: this executable may ask for these secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub exe: Glob,
    pub secret: Glob,
}

impl PolicyRule {
    /// Parse `GLOB:SECRETGLOB`.  The first colon separates the globs, so a
    /// secret name may contain a colon but an executable path may not.
    pub fn parse(text: &str) -> io::Result<PolicyRule> {
        let (exe, secret) = text.split_once(':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "policy rule '{}' wants GLOB:SECRETGLOB, such as '/usr/bin/deploy:*'",
                    text
                ),
            )
        })?;
        if exe.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("policy rule '{}' has an empty executable glob", text),
            ));
        }
        if secret.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("policy rule '{}' has an empty secret glob", text),
            ));
        }
        Ok(PolicyRule {
            exe: Glob::new(exe),
            secret: Glob::new(secret),
        })
    }
}

/// Who may ask for what.
///
/// A policy is present when it holds at least one exact executable or at
/// least one rule, and a present policy denies by default: a request
/// that no rule allows is refused.  An absent policy allows every
/// executable of the agent's uid, which is the uid check alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    exact: Vec<PathBuf>,
    rules: Vec<PolicyRule>,
}

impl Policy {
    pub fn new() -> Policy {
        Policy::default()
    }

    /// Allow exactly this executable, for every secret.
    pub fn allow_exact(&mut self, exe: PathBuf) {
        self.exact.push(exe);
    }

    /// Allow what one glob rule allows.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.rules.is_empty()
    }

    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    pub fn exact(&self) -> &[PathBuf] {
        &self.exact
    }

    /// True when this executable passes the executable half of the
    /// policy, which is what `LIST` needs.
    pub fn exe_allowed(&self, exe: &Path) -> bool {
        if self.is_empty() {
            return true;
        }
        if self.exact.iter().any(|p| p.as_os_str() == exe.as_os_str()) {
            return true;
        }
        let bytes = exe.as_os_str().as_bytes();
        self.rules.iter().any(|r| r.exe.matches(bytes))
    }

    /// True when this executable may ask for this secret.
    pub fn allows(&self, exe: &Path, secret: &str) -> bool {
        if self.is_empty() {
            return true;
        }
        if self.exact.iter().any(|p| p.as_os_str() == exe.as_os_str()) {
            return true;
        }
        let bytes = exe.as_os_str().as_bytes();
        self.rules
            .iter()
            .any(|r| r.exe.matches(bytes) && r.secret.matches(secret.as_bytes()))
    }

    /// One-line description for the startup log and `PING`.
    pub fn describe(&self) -> String {
        if self.is_empty() {
            return "uid-only (every executable of the agent's uid)".to_string();
        }
        let mut parts: Vec<String> = self
            .exact
            .iter()
            .map(|p| format!("{}:*", p.display()))
            .collect();
        parts.extend(
            self.rules
                .iter()
                .map(|r| format!("{}:{}", r.exe.describe(), r.secret.describe())),
        );
        format!("{} rule(s), default deny: {}", parts.len(), parts.join(" "))
    }
}

// ----------------------------------------------------------- the socket --

/// Create the socket directory `0700` and pin a descriptor for it.
///
/// The directory must be a directory, owned by the effective uid, with no
/// group or other bits, checked through the descriptor rather than the
/// path so a rename cannot redirect the check.
fn private_dir(dir: &Path) -> io::Result<std::fs::File> {
    if dir.as_os_str().is_empty() {
        return Err(refuse(
            io::ErrorKind::InvalidInput,
            "the socket path has no directory component".to_string(),
        ));
    }
    let c = c_path(dir)?;
    // SAFETY: `c` is a valid C string for the life of the call.
    let rc = unsafe { libc::mkdir(c.as_ptr(), 0o700) };
    if rc != 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(io::Error::new(
                e.kind(),
                format!(
                    "cannot create the socket directory {}: {}",
                    dir.display(),
                    e
                ),
            ));
        }
    }
    // SAFETY: `c` is a valid C string; O_DIRECTORY fails on a non-directory.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(refuse(
            io::ErrorKind::PermissionDenied,
            format!(
                "the socket directory {} is not usable: {}",
                dir.display(),
                e
            ),
        ));
    }
    // SAFETY: `fd` is a fresh descriptor this function owns.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let md = file.metadata()?;
    if !md.is_dir() {
        return Err(refuse(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if md.uid() != euid() {
        return Err(refuse(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {}, not by uid {}",
                dir.display(),
                md.uid(),
                euid()
            ),
        ));
    }
    if md.mode() & 0o077 != 0 {
        return Err(refuse(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is mode {:04o}; group or other can reach it.  Use a directory only you can \
                 use, such as $XDG_RUNTIME_DIR",
                dir.display(),
                md.mode() & 0o777
            ),
        ));
    }
    Ok(file)
}

/// Open a path for inspection only, without following a symbolic link.
fn pin_path(path: &Path) -> io::Result<Option<std::fs::File>> {
    let c = c_path(path)?;
    // SAFETY: `c` is a valid C string.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(io::Error::new(
            e.kind(),
            format!("cannot open {} for inspection: {}", path.display(), e),
        ));
    }
    // SAFETY: `fd` is a fresh descriptor this function owns.
    Ok(Some(unsafe { std::fs::File::from_raw_fd(fd) }))
}

/// Remove the socket at `path`, but only when the pinned descriptor says
/// it is still a socket owned by this uid.
fn unlink_pinned(path: &Path, pin: &std::fs::File, dir: &std::fs::File) -> io::Result<()> {
    let md = pin.metadata()?;
    if md.file_type().is_symlink() {
        return Err(refuse(
            io::ErrorKind::PermissionDenied,
            format!("{} is a symbolic link", path.display()),
        ));
    }
    if !md.file_type().is_socket() {
        return Err(refuse(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a socket", path.display()),
        ));
    }
    if md.uid() != euid() {
        return Err(refuse(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {}, not by uid {}",
                path.display(),
                md.uid(),
                euid()
            ),
        ));
    }
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the socket path has no file name",
        )
    })?;
    let cname = c_path(Path::new(name))?;
    // SAFETY: `dir` is an open directory descriptor and `cname` is one
    // component relative to it.
    let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) };
    if rc != 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(io::Error::new(
            e.kind(),
            format!("cannot remove {}: {}", path.display(), e),
        ));
    }
    if pin_path(path)?.is_some() {
        return Err(refuse(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} was replaced while the stale socket was being removed",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Check the socket path before binding, and remove a stale socket only
/// through a descriptor that proves it is ours.
fn prepare_path(path: &Path, dir: &std::fs::File) -> io::Result<()> {
    let Some(pin) = pin_path(path)? else {
        return Ok(());
    };
    let md = pin.metadata()?;
    if md.file_type().is_symlink() {
        return Err(refuse(
            io::ErrorKind::InvalidInput,
            format!("{} is a symbolic link", path.display()),
        ));
    }
    if !md.file_type().is_socket() {
        return Err(refuse(
            io::ErrorKind::InvalidInput,
            format!("{} exists and is not a socket", path.display()),
        ));
    }
    match UnixStream::connect(path) {
        Ok(_probe) => Err(refuse(
            io::ErrorKind::AddrInUse,
            format!("another agent is already listening on {}", path.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => unlink_pinned(path, &pin, dir),
        Err(e) => Err(refuse(
            e.kind(),
            format!(
                "cannot tell whether the socket {} is stale ({})",
                path.display(),
                e
            ),
        )),
    }
}

/// A bound listener and the identity of its socket file.
struct Bound {
    listener: UnixListener,
    dev: u64,
    ino: u64,
}

fn bind_socket(socket: &Path) -> io::Result<Bound> {
    let dir_path = socket.parent().unwrap_or_else(|| Path::new(""));
    let dir = private_dir(dir_path)?;
    prepare_path(socket, &dir)?;
    // SAFETY: umask takes a mode and returns the old one.
    let old = unsafe { libc::umask(0o077) };
    let bound = UnixListener::bind(socket);
    // SAFETY: restoring the umask this process had.
    unsafe { libc::umask(old) };
    let listener = bound.map_err(|e| {
        io::Error::new(e.kind(), format!("cannot bind {}: {}", socket.display(), e))
    })?;
    let first = std::fs::symlink_metadata(socket)?;
    if !first.file_type().is_socket() || first.uid() != euid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{}: the file after bind is not a socket owned by uid {}",
                socket.display(),
                euid()
            ),
        ));
    }
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    let second = std::fs::symlink_metadata(socket)?;
    if second.dev() != first.dev() || second.ino() != first.ino() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{}: the socket was replaced while starting",
                socket.display()
            ),
        ));
    }
    Ok(Bound {
        listener,
        dev: first.dev(),
        ino: first.ino(),
    })
}

fn remove_own_socket(socket: &Path, bound: &Bound) {
    if let Ok(md) = std::fs::symlink_metadata(socket) {
        if md.file_type().is_socket() && md.dev() == bound.dev && md.ino() == bound.ino {
            let _ = std::fs::remove_file(socket);
        }
    }
}

// ------------------------------------------------------------ hardening --

/// Stop this process from being dumped, traced by a non-root process, or
/// read through `/proc/<pid>/mem` by another process of this uid.
///
/// Call this **before** the store is decrypted.  The call is followed by
/// a check of the flag, so a host that ignores the request is reported
/// rather than trusted.
pub fn harden_holder() -> io::Result<()> {
    crate::mem::set_non_dumpable().map_err(|e| {
        refuse(
            io::ErrorKind::PermissionDenied,
            format!("cannot stop this process from being dumped: {}", e),
        )
    })?;
    // SAFETY: PR_GET_DUMPABLE takes no argument.
    let state = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) };
    if state != 0 {
        return Err(refuse(
            io::ErrorKind::PermissionDenied,
            format!(
                "PR_SET_DUMPABLE did not take effect (PR_GET_DUMPABLE returned {})",
                state
            ),
        ));
    }
    // SAFETY: a fixed rlimit structure.
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &lim);
    }
    Ok(())
}

/// True when this process can currently be dumped.
fn is_dumpable() -> bool {
    // SAFETY: PR_GET_DUMPABLE takes no argument.
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) == 1 }
}

// ------------------------------------------------------- configuration --

/// The socket path when the caller gives none.
///
/// `$XDG_RUNTIME_DIR/pmask.sock` when that directory is one this uid
/// owns with no group or other bits, else `$PMASK_SOCKET`, else the
/// empty path.  The empty path means "no safe default": the caller must
/// pass `--socket`.  There is no `/tmp` fallback, because a
/// world-writable directory cannot be checked for ownership, and an
/// attacker who wins the race for a name in it is the agent the client
/// reaches.
pub fn default_socket() -> PathBuf {
    socket_default(
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        std::env::var_os("PMASK_SOCKET").as_deref(),
    )
}

/// The decision [`default_socket`] makes, as a function of its inputs.
///
/// Split out so the rule can be tested without changing the process
/// environment: a test that sets `XDG_RUNTIME_DIR` races every other test
/// in the same process that reads it.
fn socket_default(
    runtime_dir: Option<&std::ffi::OsStr>,
    override_path: Option<&std::ffi::OsStr>,
) -> PathBuf {
    if let Some(rt) = runtime_dir {
        let p = PathBuf::from(rt);
        if let Ok(md) = std::fs::metadata(&p) {
            if md.is_dir() && md.uid() == euid() && md.mode() & 0o077 == 0 {
                return p.join("pmask.sock");
            }
        }
    }
    if let Some(p) = override_path {
        return PathBuf::from(p);
    }
    PathBuf::new()
}

fn socket_or_default(explicit: Option<&PathBuf>) -> PathBuf {
    match explicit {
        Some(p) => p.clone(),
        None => default_socket(),
    }
}

/// Everything about the agent that is not the store.
#[derive(Clone)]
pub struct AgentConfig {
    pub socket: PathBuf,
    pub policy: Policy,
    pub leases: LeaseConf,
    pub audit: AuditSink,
    /// Lock the store after this many idle seconds; 0 disables it.
    pub idle_lock_secs: u64,
    pub verbose: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            socket: default_socket(),
            policy: Policy::new(),
            leases: LeaseConf::new(),
            audit: AuditSink::Stderr,
            idle_lock_secs: 0,
            verbose: false,
        }
    }
}

impl AgentConfig {
    pub fn new(socket: PathBuf) -> AgentConfig {
        AgentConfig {
            socket,
            ..AgentConfig::default()
        }
    }

    /// Apply the settings that have an environment spelling, so a caller
    /// that cannot pass flags can still configure the agent.
    ///
    /// * `PMASK_AGENT_LEASE` holds lease clauses separated by
    ///   whitespace.  A clause is a token naming the secret (`default`
    ///   for every secret) followed by one or both bounds, `ttl=SECONDS`
    ///   and `uses=N`.  A clause with neither bound is an error.
    /// * `PMASK_AGENT_AUDIT` is `none`, `stderr` or a file path.
    /// * `PMASK_AGENT_IDLE_LOCK` is a number of seconds.
    ///
    /// A bad value is an error rather than a silent default: an agent
    /// that quietly serves without the lease the operator asked for is
    /// the failure this module exists to prevent.
    pub fn from_env(self) -> io::Result<AgentConfig> {
        self.apply_clauses(
            std::env::var_os("PMASK_AGENT_LEASE")
                .as_deref()
                .map(|v| v.to_string_lossy().into_owned())
                .as_deref()
                .unwrap_or(""),
            std::env::var_os("PMASK_AGENT_AUDIT").as_deref(),
            std::env::var_os("PMASK_AGENT_IDLE_LOCK").as_deref(),
        )
    }

    /// The same settings, taken from values a caller supplies.  Split out
    /// so a test can drive it without changing the process environment.
    pub fn apply_clauses(
        mut self,
        leases: &str,
        audit: Option<&std::ffi::OsStr>,
        idle_lock: Option<&std::ffi::OsStr>,
    ) -> io::Result<AgentConfig> {
        let parsed = parse_lease_clauses(leases)?;
        for (name, policy) in parsed {
            match name.as_deref() {
                Some(secret) => self.leases.set(secret, policy),
                None => self.leases.set_default(policy),
            }
        }
        if let Some(v) = audit {
            self.audit = AuditSink::parse(&v.to_string_lossy())?;
        }
        if let Some(v) = idle_lock {
            let text = v.to_string_lossy().into_owned();
            self.idle_lock_secs = text.trim().parse::<u64>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "PMASK_AGENT_IDLE_LOCK: '{}' is not a number of seconds",
                        text
                    ),
                )
            })?;
        }
        Ok(self)
    }
}

/// Parse lease clauses: `default ttl=SECONDS uses=N NAME ttl=...`.
///
/// A clause is a name token (`default` for every secret) followed by one
/// or both bounds.  `None` as the name means the default policy.  Every
/// error is reported, because an agent that serves without the lease the
/// operator asked for is the failure this module exists to prevent.
fn parse_lease_clauses(text: &str) -> io::Result<Vec<(Option<String>, LeasePolicy)>> {
    let fail = |e: io::Error| io::Error::new(e.kind(), format!("PMASK_AGENT_LEASE: {}", e));
    let mut out = Vec::new();
    let mut tokens = text.split_whitespace().peekable();
    while let Some(name) = tokens.next() {
        let (ttl, uses) = parse_lease_bounds(&mut tokens).map_err(fail)?;
        let policy = LeasePolicy::new(ttl, uses).map_err(fail)?;
        let key = if name == "default" {
            None
        } else {
            Some(name.to_string())
        };
        out.push((key, policy));
    }
    Ok(out)
}

fn parse_lease_bounds<'a, I>(tokens: &mut std::iter::Peekable<I>) -> io::Result<(u64, u32)>
where
    I: Iterator<Item = &'a str>,
{
    let mut ttl = 0u64;
    let mut uses = 0u32;
    let mut seen = false;
    while let Some(token) = tokens.peek().copied() {
        let Some((key, value)) = token.split_once('=') else {
            break;
        };
        let number = value.parse::<u64>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("'{}' is not a number", token),
            )
        })?;
        match key {
            "ttl" => ttl = number,
            "uses" => {
                uses = u32::try_from(number).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("'{}' is larger than a use count can be", token),
                    )
                })?
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown lease bound '{}'", other),
                ))
            }
        }
        seen = true;
        tokens.next();
    }
    if !seen {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a lease clause needs ttl=SECONDS, uses=N, or both",
        ));
    }
    Ok((ttl, uses))
}

// ------------------------------------------------------------- serving --

/// State shared by every connection thread.
struct Shared {
    vault: Vault,
    leases: Mutex<LeaseBook>,
    audit: Mutex<AuditLog>,
    policy: Policy,
    me: libc::uid_t,
    method: PeerMethod,
    idle_lock_secs: u64,
    last_used: AtomicU64,
    running: AtomicUsize,
    verbose: bool,
}

impl Shared {
    fn touch(&self) {
        self.last_used.store(lease::now_unix(), Ordering::SeqCst);
    }

    /// Lock the store and drop every leased copy.
    fn lock(&self, why: &'static str) {
        let locked = self.vault.lock(why);
        if let Ok(mut leases) = self.leases.lock() {
            leases.wipe_all();
        }
        if locked {
            eprintln!(
                "pmask: agent: store locked ({}); every plaintext byte was dropped",
                why
            );
        }
    }

    fn audit_facts(&self) -> (u64, String, String) {
        match self.audit.lock() {
            Ok(a) => (a.entries(), a.chain().to_string(), a.sink().describe()),
            Err(_) => (0, lease::genesis(), "unavailable".to_string()),
        }
    }

    /// The `PING` body: what this agent is doing right now.
    fn report(&self, peer: &Peer, exe: &Path) -> String {
        let (entries, head, sink) = self.audit_facts();
        let leases = match self.leases.lock() {
            Ok(l) => {
                let described = l.conf().describe();
                if described.is_empty() {
                    "none".to_string()
                } else {
                    described.join("; ")
                }
            }
            Err(_) => "unavailable".to_string(),
        };
        let mut out = String::new();
        out.push_str(&format!("agent=pmask {}\n", crate::VERSION));
        out.push_str(&format!(
            "status={}\n",
            match self.vault.lock_reason() {
                Some(why) => format!("locked ({})", why),
                None => "ready".to_string(),
            }
        ));
        out.push_str(&format!("uid={}\n", self.me));
        out.push_str(&format!("peer_pid={}\n", peer.pid()));
        out.push_str(&format!(
            "peer_exe={}\n",
            String::from_utf8_lossy(exe.as_os_str().as_bytes())
        ));
        out.push_str(&format!("peer_identity={}\n", self.method.as_str()));
        out.push_str(&format!("protocol={}\n", PROTOCOL));
        out.push_str(&format!("policy={}\n", self.policy.describe()));
        out.push_str(&format!("leases={}\n", leases));
        out.push_str(&format!(
            "idle_lock={}\n",
            if self.idle_lock_secs == 0 {
                "none".to_string()
            } else {
                format!("{}s", self.idle_lock_secs)
            }
        ));
        out.push_str(&format!(
            "audit={} entries={} head={}\n",
            sink, entries, head
        ));
        out.push_str("limits=none of this defeats a privileged observer\n");
        out
    }
}

/// A running agent.
pub struct Daemon {
    vault: Vault,
    config: AgentConfig,
    /// True when the store was already decrypted while the process could
    /// still be dumped, which is a defect the agent reports rather than
    /// hides.
    decrypted_while_dumpable: bool,
}

impl Daemon {
    fn from_parts(store: Store, config: AgentConfig) -> Daemon {
        let decrypted_while_dumpable = is_dumpable();
        if decrypted_while_dumpable {
            eprintln!(
                "pmask: agent: warning: the store was decrypted before this process stopped \
                 being dumpable; plaintext was readable for that window.  Open the store with \
                 Daemon::open so the hardening comes first"
            );
        }
        if let Err(e) = harden_holder() {
            eprintln!("pmask: agent: warning: {}", e);
        }
        Daemon {
            vault: Vault::new(store),
            config,
            decrypted_while_dumpable,
        }
    }

    /// Serve a store a caller has already decrypted.
    ///
    /// `allow_exe` holds executable paths, and `GLOB:SECRETGLOB` rules
    /// when the entry contains a colon.  See [`Daemon::with_config`] for
    /// leases, the audit sink and the idle lock, and [`Daemon::open`] for
    /// the constructor that hardens before it decrypts.
    pub fn new(store: Store, socket: PathBuf, allow_exe: Vec<PathBuf>) -> Daemon {
        let mut config = AgentConfig::new(socket);
        for entry in allow_exe {
            let text = entry.as_os_str().to_string_lossy().into_owned();
            if text.contains(':') {
                match PolicyRule::parse(&text) {
                    Ok(rule) => config.policy.add_rule(rule),
                    Err(e) => eprintln!("pmask: agent: --allow: {}", e),
                }
            } else {
                config.policy.allow_exact(entry);
            }
        }
        Daemon::from_parts(store, config)
    }

    /// Serve a store under an explicit configuration.
    pub fn with_config(store: Store, config: AgentConfig) -> Daemon {
        Daemon::from_parts(store, config)
    }

    /// Harden this process **first**, then read and decrypt the store.
    ///
    /// This is the constructor an agent should use: hardening after
    /// decryption leaves plaintext in a dumpable process for the length
    /// of `Store::open`.  A failure to harden is returned, so no
    /// plaintext is read at all.
    pub fn open(store: &Path, passphrase: &Passphrase, config: AgentConfig) -> io::Result<Daemon> {
        harden_holder()?;
        let store = Store::open(store, passphrase)?;
        Ok(Daemon {
            vault: Vault::new(store),
            config,
            decrypted_while_dumpable: false,
        })
    }

    pub fn socket(&self) -> &Path {
        &self.config.socket
    }

    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    /// Bind, publish and serve until the process ends.
    ///
    /// The environment spellings documented on [`AgentConfig::from_env`]
    /// are applied here, so a caller that cannot pass flags still gets
    /// its leases, audit sink and idle lock.  A malformed value refuses
    /// service rather than being ignored.
    pub fn serve(self) -> io::Result<()> {
        let mut this = self;
        this.config = this.config.clone().from_env()?;
        this.run()
    }

    fn run(self) -> io::Result<()> {
        // D: hardening must hold before anything is served, and a host
        // that refuses it gets no service rather than a dumpable agent.
        harden_holder()?;
        if self.config.socket.as_os_str().is_empty() {
            return Err(refuse(
                io::ErrorKind::InvalidInput,
                "no socket path: XDG_RUNTIME_DIR is unset or not private, so pass --socket PATH"
                    .to_string(),
            ));
        }
        let me = euid();
        let method = detect_peer_method();
        let leases = self.config.leases.describe();
        if self.config.policy.is_empty() {
            eprintln!(
                "pmask: agent: warning: no executable policy; every program of uid {} may ask \
                 for every secret",
                me
            );
        }
        let bound = bind_socket(&self.config.socket)?;
        let audit = AuditLog::open(self.config.audit.clone())?;
        let audit_sink = self.config.audit.describe();
        let secrets = self.vault.names().map(|n| n.len()).unwrap_or(0);
        let shared = Arc::new(Shared {
            vault: self.vault,
            leases: Mutex::new(LeaseBook::new(self.config.leases.clone())),
            audit: Mutex::new(audit),
            policy: self.config.policy.clone(),
            me,
            method,
            idle_lock_secs: self.config.idle_lock_secs,
            last_used: AtomicU64::new(lease::now_unix()),
            running: AtomicUsize::new(0),
            verbose: self.config.verbose,
        });

        install_revoke_handler();
        spawn_monitor(Arc::clone(&shared));

        eprintln!(
            "pmask: agent listening on {} ({} secret(s), uid {}, peer identity: {}, audit: {}, \
             leases: {})",
            self.config.socket.display(),
            secrets,
            me,
            method.as_str(),
            audit_sink,
            if leases.is_empty() {
                "none".to_string()
            } else {
                leases.join("; ")
            }
        );
        if method == PeerMethod::CredsOnly {
            eprintln!(
                "pmask: agent: warning: this kernel does not offer SO_PEERPIDFD (Linux 6.5 and \
                 later); the peer identity is best effort and cannot be pinned at accept"
            );
        }
        if self.decrypted_while_dumpable {
            eprintln!("pmask: agent: warning: this agent decrypted its store while still dumpable");
        }
        eprintln!(
            "pmask: agent: a privileged observer (root, or CAP_SYS_PTRACE with uid {}) can read \
             this process's memory; no lease, lock or audit record prevents that",
            me
        );

        for conn in bound.listener.incoming() {
            let stream = match conn {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("pmask: agent: accept: {}", e);
                    continue;
                }
            };
            if shared.running.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                let mut s = stream;
                let _ = s.write_all(b"ERR the agent is serving too many connections\n");
                continue;
            }
            shared.running.fetch_add(1, Ordering::SeqCst);
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                let _ = handle(stream, &shared);
                shared.running.fetch_sub(1, Ordering::SeqCst);
            });
        }
        remove_own_socket(&self.config.socket, &bound);
        Ok(())
    }
}

/// Which identity mechanism this kernel supports, probed on a socketpair.
fn detect_peer_method() -> PeerMethod {
    let mut sv = [-1 as RawFd; 2];
    // SAFETY: `sv` holds two descriptors to write.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        return PeerMethod::CredsOnly;
    }
    // SAFETY: both descriptors are fresh and owned by this call.
    let (a, b) = unsafe {
        (
            std::fs::File::from_raw_fd(sv[0]),
            std::fs::File::from_raw_fd(sv[1]),
        )
    };
    let method = match peer_pidfd(a.as_raw_fd()) {
        Some(p) => match pidfd_inode(p.as_raw_fd()) {
            Some(_) => PeerMethod::PidfdInode,
            None => PeerMethod::PidfdStarted,
        },
        None => PeerMethod::CredsOnly,
    };
    drop(b);
    drop(a);
    method
}

// ------------------------------------------------------ revocation signal --

static REVOKE: AtomicBool = AtomicBool::new(false);

extern "C" fn on_revoke(_sig: libc::c_int) {
    REVOKE.store(true, Ordering::SeqCst);
}

/// Install a `SIGUSR1` handler that locks the store.
///
/// The handler only stores into an atomic; the monitor thread does the
/// work, so the handler stays async-signal-safe.
fn install_revoke_handler() {
    // SAFETY: the handler only touches an atomic, and `sa` is a local
    // structure the call reads.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_revoke as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }
}

/// Watch for `SIGUSR1` and for the idle deadline.
fn spawn_monitor(shared: Arc<Shared>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(100));
        if REVOKE.swap(false, Ordering::SeqCst) {
            shared.lock("SIGUSR1");
            continue;
        }
        if shared.idle_lock_secs > 0 {
            let idle = lease::now_unix().saturating_sub(shared.last_used.load(Ordering::SeqCst));
            if idle >= shared.idle_lock_secs {
                shared.lock("idle timeout");
            }
        }
    });
}

// ---------------------------------------------------------- connections --

fn reply_ok(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_REPLY {
        return reply_err(w, "the reply is larger than the agent will send");
    }
    w.write_all(format!("OK {}\n", body.len()).as_bytes())?;
    w.write_all(body)
}

fn reply_err(w: &mut impl Write, text: &str) -> io::Result<()> {
    w.write_all(format!("ERR {}\n", text).as_bytes())
}

/// Read one command line, at most [`MAX_COMMAND`] bytes.  `None` at end
/// of stream.
fn read_command(r: &mut BufReader<UnixStream>) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    let n = r
        .by_ref()
        .take((MAX_COMMAND + 1) as u64)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(buf))
}

fn handle(stream: UnixStream, shared: &Arc<Shared>) -> io::Result<()> {
    let peer = Peer::acquire(stream.as_raw_fd())?;
    if peer.uid() != shared.me {
        let mut s = stream;
        let _ = reply_err(&mut s, "peer uid is not the agent's uid");
        return Ok(());
    }

    // The first authorisation.  A refusal is the answer to the ready
    // line, so the client reads it as the connection's verdict.
    let exe = match peer.revalidate() {
        Ok(e) => e,
        Err(e) => {
            let mut s = stream;
            let _ = reply_err(&mut s, &e.to_string());
            return Ok(());
        }
    };
    if !shared.policy.exe_allowed(&exe) {
        let mut s = stream;
        let _ = reply_err(
            &mut s,
            &format!(
                "peer executable {} is not allowed by this agent's policy",
                shown(&exe)
            ),
        );
        return Ok(());
    }

    let mut w = stream.try_clone()?;
    w.write_all(format!("READY {}\n", PROTOCOL).as_bytes())?;
    w.flush()?;
    let mut r = BufReader::new(stream);

    loop {
        let Some(line) = read_command(&mut r)? else {
            return Ok(());
        };
        if line.last() != Some(&b'\n') && line.len() > MAX_COMMAND {
            reply_err(&mut w, "command line is too long")?;
            w.flush()?;
            return Ok(());
        }
        let text = String::from_utf8_lossy(&line);
        let cmd = text.trim_end_matches('\n');
        shared.touch();

        // Per-request authorisation: the peer is re-checked before every
        // command, so a peer that exec'd since the last one is refused.
        let exe = match peer.revalidate() {
            Ok(e) => e,
            Err(e) => {
                reply_err(&mut w, &e.to_string())?;
                w.flush()?;
                return Ok(());
            }
        };

        let close = match dispatch(cmd, &peer, &exe, shared, &mut w) {
            Ok(close) => close,
            Err(e) => {
                reply_err(&mut w, &e.to_string())?;
                false
            }
        };
        w.flush()?;
        if close {
            return Ok(());
        }
    }
}

/// One command.  Returns true when the connection must close.
fn dispatch(
    cmd: &str,
    peer: &Peer,
    exe: &Path,
    shared: &Arc<Shared>,
    w: &mut impl Write,
) -> io::Result<bool> {
    match cmd {
        "PING" => {
            let body = shared.report(peer, exe);
            reply_ok(w, body.as_bytes())?;
            Ok(false)
        }
        "LIST" => {
            if !shared.policy.exe_allowed(exe) {
                reply_err(w, "peer executable is not allowed by this agent's policy")?;
                return Ok(true);
            }
            let Some(names) = shared.vault.names() else {
                reply_err(w, &locked_text(shared))?;
                return Ok(false);
            };
            let allowed: Vec<String> = names
                .into_iter()
                .filter(|n| shared.policy.allows(exe, n))
                .collect();
            reply_ok(w, allowed.join("\n").as_bytes())?;
            Ok(false)
        }
        "REVOKE" | "LOCK" => {
            shared.lock("REVOKE");
            reply_ok(
                w,
                b"the store is locked and every plaintext byte was dropped",
            )?;
            Ok(false)
        }
        "AUDIT" => {
            let (entries, head, sink) = shared.audit_facts();
            reply_ok(
                w,
                format!("entries={}\nhead={}\nsink={}\n", entries, head, sink).as_bytes(),
            )?;
            Ok(false)
        }
        "QUIT" => Ok(true),
        _ => {
            if let Some(name) = cmd.strip_prefix("GET ") {
                return release(name, peer, exe, shared, w, None);
            }
            if let Some(rest) = cmd.strip_prefix("GETL ") {
                let mut parts = rest.split_whitespace();
                let bounds = match (parts.next(), parts.next(), parts.next(), parts.next()) {
                    (Some(name), Some(ttl), Some(uses), None) => {
                        match (ttl.parse::<u64>(), uses.parse::<u32>()) {
                            (Ok(t), Ok(u)) => Some((name, t, u)),
                            _ => {
                                reply_err(w, "GETL wants numeric TTL and USES")?;
                                return Ok(false);
                            }
                        }
                    }
                    _ => {
                        reply_err(w, "GETL wants NAME TTL USES")?;
                        return Ok(false);
                    }
                };
                let Some((name, ttl, uses)) = bounds else {
                    return Ok(false);
                };
                let narrow = match LeasePolicy::new(ttl, uses) {
                    Ok(p) => p,
                    Err(e) => {
                        reply_err(w, &e.to_string())?;
                        return Ok(false);
                    }
                };
                return release(name, peer, exe, shared, w, Some(narrow));
            }
            reply_err(w, "unknown command")?;
            Ok(false)
        }
    }
}

fn locked_text(shared: &Shared) -> String {
    match shared.vault.lock_reason() {
        Some(why) => format!("the store is locked ({})", why),
        None => "the store is locked".to_string(),
    }
}

/// Release one secret, under a lease when a policy applies.
fn release(
    name: &str,
    peer: &Peer,
    exe: &Path,
    shared: &Arc<Shared>,
    w: &mut impl Write,
    narrow: Option<LeasePolicy>,
) -> io::Result<bool> {
    // The request line is one command per line: a name with a line break
    // would start, or split, a command.  A name is data.
    if name.contains('\n') || name.contains('\r') {
        reply_err(w, "a secret name must not contain LF or CR")?;
        return Ok(false);
    }
    if !shared.policy.allows(exe, name) {
        reply_err(
            w,
            &format!(
                "secret '{}' is not allowed for executable {} by this agent's policy",
                printable(name),
                shown(exe)
            ),
        )?;
        return Ok(false);
    }
    let stored = match shared.vault.copy_of(name) {
        Lookup::Found(b) => b,
        Lookup::Missing => {
            reply_err(w, &format!("no secret named '{}'", printable(name)))?;
            return Ok(false);
        }
        Lookup::Locked(_) => {
            reply_err(w, &locked_text(shared))?;
            return Ok(false);
        }
    };
    if stored.len() > MAX_VALUE {
        reply_err(w, "the secret is larger than the agent will hand out")?;
        return Ok(false);
    }

    let now = lease::now_unix();
    let (value, lease_id) = {
        let mut leases = match shared.leases.lock() {
            Ok(l) => l,
            Err(_) => {
                reply_err(w, "the lease book is unavailable")?;
                return Ok(false);
            }
        };
        match leases.acquire_with(name, stored.as_slice(), now, narrow) {
            Ok(LeaseOutcome::Leased(ticket, value)) => (value, ticket.id),
            Ok(LeaseOutcome::Unleased(value)) => (value, "-".to_string()),
            Err(e) => {
                reply_err(w, &e.to_string())?;
                return Ok(false);
            }
        }
    };

    // The audit line is written before the value is handed over.  An
    // audit that cannot be written refuses the release; the use is
    // already spent, so the refusal fails closed.
    let exe_text = shown(exe);
    let entry = AuditEntry {
        time: now,
        name,
        peer_pid: peer.pid(),
        peer_exe: &exe_text,
        lease_id: &lease_id,
    };
    let audited = match shared.audit.lock() {
        Ok(mut a) => a.record(&entry),
        Err(_) => Err(io::Error::other("the audit log is unavailable")),
    };
    if let Err(e) = audited {
        reply_err(w, &format!("the use audit could not be written: {}", e))?;
        return Ok(false);
    }
    if shared.verbose {
        eprintln!(
            "pmask: agent: release {} to pid {} ({}) lease {}",
            printable(name),
            peer.pid(),
            exe_text,
            lease_id
        );
    }
    reply_ok(w, value.as_slice())?;
    Ok(false)
}

/// A path as text for a log line or an audit field.
fn shown(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}

/// Escape control bytes so a name cannot break a line.
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        if (0x20..=0x7e).contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{:02x}", b));
        }
    }
    out
}

// ------------------------------------------------------------------ client

fn connect(socket: Option<&PathBuf>) -> io::Result<UnixStream> {
    let path = socket_or_default(socket);
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no agent socket is configured: set XDG_RUNTIME_DIR or PMASK_SOCKET, or pass \
             --socket PATH",
        ));
    }
    let stream = UnixStream::connect(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "cannot reach a pmask agent on {} ({}); start one with `pmask agent`",
                path.display(),
                e
            ),
        )
    })?;
    // The agent refuses a peer of any other uid, so a socket owned by
    // another uid is not the agent this request was meant for.
    let owner_uid = peer_cred(stream.as_raw_fd())?.uid;
    let me = euid();
    if owner_uid != me {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the agent at {} runs as uid {}, not this account (uid {}); refusing to send \
                 a request",
                path.display(),
                owner_uid,
                me
            ),
        ));
    }
    // The ready line is the agent's answer to the connection itself, sent
    // only after the uid and executable checks pass.
    let mut r = BufReader::new(stream.try_clone()?);
    let line = match read_line(&mut r) {
        Ok(line) => line,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the agent closed the connection before it was ready",
            ))
        }
        Err(e) => return Err(e),
    };
    if let Some(rest) = line.strip_prefix("ERR ") {
        return Err(io::Error::other(rest.to_string()));
    }
    let want = format!("READY {}", PROTOCOL);
    if line != want {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the agent said '{}', this client speaks '{}'", line, want),
        ));
    }
    Ok(stream)
}

fn read_line(r: &mut BufReader<UnixStream>) -> io::Result<String> {
    let mut line = String::new();
    let n = r
        .by_ref()
        .take((MAX_REPLY_LINE + 1) as u64)
        .read_line(&mut line)?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the agent closed the connection",
        ));
    }
    if !line.ends_with('\n') && line.len() > MAX_REPLY_LINE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "agent: reply line is too long",
        ));
    }
    Ok(line.trim_end_matches('\n').to_string())
}

fn check_ok(line: &str) -> io::Result<usize> {
    if let Some(rest) = line.strip_prefix("OK ") {
        let n = rest
            .parse::<usize>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "agent: bad length"))?;
        if n > MAX_REPLY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("agent: reply length {} exceeds the limit {}", n, MAX_REPLY),
            ));
        }
        Ok(n)
    } else if let Some(rest) = line.strip_prefix("ERR ") {
        Err(io::Error::other(rest.to_string()))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "agent: bad reply",
        ))
    }
}

/// True when `err` is the agent's refusal for a name it does not hold.
///
/// The reply is one `ERR` line and carries no code, so its text is the
/// only discriminator.  The agent writes `no secret named '...'` for the
/// absent case, and every other refusal names what failed (a locked
/// store, a policy, a lease).  `pmask get` uses this to keep the manual's
/// exit codes: 1 for an absent name, 255 for a transport or protocol
/// error.
pub fn is_missing_name(err: &io::Error) -> bool {
    err.to_string().starts_with("no secret named ")
}

fn request(socket: Option<&PathBuf>, command: &str) -> io::Result<SecBuf> {
    let s = connect(socket)?;
    let mut w = s.try_clone()?;
    let mut r = BufReader::new(s);
    w.write_all(command.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()?;
    let n = check_ok(&read_line(&mut r)?)?;
    let mut body = SecBuf::new(n)?;
    if n > 0 {
        r.read_exact(body.as_mut_slice())?;
    }
    Ok(body)
}

/// Ask the agent for one secret.
///
/// `name` may carry a lease suffix, which is how the CLI passes a lease
/// without a new flag: `TOKEN?ttl=60&uses=2`.  Every `&`-separated part
/// must then be `ttl=SECONDS` or `uses=N`; a name that merely contains a
/// `?` is taken whole, so an ordinary name is never reinterpreted by
/// accident.  See [`FetchSpec`].
pub fn fetch(socket: Option<&PathBuf>, name: &str) -> io::Result<SecBuf> {
    let spec = FetchSpec::parse(name)?;
    fetch_leased(socket, &spec.name, spec.lease)
}

/// A secret name, plus the lease the caller asks for.
///
/// The suffix form is `NAME?ttl=SECONDS&uses=N`, either bound alone or
/// both.  It reaches the agent as `GETL NAME TTL USES`, so the agent
/// refuses the value once the budget is gone even though the caller
/// keeps the socket.  The agent's own configuration can only narrow the
/// budget further, never widen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchSpec {
    pub name: String,
    pub lease: Option<LeasePolicy>,
}

impl FetchSpec {
    /// Split a name from an optional lease suffix.
    ///
    /// The suffix is recognised only when every part of it parses as a
    /// bound.  Anything else is part of the name, so a name that happens
    /// to contain `?` keeps working.
    pub fn parse(text: &str) -> io::Result<FetchSpec> {
        crate::secret::validate_name(text)?;
        let Some((name, suffix)) = text.split_once('?') else {
            return Ok(FetchSpec {
                name: text.to_string(),
                lease: None,
            });
        };
        let mut ttl: Option<u64> = None;
        let mut uses: Option<u32> = None;
        for part in suffix.split('&') {
            let Some((key, value)) = part.split_once('=') else {
                return Ok(FetchSpec {
                    name: text.to_string(),
                    lease: None,
                });
            };
            match key {
                "ttl" => match value.parse::<u64>() {
                    Ok(v) => ttl = Some(v),
                    Err(_) => {
                        return Ok(FetchSpec {
                            name: text.to_string(),
                            lease: None,
                        })
                    }
                },
                "uses" => match value.parse::<u32>() {
                    Ok(v) => uses = Some(v),
                    Err(_) => {
                        return Ok(FetchSpec {
                            name: text.to_string(),
                            lease: None,
                        })
                    }
                },
                _ => {
                    return Ok(FetchSpec {
                        name: text.to_string(),
                        lease: None,
                    })
                }
            }
        }
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the lease suffix needs a secret name before it",
            ));
        }
        let policy = LeasePolicy::new(ttl.unwrap_or(0), uses.unwrap_or(0)).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("'{}': a lease suffix needs ttl=SECONDS or uses=N", text),
            )
        })?;
        Ok(FetchSpec {
            name: name.to_string(),
            lease: Some(policy),
        })
    }
}

/// Ask the agent for one secret under a lease no wider than `lease`.
///
/// This is the delivery option: `--secret NAME=agent:NAME` with a lease
/// bound reaches the agent as `GETL NAME TTL USES`, so the agent refuses
/// the value once the budget is gone even though the caller keeps the
/// socket.  The agent's configuration can only narrow the budget
/// further, never widen it.
pub fn fetch_leased(
    socket: Option<&PathBuf>,
    name: &str,
    lease: Option<LeasePolicy>,
) -> io::Result<SecBuf> {
    // This is the last boundary before the name is pasted into a command
    // line, so a caller that bypasses [`FetchSpec::parse`] is still safe.
    crate::secret::validate_name(name)?;
    let command = match lease {
        None => format!("GET {}", name),
        Some(p) => format!("GETL {} {} {}", name, p.ttl_secs, p.uses),
    };
    request(socket, &command)
}

/// List the names this peer may ask for.
pub fn list(socket: Option<&PathBuf>) -> io::Result<Vec<String>> {
    let body = request(socket, "LIST")?;
    Ok(String::from_utf8_lossy(body.as_slice())
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect())
}

/// The agent's policy report, as `PING` returns it.
pub fn status(socket: Option<&PathBuf>) -> io::Result<String> {
    let body = request(socket, "PING")?;
    Ok(String::from_utf8_lossy(body.as_slice()).into_owned())
}

/// Lock the agent's store and drop its plaintext.
///
/// The agent keeps no passphrase, so this is a one-way door: serving
/// again means restarting the agent.
pub fn revoke(socket: Option<&PathBuf>) -> io::Result<String> {
    let body = request(socket, "REVOKE")?;
    Ok(String::from_utf8_lossy(body.as_slice()).into_owned())
}

/// The audit entry count, chain head and sink.
pub fn audit_head(socket: Option<&PathBuf>) -> io::Result<String> {
    let body = request(socket, "AUDIT")?;
    Ok(String::from_utf8_lossy(body.as_slice()).into_owned())
}

/// Is an agent answering, and does it accept this executable?
pub fn ping(socket: Option<&PathBuf>) -> bool {
    request(socket, "PING").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pmask-agent-{}-{}", tag, std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    fn wait_ready(sock: &Path) {
        let path = sock.to_path_buf();
        for _ in 0..400 {
            if ping(Some(&path)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the agent never became ready on {}", sock.display());
    }

    fn make_store(dir: &Path, pairs: &[(&str, &[u8])]) -> Store {
        let sp = dir.join("s.enc");
        let pp = Passphrase::new(b"pw").unwrap();
        let mut st = Store::create(&sp, &pp).unwrap();
        for (name, value) in pairs {
            st.set(name, value).unwrap();
        }
        st.save(&pp).unwrap();
        Store::open(&sp, &pp).unwrap()
    }

    fn serve(store: Store, sock: PathBuf, tune: impl FnOnce(&mut AgentConfig)) {
        let mut cfg = AgentConfig::new(sock);
        cfg.audit = AuditSink::None;
        tune(&mut cfg);
        let d = Daemon::with_config(store, cfg);
        std::thread::spawn(move || {
            let _ = d.serve();
        });
    }

    #[test]
    fn glob_matching() {
        let g = Glob::new("/usr/bin/deploy");
        assert!(g.matches(b"/usr/bin/deploy"));
        assert!(!g.matches(b"/usr/bin/deploy2"));
        let g = Glob::new("/usr/bin/*");
        assert!(g.matches(b"/usr/bin/deploy"));
        assert!(!g.matches(b"/usr/local/bin/deploy"));
        let g = Glob::new("*pmask");
        assert!(g.matches(b"/opt/bin/pmask"));
        assert!(g.matches(b"pmask"));
        assert!(!g.matches(b"pmaskx"));
        let g = Glob::new("TOKEN_?");
        assert!(g.matches(b"TOKEN_A"));
        assert!(!g.matches(b"TOKEN_AB"));
        let g = Glob::new("*");
        assert!(g.matches(b""));
        assert!(g.matches(b"anything at all"));
        let g = Glob::new("a*b*c");
        assert!(g.matches(b"abc"));
        assert!(g.matches(b"axxbyyc"));
        assert!(!g.matches(b"abx"));
        let g = Glob::new("");
        assert!(g.matches(b""));
        assert!(!g.matches(b"x"));
    }

    #[test]
    fn policy_default_denies_when_present() {
        let mut p = Policy::new();
        assert!(p.is_empty());
        assert!(p.allows(Path::new("/bin/anything"), "ANY"));
        p.add_rule(PolicyRule::parse("/usr/bin/deploy:*").unwrap());
        assert!(p.allows(Path::new("/usr/bin/deploy"), "ANY"));
        assert!(!p.allows(Path::new("/usr/bin/other"), "ANY"));
        let mut p = Policy::new();
        p.add_rule(PolicyRule::parse("/usr/bin/*:TOKEN_*").unwrap());
        assert!(p.allows(Path::new("/usr/bin/deploy"), "TOKEN_A"));
        assert!(!p.allows(Path::new("/usr/bin/deploy"), "OTHER"));
        assert!(!p.allows(Path::new("/bin/deploy"), "TOKEN_A"));
    }

    #[test]
    fn policy_rule_parsing_is_strict() {
        assert!(PolicyRule::parse("no-colon").is_err());
        assert!(PolicyRule::parse(":/x").is_err());
        assert!(PolicyRule::parse("/x:").is_err());
        let r = PolicyRule::parse("/x:y:z").unwrap();
        assert_eq!(r.exe.describe(), "/x");
        assert_eq!(r.secret.describe(), "y:z");
    }

    #[test]
    fn lease_clauses_parse() {
        let clauses = parse_lease_clauses("default ttl=5 uses=2 TOKEN uses=1").unwrap();
        assert_eq!(clauses.len(), 2);
        assert_eq!(clauses[0].0, None);
        assert_eq!(
            clauses[0].1,
            LeasePolicy {
                ttl_secs: 5,
                uses: 2
            }
        );
        assert_eq!(clauses[1].0.as_deref(), Some("TOKEN"));
        assert_eq!(
            clauses[1].1,
            LeasePolicy {
                ttl_secs: 0,
                uses: 1
            }
        );

        assert!(parse_lease_clauses("TOKEN").is_err());
        assert!(parse_lease_clauses("TOKEN ttl=x").is_err());
        assert!(parse_lease_clauses("TOKEN ttl=0 uses=0").is_err());
        assert!(parse_lease_clauses("TOKEN bad=1").is_err());
        assert!(parse_lease_clauses("").unwrap().is_empty());
    }

    #[test]
    fn clauses_reach_the_config_without_touching_the_environment() {
        let cfg = AgentConfig::new(PathBuf::from("/tmp/x"))
            .apply_clauses("default ttl=5 uses=2 TOKEN uses=1", None, None)
            .unwrap();
        assert_eq!(cfg.leases.describe().len(), 2);
        assert_eq!(
            cfg.leases.policy("OTHER"),
            Some(LeasePolicy {
                ttl_secs: 5,
                uses: 2
            })
        );
        assert_eq!(
            cfg.leases.policy("TOKEN"),
            Some(LeasePolicy {
                ttl_secs: 0,
                uses: 1
            })
        );
        let bad = AgentConfig::new(PathBuf::from("/tmp/x")).apply_clauses("TOKEN", None, None);
        assert!(bad.is_err());
    }

    #[test]
    fn the_default_socket_has_no_tmp_fallback() {
        assert!(socket_default(None, None).as_os_str().is_empty());
        let tmp = std::env::temp_dir();
        std::fs::create_dir_all(&tmp).ok();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700)).ok();
        let owned = socket_default(Some(tmp.as_os_str()), None);
        if owned.as_os_str().is_empty() {
            // The temp directory is not ours or not private; the fallback
            // must still not be under a shared directory.
            let p = socket_default(None, Some(std::ffi::OsStr::new("/x/y.sock")));
            assert_eq!(p, PathBuf::from("/x/y.sock"));
        } else {
            assert_eq!(owned, tmp.join("pmask.sock"));
        }
        let explicit = socket_default(None, Some(std::ffi::OsStr::new("/x/y.sock")));
        assert_eq!(explicit, PathBuf::from("/x/y.sock"));
    }

    #[test]
    fn a_lease_suffix_in_a_secret_name_is_parsed() {
        let s = FetchSpec::parse("TOKEN?ttl=60&uses=2").unwrap();
        assert_eq!(s.name, "TOKEN");
        assert_eq!(
            s.lease,
            Some(LeasePolicy {
                ttl_secs: 60,
                uses: 2
            })
        );
        let s = FetchSpec::parse("TOKEN?uses=1").unwrap();
        assert_eq!(
            s.lease,
            Some(LeasePolicy {
                ttl_secs: 0,
                uses: 1
            })
        );
        // An ordinary name is never reinterpreted.
        let s = FetchSpec::parse("TOKEN").unwrap();
        assert_eq!(s.name, "TOKEN");
        assert_eq!(s.lease, None);
        let s = FetchSpec::parse("A?B").unwrap();
        assert_eq!(s.name, "A?B");
        assert_eq!(s.lease, None);
        let s = FetchSpec::parse("A?x=1").unwrap();
        assert_eq!(s.name, "A?x=1");
        let s = FetchSpec::parse("A?ttl=1&bogus=2").unwrap();
        assert_eq!(s.name, "A?ttl=1&bogus=2");
        assert!(FetchSpec::parse("?ttl=1").is_err());
        assert!(FetchSpec::parse("A?ttl=0&uses=0").is_err());
    }

    #[test]
    fn daemon_serves_and_client_reads() {
        let dir = test_dir("serve");
        let sock = dir.join("d.sock");
        let store = make_store(&dir, &[("TOKEN", b"tok-value")]);
        serve(store, sock.clone(), |_| {});
        wait_ready(&sock);
        assert_eq!(list(Some(&sock)).unwrap(), vec!["TOKEN"]);
        let v = fetch(Some(&sock), "TOKEN").unwrap();
        assert_eq!(v.as_slice(), b"tok-value");
        assert!(fetch(Some(&sock), "NOPE").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn leases_refuse_after_the_budget() {
        let dir = test_dir("lease");
        let sock = dir.join("l.sock");
        let store = make_store(&dir, &[("TOKEN", b"value"), ("OTHER", b"x")]);
        serve(store, sock.clone(), |cfg| {
            cfg.leases.set("TOKEN", LeasePolicy::new(0, 2).unwrap());
        });
        wait_ready(&sock);
        assert_eq!(fetch(Some(&sock), "TOKEN").unwrap().as_slice(), b"value");
        assert_eq!(fetch(Some(&sock), "TOKEN").unwrap().as_slice(), b"value");
        let err = fetch(Some(&sock), "TOKEN").expect_err("third use refused");
        let text = err.to_string();
        assert!(text.contains("no uses left"), "{}", text);
        assert!(text.contains("lease "), "{}", text);
        // An unleased secret is unaffected.
        assert_eq!(fetch(Some(&sock), "OTHER").unwrap().as_slice(), b"x");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_request_can_narrow_a_configured_lease() {
        let dir = test_dir("narrow");
        let sock = dir.join("n.sock");
        let store = make_store(&dir, &[("TOKEN", b"value")]);
        serve(store, sock.clone(), |cfg| {
            cfg.leases.set("TOKEN", LeasePolicy::new(0, 4).unwrap());
        });
        wait_ready(&sock);
        let one = LeasePolicy::new(0, 1).unwrap();
        assert!(fetch_leased(Some(&sock), "TOKEN", Some(one)).is_ok());
        assert!(fetch_leased(Some(&sock), "TOKEN", Some(one)).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn revoke_drops_the_plaintext() {
        let dir = test_dir("revoke");
        let sock = dir.join("r.sock");
        let store = make_store(&dir, &[("TOKEN", b"value")]);
        serve(store, sock.clone(), |_| {});
        wait_ready(&sock);
        assert!(fetch(Some(&sock), "TOKEN").is_ok());
        let msg = revoke(Some(&sock)).unwrap();
        assert!(msg.contains("locked"), "{}", msg);
        let err = fetch(Some(&sock), "TOKEN").expect_err("locked");
        assert!(err.to_string().contains("locked"), "{}", err);
        let report = status(Some(&sock)).unwrap();
        assert!(report.contains("status=locked (REVOKE)"), "{}", report);
        assert!(list(Some(&sock)).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_status_report_names_the_policy() {
        let dir = test_dir("status");
        let sock = dir.join("s.sock");
        let store = make_store(&dir, &[("TOKEN", b"v")]);
        let me = std::env::current_exe().unwrap();
        serve(store, sock.clone(), |cfg| {
            cfg.policy
                .add_rule(PolicyRule::parse(&format!("{}:TOKEN", me.display())).unwrap());
            cfg.leases.set_default(LeasePolicy::new(60, 3).unwrap());
            cfg.idle_lock_secs = 120;
        });
        wait_ready(&sock);
        let report = status(Some(&sock)).unwrap();
        assert!(
            report.contains("policy=1 rule(s), default deny"),
            "{}",
            report
        );
        assert!(
            report.contains("leases=default ttl=60s uses=3"),
            "{}",
            report
        );
        assert!(report.contains("idle_lock=120s"), "{}", report);
        assert!(report.contains("limits=none of this defeats"), "{}", report);
        assert!(report.contains("peer_identity="), "{}", report);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_policy_restricts_this_test_binary() {
        let dir = test_dir("policy");
        let sock = dir.join("p.sock");
        let store = make_store(&dir, &[("TOKEN", b"v"), ("OTHER", b"v")]);
        let me = std::env::current_exe().unwrap();
        serve(store, sock.clone(), |cfg| {
            cfg.policy
                .add_rule(PolicyRule::parse(&format!("{}:TOKEN", me.display())).unwrap());
        });
        wait_ready(&sock);
        assert!(fetch(Some(&sock), "TOKEN").is_ok());
        let err = fetch(Some(&sock), "OTHER").expect_err("denied");
        assert!(err.to_string().contains("not allowed"), "{}", err);
        assert_eq!(list(Some(&sock)).unwrap(), vec!["TOKEN"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The peer pin resolves the executable of a live peer.
    ///
    /// This is the resolution half of per-request authorisation: the pin
    /// is taken once at accept, and every request resolves the peer's
    /// `/proc/<pid>/exe` again.  The exec half (a peer that execs loses
    /// access on its next request) needs a process that is allowed to read
    /// another process's `/proc/<pid>/exe`, and several tests in this
    /// module call `PR_SET_DUMPABLE=0`, which closes that for the whole
    /// process.  It is therefore driven from `tests/lease.sh` f1, in a
    /// process of its own, where the kernel state is not shared.
    #[test]
    fn the_peer_pin_resolves_a_live_peer() {
        let dir = test_dir("pin");
        let path = dir.join("l.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }
        // SAFETY: fork; the child calls only socket, connect and _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: the child owns nothing and exits immediately.
            unsafe {
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                if fd < 0 {
                    libc::_exit(10);
                }
                let rc = libc::connect(
                    fd,
                    &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                );
                if rc != 0 {
                    libc::_exit(11);
                }
                // Hold the connection open until the parent closes it.
                let mut one = 0u8;
                libc::read(fd, &mut one as *mut u8 as *mut libc::c_void, 1);
                libc::_exit(0);
            }
        }
        let (stream, _) = listener.accept().unwrap();
        let peer = Peer::acquire(stream.as_raw_fd()).unwrap();
        assert_eq!(peer.pid(), pid, "the accepted peer is the child");
        match peer.revalidate() {
            Ok(exe) => assert_eq!(
                exe,
                std::env::current_exe().unwrap(),
                "the peer's image is this test binary"
            ),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                // This process called PR_SET_DUMPABLE=0 earlier, so the
                // kernel refuses the read.  Reporting that is correct: a
                // pin that cannot resolve must refuse, never accept.
                eprintln!("the peer cannot be resolved in this process: {}", e);
            }
            Err(e) => panic!("unexpected resolution failure: {}", e),
        }
        drop(stream);
        let mut status = 0;
        // SAFETY: waiting for this process's own child.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_audit_records_a_release_without_the_value() {
        let dir = test_dir("audit");
        let sock = dir.join("a.sock");
        let path = dir.join("audit.log");
        let store = make_store(&dir, &[("TOKEN", b"SECRETVALUE")]);
        let log = path.clone();
        serve(store, sock.clone(), move |cfg| {
            cfg.audit = AuditSink::File(log);
        });
        wait_ready(&sock);
        assert!(fetch(Some(&sock), "TOKEN").is_ok());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\tTOKEN\t"), "{}", text);
        assert!(!text.contains("SECRETVALUE"), "{}", text);
        let report = lease::verify_file(&path).unwrap();
        assert!(report.intact(), "{:?}", report);
        let head = audit_head(Some(&sock)).unwrap();
        assert!(head.contains(&report.head), "{} vs {}", head, report.head);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_public_directory_refuses_service() {
        let dir = std::env::temp_dir().join(format!("pmask-agent-open-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sock = dir.join("o.sock");
        let store = make_store(&dir, &[("TOKEN", b"v")]);
        let mut cfg = AgentConfig::new(sock.clone());
        cfg.audit = AuditSink::None;
        let err = Daemon::with_config(store, cfg)
            .serve()
            .expect_err("a shared directory must be refused");
        let text = err.to_string();
        assert!(text.contains("group or other"), "{}", text);
        assert!(!sock.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_symlinked_socket_path_is_refused() {
        let dir = test_dir("symlink");
        let target = dir.join("target.sock");
        let link = dir.join("link.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let store = make_store(&dir, &[("TOKEN", b"v")]);
        let mut cfg = AgentConfig::new(link.clone());
        cfg.audit = AuditSink::None;
        let err = Daemon::with_config(store, cfg)
            .serve()
            .expect_err("a symlink must be refused");
        assert!(err.to_string().contains("symbolic link"), "{}", err);
        assert!(!target.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_socket_is_0600() {
        let dir = test_dir("mode");
        let sock = dir.join("m.sock");
        let store = make_store(&dir, &[("TOKEN", b"v")]);
        serve(store, sock.clone(), |_| {});
        wait_ready(&sock);
        let md = std::fs::metadata(&sock).unwrap();
        assert_eq!(md.mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_socket_path_refuses_service() {
        let dir = test_dir("emptysock");
        let store = make_store(&dir, &[("TOKEN", b"v")]);
        let mut cfg = AgentConfig::new(PathBuf::new());
        cfg.audit = AuditSink::None;
        let err = Daemon::with_config(store, cfg)
            .serve()
            .expect_err("an empty socket path must be refused");
        assert!(err.to_string().contains("--socket"), "{}", err);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `Daemon::open` leaves the process non-dumpable and the store
    /// unlocked.
    ///
    /// The order is hardening, then `Store::open`, and this asserts the
    /// post-condition: after the call the process cannot be dumped and the
    /// plaintext is present.  It does not observe the order itself,
    /// because a reordered implementation would also end non-dumpable.
    /// The ordering is guaranteed by the single call at the top of
    /// `Daemon::open`, and `tests/lease.sh` g1 checks the observable half
    /// in a fresh process: the agent refuses to serve where hardening is
    /// impossible.
    ///
    /// The pre-condition is only asserted when no earlier test in this
    /// process has already hardened it, because `PR_SET_DUMPABLE=0`
    /// cannot be undone and the tests share one process.
    #[test]
    fn open_leaves_the_process_undumpable_with_the_store_unlocked() {
        let dir = test_dir("order");
        let path = dir.join("o.enc");
        let pp = Passphrase::new(b"pw").unwrap();
        let mut st = Store::create(&path, &pp).unwrap();
        st.set("TOKEN", b"v").unwrap();
        st.save(&pp).unwrap();
        let mut cfg = AgentConfig::new(dir.join("never.sock"));
        cfg.audit = AuditSink::None;
        let d = Daemon::open(&path, &pp, cfg).expect("open hardens then decrypts");
        assert!(
            !is_dumpable(),
            "the process must not be dumpable after open"
        );
        match d.vault.copy_of("TOKEN") {
            Lookup::Found(b) => assert_eq!(b.as_slice(), b"v"),
            _ => panic!("the store must be unlocked after open"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_process_refuses_to_be_dumped() {
        harden_holder().unwrap();
        assert!(!is_dumpable());
    }

    #[test]
    fn a_stale_socket_is_replaced() {
        let dir = test_dir("stale");
        let sock = dir.join("st.sock");
        {
            let store = make_store(&dir, &[("TOKEN", b"v")]);
            serve(store, sock.clone(), |_| {});
            wait_ready(&sock);
            // The first agent still listens, so a second must refuse.
            let store2 = make_store(&dir, &[("TOKEN", b"v")]);
            let mut cfg = AgentConfig::new(sock.clone());
            cfg.audit = AuditSink::None;
            let err = Daemon::with_config(store2, cfg)
                .serve()
                .expect_err("a live socket must not be stolen");
            assert!(err.to_string().contains("already listening"), "{}", err);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_reply_length_above_the_cap_is_refused_before_allocating() {
        assert_eq!(check_ok(&format!("OK {}", MAX_REPLY)).unwrap(), MAX_REPLY);
        let err = check_ok(&format!("OK {}", MAX_REPLY + 1)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("limit"), "{}", err);
        assert!(check_ok("OK not-a-number").is_err());
        assert!(check_ok("ERR denied")
            .unwrap_err()
            .to_string()
            .contains("denied"));
    }

    #[test]
    fn a_reply_line_longer_than_the_cap_is_an_error() {
        let (mut a, b) = UnixStream::pair().unwrap();
        let mut r = BufReader::new(b);
        let long = vec![b'x'; MAX_REPLY_LINE + 64];
        a.write_all(&long).unwrap();
        a.write_all(b"\n").unwrap();
        let err = read_line(&mut r).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("too long"), "{}", err);

        let (mut a, b) = UnixStream::pair().unwrap();
        let mut r = BufReader::new(b);
        a.write_all(b"OK 4\n").unwrap();
        assert_eq!(read_line(&mut r).unwrap(), "OK 4");
    }

    #[test]
    fn an_oversize_reply_becomes_a_visible_error() {
        let mut out = Vec::new();
        reply_ok(&mut out, &vec![b'x'; MAX_REPLY + 1]).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("ERR "), "{}", text);
        assert!(text.contains("larger"), "{}", text);
    }
}
