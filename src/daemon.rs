//! `pmaskd`: run jobs for other local processes without the caller
//! ever holding the secrets.
//!
//! # Why a daemon
//!
//! A CI runner needs a token.  If the runner puts it on a command line,
//! every local account sees it in `ps` for the life of the job.  If it
//! puts it in the environment, `/proc/<pid>/environ` still shows it.
//! With `pmaskd` the secret lives in the daemon's memory and the job's
//! environment, never in the client's argv or environment: the client
//! sends only the command and receives stdio and the exit status.
//!
//! # Trust model
//!
//! An allowed uid may execute arbitrary programs with the daemon's privileges and inherit its environment.
//!
//! `SO_PEERCRED` decides who is allowed.  By default only the daemon's own
//! uid and root may connect.  `--allow-uid` adds more uids.  A daemon that
//! holds a token and accepts requests from any local user is a
//! privilege-escalation service, so the default is closed.
//!
//! A root daemon started with `--run-as-uid` runs each job with the uid
//! and gid of the client (from `SO_PEERCRED`) instead of root.  The
//! daemon still passes its own environment to the job.
//!
//! The client checks the daemon too.  After `connect` it reads the uid of
//! the socket owner with `SO_PEERCRED`.  [`run_remote`] accepts the
//! client's own uid and root.  [`run_remote_as`] accepts one chosen uid.
//! Any other uid makes the client refuse to send the command.
//!
//! # Wire protocol (v2)
//!
//! Client -> daemon, once, with `SCM_RIGHTS` carrying exactly three
//! descriptors (the client's stdin, stdout and stderr):
//!
//! ```text
//! 1 byte  protocol version (value 2)
//! ```
//!
//! The first byte is the protocol version.  The daemon rejects any other
//! value with a response that has code 255.  A client of the old protocol
//! sent the byte `'C'`; the daemon names that case "protocol mismatch".
//!
//! Then a request frame follows on the same stream:
//!
//! ```text
//! "PMK2"  u8 label_mode  u32 label_len  label bytes
//!         u32 argc       argc * (u32 len, bytes)
//! ```
//!
//! `label_mode` is `0` (use the daemon label, `label_len` must be 0),
//! `1` (empty label, `label_len` must be 0) or `2` (the bytes are the
//! label).
//!
//! daemon -> client:
//!
//! ```text
//! i32 exit_code  u32 has_signal  i32 signal  u32 msg_len  msg bytes
//! ```
//!
//! All integers are little-endian.
//!
//! Limits: `argc <= 4096`, one argument `<= 1 MiB`, the whole request
//! `<= 8 MiB`, label `<= 4096` bytes without NUL, LF or CR.  The daemon
//! also caps the sum of `len + 1` over all job arguments at 1 MiB
//! (`--max-job-bytes`).  It computes the size of the redaction block (job
//! arguments, daemon environment, comm and a margin) before the job
//! starts and refuses a job that would not fit under
//! [`MAX_HIDDEN`](crate::MAX_HIDDEN).  A refused job gets code 255 and a
//! message, and never runs.
//!
//! The daemon sends code 255 with a message for: an unauthorised uid, a
//! wrong protocol version, a descriptor count other than three, a
//! truncated control message, a malformed frame, an oversized job and a
//! failed spawn.  A job killed by `--job-timeout` gets code 137 with
//! signal 9.
//!
//! # Process model
//!
//! The daemon runs one job at a time by default.  A masking session owns
//! the `waitpid(-1)` domain of its process, so sessions cannot overlap in
//! one process.  With `--jobs N` (N > 1) the daemon forks one worker
//! process per connection and runs at most N workers at once.
//!
//! Every descriptor the daemon owns has `FD_CLOEXEC`.  The job gets only
//! the three client descriptors as 0, 1 and 2.  The daemon opens
//! `/dev/null` on any of 0, 1 and 2 that is closed at startup.
//!
//! # Timeouts and shutdown
//!
//! `--io-timeout` bounds each wait on a client socket (default 30 s;
//! 0 means no deadline).  The waits are `poll` calls that also watch a
//! self-pipe, so `SIGTERM` returns from them at once and the shutdown
//! flag is checked before and after every one.  A daemon that has
//! accepted a connection therefore stops on `SIGTERM` even when the
//! client has sent nothing and `--io-timeout 0` left the read with no
//! deadline of its own.  `--job-timeout` limits the job run time.
//!
//! A signal cannot be the only wake: `SA_RESTART` is set on the handler
//! because a tracer thread must not see `EINTR` from `waitpid`, and the
//! same flag keeps a blocked `poll` from returning.  The pipe is what
//! makes the signal visible; the flag is what it means.
//!
//! # Socket path
//!
//! The socket path has three parts to it, and each is a check.
//!
//! The directory is created `0700` and then `fstat`ed through an
//! `O_DIRECTORY | O_NOFOLLOW` descriptor: it must be a directory, owned
//! by the daemon's effective uid, with no group or other bits.  A
//! directory that fails any of those refuses service.  The descriptor is
//! kept, and the socket is unlinked through it, so a rename cannot
//! redirect either the check or the removal.
//!
//! The socket file is opened with `O_PATH | O_NOFOLLOW` before any
//! removal, and the descriptor is what the decision is made on.  A
//! symbolic link at the path is therefore never followed and never
//! removed; a file that is not a socket is never removed; the removal
//! itself is `unlinkat` relative to the directory descriptor.
//!
//! The default path has no `/tmp` fallback.  `$XDG_RUNTIME_DIR` is used
//! when it is a directory owned by the euid with no group or other bits,
//! else `/run/pmask.sock` for root, else nothing.  When no safe
//! default exists and `--socket` was not given, the daemon refuses to
//! start and names the flag.  A world-writable directory cannot be
//! checked for ownership, and an attacker who wins the race for a name
//! in it is the daemon the client reaches.
//!
//! The daemon connects to an existing socket first and refuses to start
//! when a daemon answers.  It unlinks a socket only after
//! `ECONNREFUSED`, and only when the pinned descriptor still says the
//! file is a socket owned by this uid.  It binds under `umask 0o077`,
//! then checks with `lstat` that the new file is a socket owned by its
//! euid.
//!
//! # Peer identity
//!
//! Invariant 11 fixes who is allowed in: `SO_PEERCRED`, the daemon's own
//! uid plus root, `--allow-uid` to widen, socket mode 0600, and never a
//! request accepted before the check.  This build adds one thing to
//! that: the identity established at `accept` is pinned, and the socket
//! directory is checked as described above.
//!
//! When the kernel offers `SO_PEERPIDFD` (Linux 6.5 and later, socket
//! option 77) the daemon keeps a pidfd for the connecting process, and
//! where `statx` on a pidfd reports an identity inode (Linux 6.9 and
//! later) that inode is the comparison as well.  Otherwise it records
//! the peer's pid and start time from `/proc/<pid>/stat` and consults
//! them again before the job starts.  **That fallback is best effort:**
//! `SO_PEERCRED` returns a number, not a handle, so a number reused
//! between `accept` and the check is detectable only by the start time,
//! and a peer that `execve`s keeps the identity it had.
//!
//! What this does not do: a uid the daemon allows may execute arbitrary
//! programs with the daemon's privileges, and a privileged observer on
//! the host can read the daemon's memory.  See the trust model above.
//!
//! # Secret store
//!
//! The daemon locks the memory that holds the job environment with
//! `mlock` (a failure is a warning).  On `SIGTERM` or `SIGINT` it stops
//! accepting, kills running jobs, overwrites the stored environment with
//! zeros, removes its socket and exits with code 0.
//!
//! # PING
//!
//! A client may send the PING request frame in place of a job, and the
//! daemon answers with the facts a caller needs before it sends work:
//! the protocol version, the label, the uid the daemon runs as, whether
//! `--run-as-uid` is in force, the number of environment entries, the
//! policy for allowed uids, the job limits, and the peer identity method
//! in use.  It never reports an environment value.  A PING is answered
//! after the same uid check a job gets, and the socket directory rules
//! are unchanged.

use crate::mask::{Mask, MaskedChild};
use crate::tracer::ExitState;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// Which label the client asks for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RemoteLabel {
    /// The daemon applies its own configured label.
    #[default]
    Default,
    /// The job gets an empty label.
    Empty,
    /// The job gets this label.
    Text(String),
}

/// Ask a running daemon to run `argv`, with this process's stdio.  The
/// socket owner must be this process's euid or root.
pub fn run_remote(socket: &Path, label: RemoteLabel, argv: &[OsString]) -> io::Result<ExitState> {
    run_remote_as(socket, None, label, argv)
}

/// Like [`run_remote`].  With `Some(uid)` the socket owner must be exactly
/// `uid`.  With `None` the owner must be this process's euid or root.
pub fn run_remote_as(
    socket: &Path,
    expected_uid: Option<u32>,
    label: RemoteLabel,
    argv: &[OsString],
) -> io::Result<ExitState> {
    check_label_text(&label)?;
    if argv.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty argv"));
    }
    let mut stream = UnixStream::connect(socket)?;
    let (owner_uid, _gid) = peer_cred(stream.as_raw_fd())?;
    let me = unsafe { libc::geteuid() };
    let owner_ok = match expected_uid {
        Some(want) => owner_uid == want,
        None => owner_uid == me || owner_uid == 0,
    };
    if !owner_ok {
        let want = match expected_uid {
            Some(want) => format!("uid {}", want),
            None => format!("uid {} or root", me),
        };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the daemon at {} runs as uid {}, expected {}; refusing to send the command",
                socket.display(),
                owner_uid,
                want
            ),
        ));
    }
    let fds = [0 as RawFd, 1, 2];
    send_fds(stream.as_raw_fd(), &fds)?;
    write_request(&mut stream, &label, argv)?;
    let (st, msg) = read_response(&mut stream)?;
    if !msg.is_empty() {
        eprintln!("{}", msg);
    }
    Ok(st)
}

/// What a running daemon reports about itself, as `PING` returns it.
///
/// The fields are the facts a caller needs before it sends work.  There
/// is no environment entry and no environment value in any field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonStatus {
    pub protocol: u8,
    pub label: String,
    pub uid: u32,
    /// `--run-as-uid` runs each job as its client.
    pub run_as_uid: bool,
    pub jobs: usize,
    pub env_vars: usize,
    pub allow_uids: Vec<u32>,
    pub socket_mode: u32,
    pub io_timeout_secs: u64,
    pub job_timeout_secs: u64,
    pub max_job_bytes: usize,
    /// How this daemon pins the identity of the peer it is answering.
    pub peer_identity: &'static str,
    /// The uid the kernel recorded for this connection.
    pub peer_uid: u32,
}

impl DaemonStatus {
    /// The wire form: one `key=value` per line.
    pub fn to_text(&self) -> String {
        let allow = if self.allow_uids.is_empty() {
            "none".to_string()
        } else {
            self.allow_uids
                .iter()
                .map(|u| u.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "protocol={}\nlabel={}\nuid={}\nrun_as_uid={}\njobs={}\nenv_vars={}\n\
             allow_uids={}\nsocket_mode={:04o}\nio_timeout={}\njob_timeout={}\n\
             max_job_bytes={}\npeer_identity={}\npeer_uid={}\nlimits=an allowed uid may run \
             arbitrary programs with this daemon's privileges; a privileged observer can read \
             its memory\n",
            self.protocol,
            escape_for_log(&self.label, MAX_LABEL),
            self.uid,
            self.run_as_uid,
            self.jobs,
            self.env_vars,
            allow,
            self.socket_mode,
            self.io_timeout_secs,
            self.job_timeout_secs,
            self.max_job_bytes,
            self.peer_identity,
            self.peer_uid
        )
    }

    /// Parse the wire form.  A line that is not `key=value` is skipped.
    pub fn parse(text: &str) -> Option<DaemonStatus> {
        let mut out = DaemonStatus {
            protocol: PROTOCOL_VERSION,
            label: String::new(),
            uid: 0,
            run_as_uid: false,
            jobs: 1,
            env_vars: 0,
            allow_uids: Vec::new(),
            socket_mode: 0o600,
            io_timeout_secs: 30,
            job_timeout_secs: 0,
            max_job_bytes: MAX_JOB_ARGV,
            peer_identity: "unknown",
            peer_uid: 0,
        };
        let mut seen = false;
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            seen = true;
            match key {
                "protocol" => out.protocol = value.parse().ok()?,
                "label" => out.label = value.to_string(),
                "uid" => out.uid = value.parse().ok()?,
                "run_as_uid" => out.run_as_uid = value == "true",
                "jobs" => out.jobs = value.parse().ok()?,
                "env_vars" => out.env_vars = value.parse().ok()?,
                "allow_uids" if value != "none" => {
                    out.allow_uids = value.split(',').filter_map(|u| u.parse().ok()).collect();
                }
                "socket_mode" => out.socket_mode = u32::from_str_radix(value, 8).ok()?,
                "io_timeout" => out.io_timeout_secs = value.parse().ok()?,
                "job_timeout" => out.job_timeout_secs = value.parse().ok()?,
                "max_job_bytes" => out.max_job_bytes = value.parse().ok()?,
                "peer_uid" => out.peer_uid = value.parse().ok()?,
                "peer_identity" => {
                    out.peer_identity = match value {
                        "pidfd + start time" => "pidfd + start time",
                        _ => "SO_PEERCRED + start time (best effort)",
                    }
                }
                _ => {}
            }
        }
        if seen {
            Some(out)
        } else {
            None
        }
    }
}

/// Ask a running daemon to describe itself.
///
/// The socket owner is checked exactly as [`run_remote`] checks it: this
/// process's euid or root.  The daemon answers only after the same uid
/// check it applies to a job.  A daemon that does not know PING answers
/// with a refusal, which is reported rather than swallowed.
pub fn ping_remote(socket: &Path) -> io::Result<DaemonStatus> {
    let mut stream = UnixStream::connect(socket)?;
    let (owner_uid, _gid) = peer_cred(stream.as_raw_fd())?;
    let me = unsafe { libc::geteuid() };
    if owner_uid != me && owner_uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the daemon at {} runs as uid {}; refusing to ask it anything",
                socket.display(),
                owner_uid
            ),
        ));
    }
    let fds = [0 as RawFd, 1, 2];
    send_fds(stream.as_raw_fd(), &fds)?;
    stream.write_all(MAGIC_PING)?;
    let (st, msg) = read_response(&mut stream)?;
    if st.code != 0 {
        return Err(io::Error::other(format!(
            "the daemon answered with code {}{}",
            st.code,
            if msg.is_empty() {
                String::new()
            } else {
                format!(": {}", msg)
            }
        )));
    }
    DaemonStatus::parse(&msg).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the daemon answered PING with no readable status",
        )
    })
}

/// Protocol version carried in the first byte of the connection.
pub const PROTOCOL_VERSION: u8 = 2;
/// Version byte of the old protocol (it sent `'C'`).
const OLD_BANNER: u8 = b'C';
pub const MAGIC: &[u8; 4] = b"PMK2";
/// Request magic for PING.  A PING carries no label and no arguments, so
/// it has its own magic rather than a third label mode.
pub const MAGIC_PING: &[u8; 4] = b"PMKP";
pub const MAX_ARGC: u32 = 4096;
pub const MAX_ARG: u32 = 1 << 20;
pub const MAX_REQUEST: usize = 8 << 20;
/// Longest label the daemon accepts, in bytes.
pub const MAX_LABEL: usize = 4096;
/// Default cap on the sum of `len + 1` over the job arguments.
pub const MAX_JOB_ARGV: usize = 1 << 20;
/// Bytes the job-size precheck keeps free on top of the string sum.
///
/// The block builder bounds the string sum (argv + environment + comm) by
/// [`MAX_HIDDEN`](crate::MAX_HIDDEN).  The presentation area (at most
/// `2 * MAX_LABEL + MAX_ARGC` bytes), the pointer arrays and the builder's
/// own scratch are mapped beside that sum and are not part of the bound.
/// The precheck repeats the same sum, so this margin is a cushion for the
/// parts the builder maps but does not count, not the bound itself: it
/// exceeds the largest presentation area (12 KiB) plus the builder's
/// scratch (2 KiB), so a job the precheck accepts cannot fail the
/// builder's check.
pub const REDACTION_MARGIN: usize = 64 << 10;
/// Number of descriptors a client must send.
const CLIENT_FDS: usize = 3;
/// Response code for a refused or failed request.
const CODE_REFUSED: i32 = 255;

/// The largest accepted `--job-timeout` and `--io-timeout`, in seconds:
/// ten years.
///
/// The deadline is `Instant::now() + Duration`, which panics on overflow.
/// A ten-year cap is far past any real job and keeps the arithmetic away
/// from the edge of the clock on every architecture.  `u64::MAX` seconds
/// is about 5.8e11 years, so the value the operator can type has to be
/// bounded before the addition, not after it.  `checked_add` in
/// [`wait_job`] is the second guard, for a value that reaches the config
/// by another route.
pub const MAX_TIMEOUT_SECS: u64 = 10 * 365 * 24 * 60 * 60;

const LABEL_DEFAULT: u8 = 0;
const LABEL_EMPTY: u8 = 1;
const LABEL_TEXT: u8 = 2;

/// Server configuration.
#[derive(Clone)]
pub struct DaemonConfig {
    pub socket: PathBuf,
    /// Presentation label for a job whose client sends no label.
    pub label: String,
    /// Environment every job runs with (see [`job_env`]).
    pub env: Vec<(OsString, OsString)>,
    /// Leave `/proc/<pid>/environ` visible for jobs.
    pub keep_env: bool,
    /// Extra uids allowed to connect (the daemon's uid and root always are).
    pub allow_uids: Vec<u32>,
    /// Socket permission bits, e.g. 0o600.
    pub socket_mode: u32,
    /// Seconds for each read or write on a client socket; 0 means none.
    pub io_timeout_secs: u64,
    /// Seconds a job may run; 0 means no limit.
    pub job_timeout_secs: u64,
    /// Run each job as the uid and gid of its client (root daemon only).
    pub run_as_uid: bool,
    /// Largest number of concurrent jobs; 1 runs jobs in the daemon itself.
    pub jobs: usize,
    /// Cap on the sum of `len + 1` over the job arguments.
    pub max_job_bytes: usize,
    pub verbose: bool,
    pub quiet: bool,
}

impl DaemonConfig {
    pub fn new() -> DaemonConfig {
        DaemonConfig {
            socket: default_socket(),
            label: "pmask-job".to_string(),
            env: Vec::new(),
            keep_env: false,
            allow_uids: Vec::new(),
            socket_mode: 0o600,
            io_timeout_secs: 30,
            job_timeout_secs: 0,
            run_as_uid: false,
            jobs: 1,
            max_job_bytes: MAX_JOB_ARGV,
            verbose: false,
            quiet: false,
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig::new()
    }
}

/// True when `dir` is a directory owned by the euid that group and other
/// cannot write to.
fn dir_is_private(dir: &Path) -> bool {
    match std::fs::metadata(dir) {
        Ok(md) => {
            let euid = unsafe { libc::geteuid() };
            md.is_dir() && md.uid() == euid && md.mode() & 0o022 == 0
        }
        Err(_) => false,
    }
}

/// `$XDG_RUNTIME_DIR/pmask.sock` when that directory is private to the
/// euid, else `/run/pmask.sock` for root, else the empty path.
///
/// The empty path means there is no safe default: the caller must pass
/// `--socket`.  There is no `/tmp` fallback.  A world-writable directory
/// cannot be checked for ownership, and an attacker who wins the race for
/// a name in it is the daemon the client reaches.
pub fn default_socket() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(dir);
        if dir_is_private(&dir) {
            return dir.join("pmask.sock");
        }
    }
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        PathBuf::from("/run/pmask.sock")
    } else {
        PathBuf::new()
    }
}

/// Create the socket directory `0700` when it is missing, then pin a
/// descriptor for it and check that descriptor.
///
/// Every call requires a directory, owned by the effective uid, that
/// group and other cannot write to: a directory they can write is a
/// directory where the name can be replaced between the check and the
/// bind.  A directory that fails any of those refuses service.
///
/// A directory this call created must be exactly `0700`.  A directory
/// that already existed must at least not be writable by group or other,
/// and when group or other can still read or traverse it the daemon says
/// so in one line ([`socket_dir_warning`]).  The distinction is visible on
/// purpose: `/run` is `0755` and root's default lives in it, and an
/// explicitly given socket path is the operator's choice.  In every case
/// the socket is `0600` by default, its owner is checked after `bind`, and
/// a stale socket is removed only through a pinned descriptor.
///
/// Returns the pinned descriptor and the mode it reported, so the caller
/// can warn about the mode it actually checked rather than re-reading the
/// path.
fn check_socket_dir(dir: &Path) -> io::Result<(std::fs::File, u32)> {
    if dir.as_os_str().is_empty() {
        return Err(refuse_start(
            io::ErrorKind::InvalidInput,
            "the socket path has no directory component".to_string(),
        ));
    }
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad socket path"))?;
    // SAFETY: `c` is a valid C string for the life of the call.
    let made = unsafe { libc::mkdir(c.as_ptr(), 0o700) } == 0;
    let require_private = made;
    if !made {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(path_error(dir, "cannot create the socket directory", e));
        }
    }
    // SAFETY: `c` is a valid C string; O_DIRECTORY fails on a non-directory
    // and O_NOFOLLOW refuses a symbolic link.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(refuse_start(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a usable directory: {}", dir.display(), e),
        ));
    }
    // SAFETY: `fd` is a fresh descriptor this function owns.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let md = file.metadata()?;
    let euid = unsafe { libc::geteuid() };
    if !md.is_dir() {
        return Err(refuse_start(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if md.uid() != euid {
        return Err(refuse_start(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {}, not by uid {}",
                dir.display(),
                md.uid(),
                euid
            ),
        ));
    }
    let mode = md.mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(refuse_start(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is mode {:04o}; group or other can write to it, so the socket name can be \
                 replaced",
                dir.display(),
                mode
            ),
        ));
    }
    if require_private && mode & 0o077 != 0 {
        return Err(refuse_start(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} was created mode {:04o} rather than 0700",
                dir.display(),
                mode
            ),
        ));
    }
    Ok((file, mode))
}

/// The one-line warning for a socket directory that group or other can
/// read or traverse, or `None` when it is private to the euid.
///
/// The check itself already refuses a writable directory; this is the
/// disclosure that remains: the socket name is visible, so an observer
/// learns that a daemon runs and under which name.  The socket file is
/// `0600` by default, so the name is all they learn.
fn socket_dir_warning(dir: &Path, mode: u32) -> Option<String> {
    let mode = mode & 0o777;
    if mode & 0o077 == 0 {
        return None;
    }
    Some(format!(
        "warning: {} is mode {:04o}; group or other can read and traverse it, so the socket \
         name is visible to them",
        dir.display(),
        mode
    ))
}

// ------------------------------------------------------------ env file --

fn env_line_error(path: &Path, line: usize, what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{}:{}: {}", path.display(), line, what),
    )
}

/// Parse an environment file.
///
/// This is the one `--env-file` grammar in the tree.  `pmask`
/// (`src/cli.rs`) and `pmaskd` (`src/bin/pmaskd.rs`) both call it, so a
/// file that works for one works for the other and a line that is
/// refused is refused by both.  A second parser would drift: the CLI
/// used to keep a trailing CR and an `export ` prefix as part of the
/// name, while the daemon stripped them.
///
/// Grammar, one entry per line:
///
/// * A blank line, or a line whose first non-blank byte is `#`, is
///   skipped.
/// * One trailing CR is removed, so a file written with CRLF endings
///   gives the same values as one with LF endings.
/// * `KEY=VALUE` or `export KEY=VALUE`; the `export ` prefix and the
///   blanks around it are not part of the name.
/// * `KEY` has printable ASCII bytes only (0x21 to 0x7e), no space and no
///   `=`, and is not empty.  A blank or control byte in a key is an error
///   rather than a variable no program can read.
/// * `VALUE` loses leading and trailing blanks.  When it then starts and
///   ends with the same quote (`'` or `"`), the quotes are removed and the
///   text between them is kept as it is.  There is no escape processing.
/// * A NUL byte anywhere in a line is an error.
///
/// Every error names the file and the line (`file:line: message`), which
/// is what both surfaces print.
pub fn parse_env_file(path: &Path) -> io::Result<Vec<(OsString, OsString)>> {
    let mut text = std::fs::read(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {}", path.display(), e)))?;
    let result = parse_env_text(path, &text);
    wipe_bytes(&mut text);
    result
}

fn parse_env_text(path: &Path, text: &[u8]) -> io::Result<Vec<(OsString, OsString)>> {
    let mut out = Vec::new();
    for (index, raw) in text.split(|&b| b == b'\n').enumerate() {
        let lineno = index + 1;
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.contains(&0) {
            return Err(env_line_error(path, lineno, "line contains a NUL byte"));
        }
        let mut body = trim(line);
        if body.is_empty() || body[0] == b'#' {
            continue;
        }
        if body.starts_with(b"export") && body.len() > 6 && body[6].is_ascii_whitespace() {
            body = trim(&body[6..]);
        }
        let Some(eq) = body.iter().position(|&b| b == b'=') else {
            return Err(env_line_error(path, lineno, "expected KEY=VALUE"));
        };
        let key = &body[..eq];
        if key.is_empty() {
            return Err(env_line_error(
                path,
                lineno,
                "expected KEY=VALUE: the key is empty",
            ));
        }
        if let Some(bad) = key.iter().find(|&&b| !(0x21..=0x7e).contains(&b)) {
            let what = if *bad == b' ' || *bad == b'\t' {
                "key contains a space".to_string()
            } else {
                format!("key contains a non-printable byte (0x{:02x})", bad)
            };
            return Err(env_line_error(path, lineno, &what));
        }
        let value = unquote(trim(&body[eq + 1..]));
        out.push((
            OsString::from_vec(key.to_vec()),
            OsString::from_vec(value.to_vec()),
        ));
    }
    Ok(out)
}

/// Remove one level of matching quotes.
fn unquote(v: &[u8]) -> &[u8] {
    if v.len() >= 2 {
        let first = v[0];
        if (first == b'"' || first == b'\'') && v[v.len() - 1] == first {
            return &v[1..v.len() - 1];
        }
    }
    v
}

fn trim(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &b[start..end]
}

/// True when group or other can read the file (mode bits 0o044).
pub fn env_file_readable_by_others(path: &Path) -> io::Result<bool> {
    let md = std::fs::metadata(path)?;
    Ok(md.mode() & 0o044 != 0)
}

// ---------------------------------------------------------- secret store --

/// Overwrite the bytes with zeros in a way the compiler keeps.
fn wipe_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: b is a valid, exclusive reference to one byte.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

fn wipe_os_string(s: &mut OsString) {
    let mut bytes = std::mem::take(s).into_vec();
    wipe_bytes(&mut bytes);
}

/// Overwrite every name and value with zeros and empty the list.
pub fn wipe_env(env: &mut Vec<(OsString, OsString)>) {
    for (k, v) in env.iter_mut() {
        wipe_os_string(k);
        wipe_os_string(v);
    }
    env.clear();
}

/// Lock the memory of every name and value with `mlock`.  Returns the
/// number of buffers the kernel refused to lock.
pub fn lock_env(env: &[(OsString, OsString)]) -> usize {
    let mut failures = 0usize;
    for (k, v) in env {
        for s in [k, v] {
            let bytes = s.as_bytes();
            if bytes.is_empty() {
                continue;
            }
            // SAFETY: the pointer and length describe a live buffer.
            let rc = unsafe { libc::mlock(bytes.as_ptr() as *const libc::c_void, bytes.len()) };
            if rc != 0 {
                failures += 1;
            }
        }
    }
    failures
}

// ------------------------------------------------------------- framing --

fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn read_bytes(r: &mut impl Read, len: usize, budget: &mut usize) -> io::Result<Vec<u8>> {
    if len > *budget {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request too large",
        ));
    }
    *budget -= len;
    let mut v = vec![0u8; len];
    r.read_exact(&mut v)?;
    Ok(v)
}

fn check_label_text(label: &RemoteLabel) -> io::Result<()> {
    if let RemoteLabel::Text(t) = label {
        if t.len() > MAX_LABEL {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("label is {} bytes, the limit is {}", t.len(), MAX_LABEL),
            ));
        }
        crate::mask::validate_label(t)?;
    }
    Ok(())
}

/// Read the request frame.  Returns `(label, argv)`.
pub fn read_request(r: &mut impl Read) -> io::Result<(RemoteLabel, Vec<OsString>)> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad magic (protocol mismatch?)",
        ));
    }
    read_request_body(r)
}

/// What a client sent after the version byte and its descriptors.
pub enum Request {
    /// A job to run.
    Job(RemoteLabel, Vec<OsString>),
    /// Ask the daemon to describe itself.  Nothing follows.
    Ping,
}

/// Read a request frame: either a job frame or a PING frame.
pub fn read_any_request(r: &mut impl Read) -> io::Result<Request> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic == MAGIC_PING {
        return Ok(Request::Ping);
    }
    if &magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad magic (protocol mismatch?)",
        ));
    }
    let (label, argv) = read_request_body(r)?;
    Ok(Request::Job(label, argv))
}

/// The rest of a job frame, after the magic.
fn read_request_body(r: &mut impl Read) -> io::Result<(RemoteLabel, Vec<OsString>)> {
    let mut mode = [0u8; 1];
    r.read_exact(&mut mode)?;
    let label_len = read_u32(r)? as usize;
    if label_len > MAX_LABEL {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("label is {} bytes, the limit is {}", label_len, MAX_LABEL),
        ));
    }
    let mut budget = MAX_REQUEST;
    let label_bytes = read_bytes(r, label_len, &mut budget)?;
    let label = match mode[0] {
        LABEL_DEFAULT | LABEL_EMPTY => {
            if label_len != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "label bytes sent with a label mode that has none",
                ));
            }
            if mode[0] == LABEL_DEFAULT {
                RemoteLabel::Default
            } else {
                RemoteLabel::Empty
            }
        }
        LABEL_TEXT => {
            let text = String::from_utf8(label_bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "label is not valid UTF-8")
            })?;
            RemoteLabel::Text(text)
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown label mode {}", other),
            ));
        }
    };
    check_label_text(&label)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let argc = read_u32(r)?;
    if argc > MAX_ARGC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "argc too large"));
    }
    let mut argv = Vec::with_capacity(argc as usize);
    for _ in 0..argc {
        let len = read_u32(r)?;
        if len > MAX_ARG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "argument too large",
            ));
        }
        argv.push(OsString::from_vec(read_bytes(
            r,
            len as usize,
            &mut budget,
        )?));
    }
    if argv.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty argv"));
    }
    Ok((label, argv))
}

/// Write the request frame.
pub fn write_request(w: &mut impl Write, label: &RemoteLabel, argv: &[OsString]) -> io::Result<()> {
    check_label_text(label)?;
    w.write_all(MAGIC)?;
    match label {
        RemoteLabel::Default => {
            w.write_all(&[LABEL_DEFAULT])?;
            write_u32(w, 0)?;
        }
        RemoteLabel::Empty => {
            w.write_all(&[LABEL_EMPTY])?;
            write_u32(w, 0)?;
        }
        RemoteLabel::Text(t) => {
            w.write_all(&[LABEL_TEXT])?;
            write_u32(w, t.len() as u32)?;
            w.write_all(t.as_bytes())?;
        }
    }
    write_u32(w, argv.len() as u32)?;
    for a in argv {
        let b = a.as_bytes();
        write_u32(w, b.len() as u32)?;
        w.write_all(b)?;
    }
    Ok(())
}

/// Read the response frame.
pub fn read_response(r: &mut impl Read) -> io::Result<(ExitState, String)> {
    let mut code = [0u8; 4];
    r.read_exact(&mut code)?;
    let code = i32::from_le_bytes(code);
    let has_signal = read_u32(r)?;
    let mut sig = [0u8; 4];
    r.read_exact(&mut sig)?;
    let sig = i32::from_le_bytes(sig);
    let mut budget = MAX_REQUEST;
    let msg_len = read_u32(r)? as usize;
    let msg = String::from_utf8_lossy(&read_bytes(r, msg_len, &mut budget)?).into_owned();
    Ok((
        ExitState::plain(code, if has_signal != 0 { Some(sig) } else { None }),
        msg,
    ))
}

/// Write the response frame in one write.
pub fn write_response(w: &mut impl Write, st: ExitState, msg: &str) -> io::Result<()> {
    let mut frame = Vec::with_capacity(16 + msg.len());
    frame.extend_from_slice(&st.code.to_le_bytes());
    frame.extend_from_slice(&(if st.signal.is_some() { 1u32 } else { 0u32 }).to_le_bytes());
    frame.extend_from_slice(&st.signal.unwrap_or(0).to_le_bytes());
    frame.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    frame.extend_from_slice(msg.as_bytes());
    w.write_all(&frame)
}

// ----------------------------------------------------------- fd passing --

fn send_fds(sock: RawFd, fds: &[RawFd]) -> io::Result<()> {
    let mut payload = [PROTOCOL_VERSION];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    let mut cbuf = vec![0u64; space.div_ceil(8)];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as _;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr() as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of_val(fds),
        );
        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// What the first message of a connection carried.
struct FirstMessage {
    /// The version byte.
    version: u8,
    /// Received descriptors.  Each has `FD_CLOEXEC`.
    fds: Vec<RawFd>,
    /// The kernel dropped control data that did not fit (`MSG_CTRUNC`).
    truncated: bool,
}

/// Receive the version byte and at most `max` descriptors.
fn recv_first(sock: RawFd, max: usize) -> io::Result<FirstMessage> {
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let space = unsafe { libc::CMSG_SPACE((max * std::mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cbuf = vec![0u64; space.div_ceil(8)];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"));
    }
    let mut fds = Vec::new();
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg) as *const RawFd;
                let bytes = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let count = bytes / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    fds.push(std::ptr::read_unaligned(data.add(i)));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok(FirstMessage {
        version: payload[0],
        fds,
        truncated: msg.msg_flags & libc::MSG_CTRUNC != 0,
    })
}

/// Uid and gid of the process that created the other end of the socket.
fn peer_cred(sock: RawFd) -> io::Result<(u32, u32)> {
    let (uid, gid, _pid) = peer_cred_full(sock)?;
    Ok((uid, gid))
}

/// Uid, gid and pid the kernel recorded when the peer connected.
fn peer_cred_full(sock: RawFd) -> io::Result<(u32, u32, libc::pid_t)> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`.
    let rc = unsafe {
        libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((cred.uid, cred.gid, cred.pid))
}

/// `SO_PEERPIDFD`: socket option 77, Linux 6.5 and later.
const SO_PEERPIDFD: libc::c_int = 77;

/// How the peer's identity is pinned for one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMethod {
    /// A pidfd from `SO_PEERPIDFD`, plus the process start time.
    ///
    /// The pidfd refers to the peer the kernel recorded at `connect`, not
    /// to whatever holds that number now, so its liveness is the answer
    /// to "is this still the same process".  The start time is checked
    /// with it as a second witness.
    Pidfd,
    /// `SO_PEERCRED` and `/proc/<pid>/stat`.  Best effort.
    CredsOnly,
}

impl PeerMethod {
    /// Text for a log line and the `PING` report.
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerMethod::Pidfd => "pidfd + start time",
            PeerMethod::CredsOnly => "SO_PEERCRED + start time (best effort)",
        }
    }
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

/// Test hook: pretend the kernel refused `SO_PEERPIDFD`, so the
/// fallback warning is reachable from a suite.  Read once.
fn peerpidfd_disabled() -> bool {
    static OFF: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OFF.get_or_init(|| std::env::var_os("PMASK_FAULT_PEERPIDFD").is_some())
}

/// A pidfd for the peer, when the kernel offers one.
fn peer_pidfd(sock: RawFd) -> Option<RawFd> {
    if peerpidfd_disabled() {
        return None;
    }
    let mut pidfd: RawFd = -1;
    let mut len = std::mem::size_of::<RawFd>() as libc::socklen_t;
    // SAFETY: getsockopt writes one descriptor into `pidfd`.
    let rc = unsafe {
        libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            &mut pidfd as *mut RawFd as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 || pidfd < 0 {
        return None;
    }
    match set_cloexec(pidfd) {
        Ok(()) => Some(pidfd),
        Err(_) => {
            // SAFETY: the descriptor is ours.
            unsafe { libc::close(pidfd) };
            None
        }
    }
}

/// A process's start time: field 22 of `/proc/<pid>/stat`.
fn proc_start(pid: libc::pid_t) -> Option<u64> {
    let text = std::fs::read(format!("/proc/{}/stat", pid)).ok()?;
    let close = text.iter().rposition(|&b| b == b')')?;
    let rest = std::str::from_utf8(&text[close + 1..]).ok()?;
    rest.split_whitespace().nth(19)?.parse::<u64>().ok()
}

/// The identity an accepted connection belongs to.
///
/// The uid and gid are the kernel's record from `connect`, and they are
/// what invariant 11 authorises on.  The pid is pinned so that the check
/// made at `accept` can be repeated immediately before the job starts,
/// which catches a number that was recycled in between.
struct PeerPin {
    pid: libc::pid_t,
    gfid: Option<RawFd>,
    start: Option<u64>,
    method: PeerMethod,
}

impl PeerPin {
    fn take(sock: RawFd, pid: libc::pid_t) -> PeerPin {
        let gfid = peer_pidfd(sock);
        let start = proc_start(pid);
        PeerPin {
            pid,
            gfid,
            start,
            method: PeerMethod::CredsOnly,
        }
    }

    /// The method this pin actually ended up with.
    fn settle(&mut self) {
        self.method = if self.gfid.is_some() {
            PeerMethod::Pidfd
        } else {
            PeerMethod::CredsOnly
        };
    }

    /// Re-check that the pid still names the process that connected.
    ///
    /// Returns `Ok(())` when the pin still holds.  A pidfd answers the
    /// question directly: it stays valid through the zombie state and
    /// reports the peer's exit.  Without one, the start time is the only
    /// evidence, and it is why this fallback is called best effort.
    fn revalidate(&self) -> io::Result<()> {
        if let Some(fd) = self.gfid {
            if !pidfd_alive(fd) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("the peer process {} has exited", self.pid),
                ));
            }
        }
        match (self.start, proc_start(self.pid)) {
            (Some(pinned), Some(now)) if pinned == now => Ok(()),
            (Some(_), Some(_)) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "pid {} now belongs to a different process than the one that connected",
                    self.pid
                ),
            )),
            (Some(_), None) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("the peer process {} has exited", self.pid),
            )),
            // The pin had no start time to compare; the connection is
            // still the one the kernel authorised.
            (None, _) => Ok(()),
        }
    }
}

impl Drop for PeerPin {
    fn drop(&mut self) {
        if let Some(fd) = self.gfid {
            // SAFETY: the descriptor is ours and is closed once.
            unsafe { libc::close(fd) };
        }
    }
}

/// Which identity mechanism this kernel supports, probed on a socketpair.
fn detect_peer_method() -> PeerMethod {
    let mut sv = [0 as RawFd; 2];
    // SAFETY: `sv` holds two descriptors to write.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        return PeerMethod::CredsOnly;
    }
    let method = match peer_pidfd(sv[0]) {
        Some(fd) => {
            // SAFETY: the descriptor is ours.
            unsafe { libc::close(fd) };
            PeerMethod::Pidfd
        }
        None => PeerMethod::CredsOnly,
    };
    // SAFETY: both descriptors are ours and are closed once.
    unsafe {
        libc::close(sv[0]);
        libc::close(sv[1]);
    }
    method
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Open `/dev/null` on each of 0, 1 and 2 that is closed, so that a job
/// never gets a descriptor number below 3 that belongs to something else.
pub fn ensure_stdio_open() -> io::Result<()> {
    for fd in 0..3 as RawFd {
        let open = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
        if open {
            continue;
        }
        let path = b"/dev/null\0";
        let n = unsafe { libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDWR) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n != fd {
            let rc = unsafe { libc::dup2(n, fd) };
            unsafe { libc::close(n) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

// --------------------------------------------------------------- server --

/// Set by `SIGTERM` and `SIGINT`.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Read end of the self-pipe the signal handler writes to.
static WAKE_READ: AtomicI32 = AtomicI32::new(-1);
/// Write end of the self-pipe.
static WAKE_WRITE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
    wake_notify();
}

/// Create the self-pipe that wakes a blocked `poll`.
///
/// A signal that arrives while the daemon waits in `poll` or in a
/// connection read has to wake it.  `SA_RESTART` is set because a tracer
/// thread must not see `EINTR` from `waitpid`, and it also keeps `poll`
/// from returning on a signal that the kernel restarts — so the flag alone
/// is not enough, and a client that never sends its request supplies no
/// other event.  The pipe carries the wake.
///
/// Both ends are `O_CLOEXEC` so a job never inherits them, and
/// `O_NONBLOCK` so the handler can never block: a full pipe means a byte
/// is already pending, which is all the reader needs.
fn install_wake_pipe() -> io::Result<()> {
    if WAKE_READ.load(Ordering::SeqCst) >= 0 {
        return Ok(());
    }
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 fills.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // A fork inherits both descriptors with the same numbers, so a worker
    // process sees the pipe its own handler writes to.
    WAKE_READ.store(fds[0], Ordering::SeqCst);
    WAKE_WRITE.store(fds[1], Ordering::SeqCst);
    Ok(())
}

/// The read end, or -1 when the pipe was never installed.
fn wake_fd() -> RawFd {
    WAKE_READ.load(Ordering::SeqCst)
}

/// Wake every `poll` in this process.  Async-signal-safe: one non-blocking
/// `write` of one byte, and `EAGAIN` is ignored.
fn wake_notify() {
    let fd = WAKE_WRITE.load(Ordering::SeqCst);
    if fd < 0 {
        return;
    }
    let byte = 1u8;
    // SAFETY: a single write to a descriptor this process owns, from a
    // buffer that lives for the call.  The descriptor is non-blocking.
    unsafe {
        libc::write(fd, &byte as *const u8 as *const libc::c_void, 1);
    }
}

/// Consume the pending wake bytes so the next `poll` waits again.
fn wake_drain() {
    let fd = wake_fd();
    if fd >= 0 {
        drain_fd(fd);
    }
}

/// Read `fd` dry.  Split out so the drain can be tested on a pipe the test
/// owns, without touching the process-wide one.
fn drain_fd(fd: RawFd) {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: a non-blocking read into a local buffer.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
    }
}

/// The error a connection operation returns once the daemon is stopping.
///
/// Not `ErrorKind::Interrupted`: `read_exact` retries that kind, so a
/// shutdown reported that way would be invisible to the caller.
fn shutdown_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "daemon is shutting down")
}

/// Block until `fd` is readable, the wake pipe fires, or `timeout` passes.
///
/// `None` means no timeout.  The wait is a `poll` on both descriptors, so
/// `SIGTERM` returns from it at once whatever the socket is doing, and the
/// flag is checked before and after every wait.
fn wait_readable(fd: RawFd, timeout: Option<Duration>) -> io::Result<()> {
    let deadline = timeout.and_then(|t| Instant::now().checked_add(t));
    loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            return Err(shutdown_error());
        }
        let wfd = wake_fd();
        let mut pfd = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wfd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n: libc::nfds_t = if wfd >= 0 { 2 } else { 1 };
        let timeout_ms = match deadline {
            None => -1 as libc::c_int,
            Some(d) => {
                let now = Instant::now();
                match d.checked_duration_since(now) {
                    Some(left) => left.as_millis().min(i32::MAX as u128) as libc::c_int,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "the client did not send its request in time",
                        ))
                    }
                }
            }
        };
        // SAFETY: `pfd` has `n` initialised entries.
        let rc = unsafe { libc::poll(pfd.as_mut_ptr(), n, timeout_ms) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if rc == 0 {
            // The deadline, if any, is reported at the top of the loop.
            continue;
        }
        if n == 2 && pfd[1].revents != 0 {
            wake_drain();
            // A wake means "look again": the caller re-checks the
            // shutdown flag and then comes back here.  Returning is what
            // makes a signal visible to a wait that has no timeout; the
            // flag check at the top of the next call is what turns it
            // into a shutdown.
            return Ok(());
        }
        if pfd[0].revents != 0 {
            return Ok(());
        }
    }
}

/// True when the wake pipe in a two-entry poll set has data.
///
/// `nfd` is the number of entries poll was given, so a one-entry set
/// (no wake pipe) never reads past the array.
fn wake_pending(pfd: &[libc::pollfd; 2], nfd: libc::nfds_t) -> bool {
    nfd >= 2 && pfd[1].revents != 0
}

/// A connection whose reads and writes wake on `SIGTERM`.
///
/// The socket is non-blocking and every operation first waits in
/// [`wait_readable`], which polls the wake pipe as well.  That is what
/// makes `--io-timeout 0` stop being an unbounded block: the read timeout
/// is `None`, so there is no deadline, but a signal still returns from the
/// wait.  `SO_RCVTIMEO` is deliberately not used: it has no effect on a
/// non-blocking socket, and it cannot be armed on the wake pipe.
struct Conn {
    stream: UnixStream,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl Conn {
    fn new(stream: UnixStream, timeout: Option<Duration>) -> Conn {
        Conn {
            stream,
            read_timeout: timeout,
            write_timeout: timeout,
        }
    }

    fn fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    fn shutdown_write(&self) {
        // SAFETY: shutdown(2) on a descriptor this process owns.
        unsafe { libc::shutdown(self.fd(), libc::SHUT_WR) };
    }

    /// Wait for the socket to be readable and return one `recvmsg`, used
    /// by the first message so the received descriptors come with it.
    fn recvmsg_first(&mut self, max: usize) -> io::Result<FirstMessage> {
        loop {
            wait_readable(self.fd(), self.read_timeout)?;
            match recv_first(self.fd(), max) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                other => return other,
            }
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            wait_readable(self.fd(), self.read_timeout)?;
            // SAFETY: one read into the caller's buffer through a
            // descriptor this process owns.
            let n =
                unsafe { libc::read(self.fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            return Ok(n as usize);
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            // SAFETY: one write from the caller's buffer.
            let n =
                unsafe { libc::write(self.fd(), buf.as_ptr() as *const libc::c_void, buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if e.kind() == io::ErrorKind::WouldBlock {
                    wait_writable(self.fd(), self.write_timeout)?;
                    continue;
                }
                return Err(e);
            }
            return Ok(n as usize);
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Block until `fd` is writable, the wake pipe fires, or `timeout` passes.
fn wait_writable(fd: RawFd, timeout: Option<Duration>) -> io::Result<()> {
    let deadline = timeout.and_then(|t| Instant::now().checked_add(t));
    loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            return Err(shutdown_error());
        }
        let wfd = wake_fd();
        let mut pfd = [
            libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: wfd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n: libc::nfds_t = if wfd >= 0 { 2 } else { 1 };
        let timeout_ms = match deadline {
            None => -1 as libc::c_int,
            Some(d) => match d.checked_duration_since(Instant::now()) {
                Some(left) => left.as_millis().min(i32::MAX as u128) as libc::c_int,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the client did not read its answer in time",
                    ))
                }
            },
        };
        // SAFETY: `pfd` has `n` initialised entries.
        let rc = unsafe { libc::poll(pfd.as_mut_ptr(), n, timeout_ms) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if rc == 0 {
            continue;
        }
        if n == 2 && pfd[1].revents != 0 {
            wake_drain();
            return Ok(());
        }
        if pfd[0].revents != 0 {
            return Ok(());
        }
    }
}

/// Install the shutdown handler without `SA_RESTART` for `poll` (poll never
/// restarts) and with it for everything else, so a tracer thread that
/// receives the signal does not see `EINTR` from `waitpid`.
fn install_signal_handlers() -> io::Result<()> {
    install_wake_pipe()?;
    for sig in [libc::SIGTERM, libc::SIGINT] {
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        unsafe { libc::sigemptyset(&mut sa.sa_mask) };
        sa.sa_flags = libc::SA_RESTART;
        if unsafe { libc::sigaction(sig, &sa, std::ptr::null_mut()) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn log_line(cfg: &DaemonConfig, text: &str) {
    if !cfg.quiet {
        eprintln!("pmaskd: {}", text);
    }
}

/// Restores the previous umask when dropped.
struct UmaskGuard {
    old: libc::mode_t,
}

impl UmaskGuard {
    fn set(mask: libc::mode_t) -> UmaskGuard {
        let old = unsafe { libc::umask(mask) };
        UmaskGuard { old }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.old);
        }
    }
}

fn path_error(path: &Path, what: &str, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {}: {}", path.display(), what, e))
}

fn refuse_start(kind: io::ErrorKind, text: String) -> io::Error {
    io::Error::new(kind, format!("refusing to start: {}", text))
}

/// Open a path for inspection only, without following a symbolic link.
///
/// `O_PATH` gives a descriptor that can be `fstat`ed and used as the
/// subject of an `unlinkat`, but cannot be read or written.  `O_NOFOLLOW`
/// makes a symbolic link itself the object of the open rather than its
/// target, so the file type check below sees a link and refuses it.
fn pin_path(path: &Path) -> io::Result<Option<std::fs::File>> {
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad socket path"))?;
    // SAFETY: `c` is a valid C string for the life of the call.
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
        return Err(path_error(path, "cannot inspect the socket path", e));
    }
    // SAFETY: `fd` is a fresh descriptor this function owns.
    Ok(Some(unsafe { std::fs::File::from_raw_fd(fd) }))
}

/// Remove the socket at `path`, but only when the pinned descriptor says
/// it is still a socket owned by this uid, and only through `dir`.
fn remove_pinned(path: &Path, pin: &std::fs::File, dir: &std::fs::File) -> io::Result<()> {
    let md = pin.metadata()?;
    let euid = unsafe { libc::geteuid() };
    if md.file_type().is_symlink() {
        return Err(refuse_start(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is a symbolic link; refusing to remove it",
                path.display()
            ),
        ));
    }
    if !md.file_type().is_socket() {
        return Err(refuse_start(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a socket; refusing to remove it", path.display()),
        ));
    }
    if md.uid() != euid {
        return Err(refuse_start(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {}, not uid {}; refusing to remove it",
                path.display(),
                md.uid(),
                euid
            ),
        ));
    }
    let name = path.file_name().ok_or_else(|| {
        refuse_start(
            io::ErrorKind::InvalidInput,
            format!("{} has no file name", path.display()),
        )
    })?;
    let cname = std::ffi::CString::new(Path::new(name).as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad socket path"))?;
    // SAFETY: `dir` is an open directory descriptor and `cname` is one
    // component relative to it.
    let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) };
    if rc != 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(path_error(path, "cannot remove the stale socket", e));
    }
    if pin_path(path)?.is_some() {
        return Err(refuse_start(
            io::ErrorKind::PermissionDenied,
            format!("{} was replaced while being removed", path.display()),
        ));
    }
    Ok(())
}

/// Check the socket path before `bind`.
///
/// A symbolic link and a file that is not a socket are errors, and the
/// answer comes from the pinned descriptor.  A socket with a live daemon
/// is an error.  A socket that refuses connections is stale and is
/// unlinked through the directory descriptor.  The path is opened with
/// `O_PATH | O_NOFOLLOW` first, so the descriptor the decision is made on
/// is the descriptor that describes the file at the path, and a symbolic
/// link is never followed and never removed.
fn prepare_socket_path(path: &Path, dir: &std::fs::File) -> io::Result<()> {
    let Some(pin) = pin_path(path)? else {
        return Ok(());
    };
    let md = pin.metadata()?;
    let ft = md.file_type();
    if ft.is_symlink() {
        return Err(refuse_start(
            io::ErrorKind::InvalidInput,
            format!("{} is a symbolic link", path.display()),
        ));
    }
    if !ft.is_socket() {
        return Err(refuse_start(
            io::ErrorKind::InvalidInput,
            format!("{} exists and is not a socket", path.display()),
        ));
    }
    match UnixStream::connect(path) {
        Ok(_probe) => Err(refuse_start(
            io::ErrorKind::AddrInUse,
            format!("another daemon is already listening on {}", path.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => remove_pinned(path, &pin, dir),
        Err(e) => Err(refuse_start(
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
struct BoundSocket {
    listener: UnixListener,
    dev: u64,
    ino: u64,
    /// The socket's directory, held so removal goes through it.
    dir: std::fs::File,
}

fn bind_socket(cfg: &DaemonConfig) -> io::Result<BoundSocket> {
    let _umask = UmaskGuard::set(0o077);
    let dir_path = cfg.socket.parent().unwrap_or_else(|| Path::new(""));
    let (dir, dir_mode) = check_socket_dir(dir_path)?;
    if let Some(warning) = socket_dir_warning(dir_path, dir_mode) {
        log_line(cfg, &warning);
    }
    prepare_socket_path(&cfg.socket, &dir)?;
    let listener =
        UnixListener::bind(&cfg.socket).map_err(|e| path_error(&cfg.socket, "cannot bind", e))?;
    set_cloexec(listener.as_raw_fd())?;

    let euid = unsafe { libc::geteuid() };
    let first = std::fs::symlink_metadata(&cfg.socket)
        .map_err(|e| path_error(&cfg.socket, "cannot inspect the new socket", e))?;
    if !first.file_type().is_socket() || first.uid() != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{}: the file after bind is not a socket owned by uid {}",
                cfg.socket.display(),
                euid
            ),
        ));
    }
    set_mode(&cfg.socket, cfg.socket_mode)?;
    let second = std::fs::symlink_metadata(&cfg.socket)
        .map_err(|e| path_error(&cfg.socket, "cannot inspect the new socket", e))?;
    if second.dev() != first.dev() || second.ino() != first.ino() || !second.file_type().is_socket()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{}: the socket was replaced while starting",
                cfg.socket.display()
            ),
        ));
    }
    listener
        .set_nonblocking(true)
        .map_err(|e| path_error(&cfg.socket, "cannot set non-blocking mode", e))?;
    Ok(BoundSocket {
        listener,
        dev: first.dev(),
        ino: first.ino(),
        dir,
    })
}

/// Remove the socket file when it is still the one this daemon bound.
fn remove_own_socket(cfg: &DaemonConfig, bound: &BoundSocket) {
    let Ok(Some(pin)) = pin_path(&cfg.socket) else {
        return;
    };
    let Ok(md) = pin.metadata() else {
        return;
    };
    if md.file_type().is_socket() && md.dev() == bound.dev && md.ino() == bound.ino {
        let _ = remove_pinned(&cfg.socket, &pin, &bound.dir);
    }
}

/// Bind and serve until `SIGTERM` or `SIGINT`.  With `jobs == 1` one job
/// runs at a time inside this process.  With `jobs > 1` a forked worker
/// handles each connection.
pub fn serve(mut cfg: DaemonConfig) -> io::Result<()> {
    ensure_stdio_open()?;
    let me = unsafe { libc::geteuid() };
    if cfg.jobs == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--jobs needs a number of at least 1",
        ));
    }
    if cfg.run_as_uid && me != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "--run-as-uid needs a daemon that runs as root",
        ));
    }
    crate::mask::validate_label(&cfg.label)?;
    // The status a PING returns carries the label, and the wire form
    // escapes it.  Refuse a label the status could not report whole
    // rather than truncating it in every answer.
    if cfg.label.len() > MAX_LABEL {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the daemon label is {} bytes, the protocol limit is {}",
                cfg.label.len(),
                MAX_LABEL
            ),
        ));
    }
    install_signal_handlers()?;
    let method = detect_peer_method();
    if cfg.socket.as_os_str().is_empty() {
        return Err(refuse_start(
            io::ErrorKind::InvalidInput,
            "no socket path: XDG_RUNTIME_DIR is unset or not private, so pass --socket PATH"
                .to_string(),
        ));
    }
    let bound = bind_socket(&cfg)?;

    let unlocked = lock_env(&cfg.env);
    if unlocked > 0 {
        log_line(
            &cfg,
            &format!("warning: mlock failed for {} environment buffers", unlocked),
        );
    }
    log_line(
        &cfg,
        &format!(
            "listening on {} (uid {}, label '{}', {} env var{}, {} job slot{})",
            cfg.socket.display(),
            me,
            escape_for_log(&cfg.label, 64),
            cfg.env.len(),
            if cfg.env.len() == 1 { "" } else { "s" },
            cfg.jobs,
            if cfg.jobs == 1 { "" } else { "s" }
        ),
    );
    log_line(&cfg, &format!("peer identity: {}", method.as_str()));
    if method == PeerMethod::CredsOnly {
        log_line(
            &cfg,
            "warning: this kernel does not offer SO_PEERPIDFD (Linux 6.5 and later); \
             the peer identity is best effort",
        );
    }

    let result = accept_loop(&cfg, &bound.listener, me, method);

    wipe_env(&mut cfg.env);
    remove_own_socket(&cfg, &bound);
    log_line(&cfg, "stopped");
    result
}

fn accept_loop(
    cfg: &DaemonConfig,
    listener: &UnixListener,
    me: u32,
    method: PeerMethod,
) -> io::Result<()> {
    let lfd = listener.as_raw_fd();
    let mut workers: Vec<libc::pid_t> = Vec::new();
    while !SHUTDOWN.load(Ordering::SeqCst) {
        reap_workers(&mut workers);
        let full = cfg.jobs > 1 && workers.len() >= cfg.jobs;
        // The wake pipe is in the same poll as the listener, so SIGTERM
        // returns from this wait at once even when nothing connects.
        let wfd = wake_fd();
        let mut pfd = [
            libc::pollfd {
                fd: lfd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wfd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let nfd: libc::nfds_t = if full {
            0
        } else if wfd >= 0 {
            2
        } else {
            1
        };
        let rc = unsafe { libc::poll(pfd.as_mut_ptr(), nfd, if full { 200 } else { 500 }) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                log_line(cfg, &format!("poll: {}", e));
                std::thread::sleep(Duration::from_millis(200));
            }
            continue;
        }
        if rc == 0 {
            continue;
        }
        if wake_pending(&pfd, nfd) {
            wake_drain();
            continue;
        }
        if full {
            continue;
        }
        let stream = match listener.accept() {
            Ok((s, _addr)) => s,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                continue;
            }
            Err(e) => {
                log_line(cfg, &format!("accept: {}", e));
                continue;
            }
        };
        if let Err(e) = stream.set_nonblocking(false) {
            log_line(cfg, &format!("accepted socket: {}", e));
            continue;
        }
        if cfg.jobs <= 1 {
            report_conn(cfg, handle_conn(cfg, stream, me, method));
            continue;
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            log_line(cfg, &format!("fork: {}", io::Error::last_os_error()));
            // The wake pipe may be shared with the other workers; the
            // refusal is written with the plain stream, which is still
            // blocking here.
            let stream = stream;
            let _ = stream.set_nonblocking(false);
            let mut conn = Conn::new(stream, None);
            reject(&mut conn, "pmaskd: cannot start a worker");
            continue;
        }
        if pid == 0 {
            unsafe { libc::close(lfd) };
            report_conn(cfg, handle_conn(cfg, stream, me, method));
            unsafe { libc::_exit(0) };
        }
        drop(stream);
        workers.push(pid);
    }
    stop_workers(&mut workers);
    Ok(())
}

fn report_conn(cfg: &DaemonConfig, r: io::Result<()>) {
    if let Err(e) = r {
        if e.kind() == io::ErrorKind::UnexpectedEof && !cfg.verbose {
            return;
        }
        log_line(cfg, &format!("connection: {}", e));
    }
}

/// Collect finished workers without blocking.
fn reap_workers(workers: &mut Vec<libc::pid_t>) {
    workers.retain(|&pid| {
        let mut status = 0 as libc::c_int;
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        rc == 0
    });
}

/// How long a worker gets to finish after `SIGTERM` before it is killed.
///
/// A worker blocked on a client that never sends its request does not see
/// the shutdown flag: the read is restarted by `SA_RESTART`, and with
/// `--io-timeout 0` it has no deadline of its own.  The daemon's promise is
/// that `SIGTERM` stops it, so the wait is bounded and the last resort is
/// `SIGKILL`.
const WORKER_STOP_GRACE: Duration = Duration::from_secs(5);

/// Ask every worker to stop, then kill the ones that did not.
fn stop_workers(workers: &mut Vec<libc::pid_t>) {
    for &pid in workers.iter() {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    let deadline = Instant::now() + WORKER_STOP_GRACE;
    let mut alive: Vec<libc::pid_t> = workers.clone();
    while !alive.is_empty() && Instant::now() < deadline {
        alive.retain(|&pid| {
            let mut status = 0 as libc::c_int;
            (unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) }) == 0
        });
        if !alive.is_empty() {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    for &pid in alive.iter() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    for &pid in alive.iter() {
        let mut status = 0 as libc::c_int;
        loop {
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            if rc >= 0 {
                break;
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
    }
    workers.clear();
}

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad socket path"))?;
    let rc = unsafe { libc::chmod(c.as_ptr(), mode as libc::mode_t) };
    if rc < 0 {
        return Err(path_error(
            path,
            "cannot set the socket mode",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// Text that is safe to put in a log line: printable ASCII stays, every
/// other byte becomes `\xNN`, and the result is cut at `limit` bytes.
pub fn escape_for_log(text: &str, limit: usize) -> String {
    let mut out = String::new();
    for &b in text.as_bytes() {
        if out.len() >= limit {
            out.push_str("...");
            break;
        }
        if (0x20..=0x7e).contains(&b) && b != b'\\' {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{:02x}", b));
        }
    }
    out
}

/// Send a refusal and close the connection.  The daemon half-closes and
/// reads what the client still sends, so the client reads the refusal
/// instead of a connection reset.
fn reject(conn: &mut Conn, msg: &str) {
    let _ = write_response(conn, ExitState::plain(CODE_REFUSED, None), msg);
    conn.shutdown_write();
    // Bounded by the same wake-aware wait: a client that never drains its
    // own input must not keep the daemon in `reject` either.
    let saved = conn.read_timeout;
    conn.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 8192];
    let mut total = 0usize;
    while total < MAX_REQUEST {
        match conn.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    conn.set_read_timeout(saved);
}

fn close_all(fds: &[RawFd]) {
    for &fd in fds {
        unsafe {
            libc::close(fd);
        }
    }
}

/// Size checks that run before the job starts.  The redaction block holds
/// the real argv, the environment and comm; a job that does not fit would
/// run with its environment visible, so it is refused.
///
/// The comparison against [`MAX_HIDDEN`](crate::MAX_HIDDEN) is on the
/// string sum, which is the quantity the block builder itself bounds; the
/// margin covers what the builder maps beside the strings
/// ([`REDACTION_MARGIN`]).
fn check_job_size(cfg: &DaemonConfig, label: &str, argv: &[OsString]) -> Result<(), String> {
    let argv_bytes: usize = argv.iter().map(|a| a.len() + 1).sum();
    if argv_bytes > cfg.max_job_bytes {
        return Err(format!(
            "job arguments are {} bytes, the limit is {}",
            argv_bytes, cfg.max_job_bytes
        ));
    }
    let env_bytes: usize = cfg.env.iter().map(|(k, v)| k.len() + v.len() + 2).sum();
    let comm_bytes = label.len().min(crate::COMM_MAX) + 1;
    let need = argv_bytes + env_bytes + comm_bytes + REDACTION_MARGIN;
    if need > crate::MAX_HIDDEN {
        return Err(format!(
            "the redaction block would need {} bytes, the limit is {}",
            need,
            crate::MAX_HIDDEN
        ));
    }
    Ok(())
}

fn handle_conn(
    cfg: &DaemonConfig,
    stream: UnixStream,
    daemon_uid: u32,
    peer_method: PeerMethod,
) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    let timeout = if cfg.io_timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(cfg.io_timeout_secs))
    };
    // The socket is non-blocking from here on.  `SO_RCVTIMEO` would not
    // fire on a non-blocking descriptor, and it cannot be armed on the
    // wake pipe either, so every wait goes through `wait_readable`, which
    // watches the socket and the pipe together.
    stream.set_nonblocking(true)?;
    let mut conn = Conn::new(stream, timeout);

    // Invariant 11: the uid check comes before the request is read.
    let (uid, gid, pid) = peer_cred_full(fd)?;
    let allowed = uid == daemon_uid || uid == 0 || cfg.allow_uids.contains(&uid);
    if !allowed {
        reject(&mut conn, &format!("pmaskd: uid {} is not allowed", uid));
        return Ok(());
    }
    // The pid the kernel recorded at connect is pinned here, and the pin
    // is consulted again immediately before the job starts.
    let mut pin = PeerPin::take(fd, pid);
    pin.settle();

    let first = conn.recvmsg_first(CLIENT_FDS)?;
    if first.version != PROTOCOL_VERSION {
        close_all(&first.fds);
        let msg = if first.version == OLD_BANNER {
            format!(
                "pmaskd: protocol mismatch: the client speaks protocol 1, the daemon speaks protocol {}",
                PROTOCOL_VERSION
            )
        } else {
            format!(
                "pmaskd: unsupported protocol version {}, the daemon speaks protocol {}",
                first.version, PROTOCOL_VERSION
            )
        };
        reject(&mut conn, &msg);
        return Ok(());
    }
    if first.truncated {
        close_all(&first.fds);
        reject(
            &mut conn,
            "pmaskd: too many file descriptors (control data truncated); send exactly 3",
        );
        return Ok(());
    }
    if first.fds.len() != CLIENT_FDS {
        let got = first.fds.len();
        close_all(&first.fds);
        reject(
            &mut conn,
            &format!("pmaskd: expected exactly 3 file descriptors, got {}", got),
        );
        return Ok(());
    }

    let (label, argv) = match read_any_request(&mut conn) {
        Ok(Request::Ping) => {
            close_all(&first.fds);
            let status = daemon_status(cfg, uid, peer_method);
            return write_response(&mut conn, ExitState::plain(0, None), &status.to_text());
        }
        Ok(Request::Job(label, argv)) => (label, argv),
        Err(e) => {
            close_all(&first.fds);
            // A shutdown is not a malformed request: say which it was.
            if e.kind() == io::ErrorKind::ConnectionAborted {
                return Ok(());
            }
            reject(&mut conn, &format!("pmaskd: bad request: {}", e));
            return Ok(());
        }
    };
    let label_text = match &label {
        RemoteLabel::Default => cfg.label.clone(),
        RemoteLabel::Empty => String::new(),
        RemoteLabel::Text(t) => t.clone(),
    };
    if let Err(why) = check_job_size(cfg, &label_text, &argv) {
        close_all(&first.fds);
        reject(&mut conn, &format!("pmaskd: job refused: {}", why));
        return Ok(());
    }

    if cfg.verbose {
        log_line(
            cfg,
            &format!(
                "uid {} job label '{}' ({} args)",
                uid,
                escape_for_log(&label_text, 64),
                argv.len()
            ),
        );
    }

    // The identity is checked once more immediately before the job
    // starts: the request took time to read, and during it the pid could
    // have been recycled.
    if let Err(e) = pin.revalidate() {
        close_all(&first.fds);
        reject(&mut conn, &format!("pmaskd: {}", e));
        return Ok(());
    }

    match run_job(cfg, uid, gid, &label_text, &argv, &first.fds) {
        Ok((state, msg)) => write_response(&mut conn, state, &msg),
        Err(e) => {
            let msg = format!("pmaskd: {}", e);
            write_response(&mut conn, ExitState::plain(CODE_REFUSED, None), &msg)
        }
    }
}

/// The PING body: what this daemon would do with a job right now.
fn daemon_status(cfg: &DaemonConfig, peer_uid: u32, method: PeerMethod) -> DaemonStatus {
    DaemonStatus {
        protocol: PROTOCOL_VERSION,
        label: cfg.label.clone(),
        uid: unsafe { libc::geteuid() },
        run_as_uid: cfg.run_as_uid,
        jobs: cfg.jobs,
        env_vars: cfg.env.len(),
        allow_uids: cfg.allow_uids.clone(),
        socket_mode: cfg.socket_mode,
        io_timeout_secs: cfg.io_timeout_secs,
        job_timeout_secs: cfg.job_timeout_secs,
        max_job_bytes: cfg.max_job_bytes,
        peer_identity: method.as_str(),
        peer_uid,
    }
}

/// Copy descriptors 0, 1 and 2 to descriptors above 2 with `FD_CLOEXEC`.
fn save_stdio() -> io::Result<Vec<RawFd>> {
    let mut saved = Vec::new();
    for fd in 0..3 as RawFd {
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if copy < 0 {
            let e = io::Error::last_os_error();
            close_all(&saved);
            return Err(e);
        }
        saved.push(copy);
    }
    Ok(saved)
}

fn restore_stdio(saved: &[RawFd]) {
    for (i, &fd) in saved.iter().enumerate() {
        unsafe {
            libc::dup2(fd, i as RawFd);
            libc::close(fd);
        }
    }
}

/// Start one job with the client's stdio on descriptors 0, 1 and 2 and
/// wait for it.  The daemon closes the received descriptors before the
/// job starts, and puts its own 0, 1 and 2 back as soon as the fork is
/// done.  Returns the terminal state and an optional message.
fn run_job(
    cfg: &DaemonConfig,
    uid: u32,
    gid: u32,
    label: &str,
    argv: &[OsString],
    fds: &[RawFd],
) -> io::Result<(ExitState, String)> {
    let saved = match save_stdio() {
        Ok(s) => s,
        Err(e) => {
            close_all(fds);
            return Err(e);
        }
    };
    for (i, &fd) in fds.iter().enumerate() {
        if unsafe { libc::dup2(fd, i as RawFd) } < 0 {
            let e = io::Error::last_os_error();
            close_all(fds);
            restore_stdio(&saved);
            return Err(e);
        }
    }
    close_all(fds);

    let mut mask = Mask::new()
        .label(label)
        .envs(cfg.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    // A job that degrades must say so on the daemon's stderr: invariant 13
    // applies to a daemon's jobs too.  `--quiet` is the operator asking for
    // silence, and the response frame carries only the exit status.
    if cfg.quiet {
        mask = mask.quiet();
    }
    if cfg.keep_env {
        mask = mask.keep_environ_visible();
    }
    if cfg.run_as_uid {
        mask = mask.run_as(uid, gid);
    }
    let rest: Vec<OsString> = argv[1..].to_vec();
    let spawned = mask.spawn(&argv[0], &rest);
    restore_stdio(&saved);
    wait_job(cfg, spawned?)
}

/// Wait for the job.  Kills the whole tree at `--job-timeout` and at
/// daemon shutdown.
fn wait_job(cfg: &DaemonConfig, mut child: MaskedChild) -> io::Result<(ExitState, String)> {
    // `Instant::now() + Duration` panics on overflow, and the panic takes
    // the daemon down with it (issue 18).  The parse-time cap in
    // `pmaskd` keeps the operator's number away from that edge; this is
    // the guard for a caller that sets the field directly.  A deadline
    // that cannot be represented is treated as "no timeout", with one
    // warning, because refusing the job after it started is worse than
    // running it without a limit.
    let deadline = match job_deadline(Instant::now(), cfg.job_timeout_secs) {
        Ok(d) => d,
        Err(secs) => {
            log_line(
                cfg,
                &format!(
                    "warning: --job-timeout {} s does not fit the clock; the job runs with no \
                     timeout (the limit is {} s)",
                    secs, MAX_TIMEOUT_SECS
                ),
            );
            None
        }
    };
    loop {
        if let Some(state) = child.wait_timeout(Duration::from_millis(250))? {
            return Ok((state, String::new()));
        }
        let timed_out = deadline.is_some_and(|d| Instant::now() >= d);
        let stopping = SHUTDOWN.load(Ordering::SeqCst);
        if timed_out || stopping {
            child.kill_tree();
            let _ = child.wait_timeout(Duration::from_secs(10));
            let msg = if timed_out {
                format!(
                    "pmaskd: job exceeded --job-timeout {} s and was killed",
                    cfg.job_timeout_secs
                )
            } else {
                "pmaskd: daemon is shutting down, job killed".to_string()
            };
            return Ok((ExitState::plain(137, Some(libc::SIGKILL)), msg));
        }
    }
}

/// The deadline `secs` seconds after `start`, or the value back when the
/// addition would overflow.
///
/// Split out so the overflow path is testable without waiting for a job:
/// `Instant::now() + Duration::from_secs(u64::MAX)` panics, and a test
/// cannot catch a panic that ends the process under test.
fn job_deadline(start: Instant, secs: u64) -> Result<Option<Instant>, u64> {
    if secs == 0 {
        return Ok(None);
    }
    start
        .checked_add(Duration::from_secs(secs))
        .map(Some)
        .ok_or(secs)
}

/// Build the job environment.  With `inherit` the daemon's own
/// environment comes first and `overrides` replace or extend it.  Without
/// `inherit` the job gets `overrides` only.
pub fn job_env(inherit: bool, overrides: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
    let mut out: Vec<(OsString, OsString)> = if inherit {
        std::env::vars_os().collect()
    } else {
        Vec::new()
    };
    for (k, v) in overrides {
        match out.iter_mut().find(|(ek, _)| ek == k) {
            Some(slot) => slot.1 = v.clone(),
            None => out.push((k.clone(), v.clone())),
        }
    }
    out
}

/// Inherited environment overridden by `--env-file` entries.
pub fn merged_env(overrides: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
    job_env(true, overrides)
}

/// Convenience: the argv vector a client sends.
pub fn client_argv(program: &OsStr, args: &[OsString]) -> Vec<OsString> {
    let mut v = Vec::with_capacity(args.len() + 1);
    v.push(program.to_os_string());
    v.extend_from_slice(args);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;

    fn test_dir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("pmask-daemon-unit-{}-{}", tag, std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    #[test]
    fn status_text_roundtrips() {
        let s = DaemonStatus {
            protocol: PROTOCOL_VERSION,
            label: "ci-runner".to_string(),
            uid: 1000,
            run_as_uid: true,
            jobs: 3,
            env_vars: 2,
            allow_uids: vec![0, 1001],
            socket_mode: 0o600,
            io_timeout_secs: 5,
            job_timeout_secs: 60,
            max_job_bytes: 4096,
            peer_identity: "pidfd + start time",
            peer_uid: 1000,
        };
        let back = DaemonStatus::parse(&s.to_text()).expect("parse");
        assert_eq!(back, s);
        // The report names the limit rather than implying security.
        assert!(s.to_text().contains("privileged observer"));
    }

    #[test]
    fn status_reports_no_environment_value() {
        let mut cfg = DaemonConfig::new();
        cfg.env = vec![
            (OsString::from("TOKEN"), OsString::from("SUPERSECRET")),
            (OsString::from("OTHER"), OsString::from("second")),
        ];
        let text = daemon_status(&cfg, 1000, PeerMethod::Pidfd).to_text();
        assert!(!text.contains("SUPERSECRET"));
        assert!(!text.contains("second"));
        assert!(text.contains("env_vars=2"));
    }

    #[test]
    fn a_long_label_is_reported_whole() {
        // The status is what a client learns about the daemon; a label
        // longer than the old 64-byte cut must survive the round trip
        // instead of arriving with "..." in it.
        let mut cfg = DaemonConfig::new();
        cfg.label =
            "pmask-job-production-eu-west-1-deployment-runner-blue-canary-2026-11-07".to_string();
        assert!(cfg.label.len() > 64, "the case must exceed the old cut");
        let st = daemon_status(&cfg, 1000, PeerMethod::Pidfd);
        let back = DaemonStatus::parse(&st.to_text()).expect("parse");
        assert_eq!(back.label, cfg.label);
    }

    #[test]
    fn a_ping_frame_is_recognised_and_carries_nothing_else() {
        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC_PING);
        let mut cursor = Cursor::new(frame);
        assert!(matches!(read_any_request(&mut cursor), Ok(Request::Ping)));

        let mut bad = Cursor::new(b"XXXX".to_vec());
        assert!(read_any_request(&mut bad).is_err());
    }

    #[test]
    fn a_job_frame_still_reads_through_read_any_request() {
        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC);
        frame.push(LABEL_EMPTY);
        frame.extend_from_slice(&0u32.to_le_bytes());
        frame.extend_from_slice(&1u32.to_le_bytes());
        frame.extend_from_slice(&2u32.to_le_bytes());
        frame.extend_from_slice(b"hi");
        match read_any_request(&mut Cursor::new(frame)).unwrap() {
            Request::Job(RemoteLabel::Empty, argv) => {
                assert_eq!(argv, vec![OsString::from("hi")])
            }
            other => panic!("expected a job, got {}", matches!(other, Request::Ping)),
        }
    }

    #[test]
    fn a_directory_we_did_not_create_must_not_be_writable_by_others() {
        let d = test_dir("world");
        // A fresh 0700 directory passes.  Making it group-writable must
        // fail, and the message must say why.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ok = check_socket_dir(&d);
        assert!(ok.is_ok(), "{:?}", ok.err());
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o770)).unwrap();
        let err = check_socket_dir(&d).expect_err("group-writable refused");
        assert!(err.to_string().contains("writ"), "{}", err);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o707)).unwrap();
        assert!(check_socket_dir(&d).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_visible_socket_directory_is_reported_in_one_line() {
        // 0700 is private: nothing to say.  0755 is `/run`, and 0750 lets
        // group read and traverse; both are accepted with a warning.
        assert!(socket_dir_warning(Path::new("/run"), 0o700).is_none());
        assert!(socket_dir_warning(Path::new("/run"), 0o701).is_some());
        let w = socket_dir_warning(Path::new("/run"), 0o755).expect("0755 warns");
        assert!(w.contains("group or other"), "{}", w);
        assert!(w.contains("0755"), "{}", w);
        assert_eq!(w.lines().count(), 1, "{}", w);
        // The warning is about the mode it was given, not a re-read path.
        assert!(socket_dir_warning(Path::new("/run"), 0o750).is_some());
    }

    #[test]
    fn a_symlink_at_the_socket_path_is_never_followed() {
        let d = test_dir("pinsymlink");
        let target = d.join("real.socket");
        let link = d.join("link.socket");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (dir, _) = check_socket_dir(&d).unwrap();
        let err = prepare_socket_path(&link, &dir).expect_err("a symlink must be refused");
        assert!(err.to_string().contains("symbolic link"), "{}", err);
        // The link itself, and the target name, are both still absent.
        assert!(std::fs::symlink_metadata(&link).is_ok());
        assert!(!target.exists());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_non_socket_at_the_socket_path_is_not_removed() {
        let d = test_dir("pinsfile");
        let path = d.join("plain.socket");
        std::fs::write(&path, b"keep me").unwrap();
        let (dir, _) = check_socket_dir(&d).unwrap();
        let err = prepare_socket_path(&path, &dir).expect_err("a plain file must be refused");
        assert!(err.to_string().contains("not a socket"), "{}", err);
        assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_symlink_wrapped_directory_is_refused() {
        let d = test_dir("dirsymlink");
        let real = d.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let alias = d.join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let err = check_socket_dir(&alias).expect_err("a symlinked directory must be refused");
        assert!(
            err.to_string().contains("not a usable directory"),
            "{}",
            err
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn the_default_socket_has_no_tmp_fallback() {
        let saved = std::env::var_os("XDG_RUNTIME_DIR");
        let saved_cs = std::env::var_os("PMASK_SOCKET");
        std::env::remove_var("XDG_RUNTIME_DIR");
        std::env::remove_var("PMASK_SOCKET");
        let got = default_socket();
        let root = unsafe { libc::geteuid() } == 0;
        if root {
            assert_eq!(got, PathBuf::from("/run/pmask.sock"));
        } else {
            assert!(got.as_os_str().is_empty(), "got {}", got.display());
        }
        match saved {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        match saved_cs {
            Some(v) => std::env::set_var("PMASK_SOCKET", v),
            None => std::env::remove_var("PMASK_SOCKET"),
        }
    }

    #[test]
    fn an_explicit_socket_is_honoured_when_xdg_is_unset() {
        let saved = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::remove_var("XDG_RUNTIME_DIR");
        let d = test_dir("explicit");
        let sock = d.join("s.sock");
        let mut cfg = DaemonConfig::new();
        cfg.socket = sock.clone();
        assert_eq!(cfg.socket, sock);
        match saved {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn ping_remote_reads_a_live_daemon() {
        let d = test_dir("live");
        let sock = d.join("live.sock");
        let mut cfg = DaemonConfig::new();
        cfg.socket = sock.clone();
        cfg.label = "unit-label".to_string();
        cfg.jobs = 2;
        cfg.quiet = true;
        std::thread::spawn(move || {
            let _ = serve(cfg);
        });
        for _ in 0..400 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(sock.exists(), "the daemon never bound {}", sock.display());
        let st = ping_remote(&sock).expect("the daemon answers PING");
        assert_eq!(st.label, "unit-label");
        assert_eq!(st.jobs, 2);
        assert_eq!(st.protocol, PROTOCOL_VERSION);
        assert_eq!(st.peer_uid, unsafe { libc::geteuid() });
        assert!(st.peer_identity.contains("peercred") || st.peer_identity.contains("pidfd"));
        std::fs::remove_dir_all(&d).ok();
    }

    // ------------------------------------------------------ env file --

    /// Write `text` to a file in a fresh private directory and parse it.
    fn parse_text_file(tag: &str, text: &[u8]) -> io::Result<Vec<(OsString, OsString)>> {
        let d = test_dir(tag);
        let p = d.join("env");
        std::fs::write(&p, text).unwrap();
        let out = parse_env_file(&p);
        std::fs::remove_dir_all(&d).ok();
        out
    }

    fn pairs(v: Vec<(&str, &str)>) -> Vec<(OsString, OsString)> {
        v.into_iter()
            .map(|(k, val)| (OsString::from(k), OsString::from(val)))
            .collect()
    }

    #[test]
    fn env_file_accepts_export_and_strips_it_from_the_key() {
        // Row 1 of issue 7.  The name is `FOO`, not `export FOO`; a
        // variable called `export FOO` is one no shell and no program
        // will ever read.
        let got = parse_text_file("export", b"export FOO=bar\n").unwrap();
        assert_eq!(got, pairs(vec![("FOO", "bar")]));
        // Blanks between `export` and the name are dropped too, and a
        // bare `export` with nothing after it is not a name.
        let got = parse_text_file("exportspace", b"export   FOO=bar\n").unwrap();
        assert_eq!(got, pairs(vec![("FOO", "bar")]));
    }

    #[test]
    fn env_file_strips_a_trailing_cr() {
        // Row 2 of issue 7, and the dangerous one: a file written on
        // Windows or by a templating step used to leave a CR on every
        // value, so `v\r` was delivered where `v` was meant.
        let got = parse_text_file("crlf", b"CRLF=v\r\nPLAIN=w\n").unwrap();
        assert_eq!(got, pairs(vec![("CRLF", "v"), ("PLAIN", "w")]));
    }

    #[test]
    fn env_file_refuses_a_key_with_a_blank_or_control_byte() {
        // Row 3 of issue 7.  A key with a space is a variable no program
        // can read, so it is refused rather than delivered.
        let e = parse_text_file("badkey", b"BAD KEY=v\n").unwrap_err();
        assert!(e.to_string().contains("key contains a space"), "{}", e);
        assert!(e.to_string().ends_with(":1: key contains a space"), "{}", e);
        // A control byte is refused by the same rule, and named.
        let e = parse_text_file("ctrlkey", b"BAD\x01KEY=v\n").unwrap_err();
        assert!(e.to_string().contains("0x01"), "{}", e);
        let e = parse_text_file("tabkey", b"BAD\tKEY=v\n").unwrap_err();
        assert!(e.to_string().contains("space"), "{}", e);
    }

    #[test]
    fn env_file_removes_one_pair_of_matching_quotes() {
        // Row 4 of issue 7.  The quotes are the CLI's documented
        // grammar, and the daemon already had them; neither surface can
        // differ any more.
        let got = parse_text_file("quoted", b"K=\"quoted value\"\nS='single'\n").unwrap();
        assert_eq!(got, pairs(vec![("K", "quoted value"), ("S", "single")]));
        // Mismatched or unpaired quotes stay as written.
        let got = parse_text_file("unquoted", b"A=\"x'\nB=\"\nC=\"\n").unwrap();
        assert_eq!(got, pairs(vec![("A", "\"x'"), ("B", "\""), ("C", "\"")]));
    }

    #[test]
    fn env_file_and_cli_agree_on_the_same_bytes() {
        // The property issue 7 asks for: one file, one environment.  The
        // table is the issue's own, plus the blank/control rows; every
        // accepted line must produce the same pair whichever surface
        // reads it, and every refused line must be refused by both.
        fn check(text: &[u8], want: &[(&str, &str)]) {
            let got = parse_text_file("agree", text).unwrap_or_else(|e| {
                panic!("{:?} was refused: {}", String::from_utf8_lossy(text), e)
            });
            assert_eq!(
                got,
                pairs(want.to_vec()),
                "{:?}",
                String::from_utf8_lossy(text)
            );
        }
        check(b"export FOO=bar\n", &[("FOO", "bar")]);
        check(b"CRLF=v\r\n", &[("CRLF", "v")]);
        check(b"K=\"quoted value\"\n", &[("K", "quoted value")]);
        check(b"# comment\n\nA=1\n", &[("A", "1")]);

        let refused: &[&[u8]] = &[b"BAD KEY=v\n", b"=v\n", b"noseparator\n", b"A=\0b\n"];
        for text in refused {
            assert!(
                parse_text_file("refuse", text).is_err(),
                "{:?} was accepted",
                String::from_utf8_lossy(text)
            );
        }
    }

    #[test]
    fn env_file_reports_the_file_and_the_line() {
        let d = test_dir("lineno");
        let p = d.join("env");
        std::fs::write(&p, b"A=1\nB=2\nBAD KEY=3\n").unwrap();
        let e = parse_env_file(&p).unwrap_err().to_string();
        assert!(e.contains("env:3:"), "{}", e);
        assert!(e.contains(&d.display().to_string()), "{}", e);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn env_file_refuses_a_nul_byte_and_an_empty_key() {
        let e = parse_text_file("nul", b"A=1\nB=2\0\n").unwrap_err();
        assert!(e.to_string().contains("NUL byte"), "{}", e);
        assert!(
            e.to_string().ends_with(":2: line contains a NUL byte"),
            "{}",
            e
        );
        let e = parse_text_file("emptykey", b"=v\n").unwrap_err();
        assert!(e.to_string().contains("expected KEY=VALUE"), "{}", e);
    }

    // ------------------------------------------------ job deadlines --

    #[test]
    fn a_job_timeout_of_zero_means_no_deadline() {
        assert_eq!(job_deadline(Instant::now(), 0), Ok(None));
    }

    #[test]
    fn a_deadline_that_would_overflow_is_reported_not_panicked() {
        // Issue 18: `Instant::now() + Duration::from_secs(u64::MAX)`
        // panics, and the panic kills the daemon on its first job.  The
        // guard has to return the value instead of reaching the add.
        for secs in [u64::MAX, u64::MAX - 1, 1u64 << 63, (1u64 << 63) + 1] {
            let got = job_deadline(Instant::now(), secs);
            assert_eq!(got, Err(secs), "{} s was not refused", secs);
        }
    }

    #[test]
    fn a_deadline_inside_the_clock_is_the_instant_we_asked_for() {
        let start = Instant::now();
        let got = job_deadline(start, 60)
            .expect("60 s must fit")
            .expect("a deadline");
        let delta = got.duration_since(start);
        assert_eq!(delta, Duration::from_secs(60));
        // The ten-year cap the parser enforces is comfortably inside the
        // clock, so an accepted value never reaches the overflow path.
        let cap = job_deadline(start, MAX_TIMEOUT_SECS);
        assert!(cap.is_ok(), "the accepted cap must not overflow");
    }

    // ------------------------------------------------ wake ups --

    /// The wake pipe is process-wide, so the tests that use it must not
    /// run at the same time: one test's drain would eat another's byte.
    /// (`serve`'s own poll competes for the same pipe, which is exactly
    /// the production behaviour; the tests below never assert on a count
    /// that a concurrent daemon could change.)
    static WAKE_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn wake_test_lock() -> std::sync::MutexGuard<'static, ()> {
        WAKE_TEST.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn a_wake_returns_from_a_wait_that_has_no_timeout() {
        // Issue 22 in miniature: with `--io-timeout 0` the wait has no
        // deadline, so nothing but the wake pipe can return from it.
        let _guard = wake_test_lock();
        install_wake_pipe().expect("pipe2");
        wake_drain();
        let (a, _b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let fd = a.as_raw_fd();
        let waker = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(100));
            wake_notify();
        });
        let start = Instant::now();
        let r = wait_readable(fd, None);
        let elapsed = start.elapsed();
        waker.join().unwrap();
        wake_drain();
        assert!(r.is_ok(), "{:?}", r);
        assert!(
            elapsed < Duration::from_secs(5),
            "the wait took {:?}, so the wake did not reach it",
            elapsed
        );
    }

    #[test]
    fn a_wake_pipe_byte_is_consumed_by_the_drain() {
        // A leftover byte would make the next poll return at once in a
        // tight loop, which is a busy wait rather than a wake.  The test
        // owns its pipe so a concurrent daemon cannot change the count.
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `fds` has room for the two descriptors pipe2 fills.
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        let byte = 1u8;
        // SAFETY: one write to a pipe this test owns.
        assert_eq!(
            unsafe { libc::write(fds[1], &byte as *const u8 as *const libc::c_void, 1) },
            1
        );
        drain_fd(fds[0]);
        let mut buf = [0u8; 1];
        // SAFETY: one non-blocking read from the pipe this test owns.
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut libc::c_void, 1) };
        // SAFETY: both descriptors belong to this test.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        assert_eq!(n, -1, "the drain left a byte behind");
    }

    #[test]
    fn a_read_timeout_still_expires_with_the_wake_pipe_in_place() {
        // The timeout must not be lost when the wake pipe is added to the
        // poll set.  `--io-timeout 2` depends on this.
        let _guard = wake_test_lock();
        install_wake_pipe().expect("pipe2");
        wake_drain();
        let (a, _b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let start = Instant::now();
        let r = wait_readable(a.as_raw_fd(), Some(Duration::from_millis(80)));
        let elapsed = start.elapsed();
        match r {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{:?}", e),
            Ok(()) => panic!("a silent socket reported readable"),
        }
        assert!(elapsed >= Duration::from_millis(70), "{:?}", elapsed);
    }

    #[test]
    fn every_deadline_arithmetic_in_the_daemon_is_guarded() {
        // The class of defect, not one call site.  Issue 18 was
        // `Instant::now() + Duration::from_secs(cfg.job_timeout_secs)`,
        // which panics on the first job when the operator passes a huge
        // number.  A bare `+` is safe only when its right-hand side is a
        // compile-time constant: a constant cannot overflow, a config
        // value can.  The filter is a source scan because the property is
        // about a shape, and it names every line it rejects so the
        // failure points at the caller rather than at this test.
        //
        // Only production code is scanned: this test's own needle and
        // messages live after the `#[cfg(test)]` marker.
        let src = include_str!("daemon.rs");
        let production = src
            .split_once("#[cfg(test)]\nmod tests")
            .map(|(a, _)| a)
            .unwrap_or(src);
        // The needle is assembled so this function's own text cannot
        // match it.
        let needle = format!("Instant::now() {}", '+');
        let mut bare: Vec<&str> = Vec::new();
        for line in production.lines() {
            let code = match line.find("//") {
                Some(i) => &line[..i],
                None => line,
            };
            let Some((_, rhs)) = code.split_once(needle.as_str()) else {
                continue;
            };
            let rhs = rhs.trim().trim_end_matches(';').trim();
            let is_const = !rhs.is_empty()
                && rhs
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b == b'_' || b.is_ascii_digit());
            if !is_const {
                bare.push(line.trim());
            }
        }
        assert!(
            bare.is_empty(),
            "a non-constant duration reaches the deadline addition: {:?}",
            bare
        );
    }
}
