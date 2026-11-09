//! Isolation: give the payload its own namespaces and its own filesystem
//! policy, without root.
//!
//! Unprivileged user namespaces let an ordinary account create a mount,
//! PID, network, UTS, IPC and cgroup namespace for a child.  What that
//! buys, concretely:
//!
//! * **PID namespace**: the payload's `/proc` lists only the payload.
//!   Code running inside cannot enumerate, or read the command lines of,
//!   the other jobs on the host.
//! * **Mount namespace**: a fresh `procfs`, a private `tmpfs` on `/tmp`
//!   and a fresh `/dev` holding only the device nodes the payload needs.
//!   Files the payload writes do not land in the host's `/tmp`, and the
//!   host's device nodes are not on a path the payload can reach.
//! * **Network namespace**: an empty network stack: nothing but
//!   loopback.  A payload that should not talk to the world cannot.
//! * **UTS namespace**: the payload sees a neutral hostname instead of
//!   the host's, so `uname -n` stops naming the machine.
//! * **IPC namespace**: no SysV objects or POSIX message queues shared
//!   with processes outside.
//! * **Cgroup namespace**: the payload's `/proc/<pid>/cgroup` shows the
//!   namespace root instead of the host's cgroup path.
//!
//! Two mechanisms work without any namespace at all:
//!
//! * **`PR_SET_NO_NEW_PRIVS`**: inherited across `fork` and `exec`, it
//!   stops a set-uid or set-gid binary, or a file capability, from raising
//!   the payload's privileges.  It is also the precondition for
//!   unprivileged Landlock, so it is set in every isolation run before the
//!   payload execs.
//! * **Landlock**: a filesystem policy the payload cannot leave.  See
//!   [`FsPolicy`].
//!
//! This is the direction metadata redaction does not cover: redaction
//! hides the payload *from* the host, isolation hides the host *from* the
//! payload.  They need different plumbing (a PID namespace needs an extra
//! fork, which a ptrace supervisor cannot drive), so `pmask run` offers
//! them as separate modes and says which one you got.
//!
//! # What each Landlock ABI adds
//!
//! The ABI is what `landlock_create_ruleset(NULL, 0,
//! LANDLOCK_CREATE_RULESET_VERSION)` returns, never a guess from the kernel
//! version.  [`FsPolicy`] handles ABI 1 and every later one.  The three
//! rights it restricts (`EXECUTE`, `READ_FILE`, `READ_DIR`) exist from ABI
//! 1, so the policy is the same on every ABI and only the reported number
//! changes:
//!
//! | ABI | kernel | what it adds | used here |
//! |---|---|---|---|
//! | 1 | 5.13 | filesystem access rights | yes: `EXECUTE`, `READ_FILE`, `READ_DIR` |
//! | 2 | 5.19 | `FS_REFER`: rename and link across directories | no |
//! | 3 | 6.2 | `FS_TRUNCATE` | no |
//! | 4 | 6.7 | TCP bind and connect | no: the network namespace covers it |
//! | 5 | 6.10 | `FS_IOCTL_DEV` | no: the payload keeps `ioctl` on its nodes |
//! | 6 | 6.12 | `SCOPE_SIGNAL`, `SCOPE_ABSTRACT_UNIX_SOCKET` | no |
//!
//! A right the ruleset does not handle is a right Landlock does not
//! restrict.  Writes, renames, truncation and `ioctl` therefore stay
//! governed by ordinary file permissions, and the network namespace, not
//! Landlock, is what removes the payload's reach.
//!
//! # Honest limits
//!
//! * Landlock does not restrict descriptors opened before the domain was
//!   applied, nor anonymous objects reopened through `/proc/<pid>/fd`.  An
//!   inherited secret descriptor stays readable.
//! * The fresh `/dev` is a default-path protection.  A device node handed
//!   to the payload some other way still works.
//! * A refused mechanism never aborts the run.  Each is attempted on its
//!   own and reported in [`Report`]; the payload runs with what it got.
//! * When the mount namespace is refused, no mount is attempted at all,
//!   because a mount without a private namespace would change the host's
//!   mount table.
//! * The session's private `/proc` is a `pidfs` mount of the payload's own
//!   PID namespace.  A PID namespace cannot be created inside a process
//!   that namespaces were already unshared into and then fork from a
//!   second time, so the payload is forked once, after every namespace
//!   call, and is pid 1 of the new one.
//!
//! # What the CLI still has to wire
//!
//! This module exposes the mechanisms; two call sites outside it are not
//! wired, and are named here rather than changed:
//!
//! 1. A namespace-free filesystem run has to skip `run::Mode::Isolate`,
//!    which today needs unprivileged user namespaces.  `run.rs` should
//!    apply [`FsPolicy::apply_child`] in its `pre_exec` closure instead.
//! 2. `-q` does not reach the report: `isolate::run` takes no quiet flag,
//!    so the effective set is printed on every isolation run.

use crate::userns;
use crate::ExitState;
use std::ffi::{CStr, CString};
use std::io;

/// `prctl(PR_SET_NO_NEW_PRIVS)`; 38 on every Linux architecture.
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

/// Landlock syscall numbers, the same on x86-64, i386 and aarch64.
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

/// `LANDLOCK_CREATE_RULESET_VERSION`.
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
/// `LANDLOCK_RULE_PATH_BENEATH`.
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

/// `LANDLOCK_ACCESS_FS_EXECUTE`.
const ACCESS_EXECUTE: u64 = 1 << 0;
/// `LANDLOCK_ACCESS_FS_READ_FILE`.
const ACCESS_READ_FILE: u64 = 1 << 2;
/// `LANDLOCK_ACCESS_FS_READ_DIR`.
const ACCESS_READ_DIR: u64 = 1 << 3;

/// The rights this module restricts: execute a file, read a file, list a
/// directory.
const HANDLED: u64 = ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR;

/// `sizeof(struct landlock_path_beneath_attr)`: a `__u64` then a `__s32`,
/// packed, so 12 bytes on a 64-bit little-endian kernel.
const PATH_BENEATH_LEN: usize = 12;

/// The neutral hostname set inside a UTS namespace.
const NEUTRAL_HOSTNAME: &[u8] = b"pmask";

/// Which namespaces to create.  A user namespace is always created (it is
/// what makes the others possible without root), and every isolation run
/// also creates the user, mount, UTS, IPC and cgroup namespaces: a refusal
/// costs nothing and cannot weaken the payload's view.  The three fields
/// here are the ones a caller can turn off.
#[derive(Debug, Clone, Copy)]
pub struct Isolate {
    pub pid: bool,
    pub net: bool,
    pub private_tmp: bool,
}

impl Isolate {
    pub fn all() -> Isolate {
        Isolate {
            pid: true,
            net: true,
            private_tmp: true,
        }
    }

    /// The set this request asks for, in the order [`Report::describe`]
    /// uses.  It names what will be *attempted*; the kernel's answer is in
    /// [`Report`].
    pub fn describe(&self) -> String {
        let flag = |on: bool| if on { "" } else { "=off" };
        format!(
            "user,mount,pid{},net{},uts,ipc,cgroup,tmp{},landlock,no_new_privs,dev,proc",
            flag(self.pid),
            flag(self.net),
            flag(self.private_tmp)
        )
    }
}

// ---------------------------------------------------------------- report

/// How one mechanism ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Not requested, so not attempted.
    Off,
    /// In effect.
    Applied,
    /// Requested, and the kernel refused it.  Carries the errno.
    Refused(i32),
    /// Not attempted because a mechanism it needs was refused.  Carries the
    /// errno of that refusal.
    Blocked(i32),
    /// Not attempted because attempting it would break the run.  Carries the
    /// errno that names the conflict, and is reported separately from a
    /// kernel refusal so the reason is not misattributed.
    Skipped(i32),
}

/// One mechanism's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub state: State,
    /// Meaning depends on the mechanism: the ABI for `landlock`, the number
    /// of bound device nodes for `dev`, the procfs mode for `proc`.
    pub detail: u32,
}

/// The effective isolation: one entry per mechanism, in the order
/// `user,mount,pid,net,uts,ipc,cgroup,tmp,landlock,no_new_privs,dev,proc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub user: Entry,
    pub mount: Entry,
    pub pid: Entry,
    pub net: Entry,
    pub uts: Entry,
    pub ipc: Entry,
    pub cgroup: Entry,
    pub private_tmp: Entry,
    pub landlock: Entry,
    pub no_new_privs: Entry,
    pub dev: Entry,
    pub proc: Entry,
    /// Allowlist paths Landlock accepted, and paths that exist but whose
    /// rule the kernel refused.  Zero when Landlock was not applied.
    pub landlock_paths: (usize, usize),
    /// Which optional members of the fresh `/dev` are in place, as the
    /// `DE_*` bits.  The `dev` entry's detail counts the basic nodes.
    pub dev_extra: u8,
}

/// Frame indices, shared with the payload child.  Two bytes each: state,
/// then detail.
const FRAME_LEN: usize = 12 * 2;
const I_USER: usize = 0;
const I_MOUNT: usize = 1;
const I_PID: usize = 2;
const I_NET: usize = 3;
const I_UTS: usize = 4;
const I_IPC: usize = 5;
const I_CGROUP: usize = 6;
const I_TMP: usize = 7;
const I_LANDLOCK: usize = 8;
const I_NNP: usize = 9;
const I_DEV: usize = 10;
const I_PROC: usize = 11;

const ST_OFF: u8 = 0;
const ST_APPLIED: u8 = 1;
const ST_REFUSED: u8 = 2;
const ST_BLOCKED: u8 = 3;
const ST_SKIPPED: u8 = 4;

/// procfs mount modes, as reported in the `proc` detail byte.
const PROC_HIDEPID2: u8 = 1;
const PROC_SUBSET_PID: u8 = 2;
const PROC_PLAIN: u8 = 3;

fn set(frame: &mut [u8; FRAME_LEN], idx: usize, state: u8, detail: u8) {
    frame[idx * 2] = state;
    frame[idx * 2 + 1] = detail;
}

fn set_ok(frame: &mut [u8; FRAME_LEN], idx: usize, detail: u8) {
    set(frame, idx, ST_APPLIED, detail);
}

fn set_refused(frame: &mut [u8; FRAME_LEN], idx: usize, errno: i32) {
    set(frame, idx, ST_REFUSED, errno as u8);
}

fn set_blocked(frame: &mut [u8; FRAME_LEN], idx: usize, errno: i32) {
    set(frame, idx, ST_BLOCKED, errno as u8);
}

fn set_skipped(frame: &mut [u8; FRAME_LEN], idx: usize, errno: i32) {
    set(frame, idx, ST_SKIPPED, errno as u8);
}

fn entry(frame: &[u8], idx: usize) -> Entry {
    let state = frame[idx * 2];
    let detail = u32::from(frame[idx * 2 + 1]);
    let state = match state {
        ST_APPLIED => State::Applied,
        ST_REFUSED => State::Refused(detail as i32),
        ST_BLOCKED => State::Blocked(detail as i32),
        ST_SKIPPED => State::Skipped(detail as i32),
        _ => State::Off,
    };
    Entry { state, detail }
}

/// The errno a mechanism's entry carries, whatever its refusal state.
fn entry_errno(e: &Entry) -> Option<i32> {
    match e.state {
        State::Refused(code) | State::Blocked(code) | State::Skipped(code) => Some(code),
        _ => None,
    }
}

fn errno_text(e: i32) -> String {
    let name = match e {
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::EINVAL => "EINVAL",
        libc::ENOSYS => "ENOSYS",
        libc::ENOENT => "ENOENT",
        libc::ENODEV => "ENODEV",
        libc::EBUSY => "EBUSY",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::E2BIG => "E2BIG",
        libc::ENOMEM => "ENOMEM",
        libc::EROFS => "EROFS",
        libc::EMFILE => "EMFILE",
        libc::EIO => "EIO",
        _ => return format!("errno {}", e),
    };
    name.to_string()
}

impl Report {
    /// Read the frame the payload child wrote before it exec'd.
    fn from_frame(frame: &[u8]) -> Report {
        Report {
            user: entry(frame, I_USER),
            mount: entry(frame, I_MOUNT),
            pid: entry(frame, I_PID),
            net: entry(frame, I_NET),
            uts: entry(frame, I_UTS),
            ipc: entry(frame, I_IPC),
            cgroup: entry(frame, I_CGROUP),
            private_tmp: entry(frame, I_TMP),
            landlock: entry(frame, I_LANDLOCK),
            no_new_privs: entry(frame, I_NNP),
            dev: entry(frame, I_DEV),
            proc: entry(frame, I_PROC),
            landlock_paths: (0, 0),
            dev_extra: 0,
        }
    }

    /// The effective set as one comma-separated line.  An applied mechanism
    /// is bare, except where its detail is the point (`landlock:abi=N`,
    /// `proc:subset`, `dev:6+4`).  A mechanism that did not take effect
    /// carries its state, so a reader never has to infer it from an
    /// absence.
    ///
    /// `dev` counts what the fresh `/dev` holds: the basic nodes, then the
    /// optional members (`pts`, `ptmx`, `shm`, the stdio links) that are in
    /// place.  The degradation lines name each absent member in full.
    pub fn describe(&self) -> String {
        let item = |name: &str, e: &Entry| -> String {
            match e.state {
                State::Applied => match name {
                    "landlock" => format!("landlock:abi={}", e.detail),
                    "proc" => {
                        let mode = match e.detail as u8 {
                            PROC_HIDEPID2 => "hidepid2",
                            PROC_SUBSET_PID => "subset",
                            PROC_PLAIN => "plain",
                            _ => "unknown",
                        };
                        format!("proc:{}", mode)
                    }
                    "dev" => {
                        let extras = DEV_EXTRAS
                            .iter()
                            .filter(|(bit, _)| self.dev_extra & bit != 0)
                            .count();
                        format!("dev:{}+{}", e.detail, extras)
                    }
                    _ => name.to_string(),
                },
                State::Off => format!("{}=off", name),
                State::Refused(code) => format!("{}=refused({})", name, errno_text(code)),
                State::Blocked(code) => format!("{}=blocked({})", name, errno_text(code)),
                State::Skipped(code) => format!("{}=skipped({})", name, errno_text(code)),
            }
        };
        [
            item("user", &self.user),
            item("mount", &self.mount),
            item("pid", &self.pid),
            item("net", &self.net),
            item("uts", &self.uts),
            item("ipc", &self.ipc),
            item("cgroup", &self.cgroup),
            item("tmp", &self.private_tmp),
            item("landlock", &self.landlock),
            item("no_new_privs", &self.no_new_privs),
            item("dev", &self.dev),
            item("proc", &self.proc),
        ]
        .join(",")
    }

    /// One line per mechanism that did not take effect, saying what the
    /// payload can still see because of it.  Empty when everything applied.
    pub fn degradations(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (name, e, consequence) in self.rows() {
            match e.state {
                State::Refused(code) => out.push(format!(
                    "{} refused ({}); {}",
                    name,
                    errno_text(code),
                    consequence
                )),
                State::Blocked(code) => out.push(format!(
                    "{} skipped ({}); {}",
                    name,
                    errno_text(code),
                    consequence
                )),
                State::Skipped(code) => out.push(format!(
                    "{} not attempted to keep the run working ({}); {}",
                    name,
                    errno_text(code),
                    consequence
                )),
                _ => {}
            }
        }
        if self.landlock.state == State::Applied && self.landlock_paths.1 > 0 {
            out.push(format!(
                "filesystem policy: {} allowlist paths attached, {} refused; the \
                 refused paths are unreadable to the payload",
                self.landlock_paths.0, self.landlock_paths.1
            ));
        }
        if self.dev.state == State::Applied {
            if (self.dev.detail as usize) < DEV_NODES.len() {
                out.push(format!(
                    "fresh /dev holds {} of {} device nodes; the payload loses the rest \
                     (absent on the host, or a refused bind)",
                    self.dev.detail,
                    DEV_NODES.len()
                ));
            }
            for (bit, path) in DEV_EXTRAS {
                if self.dev_extra & bit == 0 {
                    out.push(format!(
                        "fresh /dev has no {}; a payload that needs it sees ENOENT (absent \
                         on the host, or a refused mount)",
                        path.to_string_lossy()
                    ));
                }
            }
        }
        out
    }

    /// Name, entry and consequence for each mechanism, in describe order.
    fn rows(&self) -> [(&'static str, &Entry, &'static str); 12] {
        [
            (
                "the user namespace",
                &self.user,
                "no namespace below could be created, so the payload sees the host",
            ),
            (
                "the mount namespace",
                &self.mount,
                "nothing was mounted, so the host's /tmp, /dev and /proc stay visible",
            ),
            (
                "the pid namespace",
                &self.pid,
                "the payload can enumerate host processes and read their command lines",
            ),
            (
                "the network namespace",
                &self.net,
                "the payload keeps the host's network stack",
            ),
            (
                "the uts namespace",
                &self.uts,
                "the payload sees the host's hostname",
            ),
            (
                "the ipc namespace",
                &self.ipc,
                "the payload shares SysV objects and message queues with the host",
            ),
            (
                "the cgroup namespace",
                &self.cgroup,
                "the payload's /proc/<pid>/cgroup names the host's cgroup path",
            ),
            (
                "the private /tmp",
                &self.private_tmp,
                "the payload's writes land in the host's /tmp",
            ),
            (
                "the filesystem policy",
                &self.landlock,
                "the payload can read every path its file permissions allow",
            ),
            (
                "no_new_privs",
                &self.no_new_privs,
                "a set-uid binary can still raise the payload's privileges",
            ),
            (
                "the fresh /dev",
                &self.dev,
                "the payload sees the host's device nodes",
            ),
            (
                "the private procfs",
                &self.proc,
                "the payload sees the host's /proc",
            ),
        ]
    }
}

// ------------------------------------------------------------ Landlock

/// The filesystem policy a payload runs under.
///
/// Landlock is allowlist-only: everything the ruleset handles is denied
/// unless a rule allows it.  This policy handles `EXECUTE`, `READ_FILE`
/// and `READ_DIR`, allows them on the system directories a program needs
/// and on every path the caller adds, and leaves the rest of the filesystem
/// unreadable.  Writes, renames, truncation and `ioctl` are not handled, so
/// ordinary file permissions still govern them.
///
/// Every isolation run applies this policy; [`fs_policy`] builds the
/// default.
#[derive(Debug, Clone, Default)]
pub struct FsPolicy {
    paths: Vec<CString>,
}

/// System directories a program needs to start: its binary, its shared
/// libraries, its configuration, its locale, its view of `/proc`, `/dev`
/// and `/sys`, and the private `/tmp` it may write to.  Missing entries are
/// skipped, because a host without `/lib32` is normal.
///
/// `/opt` is deliberately absent: a rule there would allow every vendored
/// tree beneath it.  A payload installed under `/opt` gets its own parent
/// directory from `policy_for`.
pub const FS_POLICY_PATHS: [&str; 11] = [
    "/usr",
    "/usr/local",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/etc",
    "/proc",
    "/tmp",
];

/// The default filesystem policy: the system directories in
/// [`FS_POLICY_PATHS`] plus `/dev` and `/sys`.
pub fn fs_policy() -> FsPolicy {
    let mut p = FsPolicy::new();
    for path in FS_POLICY_PATHS {
        p.allow(path);
    }
    p.allow("/dev");
    p.allow("/sys");
    p
}

impl FsPolicy {
    pub fn new() -> FsPolicy {
        FsPolicy { paths: Vec::new() }
    }

    /// Allow read and execute beneath `path`.  A path that cannot be
    /// represented as a C string is ignored; a path that does not exist is
    /// skipped when the policy is applied.
    pub fn allow(&mut self, path: &str) {
        if let Ok(c) = CString::new(path) {
            self.paths.push(c);
        }
    }

    /// The paths this policy allows, in the order they will be attached.
    pub fn paths(&self) -> impl Iterator<Item = &CStr> {
        self.paths.iter().map(|c| c.as_c_str())
    }

    /// The policy as one line, for a log line or a help text.
    pub fn describe(&self) -> String {
        let list: Vec<String> = self
            .paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        format!("landlock read+execute beneath {}", list.join(","))
    }

    /// Ask the kernel which Landlock ABI it implements.  Returns an error
    /// with `ENOSYS`, `EOPNOTSUPP` or `EINVAL` where Landlock is absent or
    /// disabled, and a caller must not claim a policy in that case.
    pub fn abi() -> Result<u32, i32> {
        // SAFETY: the version query takes a null ruleset, a zero size and a
        // documented flag, and writes nothing back.
        let rc = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if rc >= 1 {
            return Ok(rc as u32);
        }
        Err(last_errno())
    }

    /// Apply the policy to the calling process and return the ABI.
    ///
    /// `PR_SET_NO_NEW_PRIVS` must already be set, which the kernel requires
    /// for an unprivileged `landlock_restrict_self`.  Intended for a
    /// `pre_exec` closure: the allowlist was built before the fork, so no
    /// path in this function allocates.
    ///
    /// Returns the ABI, and the number of rules the kernel accepted against
    /// the number offered, so a caller can report a partial policy.
    pub fn apply_child(&self) -> Result<(u32, usize, usize), i32> {
        let abi = FsPolicy::abi()?;
        let handled = HANDLED.to_ne_bytes();
        // SAFETY: a ruleset attribute of the size the kernel documents for
        // the filesystem field alone.  A shorter size than the kernel's
        // structure is accepted, and the kernel zero-extends the rest.
        let ruleset = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                handled.as_ptr() as *const libc::c_void,
                handled.len(),
                0u32,
            )
        };
        if ruleset < 0 {
            return Err(last_errno());
        }
        let ruleset = ruleset as libc::c_int;
        let (mut attached, mut refused) = (0usize, 0usize);
        let mut last = 0i32;
        for path in &self.paths {
            match add_path_rule(ruleset, path.as_ptr()) {
                RuleOutcome::Attached => attached += 1,
                RuleOutcome::Refused(e) => {
                    refused += 1;
                    last = e;
                }
                RuleOutcome::Absent => {}
            }
        }
        // No usable rule at all means the policy would deny the payload
        // everything, including its own binary.  Report the failure instead
        // of applying a rule set that cannot work.
        if attached == 0 {
            // SAFETY: the ruleset descriptor is ours.
            unsafe { libc::close(ruleset) };
            return Err(if last != 0 { last } else { libc::ENOENT });
        }
        // SAFETY: restricting the calling process with a ruleset it owns.
        let rc = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0u32) };
        let rc_errno = last_errno();
        // SAFETY: the descriptor is ours and is not needed once the
        // restriction is attached.
        unsafe { libc::close(ruleset) };
        if rc != 0 {
            return Err(rc_errno);
        }
        Ok((abi, attached, refused))
    }
}

/// The result of offering one allowlist path to a ruleset.
enum RuleOutcome {
    /// The kernel accepted a rule for this path.
    Attached,
    /// The path exists but the kernel refused the rule.  Carries the errno.
    Refused(i32),
    /// The path is not on this host, so there was nothing to allow.
    Absent,
}

fn last_errno() -> i32 {
    // SAFETY: reading this thread's errno slot.
    unsafe { *libc::__errno_location() }
}

fn open_path(path: *const libc::c_char) -> libc::c_int {
    // SAFETY: `path` is NUL-terminated and is used only for this call.
    unsafe { libc::open(path, libc::O_PATH | libc::O_CLOEXEC) }
}

fn add_fd_rule(ruleset: libc::c_int, fd: libc::c_int, access: u64) -> bool {
    let mut attr = [0u8; PATH_BENEATH_LEN];
    attr[..8].copy_from_slice(&access.to_ne_bytes());
    attr[8..].copy_from_slice(&fd.to_ne_bytes());
    // SAFETY: a ruleset this process created, a documented rule type, and a
    // 12-byte attribute laid out as `struct landlock_path_beneath_attr`.
    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset,
            LANDLOCK_RULE_PATH_BENEATH,
            attr.as_ptr() as *const libc::c_void,
            0u32,
        )
    };
    rc == 0
}

fn add_path_rule(ruleset: libc::c_int, path: *const libc::c_char) -> RuleOutcome {
    let fd = open_path(path);
    if fd < 0 {
        // A path that is not on this host is not a refused rule.
        let e = last_errno();
        return if e == libc::ENOENT || e == libc::ENOTDIR {
            RuleOutcome::Absent
        } else {
            RuleOutcome::Refused(e)
        };
    }
    let ok = add_fd_rule(ruleset, fd, HANDLED);
    let e = last_errno();
    // SAFETY: a descriptor this function opened.
    unsafe { libc::close(fd) };
    if ok {
        RuleOutcome::Attached
    } else {
        RuleOutcome::Refused(e)
    }
}

// --------------------------------------------------------- mount helpers

/// Device nodes a payload plausibly needs, bound from the host into the
/// fresh `/dev`.  Everything else the host has stays out of the payload's
/// view.  `/dev/tty` is the one a host may legitimately lack, which is why
/// the count is reported.
const DEV_NODES: [&CStr; 6] = [
    c"/dev/null",
    c"/dev/zero",
    c"/dev/full",
    c"/dev/random",
    c"/dev/urandom",
    c"/dev/tty",
];

/// The optional members of the fresh `/dev`, in report-bit order.
///
/// `/dev/pts` and `/dev/ptmx` are bound from the host: a pty is allocated
/// through the host's devpts instance, so a private one would need a new
/// `devpts` mount the kernel refuses without a full user namespace
/// handshake.  `/dev/shm` is a private tmpfs, because the host's POSIX
/// shared memory is not the payload's to see.
const DEV_PTS: &CStr = c"/dev/pts";
const DEV_PTMX: &CStr = c"/dev/ptmx";
const DEV_SHM: &CStr = c"/dev/shm";

/// Bit positions in [`Report::dev_extra`], one per entry in
/// [`DEV_EXTRAS`](self::DEV_EXTRAS).
const DE_PTS: u8 = 1 << 0;
const DE_PTMX: u8 = 1 << 1;
const DE_SHM: u8 = 1 << 2;
const DE_LINKS: u8 = 1 << 3;

/// The optional entries, with the bit that says it is in place and the
/// path named in a degradation line.
const DEV_EXTRAS: [(u8, &CStr); 4] = [
    (DE_PTS, c"/dev/pts"),
    (DE_PTMX, c"/dev/ptmx"),
    (DE_SHM, c"/dev/shm"),
    (DE_LINKS, c"/dev/fd and the stdio links"),
];

/// The stdio symlinks a payload written for a normal `/dev` expects.
/// Every one resolves through `/proc`, so it works with the private
/// procfs and with the host's `/proc` when the private one was refused.
const DEV_LINKS: [(&CStr, &CStr); 4] = [
    (c"/proc/self/fd", c"/dev/fd"),
    (c"/proc/self/fd/0", c"/dev/stdin"),
    (c"/proc/self/fd/1", c"/dev/stdout"),
    (c"/proc/self/fd/2", c"/dev/stderr"),
];

fn write_all(fd: libc::c_int, bytes: &[u8]) -> bool {
    let mut off = 0;
    while off < bytes.len() {
        // SAFETY: writing to an fd we opened.
        let n = unsafe {
            libc::write(
                fd,
                bytes[off..].as_ptr() as *const libc::c_void,
                bytes.len() - off,
            )
        };
        if n <= 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

fn write_file(path: &CStr, bytes: &[u8]) -> bool {
    // SAFETY: O_WRONLY|O_CLOEXEC on a kernel-provided file.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return false;
    }
    let ok = write_all(fd, bytes);
    // SAFETY: fd is ours.
    unsafe { libc::close(fd) };
    ok
}

fn die(what: &str) -> ! {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"pmask: isolation: ");
    msg.extend_from_slice(what.as_bytes());
    msg.extend_from_slice(b": ");
    msg.extend_from_slice(io::Error::last_os_error().to_string().as_bytes());
    msg.push(b'\n');
    // SAFETY: one write to fd 2, then exit.
    unsafe {
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::_exit(126);
    }
}

/// Mount, returning the errno on failure.
fn mount_checked(
    source: *const libc::c_char,
    target: *const libc::c_char,
    fstype: *const libc::c_char,
    flags: libc::c_ulong,
    data: *const libc::c_void,
) -> Result<(), i32> {
    // SAFETY: every pointer is a NUL-terminated constant or null, and the
    // call runs in the child's own mount namespace.
    let rc = unsafe { libc::mount(source, target, fstype, flags, data) };
    if rc == 0 {
        Ok(())
    } else {
        Err(last_errno())
    }
}

/// The private `/tmp`: an empty tmpfs of mode 1777.
fn mount_private_tmp() -> Result<(), i32> {
    mount_checked(
        c"tmpfs".as_ptr(),
        c"/tmp".as_ptr(),
        c"tmpfs".as_ptr(),
        (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
        c"mode=1777".as_ptr() as *const libc::c_void,
    )
}

/// What the fresh `/dev` ended up holding: how many of [`DEV_NODES`]
/// were bound, and the [`DE_*`] bits for the optional members.
#[derive(Debug, Clone, Copy, Default)]
struct DevOutcome {
    bound: usize,
    extra: u8,
}

/// Bind `source` (an `O_PATH` descriptor held across the tmpfs mount) at
/// `target`.  The target must already exist with the right type.
///
/// Binding through `/proc/self/fd` avoids naming a host path that the
/// tmpfs has already replaced.
fn bind_held(source: libc::c_int, target: &CStr) -> Result<(), i32> {
    let mut via = [0u8; 32];
    let prefix = b"/proc/self/fd/";
    via[..prefix.len()].copy_from_slice(prefix);
    let mut n = prefix.len();
    n += write_usize(&mut via[n..], source as usize);
    via[n] = 0;
    // SAFETY: `via` is NUL-terminated at `n`; `target` is a constant.
    let rc = unsafe {
        libc::mount(
            via.as_ptr() as *const libc::c_char,
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(last_errno())
    }
}

/// Create a file or directory the bind mount can replace, then bind.
/// A plain user namespace cannot `mknod` (`EPERM`), so the target is an
/// ordinary file for a device node and an empty directory for a mount
/// point; the bind replaces the inode, not the path.
fn bind_held_as(source: libc::c_int, target: &CStr, dir: bool) -> Result<(), i32> {
    if dir {
        // SAFETY: creating a directory inside our own tmpfs.
        let rc = unsafe { libc::mkdir(target.as_ptr(), 0o755 as libc::mode_t) };
        if rc != 0 {
            let e = last_errno();
            if e != libc::EEXIST {
                return Err(e);
            }
        }
    } else {
        // SAFETY: creating a file inside our own tmpfs.
        let fd = unsafe {
            libc::open(
                target.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                0o666 as libc::mode_t,
            )
        };
        if fd < 0 {
            return Err(last_errno());
        }
        // SAFETY: a descriptor opened here.
        unsafe { libc::close(fd) };
    }
    bind_held(source, target)
}

/// The fresh `/dev`: a tmpfs holding the nodes in [`DEV_NODES`], plus
/// `/dev/pts`, `/dev/ptmx`, a private `/dev/shm` and the stdio symlinks
/// when the host has what the first three need.
///
/// The host's nodes are opened with `O_PATH` first, because the tmpfs
/// replaces the directory they live in.  `MS_NODEV` is deliberately absent
/// from that tmpfs: it would make the bound device nodes unusable.
///
/// A missing optional member never fails the run: the payload gets a
/// `/dev` without it and [`Report::degradations`] names it.  A host
/// without `/dev/pts` has no pty to bind, and a kernel that refuses the
/// `/dev/shm` tmpfs (a seccomp filter, a restricted userns) leaves only
/// that member out.
fn mount_private_dev() -> Result<DevOutcome, i32> {
    let basic = DEV_NODES.len();
    let mut held = [-1 as libc::c_int; 6 + 2];
    for (i, node) in DEV_NODES.iter().enumerate() {
        held[i] = open_path(node.as_ptr());
    }
    held[basic] = open_path(DEV_PTS.as_ptr());
    held[basic + 1] = open_path(DEV_PTMX.as_ptr());
    let mounted = mount_checked(
        c"tmpfs".as_ptr(),
        c"/dev".as_ptr(),
        c"tmpfs".as_ptr(),
        libc::MS_NOSUID as libc::c_ulong,
        c"mode=0755,size=1m".as_ptr() as *const libc::c_void,
    );
    if let Err(e) = mounted {
        close_all(&held);
        return Err(e);
    }
    let mut out = DevOutcome::default();
    let mut first_errno = 0i32;
    for (i, node) in DEV_NODES.iter().enumerate() {
        if held[i] < 0 {
            continue;
        }
        match bind_held_as(held[i], node, false) {
            Ok(()) => out.bound += 1,
            Err(e) => {
                if first_errno == 0 {
                    first_errno = e;
                }
            }
        }
        // SAFETY: a descriptor opened above.
        unsafe { libc::close(held[i]) };
    }
    if out.bound == 0 && first_errno != 0 {
        return Err(first_errno);
    }
    if held[basic] >= 0 {
        // An optional member that fails is a degradation of that member
        // alone, so it does not set `first_errno`: the basic set is what
        // decides whether the fresh /dev exists at all.
        if bind_held_as(held[basic], DEV_PTS, true).is_ok() {
            out.extra |= DE_PTS;
        }
        // SAFETY: a descriptor opened above.
        unsafe { libc::close(held[basic]) };
    }
    if held[basic + 1] >= 0 {
        if bind_held_as(held[basic + 1], DEV_PTMX, false).is_ok() {
            out.extra |= DE_PTMX;
        }
        // SAFETY: a descriptor opened above.
        unsafe { libc::close(held[basic + 1]) };
    }
    // A private POSIX shared-memory directory.  `mode=1777` is the
    // sticky-bit world-writable mode a `/dev/shm` needs; `MS_NODEV`
    // matches the host's, so a payload cannot execute a node it creates
    // there.  The mount point has to exist in the fresh tmpfs first.
    // SAFETY: creating a directory inside our own tmpfs.
    let mkdir_rc = unsafe { libc::mkdir(DEV_SHM.as_ptr(), 0o1777 as libc::mode_t) };
    if mkdir_rc == 0 || last_errno() == libc::EEXIST {
        let shm = mount_checked(
            c"tmpfs".as_ptr(),
            DEV_SHM.as_ptr(),
            c"tmpfs".as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
            c"mode=1777".as_ptr() as *const libc::c_void,
        );
        if shm.is_ok() {
            out.extra |= DE_SHM;
        }
    }
    // Paths that resolve through /proc, so a payload written for a normal
    // /dev keeps working.  A host that already had them is not the case
    // here: the tmpfs is empty.
    let mut links = 0u8;
    for (source, target) in DEV_LINKS {
        // SAFETY: absolute paths inside our own mount namespace.
        let rc = unsafe { libc::symlink(source.as_ptr(), target.as_ptr()) };
        if rc == 0 {
            links += 1;
        }
    }
    if links as usize == DEV_LINKS.len() {
        out.extra |= DE_LINKS;
    }
    Ok(out)
}

fn close_all(fds: &[libc::c_int]) {
    for fd in fds {
        if *fd >= 0 {
            // SAFETY: descriptors opened by the caller.
            unsafe { libc::close(*fd) };
        }
    }
}

/// Write `value` as decimal digits into `out`; returns the length.
fn write_usize(out: &mut [u8], value: usize) -> usize {
    if value >= 10 {
        let n = write_usize(out, value / 10);
        out[n] = b'0' + (value % 10) as u8;
        n + 1
    } else {
        out[0] = b'0' + value as u8;
        1
    }
}

// ---------------------------------------------------------- payload child

/// The three pipes the handshake uses: the child reports that it has
/// unshared, the parent says the id maps are written, and the payload
/// child writes its status frame.
struct Pipes {
    ready_w: libc::c_int,
    go_r: libc::c_int,
    report_w: libc::c_int,
}

/// Everything the payload child needs, built before the fork so neither
/// child allocates after it.
struct Plan<'a> {
    iso: &'a Isolate,
    policy: &'a FsPolicy,
    fds: &'a [libc::c_int],
    prog: &'a CStr,
    argv: &'a [*const libc::c_char],
    envp: &'a [*const libc::c_char],
    cloexec: bool,
}

/// Runs in the first child: create each namespace on its own, record every
/// answer, then fork the payload.  Never returns.
///
/// The status frame lives on the stack and is copied into the payload
/// child, so nothing is allocated after the fork.
fn child_namespaces(plan: Plan<'_>, pipes: Pipes) -> ! {
    let Pipes {
        ready_w,
        go_r,
        report_w,
    } = pipes;
    let iso = plan.iso;
    let mut frame = [ST_OFF; FRAME_LEN];

    if userns::child_unshare(libc::CLONE_NEWUSER).is_ok() {
        set_ok(&mut frame, I_USER, 0);
    } else {
        set_refused(&mut frame, I_USER, last_errno());
    }

    // The mount namespace is attempted even when the user namespace was
    // refused: a caller that is already privileged does not need one.
    let mount_ok = match userns::child_unshare(libc::CLONE_NEWNS) {
        Ok(()) => {
            // Every mount must be private, or a mount here would propagate
            // back to the host's mount table.  A refused
            // `mount --make-rprivate /` is reported as a refused mount
            // namespace, not discarded.
            match mount_checked(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
                std::ptr::null(),
            ) {
                Ok(()) => {
                    set_ok(&mut frame, I_MOUNT, 0);
                    true
                }
                Err(e) => {
                    set_refused(&mut frame, I_MOUNT, e);
                    false
                }
            }
        }
        Err(e) => {
            set_refused(&mut frame, I_MOUNT, e.raw_os_error().unwrap_or(0));
            false
        }
    };
    if iso.pid {
        match userns::child_unshare(libc::CLONE_NEWPID) {
            Ok(()) => set_ok(&mut frame, I_PID, 0),
            Err(e) => set_refused(&mut frame, I_PID, e.raw_os_error().unwrap_or(0)),
        }
    }
    if iso.net {
        match userns::child_unshare(libc::CLONE_NEWNET) {
            Ok(()) => set_ok(&mut frame, I_NET, 0),
            Err(e) => set_refused(&mut frame, I_NET, e.raw_os_error().unwrap_or(0)),
        }
    }
    match userns::child_unshare(userns::NS_UTS) {
        Ok(()) => match userns::child_set_hostname(NEUTRAL_HOSTNAME) {
            Ok(()) => set_ok(&mut frame, I_UTS, 0),
            Err(e) => set_refused(&mut frame, I_UTS, e.raw_os_error().unwrap_or(0)),
        },
        Err(e) => set_refused(&mut frame, I_UTS, e.raw_os_error().unwrap_or(0)),
    }
    match userns::child_unshare(userns::NS_IPC) {
        Ok(()) => set_ok(&mut frame, I_IPC, 0),
        Err(e) => set_refused(&mut frame, I_IPC, e.raw_os_error().unwrap_or(0)),
    }
    match userns::child_unshare(userns::NS_CGROUP) {
        Ok(()) => set_ok(&mut frame, I_CGROUP, 0),
        Err(e) => set_refused(&mut frame, I_CGROUP, e.raw_os_error().unwrap_or(0)),
    }

    // Without a private mount namespace no mount is safe: each would land
    // in the host's mount table.  Name that in the report instead.
    if !mount_ok {
        let code = entry_errno(&entry(&frame, I_MOUNT)).unwrap_or(libc::EPERM);
        set_blocked(&mut frame, I_PROC, code);
        set_blocked(&mut frame, I_DEV, code);
        if iso.private_tmp {
            set_blocked(&mut frame, I_TMP, code);
        }
    }

    // The parent writes this child's id maps after the ready byte.  A
    // caller that hardened itself for secret material (`PR_SET_DUMPABLE=0`)
    // passes that flag across the fork, and a non-dumpable process cannot
    // have its `/proc/<pid>/uid_map` opened by the parent.  Restore it here,
    // before the handshake; the payload's own dumpability is the default
    // and `--no-dumpable` is a redaction-mode treatment.
    // SAFETY: our own dumpable flag.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };

    // The ready byte tells the parent whether it has id maps to write.  A
    // caller that is already privileged enters the mount namespace without
    // a user namespace, and then there is nothing to map.
    let ready = if entry(&frame, I_USER).state == State::Applied {
        b'u'
    } else {
        b'n'
    };
    // SAFETY: one byte to our own pipe, then one byte back.
    unsafe {
        libc::write(ready_w, &ready as *const u8 as *const libc::c_void, 1);
        let mut b = 0u8;
        libc::read(go_r, &mut b as *mut u8 as *mut libc::c_void, 1);
        libc::close(ready_w);
        libc::close(go_r);
    }

    // A PID namespace applies to children, so the payload needs one more
    // fork; this process waits and passes the status up.
    // SAFETY: the child only mounts and execs.
    let inner = unsafe { libc::fork() };
    if inner < 0 {
        die("fork");
    }
    if inner == 0 {
        payload_child(plan, mount_ok, frame, report_w);
    }
    // SAFETY: this process must not hold the write end open, or the parent
    // would not see the payload's write as complete.
    unsafe { libc::close(report_w) };

    let mut st = 0i32;
    loop {
        // SAFETY: our own child.
        let w = unsafe { libc::waitpid(inner, &mut st, 0) };
        if w == -1 {
            if last_errno() == libc::EINTR {
                continue;
            }
            // SAFETY: nothing left to wait for.
            unsafe { libc::_exit(126) };
        }
        break;
    }
    let code = if libc::WIFEXITED(st) {
        libc::WEXITSTATUS(st)
    } else {
        128 + libc::WTERMSIG(st)
    };
    // SAFETY: the payload is reaped; nothing left to do.
    unsafe { libc::_exit(code) };
}

/// Runs as the payload's pid 1: build the payload's view, report what
/// worked, then exec the payload.  Never returns.
fn payload_child(
    plan: Plan<'_>,
    mount_ok: bool,
    mut frame: [u8; FRAME_LEN],
    report_w: libc::c_int,
) -> ! {
    let Plan {
        iso,
        policy,
        fds,
        prog,
        argv,
        envp,
        cloexec,
    } = plan;
    let mut landlock_paths = (0usize, 0usize);
    let mut dev_extra = 0u8;
    if mount_ok {
        let proc = userns::child_setup_proc();
        match proc {
            Ok(userns::ProcMode::Hidepid2) => set_ok(&mut frame, I_PROC, PROC_HIDEPID2),
            Ok(userns::ProcMode::SubsetPid) => set_ok(&mut frame, I_PROC, PROC_SUBSET_PID),
            Ok(userns::ProcMode::Plain) => set_ok(&mut frame, I_PROC, PROC_PLAIN),
            Err(e) => set_refused(&mut frame, I_PROC, e.raw_os_error().unwrap_or(0)),
        }
        if iso.private_tmp {
            if prog_under_tmp(prog) {
                // A tmpfs here would replace the tree the payload's own
                // binary lives in, so the mount is refused to itself
                // rather than reported as a kernel refusal.
                set_skipped(&mut frame, I_TMP, libc::EBUSY);
            } else {
                match mount_private_tmp() {
                    Ok(()) => set_ok(&mut frame, I_TMP, 0),
                    Err(e) => set_refused(&mut frame, I_TMP, e),
                }
            }
        }
        // The device binds reach the host's nodes through /proc/self/fd.
        // That works with the private procfs just mounted and with the
        // host's `/proc` when the private one was refused, so the attempt is
        // made either way and a failure is reported on its own.
        match mount_private_dev() {
            Ok(d) => {
                set_ok(&mut frame, I_DEV, d.bound as u8);
                dev_extra = d.extra;
            }
            Err(e) => set_refused(&mut frame, I_DEV, e),
        }
    }

    // SAFETY: prctl on the calling process.
    let nnp = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) };
    if nnp == 0 {
        set_ok(&mut frame, I_NNP, 0);
    } else {
        set_refused(&mut frame, I_NNP, last_errno());
    }

    match policy.apply_child() {
        Ok((abi, attached, refused)) => {
            set_ok(&mut frame, I_LANDLOCK, abi.min(u32::from(u8::MAX)) as u8);
            landlock_paths = (attached, refused);
        }
        Err(e) => set_refused(&mut frame, I_LANDLOCK, e),
    }

    // The frame carries one detail byte per mechanism, and the Landlock
    // entry spends it on the ABI.  The rule counts follow it as two more
    // bytes and the `/dev` extras byte after them; `report_and_print`
    // reads them as `landlock_paths` and `dev_extra`.  The counts are
    // bounded by the allowlist length, well under a byte.
    let extra = [
        landlock_paths.0.min(255) as u8,
        landlock_paths.1.min(255) as u8,
        dev_extra,
    ];

    // SAFETY: the child reports through its own pipe and then execs.
    unsafe {
        write_all(report_w, &frame);
        write_all(report_w, &extra);
        libc::close(report_w);
    }
    for (i, fd) in fds.iter().enumerate() {
        let target = 3 + i as libc::c_int;
        // SAFETY: between fork and exec, async-signal-safe calls only.
        unsafe {
            if *fd != target {
                libc::dup2(*fd, target);
            }
            let flags = if cloexec { libc::FD_CLOEXEC } else { 0 };
            libc::fcntl(target, libc::F_SETFD, flags);
        }
    }
    // SAFETY: the final exec of the payload.
    unsafe { libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    die("execve");
}

/// Write `/proc/<pid>/{setgroups,uid_map,gid_map}` from the parent side.
///
/// The maps are written by the *parent*, not the child: a process that has
/// already entered a new user namespace cannot write its own `uid_map` (it
/// has no capability over the namespace it just left), which is why every
/// unprivileged sandbox does the handshake this way.
fn write_id_maps(pid: libc::pid_t) -> io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let setgroups = CString::new(format!("/proc/{}/setgroups", pid)).unwrap();
    let uid_map = CString::new(format!("/proc/{}/uid_map", pid)).unwrap();
    let gid_map = CString::new(format!("/proc/{}/gid_map", pid)).unwrap();

    // setgroups must be denied before gid_map can be written by an
    // unprivileged parent; failure is expected when we are root.
    let _ = write_file(&setgroups, b"deny");
    if !write_file(&uid_map, format!("0 {} 1\n", uid).as_bytes()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("uid_map: {}", io::Error::last_os_error()),
        ));
    }
    if !write_file(&gid_map, format!("0 {} 1\n", gid).as_bytes()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("gid_map: {}", io::Error::last_os_error()),
        ));
    }
    Ok(())
}

/// Read the status frame, then print the effective isolation.
fn report_and_print(report_r: libc::c_int) {
    let total = FRAME_LEN + 3;
    let mut frame = [0u8; FRAME_LEN + 3];
    let mut got = 0usize;
    while got < total {
        // SAFETY: reading our own pipe into a fixed buffer.
        let n = unsafe {
            libc::read(
                report_r,
                frame[got..].as_mut_ptr() as *mut libc::c_void,
                total - got,
            )
        };
        if n < 0 {
            if last_errno() == libc::EINTR {
                continue;
            }
            break;
        }
        if n == 0 {
            break;
        }
        got += n as usize;
    }
    if got < FRAME_LEN {
        eprintln!(
            "pmask: isolation: no report from the payload process \
             ({} of {} status bytes); the payload did not reach its exec",
            got, total
        );
        return;
    }
    let mut report = Report::from_frame(&frame);
    if got == total {
        if report.landlock.state == State::Applied {
            report.landlock_paths = (frame[FRAME_LEN] as usize, frame[FRAME_LEN + 1] as usize);
        }
        if report.dev.state == State::Applied {
            report.dev_extra = frame[FRAME_LEN + 2];
        }
    } else if report.dev.state == State::Applied {
        // A truncated frame does not say which optional /dev members are
        // in place.  Claiming they are absent would be a false
        // degradation, so the entry says the count is unknown instead.
        eprintln!(
            "pmask: isolation: the report was cut short ({} of {} status bytes); \
             the /dev member counts are unknown",
            got, total
        );
        report.dev.state = State::Skipped(libc::EIO);
    }
    eprintln!("pmask: isolation: {}", report.describe());
    for line in report.degradations() {
        eprintln!("pmask: isolation degraded: {}", line);
    }
}

/// Run `prog` inside fresh namespaces; `fds` are installed at 3, 4, …
///
/// `cloexec` keeps the installed descriptors closed across a later `exec`
/// in the payload, which is what a burn-after-read delivery needs.  The
/// flag is part of [`run`]'s contract rather than a second entry point
/// because both call sites set the descriptors the same way, in the child
/// between `fork` and `exec`.
///
/// Every mechanism is independent: a namespace, a mount, the hostname,
/// `PR_SET_NO_NEW_PRIVS` or the filesystem policy can be refused without
/// stopping the run.  The kernel's answers are printed on stderr as
/// `pmask: isolation: <set>` before the payload starts, and each
/// mechanism that did not take effect gets a `pmask: isolation degraded:`
/// line of its own.
pub fn run(
    iso: &Isolate,
    prog: &CStr,
    argv: &[*const libc::c_char],
    envp: &[*const libc::c_char],
    fds: &[libc::c_int],
    cloexec: bool,
) -> io::Result<ExitState> {
    let mut ready: [libc::c_int; 2] = [-1, -1];
    let mut go: [libc::c_int; 2] = [-1, -1];
    let mut report: [libc::c_int; 2] = [-1, -1];
    // SAFETY: plain pipe(2) into owned storage.
    unsafe {
        if libc::pipe(ready.as_mut_ptr()) == -1 {
            return Err(io::Error::last_os_error());
        }
        if libc::pipe(go.as_mut_ptr()) == -1 {
            libc::close(ready[0]);
            libc::close(ready[1]);
            return Err(io::Error::last_os_error());
        }
        if libc::pipe(report.as_mut_ptr()) == -1 {
            libc::close(ready[0]);
            libc::close(ready[1]);
            libc::close(go[0]);
            libc::close(go[1]);
            return Err(io::Error::last_os_error());
        }
    }

    // Built before the fork, so the child builds nothing.
    let policy = policy_for(prog);

    // SAFETY: the child only unshares, mounts, forks and execs.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: closing our ends of the handshake pipes.
        unsafe {
            libc::close(ready[0]);
            libc::close(go[1]);
            libc::close(report[0]);
        }
        child_namespaces(
            Plan {
                iso,
                policy: &policy,
                fds,
                prog,
                argv,
                envp,
                cloexec,
            },
            Pipes {
                ready_w: ready[1],
                go_r: go[0],
                report_w: report[1],
            },
        );
    }

    // ---- parent: write the maps, then let the child continue ----
    // SAFETY: closing our ends of the handshake pipes.
    unsafe {
        libc::close(ready[1]);
        libc::close(go[0]);
        libc::close(report[1]);
    }
    let mut b = 0u8;
    // SAFETY: reading one byte from our own pipe.
    let n = unsafe { libc::read(ready[0], &mut b as *mut u8 as *mut libc::c_void, 1) };
    unsafe { libc::close(ready[0]) };
    if n != 1 {
        // The child died before unsharing; collect it and report.
        let mut st = 0i32;
        unsafe {
            libc::waitpid(pid, &mut st, 0);
            libc::close(go[1]);
            libc::close(report[0]);
        }
        let code = if libc::WIFEXITED(st) {
            libc::WEXITSTATUS(st)
        } else {
            126
        };
        return Ok(ExitState::plain(code, None));
    }
    let map_err = if b == b'u' {
        write_id_maps(pid)
    } else {
        // No user namespace was entered, so there are no id maps to write.
        // Writing them would target a process whose map belongs to the
        // caller's own user namespace, which is what `EPERM` would mean.
        Ok(())
    };
    // SAFETY: releasing the child.
    unsafe {
        libc::write(go[1], b"1".as_ptr() as *const libc::c_void, 1);
        libc::close(go[1]);
    }
    if let Err(e) = map_err {
        let mut st = 0i32;
        unsafe {
            libc::waitpid(pid, &mut st, 0);
            libc::close(report[0]);
        }
        return Err(e);
    }

    report_and_print(report[0]);
    // SAFETY: the report pipe has been drained.
    unsafe { libc::close(report[0]) };

    let mut status = 0i32;
    loop {
        // SAFETY: our own child.
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        if w == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        break;
    }
    if libc::WIFEXITED(status) {
        Ok(ExitState::plain(libc::WEXITSTATUS(status), None))
    } else if libc::WIFSIGNALED(status) {
        let s = libc::WTERMSIG(status);
        Ok(ExitState::plain(128 + s, Some(s)))
    } else {
        Ok(ExitState::plain(255, None))
    }
}

/// True when the payload's binary is reached through `/tmp`, which the
/// private tmpfs would replace.
fn prog_under_tmp(prog: &CStr) -> bool {
    let bytes = prog.to_bytes();
    bytes == b"/tmp" || bytes.starts_with(b"/tmp/")
}

/// The policy an isolation run applies: [`fs_policy`] plus the directory
/// that holds the payload's own binary, which may sit anywhere.
///
/// Only the immediate parent is added, never its ancestors: a rule on `/`
/// or `/opt` would allow the whole tree beneath it and undo the policy.
/// Landlock resolves a path by executing `EXECUTE` on the binary and
/// `READ_DIR` on its parent, so the parent alone is enough.
fn policy_for(prog: &CStr) -> FsPolicy {
    let mut policy = fs_policy();
    let text = prog.to_string_lossy();
    if let Some((dir, _)) = text.rsplit_once('/') {
        if !dir.is_empty() {
            policy.allow(dir);
        }
    }
    policy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_names_every_mechanism_in_order() {
        let s = Isolate::all().describe();
        assert_eq!(
            s,
            "user,mount,pid,net,uts,ipc,cgroup,tmp,landlock,no_new_privs,dev,proc"
        );
        let off = Isolate {
            pid: false,
            net: false,
            private_tmp: false,
        }
        .describe();
        assert_eq!(
            off,
            "user,mount,pid=off,net=off,uts,ipc,cgroup,tmp=off,landlock,no_new_privs,dev,proc"
        );
    }

    // Mutation control: a report that reports an applied mechanism as Off
    // would make a degraded run look complete.
    #[test]
    fn report_describes_each_state_distinctly() {
        let mut frame = [ST_OFF; FRAME_LEN];
        set_ok(&mut frame, I_USER, 0);
        set_ok(&mut frame, I_MOUNT, 0);
        set_ok(&mut frame, I_PID, 0);
        set_refused(&mut frame, I_NET, libc::EPERM);
        set_refused(&mut frame, I_UTS, libc::EINVAL);
        set_ok(&mut frame, I_IPC, 0);
        set_ok(&mut frame, I_CGROUP, 0);
        set_ok(&mut frame, I_TMP, 0);
        set_ok(&mut frame, I_LANDLOCK, 6);
        set_ok(&mut frame, I_NNP, 0);
        set_ok(&mut frame, I_DEV, 6);
        set_ok(&mut frame, I_PROC, PROC_SUBSET_PID);
        let mut r = Report::from_frame(&frame);
        r.dev_extra = DE_PTS | DE_PTMX | DE_SHM | DE_LINKS;
        let d = r.describe();
        assert_eq!(
            d,
            "user,mount,pid,net=refused(EPERM),uts=refused(EINVAL),ipc,cgroup,tmp,\
             landlock:abi=6,no_new_privs,dev:6+4,proc:subset"
        );
        // Every mechanism is present exactly once, whatever its state.
        for name in [
            "user",
            "mount",
            "pid",
            "net",
            "uts",
            "ipc",
            "cgroup",
            "tmp",
            "landlock",
            "no_new_privs",
            "dev",
            "proc",
        ] {
            assert_eq!(
                d.split(',')
                    .filter(|seg| seg == &name
                        || seg.starts_with(&format!("{}:", name))
                        || seg.starts_with(&format!("{}=", name)))
                    .count(),
                1,
                "{} appears other than once in {}",
                name,
                d
            );
        }
        let deg = r.degradations();
        assert!(deg[0].contains("network namespace"), "{:?}", deg);
        assert!(deg[1].contains("uts namespace"), "{:?}", deg);
    }

    /// A `dev` entry with all six basic nodes bound and the given extras.
    fn dev_report(nodes: u8, extra: u8) -> Report {
        let mut frame = [ST_OFF; FRAME_LEN];
        set_ok(&mut frame, I_DEV, nodes);
        let mut r = Report::from_frame(&frame);
        r.dev_extra = extra;
        r
    }

    // Issue 25: a fresh /dev with six nodes and no pty support reported no
    // degradation, so a payload broke with "out of pty devices" under a
    // report that claimed the mechanism applied.  Each member now shows up
    // in the degradation list by name when it is absent.
    // Mutation control: dropping the extras loop makes this fail.
    #[test]
    fn dev_without_pts_is_named_as_degraded() {
        let r = dev_report(6, 0);
        let deg = r.degradations();
        let joined = deg.join("\n");
        assert!(joined.contains("no /dev/pts"), "{:?}", deg);
        assert!(joined.contains("no /dev/ptmx"), "{:?}", deg);
        assert!(joined.contains("no /dev/shm"), "{:?}", deg);
        assert!(joined.contains("no /dev/fd"), "{:?}", deg);
        // The basic-count line is not printed when all six are bound, so
        // the four extras are the whole list.
        assert_eq!(deg.len(), 4, "{:?}", deg);
    }

    // The applied entry counts what it got, so an operator sees the pty
    // members without reading the degradation list.  Mutation control:
    // printing the bare name makes this fail.
    #[test]
    fn applied_dev_entry_counts_the_members() {
        let r = dev_report(6, DE_PTS | DE_PTMX | DE_SHM | DE_LINKS);
        assert!(r.describe().contains("dev:6+4"), "{}", r.describe());
        let partial = dev_report(5, DE_PTS);
        assert!(
            partial.describe().contains("dev:5+1"),
            "{}",
            partial.describe()
        );
    }

    // A member this host lacks is not in the count, so the count and the
    // degradation line can never disagree.
    #[test]
    fn dev_count_matches_the_degradation_lines() {
        let r = dev_report(6, DE_PTS | DE_SHM);
        let d = r.describe();
        assert!(d.contains("dev:6+2"), "{}", d);
        let deg = r.degradations();
        assert_eq!(deg.len(), 2, "{:?}", deg);
        assert!(deg.iter().any(|l| l.contains("/dev/ptmx")), "{:?}", deg);
        assert!(deg.iter().any(|l| l.contains("/dev/fd")), "{:?}", deg);
    }

    // The other half: a fresh /dev with every member reports no
    // degradation at all, so the lines above cannot be printed
    // unconditionally.
    #[test]
    fn complete_dev_reports_no_degradation() {
        let all = DE_PTS | DE_PTMX | DE_SHM | DE_LINKS;
        assert!(dev_report(6, all).degradations().is_empty());
    }

    // A `dev` entry that is not applied says nothing about its members:
    // the refusal is already named once, for the mechanism as a whole.
    #[test]
    fn refused_dev_does_not_name_its_members() {
        let mut frame = [ST_OFF; FRAME_LEN];
        set_refused(&mut frame, I_DEV, libc::EPERM);
        let deg = Report::from_frame(&frame).degradations();
        assert_eq!(deg.len(), 1, "{:?}", deg);
        assert!(deg[0].contains("the fresh /dev"), "{:?}", deg);
    }

    #[test]
    fn dev_extras_cover_every_optional_member() {
        // Every bit `DE_*` is present in the table that names it, or a
        // member would be silently dropped from the report.
        let table: u8 = DEV_EXTRAS.iter().map(|(bit, _)| *bit).sum();
        assert_eq!(
            table,
            DE_PTS | DE_PTMX | DE_SHM | DE_LINKS,
            "a DE_ bit has no entry in DEV_EXTRAS"
        );
        assert_eq!(DEV_LINKS.len(), 4);
        // The six original nodes are never removed.
        assert_eq!(DEV_NODES.len(), 6);
    }

    #[test]
    fn skipped_is_distinct_from_a_kernel_refusal() {
        let mut frame = [ST_OFF; FRAME_LEN];
        set_skipped(&mut frame, I_TMP, libc::EBUSY);
        set_refused(&mut frame, I_DEV, libc::EPERM);
        let r = Report::from_frame(&frame);
        assert_eq!(r.private_tmp.state, State::Skipped(libc::EBUSY));
        assert_eq!(r.dev.state, State::Refused(libc::EPERM));
        let d = r.describe();
        assert!(d.contains("tmp=skipped(EBUSY)"), "{}", d);
        assert!(d.contains("dev=refused(EPERM)"), "{}", d);
        let deg = r.degradations();
        assert!(
            deg.iter()
                .any(|l| l.contains("not attempted to keep the run working")),
            "{:?}",
            deg
        );
    }

    #[test]
    fn blocked_mount_is_reported_as_blocked_not_refused() {
        let mut frame = [ST_OFF; FRAME_LEN];
        set_refused(&mut frame, I_MOUNT, libc::EPERM);
        set_blocked(&mut frame, I_TMP, libc::EPERM);
        set_blocked(&mut frame, I_DEV, libc::EPERM);
        let d = Report::from_frame(&frame).describe();
        assert!(d.contains("mount=refused(EPERM)"), "{}", d);
        assert!(d.contains("tmp=blocked(EPERM)"), "{}", d);
        assert!(d.contains("dev=blocked(EPERM)"), "{}", d);
    }

    #[test]
    fn policy_lists_the_system_directories() {
        let p = fs_policy();
        let list: Vec<String> = p
            .paths()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        assert!(list.contains(&"/usr".to_string()));
        assert!(list.contains(&"/dev".to_string()));
        assert!(!list.contains(&"/root".to_string()));
        assert!(p.describe().starts_with("landlock read+execute beneath "));
    }

    // Mutation control: adding the ancestors as well, or adding `/` when
    // the payload sits directly under the root, would allow the whole tree
    // and undo the policy.
    #[test]
    fn policy_for_adds_the_immediate_parent_only() {
        let p = policy_for(c"/opt/tools/bin/runner");
        let list: Vec<String> = p
            .paths()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        assert!(list.contains(&"/opt/tools/bin".to_string()));
        assert!(!list.contains(&"/opt/tools".to_string()));
        assert!(!list.contains(&"/".to_string()));
        let root = policy_for(c"/runner");
        assert!(
            !root.paths().any(|c| c.to_string_lossy() == "/"),
            "a binary directly under / must not allow /"
        );
    }

    // Mutation control: a payload reached through /tmp loses its own image
    // when a tmpfs is mounted over the directory, so the mount must be
    // skipped there.
    #[test]
    fn prog_under_tmp_detects_the_private_tmp_conflict() {
        assert!(prog_under_tmp(c"/tmp/runner"));
        assert!(prog_under_tmp(c"/tmp/tools/bin/runner"));
        assert!(prog_under_tmp(c"/tmp"));
        assert!(!prog_under_tmp(c"/usr/bin/runner"));
        assert!(!prog_under_tmp(c"/tmpfoo/runner"));
        assert!(!prog_under_tmp(c"/var/tmp/runner"));
    }

    #[test]
    fn write_usize_writes_decimal() {
        let mut buf = [0u8; 8];
        let n = write_usize(&mut buf, 1042);
        assert_eq!(&buf[..n], b"1042");
        let n = write_usize(&mut buf, 0);
        assert_eq!(&buf[..n], b"0");
        let n = write_usize(&mut buf, 7);
        assert_eq!(&buf[..n], b"7");
    }

    // Landlock's ABI query must either answer a version or a named errno;
    // a zero or negative answer treated as an ABI is the false claim this
    // guards.
    #[test]
    fn landlock_abi_is_either_positive_or_a_known_errno() {
        match FsPolicy::abi() {
            Ok(abi) => assert!(abi >= 1, "ABI {} is not a version", abi),
            Err(e) => {
                assert!(
                    matches!(
                        e,
                        libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL | libc::EPERM
                    ),
                    "unexpected errno {}",
                    e
                );
            }
        }
    }
}
