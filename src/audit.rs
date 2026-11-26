//! Live `/proc` surface audit, `profile.json` export, `--explain` renderer,
//! and label impersonation policy.
//!
//! This module implements the verification and contract layer for `pmask`:
//!
//! - [`Profile`] and [`select_auto_profile`] choose between `single`, `tree`,
//!   `tee`, and `compat` profiles.
//! - [`check_label_policy`] rejects kernel-thread bracket syntax and critical
//!   system service names unless `--allow-impersonation` is explicitly passed.
//! - [`audit_pid`] probes every observable `/proc/<pid>` surface, performs a
//!   bounded full-VMA `/proc/<pid>/mem` scan, checks invariants `INV-1`
//!   through `INV-10`, and emits an honest list of residuals.
//! - [`export_profile_for_pid`] and [`export_profile_template`] emit native
//!   `psgen` `schema: 2` JSON for downstream decoy generators without ever
//!   serializing raw secret bytes.
//! - [`render_explain`] prints what a profile hides, denies, and leaves
//!   exposed against the named observer (`same-uid local observer, no root`).

use std::ffi::OsStr;
use std::fmt::{self, Write as _};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::caps::{proc_hidepid, Caps};
use crate::COMM_MAX;

/// Version of the profile contract (`psgen` native `schema: 2`).
pub const PROFILE_VERSION: u32 = 2;

/// Native `psgen` numeric schema version emitted by `--profile-json`.
pub const PROFILE_SCHEMA_VERSION: u32 = 2;

/// Schema identifier for `--audit --json` output.
pub const AUDIT_SCHEMA: &str = "pmask-audit/1";

/// Human-readable schema label for `--profile-json` output.
pub const PROFILE_SCHEMA: &str = "psgen-profile/2";

/// Hard upper bound on total bytes scanned across `/proc/<pid>/mem` mappings
/// during one audit pass (64 MiB).
const MAX_MEM_SCAN_BYTES: usize = 64 * 1024 * 1024;

/// Chunk size for `/proc/<pid>/mem` scanning (64 KiB).
const MEM_CHUNK_BYTES: usize = 64 * 1024;

/// Maximum bytes read from a single small `/proc` file.
const MAX_PROC_READ_BYTES: usize = 4 * 1024 * 1024;

/// Maximum bytes read when dereferencing `AT_EXECFN` from `/proc/<pid>/mem`.
const MAX_EXECFN_BYTES: usize = 256;

/// Shells and launchers that routinely fork or exec subcommands and therefore
/// select [`Profile::Tree`] under `--profile auto`.
const TREE_LAUNCHERS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "ash",
    "zsh",
    "ksh",
    "mksh",
    "fish",
    "csh",
    "tcsh",
    "env",
    "make",
    "xargs",
    "timeout",
    "nice",
    "nohup",
    "sudo",
    "su",
    "busybox",
    "run-parts",
    "setsid",
    "stdbuf",
    "ionice",
    "chrt",
    "taskset",
];

/// Critical system service names refused by [`check_label_policy`] unless
/// `--allow-impersonation` is set.
const CRITICAL_SERVICES: &[&str] = &[
    "sshd",
    "systemd",
    "init",
    "cron",
    "crond",
    "systemd-journald",
    "systemd-udevd",
    "udevd",
    "dbus-daemon",
    "polkitd",
    "auditd",
    "rsyslogd",
    "syslogd",
];

/// Execution and stealth profile selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Automatically choose [`Profile::Single`] or [`Profile::Tree`].
    Auto,
    /// Single process, no persistent ptrace supervisor after exec.
    Single,
    /// Supervisor-backed process tree covering arbitrary forks and re-execs.
    Tree,
    /// Separate security domain (namespace / helper uid / microVM).
    Tee,
    /// Compatibility profile matching legacy flag-driven behavior.
    Compat,
}

impl Profile {
    /// Parse a profile name (`auto`, `single`, `tree`, `tee`, `compat`).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "single" => Some(Self::Single),
            "tree" => Some(Self::Tree),
            "tee" => Some(Self::Tee),
            "compat" => Some(Self::Compat),
            _ => None,
        }
    }

    /// Canonical lowercase profile name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Single => "single",
            Self::Tree => "tree",
            Self::Tee => "tee",
            Self::Compat => "compat",
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Choose between [`Profile::Single`] and [`Profile::Tree`] for `--profile auto`.
///
/// Returns [`Profile::Tree`] when `needs_tree` is true, when `program` has a
/// basename matching a known shell or launcher, or when `program` resolves to
/// a file starting with `#!`. Otherwise returns [`Profile::Single`].
pub fn select_auto_profile(program: &OsStr, needs_tree: bool) -> Profile {
    if needs_tree {
        return Profile::Tree;
    }

    let path = Path::new(program);
    if let Some(base) = path.file_name().and_then(|n| n.to_str()) {
        let lower = base.to_ascii_lowercase();
        if TREE_LAUNCHERS.contains(&lower.as_str()) {
            return Profile::Tree;
        }
    }

    if is_shebang_program(path) {
        return Profile::Tree;
    }

    Profile::Single
}

/// Check whether `program` (resolved via `PATH` if it has no path separator)
/// begins with the two-byte `#!` interpreter signature.
fn is_shebang_program(path: &Path) -> bool {
    if let Some(resolved) = resolve_program_path(path) {
        if let Ok(mut f) = File::open(resolved) {
            let mut magic = [0u8; 2];
            if f.read_exact(&mut magic).is_ok() && &magic == b"#!" {
                return true;
            }
        }
    }
    false
}

fn resolve_program_path(path: &Path) -> Option<PathBuf> {
    if path.as_os_str().is_empty() {
        return None;
    }
    let s = path.as_os_str().to_string_lossy();
    if s.contains('/') {
        return Some(path.to_path_buf());
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Error returned when a requested label or `comm` violates the default
/// impersonation policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelPolicyError {
    /// Label or `comm` uses kernel-thread bracket syntax such as `[kworker/0:0]`.
    KernelThread(String),
    /// Label or `comm` matches a critical system service name such as `sshd`.
    CriticalService(String),
}

impl fmt::Display for LabelPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KernelThread(val) => write!(
                f,
                "label '{val}' uses kernel-thread bracket syntax; pass --allow-impersonation to override"
            ),
            Self::CriticalService(val) => write!(
                f,
                "label '{val}' impersonates a critical system service; pass --allow-impersonation to override"
            ),
        }
    }
}

impl std::error::Error for LabelPolicyError {}

/// Validate `label` and `comm` against the label impersonation policy.
///
/// Rejects kernel-thread bracket syntax (`[...]`) and critical system service
/// names unless `allow_impersonation` is `true`.
pub fn check_label_policy(
    label: Option<&str>,
    comm: Option<&str>,
    allow_impersonation: bool,
) -> Result<(), LabelPolicyError> {
    if allow_impersonation {
        return Ok(());
    }
    if let Some(l) = label {
        check_single_label(l)?;
    }
    if let Some(c) = comm {
        check_single_label(c)?;
    }
    Ok(())
}

fn check_single_label(raw: &str) -> Result<(), LabelPolicyError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
        return Err(LabelPolicyError::KernelThread(trimmed.to_string()));
    }
    let first_token = trimmed.split_whitespace().next().unwrap_or(trimmed);
    let stripped = first_token.trim_end_matches(':');
    let basename = Path::new(stripped)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(stripped);
    let lower = basename.to_ascii_lowercase();
    if CRITICAL_SERVICES.contains(&lower.as_str()) {
        return Err(LabelPolicyError::CriticalService(trimmed.to_string()));
    }
    Ok(())
}

/// Which observer perspective an audit run represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserverRole {
    /// Observer shares the target process's uid (primary scored observer).
    SameUid,
    /// Observer runs as a different unprivileged uid.
    OtherUid,
}

impl ObserverRole {
    /// Parse an observer role (`same-uid` or `other-uid`).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "same-uid" | "same_uid" | "same" => Some(Self::SameUid),
            "other-uid" | "other_uid" | "other" => Some(Self::OtherUid),
            _ => None,
        }
    }

    /// Canonical string representation of the observer role.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SameUid => "same-uid",
            Self::OtherUid => "other-uid",
        }
    }
}

impl fmt::Display for ObserverRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Inputs configuring a live `/proc/<pid>` audit.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// Target process id to inspect.
    pub pid: libc::pid_t,
    /// Profile whose invariants are evaluated.
    pub profile: Profile,
    /// Observer role (`same-uid` or `other-uid`).
    pub observer: ObserverRole,
    /// Expected presentation label, if any.
    pub label: Option<String>,
    /// Optional secret token to hunt across `/proc` and `/proc/<pid>/mem`.
    /// Zeroized on drop and never emitted verbatim.
    pub token: Option<Vec<u8>>,
    /// Real executable path to verify is hidden in `exe`, `maps`, `auxv`, and `fd`.
    pub real_exe: Option<String>,
    /// Real working directory to verify is hidden in `cwd`.
    pub real_cwd: Option<String>,
    /// Allow `/memfd:` paths in [`Profile::Single`] without failing `INV-4`.
    pub allow_memfd: bool,
    /// Baseline `Seccomp_filters` count for the host/container. When `None`,
    /// read from `/proc/self/status` so container-imposed filters do not
    /// trigger false positives.
    pub baseline_seccomp_filters: Option<u32>,
}

impl AuditOptions {
    /// Construct default options for auditing `pid` under `profile`.
    pub fn new(pid: libc::pid_t, profile: Profile) -> Self {
        Self {
            pid,
            profile,
            observer: ObserverRole::SameUid,
            label: None,
            token: None,
            real_exe: None,
            real_cwd: None,
            allow_memfd: false,
            baseline_seccomp_filters: None,
        }
    }
}

impl Drop for AuditOptions {
    fn drop(&mut self) {
        if let Some(ref mut tok) = self.token {
            tok.zeroize();
        }
    }
}

/// Access outcome for a `/proc/<pid>` file or symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessStatus {
    /// Surface was read successfully.
    Readable,
    /// Read failed with `EACCES` or `EPERM`.
    DeniedEacces,
    /// Read failed with another OS error (for example `ENOENT` or `ESRCH`).
    Error,
}

impl AccessStatus {
    /// Wire representation used in JSON and text reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Readable => "readable",
            Self::DeniedEacces => "denied_eacces",
            Self::Error => "error",
        }
    }
}

/// Outcome of the full-VMA `/proc/<pid>/mem` scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemScanStatus {
    /// Scan completed and found no token match.
    Clean,
    /// Token was found inside at least one readable mapping.
    Leaked,
    /// `/proc/<pid>/mem` or `/proc/<pid>/maps` denied access (`EACCES`/`EPERM`).
    DeniedEacces,
    /// No token was provided so memory content scanning was skipped.
    SkippedNoToken,
}

impl MemScanStatus {
    /// Wire representation used in JSON and text reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Leaked => "leaked",
            Self::DeniedEacces => "denied_eacces",
            Self::SkippedNoToken => "skipped_no_token",
        }
    }
}

/// Probed `/proc/<pid>/cmdline` surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdlineSurface {
    pub status: AccessStatus,
    pub raw_len: usize,
    pub nul_count: usize,
    pub trailing_nuls: usize,
    pub has_token: bool,
    pub has_label: bool,
    pub has_real_exe: bool,
    /// Sanitized argv entries (never containing the raw token).
    pub argv: Vec<String>,
}

/// Probed `/proc/<pid>/comm` surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommSurface {
    pub status: AccessStatus,
    /// Sanitized `comm` value (never containing the raw token).
    pub value: Option<String>,
    pub matches_label: Option<bool>,
    pub has_token: bool,
}

/// Probed `/proc/<pid>/environ` surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironSurface {
    pub status: AccessStatus,
    pub var_count: usize,
    pub has_token: bool,
    pub has_real_exe: bool,
}

/// Probed `/proc/<pid>/auxv` surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuxvSurface {
    pub status: AccessStatus,
    pub at_execfn: Option<u64>,
    /// Sanitized `AT_EXECFN` string dereferenced from `/proc/<pid>/mem` if readable.
    pub at_execfn_str: Option<String>,
    /// Whether dereferencing `AT_EXECFN` from `/proc/<pid>/mem` succeeded.
    pub at_execfn_readable: Option<bool>,
    /// True when reading `AT_EXECFN` from `/proc/<pid>/mem` failed with `EIO`.
    pub execfn_io_error: bool,
    /// Sanitized `AT_PLATFORM` string dereferenced from `/proc/<pid>/mem` if readable.
    pub at_platform: Option<String>,
    pub at_random: Option<u64>,
    pub at_base: Option<u64>,
    pub at_entry: Option<u64>,
    pub has_token: bool,
    pub has_real_exe: bool,
    pub has_memfd: bool,
}

/// Probed `/proc/<pid>/exe` surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExeSurface {
    pub status: AccessStatus,
    /// Sanitized symlink target (never containing the raw token).
    pub path: Option<String>,
    pub is_real: bool,
    pub is_memfd: bool,
    pub has_token: bool,
}

/// Probed `/proc/<pid>/maps` and `/proc/<pid>/smaps` surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapsSurface {
    pub status: AccessStatus,
    pub smaps_status: AccessStatus,
    pub vma_count: usize,
    pub has_real_exe: bool,
    pub has_memfd: bool,
    pub anon_rx_count: usize,
    pub has_token: bool,
    pub smaps_has_real_exe: bool,
    pub smaps_has_memfd: bool,
    pub smaps_has_token: bool,
}

/// Probed `/proc/<pid>/mem` full-VMA scan surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemSurface {
    pub status: MemScanStatus,
    pub vmas_scanned: usize,
    pub bytes_scanned: usize,
    /// Name of the mapping where the token was found (never the token itself).
    pub leaked_mapping: Option<String>,
}

/// Probed `/proc/<pid>/fd` and `/proc/<pid>/fdinfo` surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdSurface {
    pub status: AccessStatus,
    pub fdinfo_status: AccessStatus,
    pub count: usize,
    pub has_real_exe: bool,
    pub has_memfd: bool,
    pub has_token: bool,
}

/// Probed `/proc/<pid>/cwd` and `/proc/<pid>/root` surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathLinkSurface {
    pub status: AccessStatus,
    /// Sanitized path (never containing the raw token).
    pub path: Option<String>,
    pub is_real_cwd: bool,
    pub has_token: bool,
}

/// Probed `/proc/<pid>/status` surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSurface {
    pub status: AccessStatus,
    pub name: Option<String>,
    pub ppid: libc::pid_t,
    pub tracer_pid: libc::pid_t,
    pub threads: u32,
    pub no_new_privs: u32,
    pub seccomp: u32,
    pub seccomp_filters: u32,
    pub uid: Option<u32>,
    pub euid: Option<u32>,
    pub vm_data_kb: Option<u64>,
    pub has_token: bool,
}

/// Probed `/proc/<pid>/stat` surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatSurface {
    pub status: AccessStatus,
    pub ppid: libc::pid_t,
    pub num_threads: u32,
    pub starttime: u64,
    pub arg_start: u64,
    pub arg_end: u64,
    pub env_start: u64,
    pub env_end: u64,
    pub arg_span_mismatch: bool,
    pub arg_span_hidden: bool,
}

/// Probed `/proc/<pid>/statm` surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatmSurface {
    pub status: AccessStatus,
    pub rss_pages: u64,
    pub rss_kb: u64,
}

/// Probed `/proc/<pid>/task/*` surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSurface {
    pub status: AccessStatus,
    pub thread_count: usize,
    pub all_match_label: Option<bool>,
}

/// Probed `/proc/<pid>/limits` core-dump surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitsSurface {
    pub status: AccessStatus,
    pub core_limit_zero: Option<bool>,
}

/// Auxiliary process metadata surfaces (`wchan`, `syscall`, `cgroup`, `ns`, `mountinfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiscSurfaces {
    pub wchan: Option<String>,
    pub syscall: Option<String>,
    pub cgroup: Option<String>,
    pub ns_pid: Option<String>,
    pub ns_mnt: Option<String>,
    pub ns_user: Option<String>,
    pub mountinfo_private_tell: bool,
    pub userns_owner_read_bypass: bool,
    pub children_count: usize,
    pub parent_is_twin: bool,
}

/// Complete snapshot of all probed `/proc/<pid>` surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSnapshot {
    pub pid: libc::pid_t,
    pub observer_uid: u32,
    pub target_uid: Option<u32>,
    pub baseline_seccomp_filters: u32,
    pub baseline_no_new_privs: u32,
    pub dumpable_zero: Option<bool>,
    pub cmdline: CmdlineSurface,
    pub comm: CommSurface,
    pub environ: EnvironSurface,
    pub auxv: AuxvSurface,
    pub exe: ExeSurface,
    pub maps: MapsSurface,
    pub mem: MemSurface,
    pub fd: FdSurface,
    pub cwd: PathLinkSurface,
    pub root: PathLinkSurface,
    pub status: StatusSurface,
    pub stat: StatSurface,
    pub statm: StatmSurface,
    pub limits: LimitsSurface,
    pub task: TaskSurface,
    pub misc: MiscSurfaces,
}

/// Result of evaluating a single security invariant (`INV-1`..`INV-10`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantResult {
    pub id: &'static str,
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// Declared residual risk or observable tradeoff left by the active profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Residual {
    pub code: &'static str,
    pub detail: String,
}

/// Complete audit result produced by [`audit_pid`] or [`evaluate_snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    pub schema: &'static str,
    pub profile: Profile,
    pub profile_version: u32,
    pub observer: ObserverRole,
    pub observer_uid: u32,
    pub target_uid: Option<u32>,
    pub pid: libc::pid_t,
    pub label: Option<String>,
    pub denied_surfaces: usize,
    pub seccomp_delta: u32,
    pub no_new_privs_delta: u32,
    pub auxv_execfn_readable: Option<bool>,
    pub execfn_io_error: bool,
    pub token_present: bool,
    pub token_sha256: Option<String>,
    pub surfaces: ProcSnapshot,
    pub invariants: Vec<InvariantResult>,
    pub residuals: Vec<Residual>,
}

impl AuditReport {
    /// Returns `true` iff every invariant (`INV-1`..`INV-10`) passed.
    pub fn passed(&self) -> bool {
        !self.invariants.is_empty() && self.invariants.iter().all(|inv| inv.passed)
    }

    /// Serialize this report as deterministic `pmask-audit/1` JSON.
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(4096);
        let s = &self.surfaces;
        let _ = writeln!(out, "{{");
        let _ = writeln!(out, "  \"schema\": \"{}\",", json_escape(self.schema));
        let _ = writeln!(out, "  \"profile\": \"{}\",", self.profile.as_str());
        let _ = writeln!(out, "  \"profile_version\": {},", self.profile_version);
        let _ = writeln!(out, "  \"observer\": \"{}\",", self.observer.as_str());
        let _ = writeln!(out, "  \"observer_uid\": {},", self.observer_uid);
        let _ = writeln!(out, "  \"target_uid\": {},", opt_u32_json(self.target_uid));
        let _ = writeln!(out, "  \"pid\": {},", self.pid);
        let _ = writeln!(out, "  \"label\": {},", opt_str_json(self.label.as_deref()));
        let _ = writeln!(out, "  \"passed\": {},", bool_json(self.passed()));
        let _ = writeln!(out, "  \"denied_surfaces\": {},", self.denied_surfaces);
        let _ = writeln!(out, "  \"seccomp_delta\": {},", self.seccomp_delta);
        let _ = writeln!(
            out,
            "  \"no_new_privs_delta\": {},",
            self.no_new_privs_delta
        );
        let _ = writeln!(
            out,
            "  \"auxv_execfn_readable\": {},",
            opt_bool_json(self.auxv_execfn_readable)
        );
        let _ = writeln!(
            out,
            "  \"execfn_io_error\": {},",
            bool_json(self.execfn_io_error)
        );
        let _ = writeln!(out, "  \"safety\": {{");
        let _ = writeln!(
            out,
            "    \"token_present\": {},",
            bool_json(self.token_present)
        );
        let _ = writeln!(
            out,
            "    \"token_sha256\": {}",
            opt_str_json(self.token_sha256.as_deref())
        );
        let _ = writeln!(out, "  }},");

        let _ = writeln!(out, "  \"surfaces\": {{");
        let _ = writeln!(
            out,
            "    \"cmdline\": {{\"status\": \"{}\", \"raw_len\": {}, \"nul_count\": {}, \"trailing_nuls\": {}, \"has_token\": {}, \"has_label\": {}, \"has_real_exe\": {}, \"argv\": {}}},",
            s.cmdline.status.as_str(),
            s.cmdline.raw_len,
            s.cmdline.nul_count,
            s.cmdline.trailing_nuls,
            bool_json(s.cmdline.has_token),
            bool_json(s.cmdline.has_label),
            bool_json(s.cmdline.has_real_exe),
            str_vec_json(&s.cmdline.argv)
        );
        let _ = writeln!(
            out,
            "    \"comm\": {{\"status\": \"{}\", \"value\": {}, \"matches_label\": {}, \"has_token\": {}}},",
            s.comm.status.as_str(),
            opt_str_json(s.comm.value.as_deref()),
            opt_bool_json(s.comm.matches_label),
            bool_json(s.comm.has_token)
        );
        let _ = writeln!(
            out,
            "    \"environ\": {{\"status\": \"{}\", \"var_count\": {}, \"has_token\": {}, \"has_real_exe\": {}}},",
            s.environ.status.as_str(),
            s.environ.var_count,
            bool_json(s.environ.has_token),
            bool_json(s.environ.has_real_exe)
        );
        let _ = writeln!(
            out,
            "    \"auxv\": {{\"status\": \"{}\", \"at_execfn\": {}, \"at_execfn_str\": {}, \"at_execfn_readable\": {}, \"execfn_io_error\": {}, \"at_platform\": {}, \"at_random\": {}, \"at_base\": {}, \"at_entry\": {}, \"has_token\": {}, \"has_real_exe\": {}, \"has_memfd\": {}}},",
            s.auxv.status.as_str(),
            opt_u64_json(s.auxv.at_execfn),
            opt_str_json(s.auxv.at_execfn_str.as_deref()),
            opt_bool_json(s.auxv.at_execfn_readable),
            bool_json(s.auxv.execfn_io_error),
            opt_str_json(s.auxv.at_platform.as_deref()),
            opt_u64_json(s.auxv.at_random),
            opt_u64_json(s.auxv.at_base),
            opt_u64_json(s.auxv.at_entry),
            bool_json(s.auxv.has_token),
            bool_json(s.auxv.has_real_exe),
            bool_json(s.auxv.has_memfd)
        );
        let _ = writeln!(
            out,
            "    \"exe\": {{\"status\": \"{}\", \"path\": {}, \"is_real\": {}, \"is_memfd\": {}, \"has_token\": {}}},",
            s.exe.status.as_str(),
            opt_str_json(s.exe.path.as_deref()),
            bool_json(s.exe.is_real),
            bool_json(s.exe.is_memfd),
            bool_json(s.exe.has_token)
        );
        let _ = writeln!(
            out,
            "    \"maps\": {{\"status\": \"{}\", \"smaps_status\": \"{}\", \"vma_count\": {}, \"has_real_exe\": {}, \"has_memfd\": {}, \"anon_rx_count\": {}, \"has_token\": {}}},",
            s.maps.status.as_str(),
            s.maps.smaps_status.as_str(),
            s.maps.vma_count,
            bool_json(s.maps.has_real_exe || s.maps.smaps_has_real_exe),
            bool_json(s.maps.has_memfd || s.maps.smaps_has_memfd),
            s.maps.anon_rx_count,
            bool_json(s.maps.has_token || s.maps.smaps_has_token)
        );
        let _ = writeln!(
            out,
            "    \"mem\": {{\"status\": \"{}\", \"vmas_scanned\": {}, \"bytes_scanned\": {}, \"leaked_mapping\": {}}},",
            s.mem.status.as_str(),
            s.mem.vmas_scanned,
            s.mem.bytes_scanned,
            opt_str_json(s.mem.leaked_mapping.as_deref())
        );
        let _ = writeln!(
            out,
            "    \"fd\": {{\"status\": \"{}\", \"fdinfo_status\": \"{}\", \"count\": {}, \"has_real_exe\": {}, \"has_memfd\": {}, \"has_token\": {}}},",
            s.fd.status.as_str(),
            s.fd.fdinfo_status.as_str(),
            s.fd.count,
            bool_json(s.fd.has_real_exe),
            bool_json(s.fd.has_memfd),
            bool_json(s.fd.has_token)
        );
        let _ = writeln!(
            out,
            "    \"cwd\": {{\"status\": \"{}\", \"path\": {}, \"is_real_cwd\": {}, \"has_token\": {}}},",
            s.cwd.status.as_str(),
            opt_str_json(s.cwd.path.as_deref()),
            bool_json(s.cwd.is_real_cwd),
            bool_json(s.cwd.has_token)
        );
        let _ = writeln!(
            out,
            "    \"root\": {{\"status\": \"{}\", \"path\": {}}},",
            s.root.status.as_str(),
            opt_str_json(s.root.path.as_deref())
        );
        let _ = writeln!(
            out,
            "    \"status\": {{\"status\": \"{}\", \"name\": {}, \"ppid\": {}, \"tracer_pid\": {}, \"threads\": {}, \"no_new_privs\": {}, \"seccomp\": {}, \"seccomp_filters\": {}, \"uid\": {}, \"euid\": {}, \"vm_data_kb\": {}, \"has_token\": {}}},",
            s.status.status.as_str(),
            opt_str_json(s.status.name.as_deref()),
            s.status.ppid,
            s.status.tracer_pid,
            s.status.threads,
            s.status.no_new_privs,
            s.status.seccomp,
            s.status.seccomp_filters,
            opt_u32_json(s.status.uid),
            opt_u32_json(s.status.euid),
            opt_u64_json(s.status.vm_data_kb),
            bool_json(s.status.has_token)
        );
        let _ = writeln!(
            out,
            "    \"stat\": {{\"status\": \"{}\", \"ppid\": {}, \"num_threads\": {}, \"starttime\": {}, \"arg_start\": {}, \"arg_end\": {}, \"env_start\": {}, \"env_end\": {}, \"arg_span_mismatch\": {}, \"arg_span_hidden\": {}}},",
            s.stat.status.as_str(),
            s.stat.ppid,
            s.stat.num_threads,
            s.stat.starttime,
            s.stat.arg_start,
            s.stat.arg_end,
            s.stat.env_start,
            s.stat.env_end,
            bool_json(s.stat.arg_span_mismatch),
            bool_json(s.stat.arg_span_hidden)
        );
        let _ = writeln!(
            out,
            "    \"statm\": {{\"status\": \"{}\", \"rss_pages\": {}, \"rss_kb\": {}}},",
            s.statm.status.as_str(),
            s.statm.rss_pages,
            s.statm.rss_kb
        );
        let _ = writeln!(
            out,
            "    \"limits\": {{\"status\": \"{}\", \"core_limit_zero\": {}}},",
            s.limits.status.as_str(),
            opt_bool_json(s.limits.core_limit_zero)
        );
        let _ = writeln!(
            out,
            "    \"task\": {{\"status\": \"{}\", \"thread_count\": {}, \"all_match_label\": {}}},",
            s.task.status.as_str(),
            s.task.thread_count,
            opt_bool_json(s.task.all_match_label)
        );
        let _ = writeln!(
            out,
            "    \"misc\": {{\"wchan\": {}, \"syscall\": {}, \"cgroup\": {}, \"ns_pid\": {}, \"ns_mnt\": {}, \"ns_user\": {}, \"mountinfo_private_tell\": {}, \"userns_owner_read_bypass\": {}, \"children_count\": {}, \"parent_is_twin\": {}}}",
            opt_str_json(s.misc.wchan.as_deref()),
            opt_str_json(s.misc.syscall.as_deref()),
            opt_str_json(s.misc.cgroup.as_deref()),
            opt_str_json(s.misc.ns_pid.as_deref()),
            opt_str_json(s.misc.ns_mnt.as_deref()),
            opt_str_json(s.misc.ns_user.as_deref()),
            bool_json(s.misc.mountinfo_private_tell),
            bool_json(s.misc.userns_owner_read_bypass),
            s.misc.children_count,
            bool_json(s.misc.parent_is_twin)
        );
        let _ = writeln!(out, "  }},");

        let _ = writeln!(out, "  \"invariants\": [");
        for (i, inv) in self.invariants.iter().enumerate() {
            let comma = if i + 1 < self.invariants.len() {
                ","
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "    {{\"id\": \"{}\", \"name\": \"{}\", \"passed\": {}, \"detail\": \"{}\"}}{}",
                json_escape(inv.id),
                json_escape(inv.name),
                bool_json(inv.passed),
                json_escape(&inv.detail),
                comma
            );
        }
        let _ = writeln!(out, "  ],");

        let _ = writeln!(out, "  \"residuals\": [");
        for (i, res) in self.residuals.iter().enumerate() {
            let comma = if i + 1 < self.residuals.len() {
                ","
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "    {{\"code\": \"{}\", \"detail\": \"{}\"}}{}",
                json_escape(res.code),
                json_escape(&res.detail),
                comma
            );
        }
        let _ = writeln!(out, "  ]");
        let _ = writeln!(out, "}}");
        out
    }

    /// Render a concise, human-readable audit table.
    pub fn to_text(&self) -> String {
        let mut out = String::with_capacity(2048);
        let verdict = if self.passed() { "PASS" } else { "FAIL" };
        let _ = writeln!(
            out,
            "pmask audit ({}, profile={} v{}, observer={}, pid={}, verdict={})",
            self.schema,
            self.profile.as_str(),
            self.profile_version,
            self.observer.as_str(),
            self.pid,
            verdict
        );
        let _ = writeln!(
            out,
            "  observer_uid={} target_uid={} label={} token_present={}",
            self.observer_uid,
            self.target_uid
                .map(|u| u.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            self.label.as_deref().unwrap_or("<none>"),
            self.token_present
        );
        if let Some(ref h) = self.token_sha256 {
            let _ = writeln!(out, "  token_sha256={h}");
        }

        let s = &self.surfaces;
        let _ = writeln!(out, "\nSurfaces:");
        let _ = writeln!(
            out,
            "  {:<12} {:<16} raw_len={} trailing_nuls={} token={} label={} real={}",
            "cmdline",
            s.cmdline.status.as_str(),
            s.cmdline.raw_len,
            s.cmdline.trailing_nuls,
            s.cmdline.has_token,
            s.cmdline.has_label,
            s.cmdline.has_real_exe
        );
        let _ = writeln!(
            out,
            "  {:<12} {:<16} value={} matches_label={} token={}",
            "comm",
            s.comm.status.as_str(),
            s.comm.value.as_deref().unwrap_or("<none>"),
            s.comm
                .matches_label
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            s.comm.has_token
        );
        let _ = writeln!(
            out,
            "  {:<12} {:<16} vars={} token={} real={}",
            "environ",
            s.environ.status.as_str(),
            s.environ.var_count,
            s.environ.has_token,
            s.environ.has_real_exe
        );
        let _ = writeln!(
            out,
            "  {:<12} {:<16} execfn={} token={} real={} memfd={}",
            "auxv",
            s.auxv.status.as_str(),
            s.auxv.at_execfn_str.as_deref().unwrap_or("<none>"),
            s.auxv.has_token,
            s.auxv.has_real_exe,
            s.auxv.has_memfd
        );
        let _ = writeln!(
            out,
            "  {:<12} {:<16} real={} memfd={} token={}",
            "exe",
            s.exe.status.as_str(),
            s.exe.is_real,
            s.exe.is_memfd,
            s.exe.has_token
        );
        let _ = writeln!(
            out,
            "  {:<12} {:<16} vmas={} anon_rx={} real={} memfd={} token={}",
            "maps",
            s.maps.status.as_str(),
            s.maps.vma_count,
            s.maps.anon_rx_count,
            s.maps.has_real_exe || s.maps.smaps_has_real_exe,
            s.maps.has_memfd || s.maps.smaps_has_memfd,
            s.maps.has_token || s.maps.smaps_has_token
        );
        let _ = writeln!(
            out,
            "  {:<12} {:<16} vmas={} bytes={} leaked_in={}",
            "mem",
            s.mem.status.as_str(),
            s.mem.vmas_scanned,
            s.mem.bytes_scanned,
            s.mem.leaked_mapping.as_deref().unwrap_or("<none>")
        );
        let _ = writeln!(
            out,
            "  {:<12} {:<16} count={} real={} memfd={} token={}",
            "fd",
            s.fd.status.as_str(),
            s.fd.count,
            s.fd.has_real_exe,
            s.fd.has_memfd,
            s.fd.has_token
        );
        let _ = writeln!(
            out,
            "  {:<12} {:<16} is_real_cwd={} token={}",
            "cwd",
            s.cwd.status.as_str(),
            s.cwd.is_real_cwd,
            s.cwd.has_token
        );
        let _ = writeln!(
            out,
            "  {:<12} {:<16} ppid={} tracer={} threads={} nnp={} seccomp_filters={} twin={}",
            "status",
            s.status.status.as_str(),
            s.status.ppid,
            s.status.tracer_pid,
            s.status.threads,
            s.status.no_new_privs,
            s.status.seccomp_filters,
            s.misc.parent_is_twin
        );
        let _ = writeln!(
            out,
            "  {:<12} {:<16} rss_kb={} span_mismatch={} span_hidden={} core_zero={}",
            "stat/limits",
            s.stat.status.as_str(),
            s.statm.rss_kb,
            s.stat.arg_span_mismatch,
            s.stat.arg_span_hidden,
            s.limits
                .core_limit_zero
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );

        let _ = writeln!(out, "\nInvariants:");
        for inv in &self.invariants {
            let tag = if inv.passed { "PASS" } else { "FAIL" };
            let _ = writeln!(
                out,
                "  {:<6} {:<4} {:<30} {}",
                inv.id, tag, inv.name, inv.detail
            );
        }

        let _ = writeln!(out, "\nResiduals:");
        for res in &self.residuals {
            let _ = writeln!(out, "  - {}: {}", res.code, res.detail);
        }
        out
    }
}

/// Wrapper holding token search variants that zeroizes every variant on drop.
struct SecretNeedles {
    variants: Vec<Vec<u8>>,
}

impl SecretNeedles {
    fn from_opt(token: Option<&[u8]>) -> Self {
        let Some(tok) = token else {
            return Self {
                variants: Vec::new(),
            };
        };
        if tok.is_empty() {
            return Self {
                variants: Vec::new(),
            };
        }
        let mut variants = Vec::with_capacity(4);
        variants.push(tok.to_vec());

        // Percent-encoded (uppercase and lowercase hex) if different from raw.
        let pct_upper = percent_encode(tok, true);
        if pct_upper != tok {
            variants.push(pct_upper);
        }
        let pct_lower = percent_encode(tok, false);
        if pct_lower != tok && !variants.contains(&pct_lower) {
            variants.push(pct_lower);
        }

        // Simple POSIX shell backslash-escaped form if different from raw.
        let shell_esc = shell_backslash_escape(tok);
        if shell_esc != tok && !variants.contains(&shell_esc) {
            variants.push(shell_esc);
        }

        Self { variants }
    }

    fn is_empty(&self) -> bool {
        self.variants.is_empty()
    }

    fn max_len(&self) -> usize {
        self.variants.iter().map(Vec::len).max().unwrap_or(0)
    }

    fn matches_bytes(&self, hay: &[u8]) -> bool {
        if self.variants.is_empty() || hay.is_empty() {
            return false;
        }
        self.variants
            .iter()
            .any(|needle| contains_subslice(hay, needle))
    }

    fn matches_str(&self, hay: &str) -> bool {
        self.matches_bytes(hay.as_bytes())
    }

    /// Replace any occurrence of any secret variant in `s` with `[REDACTED]`
    /// so raw secret bytes can never escape into reports or profile exports.
    fn scrub_string(&self, s: &str) -> String {
        if !self.matches_str(s) {
            return s.to_string();
        }
        let mut out = s.to_string();
        for needle in &self.variants {
            if let Ok(ns) = std::str::from_utf8(needle) {
                if !ns.is_empty() {
                    out = out.replace(ns, "[REDACTED]");
                }
            }
        }
        if self.matches_str(&out) {
            "[REDACTED]".to_string()
        } else {
            out
        }
    }
}

impl Drop for SecretNeedles {
    fn drop(&mut self) {
        for v in &mut self.variants {
            v.zeroize();
        }
    }
}

fn percent_encode(bytes: &[u8], uppercase: bool) -> Vec<u8> {
    const HEX_UP: &[u8; 16] = b"0123456789ABCDEF";
    const HEX_LO: &[u8; 16] = b"0123456789abcdef";
    let hex = if uppercase { HEX_UP } else { HEX_LO };
    let mut out = Vec::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(hex[(b >> 4) as usize]);
            out.push(hex[(b & 0x0f) as usize]);
        }
    }
    out
}

fn shell_backslash_escape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for &b in bytes {
        if matches!(
            b,
            b' ' | b'\t'
                | b'\''
                | b'"'
                | b'\\'
                | b'$'
                | b'`'
                | b'&'
                | b'|'
                | b';'
                | b'<'
                | b'>'
                | b'('
                | b')'
                | b'*'
                | b'?'
                | b'['
                | b']'
                | b'!'
        ) {
            out.push(b'\\');
        }
        out.push(b);
    }
    out
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Probe a live process at `/proc/<pid>` and evaluate all invariants for
/// `opts.profile`.
pub fn audit_pid(opts: &AuditOptions) -> io::Result<AuditReport> {
    if opts.pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pid must be a positive integer",
        ));
    }
    let proc_dir = format!("/proc/{}", opts.pid);
    if !Path::new(&proc_dir).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("process {} not found in /proc", opts.pid),
        ));
    }

    let needles = SecretNeedles::from_opt(opts.token.as_deref());
    let snap = probe_proc_snapshot(opts, &needles);
    Ok(evaluate_invariants(snap, opts, &needles))
}

/// Evaluate invariants `INV-1` through `INV-10` and build an [`AuditReport`]
/// from an already-collected [`ProcSnapshot`].
///
/// Separated from [`audit_pid`] so both live probes and deterministic unit
/// tests share the exact same invariant engine.
pub fn evaluate_snapshot(snap: ProcSnapshot, opts: &AuditOptions) -> AuditReport {
    let needles = SecretNeedles::from_opt(opts.token.as_deref());
    evaluate_invariants(snap, opts, &needles)
}

fn scrub_snapshot(snap: &mut ProcSnapshot, needles: &SecretNeedles) {
    if needles.is_empty() {
        return;
    }
    for arg in &mut snap.cmdline.argv {
        *arg = needles.scrub_string(arg);
    }
    if let Some(ref mut v) = snap.comm.value {
        *v = needles.scrub_string(v);
    }
    if let Some(ref mut v) = snap.auxv.at_execfn_str {
        *v = needles.scrub_string(v);
    }
    if let Some(ref mut v) = snap.exe.path {
        *v = needles.scrub_string(v);
    }
    if let Some(ref mut v) = snap.mem.leaked_mapping {
        *v = needles.scrub_string(v);
    }
    if let Some(ref mut v) = snap.cwd.path {
        *v = needles.scrub_string(v);
    }
    if let Some(ref mut v) = snap.root.path {
        *v = needles.scrub_string(v);
    }
    if let Some(ref mut v) = snap.status.name {
        *v = needles.scrub_string(v);
    }
}

fn evaluate_invariants(
    mut snap: ProcSnapshot,
    opts: &AuditOptions,
    needles: &SecretNeedles,
) -> AuditReport {
    scrub_snapshot(&mut snap, needles);

    let token_sha256 = opts
        .token
        .as_deref()
        .filter(|t| !t.is_empty())
        .map(sha256_hex);

    let token_in_surfaces = snap.cmdline.has_token
        || snap.comm.has_token
        || snap.environ.has_token
        || snap.auxv.has_token
        || snap.exe.has_token
        || snap.maps.has_token
        || snap.maps.smaps_has_token
        || snap.fd.has_token
        || snap.cwd.has_token
        || snap.status.has_token;

    let token_in_mem = snap.mem.status == MemScanStatus::Leaked;
    let token_present = token_in_surfaces || token_in_mem;

    // INV-1: No secret token in any /proc metadata surface.
    let inv1 = if token_in_surfaces {
        let mut leaked_in = Vec::new();
        if snap.cmdline.has_token {
            leaked_in.push("cmdline");
        }
        if snap.comm.has_token {
            leaked_in.push("comm");
        }
        if snap.environ.has_token {
            leaked_in.push("environ");
        }
        if snap.auxv.has_token {
            leaked_in.push("auxv");
        }
        if snap.exe.has_token {
            leaked_in.push("exe");
        }
        if snap.maps.has_token || snap.maps.smaps_has_token {
            leaked_in.push("maps");
        }
        if snap.fd.has_token {
            leaked_in.push("fd");
        }
        if snap.cwd.has_token {
            leaked_in.push("cwd");
        }
        if snap.status.has_token {
            leaked_in.push("status");
        }
        InvariantResult {
            id: "INV-1",
            name: "no_token_in_proc_surfaces",
            passed: false,
            detail: format!("secret token found in: {}", leaked_in.join(", ")),
        }
    } else if needles.is_empty() {
        InvariantResult {
            id: "INV-1",
            name: "no_token_in_proc_surfaces",
            passed: true,
            detail: "no token supplied for search".to_string(),
        }
    } else {
        InvariantResult {
            id: "INV-1",
            name: "no_token_in_proc_surfaces",
            passed: true,
            detail: "no token found in readable /proc metadata surfaces".to_string(),
        }
    };

    // INV-2: No secret token readable from full /proc/<pid>/mem scan.
    let inv2 = match snap.mem.status {
        MemScanStatus::Leaked => InvariantResult {
            id: "INV-2",
            name: "no_token_in_mem",
            passed: false,
            detail: format!(
                "secret token found in /proc/{}/mem mapping {}",
                snap.pid,
                snap.mem.leaked_mapping.as_deref().unwrap_or("<unknown>")
            ),
        },
        MemScanStatus::DeniedEacces => InvariantResult {
            id: "INV-2",
            name: "no_token_in_mem",
            passed: true,
            detail: "/proc/<pid>/mem denied with EACCES".to_string(),
        },
        MemScanStatus::Clean => InvariantResult {
            id: "INV-2",
            name: "no_token_in_mem",
            passed: true,
            detail: format!(
                "scanned {} bytes across {} VMAs; no token found",
                snap.mem.bytes_scanned, snap.mem.vmas_scanned
            ),
        },
        MemScanStatus::SkippedNoToken => InvariantResult {
            id: "INV-2",
            name: "no_token_in_mem",
            passed: true,
            detail: "no token supplied for memory scan".to_string(),
        },
    };

    // INV-3: comm and cmdline agree with label, trailing_nuls <= 2, no arg_span_mismatch.
    let mut inv3_issues = Vec::new();
    if let Some(ref lbl) = opts.label {
        if !lbl.is_empty() {
            if snap.comm.status != AccessStatus::Readable || snap.comm.matches_label != Some(true) {
                inv3_issues.push("comm does not match expected label");
            }
            if snap.cmdline.status != AccessStatus::Readable || !snap.cmdline.has_label {
                inv3_issues.push("cmdline does not contain expected label");
            }
            if snap.task.all_match_label == Some(false) {
                inv3_issues.push("one or more threads in /proc/<pid>/task disagree with label");
            }
        }
    }
    if snap.cmdline.status == AccessStatus::Readable && snap.cmdline.trailing_nuls > 2 {
        inv3_issues.push("cmdline has trailing NUL padding (> 2 NUL bytes)");
    }
    if snap.stat.arg_span_mismatch {
        inv3_issues.push("stat arg_start..arg_end span disagrees with cmdline");
    }
    let inv3 = InvariantResult {
        id: "INV-3",
        name: "label_and_cmdline_consistent",
        passed: inv3_issues.is_empty(),
        detail: if inv3_issues.is_empty() {
            "comm, cmdline, trailing NUL count, and arg span are consistent".to_string()
        } else {
            inv3_issues.join("; ")
        },
    };

    // INV-4: exe and maps do not point to real_exe; memfd flagged in single unless allow_memfd.
    let mut inv4_issues = Vec::new();
    if opts.real_exe.as_deref().is_some_and(|r| !r.is_empty()) {
        if snap.exe.is_real {
            inv4_issues.push("exe symlink points to real executable");
        }
        if snap.maps.has_real_exe || snap.maps.smaps_has_real_exe {
            inv4_issues.push("maps/smaps contain real executable path");
        }
        if snap.auxv.has_real_exe {
            inv4_issues.push("auxv AT_EXECFN contains real executable path");
        }
        if snap.fd.has_real_exe {
            inv4_issues.push("fd table references real executable path");
        }
    }
    if !opts.allow_memfd
        && opts.profile == Profile::Single
        && (snap.exe.is_memfd
            || snap.maps.has_memfd
            || snap.maps.smaps_has_memfd
            || snap.auxv.has_memfd)
    {
        inv4_issues.push("/memfd: executable fingerprint visible in single profile");
    }
    let inv4 = InvariantResult {
        id: "INV-4",
        name: "exe_and_maps_hidden",
        passed: inv4_issues.is_empty(),
        detail: if inv4_issues.is_empty() {
            "exe and maps do not expose real executable path".to_string()
        } else {
            inv4_issues.join("; ")
        },
    };

    // INV-5: Profile::Single must have no TracerPid, no extra Seccomp_filters,
    // no extra NoNewPrivs, and no supervisor twin pair.
    let mut inv5_issues = Vec::new();
    if opts.profile == Profile::Single {
        if snap.status.tracer_pid != 0 {
            inv5_issues.push(format!(
                "TracerPid is {} (expected 0)",
                snap.status.tracer_pid
            ));
        }
        if snap.status.seccomp_filters > snap.baseline_seccomp_filters {
            inv5_issues.push(format!(
                "Seccomp_filters is {} (exceeds baseline {})",
                snap.status.seccomp_filters, snap.baseline_seccomp_filters
            ));
        }
        if snap.status.no_new_privs > snap.baseline_no_new_privs {
            inv5_issues.push(format!(
                "NoNewPrivs is {} (exceeds baseline {})",
                snap.status.no_new_privs, snap.baseline_no_new_privs
            ));
        }
        if snap.misc.parent_is_twin {
            inv5_issues.push("supervisor/payload twin pair detected in single profile".to_string());
        }
    }
    let inv5 = InvariantResult {
        id: "INV-5",
        name: "no_mask_fingerprint",
        passed: inv5_issues.is_empty(),
        detail: if inv5_issues.is_empty() {
            if opts.profile == Profile::Single {
                "no TracerPid, extra Seccomp_filters, extra NoNewPrivs, or twin supervisor"
                    .to_string()
            } else {
                format!(
                    "profile '{}' permits declared supervisor/tracing residuals",
                    opts.profile.as_str()
                )
            }
        } else {
            inv5_issues.join("; ")
        },
    };

    // INV-6: Process shape recorded and cwd is not real_cwd.
    let mut inv6_issues = Vec::new();
    if snap.status.status != AccessStatus::Readable || snap.stat.status != AccessStatus::Readable {
        inv6_issues.push("could not read status/stat process shape");
    }
    if opts.real_cwd.as_deref().is_some_and(|c| !c.is_empty()) && snap.cwd.is_real_cwd {
        inv6_issues.push("cwd exposes real working directory");
    }
    let inv6 = InvariantResult {
        id: "INV-6",
        name: "process_shape_and_cwd",
        passed: inv6_issues.is_empty(),
        detail: if inv6_issues.is_empty() {
            format!(
                "ppid={} threads={} fd_count={} rss_kb={} starttime={}",
                snap.status.ppid,
                snap.status.threads,
                snap.fd.count,
                snap.statm.rss_kb,
                snap.stat.starttime
            )
        } else {
            inv6_issues.join("; ")
        },
    };

    // INV-7: Core-dump hygiene (dumpable == 0 or RLIMIT_CORE == 0).
    let inv7 = if snap.dumpable_zero == Some(true) || snap.limits.core_limit_zero == Some(true) {
        InvariantResult {
            id: "INV-7",
            name: "core_dump_hygiene",
            passed: true,
            detail: format!(
                "dumpable_zero={}, core_limit_zero={}",
                fmt_opt_yes_no(snap.dumpable_zero),
                fmt_opt_yes_no(snap.limits.core_limit_zero)
            ),
        }
    } else if opts.observer == ObserverRole::OtherUid
        && snap.limits.status == AccessStatus::DeniedEacces
    {
        InvariantResult {
            id: "INV-7",
            name: "core_dump_hygiene",
            passed: true,
            detail: "limits denied to other-uid observer".to_string(),
        }
    } else {
        InvariantResult {
            id: "INV-7",
            name: "core_dump_hygiene",
            passed: false,
            detail: "process appears dumpable and RLIMIT_CORE is not 0".to_string(),
        }
    };

    // INV-8: Exported profile.json matches native psgen schema: 2 and contains zero secret bytes.
    let exported = format_profile_json_from_snapshot(
        &snap,
        opts.profile,
        opts.label.as_deref(),
        token_present,
        token_sha256.as_deref(),
        opts.token.as_deref(),
        needles,
    );
    let schema_ok = exported.contains(&format!("\"schema\": {PROFILE_SCHEMA_VERSION},"));
    let secret_free =
        !needles.matches_str(&exported) && !contains_unredacted_secret_pattern(&exported);
    let inv8 = InvariantResult {
        id: "INV-8",
        name: "profile_export_clean",
        passed: schema_ok && secret_free,
        detail: if schema_ok && secret_free {
            format!(
                "exported psgen schema: {PROFILE_SCHEMA_VERSION} JSON contains zero secret bytes"
            )
        } else if !secret_free {
            "exported profile.json contained secret bytes or unredacted secret pattern".to_string()
        } else {
            "exported profile.json missing required schema: 2 field".to_string()
        },
    };

    // INV-9: Target was actively probed and machine-verifiable verdict is enforced.
    let probed_ok = snap.status.status == AccessStatus::Readable
        || snap.cmdline.status == AccessStatus::Readable;
    let inv9 = InvariantResult {
        id: "INV-9",
        name: "audit_verdict_enforced",
        passed: probed_ok,
        detail: if probed_ok {
            "live target surfaces probed; exit code reflects invariant verdict".to_string()
        } else {
            "unable to probe target status or cmdline".to_string()
        },
    };

    // INV-10: Cross-uid non-amplification check.
    let inv10 = match opts.observer {
        ObserverRole::SameUid => InvariantResult {
            id: "INV-10",
            name: "cross_uid_non_amplification",
            passed: true,
            detail: "same-uid observation; run with --observer other-uid from another uid to verify cross-uid view".to_string(),
        },
        ObserverRole::OtherUid => {
            let different_unpriv_uid = snap.observer_uid != 0
                && snap.target_uid.is_some_and(|t| t != snap.observer_uid);
            let leaked_restricted = different_unpriv_uid
                && (snap.environ.status == AccessStatus::Readable
                    || snap.mem.status == MemScanStatus::Clean
                    || snap.mem.status == MemScanStatus::Leaked
                    || snap.auxv.status == AccessStatus::Readable);
            if token_present {
                InvariantResult {
                    id: "INV-10",
                    name: "cross_uid_non_amplification",
                    passed: false,
                    detail: "other-uid observer observed secret token".to_string(),
                }
            } else if leaked_restricted {
                InvariantResult {
                    id: "INV-10",
                    name: "cross_uid_non_amplification",
                    passed: false,
                    detail: "other-uid observer could read restricted /proc surfaces (environ/auxv/mem)".to_string(),
                }
            } else {
                InvariantResult {
                    id: "INV-10",
                    name: "cross_uid_non_amplification",
                    passed: true,
                    detail: "other-uid view does not leak restricted surfaces or tokens"
                        .to_string(),
                }
            }
        }
    };

    let invariants = vec![inv1, inv2, inv3, inv4, inv5, inv6, inv7, inv8, inv9, inv10];
    let residuals = collect_residuals(&snap, opts.observer);
    let denied_surfaces = count_denied_surfaces(&snap);
    let seccomp_delta = snap
        .status
        .seccomp_filters
        .saturating_sub(snap.baseline_seccomp_filters);
    let no_new_privs_delta = snap
        .status
        .no_new_privs
        .saturating_sub(snap.baseline_no_new_privs);
    let auxv_execfn_readable = snap.auxv.at_execfn_readable;
    let execfn_io_error = snap.auxv.execfn_io_error;

    AuditReport {
        schema: AUDIT_SCHEMA,
        profile: opts.profile,
        profile_version: PROFILE_VERSION,
        observer: opts.observer,
        observer_uid: snap.observer_uid,
        target_uid: snap.target_uid,
        pid: snap.pid,
        label: opts.label.clone(),
        denied_surfaces,
        seccomp_delta,
        no_new_privs_delta,
        auxv_execfn_readable,
        execfn_io_error,
        token_present,
        token_sha256,
        surfaces: snap,
        invariants,
        residuals,
    }
}

fn count_denied_surfaces(snap: &ProcSnapshot) -> usize {
    let mut n = 0usize;
    if snap.environ.status == AccessStatus::DeniedEacces {
        n += 1;
    }
    if snap.mem.status == MemScanStatus::DeniedEacces {
        n += 1;
    }
    if snap.auxv.status == AccessStatus::DeniedEacces {
        n += 1;
    }
    if snap.exe.status == AccessStatus::DeniedEacces {
        n += 1;
    }
    if snap.maps.status == AccessStatus::DeniedEacces {
        n += 1;
    }
    if snap.fd.status == AccessStatus::DeniedEacces {
        n += 1;
    }
    if snap.cwd.status == AccessStatus::DeniedEacces {
        n += 1;
    }
    n
}

fn collect_residuals(snap: &ProcSnapshot, observer: ObserverRole) -> Vec<Residual> {
    let mut residuals = Vec::new();
    let any_eacces = snap.environ.status == AccessStatus::DeniedEacces
        || snap.mem.status == MemScanStatus::DeniedEacces
        || snap.auxv.status == AccessStatus::DeniedEacces
        || snap.exe.status == AccessStatus::DeniedEacces
        || snap.maps.status == AccessStatus::DeniedEacces
        || snap.fd.status == AccessStatus::DeniedEacces
        || snap.cwd.status == AccessStatus::DeniedEacces;

    if any_eacces && observer == ObserverRole::SameUid {
        let detail = if snap.dumpable_zero == Some(false) {
            "yama.ptrace_scope denies same-uid ptrace/mem attach while the target remains dumpable (environ, exe, maps, auxv, fd, and cwd are readable)"
        } else {
            "PR_SET_DUMPABLE=0 causes same-uid /proc reads to fail with EACCES; use a helper uid or userns to remove the denial signal"
        };
        residuals.push(Residual {
            code: "eacces_denial",
            detail: detail.to_string(),
        });
    }
    if snap.misc.userns_owner_read_bypass && observer == ObserverRole::SameUid {
        residuals.push(Residual {
            code: "userns_owner_read_bypass",
            detail: "target runs in a child user namespace owned by the observer's uid; Linux cap_capable() grants the creator uid CAP_SYS_PTRACE over the child userns, leaving exe, maps, cwd, and stat fields 48-51 readable to same-uid observers even with PR_SET_DUMPABLE=0 (use a separate host uid via pmaskd or a microVM, or --profile single/tree to close them with EACCES)".to_string(),
        });
    }
    if snap.stat.arg_span_hidden {
        let detail = if observer == ObserverRole::OtherUid {
            "kernel zeroes /proc/<pid>/stat fields 48-51 (arg_start..env_end) for non-owner observers without ptrace access"
        } else if snap.dumpable_zero == Some(false) {
            "kernel zeroes /proc/<pid>/stat fields 48-51 (arg_start..env_end) while dumpable=0 or ptrace access is denied"
        } else {
            "kernel zeroes /proc/<pid>/stat fields 48-51 (arg_start..env_end) while dumpable=0"
        };
        residuals.push(Residual {
            code: "arg_span_hidden",
            detail: detail.to_string(),
        });
    }
    if snap.exe.is_memfd || snap.maps.has_memfd || snap.maps.smaps_has_memfd || snap.auxv.has_memfd
    {
        residuals.push(Residual {
            code: "memfd_exe",
            detail: "/memfd: path is visible in exe/maps; prefer a private file-backed path when avoiding memfd fingerprints".to_string(),
        });
    }
    if snap.status.tracer_pid != 0 {
        residuals.push(Residual {
            code: "tracer_pid",
            detail: format!(
                "TracerPid={} is visible in /proc/<pid>/status due to active ptrace supervision",
                snap.status.tracer_pid
            ),
        });
    }
    if snap.misc.parent_is_twin {
        residuals.push(Residual {
            code: "visible_supervisor",
            detail: "parent process appears to be a supervisor twin of the target".to_string(),
        });
    }
    if snap.status.seccomp_filters > snap.baseline_seccomp_filters {
        residuals.push(Residual {
            code: "seccomp_filters",
            detail: format!(
                "Seccomp_filters={} exceeds observer baseline {}",
                snap.status.seccomp_filters, snap.baseline_seccomp_filters
            ),
        });
    }
    if snap.status.no_new_privs > snap.baseline_no_new_privs {
        residuals.push(Residual {
            code: "no_new_privs",
            detail: format!(
                "NoNewPrivs={} exceeds observer baseline {}",
                snap.status.no_new_privs, snap.baseline_no_new_privs
            ),
        });
    }
    residuals.push(Residual {
        code: "root_out_of_scope",
        detail: "root, CAP_SYS_PTRACE, kernel modules, hypervisors, and hardware enclaves are out of scope".to_string(),
    });
    residuals
}

/// Probe all `/proc/<pid>` surfaces for `opts.pid`.
fn probe_proc_snapshot(opts: &AuditOptions, needles: &SecretNeedles) -> ProcSnapshot {
    let base = format!("/proc/{}", opts.pid);
    // SAFETY: getuid(2) is always safe and cannot fail.
    let observer_uid = unsafe { libc::getuid() };
    let (self_seccomp_filters, self_nnp) = read_self_status_baselines();
    let baseline_seccomp_filters = opts
        .baseline_seccomp_filters
        .unwrap_or(self_seccomp_filters);
    let baseline_no_new_privs = self_nnp;

    let real_exe = opts.real_exe.as_deref().filter(|s| !s.is_empty());
    let real_cwd = opts.real_cwd.as_deref().filter(|s| !s.is_empty());
    let label = opts.label.as_deref().filter(|s| !s.is_empty());

    // 1. cmdline
    let cmdline = probe_cmdline(&format!("{base}/cmdline"), label, real_exe, needles);

    // 2. comm
    let comm = probe_comm(&format!("{base}/comm"), label, needles);

    // 3. environ
    let environ = probe_environ(&format!("{base}/environ"), real_exe, needles);

    // 4. auxv (+ AT_EXECFN read via mem if readable)
    let auxv = probe_auxv(
        &format!("{base}/auxv"),
        &format!("{base}/mem"),
        real_exe,
        needles,
    );

    // 5. exe
    let exe = probe_exe(&format!("{base}/exe"), real_exe, needles);

    // 6. maps & smaps (also collect parsed VMAs for full mem scan)
    let (maps, vmas) = probe_maps(
        &format!("{base}/maps"),
        &format!("{base}/smaps"),
        real_exe,
        needles,
    );

    // 7. Full VMA /proc/<pid>/mem scan
    let mem = probe_mem(&format!("{base}/mem"), maps.status, &vmas, needles);

    // 8. fd & fdinfo
    let fd = probe_fds(
        &format!("{base}/fd"),
        &format!("{base}/fdinfo"),
        real_exe,
        needles,
    );

    // 9. cwd & root
    let cwd = probe_path_link(&format!("{base}/cwd"), real_cwd, needles);
    let root = probe_path_link(&format!("{base}/root"), None, needles);

    // 10. status
    let status = probe_status(&format!("{base}/status"), needles);
    let target_uid = status.uid;

    // 11. stat
    let stat = probe_stat(
        &format!("{base}/stat"),
        cmdline.status == AccessStatus::Readable,
        cmdline.raw_len,
        cmdline.trailing_nuls,
    );

    // 12. statm
    let statm = probe_statm(&format!("{base}/statm"));

    // 13. limits
    let limits = probe_limits(&format!("{base}/limits"));

    // 14. task/*
    let task = probe_task(&format!("{base}/task"), label);

    // 15. misc (wchan, syscall, cgroup, ns, mountinfo, children, parent twin)
    let parent_is_twin =
        detect_parent_twin(status.ppid, comm.value.as_deref(), &cmdline.argv, label);
    let read_surfaces_denied = exe.status == AccessStatus::DeniedEacces
        || maps.status == AccessStatus::DeniedEacces
        || cwd.status == AccessStatus::DeniedEacces;
    let read_surfaces_readable = exe.status == AccessStatus::Readable
        || maps.status == AccessStatus::Readable
        || cwd.status == AccessStatus::Readable;
    let attach_surfaces_denied = environ.status == AccessStatus::DeniedEacces
        || mem.status == MemScanStatus::DeniedEacces
        || auxv.status == AccessStatus::DeniedEacces;

    let mut misc = probe_misc(&base, opts.pid, parent_is_twin);

    // Determine dumpable_zero: direct prctl if auditing self, otherwise inferred
    // from same-uid EACCES or zeroed stat arg span.  Under `yama.ptrace_scope=1`,
    // `environ`/`mem` return EACCES even when `dumpable=1`, so require BOTH an
    // attach-gated surface denied AND a read-gated surface (`exe`/`maps`/`cwd`)
    // denied (or `stat.arg_span_hidden`) before claiming `dumpable_zero=true`.
    // SAFETY: getpid(2) and prctl(PR_GET_DUMPABLE) are always safe.
    let self_pid = unsafe { libc::getpid() };
    let self_ns_user = fs::read_link("/proc/self/ns/user")
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let in_different_userns =
        misc.ns_user.is_some() && self_ns_user.is_some() && misc.ns_user != self_ns_user;
    if opts.observer == ObserverRole::SameUid
        && observer_uid != 0
        && target_uid == Some(observer_uid)
        && in_different_userns
        && read_surfaces_readable
    {
        misc.userns_owner_read_bypass = true;
    }

    let dumpable_zero = if opts.pid == self_pid {
        // SAFETY: PR_GET_DUMPABLE takes no pointer arguments.
        let rc = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        if rc >= 0 {
            Some(rc == 0)
        } else {
            None
        }
    } else if opts.observer == ObserverRole::SameUid
        && observer_uid != 0
        && target_uid == Some(observer_uid)
    {
        infer_same_uid_dumpable_zero(
            attach_surfaces_denied,
            read_surfaces_denied,
            read_surfaces_readable,
            stat.arg_span_hidden,
            environ.status,
            mem.status,
        )
    } else {
        None
    };

    ProcSnapshot {
        pid: opts.pid,
        observer_uid,
        target_uid,
        baseline_seccomp_filters,
        baseline_no_new_privs,
        dumpable_zero,
        cmdline,
        comm,
        environ,
        auxv,
        exe,
        maps,
        mem,
        fd,
        cwd,
        root,
        status,
        stat,
        statm,
        limits,
        task,
        misc,
    }
}

fn infer_same_uid_dumpable_zero(
    attach_surfaces_denied: bool,
    read_surfaces_denied: bool,
    read_surfaces_readable: bool,
    arg_span_hidden: bool,
    environ_status: AccessStatus,
    mem_status: MemScanStatus,
) -> Option<bool> {
    if arg_span_hidden || (attach_surfaces_denied && read_surfaces_denied) {
        Some(true)
    } else if read_surfaces_readable
        || (environ_status == AccessStatus::Readable && mem_status != MemScanStatus::DeniedEacces)
    {
        Some(false)
    } else {
        None
    }
}

fn classify_io_err(e: &io::Error) -> AccessStatus {
    match e.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => AccessStatus::DeniedEacces,
        _ => AccessStatus::Error,
    }
}

fn read_bounded_bytes(path: &str, limit: usize) -> Result<Vec<u8>, io::Error> {
    let f = File::open(path)?;
    let mut buf = Vec::new();
    f.take(limit as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

fn read_bounded_string(path: &str, limit: usize) -> Result<String, io::Error> {
    let bytes = read_bounded_bytes(path, limit)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn comm_matches_label(comm: &str, label: &str) -> bool {
    let expected = truncate_utf8_bytes(label, COMM_MAX);
    comm == expected || comm == label
}

fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut idx = max_bytes;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    &s[..idx]
}

fn probe_cmdline(
    path: &str,
    label: Option<&str>,
    real_exe: Option<&str>,
    needles: &SecretNeedles,
) -> CmdlineSurface {
    match read_bounded_bytes(path, MAX_PROC_READ_BYTES) {
        Ok(raw) => {
            let raw_len = raw.len();
            let nul_count = raw.iter().filter(|&&b| b == 0).count();
            let trimmed_len = raw
                .iter()
                .rposition(|&b| b != 0)
                .map(|i| i + 1)
                .unwrap_or(0);
            let trailing_nuls = raw_len.saturating_sub(trimmed_len);
            let has_token = needles.matches_bytes(&raw);
            let text = String::from_utf8_lossy(&raw);
            let has_label = label.is_some_and(|l| text.contains(l));
            let has_real_exe = real_exe.is_some_and(|r| text.contains(r));
            let argv = raw
                .split(|&b| b == 0)
                .filter(|part| !part.is_empty())
                .map(|part| {
                    let s = String::from_utf8_lossy(part);
                    needles.scrub_string(&s)
                })
                .collect();
            CmdlineSurface {
                status: AccessStatus::Readable,
                raw_len,
                nul_count,
                trailing_nuls,
                has_token,
                has_label,
                has_real_exe,
                argv,
            }
        }
        Err(e) => CmdlineSurface {
            status: classify_io_err(&e),
            raw_len: 0,
            nul_count: 0,
            trailing_nuls: 0,
            has_token: false,
            has_label: false,
            has_real_exe: false,
            argv: Vec::new(),
        },
    }
}

fn probe_comm(path: &str, label: Option<&str>, needles: &SecretNeedles) -> CommSurface {
    match read_bounded_string(path, 256) {
        Ok(raw) => {
            let trimmed = raw.trim_end_matches(['\n', '\r']);
            let has_token = needles.matches_str(trimmed);
            let matches_label = label.map(|l| comm_matches_label(trimmed, l));
            CommSurface {
                status: AccessStatus::Readable,
                value: Some(needles.scrub_string(trimmed)),
                matches_label,
                has_token,
            }
        }
        Err(e) => CommSurface {
            status: classify_io_err(&e),
            value: None,
            matches_label: None,
            has_token: false,
        },
    }
}

fn probe_environ(path: &str, real_exe: Option<&str>, needles: &SecretNeedles) -> EnvironSurface {
    match read_bounded_bytes(path, MAX_PROC_READ_BYTES) {
        Ok(raw) => {
            let var_count = raw.split(|&b| b == 0).filter(|p| !p.is_empty()).count();
            let has_token = needles.matches_bytes(&raw);
            let has_real_exe = real_exe.is_some_and(|r| contains_subslice(&raw, r.as_bytes()));
            EnvironSurface {
                status: AccessStatus::Readable,
                var_count,
                has_token,
                has_real_exe,
            }
        }
        Err(e) => EnvironSurface {
            status: classify_io_err(&e),
            var_count: 0,
            has_token: false,
            has_real_exe: false,
        },
    }
}

/// Read a NUL-terminated string from `/proc/<pid>/mem` without crossing into an
/// unmapped guard page past the top of `[stack]`. Reads up to the current 4 KiB
/// page boundary first, then continues into the next page only if no NUL byte
/// was seen yet.
fn read_mem_cstring_bounded(file: &File, addr: u64, max_len: usize) -> Result<Vec<u8>, io::Error> {
    if max_len == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(max_len.min(256));
    let mut cur = addr;
    let mut remaining = max_len;
    let mut chunk = [0u8; 256];
    while remaining > 0 {
        let page_rem = (4096u64 - (cur & 4095)) as usize;
        let want = remaining.min(page_rem).min(chunk.len()).max(1);
        match file.read_at(&mut chunk[..want], cur) {
            Ok(0) => break,
            Ok(n) => {
                let slice = &chunk[..n];
                if let Some(nul) = slice.iter().position(|&b| b == 0) {
                    out.extend_from_slice(&slice[..nul]);
                    return Ok(out);
                }
                out.extend_from_slice(slice);
                cur = cur.saturating_add(n as u64);
                remaining = remaining.saturating_sub(n);
            }
            Err(e) => {
                if !out.is_empty() {
                    return Ok(out);
                }
                return Err(e);
            }
        }
    }
    Ok(out)
}

fn probe_auxv(
    auxv_path: &str,
    mem_path: &str,
    real_exe: Option<&str>,
    needles: &SecretNeedles,
) -> AuxvSurface {
    const AT_BASE: u64 = 7;
    const AT_ENTRY: u64 = 9;
    const AT_PLATFORM: u64 = 15;
    const AT_RANDOM: u64 = 25;
    const AT_EXECFN: u64 = 31;

    match read_bounded_bytes(auxv_path, 64 * 1024) {
        Ok(raw) => {
            let mut at_execfn = None;
            let mut at_platform_addr = None;
            let mut at_random = None;
            let mut at_base = None;
            let mut at_entry = None;

            let word = std::mem::size_of::<usize>();
            let pair = word * 2;
            let mut off = 0;
            while off + pair <= raw.len() {
                let (k, v) = if word == 8 {
                    let mut kb = [0u8; 8];
                    let mut vb = [0u8; 8];
                    kb.copy_from_slice(&raw[off..off + 8]);
                    vb.copy_from_slice(&raw[off + 8..off + 16]);
                    (u64::from_ne_bytes(kb), u64::from_ne_bytes(vb))
                } else {
                    let mut kb = [0u8; 4];
                    let mut vb = [0u8; 4];
                    kb.copy_from_slice(&raw[off..off + 4]);
                    vb.copy_from_slice(&raw[off + 4..off + 8]);
                    (
                        u64::from(u32::from_ne_bytes(kb)),
                        u64::from(u32::from_ne_bytes(vb)),
                    )
                };
                if k == 0 {
                    break;
                }
                match k {
                    AT_EXECFN => at_execfn = Some(v),
                    AT_PLATFORM => at_platform_addr = Some(v),
                    AT_RANDOM => at_random = Some(v),
                    AT_BASE => at_base = Some(v),
                    AT_ENTRY => at_entry = Some(v),
                    _ => {}
                }
                off += pair;
            }

            let mut has_token = needles.matches_bytes(&raw);
            let mut has_real_exe = false;
            let mut has_memfd = false;
            let mut at_execfn_str = None;
            let mut at_execfn_readable = None;
            let mut execfn_io_error = false;
            let mut at_platform = None;

            let mem_file = File::open(mem_path);
            if let Some(addr) = at_execfn {
                if addr != 0 && addr <= i64::MAX as u64 {
                    match &mem_file {
                        Ok(f) => match read_mem_cstring_bounded(f, addr, MAX_EXECFN_BYTES) {
                            Ok(bytes) => {
                                let raw_str = String::from_utf8_lossy(&bytes);
                                if needles.matches_str(&raw_str) {
                                    has_token = true;
                                }
                                if real_exe.is_some_and(|r| raw_str.contains(r)) {
                                    has_real_exe = true;
                                }
                                if raw_str.contains("/memfd:") || raw_str.starts_with("memfd:") {
                                    has_memfd = true;
                                }
                                at_execfn_str = Some(needles.scrub_string(&raw_str));
                                at_execfn_readable = Some(true);
                            }
                            Err(e) => {
                                at_execfn_readable = Some(false);
                                if e.raw_os_error() == Some(libc::EIO) {
                                    execfn_io_error = true;
                                }
                            }
                        },
                        Err(e) => {
                            if classify_io_err(e) != AccessStatus::DeniedEacces {
                                at_execfn_readable = Some(false);
                            }
                        }
                    }
                }
            }
            if let Some(addr) = at_platform_addr {
                if addr != 0 && addr <= i64::MAX as u64 {
                    if let Ok(ref f) = mem_file {
                        if let Ok(bytes) = read_mem_cstring_bounded(f, addr, 64) {
                            if !bytes.is_empty() {
                                let s = String::from_utf8_lossy(&bytes);
                                at_platform = Some(needles.scrub_string(&s));
                            }
                        }
                    }
                }
            }

            AuxvSurface {
                status: AccessStatus::Readable,
                at_execfn,
                at_execfn_str,
                at_execfn_readable,
                execfn_io_error,
                at_platform,
                at_random,
                at_base,
                at_entry,
                has_token,
                has_real_exe,
                has_memfd,
            }
        }
        Err(e) => AuxvSurface {
            status: classify_io_err(&e),
            at_execfn: None,
            at_execfn_str: None,
            at_execfn_readable: None,
            execfn_io_error: false,
            at_platform: None,
            at_random: None,
            at_base: None,
            at_entry: None,
            has_token: false,
            has_real_exe: false,
            has_memfd: false,
        },
    }
}

fn probe_exe(path: &str, real_exe: Option<&str>, needles: &SecretNeedles) -> ExeSurface {
    match fs::read_link(path) {
        Ok(target) => {
            let s = target.to_string_lossy();
            let has_token = needles.matches_str(&s);
            let is_real = real_exe.is_some_and(|r| s == r || s.contains(r));
            let is_memfd = s.contains("/memfd:") || s.starts_with("memfd:");
            ExeSurface {
                status: AccessStatus::Readable,
                path: Some(needles.scrub_string(&s)),
                is_real,
                is_memfd,
                has_token,
            }
        }
        Err(e) => ExeSurface {
            status: classify_io_err(&e),
            path: None,
            is_real: false,
            is_memfd: false,
            has_token: false,
        },
    }
}

#[derive(Debug, Clone)]
struct VmaRange {
    start: u64,
    end: u64,
    readable: bool,
    name: String,
}

fn parse_maps_vmas(text: &str) -> (Vec<VmaRange>, usize) {
    let mut vmas = Vec::new();
    let mut anon_rx_count = 0usize;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else {
            continue;
        };
        let Some(perms) = parts.next() else {
            continue;
        };
        let Some((start_hex, end_hex)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = u64::from_str_radix(start_hex, 16) else {
            continue;
        };
        let Ok(end) = u64::from_str_radix(end_hex, 16) else {
            continue;
        };
        // Skip offset, dev, inode.
        let _offset = parts.next();
        let _dev = parts.next();
        let _inode = parts.next();
        let name = parts.collect::<Vec<_>>().join(" ");
        let readable = perms.starts_with('r');
        let executable = perms.as_bytes().get(2) == Some(&b'x');
        if executable && name.is_empty() {
            anon_rx_count += 1;
        }
        vmas.push(VmaRange {
            start,
            end,
            readable,
            name,
        });
    }
    (vmas, anon_rx_count)
}

fn probe_maps(
    maps_path: &str,
    smaps_path: &str,
    real_exe: Option<&str>,
    needles: &SecretNeedles,
) -> (MapsSurface, Vec<VmaRange>) {
    let (status, vmas, anon_rx_count, has_real_exe, has_memfd, has_token) =
        match read_bounded_string(maps_path, MAX_PROC_READ_BYTES) {
            Ok(text) => {
                let (vmas, anon_rx) = parse_maps_vmas(&text);
                let has_real = real_exe.is_some_and(|r| text.contains(r));
                let has_memfd = text.contains("/memfd:");
                let has_tok = needles.matches_str(&text);
                (
                    AccessStatus::Readable,
                    vmas,
                    anon_rx,
                    has_real,
                    has_memfd,
                    has_tok,
                )
            }
            Err(e) => (classify_io_err(&e), Vec::new(), 0, false, false, false),
        };

    let (smaps_status, smaps_has_real_exe, smaps_has_memfd, smaps_has_token) =
        match read_bounded_string(smaps_path, MAX_PROC_READ_BYTES) {
            Ok(text) => (
                AccessStatus::Readable,
                real_exe.is_some_and(|r| text.contains(r)),
                text.contains("/memfd:"),
                needles.matches_str(&text),
            ),
            Err(e) => (classify_io_err(&e), false, false, false),
        };

    let vma_count = vmas.len();
    (
        MapsSurface {
            status,
            smaps_status,
            vma_count,
            has_real_exe,
            has_memfd,
            anon_rx_count,
            has_token,
            smaps_has_real_exe,
            smaps_has_memfd,
            smaps_has_token,
        },
        vmas,
    )
}

fn should_skip_vma(vma: &VmaRange) -> bool {
    if !vma.readable || vma.end <= vma.start || vma.start > i64::MAX as u64 {
        return true;
    }
    matches!(
        vma.name.as_str(),
        "[vvar]" | "[vvar_vclock]" | "[vdso]" | "[vsyscall]" | "[uprobes]"
    ) || vma.name.starts_with("/dev/")
}

fn vma_priority(vma: &VmaRange) -> u8 {
    match vma.name.as_str() {
        "[heap]" => 0,
        "[stack]" => 1,
        "" => {
            // Scan smaller active anonymous VMAs (thread stacks, small heaps)
            // before huge (>16 MiB) sparse glibc arenas.
            if vma.end.saturating_sub(vma.start) <= 16 * 1024 * 1024 {
                2
            } else {
                3
            }
        }
        _ => 4,
    }
}

fn probe_mem(
    mem_path: &str,
    maps_status: AccessStatus,
    vmas: &[VmaRange],
    needles: &SecretNeedles,
) -> MemSurface {
    let file = match File::open(mem_path) {
        Ok(f) => f,
        Err(e) => {
            let st = if classify_io_err(&e) == AccessStatus::DeniedEacces {
                MemScanStatus::DeniedEacces
            } else if needles.is_empty() {
                MemScanStatus::SkippedNoToken
            } else {
                MemScanStatus::Clean
            };
            return MemSurface {
                status: st,
                vmas_scanned: 0,
                bytes_scanned: 0,
                leaked_mapping: None,
            };
        }
    };

    if needles.is_empty() {
        return MemSurface {
            status: MemScanStatus::SkippedNoToken,
            vmas_scanned: 0,
            bytes_scanned: 0,
            leaked_mapping: None,
        };
    }

    if maps_status == AccessStatus::DeniedEacces {
        return MemSurface {
            status: MemScanStatus::DeniedEacces,
            vmas_scanned: 0,
            bytes_scanned: 0,
            leaked_mapping: None,
        };
    }

    // Prioritize heap, stack, and smaller active anonymous writable mappings so
    // giant sparse arenas (e.g. 64 MiB thread/Argon2 pools) and shared libraries
    // never exhaust the 64 MiB cap before active heap/stack pages are read.
    let mut ordered: Vec<&VmaRange> = vmas.iter().filter(|v| !should_skip_vma(v)).collect();
    ordered.sort_by_key(|v| (vma_priority(v), v.end.saturating_sub(v.start), v.start));

    let overlap = needles.max_len().saturating_sub(1).min(4096);
    let mut buf = vec![0u8; MEM_CHUNK_BYTES + overlap];
    let mut total_scanned = 0usize;
    let mut vmas_scanned = 0usize;
    let mut saw_eacces = false;

    for vma in ordered {
        if total_scanned >= MAX_MEM_SCAN_BYTES {
            break;
        }
        vmas_scanned += 1;
        let mut cursor = vma.start;
        let mut carry = 0usize;

        while cursor < vma.end && total_scanned < MAX_MEM_SCAN_BYTES {
            let remaining_vma = (vma.end - cursor) as usize;
            let remaining_budget = MAX_MEM_SCAN_BYTES - total_scanned;
            let to_read = remaining_vma.min(MEM_CHUNK_BYTES).min(remaining_budget);
            if to_read == 0 {
                break;
            }
            match file.read_at(&mut buf[carry..carry + to_read], cursor) {
                Ok(0) => break,
                Ok(n) => {
                    total_scanned += n;
                    let window = &buf[..carry + n];
                    if needles.matches_bytes(window) {
                        let mapping_name = if vma.name.is_empty() {
                            format!("[anon:{:x}-{:x}]", vma.start, vma.end)
                        } else {
                            needles.scrub_string(&vma.name)
                        };
                        buf.zeroize();
                        return MemSurface {
                            status: MemScanStatus::Leaked,
                            vmas_scanned,
                            bytes_scanned: total_scanned,
                            leaked_mapping: Some(mapping_name),
                        };
                    }
                    if overlap > 0 {
                        let keep = overlap.min(carry + n);
                        buf.copy_within((carry + n - keep)..(carry + n), 0);
                        carry = keep;
                    } else {
                        carry = 0;
                    }
                    cursor = cursor.saturating_add(n as u64);
                }
                Err(e) => {
                    if matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM)) {
                        saw_eacces = true;
                    }
                    break;
                }
            }
        }
    }

    buf.zeroize();

    let status = if total_scanned == 0 && saw_eacces {
        MemScanStatus::DeniedEacces
    } else {
        MemScanStatus::Clean
    };

    MemSurface {
        status,
        vmas_scanned,
        bytes_scanned: total_scanned,
        leaked_mapping: None,
    }
}

fn probe_fds(
    fd_dir: &str,
    fdinfo_dir: &str,
    real_exe: Option<&str>,
    needles: &SecretNeedles,
) -> FdSurface {
    let fdinfo_status = match fs::read_dir(fdinfo_dir) {
        Ok(_) => AccessStatus::Readable,
        Err(e) => classify_io_err(&e),
    };

    match fs::read_dir(fd_dir) {
        Ok(entries) => {
            let mut count = 0usize;
            let mut has_real_exe = false;
            let mut has_memfd = false;
            let mut has_token = false;
            for entry in entries.flatten() {
                count += 1;
                if let Ok(target) = fs::read_link(entry.path()) {
                    let s = target.to_string_lossy();
                    if real_exe.is_some_and(|r| s.contains(r)) {
                        has_real_exe = true;
                    }
                    if s.contains("/memfd:") || s.starts_with("memfd:") {
                        has_memfd = true;
                    }
                    if needles.matches_str(&s) {
                        has_token = true;
                    }
                }
            }
            FdSurface {
                status: AccessStatus::Readable,
                fdinfo_status,
                count,
                has_real_exe,
                has_memfd,
                has_token,
            }
        }
        Err(e) => FdSurface {
            status: classify_io_err(&e),
            fdinfo_status,
            count: 0,
            has_real_exe: false,
            has_memfd: false,
            has_token: false,
        },
    }
}

fn probe_path_link(path: &str, real_cwd: Option<&str>, needles: &SecretNeedles) -> PathLinkSurface {
    match fs::read_link(path) {
        Ok(target) => {
            let s = target.to_string_lossy();
            let has_token = needles.matches_str(&s);
            let is_real_cwd = real_cwd.is_some_and(|rc| {
                let norm_s = s.trim_end_matches('/');
                let norm_rc = rc.trim_end_matches('/');
                norm_s == norm_rc
            });
            PathLinkSurface {
                status: AccessStatus::Readable,
                path: Some(needles.scrub_string(&s)),
                is_real_cwd,
                has_token,
            }
        }
        Err(e) => PathLinkSurface {
            status: classify_io_err(&e),
            path: None,
            is_real_cwd: false,
            has_token: false,
        },
    }
}

fn read_self_status_baselines() -> (u32, u32) {
    let Ok(text) = read_bounded_string("/proc/self/status", 64 * 1024) else {
        return (0, 0);
    };
    let mut seccomp_filters = 0u32;
    let mut no_new_privs = 0u32;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Seccomp_filters:") {
            if let Some(v) = rest.split_whitespace().next() {
                seccomp_filters = v.parse().unwrap_or(0);
            }
        } else if let Some(rest) = line.strip_prefix("NoNewPrivs:") {
            if let Some(v) = rest.split_whitespace().next() {
                no_new_privs = v.parse().unwrap_or(0);
            }
        }
    }
    (seccomp_filters, no_new_privs)
}

fn probe_status(path: &str, needles: &SecretNeedles) -> StatusSurface {
    match read_bounded_string(path, 64 * 1024) {
        Ok(text) => {
            let has_token = needles.matches_str(&text);
            let mut name = None;
            let mut ppid = 0;
            let mut tracer_pid = 0;
            let mut threads = 0;
            let mut no_new_privs = 0;
            let mut seccomp = 0;
            let mut seccomp_filters = 0;
            let mut uid = None;
            let mut euid = None;
            let mut vm_data_kb = None;

            for line in text.lines() {
                if let Some(v) = line.strip_prefix("Name:") {
                    name = Some(needles.scrub_string(v.trim()));
                } else if let Some(v) = line.strip_prefix("PPid:") {
                    ppid = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("TracerPid:") {
                    tracer_pid = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("Threads:") {
                    threads = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("NoNewPrivs:") {
                    no_new_privs = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("Seccomp:") {
                    seccomp = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("Seccomp_filters:") {
                    seccomp_filters = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("Uid:") {
                    let mut cols = v.split_whitespace();
                    uid = cols.next().and_then(|c| c.parse().ok());
                    euid = cols.next().and_then(|c| c.parse().ok());
                } else if let Some(v) = line.strip_prefix("VmData:") {
                    vm_data_kb = v.split_whitespace().next().and_then(|c| c.parse().ok());
                }
            }

            StatusSurface {
                status: AccessStatus::Readable,
                name,
                ppid,
                tracer_pid,
                threads,
                no_new_privs,
                seccomp,
                seccomp_filters,
                uid,
                euid,
                vm_data_kb,
                has_token,
            }
        }
        Err(e) => StatusSurface {
            status: classify_io_err(&e),
            name: None,
            ppid: 0,
            tracer_pid: 0,
            threads: 0,
            no_new_privs: 0,
            seccomp: 0,
            seccomp_filters: 0,
            uid: None,
            euid: None,
            vm_data_kb: None,
            has_token: false,
        },
    }
}

fn probe_stat(
    path: &str,
    cmdline_readable: bool,
    cmdline_raw_len: usize,
    cmdline_trailing_nuls: usize,
) -> StatSurface {
    let Ok(text) = read_bounded_string(path, 16 * 1024) else {
        return StatSurface {
            status: AccessStatus::Error,
            ppid: 0,
            num_threads: 0,
            starttime: 0,
            arg_start: 0,
            arg_end: 0,
            env_start: 0,
            env_end: 0,
            arg_span_mismatch: false,
            arg_span_hidden: false,
        };
    };

    let Some(rp) = text.rfind(')') else {
        return StatSurface {
            status: AccessStatus::Error,
            ppid: 0,
            num_threads: 0,
            starttime: 0,
            arg_start: 0,
            arg_end: 0,
            env_start: 0,
            env_end: 0,
            arg_span_mismatch: false,
            arg_span_hidden: false,
        };
    };

    let fields: Vec<&str> = text[rp + 1..].split_whitespace().collect();
    // fields[0] is field 3 (state), so 1-based field N is at index N - 3.
    let get_u64 = |n: usize| -> u64 {
        fields
            .get(n.saturating_sub(3))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let get_i32 = |n: usize| -> libc::pid_t {
        fields
            .get(n.saturating_sub(3))
            .and_then(|s| s.parse::<libc::pid_t>().ok())
            .unwrap_or(0)
    };

    let ppid = get_i32(4);
    let num_threads = get_u64(20) as u32;
    let starttime = get_u64(22);
    let arg_start = get_u64(48);
    let arg_end = get_u64(49);
    let env_start = get_u64(50);
    let env_end = get_u64(51);

    let arg_span_hidden = arg_start == 0 && arg_end == 0;
    let arg_span_mismatch = if arg_span_hidden {
        false
    } else if arg_end < arg_start {
        true
    } else if cmdline_readable {
        let span = (arg_end - arg_start) as usize;
        let raw_mismatch = cmdline_raw_len < 4096 && span.abs_diff(cmdline_raw_len) > 1;
        let trimmed = cmdline_raw_len.saturating_sub(cmdline_trailing_nuls);
        let padding_mismatch = trimmed > 0 && span > trimmed.saturating_add(2);
        raw_mismatch || padding_mismatch
    } else {
        false
    };

    StatSurface {
        status: AccessStatus::Readable,
        ppid,
        num_threads,
        starttime,
        arg_start,
        arg_end,
        env_start,
        env_end,
        arg_span_mismatch,
        arg_span_hidden,
    }
}

fn probe_statm(path: &str) -> StatmSurface {
    match read_bounded_string(path, 1024) {
        Ok(text) => {
            let rss_pages = text
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            // SAFETY: sysconf(_SC_PAGESIZE) is thread-safe and takes no pointers.
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            let page_kb = if page_size > 0 {
                (page_size as u64) / 1024
            } else {
                4
            };
            StatmSurface {
                status: AccessStatus::Readable,
                rss_pages,
                rss_kb: rss_pages.saturating_mul(page_kb.max(1)),
            }
        }
        Err(e) => StatmSurface {
            status: classify_io_err(&e),
            rss_pages: 0,
            rss_kb: 0,
        },
    }
}

fn probe_limits(path: &str) -> LimitsSurface {
    match read_bounded_string(path, 16 * 1024) {
        Ok(text) => {
            let mut core_limit_zero = None;
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("Max core file size") {
                    if let Some(soft) = rest.split_whitespace().next() {
                        core_limit_zero = Some(soft == "0");
                    }
                    break;
                }
            }
            LimitsSurface {
                status: AccessStatus::Readable,
                core_limit_zero,
            }
        }
        Err(e) => LimitsSurface {
            status: classify_io_err(&e),
            core_limit_zero: None,
        },
    }
}

fn probe_task(task_dir: &str, label: Option<&str>) -> TaskSurface {
    match fs::read_dir(task_dir) {
        Ok(entries) => {
            let mut thread_count = 0usize;
            let mut all_match = label.map(|_| true);
            for entry in entries.flatten() {
                let name = entry.file_name();
                if !name.to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                thread_count += 1;
                if let Some(lbl) = label {
                    let comm_path = entry.path().join("comm");
                    if let Ok(raw) = fs::read_to_string(comm_path) {
                        let trimmed = raw.trim_end_matches(['\n', '\r']);
                        if !comm_matches_label(trimmed, lbl) {
                            all_match = Some(false);
                        }
                    }
                }
            }
            TaskSurface {
                status: AccessStatus::Readable,
                thread_count,
                all_match_label: all_match,
            }
        }
        Err(e) => TaskSurface {
            status: classify_io_err(&e),
            thread_count: 0,
            all_match_label: None,
        },
    }
}

fn detect_parent_twin(
    ppid: libc::pid_t,
    target_comm: Option<&str>,
    target_argv: &[String],
    label: Option<&str>,
) -> bool {
    if ppid <= 1 {
        return false;
    }
    let parent_comm = read_bounded_string(&format!("/proc/{ppid}/comm"), 256)
        .ok()
        .map(|s| s.trim_end_matches(['\n', '\r']).to_string());
    let parent_cmdline: Vec<String> = read_bounded_bytes(&format!("/proc/{ppid}/cmdline"), 8192)
        .ok()
        .map(|raw| {
            raw.split(|&b| b == 0)
                .filter(|p| !p.is_empty())
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect()
        })
        .unwrap_or_default();

    if let Some(ref pcomm) = parent_comm {
        // Explicit unmasked pmask supervisor parent.
        if pcomm == "pmask" && target_comm != Some("pmask") {
            return true;
        }
        // Masked supervisor sharing the same label/comm and cmdline with child.
        if let Some(tcomm) = target_comm {
            if !tcomm.is_empty() && pcomm == tcomm {
                if !target_argv.is_empty() && parent_cmdline == target_argv {
                    return true;
                }
                if label.is_some_and(|l| comm_matches_label(pcomm, l)) {
                    return true;
                }
            }
        }
    }
    false
}

/// Extract a mount-namespace-independent fingerprint `(root, mount_point, fs_type, source)`
/// from one `/proc/<pid>/mountinfo` line.
fn mountinfo_entry_key(line: &str) -> Option<(&str, &str, &str, &str)> {
    let (head, tail) = line.split_once(" - ")?;
    let mut head_cols = head.split_whitespace();
    let _mount_id = head_cols.next()?;
    let _parent_id = head_cols.next()?;
    let _major_minor = head_cols.next()?;
    let root = head_cols.next()?;
    let mount_point = head_cols.next()?;

    let mut tail_cols = tail.split_whitespace();
    let fs_type = tail_cols.next()?;
    let mount_source = tail_cols.next()?;
    Some((root, mount_point, fs_type, mount_source))
}

/// Compare the target's mount namespace and `mountinfo` against the observer's.
/// Returns `false` when the target shares the observer's mount namespace or has
/// identical mount entries; returns `true` only when the target has extra or
/// different private mounts not present in the observer's `mountinfo`.
fn detect_mountinfo_private_tell(
    target_ns_mnt: Option<&str>,
    self_ns_mnt: Option<&str>,
    target_mountinfo: Option<&str>,
    self_mountinfo: Option<&str>,
) -> bool {
    if let (Some(t_ns), Some(s_ns)) = (target_ns_mnt, self_ns_mnt) {
        if t_ns == s_ns {
            return false;
        }
    }
    let Some(t_text) = target_mountinfo else {
        return false;
    };
    let Some(s_text) = self_mountinfo else {
        return false;
    };
    if t_text == s_text {
        return false;
    }
    let self_entries: std::collections::HashSet<(&str, &str, &str, &str)> =
        s_text.lines().filter_map(mountinfo_entry_key).collect();
    t_text
        .lines()
        .filter_map(mountinfo_entry_key)
        .any(|entry| !self_entries.contains(&entry))
}

fn probe_misc(base: &str, pid: libc::pid_t, parent_is_twin: bool) -> MiscSurfaces {
    let wchan = read_bounded_string(&format!("{base}/wchan"), 256)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let syscall = read_bounded_string(&format!("{base}/syscall"), 512)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let cgroup = read_bounded_string(&format!("{base}/cgroup"), 4096)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let ns_pid = fs::read_link(format!("{base}/ns/pid"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let ns_mnt = fs::read_link(format!("{base}/ns/mnt"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let ns_user = fs::read_link(format!("{base}/ns/user"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let self_ns_mnt = fs::read_link("/proc/self/ns/mnt")
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    let mountinfo_private_tell = if ns_mnt.is_some() && ns_mnt == self_ns_mnt {
        false
    } else {
        let target_mi = read_bounded_string(&format!("{base}/mountinfo"), 256 * 1024).ok();
        let self_mi = read_bounded_string("/proc/self/mountinfo", 256 * 1024).ok();
        detect_mountinfo_private_tell(
            ns_mnt.as_deref(),
            self_ns_mnt.as_deref(),
            target_mi.as_deref(),
            self_mi.as_deref(),
        )
    };

    let children_count = read_bounded_string(&format!("{base}/task/{pid}/children"), 16 * 1024)
        .ok()
        .map(|s| s.split_whitespace().count())
        .unwrap_or(0);

    MiscSurfaces {
        wchan,
        syscall,
        cgroup,
        ns_pid,
        ns_mnt,
        ns_user,
        mountinfo_private_tell,
        userns_owner_read_bypass: false,
        children_count,
        parent_is_twin,
    }
}

/// Maximum `maps` entries captured in native `psgen` `schema: 2` export.
const MAX_PROFILE_MAPS_LINES: usize = 512;

/// Maximum `smaps` entries captured in native `psgen` `schema: 2` export.
const MAX_PROFILE_SMAPS_LINES: usize = 256;

fn contains_ascii_ci(hay: &str, needle_upper: &[u8]) -> bool {
    let hb = hay.as_bytes();
    if needle_upper.len() > hb.len() {
        return false;
    }
    hb.windows(needle_upper.len()).any(|w| {
        w.iter()
            .zip(needle_upper.iter())
            .all(|(&a, &b)| a.to_ascii_uppercase() == b)
    })
}

fn is_sensitive_env_key(key: &str) -> bool {
    "SECRET,TOKEN,PASSWORD,PASSWD,API_KEY,APIKEY,PRIVATE_KEY,CREDENTIAL,AUTH_KEY"
        .split(',')
        .any(|k| contains_ascii_ci(key, k.as_bytes()))
}

fn contains_unredacted_secret_pattern(s: &str) -> bool {
    if (s.contains("-----BEGIN ") && s.contains("PRIVATE KEY-----"))
        || s.contains("ghp_")
        || s.contains("github_pat_")
        || s.contains("xoxb-")
        || s.contains("xoxp-")
    {
        return true;
    }
    let bytes = s.as_bytes();
    if bytes.len() >= 20 {
        for i in 0..=bytes.len() - 20 {
            if &bytes[i..i + 4] == b"AKIA"
                && bytes[i + 4..i + 20]
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                return true;
            }
        }
    }
    false
}

fn find_inline_secret_str(s: &str) -> Option<&str> {
    struct InlineRule {
        pfx: &'static [u8],
        min_len: usize,
        max_len: usize,
        dash: bool,
        under: bool,
        req_b: bool,
    }
    const RULES: &[InlineRule] = &[
        InlineRule {
            pfx: b"TOK-",
            min_len: 10,
            max_len: 68,
            dash: true,
            under: true,
            req_b: true,
        },
        InlineRule {
            pfx: b"github_pat_",
            min_len: 21,
            max_len: 107,
            dash: false,
            under: true,
            req_b: false,
        },
        InlineRule {
            pfx: b"ghp_",
            min_len: 14,
            max_len: 68,
            dash: false,
            under: false,
            req_b: false,
        },
        InlineRule {
            pfx: b"xoxb-",
            min_len: 13,
            max_len: 69,
            dash: true,
            under: false,
            req_b: false,
        },
        InlineRule {
            pfx: b"xoxp-",
            min_len: 13,
            max_len: 69,
            dash: true,
            under: false,
            req_b: false,
        },
    ];
    let hay = s.as_bytes();
    for i in 0..hay.len() {
        let rest = &hay[i..];
        let boundary = i == 0 || !hay[i - 1].is_ascii_alphanumeric();
        for r in RULES {
            if (!r.req_b || boundary) && rest.starts_with(r.pfx) {
                let mut end = r.pfx.len();
                let lim = rest.len().min(r.max_len);
                while end < lim
                    && (rest[end].is_ascii_alphanumeric()
                        || (r.dash && rest[end] == b'-')
                        || (r.under && rest[end] == b'_'))
                {
                    end += 1;
                }
                if end >= r.min_len {
                    if let Ok(found) = std::str::from_utf8(&rest[..end]) {
                        return Some(found);
                    }
                }
            }
        }
        if boundary
            && rest.len() >= 20
            && &rest[..4] == b"AKIA"
            && rest[4..20]
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            if let Ok(found) = std::str::from_utf8(&rest[..20]) {
                return Some(found);
            }
        }
    }
    None
}

fn redacted_len_marker(len: usize) -> String {
    format!("<REDACTED:len={len}>")
}

fn scrub_profile_str(s: &str, needles: &SecretNeedles) -> String {
    let mut out = s.to_string();
    for needle in &needles.variants {
        if let Ok(ns) = std::str::from_utf8(needle) {
            if !ns.is_empty() && out.contains(ns) {
                out = out.replace(ns, &redacted_len_marker(ns.len()));
            }
        }
    }
    if needles.matches_str(&out) {
        out = redacted_len_marker(s.len());
    }
    while let Some(found) = find_inline_secret_str(&out).map(ToOwned::to_owned) {
        out = out.replace(&found, &redacted_len_marker(found.len()));
    }
    if contains_unredacted_secret_pattern(&out) {
        out = redacted_len_marker(s.len());
    }
    out
}

fn scrub_profile_environ_entry(entry: &str, needles: &SecretNeedles) -> String {
    if let Some((k, v)) = entry.split_once('=') {
        let mut clean_v = v.to_string();
        for needle in &needles.variants {
            if let Ok(ns) = std::str::from_utf8(needle) {
                if !ns.is_empty() && clean_v.contains(ns) {
                    clean_v = clean_v.replace(ns, &redacted_len_marker(ns.len()));
                }
            }
        }
        let key_flagged = is_sensitive_env_key(k) && !v.is_empty() && !v.starts_with("<REDACTED");
        let pat_flagged = contains_unredacted_secret_pattern(&clean_v);
        let final_v = if key_flagged || pat_flagged {
            redacted_len_marker(v.len())
        } else {
            scrub_profile_str(&clean_v, needles)
        };
        let clean_k = scrub_profile_str(k, needles);
        format!("{clean_k}={final_v}")
    } else {
        scrub_profile_str(entry, needles)
    }
}

fn is_safe_ancestor_env_key(key: &str) -> bool {
    matches!(
        key,
        "PATH" | "HOME" | "LANG" | "TERM" | "USER" | "LOGNAME" | "SHELL" | "PWD" | "SHLVL"
    ) || key.starts_with("LC_")
}

fn filter_and_scrub_profile_environ(
    raw_env: &[u8],
    depth: usize,
    needles: &SecretNeedles,
) -> Vec<String> {
    raw_env
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .filter_map(|part| {
            let s = String::from_utf8_lossy(part);
            if depth > 0 {
                let key = s.split_once('=').map(|(k, _)| k)?;
                if !is_safe_ancestor_env_key(key) {
                    return None;
                }
            }
            Some(scrub_profile_environ_entry(&s, needles))
        })
        .collect()
}

fn fmt_opt_yes_no(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn classify_token_charset(tok: &str) -> String {
    if tok.is_empty() {
        return "ascii".to_string();
    }
    if let Some(pos) = tok.rfind(['-', '_']) {
        let pfx = &tok[..=pos];
        let suffix = &tok[pos + 1..];
        if pfx.len() >= 2
            && pfx.len() <= 8
            && suffix.len() >= 3
            && suffix.len() >= pfx.len()
            && pfx.as_bytes()[0].is_ascii_alphabetic()
            && pfx
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || b == b'-' || b == b'_')
        {
            if suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
                return format!("prefix:{pfx}:hex");
            }
            if suffix.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return format!("prefix:{pfx}:alnum");
            }
        }
    }
    if tok.bytes().all(|b| b.is_ascii_hexdigit()) {
        "hex".to_string()
    } else if tok.bytes().all(|b| b.is_ascii_alphanumeric()) {
        "alnum".to_string()
    } else if tok
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
    {
        "base64".to_string()
    } else {
        "ascii".to_string()
    }
}

fn detect_exe_memfd(exe: &str) -> Option<String> {
    let trimmed = exe.strip_prefix('/').unwrap_or(exe);
    let rest = trimmed.strip_prefix("memfd:")?;
    let name = rest.strip_suffix(" (deleted)").unwrap_or(rest).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn normalize_maps_for_profile(text: &str, needles: &SecretNeedles) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines().take(MAX_PROFILE_MAPS_LINES) {
        let mut parts = line.split_ascii_whitespace();
        let (Some(_), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        let mut s = String::with_capacity(64);
        s.push_str("<addr>");
        for p in [
            perms,
            parts.next().unwrap_or("00000000"),
            parts.next().unwrap_or("00:00"),
            parts.next().unwrap_or("0"),
        ]
        .into_iter()
        .chain(parts)
        {
            s.push(' ');
            s.push_str(p);
        }
        out.push(scrub_profile_str(&s, needles));
    }
    out
}

fn normalize_smaps_for_profile(text: &str, needles: &SecretNeedles) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur_header: Option<String> = None;
    let mut rss = 0u64;
    let mut pdirty = 0u64;
    let mut anon = 0u64;

    let flush = |out: &mut Vec<String>, hdr: &mut Option<String>, r: u64, p: u64, a: u64| {
        if let Some(h) = hdr.take() {
            if out.len() < MAX_PROFILE_SMAPS_LINES {
                out.push(scrub_profile_str(
                    &format!("{h} Rss:{r}kB Private_Dirty:{p}kB Anonymous:{a}kB"),
                    needles,
                ));
            }
        }
    };

    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if !k.contains(' ') && !k.contains('-') {
                let parsed = v
                    .split_ascii_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                match k {
                    "Rss" => rss = parsed,
                    "Private_Dirty" => pdirty = parsed,
                    "Anonymous" => anon = parsed,
                    _ => {}
                }
                continue;
            }
        }
        flush(&mut out, &mut cur_header, rss, pdirty, anon);
        rss = 0;
        pdirty = 0;
        anon = 0;
        let mut parts = line.split_ascii_whitespace();
        let _addr = parts.next();
        let perms = parts.next().unwrap_or("----");
        let mut hdr = perms.to_string();
        let mut any = false;
        for p in parts.skip(3) {
            hdr.push(' ');
            hdr.push_str(p);
            any = true;
        }
        if !any {
            hdr.push_str(" [anon]");
        }
        cur_header = Some(hdr);
    }
    flush(&mut out, &mut cur_header, rss, pdirty, anon);
    out
}

fn decode_syscall_name(raw_syscall: Option<&str>) -> String {
    let Some(text) = raw_syscall else {
        return "unknown".to_string();
    };
    let first = text.split_ascii_whitespace().next().unwrap_or("");
    if first.is_empty() {
        return "unknown".to_string();
    }
    if first == "running" {
        return "running".to_string();
    }
    let Ok(nr_l) = first.parse::<libc::c_long>() else {
        return first.to_string();
    };
    if nr_l < 0 {
        return first.to_string();
    }
    #[cfg(target_arch = "x86_64")]
    {
        if nr_l == libc::SYS_poll {
            return "poll".to_string();
        }
        if nr_l == libc::SYS_select {
            return "select".to_string();
        }
        if nr_l == libc::SYS_pause {
            return "pause".to_string();
        }
        if nr_l == libc::SYS_epoll_wait {
            return "epoll_wait".to_string();
        }
    }
    match nr_l {
        libc::SYS_read => "read".to_string(),
        libc::SYS_write => "write".to_string(),
        libc::SYS_ppoll => "ppoll".to_string(),
        libc::SYS_pselect6 => "pselect6".to_string(),
        libc::SYS_epoll_pwait => "epoll_pwait".to_string(),
        libc::SYS_nanosleep => "nanosleep".to_string(),
        libc::SYS_clock_nanosleep => "clock_nanosleep".to_string(),
        libc::SYS_futex => "futex".to_string(),
        libc::SYS_wait4 => "wait4".to_string(),
        libc::SYS_rt_sigsuspend => "rt_sigsuspend".to_string(),
        libc::SYS_accept4 => "accept4".to_string(),
        libc::SYS_recvfrom => "recvfrom".to_string(),
        _ => format!("syscall_{nr_l}"),
    }
}

fn is_stop_ancestor_comm(comm: &str) -> bool {
    let t = comm.trim();
    "init,systemd,podman-init,tini,dumb-init,conmon,catatonit,docker-init,pause,s6-svscan,supervisord,runit,sshd,login"
        .split(',')
        .any(|s| s == t)
}

fn discover_direct_children(pid: libc::pid_t) -> Vec<libc::pid_t> {
    let mut children: Vec<libc::pid_t> = Vec::new();
    let task_dir = format!("/proc/{pid}/task");
    let mut used_proc_children = false;
    if let Ok(entries) = fs::read_dir(&task_dir) {
        for entry in entries.flatten() {
            let tid_s = entry.file_name();
            if !tid_s.to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let cpath = entry.path().join("children");
            if let Ok(text) = read_bounded_string(&cpath.to_string_lossy(), 64 * 1024) {
                used_proc_children = true;
                for tok in text.split_ascii_whitespace() {
                    if let Ok(cpid) = tok.parse::<libc::pid_t>() {
                        if cpid > 0 && cpid != pid && !children.contains(&cpid) {
                            children.push(cpid);
                        }
                    }
                }
            }
        }
    }
    if !used_proc_children {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Ok(cpid) = name.to_string_lossy().parse::<libc::pid_t>() else {
                    continue;
                };
                if cpid <= 0 || cpid == pid {
                    continue;
                }
                if let Ok(text) = read_bounded_string(&format!("/proc/{cpid}/stat"), 4096) {
                    if let Some(rp) = text.rfind(')') {
                        let ppid = text[rp + 1..]
                            .split_ascii_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse::<libc::pid_t>().ok())
                            .unwrap_or(0);
                        if ppid == pid && !children.contains(&cpid) {
                            children.push(cpid);
                        }
                    }
                }
            }
        }
    }
    children.sort_unstable();
    children
}

/// Native `psgen` `schema: 2` profile model.
struct PsgenProfile {
    schema: u32,
    masker: String,
    profile: String,
    version: String,
    observer_uid: Option<u32>,
    // identity
    label: String,
    comm: String,
    argv: Vec<String>,
    cmdline_raw_nuls: Option<usize>,
    pid: i32,
    ppid: i32,
    pgid: i32,
    sid: i32,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    starttime: u64,
    cwd: String,
    root: String,
    exe: String,
    exe_memfd: Option<String>,
    ns_pid: Option<String>,
    ns_mnt: Option<String>,
    ns_user: Option<String>,
    ns_net: Option<String>,
    // status
    st_name: String,
    st_state: String,
    st_ppid: i32,
    st_uid: String,
    st_gid: String,
    st_threads: u32,
    st_tracer_pid: i32,
    st_no_new_privs: u32,
    st_seccomp: u32,
    st_seccomp_filters: u32,
    st_cap_eff: String,
    st_cap_prm: String,
    st_cap_bnd: String,
    st_vm_lck: Option<u64>,
    st_rss_shmem: Option<u64>,
    // stat
    stat_ppid: i32,
    stat_num_threads: u32,
    stat_starttime: u64,
    stat_vsize: u64,
    stat_rss: u64,
    stat_flags: Option<u64>,
    stat_arg_start: u64,
    stat_arg_end: u64,
    stat_env_start: u64,
    stat_env_end: u64,
    stat_startstack: u64,
    // memory
    maps: Vec<String>,
    smaps: Vec<String>,
    token_present: bool,
    token_sha256: Option<String>,
    token_len: Option<u32>,
    token_charset: Option<String>,
    token_placements: Vec<String>,
    readable_by: Vec<String>,
    denied_by: Vec<String>,
    // fds
    fds: Vec<(i32, String)>,
    // auxv
    at_execfn: Option<String>,
    at_platform: Option<String>,
    at_base: u64,
    at_entry: u64,
    // environ
    environ: Vec<String>,
    environ_raw_len: u64,
    environ_all_nul: bool,
    // task
    task: Vec<(i32, String, String)>,
    // syscall
    syscall_name: String,
    wchan: String,
    policy: i32,
    priority: i32,
    // timing
    exec_ms: f64,
    first_conceal_ms: f64,
    // optional / tree
    dumpable: Option<bool>,
    children: Vec<PsgenProfile>,
    parent: Option<Box<PsgenProfile>>,
    tracer: Option<Box<PsgenProfile>>,
}

fn push_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn f64_json(v: f64) -> String {
    let clean = if v.is_finite() && v >= 0.0 { v } else { 0.0 };
    if clean.fract() == 0.0 {
        format!("{clean:.1}")
    } else {
        format!("{clean}")
    }
}

fn u32_vec_json(items: &[u32]) -> String {
    let mut out = String::from("[");
    for (i, n) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{n}");
    }
    out.push(']');
    out
}

impl PsgenProfile {
    fn to_json(&self) -> String {
        let mut out = String::with_capacity(2048);
        self.write_json(&mut out, 0);
        out.push('\n');
        out
    }

    fn write_json(&self, out: &mut String, depth: usize) {
        let ind = depth + 1;
        let ind2 = depth + 2;
        out.push_str("{\n");

        // 1. schema
        push_indent(out, ind);
        let _ = writeln!(out, "\"schema\": {},", self.schema);

        // 2. source
        push_indent(out, ind);
        out.push_str("\"source\": {\n");
        let mut src_fields = vec![
            format!("\"masker\": \"{}\"", json_escape(&self.masker)),
            format!("\"profile\": \"{}\"", json_escape(&self.profile)),
            format!("\"version\": \"{}\"", json_escape(&self.version)),
        ];
        if let Some(ouid) = self.observer_uid {
            src_fields.push(format!("\"observer_uid\": {ouid}"));
        }
        write_joined_fields(out, &src_fields, ind2);
        push_indent(out, ind);
        out.push_str("},\n");

        // 3. identity
        push_indent(out, ind);
        out.push_str("\"identity\": {\n");
        let mut id_fields = vec![
            format!("\"label\": \"{}\"", json_escape(&self.label)),
            format!("\"comm\": \"{}\"", json_escape(&self.comm)),
            format!("\"argv\": {}", str_vec_json(&self.argv)),
        ];
        if let Some(nuls) = self.cmdline_raw_nuls {
            id_fields.push(format!("\"cmdline_raw_nuls\": {nuls}"));
        }
        id_fields.push(format!("\"pid\": {}", self.pid.max(0)));
        id_fields.push(format!("\"ppid\": {}", self.ppid.max(0)));
        id_fields.push(format!("\"pgid\": {}", self.pgid));
        id_fields.push(format!("\"sid\": {}", self.sid));
        id_fields.push(format!("\"uid\": {}", self.uid));
        id_fields.push(format!("\"gid\": {}", self.gid));
        id_fields.push(format!("\"groups\": {}", u32_vec_json(&self.groups)));
        id_fields.push(format!("\"starttime\": {}", self.starttime));
        id_fields.push(format!("\"cwd\": \"{}\"", json_escape(&self.cwd)));
        id_fields.push(format!("\"root\": \"{}\"", json_escape(&self.root)));
        id_fields.push(format!("\"exe\": \"{}\"", json_escape(&self.exe)));
        if let Some(ref em) = self.exe_memfd {
            id_fields.push(format!("\"exe_memfd\": \"{}\"", json_escape(em)));
        }
        let mut ns_parts = Vec::new();
        if let Some(ref v) = self.ns_pid {
            ns_parts.push(format!("\"pid\": \"{}\"", json_escape(v)));
        }
        if let Some(ref v) = self.ns_mnt {
            ns_parts.push(format!("\"mnt\": \"{}\"", json_escape(v)));
        }
        if let Some(ref v) = self.ns_user {
            ns_parts.push(format!("\"user\": \"{}\"", json_escape(v)));
        }
        if let Some(ref v) = self.ns_net {
            ns_parts.push(format!("\"net\": \"{}\"", json_escape(v)));
        }
        id_fields.push(format!("\"ns\": {{{}}}", ns_parts.join(", ")));
        write_joined_fields(out, &id_fields, ind2);
        push_indent(out, ind);
        out.push_str("},\n");

        // 4. status
        push_indent(out, ind);
        out.push_str("\"status\": {\n");
        let mut st_fields = vec![
            format!("\"Name\": \"{}\"", json_escape(&self.st_name)),
            format!("\"State\": \"{}\"", json_escape(&self.st_state)),
            format!("\"PPid\": {}", self.st_ppid.max(0)),
            format!("\"Uid\": \"{}\"", json_escape(&self.st_uid)),
            format!("\"Gid\": \"{}\"", json_escape(&self.st_gid)),
            format!("\"Threads\": {}", self.st_threads.max(1)),
            format!("\"TracerPid\": {}", self.st_tracer_pid),
            format!("\"NoNewPrivs\": {}", self.st_no_new_privs),
            format!("\"Seccomp\": {}", self.st_seccomp),
            format!("\"Seccomp_filters\": {}", self.st_seccomp_filters),
            format!("\"CapEff\": \"{}\"", json_escape(&self.st_cap_eff)),
            format!("\"CapPrm\": \"{}\"", json_escape(&self.st_cap_prm)),
            format!("\"CapBnd\": \"{}\"", json_escape(&self.st_cap_bnd)),
        ];
        if let Some(v) = self.st_vm_lck {
            st_fields.push(format!("\"VmLck\": {v}"));
        }
        if let Some(v) = self.st_rss_shmem {
            st_fields.push(format!("\"RssShmem\": {v}"));
        }
        write_joined_fields(out, &st_fields, ind2);
        push_indent(out, ind);
        out.push_str("},\n");

        // 5. stat
        push_indent(out, ind);
        out.push_str("\"stat\": {\n");
        let mut stat_fields = vec![
            format!("\"ppid\": {}", self.stat_ppid.max(0)),
            format!("\"num_threads\": {}", self.stat_num_threads.max(1)),
            format!("\"starttime\": {}", self.stat_starttime),
            format!("\"vsize\": {}", self.stat_vsize),
            format!("\"rss\": {}", self.stat_rss),
        ];
        if let Some(fl) = self.stat_flags {
            stat_fields.push(format!("\"flags\": {fl}"));
        }
        stat_fields.push(format!("\"arg_start\": {}", self.stat_arg_start));
        stat_fields.push(format!("\"arg_end\": {}", self.stat_arg_end));
        stat_fields.push(format!("\"env_start\": {}", self.stat_env_start));
        stat_fields.push(format!("\"env_end\": {}", self.stat_env_end));
        stat_fields.push(format!("\"startstack\": {}", self.stat_startstack));
        write_joined_fields(out, &stat_fields, ind2);
        push_indent(out, ind);
        out.push_str("},\n");

        // 6. memory
        push_indent(out, ind);
        out.push_str("\"memory\": {\n");
        let mut mem_fields = vec![
            format!("\"maps\": {}", str_vec_json(&self.maps)),
            format!("\"smaps\": {}", str_vec_json(&self.smaps)),
            format!("\"token_present\": {}", bool_json(self.token_present)),
            format!(
                "\"token_sha256\": {}",
                opt_str_json(self.token_sha256.as_deref())
            ),
        ];
        if let Some(tlen) = self.token_len {
            mem_fields.push(format!("\"token_len\": {tlen}"));
        }
        if let Some(ref cs) = self.token_charset {
            mem_fields.push(format!("\"token_charset\": \"{}\"", json_escape(cs)));
        }
        mem_fields.push(format!(
            "\"token_placements\": {}",
            str_vec_json(&self.token_placements)
        ));
        mem_fields.push(format!(
            "\"readable_by\": {}",
            str_vec_json(&self.readable_by)
        ));
        mem_fields.push(format!("\"denied_by\": {}", str_vec_json(&self.denied_by)));
        write_joined_fields(out, &mem_fields, ind2);
        push_indent(out, ind);
        out.push_str("},\n");

        // 7. fds
        push_indent(out, ind);
        if self.fds.is_empty() {
            out.push_str("\"fds\": [],\n");
        } else {
            out.push_str("\"fds\": [\n");
            for (i, (fd, target)) in self.fds.iter().enumerate() {
                push_indent(out, ind2);
                let comma = if i + 1 < self.fds.len() { "," } else { "" };
                let _ = writeln!(
                    out,
                    "{{\"fd\": {}, \"target\": \"{}\"}}{}",
                    (*fd).max(0),
                    json_escape(target),
                    comma
                );
            }
            push_indent(out, ind);
            out.push_str("],\n");
        }

        // 8. auxv
        push_indent(out, ind);
        out.push_str("\"auxv\": {\n");
        let auxv_fields = vec![
            format!("\"AT_EXECFN\": {}", opt_str_json(self.at_execfn.as_deref())),
            format!(
                "\"AT_PLATFORM\": {}",
                opt_str_json(self.at_platform.as_deref())
            ),
            format!("\"AT_BASE\": {}", self.at_base),
            format!("\"AT_ENTRY\": {}", self.at_entry),
        ];
        write_joined_fields(out, &auxv_fields, ind2);
        push_indent(out, ind);
        out.push_str("},\n");

        // 9-11. environ, environ_raw_len, environ_all_nul
        push_indent(out, ind);
        let _ = writeln!(out, "\"environ\": {},", str_vec_json(&self.environ));
        push_indent(out, ind);
        let _ = writeln!(out, "\"environ_raw_len\": {},", self.environ_raw_len);
        push_indent(out, ind);
        let _ = writeln!(
            out,
            "\"environ_all_nul\": {},",
            bool_json(self.environ_all_nul)
        );

        // 12. task
        push_indent(out, ind);
        if self.task.is_empty() {
            out.push_str("\"task\": [],\n");
        } else {
            out.push_str("\"task\": [\n");
            for (i, (tid, comm, state)) in self.task.iter().enumerate() {
                push_indent(out, ind2);
                let comma = if i + 1 < self.task.len() { "," } else { "" };
                let _ = writeln!(
                    out,
                    "{{\"tid\": {}, \"comm\": \"{}\", \"state\": \"{}\"}}{}",
                    tid,
                    json_escape(comm),
                    json_escape(state),
                    comma
                );
            }
            push_indent(out, ind);
            out.push_str("],\n");
        }

        // 13. syscall
        push_indent(out, ind);
        out.push_str("\"syscall\": {\n");
        let sys_fields = vec![
            format!("\"syscall\": \"{}\"", json_escape(&self.syscall_name)),
            format!("\"wchan\": \"{}\"", json_escape(&self.wchan)),
            format!("\"policy\": {}", self.policy),
            format!("\"priority\": {}", self.priority),
        ];
        write_joined_fields(out, &sys_fields, ind2);
        push_indent(out, ind);
        out.push_str("},\n");

        // 14. timing
        push_indent(out, ind);
        out.push_str("\"timing\": {\n");
        let time_fields = vec![
            format!("\"exec_ms\": {}", f64_json(self.exec_ms)),
            format!("\"first_conceal_ms\": {}", f64_json(self.first_conceal_ms)),
        ];
        write_joined_fields(out, &time_fields, ind2);
        push_indent(out, ind);
        out.push_str("},\n");

        // 15. optional dumpable
        if let Some(d) = self.dumpable {
            push_indent(out, ind);
            let _ = writeln!(out, "\"dumpable\": {},", bool_json(d));
        }

        // 16. children (+ optional 17. parent, 18. tracer)
        let has_parent = self.parent.is_some();
        let has_tracer = self.tracer.is_some();
        let children_comma = if has_parent || has_tracer { "," } else { "" };
        push_indent(out, ind);
        if self.children.is_empty() {
            let _ = writeln!(out, "\"children\": []{children_comma}");
        } else {
            out.push_str("\"children\": [\n");
            for (i, ch) in self.children.iter().enumerate() {
                push_indent(out, ind2);
                ch.write_json(out, ind2);
                if i + 1 < self.children.len() {
                    out.push_str(",\n");
                } else {
                    out.push('\n');
                }
            }
            push_indent(out, ind);
            let _ = writeln!(out, "]{children_comma}");
        }

        if let Some(ref p) = self.parent {
            push_indent(out, ind);
            out.push_str("\"parent\": ");
            p.write_json(out, ind);
            if has_tracer {
                out.push_str(",\n");
            } else {
                out.push('\n');
            }
        }
        if let Some(ref t) = self.tracer {
            push_indent(out, ind);
            out.push_str("\"tracer\": ");
            t.write_json(out, ind);
            out.push('\n');
        }

        push_indent(out, depth);
        out.push('}');
    }
}

fn write_joined_fields(out: &mut String, fields: &[String], indent: usize) {
    for (i, f) in fields.iter().enumerate() {
        push_indent(out, indent);
        out.push_str(f);
        if i + 1 < fields.len() {
            out.push_str(",\n");
        } else {
            out.push('\n');
        }
    }
}

/// Export the observable profile of a live process in native `psgen` `schema: 2` JSON.
///
/// If `token` is provided, its SHA-256 hex digest is recorded in
/// `memory.token_sha256` and `memory.token_present` records whether it was
/// observed, while any raw occurrence of `token`, sensitive environment keys,
/// and inline secret patterns are scrubbed so secret bytes are never emitted.
pub fn export_profile_for_pid(
    pid: libc::pid_t,
    profile: Profile,
    label: Option<&str>,
    token: Option<&[u8]>,
) -> io::Result<String> {
    let mut visited = Vec::new();
    let needles = SecretNeedles::from_opt(token);
    let p = extract_psgen_profile_for_pid(pid, profile, label, token, &needles, 0, &mut visited)?;
    Ok(p.to_json())
}

fn extract_psgen_profile_for_pid(
    pid: libc::pid_t,
    profile: Profile,
    label: Option<&str>,
    token: Option<&[u8]>,
    needles: &SecretNeedles,
    depth: usize,
    visited: &mut Vec<libc::pid_t>,
) -> io::Result<PsgenProfile> {
    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pid must be a positive integer",
        ));
    }
    if !visited.contains(&pid) {
        visited.push(pid);
    }

    let mut opts = AuditOptions::new(pid, profile);
    opts.label = label.map(ToOwned::to_owned);
    opts.token = token.map(|t| t.to_vec());
    let report = audit_pid(&opts)?;
    let snap = &report.surfaces;
    let base = format!("/proc/{pid}");

    let mut prof = psgen_profile_from_snapshot(
        snap,
        profile,
        label,
        report.token_present,
        report.token_sha256.as_deref(),
        token,
        needles,
    );

    // Enrich with full live /proc/<pid> details needed by psgen schema: 2.
    if let Ok(stat_text) = read_bounded_string(&format!("{base}/stat"), 16 * 1024) {
        if let Some(rp) = stat_text.rfind(')') {
            let fields: Vec<&str> = stat_text[rp + 1..].split_ascii_whitespace().collect();
            let get_u64 = |idx: usize| -> u64 {
                fields
                    .get(idx)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
            };
            let get_i32 = |idx: usize| -> i32 {
                fields
                    .get(idx)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0)
            };
            if let Some(&st) = fields.first() {
                if !st.is_empty() {
                    prof.st_state = st.to_string();
                }
            }
            prof.pgid = get_i32(2);
            prof.sid = get_i32(3);
            prof.stat_flags = Some(get_u64(6));
            prof.priority = get_i32(15);
            prof.stat_vsize = get_u64(20);
            prof.stat_rss = get_u64(21);
            prof.stat_startstack = get_u64(25);
            prof.policy = get_i32(38);
        }
    }

    if let Ok(status_text) = read_bounded_string(&format!("{base}/status"), 64 * 1024) {
        for line in status_text.lines() {
            let Some((k, raw_v)) = line.split_once(':') else {
                continue;
            };
            let v = raw_v.trim();
            match k {
                "State" => {
                    if let Some(code) = v.split_ascii_whitespace().next() {
                        prof.st_state = code.to_string();
                    }
                }
                "Uid" => {
                    let cols: Vec<&str> = v.split_ascii_whitespace().collect();
                    if !cols.is_empty() {
                        prof.st_uid = cols.join(" ");
                        if let Some(euid) = cols
                            .get(1)
                            .or_else(|| cols.first())
                            .and_then(|s| s.parse::<u32>().ok())
                        {
                            prof.uid = euid;
                        }
                    }
                }
                "Gid" => {
                    let cols: Vec<&str> = v.split_ascii_whitespace().collect();
                    if !cols.is_empty() {
                        prof.st_gid = cols.join(" ");
                        if let Some(egid) = cols
                            .get(1)
                            .or_else(|| cols.first())
                            .and_then(|s| s.parse::<u32>().ok())
                        {
                            prof.gid = egid;
                        }
                    }
                }
                "Groups" => {
                    prof.groups = v
                        .split_ascii_whitespace()
                        .filter_map(|t| t.parse::<u32>().ok())
                        .collect();
                }
                "CapEff" => prof.st_cap_eff = v.to_string(),
                "CapPrm" => prof.st_cap_prm = v.to_string(),
                "CapBnd" => prof.st_cap_bnd = v.to_string(),
                "VmLck" => {
                    prof.st_vm_lck = v
                        .split_ascii_whitespace()
                        .next()
                        .and_then(|s| s.parse::<u64>().ok());
                }
                "RssShmem" => {
                    prof.st_rss_shmem = v
                        .split_ascii_whitespace()
                        .next()
                        .and_then(|s| s.parse::<u64>().ok());
                }
                _ => {}
            }
        }
    }

    prof.ns_net = fs::read_link(format!("{base}/ns/net"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    if let Ok(maps_text) = read_bounded_string(&format!("{base}/maps"), MAX_PROC_READ_BYTES) {
        prof.maps = normalize_maps_for_profile(&maps_text, needles);
    }
    if let Ok(smaps_text) = read_bounded_string(&format!("{base}/smaps"), MAX_PROC_READ_BYTES) {
        prof.smaps = normalize_smaps_for_profile(&smaps_text, needles);
    }

    if let Ok(raw_env) = read_bounded_bytes(&format!("{base}/environ"), MAX_PROC_READ_BYTES) {
        prof.environ_raw_len = raw_env.len() as u64;
        prof.environ_all_nul = !raw_env.is_empty() && raw_env.iter().all(|&b| b == 0);
        prof.environ = filter_and_scrub_profile_environ(&raw_env, depth, needles);
    }

    if let Ok(entries) = fs::read_dir(format!("{base}/fd")) {
        let mut fds = Vec::new();
        for entry in entries.flatten() {
            if let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() {
                if fd >= 0 {
                    if let Ok(target) = fs::read_link(entry.path()) {
                        let t = scrub_profile_str(&target.to_string_lossy(), needles);
                        fds.push((fd, t));
                    }
                }
            }
        }
        fds.sort_by_key(|(fd, _)| *fd);
        prof.fds = fds;
    }

    if let Ok(entries) = fs::read_dir(format!("{base}/task")) {
        let mut tasks = Vec::new();
        for entry in entries.flatten() {
            if let Ok(tid) = entry.file_name().to_string_lossy().parse::<i32>() {
                let tcomm = read_bounded_string(&entry.path().join("comm").to_string_lossy(), 256)
                    .ok()
                    .map(|s| s.trim_end_matches(['\n', '\r']).to_string())
                    .filter(|s| !s.is_empty())
                    .map(|s| scrub_profile_str(&s, needles))
                    .unwrap_or_else(|| prof.comm.clone());
                let tstate =
                    read_bounded_string(&entry.path().join("stat").to_string_lossy(), 4096)
                        .ok()
                        .and_then(|s| {
                            let rp = s.rfind(')')?;
                            s[rp + 1..]
                                .split_ascii_whitespace()
                                .next()
                                .map(ToOwned::to_owned)
                        })
                        .unwrap_or_else(|| prof.st_state.clone());
                tasks.push((tid, tcomm, tstate));
            }
        }
        tasks.sort_by_key(|(tid, _, _)| *tid);
        if !tasks.is_empty() {
            prof.task = tasks;
        }
    }

    // 1-level children, parent, and tracer capture (avoiding cycles).
    if depth == 0 {
        for cpid in discover_direct_children(pid) {
            if !visited.contains(&cpid) {
                if let Ok(child_prof) = extract_psgen_profile_for_pid(
                    cpid,
                    profile,
                    None,
                    token,
                    needles,
                    depth + 1,
                    visited,
                ) {
                    prof.children.push(child_prof);
                }
            }
        }

        let ppid = prof.ppid;
        let capture_parent = ppid > 1
            && !visited.contains(&ppid)
            && (snap.misc.parent_is_twin
                || prof.st_tracer_pid > 0
                || matches!(profile, Profile::Tree | Profile::Tee | Profile::Compat));
        if capture_parent {
            let pcomm = read_bounded_string(&format!("/proc/{ppid}/comm"), 256)
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if !is_stop_ancestor_comm(&pcomm) {
                if let Ok(parent_prof) = extract_psgen_profile_for_pid(
                    ppid,
                    profile,
                    None,
                    token,
                    needles,
                    depth + 1,
                    visited,
                ) {
                    prof.parent = Some(Box::new(parent_prof));
                }
            }
        }

        let tpid = prof.st_tracer_pid;
        if tpid > 0 && !visited.contains(&tpid) {
            if let Ok(tracer_prof) = extract_psgen_profile_for_pid(
                tpid,
                profile,
                None,
                token,
                needles,
                depth + 1,
                visited,
            ) {
                prof.tracer = Some(Box::new(tracer_prof));
            }
        }
    }

    Ok(prof)
}

/// Options shaping a static `psgen` `schema: 2` JSON template emitted by
/// [`export_profile_template_with`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TemplateOptions {
    /// `--reparent` was requested (only applies to [`Profile::Single`]).
    pub reparent: bool,
    /// `--allow-dumpable` was requested (keeps `PR_SET_DUMPABLE=1`).
    pub allow_dumpable: bool,
    /// `--no-dumpable` was explicitly requested (relevant to [`Profile::Compat`]).
    pub no_dumpable: bool,
    /// `--cwd` was explicitly set.
    pub cwd_override: bool,
    /// `--no-rexec` was requested.
    pub no_rexec: bool,
    /// `--rexec-mode=memfd` (or a memfd-preferring flag) was requested.
    pub memfd_rexec: bool,
}

/// Export a static `psgen` `schema: 2` JSON template without probing a live PID,
/// using default options for `profile`.
pub fn export_profile_template(profile: Profile, label: &str, cmdline: &[String]) -> String {
    export_profile_template_with(profile, label, cmdline, &TemplateOptions::default())
}

/// Export a static `psgen` `schema: 2` JSON template reflecting `opts`
/// (`--reparent`, `--allow-dumpable`, `--cwd`, `--no-rexec`, `--rexec-mode`).
pub fn export_profile_template_with(
    profile: Profile,
    label: &str,
    cmdline: &[String],
    opts: &TemplateOptions,
) -> String {
    // SAFETY: getuid(2) and getgid(2) are always safe.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let empty_needles = SecretNeedles::from_opt(None);
    let clean_label = {
        let s = scrub_profile_str(label.trim(), &empty_needles);
        if s.is_empty() {
            "pmask".to_string()
        } else {
            s
        }
    };
    let clean_comm = {
        let c = truncate_utf8_bytes(&clean_label, COMM_MAX).trim();
        if c.is_empty() {
            "pmask".to_string()
        } else {
            c.to_string()
        }
    };
    let argv: Vec<String> = if cmdline.is_empty() {
        vec![clean_label.clone()]
    } else {
        cmdline
            .iter()
            .map(|a| scrub_profile_str(a, &empty_needles))
            .collect()
    };

    let effective_dumpable = match profile {
        Profile::Single | Profile::Tree | Profile::Tee | Profile::Auto => opts.allow_dumpable,
        Profile::Compat => !opts.no_dumpable,
    };

    let (ppid, tracer_pid) = match profile {
        Profile::Single | Profile::Auto => {
            if opts.reparent {
                (1, 0)
            } else {
                (0, 0)
            }
        }
        Profile::Tree | Profile::Tee | Profile::Compat => (0, 1),
    };

    // In `Profile::Tee`, Linux `cap_capable()` grants the user-namespace
    // creator uid `CAP_SYS_PTRACE` over the child userns, leaving `exe`
    // (staged path), `maps`/`smaps`, and `cwd` (`/`) readable to a same-uid
    // host observer even with `PR_SET_DUMPABLE=0`, while `environ`, `mem`,
    // `auxv`, and `fd` return `EACCES` via root:root VFS DAC.
    let read_surfaces_visible = effective_dumpable || profile == Profile::Tee;
    let (exe, exe_memfd) = if !read_surfaces_visible {
        (String::new(), None)
    } else if opts.no_rexec || profile == Profile::Compat {
        (format!("/usr/bin/{clean_comm}"), None)
    } else if opts.memfd_rexec {
        (
            format!("/memfd:{clean_comm} (deleted)"),
            Some(clean_comm.clone()),
        )
    } else {
        (format!("/run/user/{uid}/{clean_comm}"), None)
    };

    let cwd = if !read_surfaces_visible {
        String::new()
    } else if opts.cwd_override || profile == Profile::Tee {
        "/".to_string()
    } else {
        "/srv/work".to_string()
    };

    let mut readable_by = vec![format!("uid:{uid}")];
    let mut denied_by = Vec::new();
    if effective_dumpable {
        for s in [
            "environ", "mem", "maps", "smaps", "auxv", "exe", "fd", "cwd",
        ] {
            readable_by.push(s.to_string());
        }
    } else if profile == Profile::Tee {
        for s in ["exe", "maps", "smaps", "cwd"] {
            readable_by.push(s.to_string());
        }
        for s in ["environ", "mem", "auxv", "fd"] {
            denied_by.push(s.to_string());
        }
    } else {
        for s in [
            "environ", "mem", "maps", "smaps", "auxv", "exe", "fd", "cwd",
        ] {
            denied_by.push(s.to_string());
        }
    }

    let uid_line = format!("{uid} {uid} {uid} {uid}");
    let gid_line = format!("{gid} {gid} {gid} {gid}");
    let at_execfn = if effective_dumpable && !exe.is_empty() {
        Some(exe.clone())
    } else {
        None
    };

    let prof = PsgenProfile {
        schema: PROFILE_SCHEMA_VERSION,
        masker: "pmask".to_string(),
        profile: profile.as_str().to_string(),
        version: crate::VERSION.to_string(),
        observer_uid: Some(uid),
        label: clean_label,
        comm: clean_comm.clone(),
        argv,
        cmdline_raw_nuls: Some(1),
        pid: 0,
        ppid,
        pgid: 0,
        sid: 0,
        uid,
        gid,
        groups: Vec::new(),
        starttime: 0,
        cwd,
        root: "/".to_string(),
        exe,
        exe_memfd,
        ns_pid: None,
        ns_mnt: None,
        ns_user: None,
        ns_net: None,
        st_name: clean_comm.clone(),
        st_state: "S".to_string(),
        st_ppid: ppid,
        st_uid: uid_line,
        st_gid: gid_line,
        st_threads: 1,
        st_tracer_pid: tracer_pid,
        st_no_new_privs: 0,
        st_seccomp: 0,
        st_seccomp_filters: 0,
        st_cap_eff: "0000000000000000".to_string(),
        st_cap_prm: "0000000000000000".to_string(),
        st_cap_bnd: "0000000000000000".to_string(),
        st_vm_lck: None,
        st_rss_shmem: None,
        stat_ppid: ppid,
        stat_num_threads: 1,
        stat_starttime: 0,
        stat_vsize: 0,
        stat_rss: 0,
        stat_flags: None,
        stat_arg_start: 0,
        stat_arg_end: 0,
        stat_env_start: 0,
        stat_env_end: 0,
        stat_startstack: 0,
        maps: Vec::new(),
        smaps: Vec::new(),
        token_present: false,
        token_sha256: None,
        token_len: None,
        token_charset: None,
        token_placements: Vec::new(),
        readable_by,
        denied_by,
        fds: Vec::new(),
        at_execfn,
        at_platform: Some(std::env::consts::ARCH.to_string()),
        at_base: 0,
        at_entry: 0,
        environ: Vec::new(),
        environ_raw_len: 0,
        environ_all_nul: false,
        task: vec![(0, clean_comm, "S".to_string())],
        syscall_name: "unknown".to_string(),
        wchan: String::new(),
        policy: 0,
        priority: 20,
        exec_ms: 0.0,
        first_conceal_ms: 0.0,
        dumpable: Some(effective_dumpable),
        children: Vec::new(),
        parent: None,
        tracer: None,
    };
    prof.to_json()
}

fn format_profile_json_from_snapshot(
    snap: &ProcSnapshot,
    profile: Profile,
    label: Option<&str>,
    token_present: bool,
    token_sha256: Option<&str>,
    token: Option<&[u8]>,
    needles: &SecretNeedles,
) -> String {
    psgen_profile_from_snapshot(
        snap,
        profile,
        label,
        token_present,
        token_sha256,
        token,
        needles,
    )
    .to_json()
}

fn psgen_profile_from_snapshot(
    snap: &ProcSnapshot,
    profile: Profile,
    label: Option<&str>,
    token_present: bool,
    token_sha256: Option<&str>,
    token: Option<&[u8]>,
    needles: &SecretNeedles,
) -> PsgenProfile {
    let comm_raw = snap
        .comm
        .value
        .as_deref()
        .or(snap.status.name.as_deref())
        .or(label)
        .unwrap_or("pmask");
    let comm_clean = {
        let s = scrub_profile_str(comm_raw.trim(), needles);
        if s.is_empty() {
            "pmask".to_string()
        } else {
            s
        }
    };
    let label_clean = {
        let raw = label.unwrap_or(&comm_clean);
        let s = scrub_profile_str(raw.trim(), needles);
        if s.is_empty() {
            comm_clean.clone()
        } else {
            s
        }
    };
    let argv: Vec<String> = snap
        .cmdline
        .argv
        .iter()
        .map(|a| scrub_profile_str(a, needles))
        .collect();
    let exe = snap
        .exe
        .path
        .as_deref()
        .map(|p| scrub_profile_str(p, needles))
        .unwrap_or_default();
    let exe_memfd = detect_exe_memfd(&exe);
    let cwd = snap
        .cwd
        .path
        .as_deref()
        .map(|p| scrub_profile_str(p, needles))
        .unwrap_or_default();
    let root = snap
        .root
        .path
        .as_deref()
        .map(|p| scrub_profile_str(p, needles))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/".to_string());

    let ppid = if snap.status.status == AccessStatus::Readable {
        snap.status.ppid.max(0)
    } else {
        snap.stat.ppid.max(0)
    };
    let uid = snap.target_uid.unwrap_or(snap.observer_uid);
    let euid = snap.status.euid.unwrap_or(uid);
    let threads = snap.status.threads.max(snap.stat.num_threads).max(1);

    let mut readable_by = vec![format!("uid:{}", snap.observer_uid)];
    let mut denied_by = Vec::new();
    for (name, st) in [
        ("environ", snap.environ.status),
        ("auxv", snap.auxv.status),
        ("exe", snap.exe.status),
        ("maps", snap.maps.status),
        ("smaps", snap.maps.smaps_status),
        ("fd", snap.fd.status),
        ("cwd", snap.cwd.status),
    ] {
        match st {
            AccessStatus::Readable => readable_by.push(name.to_string()),
            AccessStatus::DeniedEacces => denied_by.push(name.to_string()),
            AccessStatus::Error => {}
        }
    }
    match snap.mem.status {
        MemScanStatus::DeniedEacces => denied_by.push("mem".to_string()),
        MemScanStatus::Clean | MemScanStatus::Leaked => readable_by.push("mem".to_string()),
        MemScanStatus::SkippedNoToken => {}
    }

    let mut token_placements = Vec::new();
    if snap.cmdline.has_token {
        token_placements.push("argv".to_string());
    }
    if snap.environ.has_token {
        token_placements.push("environ".to_string());
    }
    if snap.mem.status == MemScanStatus::Leaked {
        let pl = match snap.mem.leaked_mapping.as_deref() {
            Some("[heap]") => "heap",
            Some(m) if m.starts_with("[stack") => "stack",
            _ => "anon",
        };
        if !token_placements.iter().any(|p| p == pl) {
            token_placements.push(pl.to_string());
        }
    }

    let (token_len, token_charset) = if token_present {
        if let Some(tok_bytes) = token.filter(|t| !t.is_empty()) {
            let tlen = u32::try_from(tok_bytes.len()).ok();
            let cs = std::str::from_utf8(tok_bytes)
                .ok()
                .map(classify_token_charset);
            (tlen, cs)
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let at_execfn = snap
        .auxv
        .at_execfn_str
        .as_deref()
        .map(|s| scrub_profile_str(s, needles));
    let at_platform = snap
        .auxv
        .at_platform
        .as_deref()
        .map(|s| scrub_profile_str(s, needles))
        .or_else(|| Some(std::env::consts::ARCH.to_string()));

    PsgenProfile {
        schema: PROFILE_SCHEMA_VERSION,
        masker: "pmask".to_string(),
        profile: profile.as_str().to_string(),
        version: crate::VERSION.to_string(),
        observer_uid: Some(snap.observer_uid),
        label: label_clean,
        comm: comm_clean.clone(),
        argv,
        cmdline_raw_nuls: Some(snap.cmdline.trailing_nuls),
        pid: snap.pid.max(0),
        ppid,
        pgid: snap.pid.max(0),
        sid: snap.pid.max(0),
        uid: euid,
        gid: euid,
        groups: Vec::new(),
        starttime: snap.stat.starttime,
        cwd,
        root,
        exe,
        exe_memfd,
        ns_pid: snap.misc.ns_pid.clone(),
        ns_mnt: snap.misc.ns_mnt.clone(),
        ns_user: snap.misc.ns_user.clone(),
        ns_net: None,
        st_name: comm_clean.clone(),
        st_state: "S".to_string(),
        st_ppid: ppid,
        st_uid: format!("{uid} {euid} {euid} {euid}"),
        st_gid: format!("{uid} {euid} {euid} {euid}"),
        st_threads: threads,
        st_tracer_pid: snap.status.tracer_pid,
        st_no_new_privs: snap.status.no_new_privs,
        st_seccomp: snap.status.seccomp,
        st_seccomp_filters: snap.status.seccomp_filters,
        st_cap_eff: "0000000000000000".to_string(),
        st_cap_prm: "0000000000000000".to_string(),
        st_cap_bnd: "0000000000000000".to_string(),
        st_vm_lck: None,
        st_rss_shmem: None,
        stat_ppid: ppid,
        stat_num_threads: threads,
        stat_starttime: snap.stat.starttime,
        stat_vsize: 0,
        stat_rss: snap.statm.rss_pages,
        stat_flags: None,
        stat_arg_start: snap.stat.arg_start,
        stat_arg_end: snap.stat.arg_end,
        stat_env_start: snap.stat.env_start,
        stat_env_end: snap.stat.env_end,
        stat_startstack: 0,
        maps: Vec::new(),
        smaps: Vec::new(),
        token_present,
        token_sha256: token_sha256.map(ToOwned::to_owned),
        token_len,
        token_charset,
        token_placements,
        readable_by,
        denied_by,
        fds: Vec::new(),
        at_execfn,
        at_platform,
        at_base: snap.auxv.at_base.unwrap_or(0),
        at_entry: snap.auxv.at_entry.unwrap_or(0),
        environ: Vec::new(),
        environ_raw_len: 0,
        environ_all_nul: false,
        task: vec![(snap.pid.max(0), comm_clean, "S".to_string())],
        syscall_name: decode_syscall_name(snap.misc.syscall.as_deref()),
        wchan: snap.misc.wchan.clone().unwrap_or_default(),
        policy: 0,
        priority: 20,
        exec_ms: 0.0,
        first_conceal_ms: 0.0,
        dumpable: snap.dumpable_zero.map(|z| !z),
        children: Vec::new(),
        parent: None,
        tracer: None,
    }
}

/// Host subuid / helper-uid availability detected for `--explain`.
struct SubuidStatus {
    uid_map_entries: u64,
    has_etc_subuid: bool,
    helper_uid_ready: bool,
}

fn detect_subuid_status() -> SubuidStatus {
    let uid_map_entries = read_bounded_string("/proc/self/uid_map", 4096)
        .ok()
        .map(|text| {
            text.lines()
                .filter_map(|l| l.split_whitespace().nth(2)?.parse::<u64>().ok())
                .sum()
        })
        .unwrap_or(0);

    // SAFETY: getuid(2) is always safe.
    let uid = unsafe { libc::getuid() };
    let uid_str = uid.to_string();
    let user_env = std::env::var("USER").ok();

    let has_etc_subuid = read_bounded_string("/etc/subuid", 64 * 1024)
        .ok()
        .is_some_and(|text| {
            text.lines().any(|line| {
                let mut parts = line.split(':');
                let Some(entry_user) = parts.next() else {
                    return false;
                };
                let _start = parts.next();
                let count = parts
                    .next()
                    .and_then(|c| c.trim().parse::<u64>().ok())
                    .unwrap_or(0);
                let matches_me = entry_user == uid_str || user_env.as_deref() == Some(entry_user);
                matches_me && count >= 2
            })
        });

    let helper_uid_ready = has_etc_subuid || uid_map_entries > 1;
    SubuidStatus {
        uid_map_entries,
        has_etc_subuid,
        helper_uid_ready,
    }
}

/// Render the `--explain` report for `profile` and `label` in text or JSON.
///
/// Uses [`Caps::detect`] plus `/proc/self/uid_map` and `/etc/subuid` to show
/// the active host capabilities, named observer, explicit non-goals, hidden
/// surfaces, `EACCES` denial tradeoff, and honest residuals.
pub fn render_explain(profile: Profile, label: &str, json: bool) -> String {
    let caps = Caps::detect();
    let hidepid = proc_hidepid();
    let subuid = detect_subuid_status();
    let observer = "same-uid local observer, no root";
    let non_goals = [
        "root and CAP_SYS_PTRACE observers on the same kernel",
        "kernel modules, eBPF/perf tracers, hypervisors, or hardware TEE attackers",
        "network observers",
        "generating decoy populations (owned by psgen via --profile-json)",
    ];

    let profile_ranking = [
        "1. single (#1 for direct native ELFs: zero persistent supervisor, TracerPid: 0)",
        "2. tree (shells, #! scripts, and multi-process descendants; --stealth is a tree preset)",
        "3. pmaskd --run-as-uid=UID[:GID] / subuid (cross-UID isolation with zero same-uid EACCES)",
        "4. tee (fail-closed user/pid/mount namespaces with private /proc, private /tmp, and cwd=/)",
    ];

    let (hidden, denied, residuals): (&[&str], &[&str], &[&str]) = match profile {
        Profile::Single => (
            &[
                "cmdline (exact label, no trailing NUL padding)",
                "comm (matches label)",
                "environ (minimal decoy environment, no secret)",
                "exe and maps (staged private path via --rexec-mode=auto/path/tmpfile, no real payload path)",
                "secrets delivered via --secret-fd rather than argv/environ",
            ],
            &[
                "same-uid /proc/<pid>/mem, environ, auxv, exe, maps, fd, and cwd via PR_SET_DUMPABLE=0 (returns EACCES unless isolated by a separate host uid via pmaskd --run-as-uid)",
            ],
            &[
                "cwd stays real unless --cwd PATH is passed (denied via EACCES while non-dumpable; use --profile tee for automatic cwd=/)",
                "EACCES on same-uid /proc reads is an observable denial signal unless a separate host uid (pmaskd --run-as-uid) or subuid namespace is used",
                "kernel zeroes /proc/<pid>/stat fields 48-51 (arg_start..env_end) while dumpable=0",
                "root, CAP_SYS_PTRACE, and kernel-level observers remain out of scope",
            ],
        ),
        Profile::Tree => (
            &[
                "cmdline, comm, environ, and AT_EXECFN across the full descendant process tree",
                "comm kept pinned under rename supervision when enabled",
                "supervisor at-rest argv/environ encrypted in locked memory when enabled",
            ],
            &[
                "same-uid /proc/<pid>/mem, environ, auxv, exe, maps, fd via PR_SET_DUMPABLE=0 (returns EACCES)",
            ],
            &[
                "visible supervisor parent process and non-zero TracerPid while tracing descendants",
                "EACCES denial signal on same-uid /proc reads",
                "memfd path visible if --rexec memfd fallback is active",
                "root, CAP_SYS_PTRACE, and kernel-level observers remain out of scope",
            ],
        ),
        Profile::Tee => (
            &[
                "payload runs inside isolated user/pid/mount namespaces with private /proc and /tmp (isolates host from payload)",
                "cmdline, comm, environ, and AT_EXECFN redacted across the namespace tree",
                "exe and maps staged at a private path (--rexec-mode=auto) and cwd normalized to / by default",
                "RLIMIT_CORE=0, MADV_DONTDUMP, and PR_SET_DUMPABLE=0 applied to the isolated child",
            ],
            &[
                "same-uid /proc/<pid>/mem, environ, auxv, and fd return EACCES via PR_SET_DUMPABLE=0 VFS DAC ownership (root:root)",
                "Linux cap_capable() grants the userns creator uid CAP_SYS_PTRACE over the child userns, so exe, maps, cwd, and stat 48-51 stay readable to same-uid host observers (but hide real exe/cwd via staged rexec and default cwd=/)",
            ],
            &[
                "requires unprivileged user namespaces; host->payload isolation of exe/maps/cwd/stat requires a separate host uid (pmaskd) or a microVM rather than a same-uid userns (use --profile single or tree for EACCES on all seven surfaces under the same uid)",
                "visible supervisor parent process and non-zero TracerPid in the host PID namespace",
                "root on the host, kernel bugs, and VM escape remain out of scope",
            ],
        ),
        Profile::Auto => (
            &[
                "selects 'single' for single-process native ELFs (no persistent tracer) and 'tree' for shells, launchers, and #! scripts",
                "redacts cmdline, comm, environ, and sets non-dumpable core-dump hygiene",
            ],
            &[
                "same-uid /proc/<pid>/mem, environ, auxv, exe, maps, fd via PR_SET_DUMPABLE=0 (returns EACCES)",
            ],
            &[
                "residuals depend on whether auto resolves to single (EACCES, zeroed stat spans) or tree (visible supervisor, TracerPid)",
                "root, CAP_SYS_PTRACE, and kernel-level observers remain out of scope",
            ],
        ),
        Profile::Compat => (
            &[
                "legacy flag-composed redaction of cmdline, comm, environ, and AT_EXECFN",
            ],
            &[
                "same-uid /proc/<pid>/mem and environ denied only when --no-dumpable or --stealth is enabled",
            ],
            &[
                "default compat leaves exe, maps, cwd, and same-uid mem readable unless additional flags are passed",
                "visible supervisor and TracerPid unless --detach is passed",
                "root, CAP_SYS_PTRACE, and kernel-level observers remain out of scope",
            ],
        ),
    };

    let policy_warning = check_label_policy(Some(label), None, false)
        .err()
        .map(|e| e.to_string());

    if json {
        let mut out = String::with_capacity(2048);
        let _ = writeln!(out, "{{");
        let _ = writeln!(out, "  \"profile\": \"{}\",", profile.as_str());
        let _ = writeln!(out, "  \"profile_version\": {PROFILE_VERSION},");
        let _ = writeln!(out, "  \"label\": \"{}\",", json_escape(label));
        let _ = writeln!(
            out,
            "  \"label_policy_warning\": {},",
            opt_str_json(policy_warning.as_deref())
        );
        let _ = writeln!(out, "  \"observer\": \"{}\",", json_escape(observer));
        let _ = writeln!(out, "  \"non_goals\": {},", slice_str_json(&non_goals));
        let _ = writeln!(out, "  \"host\": {{");
        let _ = writeln!(out, "    \"arch\": \"{}\",", json_escape(caps.arch));
        let _ = writeln!(out, "    \"kernel\": \"{}\",", json_escape(&caps.kernel));
        let _ = writeln!(out, "    \"tier\": \"{}\",", caps.tier_word());
        let _ = writeln!(out, "    \"ptrace\": {},", bool_json(caps.ptrace));
        let _ = writeln!(out, "    \"userns\": {},", bool_json(caps.userns));
        let _ = writeln!(
            out,
            "    \"memfd_secret\": {},",
            bool_json(caps.memfd_secret)
        );
        let _ = writeln!(out, "    \"mlock\": {},", bool_json(caps.mlock));
        let _ = writeln!(
            out,
            "    \"non_dumpable\": {},",
            bool_json(caps.non_dumpable)
        );
        let _ = writeln!(out, "    \"set_mm_map\": {},", bool_json(caps.set_mm_map));
        let _ = writeln!(out, "    \"landlock_abi\": {},", caps.landlock_abi);
        let _ = writeln!(out, "    \"hidepid\": \"{}\",", hidepid.as_word());
        let _ = writeln!(out, "    \"uid_map_entries\": {},", subuid.uid_map_entries);
        let _ = writeln!(
            out,
            "    \"etc_subuid_configured\": {},",
            bool_json(subuid.has_etc_subuid)
        );
        let _ = writeln!(
            out,
            "    \"helper_uid_available\": {}",
            bool_json(subuid.helper_uid_ready)
        );
        let _ = writeln!(out, "  }},");
        let _ = writeln!(
            out,
            "  \"profile_ranking\": {},",
            slice_str_json(&profile_ranking)
        );
        let _ = writeln!(out, "  \"hidden_surfaces\": {},", slice_str_json(hidden));
        let _ = writeln!(out, "  \"denied_surfaces\": {},", slice_str_json(denied));
        let _ = writeln!(out, "  \"residuals\": {}", slice_str_json(residuals));
        let _ = writeln!(out, "}}");
        return out;
    }

    let mut out = String::with_capacity(2048);
    let _ = writeln!(
        out,
        "pmask explain: profile={} (v{}) label={}",
        profile.as_str(),
        PROFILE_VERSION,
        label
    );
    if let Some(ref warn) = policy_warning {
        let _ = writeln!(out, "  policy notice: {warn}");
    }
    let _ = writeln!(out, "\nNamed observer:");
    let _ = writeln!(out, "  {observer}");
    let _ = writeln!(out, "\nProfile ranking:");
    for rank in &profile_ranking {
        let _ = writeln!(out, "  {rank}");
    }
    let _ = writeln!(out, "\nExplicit non-goals:");
    for ng in &non_goals {
        let _ = writeln!(out, "  - {ng}");
    }
    let _ = writeln!(out, "\nHost capabilities:");
    let _ = writeln!(
        out,
        "  arch={} kernel={} tier={} hidepid={}",
        caps.arch,
        caps.kernel,
        caps.tier_word(),
        hidepid.as_word()
    );
    let _ = writeln!(
        out,
        "  ptrace={} userns={} non_dumpable={} set_mm_map={} memfd_secret={} mlock={} landlock_abi={}",
        caps.ptrace,
        caps.userns,
        caps.non_dumpable,
        caps.set_mm_map,
        caps.memfd_secret,
        caps.mlock,
        caps.landlock_abi
    );
    let _ = writeln!(
        out,
        "  helper_uid/subuid: available={} (etc_subuid={}, uid_map_entries={}, userns={})",
        subuid.helper_uid_ready && caps.userns,
        subuid.has_etc_subuid,
        subuid.uid_map_entries,
        caps.userns
    );
    let _ = writeln!(out, "\nHidden surfaces:");
    for h in hidden {
        let _ = writeln!(out, "  - {h}");
    }
    let _ = writeln!(out, "\nDenied surfaces (EACCES tradeoff):");
    for d in denied {
        let _ = writeln!(out, "  - {d}");
    }
    let _ = writeln!(out, "\nHonest residuals:");
    for r in residuals {
        let _ = writeln!(out, "  - {r}");
    }
    out
}

/// Pure-Rust FIPS 180-4 SHA-256 returning lowercase 64-char hex.
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in padded.chunks_exact(64) {
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    padded.zeroize();
    w.zeroize();

    let mut hex = String::with_capacity(64);
    for word in &h {
        let _ = write!(hex, "{word:08x}");
    }
    hex
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn bool_json(v: bool) -> &'static str {
    if v {
        "true"
    } else {
        "false"
    }
}

fn opt_bool_json(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
}

fn opt_u32_json(v: Option<u32>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

fn opt_u64_json(v: Option<u64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

fn opt_str_json(v: Option<&str>) -> String {
    match v {
        Some(s) => format!("\"{}\"", json_escape(s)),
        None => "null".to_string(),
    }
}

fn str_vec_json(items: &[String]) -> String {
    let mut out = String::from("[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push('"');
        out.push_str(&json_escape(item));
        out.push('"');
    }
    out.push(']');
    out
}

fn slice_str_json(items: &[&str]) -> String {
    let mut out = String::from("[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push('"');
        out.push_str(&json_escape(item));
        out.push('"');
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn clean_single_snapshot() -> ProcSnapshot {
        ProcSnapshot {
            pid: 4242,
            observer_uid: 1000,
            target_uid: Some(1000),
            baseline_seccomp_filters: 0,
            baseline_no_new_privs: 0,
            dumpable_zero: Some(true),
            cmdline: CmdlineSurface {
                status: AccessStatus::Readable,
                raw_len: 10,
                nul_count: 1,
                trailing_nuls: 1,
                has_token: false,
                has_label: true,
                has_real_exe: false,
                argv: vec!["ci-runner".to_string()],
            },
            comm: CommSurface {
                status: AccessStatus::Readable,
                value: Some("ci-runner".to_string()),
                matches_label: Some(true),
                has_token: false,
            },
            environ: EnvironSurface {
                status: AccessStatus::DeniedEacces,
                var_count: 0,
                has_token: false,
                has_real_exe: false,
            },
            auxv: AuxvSurface {
                status: AccessStatus::DeniedEacces,
                at_execfn: None,
                at_execfn_str: None,
                at_execfn_readable: None,
                execfn_io_error: false,
                at_platform: None,
                at_random: None,
                at_base: None,
                at_entry: None,
                has_token: false,
                has_real_exe: false,
                has_memfd: false,
            },
            exe: ExeSurface {
                status: AccessStatus::Readable,
                path: Some("/run/user/1000/ci-runner".to_string()),
                is_real: false,
                is_memfd: false,
                has_token: false,
            },
            maps: MapsSurface {
                status: AccessStatus::Readable,
                smaps_status: AccessStatus::Readable,
                vma_count: 12,
                has_real_exe: false,
                has_memfd: false,
                anon_rx_count: 0,
                has_token: false,
                smaps_has_real_exe: false,
                smaps_has_memfd: false,
                smaps_has_token: false,
            },
            mem: MemSurface {
                status: MemScanStatus::DeniedEacces,
                vmas_scanned: 0,
                bytes_scanned: 0,
                leaked_mapping: None,
            },
            fd: FdSurface {
                status: AccessStatus::DeniedEacces,
                fdinfo_status: AccessStatus::DeniedEacces,
                count: 0,
                has_real_exe: false,
                has_memfd: false,
                has_token: false,
            },
            cwd: PathLinkSurface {
                status: AccessStatus::Readable,
                path: Some("/".to_string()),
                is_real_cwd: false,
                has_token: false,
            },
            root: PathLinkSurface {
                status: AccessStatus::Readable,
                path: Some("/".to_string()),
                is_real_cwd: false,
                has_token: false,
            },
            status: StatusSurface {
                status: AccessStatus::Readable,
                name: Some("ci-runner".to_string()),
                ppid: 1,
                tracer_pid: 0,
                threads: 1,
                no_new_privs: 0,
                seccomp: 0,
                seccomp_filters: 0,
                uid: Some(1000),
                euid: Some(1000),
                vm_data_kb: Some(128),
                has_token: false,
            },
            stat: StatSurface {
                status: AccessStatus::Readable,
                ppid: 1,
                num_threads: 1,
                starttime: 123456,
                arg_start: 0x7fff_0000_0000,
                arg_end: 0x7fff_0000_000a,
                env_start: 0x7fff_0000_0010,
                env_end: 0x7fff_0000_0040,
                arg_span_mismatch: false,
                arg_span_hidden: false,
            },
            statm: StatmSurface {
                status: AccessStatus::Readable,
                rss_pages: 512,
                rss_kb: 2048,
            },
            limits: LimitsSurface {
                status: AccessStatus::Readable,
                core_limit_zero: Some(true),
            },
            task: TaskSurface {
                status: AccessStatus::Readable,
                thread_count: 1,
                all_match_label: Some(true),
            },
            misc: MiscSurfaces {
                wchan: Some("do_poll".to_string()),
                syscall: Some("7 0 0 0 0 0 0".to_string()),
                cgroup: Some("0::/user.slice".to_string()),
                ns_pid: Some("pid:[4026531836]".to_string()),
                ns_mnt: Some("mnt:[4026531840]".to_string()),
                ns_user: Some("user:[4026531837]".to_string()),
                mountinfo_private_tell: false,
                userns_owner_read_bypass: false,
                children_count: 0,
                parent_is_twin: false,
            },
        }
    }

    fn clean_single_opts() -> AuditOptions {
        AuditOptions {
            pid: 4242,
            profile: Profile::Single,
            observer: ObserverRole::SameUid,
            label: Some("ci-runner".to_string()),
            token: Some(b"TOK_SUPER_SECRET_987654".to_vec()),
            real_exe: Some("/usr/local/bin/holdsecret".to_string()),
            real_cwd: Some("/home/runner/secret-repo".to_string()),
            allow_memfd: false,
            baseline_seccomp_filters: Some(0),
        }
    }

    #[test]
    fn label_policy_blocks_kernel_threads_and_critical_services() {
        let err = check_label_policy(Some("[kworker/0:0]"), None, false).unwrap_err();
        assert!(matches!(err, LabelPolicyError::KernelThread(_)));
        assert!(err.to_string().contains("--allow-impersonation"));

        for svc in [
            "sshd",
            "/usr/sbin/sshd",
            "sshd -D",
            "systemd",
            "SYSTEMD",
            "cron",
            "crond",
            "init",
            "auditd",
        ] {
            let e = check_label_policy(Some(svc), None, false).unwrap_err();
            assert!(
                matches!(e, LabelPolicyError::CriticalService(_)),
                "expected CriticalService for {svc}"
            );
            assert!(e.to_string().contains("--allow-impersonation"));
        }

        // Comm parameter is also enforced.
        assert!(check_label_policy(Some("ci-runner"), Some("[ksoftirqd/0]"), false).is_err());

        // Benign labels pass.
        assert!(check_label_policy(Some("ci-runner"), Some("worker"), false).is_ok());

        // Override allows blocked names.
        assert!(check_label_policy(Some("[kworker/0:0]"), Some("sshd"), true).is_ok());
    }

    #[test]
    fn select_auto_profile_distinguishes_launchers_shebangs_and_elfs() {
        assert_eq!(
            select_auto_profile(OsStr::new("/bin/sh"), false),
            Profile::Tree
        );
        assert_eq!(
            select_auto_profile(OsStr::new("bash"), false),
            Profile::Tree
        );
        assert_eq!(
            select_auto_profile(OsStr::new("/usr/bin/env"), false),
            Profile::Tree
        );
        assert_eq!(
            select_auto_profile(OsStr::new("make"), false),
            Profile::Tree
        );
        assert_eq!(
            select_auto_profile(OsStr::new("/bin/true"), true),
            Profile::Tree
        );
        assert_eq!(
            select_auto_profile(OsStr::new("/bin/true"), false),
            Profile::Single
        );

        // Temporary #! script must select Tree.
        let pid = unsafe { libc::getpid() };
        let script_path = std::env::temp_dir().join(format!("pmask-audit-shebang-{pid}.sh"));
        let mut f = File::create(&script_path).expect("create temp script");
        writeln!(f, "#!/bin/sh\necho hi").expect("write temp script");
        drop(f);
        assert_eq!(
            select_auto_profile(script_path.as_os_str(), false),
            Profile::Tree
        );
        let _ = fs::remove_file(&script_path);

        // Non-shebang regular file selects Single.
        let bin_path = std::env::temp_dir().join(format!("pmask-audit-elf-{pid}.bin"));
        let mut f = File::create(&bin_path).expect("create temp bin");
        f.write_all(b"\x7fELF\x02\x01\x01\x00")
            .expect("write elf header");
        drop(f);
        assert_eq!(
            select_auto_profile(bin_path.as_os_str(), false),
            Profile::Single
        );
        let _ = fs::remove_file(&bin_path);
    }

    #[test]
    fn sha256_matches_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn json_escaping_and_zero_secret_guarantee() {
        assert_eq!(json_escape("a\"b\\c\n\t\x01"), "a\\\"b\\\\c\\n\\t\\u0001");

        let secret = "PMASK_RAW_TOKEN_DO_NOT_EMIT_7711";
        let mut opts = clean_single_opts();
        opts.token = Some(secret.as_bytes().to_vec());
        let mut snap = clean_single_snapshot();
        // Even if a surface had the token string in a field, scrubbed export + audit JSON
        // must never contain the raw secret.
        snap.cmdline.has_token = true;
        snap.cmdline.argv = vec![format!("ci-runner --tok={secret}")];

        let report = evaluate_snapshot(snap, &opts);
        let audit_json = report.to_json();
        assert!(!audit_json.contains(secret));
        assert!(audit_json.contains(&sha256_hex(secret.as_bytes())));
        assert!(audit_json.contains("\"token_present\": true"));

        // INV-8 must still keep profile.json secret-free.
        let inv8 = report
            .invariants
            .iter()
            .find(|i| i.id == "INV-8")
            .expect("INV-8 present");
        assert!(inv8.passed);

        let tpl = export_profile_template(Profile::Single, "ci-runner", &["ci-runner".into()]);
        assert!(tpl.contains("\"schema\": 2,"));
        assert!(!tpl.contains(secret));
    }

    #[test]
    fn clean_single_profile_passes_all_invariants() {
        let report = evaluate_snapshot(clean_single_snapshot(), &clean_single_opts());
        assert!(
            report.passed(),
            "expected clean snapshot to pass, got:\n{}",
            report.to_text()
        );
        assert!(report.to_json().contains("\"schema\": \"pmask-audit/1\""));
        assert!(report.residuals.iter().any(|r| r.code == "eacces_denial"));
        assert!(report
            .residuals
            .iter()
            .any(|r| r.code == "root_out_of_scope"));
    }

    #[test]
    fn planted_defects_all_fail_audit() {
        // 1. token in cmdline
        {
            let mut s = clean_single_snapshot();
            s.cmdline.has_token = true;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 2. token in environ
        {
            let mut s = clean_single_snapshot();
            s.environ.status = AccessStatus::Readable;
            s.environ.has_token = true;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 3. token in heap/mem
        {
            let mut s = clean_single_snapshot();
            s.mem.status = MemScanStatus::Leaked;
            s.mem.leaked_mapping = Some("[heap]".to_string());
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 4. real exe
        {
            let mut s = clean_single_snapshot();
            s.exe.is_real = true;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 5. real maps
        {
            let mut s = clean_single_snapshot();
            s.maps.has_real_exe = true;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 6. real cwd
        {
            let mut s = clean_single_snapshot();
            s.cwd.is_real_cwd = true;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 7. missing label (comm/cmdline)
        {
            let mut s = clean_single_snapshot();
            s.comm.matches_label = Some(false);
            s.cmdline.has_label = false;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 8. visible TracerPid
        {
            let mut s = clean_single_snapshot();
            s.status.tracer_pid = 9999;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 9. Seccomp_filters > baseline
        {
            let mut s = clean_single_snapshot();
            s.status.seccomp_filters = 2;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 10. NoNewPrivs > baseline
        {
            let mut s = clean_single_snapshot();
            s.status.no_new_privs = 1;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 11. memfd path in single profile
        {
            let mut s = clean_single_snapshot();
            s.exe.is_memfd = true;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 12. trailing NUL padding > 2
        {
            let mut s = clean_single_snapshot();
            s.cmdline.trailing_nuls = 16;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 13. arg span mismatch
        {
            let mut s = clean_single_snapshot();
            s.stat.arg_span_mismatch = true;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
        // 14. supervisor/payload twin pair in single
        {
            let mut s = clean_single_snapshot();
            s.misc.parent_is_twin = true;
            assert!(!evaluate_snapshot(s, &clean_single_opts()).passed());
        }
    }

    #[test]
    fn live_self_mem_scan_detects_planted_heap_token() {
        // Run inside a forked dumpable child so a prior test calling
        // `mem::harden_self()` (PR_SET_DUMPABLE=0) under `--test-threads=1`
        // cannot make `/proc/self/mem` unreadable or perturb the test runner.
        let mut pipe = [0 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "pipe2 failed"
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                libc::close(pipe[0]);
                libc::prctl(libc::PR_SET_DUMPABLE, 1 as libc::c_ulong, 0, 0, 0);
            }
            let result = std::panic::catch_unwind(|| {
                let parts = ["PMASK", "HEAP", "AUDIT", "NEEDLE", "9F8E7D6C"];
                let heap_secret: Vec<u8> = parts.join("_").into_bytes();
                let pinned = Box::new(heap_secret.clone());
                // Also place the secret in a dedicated 4 KiB private anonymous page
                // so parallel test-runner arenas (e.g. Argon2) never push the needle
                // past MAX_MEM_SCAN_BYTES on multi-core CI runners.
                let page = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(page, libc::MAP_FAILED, "mmap failed");
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        heap_secret.as_ptr(),
                        page as *mut u8,
                        heap_secret.len(),
                    );
                }

                let self_pid = unsafe { libc::getpid() };
                let mut opts = AuditOptions::new(self_pid, Profile::Compat);
                opts.token = Some(heap_secret);

                let report = audit_pid(&opts).expect("audit self pid");
                assert_eq!(
                    report.surfaces.mem.status,
                    MemScanStatus::Leaked,
                    "expected live /proc/self/mem full-VMA scan to detect heap secret (scanned {} bytes across {} VMAs)",
                    report.surfaces.mem.bytes_scanned,
                    report.surfaces.mem.vmas_scanned
                );
                assert!(!report.passed());

                let json = report.to_json();
                let text = report.to_text();
                let needle_str = std::str::from_utf8(&pinned).expect("utf8");
                assert!(
                    !json.contains(needle_str),
                    "raw token must never appear in audit JSON"
                );
                assert!(
                    !text.contains(needle_str),
                    "raw token must never appear in audit text"
                );
                assert!(json.contains("\"token_present\": true"));
                assert!(json.contains(&sha256_hex(&pinned)));

                let prof_json =
                    export_profile_for_pid(self_pid, Profile::Compat, None, Some(&pinned))
                        .expect("export self profile");
                assert!(prof_json.contains("\"schema\": 2,"));
                assert!(!prof_json.contains(needle_str));
                assert!(prof_json.contains("\"token_present\": true"));

                std::hint::black_box(&pinned);
                unsafe {
                    libc::munmap(page, 4096);
                }
            });
            match result {
                Ok(()) => unsafe {
                    libc::close(pipe[1]);
                    libc::_exit(0);
                },
                Err(payload) => {
                    let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                        (*s).to_string()
                    } else if let Some(s) = payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "child panicked".to_string()
                    };
                    let bytes = msg.as_bytes();
                    unsafe {
                        let _ = libc::write(
                            pipe[1],
                            bytes.as_ptr() as *const libc::c_void,
                            bytes.len(),
                        );
                        libc::close(pipe[1]);
                        libc::_exit(1);
                    }
                }
            }
        }

        unsafe { libc::close(pipe[1]) };
        let mut err_buf = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let n = unsafe {
                libc::read(
                    pipe[0],
                    chunk.as_mut_ptr() as *mut libc::c_void,
                    chunk.len(),
                )
            };
            if n > 0 {
                err_buf.extend_from_slice(&chunk[..n as usize]);
            } else if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            } else {
                break;
            }
        }
        unsafe { libc::close(pipe[0]) };

        let mut status: libc::c_int = 0;
        loop {
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            if rc == pid {
                break;
            }
            if rc < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "forked mem scan child failed (status={status}): {}",
            String::from_utf8_lossy(&err_buf)
        );
    }

    #[test]
    fn explain_renders_text_and_json() {
        let text = render_explain(Profile::Single, "ci-runner", false);
        assert!(text.contains("same-uid local observer, no root"));
        assert!(text.contains("EACCES"));
        assert!(text.contains("helper_uid/subuid"));

        let json = render_explain(Profile::Single, "ci-runner", true);
        assert!(json.contains("\"profile\": \"single\""));
        assert!(json.contains("\"observer\": \"same-uid local observer, no root\""));
        assert!(json.contains("\"helper_uid_available\":"));
    }

    #[test]
    fn profile_and_observer_parsers_roundtrip() {
        for (raw, expected) in [
            ("auto", Profile::Auto),
            ("SINGLE", Profile::Single),
            ("tree", Profile::Tree),
            ("tee", Profile::Tee),
            ("compat", Profile::Compat),
        ] {
            let parsed = Profile::parse(raw).expect("valid profile");
            assert_eq!(parsed, expected);
            assert_eq!(Profile::parse(parsed.as_str()), Some(expected));
        }
        assert_eq!(Profile::parse("unknown"), None);

        assert_eq!(ObserverRole::parse("same-uid"), Some(ObserverRole::SameUid));
        assert_eq!(
            ObserverRole::parse("other-uid"),
            Some(ObserverRole::OtherUid)
        );
        assert_eq!(ObserverRole::parse("root"), None);
    }

    #[test]
    fn escaped_token_variants_are_detected() {
        let needles = SecretNeedles::from_opt(Some(b"tok+a b/c"));
        assert!(needles.matches_str("raw tok+a b/c end"));
        assert!(needles.matches_str("url tok%2Ba%20b%2Fc end"));
        assert!(needles.matches_str("url tok%2ba%20b%2fc end"));
        assert!(needles.matches_str("sh tok+a\\ b/c end"));
    }

    #[test]
    fn tree_profile_and_allow_memfd_declare_residuals() {
        let mut s = clean_single_snapshot();
        s.exe.is_memfd = true;
        s.status.tracer_pid = 1234;
        s.misc.parent_is_twin = true;

        let mut tree_opts = clean_single_opts();
        tree_opts.profile = Profile::Tree;
        let tree_report = evaluate_snapshot(s.clone(), &tree_opts);
        assert!(
            tree_report.passed(),
            "tree profile declares tracer/memfd residuals"
        );
        assert!(tree_report.residuals.iter().any(|r| r.code == "memfd_exe"));
        assert!(tree_report.residuals.iter().any(|r| r.code == "tracer_pid"));
        assert!(tree_report
            .residuals
            .iter()
            .any(|r| r.code == "visible_supervisor"));

        let mut single_allow_memfd = clean_single_opts();
        single_allow_memfd.allow_memfd = true;
        let mut s2 = clean_single_snapshot();
        s2.exe.is_memfd = true;
        let report2 = evaluate_snapshot(s2, &single_allow_memfd);
        assert!(report2.passed());
        assert!(report2.residuals.iter().any(|r| r.code == "memfd_exe"));
    }

    #[test]
    fn other_uid_observer_checks_cross_uid_non_amplification() {
        let mut s = clean_single_snapshot();
        s.observer_uid = 2001;
        s.target_uid = Some(1000);
        s.environ.status = AccessStatus::Readable;

        let mut opts = clean_single_opts();
        opts.observer = ObserverRole::OtherUid;
        let report = evaluate_snapshot(s, &opts);
        assert!(!report.passed());
        let inv10 = report
            .invariants
            .iter()
            .find(|i| i.id == "INV-10")
            .expect("INV-10 present");
        assert!(!inv10.passed);
    }

    /// Strict RFC 8259 JSON syntax checker for test verification.
    fn assert_valid_json(input: &str) {
        struct Parser<'a> {
            b: &'a [u8],
            pos: usize,
        }
        impl<'a> Parser<'a> {
            fn skip_ws(&mut self) {
                while let Some(&c) = self.b.get(self.pos) {
                    if matches!(c, b' ' | b'\n' | b'\r' | b'\t') {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
            }
            fn peek(&self) -> Option<u8> {
                self.b.get(self.pos).copied()
            }
            fn parse_value(&mut self) -> Result<(), String> {
                self.skip_ws();
                match self.peek() {
                    Some(b'{') => self.parse_object(),
                    Some(b'[') => self.parse_array(),
                    Some(b'"') => self.parse_string(),
                    Some(b't') => self.expect_lit(b"true"),
                    Some(b'f') => self.expect_lit(b"false"),
                    Some(b'n') => self.expect_lit(b"null"),
                    Some(b'-' | b'0'..=b'9') => self.parse_number(),
                    other => Err(format!("unexpected byte {other:?} at offset {}", self.pos)),
                }
            }
            fn expect_lit(&mut self, lit: &[u8]) -> Result<(), String> {
                if self.b[self.pos..].starts_with(lit) {
                    self.pos += lit.len();
                    Ok(())
                } else {
                    Err(format!("expected {:?} at offset {}", lit, self.pos))
                }
            }
            fn parse_string(&mut self) -> Result<(), String> {
                if self.peek() != Some(b'"') {
                    return Err(format!("expected '\"' at {}", self.pos));
                }
                self.pos += 1;
                while let Some(&c) = self.b.get(self.pos) {
                    self.pos += 1;
                    match c {
                        b'"' => return Ok(()),
                        b'\\' => {
                            let Some(&esc) = self.b.get(self.pos) else {
                                return Err("unterminated escape".into());
                            };
                            self.pos += 1;
                            if esc == b'u' {
                                if self.pos + 4 > self.b.len()
                                    || !self.b[self.pos..self.pos + 4]
                                        .iter()
                                        .all(u8::is_ascii_hexdigit)
                                {
                                    return Err(format!("bad \\u escape at {}", self.pos));
                                }
                                self.pos += 4;
                            } else if !matches!(
                                esc,
                                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                            ) {
                                return Err(format!("bad escape {esc} at {}", self.pos));
                            }
                        }
                        0x00..=0x1f => {
                            return Err(format!("unescaped control byte {c} at {}", self.pos));
                        }
                        _ => {}
                    }
                }
                Err("unterminated string".into())
            }
            fn parse_number(&mut self) -> Result<(), String> {
                if self.peek() == Some(b'-') {
                    self.pos += 1;
                }
                let start = self.pos;
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.pos += 1;
                }
                if self.pos == start {
                    return Err(format!("invalid number at {}", self.pos));
                }
                if self.peek() == Some(b'.') {
                    self.pos += 1;
                    let frac_start = self.pos;
                    while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                        self.pos += 1;
                    }
                    if self.pos == frac_start {
                        return Err(format!("invalid fraction at {}", self.pos));
                    }
                }
                if matches!(self.peek(), Some(b'e' | b'E')) {
                    self.pos += 1;
                    if matches!(self.peek(), Some(b'+' | b'-')) {
                        self.pos += 1;
                    }
                    let exp_start = self.pos;
                    while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                        self.pos += 1;
                    }
                    if self.pos == exp_start {
                        return Err(format!("invalid exponent at {}", self.pos));
                    }
                }
                Ok(())
            }
            fn parse_array(&mut self) -> Result<(), String> {
                self.pos += 1;
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.parse_value()?;
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(());
                        }
                        other => {
                            return Err(format!(
                                "expected ',' or ']' in array, got {other:?} at {}",
                                self.pos
                            ))
                        }
                    }
                }
            }
            fn parse_object(&mut self) -> Result<(), String> {
                self.pos += 1;
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.skip_ws();
                    self.parse_string()?;
                    self.skip_ws();
                    if self.peek() != Some(b':') {
                        return Err(format!("expected ':' at {}", self.pos));
                    }
                    self.pos += 1;
                    self.parse_value()?;
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(());
                        }
                        other => {
                            return Err(format!(
                                "expected ',' or '}}' in object, got {other:?} at {}",
                                self.pos
                            ))
                        }
                    }
                }
            }
        }
        let mut p = Parser {
            b: input.as_bytes(),
            pos: 0,
        };
        p.parse_value()
            .unwrap_or_else(|e| panic!("invalid JSON: {e}\n{input}"));
        p.skip_ws();
        assert_eq!(
            p.pos,
            p.b.len(),
            "trailing garbage at offset {} in JSON:\n{input}",
            p.pos
        );
    }

    #[test]
    fn all_json_emitters_produce_valid_rfc8259_json() {
        let report = evaluate_snapshot(clean_single_snapshot(), &clean_single_opts());
        assert_valid_json(&report.to_json());

        let tpl = export_profile_template(
            Profile::Single,
            "ci-runner \"quoted\"",
            &["ci-runner".into(), "--flag".into()],
        );
        assert_valid_json(&tpl);

        let self_pid = unsafe { libc::getpid() };
        let live_prof = export_profile_for_pid(self_pid, Profile::Compat, Some("ci-runner"), None)
            .expect("export self profile");
        assert_valid_json(&live_prof);

        for prof in [
            Profile::Auto,
            Profile::Single,
            Profile::Tree,
            Profile::Tee,
            Profile::Compat,
        ] {
            assert_valid_json(&render_explain(prof, "ci-runner", true));
        }
    }

    #[test]
    fn dumpable_zero_inference_distinguishes_yama_from_non_dumpable() {
        // Under yama.ptrace_scope=1 with dumpable=1, environ/mem return EACCES
        // while exe/maps/cwd remain readable and stat arg_start..env_end are non-zero.
        assert_eq!(
            infer_same_uid_dumpable_zero(
                true,
                false,
                true,
                false,
                AccessStatus::DeniedEacces,
                MemScanStatus::DeniedEacces
            ),
            Some(false)
        );
        // True PR_SET_DUMPABLE=0 denies BOTH attach and read surfaces.
        assert_eq!(
            infer_same_uid_dumpable_zero(
                true,
                true,
                false,
                false,
                AccessStatus::DeniedEacces,
                MemScanStatus::DeniedEacces
            ),
            Some(true)
        );
        // Zeroed stat arg span is sufficient evidence of dumpable=0.
        assert_eq!(
            infer_same_uid_dumpable_zero(
                true,
                false,
                false,
                true,
                AccessStatus::DeniedEacces,
                MemScanStatus::DeniedEacces
            ),
            Some(true)
        );
    }

    #[test]
    fn mountinfo_private_tell_ignores_shared_host_mounts() {
        let host_mi = "137 86 0:77 / /workspaces/pmask rw,relatime - 9p C:/Users/pmask rw\n\
                       22 1 0:20 / /proc rw,nosuid - proc proc rw\n";
        // Identical mount namespace must always be false, even with /pmask in host mounts.
        assert!(!detect_mountinfo_private_tell(
            Some("mnt:[4026531840]"),
            Some("mnt:[4026531840]"),
            Some(host_mi),
            Some(host_mi),
        ));
        // Different ns/mnt with identical mount tuples (only mount IDs differ) -> false.
        let cloned_mi = "500 400 0:77 / /workspaces/pmask rw,relatime - 9p C:/Users/pmask rw\n\
                         501 400 0:20 / /proc rw,nosuid - proc proc rw\n";
        assert!(!detect_mountinfo_private_tell(
            Some("mnt:[4026532999]"),
            Some("mnt:[4026531840]"),
            Some(cloned_mi),
            Some(host_mi),
        ));
        // Different ns/mnt with an extra private tmpfs mount -> true.
        let priv_mi = "500 400 0:77 / /workspaces/pmask rw,relatime - 9p C:/Users/pmask rw\n\
                       502 400 0:99 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw,mode=1777\n";
        assert!(detect_mountinfo_private_tell(
            Some("mnt:[4026532999]"),
            Some("mnt:[4026531840]"),
            Some(priv_mi),
            Some(host_mi),
        ));
    }

    #[test]
    fn static_profile_template_matches_live_profile_defaults() {
        let single = export_profile_template(Profile::Single, "ci-runner", &["ci-runner".into()]);
        assert_valid_json(&single);
        assert!(single.contains("\"schema\": 2,"));
        assert!(single.contains("\"masker\": \"pmask\""));
        assert!(single.contains("\"profile\": \"single\""));
        assert!(single.contains("\"ppid\": 0"));
        assert!(single.contains("\"exe\": \"\""));
        assert!(single.contains("\"cwd\": \"\""));
        assert!(single.contains("\"dumpable\": false"));
        assert!(single.contains("\"denied_by\": [\"environ\", \"mem\", \"maps\""));

        let reparented = export_profile_template_with(
            Profile::Single,
            "ci-runner",
            &["ci-runner".into()],
            &TemplateOptions {
                reparent: true,
                ..TemplateOptions::default()
            },
        );
        assert_valid_json(&reparented);
        assert!(reparented.contains("\"ppid\": 1"));
        assert!(reparented.contains("\"PPid\": 1"));

        let dumpable_cwd = export_profile_template_with(
            Profile::Single,
            "ci-runner",
            &["ci-runner".into()],
            &TemplateOptions {
                allow_dumpable: true,
                cwd_override: true,
                ..TemplateOptions::default()
            },
        );
        assert_valid_json(&dumpable_cwd);
        assert!(dumpable_cwd.contains("/ci-runner\""));
        assert!(dumpable_cwd.contains("\"cwd\": \"/\""));
        assert!(dumpable_cwd.contains("\"dumpable\": true"));

        let tree = export_profile_template(Profile::Tree, "ci-runner", &["ci-runner".into()]);
        assert_valid_json(&tree);
        assert!(tree.contains("\"TracerPid\": 1"));
        assert!(tree.contains("\"exe\": \"\""));
        assert!(tree.contains("\"cwd\": \"\""));

        let tee = export_profile_template(Profile::Tee, "ci-runner", &["ci-runner".into()]);
        assert_valid_json(&tee);
        assert!(tee.contains("\"dumpable\": false"));
        assert!(tee.contains("/ci-runner\""));
        assert!(tee.contains("\"cwd\": \"/\""));
        assert!(tee.contains("\"denied_by\": [\"environ\", \"mem\", \"auxv\", \"fd\"]"));
        assert!(tee.contains("\"exe\", \"maps\", \"smaps\", \"cwd\""));
    }

    #[test]
    fn psgen_schema_v2_scrubs_secrets_and_audit_reports_score_parity_fields() {
        let needles = SecretNeedles::from_opt(Some(b"TOK-CUSTOM-123456"));
        let env_api = scrub_profile_environ_entry("OPENAI_API_KEY=sk-live-secret", &needles);
        assert_eq!(env_api, "OPENAI_API_KEY=<REDACTED:len=14>");
        let env_ghp = scrub_profile_environ_entry("FOO=ghp_1234567890abcdef1234", &needles);
        assert!(env_ghp.starts_with("FOO=<REDACTED:len="));
        assert!(!env_ghp.contains("ghp_"));
        let env_aws = scrub_profile_environ_entry("BAR=AKIAIOSFODNN7EXAMPLE", &needles);
        assert!(env_aws.starts_with("BAR=<REDACTED:len="));
        assert!(!env_aws.contains("AKIA"));
        let env_key_tok = scrub_profile_environ_entry("K_TOK-CUSTOM-123456=plain", &needles);
        assert!(!env_key_tok.contains("TOK-CUSTOM-123456"));
        assert!(env_key_tok.ends_with("=plain"));
        let env_key_ghp = scrub_profile_environ_entry("ghp_1234567890abcdef1234=1", &needles);
        assert!(!env_key_ghp.contains("ghp_"));

        let report = evaluate_snapshot(clean_single_snapshot(), &clean_single_opts());
        let j = report.to_json();
        assert_valid_json(&j);
        assert_eq!(report.denied_surfaces, 4);
        assert_eq!(report.seccomp_delta, 0);
        assert_eq!(report.no_new_privs_delta, 0);
        assert!(j.contains("\"denied_surfaces\": 4,"));
        assert!(j.contains("\"seccomp_delta\": 0,"));
        assert!(j.contains("\"no_new_privs_delta\": 0,"));
        assert!(j.contains("\"auxv_execfn_readable\": null,"));
        assert!(j.contains("\"execfn_io_error\": false,"));

        let exp = render_explain(Profile::Single, "ci-runner", false);
        assert!(!exp.contains("cwd (normalized working directory)"));
        assert!(exp.contains("cwd stays real unless --cwd PATH"));
    }

    #[test]
    fn userns_owner_read_bypass_emits_residual() {
        let mut s = clean_single_snapshot();
        s.misc.userns_owner_read_bypass = true;
        let mut opts = clean_single_opts();
        opts.profile = Profile::Tee;
        let report = evaluate_snapshot(s, &opts);
        assert!(report
            .residuals
            .iter()
            .any(|r| r.code == "userns_owner_read_bypass"));
    }

    #[test]
    fn inv7_detail_formats_clean_yes_no_unknown() {
        for (dumpable_zero, core_limit_zero, want) in [
            (
                Some(true),
                Some(true),
                "dumpable_zero=yes, core_limit_zero=yes",
            ),
            (
                Some(true),
                Some(false),
                "dumpable_zero=yes, core_limit_zero=no",
            ),
            (
                Some(true),
                None,
                "dumpable_zero=yes, core_limit_zero=unknown",
            ),
            (
                Some(false),
                Some(true),
                "dumpable_zero=no, core_limit_zero=yes",
            ),
        ] {
            let mut s = clean_single_snapshot();
            s.dumpable_zero = dumpable_zero;
            s.limits.core_limit_zero = core_limit_zero;
            let report = evaluate_snapshot(s, &clean_single_opts());
            let inv7 = report
                .invariants
                .iter()
                .find(|i| i.id == "INV-7")
                .expect("INV-7 present");
            assert!(inv7.passed);
            assert!(!inv7.detail.contains("Some("), "{}", inv7.detail);
            assert!(!inv7.detail.contains("None"), "{}", inv7.detail);
            assert_eq!(inv7.detail, want);
        }
    }

    #[test]
    fn collect_residuals_distinguishes_yama_eacces_and_other_uid_arg_span() {
        // 1. dumpable_zero=Some(false) + mem EACCES must NOT claim PR_SET_DUMPABLE=0.
        let mut s_yama = clean_single_snapshot();
        s_yama.dumpable_zero = Some(false);
        s_yama.environ.status = AccessStatus::Readable;
        s_yama.auxv.status = AccessStatus::Readable;
        s_yama.fd.status = AccessStatus::Readable;
        s_yama.mem.status = MemScanStatus::DeniedEacces;
        let res_yama = collect_residuals(&s_yama, ObserverRole::SameUid);
        let eacces = res_yama
            .iter()
            .find(|r| r.code == "eacces_denial")
            .expect("eacces_denial emitted");
        assert!(
            !eacces.detail.contains("PR_SET_DUMPABLE=0"),
            "{}",
            eacces.detail
        );
        assert!(
            eacces.detail.contains("yama.ptrace_scope"),
            "{}",
            eacces.detail
        );

        // 2. ObserverRole::OtherUid + arg_span_hidden must NOT claim while dumpable=0.
        let mut s_other = clean_single_snapshot();
        s_other.dumpable_zero = None;
        s_other.stat.arg_span_hidden = true;
        let res_other = collect_residuals(&s_other, ObserverRole::OtherUid);
        let arg_span = res_other
            .iter()
            .find(|r| r.code == "arg_span_hidden")
            .expect("arg_span_hidden emitted");
        assert!(
            !arg_span.detail.contains("while dumpable=0"),
            "{}",
            arg_span.detail
        );
        assert!(
            arg_span
                .detail
                .contains("non-owner observers without ptrace access"),
            "{}",
            arg_span.detail
        );

        // 3. SameUid + dumpable_zero=Some(false) + arg_span_hidden notes ptrace denial too.
        let mut s_same_dumpable = clean_single_snapshot();
        s_same_dumpable.dumpable_zero = Some(false);
        s_same_dumpable.stat.arg_span_hidden = true;
        let res_same = collect_residuals(&s_same_dumpable, ObserverRole::SameUid);
        let arg_span_same = res_same
            .iter()
            .find(|r| r.code == "arg_span_hidden")
            .expect("arg_span_hidden emitted");
        assert!(
            arg_span_same
                .detail
                .contains("while dumpable=0 or ptrace access is denied"),
            "{}",
            arg_span_same.detail
        );
    }

    #[test]
    fn ancestor_environ_allowlist_strips_custom_and_ci_vars() {
        let raw = b"PATH=/usr/bin\0HOME=/home/runner\0LANG=C.UTF-8\0TERM=xterm\0USER=runner\0LOGNAME=runner\0SHELL=/bin/sh\0PWD=/work\0SHLVL=2\0LC_ALL=C.UTF-8\0GITHUB_ACTIONS=true\0CI_JOB_TOKEN=ghp_1234567890abcdef1234\0CUSTOM_HOST=internal.corp\0LC_TOKEN=tok123\0";
        let needles = SecretNeedles::from_opt(Some(b"tok123"));

        let ancestor = filter_and_scrub_profile_environ(raw, 1, &needles);
        assert!(ancestor.contains(&"PATH=/usr/bin".to_string()));
        assert!(ancestor.contains(&"LANG=C.UTF-8".to_string()));
        assert!(ancestor.contains(&"TERM=xterm".to_string()));
        assert!(ancestor.contains(&"LC_ALL=C.UTF-8".to_string()));
        assert!(ancestor.contains(&"LC_TOKEN=<REDACTED:len=6>".to_string()));
        assert!(!ancestor.iter().any(|e| e.starts_with("GITHUB_ACTIONS=")));
        assert!(!ancestor.iter().any(|e| e.starts_with("CI_JOB_TOKEN=")));
        assert!(!ancestor.iter().any(|e| e.starts_with("CUSTOM_HOST=")));

        let target = filter_and_scrub_profile_environ(raw, 0, &needles);
        assert!(target.contains(&"GITHUB_ACTIONS=true".to_string()));
        assert!(target.contains(&"CUSTOM_HOST=internal.corp".to_string()));
        assert!(target.contains(&"CI_JOB_TOKEN=<REDACTED:len=24>".to_string()));
    }
}
