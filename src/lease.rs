//! Leases, revocation and the use audit for the secret agent.
//!
//! A secret that is handed out without a bound is a secret that stays
//! handed out.  This module puts three bounds on a release and records
//! what was released:
//!
//! * A **lease** gives one secret a time budget, a use budget, or both.
//!   The first release starts the clock and spends one use.  When the
//!   clock runs out or the uses are gone, the lease's copy of the value
//!   is zeroised and every later fetch of that secret fails with the
//!   lease id and the reason.  A lease is per secret and per agent, not
//!   per peer: two peers of one agent share the budget.
//! * A **vault lock** drops every plaintext byte the agent holds.  The
//!   unlocked store is replaced by `None`, which drops each [`SecBuf`]
//!   and zeroises it.  The agent keeps no passphrase, so it cannot
//!   unlock itself; serving again means restarting it.
//! * A **use audit** writes one line per release: time, secret name,
//!   peer pid, peer executable and lease id, never the value.  The lines
//!   are hash-chained so an edit to one line breaks the chain.
//!
//! # What none of this does
//!
//! None of it defeats a privileged observer.  A privileged observer
//! (root, or any process with `CAP_SYS_PTRACE` and the uid of the agent)
//! reads this process's memory and obtains every secret the agent holds,
//! whatever the lease, the lock or the audit says.  A process of the
//! peer's uid that may run an allowed executable can ask for what that
//! executable's rules allow.  The audit records releases; it cannot
//! report one that never reached this code, and a writer with access to
//! the sink can rewrite the whole chain from the genesis value.  See
//! [`AuditLog`] for the exact limit of the chain.
//!
//! # The seal constraint for a burn after read
//!
//! A delivered secret is a sealed memfd whose seal set includes
//! `F_SEAL_SEAL` (see [`crate::mem::SealedFd`]).  `F_SEAL_SEAL` is
//! permanent and blocks every later `F_ADD_SEALS`, so the descriptor
//! cannot be shrunk and re-sealed to zero after the reader consumed it.
//! A burn after read therefore needs its own seal set on the delivered
//! descriptor (size sealing and write sealing, with the seal-seal bit
//! added only after the size has been set to the final value), or a
//! delivery path that hands the reader an unsealed copy it is allowed to
//! destroy.  The leases here bound how often and how long a value is
//! released; they do not revoke a copy that has already left the process.

use crate::mem::SecBuf;
use crate::store::Store;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, or 0 when the clock is before it.
pub fn now_unix() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix time, in UTC.
pub fn iso_utc(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian year, month and day.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn random_hex(n_bytes: usize) -> io::Result<String> {
    let mut buf = vec![0u8; n_bytes];
    let mut off = 0usize;
    while off < buf.len() {
        // SAFETY: writing into this function's own buffer.
        let n = unsafe {
            libc::getrandom(
                buf[off..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - off,
                0,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        off += n as usize;
    }
    let mut s = String::with_capacity(n_bytes * 2);
    for b in buf {
        s.push_str(&format!("{:02x}", b));
    }
    Ok(s)
}

// ------------------------------------------------------------- leases --

/// The budget one secret is released under.
///
/// `ttl_secs` and `uses` are both optional; `0` means "no limit" for
/// that dimension, and a policy with two zeroes is rejected because it
/// would bound nothing.  The clock starts at the first release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeasePolicy {
    pub ttl_secs: u64,
    pub uses: u32,
}

impl LeasePolicy {
    /// A policy with at least one bound.
    pub fn new(ttl_secs: u64, uses: u32) -> io::Result<LeasePolicy> {
        if ttl_secs == 0 && uses == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a lease needs a TTL, a use count, or both",
            ));
        }
        Ok(LeasePolicy { ttl_secs, uses })
    }

    /// One-line description for the startup log and `PING`.
    pub fn describe(&self) -> String {
        let ttl = if self.ttl_secs == 0 {
            "ttl=none".to_string()
        } else {
            format!("ttl={}s", self.ttl_secs)
        };
        let uses = if self.uses == 0 {
            "uses=none".to_string()
        } else {
            format!("uses={}", self.uses)
        };
        format!("{} {}", ttl, uses)
    }
}

/// Lifecycle of one lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// The lease may be used.
    Live,
    /// The TTL ran out and the leased value was zeroised.
    Expired,
    /// Every use was spent and the leased value was zeroised.
    Spent,
    /// The agent locked its store and dropped the leased value.
    Wiped,
}

/// What a caller learns about the lease that served its request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseTicket {
    /// Opaque identifier, 128 random bits as 32 lowercase hex characters.
    pub id: String,
    pub name: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub uses_total: u32,
    pub uses_left: u32,
}

/// Why a fetch under a lease was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    /// The TTL ran out; the value was zeroised.
    Expired {
        id: String,
        name: String,
        expires_at: u64,
    },
    /// Every use was spent; the value was zeroised.
    Spent { id: String, name: String },
    /// The agent locked its store; the value was zeroised.
    Wiped { id: String, name: String },
}

impl LeaseError {
    /// The lease id the refusal belongs to.
    pub fn lease_id(&self) -> &str {
        match self {
            LeaseError::Expired { id, .. }
            | LeaseError::Spent { id, .. }
            | LeaseError::Wiped { id, .. } => id,
        }
    }
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeaseError::Expired {
                id,
                name,
                expires_at,
            } => write!(
                f,
                "lease {} for secret '{}' expired at {} and its value was zeroised; \
                 restart the agent to issue a new lease",
                id,
                name,
                iso_utc(*expires_at)
            ),
            LeaseError::Spent { id, name } => write!(
                f,
                "lease {} for secret '{}' has no uses left and its value was zeroised; \
                 restart the agent to issue a new lease",
                id, name
            ),
            LeaseError::Wiped { id, name } => write!(
                f,
                "lease {} for secret '{}' was wiped when the agent locked its store",
                id, name
            ),
        }
    }
}

/// One secret's lease.
///
/// # The seal constraint
///
/// The descriptor a client receives for a delivered secret carries
/// `F_SEAL_SEAL` (see [`crate::mem::SealedFd`]).  That bit is permanent
/// and forecloses every later `F_ADD_SEALS`, so the usual
/// truncate-and-reseal burn (`ftruncate(fd, 0)` then re-seal against
/// growth) cannot be done on that descriptor at all.  A burn after read
/// therefore needs its own seal set: size sealing applied before the
/// final size is fixed, write sealing, and the seal-seal bit added last,
/// or a separate delivery descriptor the reader is allowed to destroy.
/// This lease bounds the time and the number of releases; it does not
/// revoke a value that has already been handed over.
#[derive(Debug)]
pub struct Lease {
    pub id: String,
    pub name: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub uses_total: u32,
    pub uses_left: u32,
    pub state: LeaseState,
    /// The leased copy.  Dropping it zeroises the bytes.
    value: Option<SecBuf>,
}

impl Lease {
    fn expires(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|t| now >= t)
    }

    fn destroy(&mut self, why: LeaseState) {
        if let Some(mut buf) = self.value.take() {
            buf.wipe();
        }
        self.state = why;
    }

    /// Drop this lease's copy now (used by the vault lock).
    pub fn wipe(&mut self) {
        self.destroy(LeaseState::Wiped);
    }

    /// Ticket for one successful release.
    fn ticket(&self) -> LeaseTicket {
        LeaseTicket {
            id: self.id.clone(),
            name: self.name.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            uses_total: self.uses_total,
            uses_left: self.uses_left,
        }
    }
}

/// The result of asking for one release under a lease policy.
///
/// `Debug` is derived, and it is safe because [`SecBuf`]'s own `Debug`
/// prints the length and the backing, never the bytes.
#[derive(Debug)]
pub enum LeaseOutcome {
    /// The secret is leased; `ticket` names the lease that served it.
    Leased(LeaseTicket, SecBuf),
    /// The secret carries no lease policy; the value is unleased.
    Unleased(SecBuf),
}

/// Lease configuration: which budgets apply to which secret.
#[derive(Debug, Clone, Default)]
pub struct LeaseConf {
    default: Option<LeasePolicy>,
    by_name: BTreeMap<String, LeasePolicy>,
}

impl LeaseConf {
    pub fn new() -> LeaseConf {
        LeaseConf::default()
    }

    /// Budget for every secret that has no entry of its own.
    pub fn set_default(&mut self, policy: LeasePolicy) {
        self.default = Some(policy);
    }

    /// Budget for one named secret.
    pub fn set(&mut self, name: &str, policy: LeasePolicy) {
        self.by_name.insert(name.to_string(), policy);
    }

    /// Effective policy for a secret, `None` when it is unleased.
    pub fn policy(&self, name: &str) -> Option<LeasePolicy> {
        self.by_name.get(name).copied().or(self.default)
    }

    /// Narrow a configured policy by a per-request one.  Neither side can
    /// widen the other: the result takes the smaller time budget and the
    /// smaller use budget, and a dimension that only one side bounds is
    /// kept.  `None` on both sides stays unleased.
    pub fn narrow(
        wanted: Option<LeasePolicy>,
        request: Option<LeasePolicy>,
    ) -> Option<LeasePolicy> {
        match (wanted, request) {
            (None, None) => None,
            (Some(p), None) | (None, Some(p)) => Some(p),
            (Some(a), Some(b)) => {
                let ttl = match (a.ttl_secs, b.ttl_secs) {
                    (0, t) | (t, 0) => t,
                    (x, y) => x.min(y),
                };
                let uses = match (a.uses, b.uses) {
                    (0, u) | (u, 0) => u,
                    (x, y) => x.min(y),
                };
                Some(LeasePolicy {
                    ttl_secs: ttl,
                    uses,
                })
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.default.is_none() && self.by_name.is_empty()
    }

    /// Configuration lines for the startup log and `PING`.
    pub fn describe(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(p) = self.default {
            out.push(format!("default {}", p.describe()));
        }
        for (name, p) in &self.by_name {
            out.push(format!("{} {}", name, p.describe()));
        }
        out
    }
}

/// Lease configuration plus the live leases it created.
#[derive(Default)]
pub struct LeaseBook {
    conf: LeaseConf,
    leases: BTreeMap<String, Lease>,
}

impl LeaseBook {
    pub fn new(conf: LeaseConf) -> LeaseBook {
        LeaseBook {
            conf,
            leases: BTreeMap::new(),
        }
    }

    pub fn conf(&self) -> &LeaseConf {
        &self.conf
    }

    /// True when the secret is released under a budget.
    pub fn is_leased(&self, name: &str) -> bool {
        self.conf.policy(name).is_some()
    }

    /// Take one release of `name`.  The first call creates the lease from
    /// `stored`; a lease that has expired, run out, or been wiped stays
    /// refused until the agent restarts or re-unlocks.
    pub fn acquire(
        &mut self,
        name: &str,
        stored: &[u8],
        now: u64,
    ) -> Result<LeaseOutcome, io::Error> {
        self.acquire_with(name, stored, now, None)
    }

    /// Like [`LeaseBook::acquire`], with a policy narrower than the
    /// configured one.  The narrower policy is used when it is the first
    /// request for this secret; afterwards the lease that was issued
    /// stands, because a lease is a promise about one budget.
    pub fn acquire_with(
        &mut self,
        name: &str,
        stored: &[u8],
        now: u64,
        narrow: Option<LeasePolicy>,
    ) -> Result<LeaseOutcome, io::Error> {
        let Some(policy) = LeaseConf::narrow(self.conf.policy(name), narrow) else {
            return Ok(LeaseOutcome::Unleased(SecBuf::from_slice(stored)?));
        };
        let lease = match self.leases.get_mut(name) {
            Some(lease) => lease,
            None => {
                let id = random_hex(16)?;
                let expires_at = if policy.ttl_secs == 0 {
                    None
                } else {
                    Some(now.saturating_add(policy.ttl_secs))
                };
                let uses_total = if policy.uses == 0 {
                    u32::MAX
                } else {
                    policy.uses
                };
                self.leases.insert(
                    name.to_string(),
                    Lease {
                        id,
                        name: name.to_string(),
                        issued_at: now,
                        expires_at,
                        uses_total,
                        uses_left: uses_total,
                        state: LeaseState::Live,
                        value: None,
                    },
                );
                self.leases.get_mut(name).expect("just inserted")
            }
        };

        match lease.state {
            LeaseState::Expired => {
                return Err(io::Error::other(
                    LeaseError::Expired {
                        id: lease.id.clone(),
                        name: lease.name.clone(),
                        expires_at: lease.expires_at.unwrap_or(lease.issued_at),
                    }
                    .to_string(),
                ))
            }
            LeaseState::Spent => {
                return Err(io::Error::other(
                    LeaseError::Spent {
                        id: lease.id.clone(),
                        name: lease.name.clone(),
                    }
                    .to_string(),
                ))
            }
            LeaseState::Wiped => {
                return Err(io::Error::other(
                    LeaseError::Wiped {
                        id: lease.id.clone(),
                        name: lease.name.clone(),
                    }
                    .to_string(),
                ))
            }
            LeaseState::Live => {}
        }
        if lease.expires(now) {
            let expires_at = lease.expires_at.unwrap_or(lease.issued_at);
            let id = lease.id.clone();
            let name = lease.name.clone();
            lease.destroy(LeaseState::Expired);
            return Err(io::Error::other(
                LeaseError::Expired {
                    id,
                    name,
                    expires_at,
                }
                .to_string(),
            ));
        }
        if lease.uses_left == 0 {
            let id = lease.id.clone();
            let name = lease.name.clone();
            lease.destroy(LeaseState::Spent);
            return Err(io::Error::other(LeaseError::Spent { id, name }.to_string()));
        }

        if lease.value.is_none() {
            lease.value = Some(SecBuf::from_slice(stored)?);
        }
        lease.uses_left -= 1;
        let copy = SecBuf::from_slice(
            lease
                .value
                .as_ref()
                .map(|b| b.as_slice())
                .unwrap_or_default(),
        )?;
        Ok(LeaseOutcome::Leased(lease.ticket(), copy))
    }

    /// Drop every leased copy and refuse the affected secrets from now on.
    pub fn wipe_all(&mut self) {
        for lease in self.leases.values_mut() {
            lease.wipe();
        }
    }

    /// One line per live lease, for `PING` and the startup log.
    pub fn summary(&self, now: u64) -> Vec<String> {
        self.leases
            .values()
            .map(|l| {
                let state = match l.state {
                    LeaseState::Live if l.expires(now) => "expired",
                    LeaseState::Live => "live",
                    LeaseState::Expired => "expired",
                    LeaseState::Spent => "spent",
                    LeaseState::Wiped => "wiped",
                };
                let expires = match l.expires_at {
                    Some(t) => format!("expires={}", iso_utc(t)),
                    None => "expires=never".to_string(),
                };
                format!(
                    "{} id={} state={} uses_left={}/{} {}",
                    l.name, l.id, state, l.uses_left, l.uses_total, expires
                )
            })
            .collect()
    }
}

// -------------------------------------------------------------- vault --

/// What a lookup in the vault found.
pub enum Lookup {
    /// The secret, as a fresh protected copy.
    Found(SecBuf),
    /// No secret has that name.
    Missing,
    /// The store is locked; the reason names what locked it.
    Locked(&'static str),
}

/// The unlocked store, or nothing once the agent has locked.
///
/// Locking replaces the store with `None` under the write lock, which
/// drops every [`SecBuf`] in it and zeroises those bytes.  The agent
/// holds no passphrase, so a locked vault stays locked until the agent
/// is restarted with one.
pub struct Vault {
    inner: RwLock<Option<Store>>,
    reason: RwLock<Option<&'static str>>,
}

impl Vault {
    pub fn new(store: Store) -> Vault {
        Vault {
            inner: RwLock::new(Some(store)),
            reason: RwLock::new(None),
        }
    }

    /// True when the plaintext is gone.
    pub fn is_locked(&self) -> bool {
        match self.inner.read() {
            Ok(g) => g.is_none(),
            Err(_) => true,
        }
    }

    /// Why the vault locked, when it did.
    pub fn lock_reason(&self) -> Option<&'static str> {
        self.reason.read().ok().and_then(|g| *g)
    }

    /// Secret names, or `None` when the store is locked.
    pub fn names(&self) -> Option<Vec<String>> {
        let g = self.inner.read().ok()?;
        g.as_ref()
            .map(|s| s.names().into_iter().map(|n| n.to_string()).collect())
    }

    /// Copy one secret out of the store.
    pub fn copy_of(&self, name: &str) -> Lookup {
        let reason = self.lock_reason().unwrap_or("the store is locked");
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return Lookup::Locked(reason),
        };
        let Some(store) = g.as_ref() else {
            return Lookup::Locked(reason);
        };
        match store.get(name) {
            Some(v) => match SecBuf::from_slice(v) {
                Ok(b) => Lookup::Found(b),
                Err(_) => Lookup::Missing,
            },
            None => Lookup::Missing,
        }
    }

    /// Drop every plaintext byte.  Returns true when this call locked it.
    pub fn lock(&self, why: &'static str) -> bool {
        let Ok(mut g) = self.inner.write() else {
            return false;
        };
        let had = g.is_some();
        if had {
            // Dropping the store here drops each SecBuf, which zeroises it.
            g.take();
        }
        if let Ok(mut r) = self.reason.write() {
            if r.is_none() {
                *r = Some(why);
            }
        }
        had
    }
}

// -------------------------------------------------------------- audit --

/// Where the use audit goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditSink {
    /// Nothing is written.
    None,
    /// One line per release on the agent's standard error.
    Stderr,
    /// One line per release, appended to this file.
    File(PathBuf),
}

impl AuditSink {
    /// Parse `none`, `stderr` or a path.
    pub fn parse(text: &str) -> io::Result<AuditSink> {
        match text {
            "" | "none" => Ok(AuditSink::None),
            "stderr" => Ok(AuditSink::Stderr),
            p => Ok(AuditSink::File(PathBuf::from(p))),
        }
    }

    /// One-line description for the startup log and `PING`.
    pub fn describe(&self) -> String {
        match self {
            AuditSink::None => "none".to_string(),
            AuditSink::Stderr => "stderr".to_string(),
            AuditSink::File(p) => p.display().to_string(),
        }
    }
}

/// One release, as it is recorded.
///
/// The value is not a field: there is no code path that could put it in
/// a line, and the format has no slot for it.
#[derive(Debug, Clone, Copy)]
pub struct AuditEntry<'a> {
    /// Unix time of the release.
    pub time: u64,
    /// Secret name.
    pub name: &'a str,
    /// Peer pid, as pinned at accept.
    pub peer_pid: libc::pid_t,
    /// Peer executable, as resolved for this request.
    pub peer_exe: &'a str,
    /// Lease id, or `-` when the secret is unleased.
    pub lease_id: &'a str,
}

/// The hash-chained use audit.
///
/// # Format
///
/// One line per release, tab separated, fields in this order:
///
/// ```text
/// v1  <unix time>  <UTC time>  <secret name>  <peer pid>  <peer exe>  <lease id>  chain=<hex>
/// ```
///
/// The last field is written as one space, the text `chain=`, and 64
/// lowercase hex characters.  The chained value is
///
/// ```text
/// chain[0] = 64 zero characters (the genesis value)
/// chain[i] = SHA-256(chain[i-1] as text || the line fields of entry i)
/// ```
///
/// where `the line fields` is the line up to and including the lease id,
/// with no trailing separator.  A reader recomputes the chain from the
/// genesis value and compares.
///
/// # What the chain proves, and what it does not
///
/// It proves that the lines as they stand are the lines this code would
/// have written in that order, when every line is present.  It does not
/// prove that a line was not removed: a writer with access to the sink
/// can delete the last entries, or rewrite the whole file from the
/// genesis value, and the remaining chain still verifies.  It proves
/// nothing about releases that never reached this code, nothing about
/// who wrote the file, and nothing about a privileged observer, who can
/// read the agent's memory whatever the audit says.  Detecting a
/// truncation needs an anchor outside the file: a copy of the head
/// value, a counter in another log, or a sink that can only be appended.
pub struct AuditLog {
    sink: AuditSink,
    file: Option<std::fs::File>,
    chain: String,
    entries: u64,
}

impl AuditLog {
    /// Open the sink.  A file sink is created 0600 and never follows a
    /// symbolic link.
    pub fn open(sink: AuditSink) -> io::Result<AuditLog> {
        let file = match &sink {
            AuditSink::File(path) => Some(open_audit_file(path)?),
            _ => None,
        };
        Ok(AuditLog {
            sink,
            file,
            chain: genesis(),
            entries: 0,
        })
    }

    pub fn sink(&self) -> &AuditSink {
        &self.sink
    }

    /// Current chain head, as 64 lowercase hex characters.
    pub fn chain(&self) -> &str {
        &self.chain
    }

    pub fn entries(&self) -> u64 {
        self.entries
    }

    /// Append one release.  The write happens before the caller hands
    /// the value over, so an audit that cannot be written refuses the
    /// release.
    pub fn record(&mut self, entry: &AuditEntry<'_>) -> io::Result<()> {
        let fields = format!(
            "v1\t{}\t{}\t{}\t{}\t{}\t{}",
            entry.time,
            iso_utc(entry.time),
            escape_field(entry.name),
            entry.peer_pid,
            escape_field(entry.peer_exe),
            escape_field(entry.lease_id)
        );
        let chain = sha256_hex(&[self.chain.as_bytes(), fields.as_bytes()]);
        let line = format!("{}\tchain={}\n", fields, chain);
        match (&self.sink, &mut self.file) {
            (AuditSink::None, _) => {}
            (AuditSink::Stderr, _) => {
                let mut err = io::stderr();
                err.write_all(line.as_bytes())?;
                err.flush()?;
            }
            (AuditSink::File(_), Some(f)) => {
                f.write_all(line.as_bytes())?;
                f.flush()?;
            }
            (AuditSink::File(_), None) => {
                return Err(io::Error::other("audit file is not open"));
            }
        }
        self.chain = chain;
        self.entries += 1;
        Ok(())
    }
}

fn open_audit_file(path: &Path) -> io::Result<std::fs::File> {
    let mut opts = OpenOptions::new();
    opts.append(true)
        .create(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_APPEND | libc::O_CLOEXEC);
    opts.open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("audit sink {}: {}", path.display(), e)))
}

/// The genesis value: 64 zero characters.
pub fn genesis() -> String {
    "0".repeat(64)
}

/// Escape bytes that would break a line: printable ASCII stays, a tab,
/// a newline and every other byte become `\xNN`.
fn escape_field(text: &str) -> String {
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

/// The result of checking a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    /// Number of entry lines read.
    pub entries: u64,
    /// Chain head after the last line.
    pub head: String,
    /// 1-based line number of the first line that does not verify.
    pub damaged: Option<u64>,
}

impl ChainReport {
    /// True when every line verified.
    pub fn intact(&self) -> bool {
        self.damaged.is_none()
    }
}

/// Recompute the chain of an audit file and report the first bad line.
///
/// A truncated tail verifies: see [`AuditLog`].
pub fn verify_file(path: &Path) -> io::Result<ChainReport> {
    let text = std::fs::read_to_string(path)?;
    let mut chain = genesis();
    let mut entries = 0u64;
    let mut damaged = None;
    for (index, line) in text.lines().enumerate() {
        let lineno = index as u64 + 1;
        entries = lineno;
        let Some((fields, recorded)) = line.rsplit_once("\tchain=") else {
            damaged.get_or_insert(lineno);
            continue;
        };
        let want = sha256_hex(&[chain.as_bytes(), fields.as_bytes()]);
        if want != recorded {
            damaged.get_or_insert(lineno);
        }
        chain = want;
    }
    Ok(ChainReport {
        entries,
        head: chain,
        damaged,
    })
}

// ------------------------------------------------------------- sha256 --

/// A streaming SHA-256, so the chain needs no dependency.
struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    fill: usize,
    len: u64,
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256 {
    fn new() -> Sha256 {
        Sha256 {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            fill: 0,
            len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let take = (64 - self.fill).min(data.len());
            self.buf[self.fill..self.fill + take].copy_from_slice(&data[..take]);
            self.fill += take;
            data = &data[take..];
            if self.fill == 64 {
                let block = self.buf;
                self.compress(&block);
                self.fill = 0;
            }
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }

    fn finish(mut self) -> [u8; 32] {
        let bits = self.len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.fill != 56 {
            self.update(&[0x00]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 32];
        for (i, word) in self.h.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// SHA-256 over the concatenation of `parts`, as lowercase hex.
pub fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    let digest = h.finish();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_time_matches_known_values() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso_utc(2_147_483_647), "2038-01-19T03:14:07Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn lease_counts_uses_and_then_refuses() {
        let mut conf = LeaseConf::new();
        conf.set("TOKEN", LeasePolicy::new(0, 2).unwrap());
        let mut book = LeaseBook::new(conf);
        let first = match book.acquire("TOKEN", b"v", 100).unwrap() {
            LeaseOutcome::Leased(t, b) => {
                assert_eq!(b.as_slice(), b"v");
                assert_eq!(t.uses_left, 1);
                t
            }
            LeaseOutcome::Unleased(_) => panic!("expected a lease"),
        };
        assert!(matches!(
            book.acquire("TOKEN", b"v", 101),
            Ok(LeaseOutcome::Leased(..))
        ));
        let err = book
            .acquire("TOKEN", b"v", 102)
            .expect_err("third use refused");
        let text = err.to_string();
        assert!(
            text.contains(&first.id),
            "refusal names the lease id: {}",
            text
        );
        assert!(text.contains("no uses left"), "{}", text);
        // The refusal is sticky: the lease stays spent.
        assert!(book.acquire("TOKEN", b"v", 103).is_err());
    }

    #[test]
    fn lease_expires_on_ttl() {
        let mut conf = LeaseConf::new();
        conf.set("TOKEN", LeasePolicy::new(2, 0).unwrap());
        let mut book = LeaseBook::new(conf);
        assert!(book.acquire("TOKEN", b"v", 100).is_ok());
        assert!(book.acquire("TOKEN", b"v", 101).is_ok());
        let err = book.acquire("TOKEN", b"v", 102).expect_err("expired");
        assert!(err.to_string().contains("expired"), "{}", err);
    }

    #[test]
    fn lease_default_applies_to_every_secret() {
        let mut conf = LeaseConf::new();
        conf.set_default(LeasePolicy::new(0, 1).unwrap());
        assert!(conf.policy("anything").is_some());
        assert_eq!(
            conf.policy("anything").unwrap(),
            LeasePolicy::new(0, 1).unwrap()
        );
    }

    #[test]
    fn unleased_secret_has_no_lease() {
        let mut book = LeaseBook::new(LeaseConf::new());
        match book.acquire("TOKEN", b"abc", 0).unwrap() {
            LeaseOutcome::Unleased(b) => assert_eq!(b.as_slice(), b"abc"),
            LeaseOutcome::Leased(..) => panic!("no policy must not lease"),
        }
    }

    #[test]
    fn wipe_all_refuses_every_leased_secret() {
        let mut conf = LeaseConf::new();
        conf.set("A", LeasePolicy::new(0, 5).unwrap());
        conf.set("B", LeasePolicy::new(60, 0).unwrap());
        let mut book = LeaseBook::new(conf);
        assert!(book.acquire("A", b"a", 10).is_ok());
        assert!(book.acquire("B", b"b", 10).is_ok());
        book.wipe_all();
        assert!(book.acquire("A", b"a", 11).is_err());
        assert!(book.acquire("B", b"b", 11).is_err());
    }

    #[test]
    fn policy_needs_a_bound() {
        assert!(LeasePolicy::new(0, 0).is_err());
    }

    #[test]
    fn vault_lock_drops_and_keeps_refusing() {
        use crate::store::Passphrase;
        let dir = std::env::temp_dir().join(format!("pmask-vault-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.enc");
        let pp = Passphrase::new(b"pw").unwrap();
        let mut st = crate::store::Store::create(&path, &pp).unwrap();
        st.set("TOKEN", b"v").unwrap();
        let v = Vault::new(st);
        match v.copy_of("TOKEN") {
            Lookup::Found(b) => assert_eq!(b.as_slice(), b"v"),
            _ => panic!("expected the secret"),
        }
        assert!(v.lock("a test"));
        assert!(v.is_locked());
        assert!(matches!(v.copy_of("TOKEN"), Lookup::Locked(_)));
        assert!(!v.lock("again"));
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(&[b""]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(&[b"abc"]),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(&[
                b"abcdbcdecdefdefgefghfghighijhijk",
                b"ijkljklmklmnlmnomnopnopq"
            ]),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn audit_chain_verifies_and_detects_an_edit() {
        let dir = std::env::temp_dir().join(format!("pmask-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        let mut log = AuditLog::open(AuditSink::File(path.clone())).unwrap();
        for (i, name) in ["A", "B", "C"].iter().enumerate() {
            log.record(&AuditEntry {
                time: 1_700_000_000 + i as u64,
                name,
                peer_pid: 4242,
                peer_exe: "/usr/bin/pmask",
                lease_id: "ab12",
            })
            .unwrap();
        }
        let report = verify_file(&path).unwrap();
        assert_eq!(report.entries, 3);
        assert!(report.intact(), "{:?}", report);
        assert_eq!(report.head, log.chain());

        let text = std::fs::read_to_string(&path).unwrap();
        let edited = text.replacen("\tB\t", "\tX\t", 1);
        assert_ne!(text, edited);
        std::fs::write(&path, &edited).unwrap();
        let report = verify_file(&path).unwrap();
        assert_eq!(report.damaged, Some(2), "{:?}", report);

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn audit_line_carries_no_value_slot() {
        let dir = std::env::temp_dir().join(format!("pmask-audit2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        let mut log = AuditLog::open(AuditSink::File(path.clone())).unwrap();
        log.record(&AuditEntry {
            time: 1,
            name: "TOK",
            peer_pid: 7,
            peer_exe: "/bin/x",
            lease_id: "-",
        })
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("v1\t1\t1970-01-01T00:00:01Z\tTOK\t7\t/bin/x\t-"));
        assert!(text.contains("\tchain="));
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn audit_refuses_a_symlink_sink() {
        let dir = std::env::temp_dir().join(format!("pmask-audit3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.log");
        let link = dir.join("link.log");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(AuditLog::open(AuditSink::File(link.clone())).is_err());
        std::fs::remove_file(&link).ok();
        std::fs::remove_file(&target).ok();
        std::fs::remove_dir_all(&dir).ok();
    }
}
