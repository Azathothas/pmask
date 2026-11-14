//! The encrypted secret store.
//!
//! One file, one passphrase, no daemon required:
//!
//! ```text
//! pmask store init
//! pmask store set DEPLOY_TOKEN < token.txt
//! pmask run --secret DEPLOY_TOKEN=agent:DEPLOY_TOKEN -- ./deploy.sh
//! ```
//!
//! At rest the file is XChaCha20-Poly1305 ciphertext under an Argon2id
//! key; the header (KDF parameters, salt, nonce) is authenticated as
//! associated data, so it cannot be weakened without the tag failing.
//!
//! Why a store at all: the alternative on a shared host is a plaintext
//! `.env`, a `~/.config` file, or a token pasted into a runner's
//! configuration.  All of those are readable by anything running as the
//! same account, including the job that is supposed to be untrusted.
//!
//! # Writing
//!
//! A write creates a missing parent directory with mode 0700 and then
//! checks the directory it is about to write into.  The store is replaced
//! through a temporary file with an unguessable name, opened with
//! `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` and mode 0600 before any
//! ciphertext exists; the file is fsynced, renamed, and the directory is
//! fsynced after the rename.
//!
//! Writers serialize on `<store>.lock` with a non-blocking exclusive
//! `flock`.  A writer that cannot take the lock fails with "store is
//! busy" instead of waiting.  A writer also refuses to overwrite a store
//! whose metadata changed since it was opened, so a read-modify-write
//! that lost a race is reported instead of silently discarding the newer
//! entry.
//!
//! # Knobs
//!
//! | variable | effect |
//! |---|---|
//! | `PMASK_KDF_MAX_MEM` | ceiling for `m_cost`, in KiB (default 1048576) |
//! | `PMASK_KDF_MAX_TIME` | ceiling for `t_cost` (default 10) |
//! | `PMASK_ALLOW_WEAK_KDF` | accept KDF parameters below the baseline |
//! | `PMASK_ALLOW_SHARED_DIR` | write a store into a group/other writable directory |
//! | `PMASK_ALLOW_STALE_WRITE` | overwrite a store that changed since it was opened |
//!
//! Each is read when a [`Store`] is constructed (or, for the last one,
//! when it is saved), never in a loop.

use crate::mem::SecBuf;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroize;

const MAGIC: &[u8; 16] = b"PMASKSTORE1\0\0\0\0\0";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Mode of the store file and of every temporary file written for it.
const FILE_MODE: u32 = 0o600;
/// Mode of a store directory this process creates.
const DIR_MODE: u32 = 0o700;

/// Smallest memory cost `argon2` accepts, in KiB.
const MIN_M_COST: u32 = 8;
/// Largest lane count this store accepts.
const MAX_P_COST: u32 = 8;
/// Default ceiling for `m_cost`, in KiB (1 GiB).
const DEFAULT_MAX_M_COST: u32 = 1024 * 1024;
/// Hard ceiling for `PMASK_KDF_MAX_MEM`, in KiB (4 GiB).
const HARD_MAX_M_COST: u32 = 4 * 1024 * 1024;
/// Default ceiling for `t_cost`.
const DEFAULT_MAX_T_COST: u32 = 10;
/// Hard ceiling for `PMASK_KDF_MAX_TIME`.
const HARD_MAX_T_COST: u32 = 1000;
/// How many temporary names to try before giving up on `EEXIST`.
const TEMP_ATTEMPTS: usize = 8;
/// Longest passphrase line [`Passphrase::from_file`] accepts, in bytes.
const MAX_PASSPHRASE: usize = 4096;

/// Largest store file [`Store::open_with_policy`] reads, in bytes.
///
/// A store is a local secrets file, not a data store.  The agent's largest
/// single reply is 8 MiB and one value is capped at 1 MiB, so 64 MiB holds
/// 64 maximum-size values.  The bound exists so a replaced or corrupted
/// file cannot make an open pull an unbounded amount into memory, and
/// [`Store::save`] refuses to write a store this limit would refuse to
/// open.
const MAX_STORE_FILE: usize = 64 << 20;
/// Fixed part of a store file: magic, the three KDF parameters, the salt
/// length and salt, the nonce length and nonce, and the ciphertext length.
const HEADER_LEN: usize = MAGIC.len() + 12 + 1 + SALT_LEN + 1 + NONCE_LEN + 8;
/// Poly1305 tag appended to the ciphertext.
const TAG_LEN: usize = 16;
/// Largest plaintext a store file can hold within [`MAX_STORE_FILE`].
const MAX_STORE_PLAINTEXT: usize = MAX_STORE_FILE - HEADER_LEN - TAG_LEN;

/// Argon2id cost.  The OWASP 2024 baseline for interactive use; it is
/// what a phone and a CI runner can both afford.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params2 {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallel lanes.
    pub p_cost: u32,
}

impl Default for Params2 {
    fn default() -> Self {
        Params2 {
            m_cost: 19 * 1024, // KiB == 19 MiB
            t_cost: 2,
            p_cost: 1,
        }
    }
}

impl Params2 {
    /// Memory cost of the baseline, in KiB (19 MiB).
    pub const BASELINE_M_COST: u32 = 19 * 1024;
    /// Iteration count of the baseline.
    pub const BASELINE_T_COST: u32 = 2;

    /// Reject parameters outside the range this build will derive a key
    /// with.  Called before [`Params::new`], so a crafted header cannot
    /// ask for a multi-gigabyte allocation or a days-long derivation.
    pub fn validate(&self, limits: &KdfLimits) -> io::Result<()> {
        if self.m_cost < MIN_M_COST {
            return Err(invalid_params(format!(
                "m_cost {} KiB is below the minimum {} KiB",
                self.m_cost, MIN_M_COST
            )));
        }
        if self.m_cost > limits.max_m_cost {
            return Err(invalid_params(format!(
                "m_cost {} KiB exceeds the ceiling {} KiB; raise PMASK_KDF_MAX_MEM to accept it",
                self.m_cost, limits.max_m_cost
            )));
        }
        if self.t_cost < 1 {
            return Err(invalid_params(format!(
                "t_cost {} is below the minimum 1",
                self.t_cost
            )));
        }
        if self.t_cost > limits.max_t_cost {
            return Err(invalid_params(format!(
                "t_cost {} exceeds the ceiling {}; raise PMASK_KDF_MAX_TIME to accept it",
                self.t_cost, limits.max_t_cost
            )));
        }
        if self.p_cost < 1 || self.p_cost > MAX_P_COST {
            return Err(invalid_params(format!(
                "p_cost {} is outside 1 to {}",
                self.p_cost, MAX_P_COST
            )));
        }
        if self.m_cost < 8 * self.p_cost {
            return Err(invalid_params(format!(
                "m_cost {} KiB is below 8 KiB times p_cost {} ({} KiB)",
                self.m_cost,
                self.p_cost,
                8 * self.p_cost
            )));
        }
        if !limits.allow_weak
            && (self.m_cost < Params2::BASELINE_M_COST || self.t_cost < Params2::BASELINE_T_COST)
        {
            return Err(invalid_params(format!(
                "m_cost {} KiB with t_cost {} is weaker than the baseline \
                 (m_cost {} KiB, t_cost {}); set PMASK_ALLOW_WEAK_KDF=1 to accept weaker parameters",
                self.m_cost,
                self.t_cost,
                Params2::BASELINE_M_COST,
                Params2::BASELINE_T_COST
            )));
        }
        Ok(())
    }
}

fn invalid_params(message: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("KDF parameters refused: {}", message),
    )
}

/// Bounds applied to the Argon2id parameters, from the environment or set
/// explicitly by the caller.
#[derive(Debug, Clone, Copy)]
pub struct KdfLimits {
    /// Largest accepted `m_cost`, in KiB.
    pub max_m_cost: u32,
    /// Largest accepted `t_cost`.
    pub max_t_cost: u32,
    /// Accept parameters below the baseline (19 MiB, t=2).
    pub allow_weak: bool,
}

impl Default for KdfLimits {
    fn default() -> Self {
        KdfLimits {
            max_m_cost: DEFAULT_MAX_M_COST,
            max_t_cost: DEFAULT_MAX_T_COST,
            allow_weak: false,
        }
    }
}

impl KdfLimits {
    /// Read the limits from the environment.  A malformed value is an
    /// error, never a silent fallback to the default.
    pub fn from_env() -> io::Result<KdfLimits> {
        Ok(KdfLimits {
            max_m_cost: env_u32(
                "PMASK_KDF_MAX_MEM",
                DEFAULT_MAX_M_COST,
                MIN_M_COST,
                HARD_MAX_M_COST,
            )?,
            max_t_cost: env_u32("PMASK_KDF_MAX_TIME", DEFAULT_MAX_T_COST, 1, HARD_MAX_T_COST)?,
            allow_weak: env_flag("PMASK_ALLOW_WEAK_KDF"),
        })
    }
}

/// How a [`Store`] is allowed to write: KDF bounds plus the two opt-ins
/// that a write otherwise refuses.
#[derive(Debug, Clone, Copy, Default)]
pub struct StorePolicy {
    /// Bounds on the Argon2id parameters.
    pub kdf: KdfLimits,
    /// Write into a directory that is group or other writable.
    pub allow_shared_dir: bool,
    /// Overwrite a store that changed since it was opened.
    pub allow_stale_write: bool,
}

impl StorePolicy {
    /// Read the policy from the environment.
    pub fn from_env() -> io::Result<StorePolicy> {
        Ok(StorePolicy {
            kdf: KdfLimits::from_env()?,
            allow_shared_dir: env_flag("PMASK_ALLOW_SHARED_DIR"),
            allow_stale_write: env_flag("PMASK_ALLOW_STALE_WRITE"),
        })
    }
}

/// A passphrase, held in protected memory.
pub struct Passphrase(SecBuf);

impl Passphrase {
    /// Copy `bytes` into protected memory.
    pub fn new(bytes: &[u8]) -> io::Result<Passphrase> {
        Ok(Passphrase(SecBuf::from_slice(bytes)?))
    }

    /// The passphrase bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Read a passphrase from a file: one line, with one trailing newline
    /// removed.
    ///
    /// Only the first line is read, so a second line is not part of the
    /// passphrase.  A first line longer than `MAX_PASSPHRASE` bytes and a
    /// NUL byte are refused rather than hashed: either means the file is
    /// not a passphrase, and hashing it would derive a key nothing else can
    /// reproduce.
    pub fn from_file(p: &Path) -> io::Result<Passphrase> {
        let f = std::fs::File::open(p)?;
        let md = f.metadata()?;
        if md.permissions().mode() & 0o077 != 0 {
            eprintln!(
                "pmask: warning: passphrase file {} is group/world readable",
                p.display()
            );
        }
        // One byte for the newline and one to tell an over-long line from a
        // line that is exactly at the limit, without reading the rest of
        // the file.
        let mut r = std::io::BufReader::new(f).take((MAX_PASSPHRASE + 2) as u64);
        let mut v = Vec::new();
        r.read_until(b'\n', &mut v)?;
        if v.last() == Some(&b'\n') {
            v.pop();
        }
        if v.len() > MAX_PASSPHRASE {
            v.zeroize();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "passphrase file {} is longer than {} bytes on its first line; \
                     a passphrase must fit in one line",
                    p.display(),
                    MAX_PASSPHRASE
                ),
            ));
        }
        if v.contains(&0) {
            v.zeroize();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("passphrase file {} contains a NUL byte", p.display()),
            ));
        }
        let pp = match Passphrase::new(&v) {
            Ok(pp) => pp,
            Err(e) => {
                v.zeroize();
                return Err(e);
            }
        };
        v.zeroize();
        Ok(pp)
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        // SAFETY: writing into our own buffer.
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
    Ok(())
}

fn derive_key(passphrase: &Passphrase, salt: &[u8], params: Params2) -> io::Result<[u8; KEY_LEN]> {
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut key = [0u8; KEY_LEN];
    a.hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok(key)
}

fn env_flag(name: &str) -> bool {
    match std::env::var_os(name) {
        Some(v) => {
            let s = v.to_string_lossy();
            !s.is_empty() && s != "0"
        }
        None => false,
    }
}

fn env_u32(name: &str, fallback: u32, min: u32, max: u32) -> io::Result<u32> {
    let Some(raw) = std::env::var_os(name) else {
        return Ok(fallback);
    };
    let text = raw.to_string_lossy();
    let value: u32 = text.trim().parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}={:?} is not a decimal number", name, text),
        )
    })?;
    if value < min || value > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{}={} is outside the accepted range {} to {}",
                name, value, min, max
            ),
        ));
    }
    Ok(value)
}

fn context(path: &Path, err: io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {}", path.display(), err))
}

/// The refusal for a store file larger than [`MAX_STORE_FILE`].
fn store_too_large(path: &Path, len: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{} is {} bytes, larger than the {} MiB store limit",
            path.display(),
            len,
            MAX_STORE_FILE / (1024 * 1024)
        ),
    )
}

/// Identity and timestamps of the store file at the moment it was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileSnapshot {
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    len: u64,
}

impl FileSnapshot {
    fn from_metadata(md: &std::fs::Metadata) -> FileSnapshot {
        FileSnapshot {
            dev: md.dev(),
            ino: md.ino(),
            mtime: md.mtime(),
            mtime_nsec: md.mtime_nsec(),
            len: md.len(),
        }
    }

    fn read(path: &Path) -> io::Result<FileSnapshot> {
        Ok(FileSnapshot::from_metadata(&std::fs::metadata(path)?))
    }
}

fn lock_path(store: &Path) -> PathBuf {
    let mut name = match store.file_name() {
        Some(n) => n.to_os_string(),
        None => std::ffi::OsString::from("store.enc"),
    };
    name.push(".lock");
    store.with_file_name(name)
}

/// The exclusive advisory lock on `<store>.lock`.
///
/// Hold it across a read-modify-write and call [`Store::save_locked`].
/// It is released on drop.
pub struct StoreLock {
    file: File,
    path: PathBuf,
}

impl StoreLock {
    /// Take the lock without waiting.  A second writer fails at once with
    /// [`io::ErrorKind::WouldBlock`] and a "store is busy" message.
    pub fn acquire(store: &Path) -> io::Result<StoreLock> {
        let path = lock_path(store);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| context(&path, e))?;
        // SAFETY: flock on our own descriptor.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == -1 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "store is busy: another pmask process holds {}; retry when it finishes",
                        path.display()
                    ),
                ));
            }
            return Err(context(&path, e));
        }
        Ok(StoreLock { file, path })
    }

    /// The lock file this guard holds.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor is ours and is still open here.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl std::fmt::Debug for StoreLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreLock")
            .field("path", &self.path)
            .finish()
    }
}

/// A temporary file that is removed unless it was renamed into place.
struct TempFile {
    path: PathBuf,
    armed: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Bounds-checked reads over the store file.
struct SliceReader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> SliceReader<'a> {
    fn new(buf: &'a [u8]) -> SliceReader<'a> {
        SliceReader { buf, off: 0 }
    }

    fn offset(&self) -> usize {
        self.off
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.off
    }

    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "store file truncated",
            ));
        }
        let s = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }

    fn take_len(&mut self, n: u64) -> io::Result<&'a [u8]> {
        let n = usize::try_from(n)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "store length out of range"))?;
        self.take(n)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        // unwrap-ok: take(2) returns exactly two bytes
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> io::Result<u32> {
        // unwrap-ok: take(4) returns exactly four bytes
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> io::Result<u64> {
        // unwrap-ok: take(8) returns exactly eight bytes
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

/// The parsed header of a store file, with offsets into the file bytes.
/// Salt and nonce are public and are copied out, so the caller can wipe the
/// file bytes while the header is still in scope.
struct Header {
    params: Params2,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    aad_end: usize,
    ciphertext_start: usize,
    ciphertext_len: usize,
}

/// Parse a store header from raw bytes and validate its KDF parameters.
///
/// This is the entry point a fuzz target needs: it walks every length
/// field in the header (`m_cost`, `t_cost`, `p_cost`, the salt and nonce
/// lengths, the ciphertext length) and bounds each one before anything
/// allocates.  It is public because the parser is the only part of this
/// crate that reads attacker-influenced bytes, and a target outside the
/// crate cannot exercise it otherwise.
pub fn parse_header_bounded(blob: &[u8], policy: &StorePolicy) -> io::Result<()> {
    let header = parse_header(blob)?;
    header.params.validate(&policy.kdf)
}

fn parse_header(blob: &[u8]) -> io::Result<Header> {
    let mut r = SliceReader::new(blob);
    if r.take(MAGIC.len())? != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a pmask store (bad magic)",
        ));
    }
    let params = Params2 {
        m_cost: r.u32()?,
        t_cost: r.u32()?,
        p_cost: r.u32()?,
    };
    if r.u8()? as usize != SALT_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad salt"));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(r.take(SALT_LEN)?);
    if r.u8()? as usize != NONCE_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad nonce"));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(r.take(NONCE_LEN)?);
    let aad_end = r.offset();
    let ciphertext_len = r.u64()?;
    let ciphertext_start = r.offset();
    let ciphertext = r.take_len(ciphertext_len)?;
    if r.remaining() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing bytes after the ciphertext",
        ));
    }
    Ok(Header {
        params,
        salt,
        nonce,
        aad_end,
        ciphertext_start,
        ciphertext_len: ciphertext.len(),
    })
}

/// An unlocked store.
pub struct Store {
    path: PathBuf,
    entries: BTreeMap<String, SecBuf>,
    params: Params2,
    snapshot: Mutex<Option<FileSnapshot>>,
    policy: StorePolicy,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.path)
            .field("entries", &self.entries.keys().collect::<Vec<_>>())
            .field("params", &self.params)
            .finish()
    }
}

fn encode_plaintext(entries: &BTreeMap<String, SecBuf>) -> io::Result<SecBuf> {
    let total = plaintext_len(entries);
    let mut out = SecBuf::new(total)?;
    let mut o = 0usize;
    let put = |out: &mut SecBuf, bytes: &[u8], o: &mut usize| {
        out.as_mut_slice()[*o..*o + bytes.len()].copy_from_slice(bytes);
        *o += bytes.len();
    };
    put(&mut out, &(entries.len() as u32).to_le_bytes(), &mut o);
    for (k, v) in entries {
        put(&mut out, &(k.len() as u16).to_le_bytes(), &mut o);
        put(&mut out, k.as_bytes(), &mut o);
        put(&mut out, &(v.len() as u32).to_le_bytes(), &mut o);
        put(&mut out, v.as_slice(), &mut o);
    }
    Ok(out)
}

/// Encoded size of `entries`: the length [`encode_plaintext`] produces.
///
/// Split out so the write path can check the size against
/// [`MAX_STORE_PLAINTEXT`] before it allocates the buffer.
fn plaintext_len(entries: &BTreeMap<String, SecBuf>) -> usize {
    let mut total = 4usize;
    for (k, v) in entries {
        total += 2 + k.len() + 4 + v.len();
    }
    total
}

fn decode_plaintext(buf: &SecBuf) -> io::Result<BTreeMap<String, SecBuf>> {
    let mut r = SliceReader::new(buf.as_slice());
    let count = r.u32()? as usize;
    let mut m = BTreeMap::new();
    for _ in 0..count {
        let name_len = r.u16()? as usize;
        let name = String::from_utf8(r.take(name_len)?.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "store: bad name"))?;
        let value_len = r.u32()? as u64;
        let value = r.take_len(value_len)?;
        m.insert(name, SecBuf::from_slice(value)?);
    }
    Ok(m)
}

impl Store {
    /// Create a new, empty store and write it out.
    pub fn create(path: &Path, passphrase: &Passphrase) -> io::Result<Store> {
        Store::create_with_policy(path, passphrase, StorePolicy::from_env()?)
    }

    /// Create a new, empty store under an explicit policy.
    pub fn create_with_policy(
        path: &Path,
        passphrase: &Passphrase,
        policy: StorePolicy,
    ) -> io::Result<Store> {
        let s = Store {
            path: path.to_path_buf(),
            entries: BTreeMap::new(),
            params: Params2::default(),
            snapshot: Mutex::new(None),
            policy,
        };
        s.save(passphrase)?;
        Ok(s)
    }

    /// Unlock an existing store.
    pub fn open(path: &Path, passphrase: &Passphrase) -> io::Result<Store> {
        Store::open_with_policy(path, passphrase, StorePolicy::from_env()?)
    }

    /// Unlock an existing store under an explicit policy.
    #[allow(deprecated)]
    pub fn open_with_policy(
        path: &Path,
        passphrase: &Passphrase,
        policy: StorePolicy,
    ) -> io::Result<Store> {
        let f = File::open(path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => io::Error::new(
                e.kind(),
                format!(
                    "no store at {}; run `pmask store init` to create one",
                    path.display()
                ),
            ),
            _ => context(path, e),
        })?;
        let md = f.metadata()?;
        if !md.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: not a regular file", path.display()),
            ));
        }
        if md.permissions().mode() & 0o077 != 0 {
            eprintln!(
                "pmask: warning: store {} is group/world readable",
                path.display()
            );
        }
        // Refuse an oversize file before it is read.  The store is 0600,
        // but a replaced or corrupted file must not decide how much this
        // process allocates.
        if md.len() > MAX_STORE_FILE as u64 {
            return Err(store_too_large(path, md.len()));
        }
        let snapshot = FileSnapshot::from_metadata(&md);
        let mut blob = Vec::new();
        // One byte past the limit, so a file that grew after the metadata
        // check is refused rather than read whole.
        f.take(MAX_STORE_FILE as u64 + 1).read_to_end(&mut blob)?;
        if blob.len() > MAX_STORE_FILE {
            return Err(store_too_large(path, blob.len() as u64));
        }

        let header = parse_header(&blob)?;
        header.params.validate(&policy.kdf)?;
        let params = header.params;

        let mut key = derive_key(passphrase, &header.salt, params)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        key.zeroize();

        let ct_end = header.ciphertext_start + header.ciphertext_len;
        let plain = cipher
            .decrypt(
                XNonce::from_slice(&header.nonce),
                Payload {
                    msg: &blob[header.ciphertext_start..ct_end],
                    aad: &blob[..header.aad_end],
                },
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cannot decrypt store: wrong passphrase or corrupted file",
                )
            })?;

        let mut sb = SecBuf::new(plain.len())?;
        sb.as_mut_slice().copy_from_slice(&plain);
        let mut plain = plain;
        plain.zeroize();
        let entries = decode_plaintext(&sb)?;
        blob.zeroize();
        Ok(Store {
            path: path.to_path_buf(),
            entries,
            params,
            snapshot: Mutex::new(Some(snapshot)),
            policy,
        })
    }

    /// Re-encrypt and write the store.
    ///
    /// Takes the writer lock, refuses a store that changed since it was
    /// opened, and replaces the file atomically.
    pub fn save(&self, passphrase: &Passphrase) -> io::Result<()> {
        let lock = self.lock()?;
        self.save_locked(passphrase, &lock)
    }

    /// Write the store while the caller holds its lock.
    ///
    /// The lock is checked against this store's path: a guard taken on a
    /// different store would serialize the wrong pair of writers.
    pub fn save_locked(&self, passphrase: &Passphrase, lock: &StoreLock) -> io::Result<()> {
        let want = lock_path(&self.path);
        if lock.path != want {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "the lock for {} does not guard {}; take it with Store::lock",
                    lock.path.display(),
                    self.path.display()
                ),
            ));
        }
        let dir = check_parent_dir(&self.path, self.policy.allow_shared_dir, false)?;
        self.save_in(&dir, passphrase)
    }

    #[allow(deprecated)]
    fn save_in(&self, dir: &Path, passphrase: &Passphrase) -> io::Result<()> {
        self.params.validate(&self.policy.kdf)?;

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        random_bytes(&mut salt)?;
        random_bytes(&mut nonce)?;

        let plain_len = plaintext_len(&self.entries);
        if plain_len > MAX_STORE_PLAINTEXT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "the store would be {} bytes, larger than the {} MiB store limit; \
                     remove entries or values",
                    plain_len + HEADER_LEN + TAG_LEN,
                    MAX_STORE_FILE / (1024 * 1024)
                ),
            ));
        }
        let plain = encode_plaintext(&self.entries)?;
        let mut key = derive_key(passphrase, &salt, self.params)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        key.zeroize();

        let mut header = Vec::with_capacity(16 + 12 + 1 + SALT_LEN + 1 + NONCE_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&self.params.m_cost.to_le_bytes());
        header.extend_from_slice(&self.params.t_cost.to_le_bytes());
        header.extend_from_slice(&self.params.p_cost.to_le_bytes());
        header.push(SALT_LEN as u8);
        header.extend_from_slice(&salt);
        header.push(NONCE_LEN as u8);
        header.extend_from_slice(&nonce);

        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plain.as_slice(),
                    aad: &header,
                },
            )
            .map_err(|_| io::Error::other("encryption failed"))?;

        self.check_snapshot()?;
        let snapshot = write_store(&self.path, dir, &header, &ct)?;
        *self.snapshot.lock().unwrap_or_else(|e| e.into_inner()) = Some(snapshot);
        Ok(())
    }

    /// Take the store's writer lock, or fail with "store is busy".
    ///
    /// The parent directory is created when it is missing, because the lock
    /// file is a sibling of the store.
    pub fn lock(&self) -> io::Result<StoreLock> {
        check_parent_dir(&self.path, self.policy.allow_shared_dir, true)?;
        StoreLock::acquire(&self.path)
    }

    /// Re-read the file when it changed since this handle opened it.
    ///
    /// Returns `true` when the entries were replaced.  Use this together
    /// with [`Store::lock`] and [`Store::save_locked`] to make a
    /// read-modify-write safe against a concurrent writer.
    pub fn reload_if_changed(&mut self, passphrase: &Passphrase) -> io::Result<bool> {
        let expected = *self.snapshot.lock().unwrap_or_else(|e| e.into_inner());
        let Some(expected) = expected else {
            return Ok(false);
        };
        let current = match FileSnapshot::read(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(conflict_error(
                    &self.path,
                    "was removed on disk since it was opened",
                ))
            }
            Err(e) => return Err(context(&self.path, e)),
        };
        if current == expected {
            return Ok(false);
        }
        let fresh = Store::open_with_policy(&self.path, passphrase, self.policy)?;
        self.entries = fresh.entries;
        self.params = fresh.params;
        *self.snapshot.lock().unwrap_or_else(|e| e.into_inner()) = Some(current);
        Ok(true)
    }

    /// Refuse to write over a file that changed since this handle read it.
    fn check_snapshot(&self) -> io::Result<()> {
        if self.policy.allow_stale_write {
            return Ok(());
        }
        let expected = *self.snapshot.lock().unwrap_or_else(|e| e.into_inner());
        let Some(expected) = expected else {
            return Ok(());
        };
        match FileSnapshot::read(&self.path) {
            Ok(current) if current == expected => Ok(()),
            Ok(_) => Err(conflict_error(
                &self.path,
                "changed on disk since it was opened",
            )),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(conflict_error(
                &self.path,
                "was removed on disk since it was opened",
            )),
            Err(e) => Err(context(&self.path, e)),
        }
    }

    /// Add or replace an entry.
    ///
    /// A name longer than 65535 bytes or a value longer than 4 GiB is
    /// refused: the store's encoding carries those lengths in a `u16` and a
    /// `u32`, and a truncated length would write a file nothing can read
    /// back.
    pub fn set(&mut self, name: &str, value: &[u8]) -> io::Result<()> {
        if name.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "secret name is {} bytes, the limit is {}",
                    name.len(),
                    u16::MAX
                ),
            ));
        }
        if value.len() > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "secret value is {} bytes, the limit is {}",
                    value.len(),
                    u32::MAX
                ),
            ));
        }
        self.entries
            .insert(name.to_string(), SecBuf::from_slice(value)?);
        Ok(())
    }

    /// The value of `name`, if present.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.entries.get(name).map(|b| b.as_slice())
    }

    /// Remove `name`; true when it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        self.entries.remove(name).is_some()
    }

    /// Every name, in sorted order.
    pub fn names(&self) -> Vec<&str> {
        self.entries.keys().map(|s| s.as_str()).collect()
    }

    /// True when the store holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Where this store lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The Argon2id cost used for the next save.
    pub fn params(&self) -> Params2 {
        self.params
    }

    /// Set the Argon2id cost for the next save.  [`Store::save`] rejects
    /// values outside the policy bounds.
    pub fn set_params(&mut self, params: Params2) {
        self.params = params;
    }
}

fn conflict_error(path: &Path, what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        format!(
            "store changed while it was being written: {} {}; re-run the command \
             to read the newer store, or set PMASK_ALLOW_STALE_WRITE=1 to overwrite it",
            path.display(),
            what
        ),
    )
}

/// Create the store's directory when it is missing and check the directory
/// the store is about to be written into.
///
/// A directory this process creates must be 0700 and owned by this account.
/// A directory that already existed is checked the same way, but a bad mode
/// or a foreign owner only produces a warning: permissions on a directory we
/// did not create are not ours to change.
///
/// A group or other writable directory needs `allow_shared`, because another
/// account could replace the store between the rename and the next read.
/// `warn` is false for a caller that already checked this directory in the
/// same write, so one operation never prints the same warning twice.
fn check_parent_dir(store: &Path, allow_shared: bool, warn: bool) -> io::Result<PathBuf> {
    let parent = match store.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let existed = parent.is_dir();
    if !existed {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(parent)
            .map_err(|e| context(parent, e))?;
    }
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|e| context(parent, e))?;
    let md = dir.metadata().map_err(|e| context(parent, e))?;
    if !md.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: not a directory", parent.display()),
        ));
    }
    let mode = md.permissions().mode() & 0o7777;
    let uid = md.uid();
    // SAFETY: geteuid has no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if !existed {
        if uid != euid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{}: the directory just created is owned by uid {}, not this account (uid {})",
                    parent.display(),
                    uid,
                    euid
                ),
            ));
        }
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{}: the directory just created has mode 0o{:o}, not 0700",
                    parent.display(),
                    mode
                ),
            ));
        }
        return Ok(parent.to_path_buf());
    }
    if mode & 0o022 != 0 {
        if !allow_shared {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{}: store directory is group or other writable (mode 0o{:o}); \
                     refusing to write a store there. Set PMASK_ALLOW_SHARED_DIR=1 to allow it.",
                    parent.display(),
                    mode
                ),
            ));
        }
        if warn {
            eprintln!(
                "pmask: warning: writing the store into a group or other writable directory {} (mode 0o{:o}); another account can replace it",
                parent.display(),
                mode
            );
        }
    }
    if warn && uid != euid {
        eprintln!(
            "pmask: warning: store directory {} is owned by uid {}, not this account (uid {}); its owner can replace the store",
            parent.display(),
            uid,
            euid
        );
    }
    Ok(parent.to_path_buf())
}

/// A fresh, unguessable sibling name for the temporary file.
fn temp_path(store: &Path) -> io::Result<PathBuf> {
    let name = store.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: store path has no file name", store.display()),
        )
    })?;
    let mut rnd = [0u8; 8];
    random_bytes(&mut rnd)?;
    let mut tmp = name.to_os_string();
    tmp.push(".tmp.");
    for b in rnd {
        tmp.push(format!("{:02x}", b));
    }
    Ok(store.with_file_name(tmp))
}

/// Create the temporary file with an exclusive create, and set its mode
/// before the caller writes anything into it.
fn create_temp(store: &Path) -> io::Result<(File, TempFile)> {
    let mut last: Option<io::Error> = None;
    for _ in 0..TEMP_ATTEMPTS {
        let path = temp_path(store)?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => {
                if let Err(e) = file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE)) {
                    let _ = std::fs::remove_file(&path);
                    return Err(context(&path, e));
                }
                return Ok((file, TempFile { path, armed: true }));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                last = Some(context(&path, e));
            }
            Err(e) => return Err(context(&path, e)),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{}: cannot create a temporary store file next to the store",
                store.display()
            ),
        )
    }))
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(dir)
        .map_err(|e| context(dir, e))?;
    f.sync_all().map_err(|e| context(dir, e))
}

fn write_store(
    path: &Path,
    dir: &Path,
    header: &[u8],
    ciphertext: &[u8],
) -> io::Result<FileSnapshot> {
    let (mut file, mut temp) = create_temp(path)?;
    file.write_all(header).map_err(|e| context(&temp.path, e))?;
    file.write_all(&(ciphertext.len() as u64).to_le_bytes())
        .map_err(|e| context(&temp.path, e))?;
    file.write_all(ciphertext)
        .map_err(|e| context(&temp.path, e))?;
    file.sync_all().map_err(|e| context(&temp.path, e))?;
    let snapshot =
        FileSnapshot::from_metadata(&file.metadata().map_err(|e| context(&temp.path, e))?);
    std::fs::rename(&temp.path, path).map_err(|e| context(path, e))?;
    temp.armed = false;
    fsync_dir(dir)?;
    Ok(snapshot)
}

/// Where the store lives when no `--store` is given.
pub fn default_path() -> PathBuf {
    if let Some(p) = std::env::var_os("PMASK_STORE") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("pmask").join("store.enc")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("pmask-store-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    /// A private directory for one test case.
    fn case(name: &str) -> PathBuf {
        let d = tmpdir().join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn roundtrip() {
        let d = tmpdir();
        let p = d.join("s.enc");
        let pp = Passphrase::new(b"correct horse").unwrap();
        let mut s = Store::create(&p, &pp).unwrap();
        s.set("A", b"one").unwrap();
        s.set("B", b"two").unwrap();
        s.save(&pp).unwrap();

        let s2 = Store::open(&p, &pp).unwrap();
        assert_eq!(s2.get("A"), Some(&b"one"[..]));
        assert_eq!(s2.get("B"), Some(&b"two"[..]));
        assert_eq!(s2.names(), vec!["A", "B"]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn wrong_passphrase_fails() {
        let d = tmpdir();
        let p = d.join("w.enc");
        let pp = Passphrase::new(b"right").unwrap();
        let mut s = Store::create(&p, &pp).unwrap();
        s.set("A", b"one").unwrap();
        s.save(&pp).unwrap();
        let bad = Passphrase::new(b"wrong").unwrap();
        assert!(Store::open(&p, &bad).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn file_is_0600() {
        let d = tmpdir();
        let p = d.join("m.enc");
        let pp = Passphrase::new(b"x").unwrap();
        Store::create(&p, &pp).unwrap();
        assert_eq!(mode_of(&p), 0o600);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let d = tmpdir();
        let p = d.join("c.enc");
        let pp = Passphrase::new(b"x").unwrap();
        let mut s = Store::create(&p, &pp).unwrap();
        s.set("TOKEN", b"SUPERSECRETVALUE").unwrap();
        s.save(&pp).unwrap();
        let raw = std::fs::read(&p).unwrap();
        assert!(!raw.windows(16).any(|w| w == b"SUPERSECRETVALUE"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn creates_missing_parent_directory() {
        // Deliberately no create_dir_all: the store must create the chain.
        let root = tmpdir().join("fresh-account");
        std::fs::remove_dir_all(&root).ok();
        let d = root.join("nested");
        let p = d.join("s.enc");
        let pp = Passphrase::new(b"x").unwrap();
        Store::create(&p, &pp).unwrap();
        assert!(d.is_dir());
        assert_eq!(mode_of(&d), 0o700);
        assert_eq!(mode_of(&p), 0o600);
        assert_eq!(mode_of(&root), 0o700);
        let s = Store::open(&p, &pp).unwrap();
        assert!(s.is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn existing_directory_mode_is_not_changed() {
        let d = case("existing-0755");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pp = Passphrase::new(b"x").unwrap();
        Store::create(&d.join("s.enc"), &pp).unwrap();
        assert_eq!(mode_of(&d), 0o755);
    }

    #[test]
    fn shared_directory_needs_optin() {
        let d = case("shared-0777");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        let p = d.join("s.enc");
        let err = check_parent_dir(&p, false, true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains("PMASK_ALLOW_SHARED_DIR"),
            "{}",
            err
        );
        check_parent_dir(&p, true, true).unwrap();

        let pp = Passphrase::new(b"x").unwrap();
        let policy = StorePolicy {
            allow_shared_dir: true,
            ..StorePolicy::default()
        };
        Store::create_with_policy(&p, &pp, policy).unwrap();
        assert!(Store::open(&p, &pp).is_ok());
    }

    #[test]
    fn temp_file_is_private_and_removed() {
        let d = case("temp-clean");
        let p = d.join("s.enc");
        let pp = Passphrase::new(b"x").unwrap();
        Store::create(&p, &pp).unwrap();
        assert_eq!(mode_of(&p), 0o600);
        let leftovers: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temporary files left: {:?}",
            leftovers
        );
    }

    #[test]
    fn temp_file_is_unlinked_when_the_write_does_not_land() {
        // A guard that is only dropped after a successful rename proves
        // nothing about the error path, which is the one that can leave a
        // partial ciphertext behind.
        let d = case("temp-drop");
        let p = d.join("s.enc");
        let (file, temp) = create_temp(&p).unwrap();
        let path = temp.path.clone();
        assert_eq!(mode_of(&path), 0o600);
        drop(file);
        assert!(path.exists(), "the temporary file should exist before drop");
        drop(temp);
        assert!(!path.exists(), "the temporary file survived the error path");
    }

    #[test]
    fn planted_symlink_is_not_followed() {
        let d = case("planted-link");
        let p = d.join("s.enc");
        let sentinel = d.join("sentinel");
        std::fs::write(&sentinel, b"sentinel-content").unwrap();
        let planted = ["s.tmp", "s.enc.tmp", "s.enc.tmp.0000000000000000"];
        for old in planted {
            std::os::unix::fs::symlink(&sentinel, d.join(old)).unwrap();
        }
        let pp = Passphrase::new(b"x").unwrap();
        let mut s = Store::create(&p, &pp).unwrap();
        s.set("A", b"one").unwrap();
        s.save(&pp).unwrap();
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel-content");
        for old in planted {
            assert!(std::fs::symlink_metadata(d.join(old))
                .unwrap()
                .file_type()
                .is_symlink());
        }
        assert_eq!(Store::open(&p, &pp).unwrap().get("A"), Some(&b"one"[..]));
    }

    #[test]
    fn stale_temp_file_is_not_reused() {
        let d = case("stale-temp");
        let p = d.join("s.enc");
        let stale = d.join("s.enc.tmp");
        std::fs::write(&stale, b"stale").unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644)).unwrap();
        let pp = Passphrase::new(b"x").unwrap();
        Store::create(&p, &pp).unwrap();
        assert_eq!(mode_of(&p), 0o600);
        assert_eq!(std::fs::read(&stale).unwrap(), b"stale");
        assert_eq!(mode_of(&stale), 0o644);
    }

    #[test]
    fn lock_is_exclusive_and_nonblocking() {
        let d = case("lock");
        let p = d.join("s.enc");
        let pp = Passphrase::new(b"x").unwrap();
        Store::create(&p, &pp).unwrap();
        let held = StoreLock::acquire(&p).unwrap();
        let err = StoreLock::acquire(&p).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(err.to_string().contains("store is busy"), "{}", err);
        drop(held);
        StoreLock::acquire(&p).unwrap();
    }

    #[test]
    fn changed_store_is_not_overwritten() {
        let d = case("conflict");
        let p = d.join("s.enc");
        let pp = Passphrase::new(b"x").unwrap();
        let mut s = Store::create(&p, &pp).unwrap();
        s.set("A", b"one").unwrap();
        s.save(&pp).unwrap();

        let mut stale = Store::open(&p, &pp).unwrap();
        // An external writer replaces the file behind this handle.
        let other_dir = case("conflict-other");
        let other_path = other_dir.join("s.enc");
        let mut other = Store::create(&other_path, &pp).unwrap();
        other.set("B", b"two").unwrap();
        other.save(&pp).unwrap();
        std::fs::rename(&other_path, &p).unwrap();

        stale.set("C", b"three").unwrap();
        let err = stale.save(&pp).unwrap_err();
        assert!(
            err.to_string()
                .contains("changed while it was being written"),
            "{}",
            err
        );
        assert!(!err.to_string().contains("store is busy"), "{}", err);
        assert!(
            err.to_string().contains("PMASK_ALLOW_STALE_WRITE"),
            "{}",
            err
        );

        let policy = StorePolicy {
            allow_stale_write: true,
            ..StorePolicy::default()
        };
        let mut over = Store::open_with_policy(&p, &pp, policy).unwrap();
        over.set("C", b"three").unwrap();
        over.save(&pp).unwrap();
        let back = Store::open(&p, &pp).unwrap();
        assert_eq!(back.get("C"), Some(&b"three"[..]));
    }

    #[test]
    fn save_locked_rejects_a_lock_for_another_store() {
        let d = case("wrong-lock");
        let pp = Passphrase::new(b"x").unwrap();
        let p1 = d.join("a.enc");
        let p2 = d.join("b.enc");
        let s1 = Store::create(&p1, &pp).unwrap();
        let s2 = Store::create(&p2, &pp).unwrap();
        let lock = s1.lock().unwrap();
        let err = s2.save_locked(&pp, &lock).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        s1.save_locked(&pp, &lock).unwrap();
    }

    #[test]
    fn second_handle_writes_without_a_conflict() {
        let d = case("second-handle");
        let p = d.join("s.enc");
        let pp = Passphrase::new(b"x").unwrap();
        let mut s = Store::create(&p, &pp).unwrap();
        s.set("A", b"one").unwrap();
        s.save(&pp).unwrap();

        // A second handle that opens the current file, writes, and saves
        // must be allowed: its snapshot matches what is on disk.
        let mut second = Store::open(&p, &pp).unwrap();
        second.set("B", b"two").unwrap();
        second.save(&pp).unwrap();

        let back = Store::open(&p, &pp).unwrap();
        assert_eq!(back.get("A"), Some(&b"one"[..]));
        assert_eq!(back.get("B"), Some(&b"two"[..]));
    }

    #[test]
    fn reload_if_changed_picks_up_a_newer_store() {
        let d = case("reload");
        let p = d.join("s.enc");
        let pp = Passphrase::new(b"x").unwrap();
        let mut s = Store::create(&p, &pp).unwrap();
        s.set("A", b"one").unwrap();
        s.save(&pp).unwrap();

        let mut live = Store::open(&p, &pp).unwrap();
        assert!(!live.reload_if_changed(&pp).unwrap());

        let other_dir = case("reload-other");
        let other_path = other_dir.join("s.enc");
        let mut other = Store::create(&other_path, &pp).unwrap();
        other.set("B", b"two").unwrap();
        other.save(&pp).unwrap();
        std::fs::rename(&other_path, &p).unwrap();

        assert!(live.reload_if_changed(&pp).unwrap());
        assert_eq!(live.get("B"), Some(&b"two"[..]));
        assert_eq!(live.get("A"), None);
    }

    #[test]
    fn kdf_bounds_reject_huge_m_cost_quickly() {
        let limits = KdfLimits::default();
        let start = std::time::Instant::now();
        let err = Params2 {
            m_cost: u32::MAX,
            t_cost: 2,
            p_cost: 1,
        }
        .validate(&limits)
        .unwrap_err();
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("m_cost"), "{}", err);
        assert!(err.to_string().contains("PMASK_KDF_MAX_MEM"), "{}", err);
    }

    #[test]
    fn kdf_bounds_reject_out_of_range_parameters() {
        let limits = KdfLimits::default();
        let base = Params2::default();
        for bad in [
            Params2 { m_cost: 4, ..base },
            Params2 { t_cost: 0, ..base },
            Params2 { p_cost: 0, ..base },
            Params2 { p_cost: 9, ..base },
            Params2 {
                m_cost: 16,
                p_cost: 4,
                ..base
            },
        ] {
            let err = bad.validate(&limits).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{:?}", bad);
        }
        base.validate(&limits).unwrap();
    }

    #[test]
    fn kdf_ceiling_is_configurable() {
        let params = Params2 {
            m_cost: 2 * 1024 * 1024,
            t_cost: 2,
            p_cost: 1,
        };
        let low = KdfLimits::default();
        assert!(params.validate(&low).is_err());
        let high = KdfLimits {
            max_m_cost: 4 * 1024 * 1024,
            ..KdfLimits::default()
        };
        params.validate(&high).unwrap();
        let short = KdfLimits {
            max_t_cost: 1,
            ..KdfLimits::default()
        };
        assert!(Params2::default().validate(&short).is_err());
    }

    #[test]
    fn weak_parameters_need_an_optin() {
        let d = case("weak");
        let p = d.join("s.enc");
        let pp = Passphrase::new(b"x").unwrap();
        let weak = Params2 {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let permissive = StorePolicy {
            kdf: KdfLimits {
                allow_weak: true,
                ..KdfLimits::default()
            },
            ..StorePolicy::default()
        };
        let mut s = Store::create_with_policy(&p, &pp, permissive).unwrap();
        s.set_params(weak);
        s.save(&pp).unwrap();

        let err = Store::open(&p, &pp).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("PMASK_ALLOW_WEAK_KDF"), "{}", err);

        let reopened = Store::open_with_policy(&p, &pp, permissive).unwrap();
        assert_eq!(reopened.params(), weak);
    }

    #[test]
    fn a_store_file_larger_than_the_limit_is_refused_before_it_is_read() {
        let d = case("oversize");
        let p = d.join("big.store");
        let f = std::fs::File::create(&p).unwrap();
        // Sparse: the size is what the check reads, not bytes on disk.
        f.set_len(MAX_STORE_FILE as u64 + 1).unwrap();
        drop(f);
        let pp = Passphrase::new(b"x").unwrap();
        let err = Store::open_with_policy(&p, &pp, StorePolicy::default())
            .expect_err("an oversize store is refused");
        assert!(err.to_string().contains("larger than"), "{}", err);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn the_file_length_matches_the_plaintext_plus_header_and_tag() {
        // Ties HEADER_LEN and TAG_LEN to a real file, so the write-side
        // limit (MAX_STORE_PLAINTEXT) is the read-side limit minus what a
        // file really carries.
        let d = case("length");
        let p = d.join("len.enc");
        let pp = Passphrase::new(b"x").unwrap();
        let mut s = Store::create(&p, &pp).unwrap();
        s.set("A", b"one").unwrap();
        s.save(&pp).unwrap();
        let file_len = std::fs::metadata(&p).unwrap().len() as usize;
        let reopened = Store::open(&p, &pp).unwrap();
        assert_eq!(
            file_len,
            plaintext_len(&reopened.entries) + HEADER_LEN + TAG_LEN
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn truncated_header_is_an_error_not_a_panic() {
        for len in 0..80usize {
            let mut blob = vec![0u8; len];
            if len >= 16 {
                blob[..16].copy_from_slice(MAGIC);
            }
            assert!(parse_header(&blob).is_err(), "length {}", len);
        }
    }

    #[test]
    fn passphrase_file_reads_one_line_and_strips_one_newline() {
        let d = case("pass-line");
        let p = d.join("pass");

        std::fs::write(&p, b"first-line\nsecond line is not part of it\n").unwrap();
        assert_eq!(
            Passphrase::from_file(&p).unwrap().as_bytes(),
            b"first-line",
            "only the first line is the passphrase"
        );

        std::fs::write(&p, b"no-newline").unwrap();
        assert_eq!(Passphrase::from_file(&p).unwrap().as_bytes(), b"no-newline");

        std::fs::write(&p, b"one\n").unwrap();
        assert_eq!(Passphrase::from_file(&p).unwrap().as_bytes(), b"one");
    }

    #[test]
    fn passphrase_file_refuses_a_nul_byte() {
        let d = case("pass-nul");
        let p = d.join("pass");
        std::fs::write(&p, b"before\0after\n").unwrap();
        let err = Passphrase::from_file(&p).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("NUL"), "{}", err);
    }

    #[test]
    fn passphrase_file_refuses_an_oversize_line() {
        let d = case("pass-big");
        let p = d.join("pass");
        let mut big = vec![b'a'; MAX_PASSPHRASE + 1];
        big.push(b'\n');
        std::fs::write(&p, &big).unwrap();
        let err = Passphrase::from_file(&p).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains(&MAX_PASSPHRASE.to_string()),
            "{}",
            err
        );

        // The limit itself is accepted, newline and all.
        let mut at_limit = vec![b'a'; MAX_PASSPHRASE];
        at_limit.push(b'\n');
        std::fs::write(&p, &at_limit).unwrap();
        assert_eq!(
            Passphrase::from_file(&p).unwrap().as_bytes().len(),
            MAX_PASSPHRASE
        );
    }

    #[test]
    fn an_over_long_name_is_refused_instead_of_truncated() {
        let d = case("long-name");
        let p = d.join("s.enc");
        let pp = Passphrase::new(b"x").unwrap();
        let mut s = Store::create(&p, &pp).unwrap();

        let too_long = "N".repeat(u16::MAX as usize + 1);
        let err = s.set(&too_long, b"v").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("65535"), "{}", err);
        assert!(s.is_empty(), "a refused name must not be stored");

        // The boundary itself round-trips through the length field.
        let at_limit = "N".repeat(u16::MAX as usize);
        s.set(&at_limit, b"v").unwrap();
        s.save(&pp).unwrap();
        let back = Store::open(&p, &pp).unwrap();
        assert_eq!(back.get(&at_limit), Some(&b"v"[..]));
    }
}
