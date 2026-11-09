//! Secrets: where they come from, and how they reach a program without
//! appearing in `argv`, the environment, or `ps` output.
//!
//! A secret is read once, held in a [`SecBuf`] (locked, dump-excluded),
//! and then handed to the child as a **sealed file descriptor**.  The
//! child learns the descriptor number from an environment variable whose
//! *name* describes the secret and whose *value* is the number — neither
//! of which is sensitive:
//!
//! ```text
//! PMASK_SECRET_DEPLOY_TOKEN=3
//! ```
//!
//! `/proc/<pid>/environ` therefore discloses the *names* of the secrets a
//! process was given, never their contents, and `/proc/<pid>/cmdline`
//! discloses nothing at all.  A program reads its secret with the one
//! line it would otherwise have read it from the environment:
//!
//! ```sh
//! token=$(pmask read DEPLOY_TOKEN)
//! ```
//!
//! # What a delivered secret is worth
//!
//! Three claims, from strongest to weakest.  Each one is what the tool can
//! assert, and the weaker ones are not implied by the stronger:
//!
//! | claim | how it holds |
//! |---|---|
//! | the value is in neither `cmdline` nor `environ` | the value never enters either, only its name and its descriptor number do.  Strong: no `/proc` text file of the tree carries it, so `ps` cannot show it. |
//! | the value is in a sealed descriptor any process of the same account can reach | `/proc/<pid>/fd/N` can be opened and read by the same uid unless the holder is not dumpable.  Partial: the descriptor is sealed against change, not against reading. |
//! | the value is gone after a burn | with [`DeliveryMode::Burn`] the descriptor can be truncated to zero once and never grown or written again.  After that the bytes are unreachable through the descriptor.  They may still exist in the reader's memory and on freed pages, so this is not "erased from RAM". |
//!
//! [`DeliveryMode::CloseOnExec`] is not one of these: it withholds the
//! secret from every descendant at that descendant's fork, and says
//! nothing about the direct child's own lifetime.

use crate::mem::{SealedFd, SecBuf};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use zeroize::Zeroize;

/// The largest number of secrets one delivery carries.
///
/// [`install_fds`] works on a fixed-size stack array so that nothing
/// allocates between `fork` and `exec`, and this is the size of that array.
/// A request above it is refused rather than truncated: a partial delivery
/// would start the program without secrets it was promised.
pub const MAX_SECRETS: usize = 32;

/// The longest accepted secret name, in bytes.
pub const MAX_NAME_LEN: usize = 64;

/// The descriptor number the first secret lands on; secret `i` lands on
/// `FIRST_FD + i`.
pub const FIRST_FD: libc::c_int = 3;

/// Where [`install_fds`] relocates every source before it duplicates it
/// onto its target.  Above any target, so no source can be clobbered by an
/// earlier `dup2`, and above the range stdio and pipes normally use.
pub const RELOCATE_FLOOR: libc::c_int = 200;

/// The child's exit code when the descriptor install fails.  Distinct from
/// 126 and 127, so a caller can tell a delivery failure from a failed exec.
pub const CHILD_INSTALL_FAILED: i32 = 125;

/// The environment variable prefix that names a delivered descriptor.
pub const ENV_PREFIX: &str = "PMASK_SECRET_";

/// Where a secret's bytes come from.
#[derive(Debug, Clone)]
pub enum Source {
    /// `literal:VALUE` — fine for tests, not for real use: the value is
    /// in the shell history and in the argument list of the process that
    /// invoked `pmask`.
    Literal(String),
    /// `file:PATH` — a file readable only by the owner (mode 0600) is the
    /// normal case.
    File(PathBuf),
    /// `env:VAR` — read from pmask's own environment.  The variable is
    /// visible in *pmask's* environ while it runs, so this is a
    /// convenience, not a recommendation.
    Env(String),
    /// `stdin` — read to EOF from standard input.
    Stdin,
    /// `agent:NAME` (or the older spelling `daemon:NAME`) — fetched from
    /// a running `pmask agent`.
    Daemon(String),
}

impl Source {
    /// Parse the `NAME=SOURCE` form used by `--secret`.
    ///
    /// A caller that can tell the operator about a typo should use
    /// [`parse_spec`](Source::parse_spec), which reports the scheme it
    /// could not place; this form discards that and is kept for callers
    /// that only want the pair.
    pub fn parse(spec: &str) -> io::Result<(String, Source)> {
        let (name, source, _unknown) = Source::parse_spec(spec)?;
        Ok((name, source))
    }

    /// Parse `NAME=SOURCE` and say when the source named a scheme this
    /// build does not know.
    ///
    /// A source that starts with `word:` where `word` is not a known
    /// scheme is delivered whole as a literal, because refusing it would
    /// break a value that legitimately contains a colon.  That fallback
    /// is silent from the parser's point of view, so the third element
    /// is the unrecognised word: the caller prints one warning naming it,
    /// and `--secret TOK=flie:/x` stops looking like a file source.
    ///
    /// A bare value (`--secret TOK=abc`) and `stdin` name no scheme and
    /// report nothing.
    pub fn parse_spec(spec: &str) -> io::Result<(String, Source, Option<String>)> {
        let (name, rest) = spec.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("--secret wants NAME=SOURCE, got '{}'", spec),
            )
        })?;
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--secret needs a non-empty NAME",
            ));
        }
        if name.len() > MAX_NAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "secret name '{}' is {} bytes; the limit is {}",
                    name,
                    name.len(),
                    MAX_NAME_LEN
                ),
            ));
        }
        let mut unknown = None;
        let source = if let Some(v) = rest.strip_prefix("literal:") {
            Source::Literal(v.to_string())
        } else if let Some(p) = rest.strip_prefix("file:") {
            Source::File(PathBuf::from(p))
        } else if let Some(v) = rest.strip_prefix("env:") {
            Source::Env(v.to_string())
        } else if let Some(v) = rest.strip_prefix("agent:") {
            Source::Daemon(v.to_string())
        } else if let Some(v) = rest.strip_prefix("daemon:") {
            // The agent was called `pmask daemon` before it was split
            // from pmaskd; keep the old spelling working.
            Source::Daemon(v.to_string())
        } else if rest == "stdin" {
            Source::Stdin
        } else {
            unknown = scheme_candidate(rest).map(str::to_string);
            // bare value: treat as a literal, so `--secret TOKEN=abc` works
            Source::Literal(rest.to_string())
        };
        Ok((name.to_string(), source, unknown))
    }

    /// A short description of the source for an error message.  It carries
    /// the kind, and for `file:` the path, never the value.
    pub fn describe(&self) -> String {
        match self {
            Source::Literal(_) => "literal:".to_string(),
            Source::File(p) => format!("file:{}", p.display()),
            Source::Env(v) => format!("env:{}", v),
            Source::Stdin => "stdin".to_string(),
            Source::Daemon(n) => format!("agent:{}", n),
        }
    }

    /// True when the value comes from, or is spelled out in, the
    /// supervisor's own argv or environment, where `/proc` shows it.
    pub fn is_in_plain_sight(&self) -> bool {
        matches!(self, Source::Literal(_) | Source::Env(_))
    }
}

/// The schemes [`Source::parse_spec`] recognises, as an operator would
/// type them.  `stdin` is not in the list because a source of exactly
/// `stdin` carries no colon.
pub const KNOWN_SCHEMES: &[&str] = &["literal:", "file:", "env:", "agent:", "daemon:"];

/// The scheme a source looks like it names, when it begins `word:` and
/// the word cannot be one of the known schemes.
///
/// `None` for a value with no colon or with a colon that cannot start a
/// scheme (`/etc/passwd:x`, `./a:b`, a value with a blank before the
/// colon).  The rules are narrow on purpose: a scheme is a short run of
/// ASCII letters, digits, `-`, `_`, `+` and `.`, so a path and a token
/// that merely contains a colon are not mistaken for a typo'd one.
fn scheme_candidate(rest: &str) -> Option<&str> {
    let (word, _) = rest.split_once(':')?;
    if word.is_empty() || word.len() > 32 {
        return None;
    }
    let looks_like_a_scheme = word
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+' | b'.'));
    if looks_like_a_scheme {
        Some(word)
    } else {
        None
    }
}

/// The one warning for a `--secret` source that named a scheme this
/// build does not know.  Both surfaces that parse a spec print it: the
/// CLI after it has read the whole command line, so the last `-q`
/// decides, and [`Runner::secret_spec`] as it is called.
pub fn unknown_scheme_warning(name: &str, scheme: &str) -> String {
    format!(
        "warning: --secret {}: '{}:' is not a known secret scheme ({}); the value is \
         delivered as a literal",
        name,
        scheme,
        KNOWN_SCHEMES.join(", ")
    )
}

/// A named secret held in protected memory.
pub struct Secret {
    pub name: String,
    pub(crate) buf: SecBuf,
}

impl Secret {
    pub fn from_bytes(name: impl Into<String>, bytes: &[u8]) -> io::Result<Secret> {
        Ok(Secret {
            name: name.into(),
            buf: SecBuf::from_slice(bytes)?,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        self.buf.as_slice()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// True when the value's pages are locked against swap.
    pub fn is_locked(&self) -> bool {
        self.buf.is_locked()
    }

    /// True when the value's pages live in a `memfd_secret` mapping.
    pub fn is_secret_mem(&self) -> bool {
        self.buf.is_secret_mem()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The value never reaches a log line, an error message or a panic.
        f.debug_struct("Secret")
            .field("name", &self.name)
            .field("len", &self.len())
            .finish()
    }
}

/// Read a file as secret material, warning when its mode lets other
/// accounts read it.
pub fn read_secret_file(path: &PathBuf) -> io::Result<SecBuf> {
    let mut f = std::fs::File::open(path)?;
    let md = f.metadata()?;
    if md.mode() & 0o077 != 0 {
        eprintln!(
            "pmask: warning: {} is mode {:04o}; other accounts can read it",
            path.display(),
            md.mode() & 0o777
        );
    }
    let mut v = Vec::new();
    f.read_to_end(&mut v)?;
    // Trim one trailing newline: `echo token > file` is the common case.
    if v.last() == Some(&b'\n') {
        v.pop();
    }
    let mut b = SecBuf::new(v.len())?;
    b.as_mut_slice().copy_from_slice(&v);
    // The intermediate Vec held the plaintext too.
    v.zeroize();
    Ok(b)
}

/// Load one secret from its source.
pub fn load(name: &str, source: &Source, daemon_socket: Option<&PathBuf>) -> io::Result<Secret> {
    let buf = match source {
        Source::Literal(v) => SecBuf::from_slice(v.as_bytes())?,
        Source::File(p) => read_secret_file(p)?,
        Source::Env(var) => match std::env::var_os(var) {
            Some(v) => SecBuf::from_slice(v.as_bytes())?,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("environment variable {} is not set", var),
                ))
            }
        },
        Source::Stdin => {
            let mut v = Vec::new();
            io::stdin().read_to_end(&mut v)?;
            if v.last() == Some(&b'\n') {
                v.pop();
            }
            let mut b = SecBuf::new(v.len())?;
            b.as_mut_slice().copy_from_slice(&v);
            v.zeroize();
            b
        }
        Source::Daemon(remote) => crate::agent::fetch(daemon_socket, remote)?,
    };
    Ok(Secret {
        name: name.to_string(),
        buf,
    })
}

/// The environment variable that tells a child where a secret lives.
///
/// Every byte that is not an ASCII letter or digit becomes `_`, and a
/// letter is upper-cased, so the mapping stays readable but is lossy:
/// `deploy-token`, `deploy_token` and `DEPLOY.TOKEN` all become
/// `PMASK_SECRET_DEPLOY_TOKEN`.  Two names that differ only in
/// punctuation therefore collide, and [`check_names`] refuses them before
/// any secret is loaded, so one secret can never silently take another's
/// variable.
pub fn env_var_for(name: &str) -> String {
    let mut s = String::from(ENV_PREFIX);
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c.to_ascii_uppercase());
        } else {
            s.push('_');
        }
    }
    s
}

/// The part of the environment variable name that comes from the secret
/// name.  This is the part [`env_var_for`] can collapse, so it is what the
/// collision check compares.
fn env_suffix(name: &str) -> String {
    env_var_for(name)
        .strip_prefix(ENV_PREFIX)
        .unwrap_or_default()
        .to_string()
}

/// Reject a set of secret names that cannot be delivered without one
/// silently replacing another.
///
/// Fails closed on four defects: an empty name, a name longer than
/// [`MAX_NAME_LEN`], a name whose mapped suffix is empty, and two names
/// that map to the same environment variable.  A collision names both
/// original names, because the operator wrote those and needs to find them.
/// More than [`MAX_SECRETS`] names are refused by the same call.
pub fn check_names(names: &[String]) -> io::Result<()> {
    if names.len() > MAX_SECRETS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} secrets requested; the limit is {}",
                names.len(),
                MAX_SECRETS
            ),
        ));
    }
    let mut seen: Vec<(String, &str)> = Vec::with_capacity(names.len());
    for name in names {
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret names must not be empty",
            ));
        }
        if name.len() > MAX_NAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "secret name '{}' is {} bytes; the limit is {}",
                    name,
                    name.len(),
                    MAX_NAME_LEN
                ),
            ));
        }
        let suffix = env_suffix(name);
        if suffix.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "secret name '{}' maps to an empty environment variable suffix",
                    name
                ),
            ));
        }
        if let Some((_, other)) = seen.iter().find(|(s, _)| *s == suffix) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "secrets '{}' and '{}' both map to {}; rename one so each secret \
                     keeps its own descriptor",
                    other,
                    name,
                    env_var_for(name)
                ),
            ));
        }
        seen.push((suffix, name.as_str()));
    }
    Ok(())
}

/// How the delivered descriptors behave in the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    /// The default.  Every descriptor is sealed against growth, shrink and
    /// write, and `FD_CLOEXEC` is cleared, so the direct child and every
    /// descendant it spawns can read the value for the whole run.
    Inherit,
    /// Every descriptor is sealed against growth, shrink and write, and
    /// the tracer closes it in every descendant at that descendant's fork,
    /// before the descendant runs.  The direct child keeps the value for
    /// its whole life; the programs it starts never see the descriptor.
    /// Use it for a secret the supervised program needs but its children
    /// do not.
    ///
    /// A child created with `clone(CLONE_FILES)` without `CLONE_THREAD`
    /// shares the direct child's descriptor table.  Closing there would
    /// also close the direct child's copy, so the tracer leaves it open,
    /// warns, and counts the degradation in the session summary.
    CloseOnExec,
    /// Every descriptor is sealed without `F_SEAL_SHRINK`, so the reader
    /// can truncate it to zero once, after reading, and cannot then grow it
    /// back or write it.  `FD_CLOEXEC` is cleared, as with
    /// [`DeliveryMode::Inherit`], because the point is a stage that reads
    /// and then burns in place, not a descriptor withheld from children.
    ///
    /// This is a separate mode rather than a flag on `Inherit` because
    /// `F_SEAL_SEAL` is set on both: once the seal set is frozen a
    /// descriptor cannot move from the readable set to the burnable set, so
    /// the shape has to be chosen at creation.
    Burn,
}

impl DeliveryMode {
    /// The mode name used in the run report.
    pub fn as_str(&self) -> &'static str {
        match self {
            DeliveryMode::Inherit => "inherit",
            DeliveryMode::CloseOnExec => "close-on-exec",
            DeliveryMode::Burn => "burn",
        }
    }

    /// True when the value stays readable in the descendants the program
    /// starts.
    pub fn readable_by_descendants(&self) -> bool {
        matches!(self, DeliveryMode::Inherit | DeliveryMode::Burn)
    }
}

/// Secrets turned into descriptors, ready to be inherited.
pub struct Delivery {
    /// Descriptors in delivery order; index `i` is placed at `FIRST_FD + i`.
    fds: Vec<SealedFd>,
    /// Environment entries telling the child which fd holds which secret.
    env: Vec<(OsString, OsString)>,
    /// The first descriptor number handed out.
    pub first_fd: libc::c_int,
    mode: DeliveryMode,
    /// Names in delivery order, for the report.
    names: Vec<String>,
}

impl Delivery {
    /// Build sealed descriptors for every secret and the matching
    /// environment entries.
    ///
    /// # Errors
    /// The names are checked first: empty, too long, mapping to nothing, or
    /// two names mapping to one environment variable are refused before a
    /// descriptor exists, and more than [`MAX_SECRETS`] secrets are refused
    /// rather than truncated.
    pub fn new(secrets: &[Secret]) -> io::Result<Delivery> {
        Delivery::with_mode(secrets, DeliveryMode::Inherit)
    }

    /// Build a delivery with the given descriptor behaviour.
    pub fn with_mode(secrets: &[Secret], mode: DeliveryMode) -> io::Result<Delivery> {
        Delivery::with_mode_named(secrets, mode, None)
    }

    /// Build a delivery with the given descriptor behaviour and memfd
    /// name.
    ///
    /// `fd_name` is the name every delivered descriptor carries, which is
    /// what `/proc/<pid>/fd/N` renders after `/memfd:`; `None` keeps
    /// [`crate::mem::DEFAULT_SECRET_FD_NAME`].  An invalid name is
    /// refused here, before a descriptor exists.
    pub fn with_mode_named(
        secrets: &[Secret],
        mode: DeliveryMode,
        fd_name: Option<&str>,
    ) -> io::Result<Delivery> {
        let names: Vec<String> = secrets.iter().map(|s| s.name.clone()).collect();
        check_names(&names)?;
        let fd_name = fd_name.unwrap_or(crate::mem::DEFAULT_SECRET_FD_NAME);
        crate::mem::validate_memfd_name(fd_name)?;
        let mut fds = Vec::with_capacity(secrets.len());
        let mut env = Vec::with_capacity(secrets.len());
        for (i, s) in secrets.iter().enumerate() {
            let fd = match mode {
                DeliveryMode::Burn => SealedFd::new_burn_named(fd_name, s.buf.as_slice())?,
                DeliveryMode::Inherit | DeliveryMode::CloseOnExec => {
                    SealedFd::new_named(fd_name, s.buf.as_slice())?
                }
            };
            env.push((
                OsString::from(env_var_for(&s.name)),
                OsString::from((FIRST_FD + i as libc::c_int).to_string()),
            ));
            fds.push(fd);
        }
        Ok(Delivery {
            fds,
            env,
            first_fd: FIRST_FD,
            mode,
            names,
        })
    }

    /// The raw descriptors, in the order they will be placed.
    pub fn raw_fds(&self) -> Vec<libc::c_int> {
        self.fds.iter().map(|f| f.raw()).collect()
    }

    pub fn env(&self) -> &[(OsString, OsString)] {
        &self.env
    }

    pub fn mode(&self) -> DeliveryMode {
        self.mode
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// True when no descriptor is delivered.
    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }

    /// True when the descriptors stay readable in the descendants the
    /// program starts.
    pub fn readable_by_descendants(&self) -> bool {
        self.mode.readable_by_descendants()
    }

    /// Prove, in the parent, that [`install_fds`] can run in the child.
    ///
    /// Every source is duplicated above [`RELOCATE_FLOOR`] and the copy is
    /// closed at once.  A successful `F_DUPFD` proves that the relocation
    /// will work; a failure is reported here with its errno, so the program
    /// is never started without its secrets.
    pub fn preflight(&self) -> io::Result<()> {
        if self.fds.is_empty() {
            return Ok(());
        }
        for f in &self.fds {
            // SAFETY: duplicating and closing our own descriptor.
            let hi = unsafe { libc::fcntl(f.raw(), libc::F_DUPFD, RELOCATE_FLOOR) };
            if hi < 0 {
                let e = io::Error::last_os_error();
                return Err(io::Error::new(
                    e.kind(),
                    format!(
                        "cannot relocate the secret descriptors above fd {}: {}; refusing to \
                         start the program without its secrets",
                        RELOCATE_FLOOR, e
                    ),
                ));
            }
            // SAFETY: the duplicate is ours.
            unsafe { libc::close(hi) };
        }
        Ok(())
    }
}

impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Delivery")
            .field("count", &self.fds.len())
            .field("mode", &self.mode)
            .finish()
    }
}

/// Install `fds` at [`FIRST_FD`], [`FIRST_FD`] + 1, ... in the child, or end
/// the child with [`CHILD_INSTALL_FAILED`].
///
/// Every source is first relocated with `F_DUPFD` above [`RELOCATE_FLOOR`],
/// so no source can be clobbered by another target.  Each relocation is
/// checked; then each relocated descriptor is `dup2`-ed onto its target and
/// its `FD_CLOEXEC` flag is set or cleared, with every return value
/// checked.  Any failure ends the child, so the program never starts with
/// only some of its secrets.
///
/// Nothing here allocates, and only `fcntl`, `dup2`, `close`, `write` and
/// `_exit` are called.
///
/// # Safety
/// Must be called in the child between `fork` and `exec`, where only
/// async-signal-safe calls are permitted.
pub unsafe fn install_fds(fds: &[libc::c_int], cloexec: bool) {
    let mut sources = [-1 as libc::c_int; MAX_SECRETS];
    if fds.len() > MAX_SECRETS {
        abort_install();
    }
    for (i, fd) in fds.iter().enumerate() {
        let hi = libc::fcntl(*fd, libc::F_DUPFD, RELOCATE_FLOOR);
        if hi < 0 {
            abort_install();
        }
        sources[i] = hi;
    }
    let flags = if cloexec { libc::FD_CLOEXEC } else { 0 };
    for (i, source) in sources.iter().enumerate().take(fds.len()) {
        let target = FIRST_FD + i as libc::c_int;
        if libc::dup2(*source, target) < 0 {
            abort_install();
        }
        if libc::fcntl(target, libc::F_SETFD, flags) < 0 {
            abort_install();
        }
        libc::close(*source);
    }
}

/// End the child after a failed install, with one fixed message.  The
/// message is a single `write` to a fixed descriptor, which is
/// async-signal-safe.
fn abort_install() -> ! {
    const MSG: &[u8] = b"pmask: cannot install the secret descriptors; not starting the program\n";
    // SAFETY: one write to a fixed descriptor from a fixed buffer.
    unsafe {
        libc::write(2, MSG.as_ptr() as *const libc::c_void, MSG.len());
        libc::_exit(CHILD_INSTALL_FAILED);
    }
}

// ------------------------------------------------------------------ read

/// What `pmask read` does with the newline after the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Newline {
    /// Append a newline unless the value already ends with one.
    Auto,
    /// Never append anything.
    Never,
}

/// The parsed form of `pmask read ...`.
#[derive(Debug, Clone)]
pub struct ReadRequest {
    /// The secret name, looked up through [`env_var_for`].
    pub name: Option<String>,
    /// A descriptor number given directly, without the environment lookup.
    pub fd: Option<libc::c_int>,
    pub newline: Newline,
    /// Whether writing a secret to a terminal is allowed.
    pub tty_ok: bool,
}

impl ReadRequest {
    /// The label used in messages: the name, or the descriptor number.
    fn label(&self) -> String {
        match (&self.name, self.fd) {
            (Some(n), _) => format!("secret '{}'", n),
            (None, Some(fd)) => format!("fd {}", fd),
            (None, None) => "secret".to_string(),
        }
    }

    /// The descriptor to read, resolved from the request or the
    /// environment.
    pub fn resolve_fd(&self) -> io::Result<libc::c_int> {
        if let Some(fd) = self.fd {
            if (0..=2).contains(&fd) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("--fd {} would read standard input, output or error", fd),
                ));
            }
            return Ok(fd);
        }
        let name = self.name.as_deref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "read needs a NAME or --fd N")
        })?;
        let var = env_var_for(name);
        let value = std::env::var(&var).map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "no secret named '{}' in this process ({} is not set)",
                    name, var
                ),
            )
        })?;
        value.parse::<libc::c_int>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} holds '{}', not a descriptor", var, value),
            )
        })
    }
}

/// Copy a delivered descriptor to `out`, starting at offset 0.
///
/// The descriptor is rewound first, so reading the same secret twice
/// returns the whole value both times.  A descriptor that cannot seek (a
/// pipe, a terminal) is read from wherever it is, because seeking is the
/// only way to make a repeat possible and a pipe cannot be repeated
/// anyway.  The stack buffer is zeroised after every chunk, so the
/// plaintext does not outlive the copy in this process.
pub fn copy_to(fd: libc::c_int, out: &mut dyn Write, newline: Newline) -> io::Result<usize> {
    // SAFETY: lseek on a descriptor the caller handed us.
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } == -1 {
        let e = io::Error::last_os_error();
        // A pipe or a socket cannot seek and does not need to.
        if e.raw_os_error() != Some(libc::ESPIPE) {
            return Err(e);
        }
    }
    let mut buf = [0u8; 8192];
    let mut total = 0usize;
    let mut last = 0u8;
    loop {
        // SAFETY: reading into a buffer we own, through a descriptor the
        // caller handed us.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            buf.zeroize();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        let chunk = &buf[..n as usize];
        last = chunk[chunk.len() - 1];
        out.write_all(chunk)?;
        buf.zeroize();
        total += n as usize;
    }
    if newline == Newline::Auto && (total == 0 || last != b'\n') {
        out.write_all(b"\n")?;
    }
    out.flush()?;
    Ok(total)
}

/// Write one delivered secret to standard output.
///
/// Refuses to write to a terminal unless `tty_ok` is set.
pub fn write_secret(fd: libc::c_int, newline: Newline, tty_ok: bool) -> io::Result<usize> {
    // SAFETY: isatty on a constant descriptor.
    if unsafe { libc::isatty(libc::STDOUT_FILENO) } == 1 && !tty_ok {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to write a secret to a terminal; redirect standard output or pass --tty",
        ));
    }
    let mut stdout = io::stdout().lock();
    copy_to(fd, &mut stdout, newline)
}

/// Parse the arguments of `pmask read` and print one secret.
///
/// Returns the process exit status: 0 on success, 1 when the secret cannot
/// be found, read or written to a terminal (2 for the terminal refusal),
/// and 255 on a usage error.
pub fn read_main(args: &[OsString]) -> i32 {
    let mut name: Option<String> = None;
    let mut fd: Option<libc::c_int> = None;
    let mut newline = Newline::Auto;
    let mut tty_ok = false;
    let mut i = 0usize;
    while i < args.len() {
        let bytes = args[i].as_bytes();
        if let Some(value) = bytes.strip_prefix(b"--fd=") {
            match parse_fd(value) {
                Some(n) => fd = Some(n),
                None => {
                    eprintln!("pmask: read --fd needs a file descriptor number");
                    return 255;
                }
            }
        } else if bytes == b"--fd" {
            i += 1;
            match args.get(i).and_then(|a| parse_fd(a.as_bytes())) {
                Some(n) => fd = Some(n),
                None => {
                    eprintln!("pmask: read --fd needs a file descriptor number");
                    return 255;
                }
            }
        } else if bytes == b"--no-newline" {
            newline = Newline::Never;
        } else if bytes == b"--tty" {
            tty_ok = true;
        } else if bytes == b"-h" || bytes == b"--help" {
            println!("pmask read NAME [--fd N] [--no-newline] [--tty]");
            return 0;
        } else if bytes.starts_with(b"--") {
            eprintln!(
                "pmask: read: unknown option '{}'",
                String::from_utf8_lossy(bytes)
            );
            return 255;
        } else if name.is_none() {
            name = Some(String::from_utf8_lossy(bytes).into_owned());
        } else {
            eprintln!("pmask: read takes one NAME");
            return 255;
        }
        i += 1;
    }
    if name.is_some() && fd.is_some() {
        eprintln!("pmask: read takes a NAME or --fd, not both");
        return 255;
    }
    let request = ReadRequest {
        name,
        fd,
        newline,
        tty_ok,
    };
    let fd = match request.resolve_fd() {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("pmask: {}", e);
            return 1;
        }
    };
    // SAFETY: the descriptor comes from the operator or from the variable a
    // delivery wrote; the File closes it on every path below.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let result = write_secret(file.as_raw_fd(), request.newline, request.tty_ok);
    let label = request.label();
    drop(file);
    match result {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("pmask: {}: {}", label, e);
            1
        }
    }
}

fn parse_fd(bytes: &[u8]) -> Option<libc::c_int> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.parse::<libc::c_int>().ok())
        .filter(|n| *n >= 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_parsing() {
        let (n, s) = Source::parse("TOKEN=file:/tmp/x").unwrap();
        assert_eq!(n, "TOKEN");
        assert!(matches!(s, Source::File(_)));

        let (n, s) = Source::parse("A=literal:hi").unwrap();
        assert_eq!(n, "A");
        assert!(matches!(s, Source::Literal(ref v) if v == "hi"));

        let (n, s) = Source::parse("B=stdin").unwrap();
        assert_eq!(n, "B");
        assert!(matches!(s, Source::Stdin));

        assert!(Source::parse("nope").is_err());
    }

    #[test]
    fn spec_parsing_rejects_an_over_long_name() {
        let long = "A".repeat(MAX_NAME_LEN + 1);
        assert!(Source::parse(&format!("{}=literal:x", long)).is_err());
    }

    #[test]
    fn an_unknown_scheme_is_reported_and_delivered_as_a_literal() {
        // Issue 11: a typo in the scheme used to be delivered silently.
        // The word is reported so the caller can warn; the value is still
        // delivered, because a literal that contains a colon is legal.
        let (name, src, unknown) = Source::parse_spec("TOK=flie:/etc/passwd").unwrap();
        assert_eq!(name, "TOK");
        assert_eq!(unknown.as_deref(), Some("flie"));
        assert!(matches!(src, Source::Literal(ref v) if v == "flie:/etc/passwd"));

        let (_, _, unknown) = Source::parse_spec("TOK=agent:NAME").unwrap();
        assert!(unknown.is_none(), "a known scheme must not be reported");
        let (_, _, unknown) = Source::parse_spec("TOK=daemon:NAME").unwrap();
        assert!(unknown.is_none(), "the old spelling is still a scheme");
        let (_, _, unknown) = Source::parse_spec("TOK=stdin").unwrap();
        assert!(unknown.is_none());
    }

    #[test]
    fn a_bare_value_names_no_scheme_and_is_silent() {
        // The whole point of the fallback: `--secret TOK=abc` is a value,
        // not a typo, and must not produce a diagnostic.
        for spec in [
            "TOK=abc123",
            "TOK=/etc/passwd",
            "TOK=./relative:file",
            "TOK=",
            "TOK=with space: here",
            "TOK=:leading",
        ] {
            let (_, src, unknown) = Source::parse_spec(spec).unwrap();
            assert!(unknown.is_none(), "{} reported {:?}", spec, unknown);
            assert!(matches!(src, Source::Literal(_)), "{}", spec);
        }
    }

    #[test]
    fn the_warning_names_the_scheme_and_the_known_ones() {
        let w = unknown_scheme_warning("TOK", "flie");
        assert!(w.contains("'flie:'"), "{}", w);
        assert!(w.contains("literal:") && w.contains("file:"), "{}", w);
        assert!(w.contains("TOK"), "{}", w);
        // One line: a warning that wraps is read as two.
        assert_eq!(w.lines().count(), 1, "{}", w);
    }

    #[test]
    fn env_var_naming() {
        assert_eq!(env_var_for("deploy-token"), "PMASK_SECRET_DEPLOY_TOKEN");
        assert_eq!(env_var_for("a.b"), "PMASK_SECRET_A_B");
    }

    #[test]
    fn plain_sight_sources_are_the_ones_in_argv_or_environ() {
        assert!(Source::Literal("x".into()).is_in_plain_sight());
        assert!(Source::Env("X".into()).is_in_plain_sight());
        assert!(!Source::File(PathBuf::from("/tmp/x")).is_in_plain_sight());
        assert!(!Source::Daemon("x".into()).is_in_plain_sight());
        assert!(!Source::Stdin.is_in_plain_sight());
    }

    #[test]
    fn delivery_installs_onto_fd_3() {
        let s = Secret::from_bytes("X", b"v").unwrap();
        let d = Delivery::new(&[s]).unwrap();
        assert_eq!(d.first_fd, FIRST_FD);
        assert_eq!(d.env()[0].0, OsString::from("PMASK_SECRET_X"));
        assert_eq!(d.env()[0].1, OsString::from("3"));
        assert_eq!(d.mode(), DeliveryMode::Inherit);
        assert!(d.readable_by_descendants());
    }

    #[test]
    fn distinct_names_are_accepted() {
        // The names have to survive the mapping in `env_var_for`, which
        // upper-cases and replaces punctuation: `DEPLOY_TOKEN` and
        // `deploy.token` both become PMASK_SECRET_DEPLOY_TOKEN and are
        // a collision (see `colliding_names_are_refused`), so distinctness
        // is about the mapped suffix, not the spelling.
        let a = Secret::from_bytes("DEPLOY_TOKEN", b"a").unwrap();
        let b = Secret::from_bytes("OTHER_SECRET", b"b").unwrap();
        let c = Secret::from_bytes("third", b"c").unwrap();
        assert_eq!(env_var_for("DEPLOY_TOKEN"), "PMASK_SECRET_DEPLOY_TOKEN");
        assert_eq!(env_var_for("third"), "PMASK_SECRET_THIRD");
        assert!(Delivery::new(&[a, b, c]).is_ok());
    }

    #[test]
    fn colliding_names_are_refused() {
        let pairs = [
            ("deploy-token", "deploy_token"),
            ("deploy_token", "DEPLOY.TOKEN"),
            ("TOKEN", "token"),
            ("a.b", "a-b"),
            ("X", "x"),
            ("A_1", "a.1"),
        ];
        for (one, two) in pairs {
            let s1 = Secret::from_bytes(one, b"1").unwrap();
            let s2 = Secret::from_bytes(two, b"2").unwrap();
            let err = Delivery::new(&[s1, s2])
                .err()
                .unwrap_or_else(|| panic!("{} and {} were not refused", one, two));
            let text = err.to_string();
            assert!(
                text.contains(one) && text.contains(two),
                "message must name both names: {}",
                text
            );
        }
    }

    #[test]
    fn empty_and_over_long_names_are_refused() {
        let empty = Secret::from_bytes("", b"v").unwrap();
        assert!(Delivery::new(&[empty]).is_err());

        let long = "A".repeat(MAX_NAME_LEN + 1);
        let s = Secret::from_bytes(long, b"v").unwrap();
        assert!(Delivery::new(&[s]).is_err());

        let ok = Secret::from_bytes("A".repeat(MAX_NAME_LEN), b"v").unwrap();
        assert!(Delivery::new(&[ok]).is_ok());
    }

    #[test]
    fn an_empty_mapped_suffix_is_refused() {
        // Only the empty name maps to the empty suffix today; the guard is
        // on the mapped suffix because the mapping is what can change.
        assert_eq!(env_suffix(""), "");
        assert!(check_names(&["".to_string()]).is_err());
    }

    #[test]
    fn too_many_secrets_are_refused() {
        let mut v = Vec::new();
        for i in 0..MAX_SECRETS {
            v.push(Secret::from_bytes(format!("S{}", i), b"v").unwrap());
        }
        assert!(Delivery::new(&v).is_ok());
        v.push(Secret::from_bytes("ONE_MORE", b"v").unwrap());
        let err = Delivery::new(&v).unwrap_err();
        assert!(err.to_string().contains(&MAX_SECRETS.to_string()));
    }

    #[test]
    fn delivery_names_every_descriptor() {
        let a = Secret::from_bytes("A", b"1").unwrap();
        let b = Secret::from_bytes("B", b"2").unwrap();
        let d = Delivery::with_mode_named(&[a, b], DeliveryMode::Inherit, Some("secret-deadbeef"))
            .unwrap();
        for fd in d.raw_fds() {
            let link = std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap();
            assert_eq!(
                link.to_string_lossy(),
                "/memfd:secret-deadbeef (deleted)",
                "descriptor {} kept another name",
                fd
            );
        }
    }

    // Mutation control: dropping the `validate_memfd_name` call from
    // `with_mode_named` makes the empty-name case create a `/memfd:`
    // descriptor instead of erroring.
    #[test]
    fn delivery_refuses_an_invalid_fd_name() {
        let s = Secret::from_bytes("X", b"v").unwrap();
        for bad in ["", "a/b", "a\nb"] {
            let err = Delivery::with_mode_named(
                std::slice::from_ref(&s),
                DeliveryMode::Inherit,
                Some(bad),
            )
            .err()
            .unwrap_or_else(|| panic!("{:?} was accepted", bad));
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn each_delivery_mode_gets_its_own_seal_set() {
        let s = Secret::from_bytes("X", b"v").unwrap();
        let inherit = Delivery::with_mode(std::slice::from_ref(&s), DeliveryMode::Inherit).unwrap();
        let coe = Delivery::with_mode(std::slice::from_ref(&s), DeliveryMode::CloseOnExec).unwrap();
        let burn = Delivery::with_mode(std::slice::from_ref(&s), DeliveryMode::Burn).unwrap();
        let seals = |d: &Delivery| {
            // SAFETY: F_GET_SEALS on a descriptor we own.
            unsafe { libc::fcntl(d.raw_fds()[0], libc::F_GET_SEALS) }
        };
        // SEAL 1, SHRINK 2, GROW 4, WRITE 8.
        assert_eq!(seals(&inherit), 15);
        assert_eq!(seals(&coe), 15);
        assert_eq!(seals(&burn), 13);
        assert!(!coe.readable_by_descendants());
    }

    #[test]
    fn preflight_passes_for_a_normal_descriptor() {
        let s = Secret::from_bytes("X", b"v").unwrap();
        let d = Delivery::new(&[s]).unwrap();
        assert!(d.preflight().is_ok());
    }

    #[test]
    fn read_returns_the_whole_value_twice() {
        let sealed = SealedFd::new(b"token-value").unwrap();
        let mut first = Vec::new();
        assert_eq!(
            copy_to(sealed.raw(), &mut first, Newline::Never).unwrap(),
            11
        );
        let mut second = Vec::new();
        assert_eq!(
            copy_to(sealed.raw(), &mut second, Newline::Never).unwrap(),
            11
        );
        assert_eq!(first, b"token-value");
        assert_eq!(second, first);
    }

    #[test]
    fn read_appends_one_newline_unless_the_value_has_one() {
        let plain = SealedFd::new(b"abc").unwrap();
        let mut out = Vec::new();
        copy_to(plain.raw(), &mut out, Newline::Auto).unwrap();
        assert_eq!(out, b"abc\n");

        let with_newline = SealedFd::new(b"abc\n").unwrap();
        let mut out = Vec::new();
        copy_to(with_newline.raw(), &mut out, Newline::Auto).unwrap();
        assert_eq!(out, b"abc\n");

        let mut out = Vec::new();
        copy_to(with_newline.raw(), &mut out, Newline::Never).unwrap();
        assert_eq!(out, b"abc\n");
    }

    #[test]
    fn read_without_newline_adds_nothing() {
        let sealed = SealedFd::new(b"abc").unwrap();
        let mut out = Vec::new();
        copy_to(sealed.raw(), &mut out, Newline::Never).unwrap();
        assert_eq!(out, b"abc");
    }

    #[test]
    fn read_request_resolves_a_descriptor_without_the_environment() {
        let req = ReadRequest {
            name: None,
            fd: Some(7),
            newline: Newline::Auto,
            tty_ok: false,
        };
        assert_eq!(req.resolve_fd().unwrap(), 7);
        // Standard streams are refused rather than closed on the way out.
        let bad = ReadRequest {
            name: None,
            fd: Some(1),
            newline: Newline::Auto,
            tty_ok: false,
        };
        assert!(bad.resolve_fd().is_err());
        let missing = ReadRequest {
            name: Some("NOT_DELIVERED_ANYWHERE".to_string()),
            fd: None,
            newline: Newline::Auto,
            tty_ok: false,
        };
        assert!(missing.resolve_fd().is_err());
    }

    #[test]
    fn a_failed_install_ends_the_child_instead_of_running_it() {
        // A failed duplicate must not fall through to the F_SETFD that
        // would clear FD_CLOEXEC on a descriptor this call did not
        // install.  The routine ends the child with a distinct status
        // instead, so the program never starts with a partial delivery.
        // The check runs in a child: install_fds writes fixed descriptor
        // numbers, and the test binary shares its descriptor table with
        // every other test.
        // SAFETY: fork in a test; the child only calls install_fds and
        // _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            // SAFETY: the child owns its descriptor table and exits here.
            unsafe {
                install_fds(&[-1], false);
                libc::_exit(0);
            }
        }
        let mut st = 0i32;
        // SAFETY: waiting for the child this test forked.
        let w = unsafe { libc::waitpid(pid, &mut st, 0) };
        assert_eq!(w, pid);
        assert!(libc::WIFEXITED(st), "child did not exit normally");
        assert_eq!(libc::WEXITSTATUS(st), CHILD_INSTALL_FAILED);
    }
}
