//! The runner: pick the strongest available mode, deliver secrets, and
//! run the command.
//!
//! Three modes, chosen from what the host allows:
//!
//! | mode | needs | gives |
//! |---|---|---|
//! | redact | `ptrace` | cmdline/environ/comm of the whole tree are redacted |
//! | isolate | unprivileged user namespaces | the payload gets a private mount/pid/net view |
//! | plain | nothing | the payload still receives its secrets on descriptors; no /proc redaction |
//!
//! Secret delivery is the same in all three, because it never needed a
//! privilege: a sealed memfd inherited at a known descriptor.  That is
//! the part that works in a locked-down container, and it is the part
//! that matters most for the motivating case (a CI runner whose token is
//! otherwise readable by everything on the machine).
//!
//! # Secrets whose source is in plain sight
//!
//! A `literal:` or `env:` source is only safe when the supervisor can
//! redact its own `/proc` entry.  In plain mode (no ptrace, or
//! `--no-redact`) it cannot, so the value sits in pmask's own argv or
//! environment for the whole run, readable by every local account.  That
//! is refused by default, naming the source and pointing at `file:` and
//! `agent:`; [`Runner::allow_argv_secret`] restores the old behaviour and
//! prints the warning.  In redact mode the value is still briefly in
//! pmask's argv, so the run warns once.
//!
//! No mode reaches the other three copies of the value: the kernel's
//! audit record of pmask's own exec (written before pmask can rewrite
//! anything), the shell history and any wrapper's argv.  The CLI prints
//! one warning about them, before the run starts, through
//! [`argv_secret_warning`]; it is louder when the host answers that the
//! audit subsystem is enabled, because then the record already exists.

use crate::caps::Caps;
use crate::isolate::{self, Isolate};
use crate::mask::Mask;
use crate::secret::{self, Delivery, DeliveryMode, Secret, Source};
use crate::ExitState;
use std::ffi::{CString, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// How the command is going to be run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Redact,
    Isolate,
    Plain,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Redact => "redact",
            Mode::Isolate => "isolate",
            Mode::Plain => "plain",
        }
    }
}

/// The selected mode and the axis that kept it from the strongest one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Selection {
    mode: Mode,
    reason: &'static str,
}

/// The axis that refused `ptrace`, from the probe that explains it.
fn ptrace_reason(caps: &Caps) -> &'static str {
    if caps.seccomp_filter {
        "seccomp"
    } else if caps.ptrace_scope.is_some_and(|scope| scope >= 3) {
        "yama_ptrace_scope"
    } else {
        "no_capability"
    }
}

/// What actually happened.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub mode: Mode,
    /// Why the selected mode is not the strongest one available, or the
    /// empty string when it is.  The values are `forced`, `seccomp`,
    /// `yama_ptrace_scope`, `no_capability` and `isolate_unavailable`.
    pub mode_reason: String,
    pub exit: ExitState,
    pub secrets_delivered: usize,
    pub notes: Vec<String>,
    /// True when `/proc` redaction was available for this run.
    pub ptrace: bool,
    /// False when the run asked for a non-dumpable payload
    /// (`--no-dumpable`), so a same-account reader cannot open
    /// `/proc/<pid>/fd/N` to read a delivered value.  The redaction mode
    /// applies the request at each exec; the isolate and plain modes do
    /// not change dumpability and say so in a note.
    pub payload_dumpable: bool,
    /// The hardening tier of the buffers that held the values.
    pub hardening: Hardening,
    /// One entry per delivered secret.
    pub secrets: Vec<SecretReport>,
}

/// The memory-hardening tier of the secret buffers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Hardening {
    /// True when every value's pages were locked against swap.
    pub locked: bool,
    /// True when every value's pages lived in a `memfd_secret` mapping.
    pub secret_mem: bool,
}

impl Hardening {
    /// The tier as one word: `locked+secret_mem`, `locked`, `secret_mem`
    /// or `heap`.
    pub fn as_str(&self) -> &'static str {
        match (self.locked, self.secret_mem) {
            (true, true) => "locked+secret_mem",
            (true, false) => "locked",
            (false, true) => "secret_mem",
            (false, false) => "heap",
        }
    }
}

impl Outcome {
    /// The run as one JSON object, so a CI job asserts on the deployment
    /// instead of grepping stderr.  The values are never included.
    pub fn report_json(&self) -> String {
        let esc = |s: &str| -> String {
            let mut o = String::with_capacity(s.len());
            for c in s.chars() {
                match c {
                    '"' => o.push_str("\\\""),
                    '\\' => o.push_str("\\\\"),
                    '\n' => o.push_str("\\n"),
                    '\r' => o.push_str("\\r"),
                    '\t' => o.push_str("\\t"),
                    c if (c as u32) < 0x20 => o.push_str("\\uFFFD"),
                    c => o.push(c),
                }
            }
            o
        };
        let b = |v: bool| if v { "true" } else { "false" };
        let mut secrets = String::new();
        for (i, s) in self.secrets.iter().enumerate() {
            if i > 0 {
                secrets.push(',');
            }
            secrets.push_str(&format!(
                "\n    {{\"name\": \"{}\", \"locked\": {}, \"secret_mem\": {}, \"fd\": {}}}",
                esc(&s.name),
                b(s.locked),
                b(s.secret_mem),
                s.fd
            ));
        }
        let mut notes = String::new();
        for (i, n) in self.notes.iter().enumerate() {
            if i > 0 {
                notes.push(',');
            }
            notes.push_str(&format!("\n    \"{}\"", esc(n)));
        }
        format!(
            concat!(
                "{{\n",
                "  \"mode\": \"{}\",\n",
                "  \"mode_reason\": \"{}\",\n",
                "  \"ptrace\": {},\n",
                "  \"payload_dumpable\": {},\n",
                "  \"hardening\": \"{}\",\n",
                "  \"exit\": {{\"code\": {}, \"signal\": {}}},\n",
                "  \"execs\": {{\"total\": {}, \"degraded\": {}, \"detached\": {}, \"sized\": {}, \
                 \"sized_skipped\": {}, \"secret_close_failed\": {}}},\n",
                "  \"secrets\": [{}],\n",
                "  \"notes\": [{}]\n",
                "}}\n"
            ),
            self.mode.as_str(),
            esc(&self.mode_reason),
            b(self.ptrace),
            b(self.payload_dumpable),
            self.hardening.as_str(),
            self.exit.code,
            self.exit
                .signal
                .map(|s| s.to_string())
                .unwrap_or_else(|| "null".into()),
            self.exit.stats.execs,
            self.exit.stats.degraded,
            self.exit.stats.detached,
            self.exit.stats.sized,
            self.exit.stats.sized_skipped,
            self.exit.stats.secret_close_failed,
            secrets,
            notes
        )
    }
}

/// One secret as the report describes it.  The value is never included.
#[derive(Debug, Clone)]
pub struct SecretReport {
    pub name: String,
    pub locked: bool,
    pub secret_mem: bool,
    pub fd: libc::c_int,
}

// ------------------------------------------------- the audit-log exposure

/// `AUDIT_GET` from `linux/audit.h`: the message type that asks the kernel
/// for its audit status.
const AUDIT_GET: u16 = 1000;
/// `NLM_F_REQUEST` from `linux/netlink.h`.
const NLM_F_REQUEST: u16 = 0x01;
/// `NLM_F_ACK` from `linux/netlink.h`.
const NLM_F_ACK: u16 = 0x04;
/// `NLMSG_ERROR` from `linux/netlink.h`.
const NLMSG_ERROR: u16 = 0x02;
/// `struct nlmsghdr` is 16 bytes on every Linux ABI.
const NLMSG_HDR: usize = 16;
/// `struct audit_status` starts with `mask`, then `enabled`, so the word
/// this probe reads is the second `u32` after the header.
const AUDIT_STATUS_ENABLED: usize = NLMSG_HDR + 4;

/// What this host's kernel audit subsystem will do with an exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditState {
    /// The kernel answered with its audit status: auditing is on, so a
    /// rule that covers this exec has already written it to the audit
    /// log.  Whether a rule covers it is the deployment's business.
    Enabled,
    /// The kernel refused the query with `ECONNREFUSED`, which is how it
    /// answers every audit request while auditing is off.
    Disabled,
    /// The question could not be put or the answer was neither of the
    /// two above: no `NETLINK_AUDIT` socket, a seccomp filter, a locked
    /// subsystem this process may not read.  Callers warn without
    /// claiming either state.
    Unknown,
}

/// Ask the kernel whether its audit subsystem is enabled.
///
/// The probe is the one `auditctl -s` makes: a `NETLINK_AUDIT` socket and
/// an `AUDIT_GET` request.  It needs no privilege (the kernel answers
/// `ECONNREFUSED` to an unprivileged caller while auditing is off), which
/// is why it is done here rather than by running `auditctl`, whose own
/// root check fails for the account pmask usually runs as.
///
/// The receive timeout bounds the probe: a kernel that never answers must
/// not hang the run.  A probe that cannot answer is [`AuditState::Unknown`]
/// and the caller warns without the stronger wording, so a failed probe
/// never turns a warning into a refusal.
///
/// `PMASK_PROBE_AUDIT=1` (enabled) or `0` (disabled) replaces the answer
/// and skips the syscalls.  It is the test hook for the two wordings, read
/// once per call, in the same spirit as the `PMASK_PROBE_*` host-profile
/// overrides in [`crate::caps`]; it changes no production behaviour beyond
/// the adjective in one warning.
pub fn audit_state() -> AuditState {
    match std::env::var("PMASK_PROBE_AUDIT").as_deref() {
        Ok("1") => return AuditState::Enabled,
        Ok("0") => return AuditState::Disabled,
        _ => {}
    }
    // SAFETY: a netlink socket owned by this call; it is closed below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_AUDIT,
        )
    };
    if fd < 0 {
        return AuditState::Unknown;
    }
    let state = audit_state_on(fd);
    // SAFETY: the descriptor is ours and is not used again.
    unsafe { libc::close(fd) };
    state
}

/// The body of [`audit_state`], on an open netlink socket.
fn audit_state_on(fd: libc::c_int) -> AuditState {
    // A zeroed `sockaddr_nl` binds the socket to this process, so the
    // reply is addressed to it and not to another audit reader.
    // SAFETY: `sockaddr_nl` is plain old data.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: binding our own socket to a zeroed address.
    let bound = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return AuditState::Unknown;
    }
    // A kernel that never answers must not hang the run.
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 200_000,
    };
    // SAFETY: a timeout on our own socket.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };

    // struct nlmsghdr: len, type, flags, seq, pid.  Native endian, as
    // netlink requires.
    let mut request = [0u8; NLMSG_HDR];
    request[0..4].copy_from_slice(&(NLMSG_HDR as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&AUDIT_GET.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    // SAFETY: sending our own 16-byte request to the kernel.
    let sent = unsafe {
        libc::sendto(
            fd,
            request.as_ptr() as *const libc::c_void,
            request.len(),
            0,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return AuditState::Unknown;
    }
    let mut reply = [0u8; 256];
    // SAFETY: receiving into a buffer we own.
    let n = unsafe { libc::recv(fd, reply.as_mut_ptr() as *mut libc::c_void, reply.len(), 0) };
    if n < 0 {
        return AuditState::Unknown;
    }
    parse_audit_reply(&reply[..n as usize])
}

/// Classify one netlink reply to the `AUDIT_GET` request.
///
/// Split from the socket code so the wire format is testable without a
/// kernel that answers.  A status reply (`AUDIT_GET`) means auditing is
/// on; `NLMSG_ERROR` with `ECONNREFUSED` is the kernel's "auditing is
/// off" answer; a bare acknowledgement, another errno, or a short message
/// is [`AuditState::Unknown`].
fn parse_audit_reply(reply: &[u8]) -> AuditState {
    if reply.len() < NLMSG_HDR {
        return AuditState::Unknown;
    }
    let msg_type = u16::from_ne_bytes([reply[4], reply[5]]);
    if msg_type == AUDIT_GET {
        if reply.len() < AUDIT_STATUS_ENABLED + 4 {
            return AuditState::Unknown;
        }
        let enabled = u32::from_ne_bytes([
            reply[AUDIT_STATUS_ENABLED],
            reply[AUDIT_STATUS_ENABLED + 1],
            reply[AUDIT_STATUS_ENABLED + 2],
            reply[AUDIT_STATUS_ENABLED + 3],
        ]);
        // 0 is off, 1 is on, 2 is on and locked.  Any other value is a
        // kernel this probe does not know.
        return match enabled {
            1 | 2 => AuditState::Enabled,
            0 => AuditState::Disabled,
            _ => AuditState::Unknown,
        };
    }
    if msg_type == NLMSG_ERROR && reply.len() >= NLMSG_HDR + 4 {
        let err = i32::from_ne_bytes([
            reply[NLMSG_HDR],
            reply[NLMSG_HDR + 1],
            reply[NLMSG_HDR + 2],
            reply[NLMSG_HDR + 3],
        ]);
        if err == -libc::ECONNREFUSED {
            return AuditState::Disabled;
        }
    }
    AuditState::Unknown
}

/// The one warning a `literal:` or `env:` secret source earns, or `None`
/// when every source is out of plain sight.
///
/// The text names the artefacts pmask cannot reach and points at the two
/// ways out: a non-argv source for the value and `--args-from-fd` for the
/// payload's own arguments.  It never includes a value, only names and
/// source kinds.
///
/// A `literal:` value is in pmask's argv, so the kernel's exec record
/// (`type=EXECVE` and `PROCTITLE`) holds it when the audit subsystem is
/// enabled, and it is already written by the time pmask runs.  An `env:`
/// value is in pmask's environment instead; the kernel's exec record does
/// not carry the environment, so the audit clause is only claimed for a
/// `literal:` source.
///
/// The text is stronger when [`audit_state`] answers
/// [`AuditState::Enabled`] and a `literal:` source is present, because
/// then the record exists and is permanent.  It never refuses: `literal:`
/// is documented, and the operator may have a reason to keep it.
pub fn argv_secret_warning(sources: &[(String, Source)]) -> Option<String> {
    argv_secret_warning_with(sources, audit_state())
}

/// The body of [`argv_secret_warning`], with the audit answer supplied so
/// the three wordings are testable on one host.
fn argv_secret_warning_with(sources: &[(String, Source)], audit: AuditState) -> Option<String> {
    let plain: Vec<&(String, Source)> = sources
        .iter()
        .filter(|(_, src)| src.is_in_plain_sight())
        .collect();
    if plain.is_empty() {
        return None;
    }
    let list = plain
        .iter()
        .map(|(name, src)| format!("{}={}", name, src.describe()))
        .collect::<Vec<String>>()
        .join(", ");
    let literal = plain
        .iter()
        .any(|(_, src)| matches!(src, Source::Literal(_)));
    let env = plain.iter().any(|(_, src)| matches!(src, Source::Env(_)));
    let one = plain.len() == 1;
    let mut text = format!(
        "secret {}{} {} the value in pmask's own {}",
        if one { "source " } else { "sources " },
        list,
        if one { "puts" } else { "put" },
        match (literal, env) {
            (true, true) => "argv or environment",
            (false, true) => "environment",
            (true, false) => "argv",
            (false, false) => unreachable!("a plain-sight source is literal: or env:"),
        }
    );
    if literal {
        text.push_str(", where the shell history and any wrapper's argv keep a copy");
        match audit {
            AuditState::Enabled => text.push_str(
                ", and this host's audit subsystem is enabled, so the kernel has already \
                 written that argv into its audit log (type=EXECVE and PROCTITLE) for the life \
                 of the log",
            ),
            AuditState::Disabled => text.push_str(
                ", and the kernel audit log would hold it too if this host's audit subsystem \
                 were enabled",
            ),
            AuditState::Unknown => text.push_str(
                ", and the kernel audit log holds it too when this host's audit subsystem is \
                 enabled (this run could not ask)",
            ),
        }
    }
    if env {
        text.push_str(if literal { ", and" } else { ", where" });
        text.push_str(
            " /proc/<pmask-pid>/environ serves it until pmask masks itself and the shell \
             history or a wrapper's environment may keep a copy; the kernel's exec record \
             carries argv, not the environment",
        );
    }
    text.push_str(
        ". pmask cannot reach the copies outside its own process: use file:PATH, agent:NAME or \
         stdin for the value, and --args-from-fd N to keep the payload's own arguments out of \
         pmask's argv",
    );
    Some(text)
}

/// Builder for one supervised run.
pub struct Runner {
    label: Option<String>,
    follow_tree: bool,
    redact_environ: bool,
    exit_kill: bool,
    quiet: bool,
    verbose: bool,
    force_mode: Option<Mode>,
    isolate: Option<Isolate>,
    /// `--redact --isolate`: redact the tree *and* give the payload the
    /// requested namespaces.  Distinct from [`Runner::isolate`], which is
    /// the namespace-only mode.
    compose: Option<Isolate>,
    secrets: Vec<(String, Source)>,
    env_overrides: Vec<(OsString, OsString)>,
    socket: Option<PathBuf>,
    mask: Option<Mask>,
    delivery_mode: DeliveryMode,
    close_on_exec: bool,
    allow_argv_secret: bool,
    no_dumpable: bool,
    /// Mask options the caller passed, for the modes that cannot apply
    /// them.  Every entry becomes one note, so a dropped option is never
    /// silent (AGENTS.md invariant 13).
    requested: Vec<&'static str>,
    /// `--audit` was requested.  The rows need the tracer, so every
    /// non-redaction mode refuses the request.
    requests_audit: bool,
}

impl Default for Runner {
    fn default() -> Self {
        Runner::new()
    }
}

impl Runner {
    pub fn new() -> Runner {
        Runner {
            label: None,
            follow_tree: true,
            redact_environ: true,
            exit_kill: true,
            quiet: false,
            verbose: false,
            force_mode: None,
            isolate: None,
            compose: None,
            secrets: Vec::new(),
            env_overrides: Vec::new(),
            socket: None,
            mask: None,
            delivery_mode: DeliveryMode::Inherit,
            close_on_exec: false,
            allow_argv_secret: false,
            no_dumpable: false,
            requested: Vec::new(),
            requests_audit: false,
        }
    }

    pub fn label(mut self, l: impl Into<String>) -> Runner {
        self.label = Some(l.into());
        self
    }

    pub fn follow_tree(mut self, on: bool) -> Runner {
        self.follow_tree = on;
        self
    }

    pub fn keep_environ_visible(mut self) -> Runner {
        self.redact_environ = false;
        self
    }

    pub fn let_tree_survive_self_death(mut self) -> Runner {
        self.exit_kill = false;
        self
    }

    pub fn quiet(mut self) -> Runner {
        self.quiet = true;
        self.verbose = false;
        self
    }

    pub fn verbose(mut self) -> Runner {
        self.verbose = true;
        self.quiet = false;
        self
    }

    /// Skip `/proc` redaction even where ptrace is available.
    pub fn no_redaction(mut self) -> Runner {
        self.force_mode = Some(Mode::Plain);
        self
    }

    /// Run inside fresh namespaces (needs unprivileged user namespaces).
    /// This is the namespace-only mode: the payload's `/proc` metadata is
    /// not redacted, and every mask option that needs the tracer is
    /// reported as not applied.
    pub fn isolate(mut self, iso: Isolate) -> Runner {
        self.isolate = Some(iso);
        self
    }

    /// Redact the tree *and* give the payload the namespaces in `iso`:
    /// the `--redact --isolate` composition.  The redaction path owns the
    /// tree, and the payload is forked into the requested namespaces
    /// before its exec.  A set the host cannot grant is reported as a
    /// counted degradation, never silently replaced by `--unshare`'s
    /// user+pid+mount set.
    pub fn redact_with_isolate(mut self, iso: Isolate) -> Runner {
        self.compose = Some(iso);
        self
    }

    /// Record the mask options the caller passed, so the modes that
    /// cannot apply one can name it in the run report.
    pub fn requested_options(mut self, opts: &[&'static str]) -> Runner {
        for o in opts {
            if !self.requested.contains(o) {
                self.requested.push(o);
            }
        }
        self
    }

    pub fn secret(mut self, name: impl Into<String>, source: Source) -> Runner {
        self.secrets.push((name.into(), source));
        self
    }

    /// Set one variable for the payload, on top of the environment it
    /// would otherwise inherit.  A later call with the same name wins.
    /// This is the runner-level counterpart of `Mask::env`: the redaction
    /// mode gets the pair through the mask, and the isolate and plain
    /// modes get it here.  A caller that configures `Mask::env` directly
    /// and also asks for isolation must repeat the pair here, because the
    /// runner cannot read the mask's environment.
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Runner {
        self.env_overrides.push((key.into(), value.into()));
        self
    }

    pub fn secret_spec(mut self, spec: &str) -> io::Result<Runner> {
        let (name, src) = Source::parse(spec)?;
        self.secrets.push((name, src));
        Ok(self)
    }

    /// Choose how the delivered descriptors behave.  See [`DeliveryMode`].
    pub fn delivery_mode(mut self, mode: DeliveryMode) -> Runner {
        self.delivery_mode = mode;
        self
    }

    /// Withhold the delivered descriptors from what the payload starts:
    /// the tracer closes them in each descendant at that descendant's
    /// fork, and the payload keeps them for its whole life.  This needs
    /// the redaction mode's tracer; a run without one refuses the
    /// combination instead of closing the payload's own copy at its exec.
    pub fn close_on_exec(mut self) -> Runner {
        self.close_on_exec = true;
        self
    }

    /// Permit a `literal:` or `env:` source where the supervisor cannot
    /// redact its own argv or environment.  The run then prints the
    /// warning that says the value is disclosed.
    pub fn allow_argv_secret(mut self) -> Runner {
        self.allow_argv_secret = true;
        self
    }

    /// Record that the run asks for a non-dumpable payload
    /// (`--no-dumpable`), so the report's `payload_dumpable` is false.
    /// The redaction mode applies it at each exec; the isolate and plain
    /// modes do not change dumpability and say so in a note.
    pub fn no_dumpable(mut self, on: bool) -> Runner {
        self.no_dumpable = on;
        self
    }

    /// `--audit`: one residue row per tracee.  The redaction mode owns the
    /// tree the rows describe; every other mode refuses the flag instead
    /// of printing nothing.
    pub fn audit(mut self) -> Runner {
        self.requests_audit = true;
        self
    }

    pub fn daemon_socket(mut self, p: PathBuf) -> Runner {
        self.socket = Some(p);
        self
    }

    /// Use a fully configured [`Mask`] for the redaction mode, instead of
    /// the simple flags of this builder.  This is how the CLI hands one
    /// parsed option set to both surfaces: every mask option (`--comm`,
    /// `--argv0`, `--env`, `--no-dumpable`, `--rexec`, `--unshare`, the
    /// session-end policy, ...) then applies to a `--secret` run too.
    ///
    /// The mask's `no_dumpable` flag is private, so a caller that sets it
    /// with [`Mask::no_dumpable`] must also call [`Runner::no_dumpable`]
    /// with `true`: the report's `payload_dumpable` is built from the
    /// runner's copy.
    pub fn mask(mut self, mask: Mask) -> Runner {
        self.mask = Some(mask);
        self
    }

    /// Decide the mode from the host's capabilities and the request.
    ///
    /// The rule is the ladder in `docs/DEFAULTS.md` section 4: a forced
    /// mode wins; a host without `ptrace` runs plain; an explicit
    /// `--isolate` runs isolate when user namespaces are available and
    /// redact when they are not; every other run redacts.  A request the
    /// host cannot honour degrades instead of failing, and
    /// [`Runner::mode_reason`] names the axis that failed.
    pub fn mode(&self) -> Mode {
        self.select().mode
    }

    /// The axis that kept the run from the strongest mode, or the empty
    /// string when the selected mode is the strongest available one.
    pub fn mode_reason(&self) -> &'static str {
        self.select().reason
    }

    fn select(&self) -> Selection {
        self.select_with(Caps::cached())
    }

    fn select_with(&self, caps: &Caps) -> Selection {
        // `--redact --isolate` composes: the redaction path owns the tree
        // and the payload is forked into the requested namespaces.  When
        // ptrace is unavailable the namespace half still works, so the
        // isolate path runs with the probe reason in `mode_reason` rather
        // than dropping the namespaces the operator asked for.
        if let Some(iso) = self.compose {
            if !iso.none {
                if !caps.userns {
                    if caps.ptrace {
                        return Selection {
                            mode: Mode::Redact,
                            reason: "isolate_unavailable",
                        };
                    }
                    return Selection {
                        mode: Mode::Plain,
                        reason: ptrace_reason(caps),
                    };
                }
                if caps.ptrace {
                    return Selection {
                        mode: Mode::Redact,
                        reason: "",
                    };
                }
                return Selection {
                    mode: Mode::Isolate,
                    reason: ptrace_reason(caps),
                };
            }
        }
        // `--no-redact` means exactly that: never touch /proc metadata.
        // It does not mean "plain before isolate": a namespace request is
        // still honourable without a tracer, and dropping it silently is
        // the defect this ordering used to be (issue 20).  The pair takes
        // the isolate path when the host grants it and the plain path with
        // a note otherwise.
        if self.force_mode == Some(Mode::Plain) {
            if self.isolate.is_some() && !self.is_none_isolation() && caps.userns {
                return Selection {
                    mode: Mode::Isolate,
                    reason: "forced",
                };
            }
            if self.isolate.is_some() && !self.is_none_isolation() {
                return Selection {
                    mode: Mode::Plain,
                    reason: "isolate_unavailable",
                };
            }
            return Selection {
                mode: Mode::Plain,
                reason: "forced",
            };
        }
        if let Some(mode) = self.force_mode {
            return Selection {
                mode,
                reason: "forced",
            };
        }
        // `--isolate=none` asks for no isolation, not for a different
        // mode: the namespace request simply contributes nothing, and the
        // ordinary ladder decides (redact where ptrace works, plain where
        // it does not).  Entering the isolation path here would create the
        // unconditional user/mount/UTS/IPC/cgroup namespaces anyway
        // (issue 26).
        if !caps.ptrace {
            return Selection {
                mode: Mode::Plain,
                reason: ptrace_reason(caps),
            };
        }
        if self.isolate.is_some() && !self.is_none_isolation() {
            if caps.userns {
                return Selection {
                    mode: Mode::Isolate,
                    reason: "",
                };
            }
            return Selection {
                mode: Mode::Redact,
                reason: "isolate_unavailable",
            };
        }
        Selection {
            mode: Mode::Redact,
            reason: "",
        }
    }

    /// The namespace set the selected mode should apply, if any.  `None`
    /// when `--isolate` was not given or named `none`.
    fn iso_set(&self) -> Option<Isolate> {
        let iso = self.isolate.or(self.compose)?;
        if iso.none {
            None
        } else {
            Some(iso)
        }
    }

    /// True when `--isolate=none` was the request: no isolation at all.
    fn is_none_isolation(&self) -> bool {
        self.isolate.is_some_and(|i| i.none) || self.compose.is_some_and(|i| i.none)
    }

    /// True when isolation was asked for and the host refused it.
    pub fn isolate_unavailable(&self) -> bool {
        self.isolate.is_some() && !self.is_none_isolation() && !Caps::cached().userns
    }

    /// Check every secret source against the mode the run will use, and
    /// return the warnings the operator must see.
    ///
    /// A source that puts the value in the supervisor's own argv or
    /// environment needs a mode in which the supervisor redacts itself
    /// and the payload.  Redact mode does; plain and isolate modes do
    /// not redact the payload.
    fn check_sources(&self, mode: Mode) -> io::Result<Vec<String>> {
        let mut warnings = Vec::new();
        if self.allow_argv_secret {
            for (name, src) in &self.secrets {
                if src.is_in_plain_sight() {
                    warnings.push(format!(
                        "secret '{}' uses {} and the value is in this process's argv or \
                         environment; another local account can read it",
                        name,
                        src.describe()
                    ));
                }
            }
            return Ok(warnings);
        }
        if mode == Mode::Redact {
            // The tracer redacts the payload's /proc; the value is only
            // in this process's argv or environment until the supervisor
            // masks its own entry.
            for (name, src) in &self.secrets {
                if src.is_in_plain_sight() {
                    warnings.push(format!(
                        "secret '{}' uses {}; the value was briefly in this process's argv or \
                         environment before the supervisor masked its own /proc entry",
                        name,
                        src.describe()
                    ));
                }
            }
            return Ok(warnings);
        }
        // Plain and isolate modes cannot redact the payload's /proc.  A
        // plain run leaves the value in this process for its whole life;
        // an isolate run hands the payload the inherited environment and
        // does not redact the payload, so an env: value stays readable
        // there for the whole run.  Refuse both rather than warn.
        for (name, src) in &self.secrets {
            if src.is_in_plain_sight() {
                let why = if mode == Mode::Isolate {
                    "isolate mode does not redact the payload's /proc, so a source that puts \
                     the value in plain sight is refused"
                } else {
                    "this run cannot redact /proc, so the value would stay in pmask's own \
                     argv or environment for the whole run"
                };
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "secret '{}' uses {}; {}; use file:PATH or agent:NAME, or pass \
                         --allow-argv-secret",
                        name,
                        src.describe(),
                        why
                    ),
                ));
            }
        }
        Ok(warnings)
    }

    /// The environment the isolate and plain modes hand the payload:
    /// inherited, then the runner's own pairs, then the delivered-
    /// descriptor map.  A later pair with the same name replaces the
    /// earlier value, which is the rule `Mask::env` applies in the
    /// redaction mode.
    fn environment(&self, extra: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
        let mut pairs: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        for (k, v) in self.env_overrides.iter().chain(extra) {
            match pairs.iter_mut().find(|(ek, _)| ek == k) {
                Some(slot) => slot.1 = v.clone(),
                None => pairs.push((k.clone(), v.clone())),
            }
        }
        pairs
    }

    /// Run the command and wait for it.
    pub fn run<P, A>(&self, program: P, args: &[A]) -> io::Result<Outcome>
    where
        P: AsRef<std::ffi::OsStr>,
        A: AsRef<std::ffi::OsStr>,
    {
        let args: Vec<OsString> = args.iter().map(|a| a.as_ref().to_os_string()).collect();
        let mut notes = Vec::new();
        let mode = self.mode();
        let ptrace = Caps::cached().ptrace;
        // `--image` is a redaction-mode feature: the image is executed by
        // the masked child.  The isolate and plain modes exec a path
        // directly, so they cannot honour it.
        if self.mask.as_ref().is_some_and(|m| m.has_image()) && mode != Mode::Redact {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "--image needs the redaction mode: {} mode executes a path, not an \
                     image; drop --image, or drop the flag that forces {} mode",
                    mode.as_str(),
                    mode.as_str()
                ),
            ));
        }
        let mode_reason = self.mode_reason();
        // `--audit` describes the tree the tracer owns.  The mode is only
        // known here, after the probe, so this is where a host that
        // selects plain mode (no ptrace) refuses the flag; the explicit
        // `--no-redact`/`--isolate` pair is refused in `main`, before any
        // secret is read.  Refusing instead of printing nothing keeps the
        // promise the man page makes (issue 32).
        if self.requests_audit && mode != Mode::Redact {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "--audit needs the redaction mode: the selected mode is {}, which has no \
                     tracer to describe the tree, so the audit rows would be empty; run where \
                     ptrace is available, or drop --audit",
                    mode.as_str()
                ),
            ));
        }
        if self.isolate_unavailable() {
            notes.push(
                "--isolate was requested but this host has no unprivileged user namespaces; \
                 running without it"
                    .to_string(),
            );
        }
        // `--isolate=none` asks for no isolation at all: no namespace, no
        // `no_new_privs` and no Landlock.  The runner honours it by not
        // entering the isolation path; the note makes the run's mode and
        // the absence of a namespace report unambiguous (issue 26).
        if self.is_none_isolation() {
            notes.push(
                "--isolate=none: the payload runs with the host's namespaces, no_new_privs \
                 and filesystem policy unchanged"
                    .to_string(),
            );
        }
        // `--no-redact --isolate`: the pair used to select plain mode
        // before the namespace request was read, so the isolation vanished
        // (issue 20).  It now runs the isolation path; say that the
        // redaction half was the operator's choice and the namespace half
        // was delivered, so neither is inferred from an absence.
        if self.force_mode == Some(Mode::Plain) && mode == Mode::Isolate && self.isolate.is_some() {
            notes.push(
                "--no-redact was honoured and --isolate still applies: isolation does not \
                 need ptrace, so the payload gets its namespaces and its /proc metadata \
                 stays visible"
                    .to_string(),
            );
        }
        // A label is a /proc presentation, so it exists only where /proc is
        // redacted.  The isolate and plain modes cannot apply it to the
        // payload; say so instead of dropping it silently.
        if self.label.is_some() && mode != Mode::Redact {
            notes.push(format!(
                "the payload's label was not applied: {} mode does not redact the payload's \
                 /proc metadata",
                mode.as_str()
            ));
        }
        // `--no-dumpable` is a redaction-mode treatment: the tracer sets
        // `PR_SET_DUMPABLE=0` at each exec completion.  The other modes do
        // not change dumpability, so this note says it was not delivered.
        if self.no_dumpable && mode != Mode::Redact {
            notes.push(format!(
                "--no-dumpable was not applied: {} mode does not change the payload's \
                 dumpability",
                mode.as_str()
            ));
        }
        // Every other mask option needs the tracer too: the entry swap, the
        // post-exec rebuild, the window relocation, the seccomp filter, the
        // image carriers, the session-end policy or the namespace set.  A
        // mode without a tracer cannot apply any of them, and a silent drop
        // is a defect (AGENTS.md invariant 13), so each one is named with
        // the reason.  `--no-dumpable`, the label and `--unshare` are
        // handled above because their notes say something specific.
        if mode != Mode::Redact {
            for opt in &self.requested {
                if matches!(*opt, "--no-dumpable" | "--audit" | "--isolate") {
                    continue;
                }
                // These are applied by the non-redaction modes themselves:
                // the environment pairs reach the payload, the scope
                // re-exec happens before the mode is chosen, and a secret
                // is delivered on a descriptor in every mode.
                if matches!(
                    *opt,
                    "--env"
                        | "--env-file"
                        | "--secret"
                        | "--socket"
                        | "--allow-argv-secret"
                        | "--secret-burn"
                        | "--secret-close-on-exec"
                        | "--scope-name"
                ) {
                    continue;
                }
                // Isolate mode sets PR_SET_NO_NEW_PRIVS in the payload as
                // part of the isolation, so the option is satisfied there.
                if *opt == "--no-new-privs" && mode == Mode::Isolate {
                    continue;
                }
                // `--keep-env` asks for the inherited environment to stay
                // visible; neither mode redacts it, so it is satisfied.
                if *opt == "--keep-env" {
                    continue;
                }
                // `--no-redact` asks for exactly what these modes do: no
                // /proc treatment.  It is the reason the mode was chosen,
                // not a request that was dropped.
                if *opt == "--no-redact" {
                    continue;
                }
                notes.push(format!(
                    "{} was not applied: {} mode does not redact the payload's /proc \
                     metadata, and this option needs the redaction path",
                    opt,
                    mode.as_str()
                ));
            }
        }

        // `--secret-close-on-exec` is enforced by the tracer: it closes the
        // descriptors in each descendant at that descendant's fork, and the
        // payload keeps them across its own exec.  Without a tracer there is
        // no fork event to act on, so the only lever is `FD_CLOEXEC` on the
        // delivered descriptor, and the payload's own exec would honour it:
        // the program would start with no secret.  Refuse rather than
        // silently break either half of the flag's contract.  A library
        // caller that sets `DeliveryMode::CloseOnExec` directly asks for the
        // same policy and gets the same answer.
        let wants_close_on_exec =
            self.close_on_exec || self.delivery_mode == DeliveryMode::CloseOnExec;
        if wants_close_on_exec && !self.secrets.is_empty() && mode != Mode::Redact {
            let why = if mode == Mode::Isolate {
                "--isolate runs the payload without a tracer"
            } else if self.force_mode == Some(Mode::Plain) {
                "--no-redact forces plain mode"
            } else {
                "this host has no ptrace"
            };
            // The fix is always to remove the flag or the mode that makes
            // it impossible.  "Run where ptrace is available" cannot help
            // an explicit --isolate or --no-redact, which force the mode
            // on a host that has ptrace.
            let advice = if mode == Mode::Isolate {
                "Drop --secret-close-on-exec, or drop --isolate"
            } else if self.force_mode == Some(Mode::Plain) {
                "Drop --secret-close-on-exec, or drop --no-redact"
            } else {
                "Drop --secret-close-on-exec, or run where ptrace is available"
            };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "--secret-close-on-exec needs the ptrace supervisor: {} ({} mode), so the \
                     flag cannot be honoured; with FD_CLOEXEC the payload's own exec would close \
                     the descriptor, and without it every descendant would inherit it.  {}",
                    why,
                    mode.as_str(),
                    advice
                ),
            ));
        }
        // With no secret there is nothing to close.  The flag is a no-op,
        // and the help says so; name it rather than dropping it silently.
        if wants_close_on_exec && self.secrets.is_empty() {
            notes.push(
                "--secret-close-on-exec has nothing to close: no --secret was given".to_string(),
            );
        }
        // A name with no descriptor to carry it is the same kind of
        // no-op, and the operator has no other way to see it.
        if self
            .mask
            .as_ref()
            .is_some_and(|m| m.secret_fd_name_value().is_some())
            && self.secrets.is_empty()
        {
            notes.push(
                "--secret-fd-name has no effect: no --secret was given, so no descriptor is \
                 delivered"
                    .to_string(),
            );
        }

        // 0. Refuse a source that plain mode cannot protect, before any
        //    value is read.  The copies pmask cannot reach at all are the
        //    CLI's loud warning, printed once to stderr before the run;
        //    the report also records the exposure, so a CI job that reads
        //    `--report=json` sees it without scraping stderr (invariant
        //    13).
        if !self.secrets.is_empty() && self.secrets.iter().any(|(_, src)| src.is_in_plain_sight()) {
            notes.push(
                "a literal: or env: secret value is in pmask's own argv or environment, \
                 and the kernel audit log, the shell history and any wrapper's argv keep a \
                 copy of it"
                    .to_string(),
            );
        }
        notes.extend(self.check_sources(mode)?);

        // 1. Load secrets into protected memory.
        let mut secrets: Vec<Secret> = Vec::with_capacity(self.secrets.len());
        for (name, src) in &self.secrets {
            let s = secret::load(name, src, self.socket.as_ref())?;
            secrets.push(s);
        }
        let hardening = Hardening {
            locked: !secrets.is_empty() && secrets.iter().all(|s| s.is_locked()),
            secret_mem: !secrets.is_empty() && secrets.iter().all(|s| s.is_secret_mem()),
        };
        let delivery_mode = if self.close_on_exec {
            DeliveryMode::CloseOnExec
        } else {
            self.delivery_mode
        };
        let delivery = Delivery::with_mode_named(
            &secrets,
            delivery_mode,
            self.mask.as_ref().and_then(|m| m.secret_fd_name_value()),
        )?;
        if !secrets.is_empty() {
            // Once we hold plaintext, stop other processes of this account
            // from reading our memory.
            notes.extend(crate::mem::harden_self());
        }
        // Prove in the parent that the child can install the descriptors.
        // A failure here is the difference between "no secret" and "no
        // run".
        delivery.preflight()?;

        // 2. Environment: inherited, plus the overrides and the fd map.
        //    The redaction mode hands the pairs to `Mask::env`, which adds
        //    them on top of the inherited environment; the other modes
        //    build the vector from the same rule below.
        let extra_env: Vec<(OsString, OsString)> = delivery.env().to_vec();
        let fds = delivery.raw_fds();
        // True only for `DeliveryMode::CloseOnExec`, which the redaction
        // mode enforces at each descendant's fork.  The other modes refuse
        // that policy above, so this is false on every path that reaches
        // `install_fds` or `isolate::run`.
        let cloexec = !delivery.readable_by_descendants();

        // 3. Dispatch.
        let exit = match mode {
            Mode::Redact => {
                let mut mask = match self.mask.clone() {
                    Some(m) => m,
                    None => {
                        let m = Mask::new().follow_tree(self.follow_tree);
                        let m = if self.redact_environ {
                            m
                        } else {
                            m.keep_environ_visible()
                        };
                        let m = if self.exit_kill {
                            m
                        } else {
                            m.let_tree_survive_self_death()
                        };
                        // No label means the engine's default: each
                        // program's own basename, with arguments stripped.
                        match &self.label {
                            Some(l) => m.label(l.clone()),
                            None => m,
                        }
                    }
                };
                mask = mask.inherit_fds_with(fds.clone(), cloexec);
                // `--redact --isolate`: hand the requested namespace set to
                // the redaction child.  The set is the parsed `Isolate`
                // value, so `--isolate=net` yields a network namespace and
                // the host's pid namespace instead of `--unshare`'s
                // user+pid+mount set (issue 19).
                if let Some(iso) = self.compose {
                    if !iso.none {
                        mask = mask.namespaces(crate::userns::ChildNs {
                            pid: iso.pid,
                            net: iso.net,
                            procfs: iso.pid,
                            private_tmp: iso.private_tmp,
                        });
                    }
                }
                // `Mask::env` adds each pair on top of the inherited
                // environment.  `Mask::envs` would replace it wholesale,
                // which dropped PATH and HOME from a `--secret` run.
                for (k, v) in self.env_overrides.iter().chain(extra_env.iter()) {
                    mask = mask.env(k.clone(), v.clone());
                }
                mask = if self.quiet {
                    mask.quiet()
                } else if self.verbose {
                    mask.verbose()
                } else {
                    mask
                };
                // Fork first (the child must see the real environment),
                // then give the supervisor the same treatment it gives
                // the tree: its own cmdline is `pmask run --secret
                // TOKEN=file:...`, which names the secret.
                let child = mask.spawn(program.as_ref(), &args)?;
                let comm = child.label_comm().to_vec();
                let redact_env = child.redacts_environ();
                let selfmask = crate::selfmask::mask_self_with_window(&comm, redact_env);
                if let Some(e) = selfmask.window {
                    // A refused PR_SET_MM_MAP needs CAP_SYS_RESOURCE.  The
                    // argv block is zeroed and labelled either way; only
                    // the byte-length fingerprint stays.
                    notes.push(format!(
                        "the supervisor's own /proc window keeps its extent: {}",
                        e
                    ));
                }
                if let Some(e) = selfmask.error {
                    notes.push(format!(
                        "could not redact the supervisor's own /proc entry: {}",
                        e
                    ));
                }
                if let Some(e) = selfmask.dumpable {
                    notes.push(format!("could not make the supervisor non-dumpable: {}", e));
                }
                child.wait()?
            }
            Mode::Isolate => {
                let iso = self.iso_set().unwrap_or_else(Isolate::all);
                let prog = resolve_program(program.as_ref())?;
                let mut argv_c: Vec<CString> = Vec::with_capacity(args.len() + 1);
                argv_c.push(prog.clone());
                for a in &args {
                    argv_c.push(CString::new(a.as_bytes()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "NUL byte in argument")
                    })?);
                }
                let mut argv_ptr: Vec<*const libc::c_char> =
                    argv_c.iter().map(|c| c.as_ptr()).collect();
                argv_ptr.push(std::ptr::null());

                let mut envp_c: Vec<CString> = Vec::new();
                for (k, v) in self.environment(&extra_env) {
                    let mut j = k.as_bytes().to_vec();
                    j.push(b'=');
                    j.extend_from_slice(v.as_bytes());
                    j.push(0);
                    envp_c.push(unsafe { CString::from_vec_unchecked(j) });
                }
                let mut envp_ptr: Vec<*const libc::c_char> =
                    envp_c.iter().map(|c| c.as_ptr()).collect();
                envp_ptr.push(std::ptr::null());

                // The supervisor's own /proc entry names the command and
                // its arguments for the whole run.  Apply the same label
                // the redaction mode uses, with the program basename as
                // the default.  The child's argv and envp are already
                // copied into the owned C strings above, so zeroing this
                // process's block does not touch them.
                let label = match &self.label {
                    Some(l) => l.clone(),
                    None => program_basename(program.as_ref()),
                };
                let mut comm: Vec<u8> = label.bytes().take(crate::COMM_MAX).collect();
                if comm.is_empty() {
                    comm.push(b' ');
                }
                let selfmask =
                    crate::selfmask::mask_self_label_with_window(label.as_bytes(), &comm, true);
                if let Some(e) = selfmask.window {
                    notes.push(format!(
                        "the supervisor's own /proc window keeps its extent: {}",
                        e
                    ));
                }
                if let Some(e) = selfmask.error {
                    notes.push(format!(
                        "could not redact the supervisor's own /proc entry: {}",
                        e
                    ));
                }
                if let Some(e) = selfmask.dumpable {
                    notes.push(format!("could not make the supervisor non-dumpable: {}", e));
                }

                isolate::run(&iso, &prog, &argv_ptr, &envp_ptr, &fds, cloexec, self.quiet)?
            }
            Mode::Plain => {
                let prog = resolve_program(program.as_ref())?;
                let mut cmd =
                    std::process::Command::new(std::ffi::OsStr::from_bytes(prog.as_bytes()));
                for a in &args {
                    cmd.arg(a);
                }
                for (k, v) in self.environment(&extra_env) {
                    cmd.env(k, v);
                }
                // SAFETY: the closure calls only the shared checked install
                // routine between fork and exec, and install_fds allocates
                // nothing.
                let child_fds = fds.clone();
                unsafe {
                    use std::os::unix::process::CommandExt;
                    cmd.pre_exec(move || {
                        secret::install_fds(&child_fds, cloexec);
                        Ok(())
                    });
                }
                // The plain mode is the one path that runs a program
                // through `std::process::Command`, whose own error text is
                // the bare errno ("No such file or directory (os error
                // 2)").  Name the program the same way the redaction path
                // does, so a typo is attributable (issue 14 N1).
                let status = cmd.status().map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("{}: {}", program.as_ref().to_string_lossy(), e),
                    )
                })?;
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = status.signal() {
                    ExitState::plain(128 + sig, Some(sig))
                } else {
                    ExitState::plain(status.code().unwrap_or(255), None)
                }
            }
        };

        let secrets_report: Vec<SecretReport> = secrets
            .iter()
            .enumerate()
            .map(|(i, s)| SecretReport {
                name: s.name.clone(),
                locked: s.is_locked(),
                secret_mem: s.is_secret_mem(),
                fd: secret::FIRST_FD + i as libc::c_int,
            })
            .collect();

        Ok(Outcome {
            mode,
            mode_reason: mode_reason.to_string(),
            exit,
            secrets_delivered: fds.len(),
            notes,
            ptrace,
            // The field describes what the payload's `PR_GET_DUMPABLE`
            // returns, not the flag's name: the redaction mode applies
            // `--no-dumpable` at each exec, the isolate and plain modes
            // never change dumpability.  Reporting the request made the
            // document contradict the payload (issue 21).
            payload_dumpable: mode != Mode::Redact || !self.no_dumpable,
            hardening,
            secrets: secrets_report,
        })
    }
}

/// The program's basename, for the default self-mask label in a mode
/// that has no `Mask` to derive it.  The label is display text, so a
/// lossy decode is right; argv bytes are never touched.
fn program_basename(program: &std::ffi::OsStr) -> String {
    let bytes = program.as_bytes();
    let start = bytes
        .iter()
        .rposition(|&b| b == b'/')
        .map(|i| i + 1)
        .unwrap_or(0);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

/// PATH-resolve the program, like `execvp`.
fn resolve_program(program: &std::ffi::OsStr) -> io::Result<CString> {
    let bytes = program.as_bytes();
    if bytes.contains(&b'/') {
        return CString::new(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in program name"));
    }
    let path = std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin"));
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let cand = dir.join(program);
        if let Ok(md) = std::fs::metadata(&cand) {
            use std::os::unix::fs::MetadataExt;
            if md.is_file() && md.mode() & 0o111 != 0 {
                return CString::new(cand.as_os_str().as_bytes()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "NUL in program name")
                });
            }
        }
    }
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in program name"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(stats: crate::SessionStats, dumpable: bool) -> Outcome {
        Outcome {
            mode: Mode::Redact,
            mode_reason: String::new(),
            exit: crate::ExitState {
                code: 0,
                signal: None,
                stats,
            },
            secrets_delivered: 0,
            notes: Vec::new(),
            ptrace: true,
            payload_dumpable: dumpable,
            hardening: Hardening::default(),
            secrets: Vec::new(),
        }
    }

    fn caps_with(ptrace: bool, userns: bool, seccomp: bool, scope: Option<u32>) -> Caps {
        Caps {
            arch: "x86_64",
            kernel: "test".to_string(),
            ptrace,
            userns,
            memfd_secret: false,
            mlock: false,
            non_dumpable: false,
            seccomp_filter: seccomp,
            memlock_limit: 0,
            landlock_abi: 0,
            pidfd_open: false,
            peerpidfd: false,
            set_mm_map: false,
            no_new_privs: false,
            ptrace_scope: scope,
            proc_hidden: false,
            memfd_noexec: false,
            protected_regular: false,
            cap_effective: 0,
        }
    }

    #[test]
    fn report_json_carries_the_mode_reason() {
        let mut o = outcome(crate::SessionStats::default(), true);
        o.mode_reason = "isolate_unavailable".to_string();
        let json = o.report_json();
        assert!(
            json.contains("\"mode_reason\": \"isolate_unavailable\""),
            "{}",
            json
        );
        assert!(json.contains("\"mode\": \"redact\""), "{}", json);
    }

    #[test]
    fn selection_rule_names_the_axis_that_failed() {
        let plain = Runner::new();
        let s = plain.select_with(&caps_with(true, false, false, Some(0)));
        assert_eq!(s.mode, Mode::Redact);
        assert_eq!(s.reason, "");

        let s = plain.select_with(&caps_with(false, true, true, Some(0)));
        assert_eq!(s.mode, Mode::Plain);
        assert_eq!(s.reason, "seccomp");

        let s = plain.select_with(&caps_with(false, true, false, Some(3)));
        assert_eq!(s.mode, Mode::Plain);
        assert_eq!(s.reason, "yama_ptrace_scope");

        let s = plain.select_with(&caps_with(false, true, false, Some(0)));
        assert_eq!(s.mode, Mode::Plain);
        assert_eq!(s.reason, "no_capability");

        let isolate = Runner::new().isolate(Isolate::all());
        let s = isolate.select_with(&caps_with(true, true, false, Some(0)));
        assert_eq!(s.mode, Mode::Isolate);
        assert_eq!(s.reason, "");

        let s = isolate.select_with(&caps_with(true, false, false, Some(0)));
        assert_eq!(s.mode, Mode::Redact);
        assert_eq!(s.reason, "isolate_unavailable");

        let forced = Runner::new().no_redaction();
        let s = forced.select_with(&caps_with(true, true, false, Some(0)));
        assert_eq!(s.mode, Mode::Plain);
        assert_eq!(s.reason, "forced");
    }

    #[test]
    fn report_json_carries_the_session_degradations() {
        let stats = crate::SessionStats {
            execs: 3,
            degraded: 1,
            detached: 2,
            sized: 1,
            sized_skipped: 4,
            secret_close_failed: 5,
            ..crate::SessionStats::default()
        };
        let json = outcome(stats, true).report_json();
        assert!(json.contains("\"sized_skipped\": 4"), "{}", json);
        assert!(json.contains("\"secret_close_failed\": 5"), "{}", json);
        assert!(json.contains("\"degraded\": 1"), "{}", json);
    }

    #[test]
    fn report_json_payload_dumpable_follows_the_request() {
        assert!(outcome(crate::SessionStats::default(), true)
            .report_json()
            .contains("\"payload_dumpable\": true"));
        assert!(outcome(crate::SessionStats::default(), false)
            .report_json()
            .contains("\"payload_dumpable\": false"));
    }

    #[test]
    fn isolate_refuses_a_plain_sight_secret_but_redact_warns() {
        let r = Runner::new().secret("T", Source::Env("TOKEN".into()));
        let e = r.check_sources(Mode::Isolate).unwrap_err();
        assert!(e.to_string().contains("env:TOKEN"), "{}", e);
        assert!(e.to_string().contains("--allow-argv-secret"), "{}", e);
        assert!(r.check_sources(Mode::Plain).is_err());
        let warnings = r.check_sources(Mode::Redact).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("briefly"), "{}", warnings[0]);
        // The escape hatch keeps the source and warns in every mode.
        let allowed = Runner::new()
            .secret("T", Source::Literal("value".into()))
            .allow_argv_secret();
        assert!(allowed.check_sources(Mode::Isolate).is_ok());
        assert_eq!(allowed.check_sources(Mode::Isolate).unwrap().len(), 1);
    }

    #[test]
    fn a_literal_source_warns_about_the_audit_log_and_the_arg_ways_out() {
        let src = vec![("T".to_string(), Source::Literal("CANARY-9".into()))];
        let text = argv_secret_warning_with(&src, AuditState::Disabled).unwrap();
        assert!(text.contains("T=literal:"), "{}", text);
        assert!(text.contains("shell history"), "{}", text);
        assert!(text.contains("wrapper's argv"), "{}", text);
        assert!(text.contains("kernel audit log"), "{}", text);
        assert!(text.contains("--args-from-fd N"), "{}", text);
        assert!(text.contains("file:PATH, agent:NAME or stdin"), "{}", text);
        // The value is never in the warning.
        assert!(!text.contains("CANARY-9"), "{}", text);
    }

    #[test]
    fn an_enabled_audit_subsystem_makes_the_warning_stronger() {
        let src = vec![("T".to_string(), Source::Literal("v".into()))];
        let enabled = argv_secret_warning_with(&src, AuditState::Enabled).unwrap();
        let unknown = argv_secret_warning_with(&src, AuditState::Unknown).unwrap();
        let disabled = argv_secret_warning_with(&src, AuditState::Disabled).unwrap();
        assert!(enabled.contains("has already written"), "{}", enabled);
        assert!(!unknown.contains("has already written"), "{}", unknown);
        assert!(unknown.contains("could not ask"), "{}", unknown);
        assert!(disabled.contains("would hold it too"), "{}", disabled);
    }

    #[test]
    fn an_env_source_claims_no_audit_record() {
        let src = vec![("T".to_string(), Source::Env("TOKEN".into()))];
        let text = argv_secret_warning_with(&src, AuditState::Enabled).unwrap();
        assert!(text.contains("T=env:TOKEN"), "{}", text);
        assert!(text.contains("/proc/<pmask-pid>/environ"), "{}", text);
        assert!(text.contains("shell history"), "{}", text);
        assert!(text.contains("wrapper's environment"), "{}", text);
        // The kernel's exec record carries argv, not the environment.
        assert!(!text.contains("type=EXECVE"), "{}", text);
        assert!(
            text.contains("carries argv, not the environment"),
            "{}",
            text
        );
    }

    #[test]
    fn a_mixed_source_list_names_both_places() {
        let src = vec![
            ("A".to_string(), Source::Literal("v".into())),
            ("B".to_string(), Source::Env("TOKEN".into())),
        ];
        let text = argv_secret_warning_with(&src, AuditState::Disabled).unwrap();
        assert!(
            text.contains("sources A=literal:, B=env:TOKEN put"),
            "{}",
            text
        );
        assert!(text.contains("argv or environment"), "{}", text);
    }

    #[test]
    fn a_source_out_of_plain_sight_earns_no_warning() {
        let src = vec![
            ("T".to_string(), Source::File(PathBuf::from("/tmp/x"))),
            ("U".to_string(), Source::Stdin),
        ];
        assert!(argv_secret_warning_with(&src, AuditState::Enabled).is_none());
    }

    #[test]
    fn the_netlink_reply_parser_reads_the_three_shapes() {
        // A status reply: header, mask, enabled.
        let mut status = [0u8; 16 + 8];
        status[0..4].copy_from_slice(&24u32.to_ne_bytes());
        status[4..6].copy_from_slice(&AUDIT_GET.to_ne_bytes());
        status[AUDIT_STATUS_ENABLED..AUDIT_STATUS_ENABLED + 4].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(parse_audit_reply(&status), AuditState::Enabled);

        // The same reply with auditing off, and with the locked value.
        let mut off = status;
        off[AUDIT_STATUS_ENABLED..AUDIT_STATUS_ENABLED + 4].copy_from_slice(&0u32.to_ne_bytes());
        assert_eq!(parse_audit_reply(&off), AuditState::Disabled);
        let mut locked = status;
        locked[AUDIT_STATUS_ENABLED..AUDIT_STATUS_ENABLED + 4].copy_from_slice(&2u32.to_ne_bytes());
        assert_eq!(parse_audit_reply(&locked), AuditState::Enabled);

        // An error reply: the kernel's answer while auditing is off.
        let mut err = [0u8; 20];
        err[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        err[NLMSG_HDR..NLMSG_HDR + 4].copy_from_slice(&(-libc::ECONNREFUSED).to_ne_bytes());
        assert_eq!(parse_audit_reply(&err), AuditState::Disabled);

        // Another errno, a bare acknowledgement and a short message are
        // all "cannot tell", never "enabled" or "disabled".
        let mut eperm = err;
        eperm[NLMSG_HDR..NLMSG_HDR + 4].copy_from_slice(&(-libc::EPERM).to_ne_bytes());
        assert_eq!(parse_audit_reply(&eperm), AuditState::Unknown);
        let mut ack = err;
        ack[NLMSG_HDR..NLMSG_HDR + 4].copy_from_slice(&0i32.to_ne_bytes());
        assert_eq!(parse_audit_reply(&ack), AuditState::Unknown);
        assert_eq!(parse_audit_reply(&[0u8; 8]), AuditState::Unknown);
    }

    #[test]
    fn the_probe_answers_on_this_host() {
        // The answer depends on the host, so the assertion is that the
        // probe returns at all and never invents a state it cannot know.
        let state = audit_state();
        assert!(matches!(
            state,
            AuditState::Enabled | AuditState::Disabled | AuditState::Unknown
        ));
    }

    #[test]
    fn program_basename_strips_the_directory() {
        assert_eq!(
            program_basename(std::ffi::OsStr::new("/usr/bin/env")),
            "env"
        );
        assert_eq!(program_basename(std::ffi::OsStr::new("env")), "env");
        assert_eq!(program_basename(std::ffi::OsStr::new("/")), "");
    }
}
