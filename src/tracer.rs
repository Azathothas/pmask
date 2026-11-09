//! The tracer: one thread/process supervising a whole process tree.
//!
//! Every process of the tree is auto-attached (`PTRACE_O_TRACE{FORK,
//! VFORK,CLONE,EXEC,EXIT}`), syscall-supervised until its first exec
//! settles, and redacted at every `execve`/`execveat` — see `execimg`
//! for the image surgery.

use crate::arch::{self, ExecClass, Regs, SyscallInfo};
use crate::inject::{self, InjectError};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

/// Knobs of a masking session.
#[derive(Clone)]
pub struct Config {
    /// Label presented as the process command line (argv[0] of the
    /// /proc image); remaining argv entries present as empty strings.
    pub label: Vec<u8>,
    /// Label truncated to the kernel `comm` limit (15 bytes + NUL).
    pub label_comm: Vec<u8>,
    /// Also redact `/proc/<pid>/environ` (default on).
    pub redact_environ: bool,
    /// Follow every descendant (default on).
    pub follow_tree: bool,
    /// Kill the whole tree if the tracer dies (default on).
    pub exit_kill: bool,
    /// Event logging to stderr.
    pub verbose: bool,
    /// Suppress all diagnostics.
    pub quiet: bool,
    /// Inject `prctl(PR_SET_DUMPABLE, 0)` at every exec completion.
    pub no_dumpable: bool,
    /// The children carry a seccomp filter that traps `prctl(PR_SET_NAME)`
    /// (`SECCOMP_RET_TRACE`). The tracer redirects the rename to the label, or
    /// refuses the call when it cannot reach the label address.
    pub watch_prctl: bool,
    /// What happens to the remaining tree when the master exits.
    pub session_end: SessionEnd,
    /// Environment variable names that stay visible in `environ` while
    /// every other variable is redacted.  Empty: none stay visible.
    pub keep_env: Vec<Vec<u8>>,
    /// Move the kernel's argv/environment windows onto the presentation
    /// block with `prctl(PR_SET_MM, PR_SET_MM_MAP)` after each exec, so
    /// `/proc/<pid>/cmdline` is exactly the label and `/proc/<pid>/stat`
    /// no longer reports the original byte length (default on).
    pub exact: bool,
    /// Descriptors that must be closed in a descendant at its fork, while
    /// the supervised program keeps them (`--secret-close-on-exec`).
    pub close_secret_fds_in_descendants: Vec<libc::c_int>,
    /// `PTRACE_DETACH` a tracee once its exec has settled, so
    /// `TracerPid` reads 0 at rest.  Costs tree coverage: a detached
    /// process and its descendants are not redacted at later execs.
    pub detach: bool,
    /// The cache the builder and the tracer share.
    pub rexec_cache: crate::rexec::SharedCache,
    /// `--hugetlb`: ask for a hugetlb backing for later-exec images too.
    pub rexec_hugetlb: bool,
    /// `--memfd-name`: the memfd name for an image the tracer prepares
    /// (`--exec-once` later execs), so every carrier of one session reads
    /// the same `/memfd:` string.
    pub rexec_memfd_name: Option<String>,
    /// `--audit`: print one residue row per tracee at each exec
    /// completion, and a residue count at session end.
    pub audit: bool,
    /// `--exec-once`: redirect a settled tracee's later exec to a cached
    /// temporary-file image.  False when the tracee has a private pid
    /// namespace or the payload drops to another uid; later execs then
    /// run from disk and the builder says so once.
    pub rexec_per_exec: bool,
    /// Test hook: the n-th (1-based) repoint write of a completion stop
    /// fails.  Read from `PMASK_FAULT_POKE` by the builder, before the
    /// supervisor's own environment is redacted.
    pub fault_poke_at: u32,
    /// Test hook: skip the vDSO when looking for a syscall instruction.
    /// Read from `PMASK_FAULT_NOVDSO` by the builder.
    pub fault_no_vdso: bool,
    /// Test hook: treat every `PR_SET_MM_MAP` relocation as refused, so the
    /// degraded-window path and its summary line can be reached on a kernel
    /// that accepts the call.  Read from `PMASK_FAULT_REFUSE_MAP`.
    pub fault_refuse_map: bool,
    /// Test hook: every descendant's secret-fd close reports a failure, so
    /// the warning, the count and the re-attempt at depth > 1 can be
    /// reached on a host where the injection itself works.  Read from
    /// `PMASK_FAULT_CLOSE` by the builder.
    pub fault_close_fds: bool,
    /// Pids of every live tracee, kept current by the tracer so the
    /// owner of the session can kill the whole tree from outside.
    pub tree: TreeRegistry,
}

/// Shared set of live tracee pids.
pub type TreeRegistry = std::sync::Arc<std::sync::Mutex<std::collections::HashSet<libc::pid_t>>>;

/// What the session does with descendants still alive when the master
/// process exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// `PTRACE_DETACH` every remaining tracee once it is settled (its
    /// image is already redacted and keeps the label).  The session
    /// returns without waiting for them.  Default.
    Detach,
    /// Keep supervising until every descendant has exited.
    WaitTree,
    /// `SIGKILL` every remaining descendant.
    KillTree,
}

/// Terminal state of the supervised master process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitState {
    /// Process exit code, or 128+signal if it died from a signal.
    pub code: i32,
    /// Signal number if the master was killed by a signal.
    pub signal: Option<i32>,
    /// Exec accounting for the whole session.
    pub stats: SessionStats,
}

impl ExitState {
    /// An exit state without exec accounting.
    pub fn plain(code: i32, signal: Option<i32>) -> ExitState {
        ExitState {
            code,
            signal,
            stats: SessionStats::default(),
        }
    }
}

/// Exec accounting: how many execs the session saw and how many of them
/// ran with less than full redaction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Execs supervised (entry or completion stops handled).
    pub execs: u32,
    /// Execs that ran through the post-exec path (`#!` scripts, a vfork
    /// child, argv too large for the entry swap).  Redacted, with a short
    /// exposure window.
    pub script: u32,
    /// Execs where redaction failed or was skipped: disclosure.
    pub unredacted: u32,
    /// Execs that skipped only the `comm` rename.
    pub comm_skipped: u32,
    /// `prctl(PR_SET_NAME)` calls the redirect could not aim at the
    /// label, so the kernel refused them with `EFAULT` and `comm` kept
    /// the label.  Counted rather than letting the payload's own name
    /// through (`--watch-rename`, issue 60).
    pub rename_refused: u32,
    /// Foreign-architecture execs refused.
    pub foreign_arch: u32,
    /// Execs of an already settled process: redacted after the exec, with
    /// a short exposure window (no entry swap).
    pub reexec: u32,
    /// Execs whose kernel argv window was relocated with
    /// `PR_SET_MM_MAP`: `cmdline` is exactly the presentation string and
    /// `environ` is empty, without a byte-length fingerprint.
    pub sized: u32,
    /// Execs where the relocation was refused and the window keeps its
    /// original extent.
    pub sized_skipped: u32,
    /// Tracees left detached after a settled exec (`--detach`).
    pub detached: u32,
    /// Descendants whose secret descriptors could not be closed at their
    /// fork (`--secret-close-on-exec`): the descriptor stayed readable in
    /// that process.  Counted per descriptor and per descendant that
    /// inherits it.
    pub secret_close_failed: u32,
    /// `--rexec` fallback steps the child had to take (a refused
    /// `execveat`, `/proc/self/fd` or temporary-file attempt).
    pub rexec_fallback: u32,
    /// `--rexec` runs that used the explicit on-disk last resort.
    pub rexec_disk: u32,
    /// Execs with at least one of the degradations above.
    pub degraded: u32,
}

/// Where a tracee is in the exec lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Syscall supervision until the first exec completes (its entry
    /// stop is where the zero-exposure swap happens).
    Slow,
    /// Running free; only exec events will stop it (reread redaction).
    Run,
    /// exec entry arrays swapped, awaiting exec completion or error.
    Swapped,
    /// Script/unknown exec: redact after completion instead.
    Script,
    /// The new image runs another ABI (32-bit): refused, not redacted.
    Foreign,
}

/// Per-tracee bookkeeping.
pub struct Tracee {
    pub state: State,
    /// `--no-follow` mode: the descendant is traced (it has to be, to be
    /// followed at all) but its exec is never redacted.  Its exec stops
    /// are answered and it is then resumed unsupervised.
    pub no_redact: bool,
    pub env_swapped: bool,
    pub av_addr: u64,
    pub ev_addr: u64,
    pub av_save: Option<Vec<u64>>,
    pub ev_save: Option<Vec<u64>>,
    pub argv: Option<Vec<Vec<u8>>>,
    pub envp: Option<Vec<Vec<u8>>>,
    /// Fork depth relative to the supervised master: 0 for the master, 1
    /// for its direct children.  The descriptor policy needs it, because
    /// the program the caller started keeps the secret descriptors and
    /// everything it spawns must lose them.
    pub depth: u32,
    /// The secret descriptors are still open in this tracee: its own
    /// close failed, or it shares the descriptor table of a process whose
    /// close failed.  A fork from it re-attempts the close, so the
    /// inherited copies are closed as low as the injection reaches.
    pub secret_fds_open: bool,
    /// The tracee is a `vfork` child: it shares its parent's address
    /// space until it execs, so the entry swap must not write there.  Its
    /// first exec takes the post-exec path instead.
    pub vfork_child: bool,
    /// The cached image this tracee's current exec was redirected to
    /// (`--exec-once`).  Kept until the exec completes so the descriptor
    /// stays open for the tracee's `/proc/<tracer>/fd/N` path.
    pub rexec_image: Option<std::sync::Arc<crate::rexec::Image>>,
    /// Absolute address of the NUL-terminated `comm` label in this
    /// tracee's presentation block, or 0 when no block is mapped (an
    /// unredacted exec, `--no-follow`, or before the first completion).
    ///
    /// `--watch-rename` points the trapped `prctl(PR_SET_NAME)` name
    /// argument here, so the redirect needs no tracee memory write.  A
    /// write is what a `--no-dumpable` tracee refuses to a non-root
    /// tracer, which turned the natural flag pair into a silent leak
    /// (issue 60).
    pub rename_addr: u64,
}

impl Tracee {
    fn new(state: State) -> Tracee {
        Tracee {
            state,
            no_redact: false,
            env_swapped: false,
            av_addr: 0,
            ev_addr: 0,
            av_save: None,
            ev_save: None,
            argv: None,
            envp: None,
            depth: 0,
            secret_fds_open: false,
            vfork_child: false,
            rexec_image: None,
            rename_addr: 0,
        }
    }

    pub(super) fn clear_exec_state(&mut self) {
        self.env_swapped = false;
        self.rexec_image = None;
        self.av_addr = 0;
        self.ev_addr = 0;
        self.av_save = None;
        self.ev_save = None;
        self.argv = None;
        self.envp = None;
    }
}

/// Grace period after the master exits during which descendants that
/// have not yet settled their first exec keep their supervision.
const DETACH_GRACE: Duration = Duration::from_secs(1);

pub struct Tracer {
    pub cfg: Config,
    pub table: HashMap<libc::pid_t, Tracee>,
    pub stats: SessionStats,
    /// The master process of the session.
    master: libc::pid_t,
    /// Terminal state of the master, once it has exited.  Its presence
    /// means the session is ending.
    master_exit: Option<ExitState>,
    /// Detach drain: when the grace period ends.
    drain_deadline: Option<Instant>,
    /// Session start, the origin for the `-v` line timestamps.
    started: Instant,
    /// Tracees that were sent `PTRACE_INTERRUPT` during the drain.
    interrupted: std::collections::HashSet<libc::pid_t>,
    /// Child pid to the pid that forked it and that parent's fork depth,
    /// filled from the fork event and consumed when the child's first stop
    /// arrives.  The depth comes from the event, so a parent that exits
    /// before the child's first stop cannot make the child look shallower
    /// than it is.
    pending_children: HashMap<libc::pid_t, (libc::pid_t, u32)>,
    /// Child pids from a `PTRACE_EVENT_VFORK` stop, consumed when the
    /// child's first stop registers it.  A vfork child shares its parent's
    /// address space, so its first exec takes the post-exec path.
    vfork_children: std::collections::HashSet<libc::pid_t>,
    /// Test hook: the n-th (1-based) repoint write of a completion stop
    /// fails.  Zero: no fault.  Set from `PMASK_FAULT_POKE`.
    pub(super) fault_poke_at: u32,
    pub(super) poke_count: u32,
    /// Test hook: skip the vDSO when looking for a syscall instruction.
    /// Set from `PMASK_FAULT_NOVDSO`.
    pub(super) fault_no_vdso: bool,
    /// Test hook: every window relocation reports a refusal.
    /// Set from `PMASK_FAULT_REFUSE_MAP`.
    pub(super) fault_refuse_map: bool,
    /// Test hook: every secret-fd close reports a failure.
    /// Set from `PMASK_FAULT_CLOSE`.
    pub(super) fault_close_fds: bool,
    /// `--audit` rows counted and the reasons seen, printed at session
    /// end.
    audit_residue: u32,
    audit_reasons: std::collections::BTreeSet<&'static str>,
    audit_header: bool,
    /// Read end of the child's `--rexec` step-report pipe, or -1.
    rexec_report_fd: RawFd,
    /// The `--detach` release warning has been printed.  One line per
    /// session: the count is in the session summary.
    detach_warned: bool,
}

impl Tracer {
    pub(crate) fn vlog(&self, args: std::fmt::Arguments) {
        if self.cfg.verbose && !self.cfg.quiet {
            // A monotonic offset makes two `-v` lines orderable and lets a
            // reader correlate a completion-stop duration with the event
            // before it (issue 14 N7).  A wall-clock prefix would tie the
            // trace to an external log but also disclose the host clock,
            // so the offset is relative to the session start.
            let ms = self.started.elapsed().as_micros();
            eprintln!(
                "[pmask {} +{}.{:06}s] {}",
                std::process::id(),
                ms / 1_000_000,
                ms % 1_000_000,
                args
            );
        }
    }

    /// A degradation the operator must see even without `--verbose`.
    pub(crate) fn warn(&self, args: std::fmt::Arguments) {
        if !self.cfg.quiet {
            eprintln!("pmask: warning: {}", args);
        }
    }

    pub fn new(cfg: Config) -> Tracer {
        let fault_poke_at = cfg.fault_poke_at;
        let fault_no_vdso = cfg.fault_no_vdso;
        let fault_refuse_map = cfg.fault_refuse_map;
        let fault_close_fds = cfg.fault_close_fds;
        Tracer {
            cfg,
            table: HashMap::new(),
            stats: SessionStats::default(),
            master: 0,
            master_exit: None,
            drain_deadline: None,
            started: Instant::now(),
            interrupted: std::collections::HashSet::new(),
            pending_children: HashMap::new(),
            vfork_children: std::collections::HashSet::new(),
            fault_poke_at,
            poke_count: 0,
            fault_no_vdso,
            fault_refuse_map,
            fault_close_fds,
            audit_residue: 0,
            audit_reasons: std::collections::BTreeSet::new(),
            audit_header: false,
            rexec_report_fd: -1,
            detach_warned: false,
        }
    }

    fn register(&mut self, pid: libc::pid_t, t: Tracee) {
        self.table.insert(pid, t);
        if let Ok(mut set) = self.cfg.tree.lock() {
            set.insert(pid);
        }
    }

    fn unregister(&mut self, pid: libc::pid_t) {
        self.table.remove(&pid);
        self.interrupted.remove(&pid);
        if let Ok(mut set) = self.cfg.tree.lock() {
            set.remove(&pid);
        }
    }

    /// Supervise `master` until the session ends; returns the master's
    /// terminal state.
    ///
    /// `master` is forked and blocked reading `go_fd`.  The tracer seizes
    /// it, stops it with `PTRACE_INTERRUPT`, takes that `PTRACE_EVENT_STOP`
    /// as the handshake, releases it by writing one byte to `go_fd`, and
    /// begins syscall supervision from there.  The stop must not come from
    /// the child: a pid-namespace init cannot count on a job-control stop
    /// it sends itself being delivered (issue 4).
    pub fn supervise(
        mut self,
        master: libc::pid_t,
        ready_fd: RawFd,
        go_fd: RawFd,
        report_fd: RawFd,
    ) -> io::Result<ExitState> {
        self.master = master;
        self.rexec_report_fd = report_fd;
        if report_fd >= 0 {
            // The tracer drains the pipe at each exec completion and at
            // session end; a non-blocking read never wedges the loop.
            // SAFETY: fcntl on a descriptor owned by this call.
            unsafe {
                let flags = libc::fcntl(report_fd, libc::F_GETFL);
                if flags >= 0 {
                    libc::fcntl(report_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
        }
        if self.cfg.rexec_per_exec && !self.cfg.quiet {
            eprintln!(
                "pmask: --exec-once: later execs use a guarded temporary-file image, not \
                 the supervisor's descriptor"
            );
        }
        // `--detach` gives up the fork events of a settled tracee, so the
        // close-on-exec policy cannot be enforced below it: the payload
        // keeps the descriptors and a detached descendant's children
        // inherit them.  The default session-end policy detaches what is
        // still running when the master exits, with the same consequence
        // for a descriptor whose close failed.  Say so once, at the
        // default verbosity.
        if !self.cfg.close_secret_fds_in_descendants.is_empty() {
            if self.cfg.detach {
                self.warn(format_args!(
                    "--detach with --secret-close-on-exec: a detached tracee is not traced, \
                     so the secret descriptors stay open in what it starts"
                ));
            } else if self.cfg.session_end == SessionEnd::Detach {
                self.warn(format_args!(
                    "--secret-close-on-exec with the default --on-exit detach: a descendant \
                     still running when the program exits is detached untraced, so a \
                     descriptor that could not be closed at a fork stays open in what it starts"
                ));
            }
        }
        // The child sends one handshake byte before it waits for the go
        // signal; by then it has restored its own `dumpable` (a caller
        // that hardens itself for secret material sets
        // `PR_SET_DUMPABLE(0)`, and the child inherits it across the
        // fork).  Reading the handshake first makes the seize
        // deterministic: an unprivileged tracer may not seize a
        // non-dumpable process even when it forked it.
        let mut ready = [0u8; 1];
        loop {
            // SAFETY: reading one byte from the pipe end owned by this call.
            let n = unsafe { libc::read(ready_fd, ready.as_mut_ptr() as *mut libc::c_void, 1) };
            if n == 1 {
                break;
            }
            if n == -1 && last_errno() == libc::EINTR {
                continue;
            }
            // EOF: the child is gone before the handshake.
            let mut st = 0i32;
            // SAFETY: plain waitpid of our own child.
            unsafe {
                libc::waitpid(master, &mut st, libc::__WALL);
            }
            // SAFETY: pipe ends not used past this point.
            unsafe {
                libc::close(ready_fd);
                libc::close(go_fd);
                if report_fd >= 0 {
                    libc::close(report_fd);
                }
            }
            return Ok(finish_status(master, st));
        }
        // SAFETY: closing the pipe end owned by this call.
        unsafe { libc::close(ready_fd) };
        if let Err(e) = self.seize(master) {
            // SAFETY: closing the pipe end owned by this call.
            unsafe {
                libc::close(go_fd);
                if report_fd >= 0 {
                    libc::close(report_fd);
                }
            }
            // Nothing is traced: the child must not run unmasked.
            // SAFETY: plain kill and reap of our own child.
            unsafe {
                libc::kill(master, libc::SIGKILL);
                let mut st = 0i32;
                libc::waitpid(master, &mut st, libc::__WALL);
            }
            return Err(e);
        }
        // Ask the seized child to stop instead of waiting for a signal it
        // sends itself.  The old handshake was `libc::raise(SIGSTOP)` in
        // the child, and a process that is pid 1 of its own pid namespace
        // (`--unshare`, `--redact --isolate`) cannot rely on that stop
        // arriving: the kernel discards a job-control stop aimed at a
        // namespace init, the tracer then took the next stop it saw (the
        // exec event) as the handshake, and `supervise` returned without
        // redacting anything (issue 4).  `PTRACE_INTERRUPT` is delivered
        // by the kernel to the tracee, so the namespace cannot change the
        // outcome.
        //
        // Order matters: interrupt, wait for the stop, and only then
        // release the child.  The child cannot exec while it is stopped,
        // so the stop that arrives is always the interrupt stop and never
        // an exec event.
        let rc = unsafe {
            libc::ptrace(
                arch::PTRACE_INTERRUPT as _,
                master,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if rc == -1 {
            let e = io::Error::last_os_error();
            // SAFETY: closing the pipe ends and the report descriptor
            // owned by this call.
            unsafe {
                libc::close(go_fd);
                if report_fd >= 0 {
                    libc::close(report_fd);
                }
            }
            if e.raw_os_error() == Some(libc::ESRCH) {
                // The child is already gone (a refused setup step exits
                // it before the handshake).  Reap it and report its own
                // status, like the readiness-EOF path above.
                let mut st = 0i32;
                // SAFETY: plain waitpid of our own child.
                unsafe {
                    libc::waitpid(master, &mut st, libc::__WALL);
                }
                return Ok(finish_status(master, st));
            }
            // Nothing is traced: the child must not run unmasked.
            // SAFETY: plain kill and reap of our own child.
            unsafe {
                libc::kill(master, libc::SIGKILL);
                let mut st = 0i32;
                libc::waitpid(master, &mut st, libc::__WALL);
            }
            return Err(e);
        }
        let status = match wait_master_stop(master) {
            Ok(s) => s,
            Err(e) => {
                // The master is seized and stopped or running, and the
                // table does not own it yet.  Invariant 5: never leave a
                // stopped-and-forgotten tracee, so kill and reap it here.
                // SAFETY: the descriptor, the pipe end and our own child.
                unsafe {
                    libc::close(go_fd);
                    if report_fd >= 0 {
                        libc::close(report_fd);
                    }
                    libc::kill(master, libc::SIGKILL);
                    let mut st = 0i32;
                    libc::waitpid(master, &mut st, libc::__WALL);
                }
                return Err(e);
            }
        };
        if !libc::WIFSTOPPED(status) {
            // died before the handshake (for example an internal error)
            // SAFETY: the pipe end is owned by this call.
            unsafe { libc::close(go_fd) };
            return Ok(finish_status(master, status));
        }
        // A `PTRACE_INTERRUPT` stop is `PTRACE_EVENT_STOP` with SIGTRAP.
        // Any other stop here means the child got a job-control signal of
        // its own; it is still a stop, so release it the same way, but
        // say so: the handshake is then not the one this code installs.
        let sig = libc::WSTOPSIG(status);
        let event = (status as u32) >> 16;
        if event == arch::PTRACE_EVENT_STOP && sig == libc::SIGTRAP {
            vlog!(
                self,
                "master {}: handshake is the PTRACE_INTERRUPT stop",
                master
            );
        } else {
            vlog!(
                self,
                "master {}: handshake stop is sig {}/{}, not PTRACE_INTERRUPT",
                master,
                sig,
                event
            );
        }
        let byte = [1u8; 1];
        // SAFETY: go_fd is a valid pipe write end owned by this call.
        unsafe {
            libc::write(go_fd, byte.as_ptr() as *const libc::c_void, 1);
            libc::close(go_fd);
        }
        self.register(master, Tracee::new(State::Slow));
        // PTRACE_SYSCALL starts the syscall supervision the first exec is
        // swapped at.  The stop above is normally the interrupt stop and
        // the release carries no signal.  The two other shapes must not
        // lose a signal the child was sent: a signal-delivery stop is
        // re-injected so its handler or default action still runs, and a
        // group-stop (which has already consumed its stop signal) is left
        // with SIGCONT.
        let release = if event == arch::PTRACE_EVENT_STOP {
            if sig == libc::SIGTRAP {
                0
            } else {
                libc::SIGCONT
            }
        } else {
            sig
        };
        self.resume(master, release, true);

        loop {
            let waited = if self.master_exit.is_some() && self.table.is_empty() {
                // The master is gone and no tracee is left in the table.
                // A child forked a moment before it exited can still stop
                // afterwards, so block on the queue instead of returning:
                // `PTRACE_O_EXITKILL` would kill that child as this
                // process exits, and `--on-exit wait` would stop waiting.
                // With nothing left the kernel answers ECHILD at once, so
                // a session with no descendants pays nothing.
                match wait_any() {
                    Ok(w) => w,
                    Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                        self.table.clear();
                        return Ok(self.finish());
                    }
                    Err(e) => return Err(e),
                }
            } else if self.drain_ready() {
                match wait_any_nohang()? {
                    Some(w) => w,
                    None => {
                        self.drain_tick();
                        if self.table.is_empty() {
                            continue;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                }
            } else {
                // The master is alive, or it is gone and a tracee is still
                // stopped under this session: block on the queue.  A
                // tracee that is running free produces no stop, so this is
                // reachable only while something is ptrace-stopped, which
                // is exactly when a wait will return.
                match wait_any() {
                    Ok(w) => w,
                    Err(e) => {
                        if e.raw_os_error() == Some(libc::ECHILD) && self.master_exit.is_some() {
                            self.table.clear();
                            return Ok(self.finish());
                        }
                        return Err(e);
                    }
                }
            };
            let (pid, status) = waited;
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                self.on_gone(pid, status);
                continue;
            }
            if !libc::WIFSTOPPED(status) {
                continue;
            }
            let sig = libc::WSTOPSIG(status);
            let event = (status as u32) >> 16;

            if !self.table.contains_key(&pid) {
                let (parent, parent_depth) = match self.pending_children.remove(&pid) {
                    Some((p, d)) => (p, Some(d)),
                    None => (proc_ppid(pid).unwrap_or(master), None),
                };
                self.on_new_tracee(pid, master, parent, parent_depth);
                continue;
            }

            if event == arch::PTRACE_EVENT_STOP {
                self.on_event_stop(pid, sig);
                continue;
            }
            if event == arch::PTRACE_EVENT_SECCOMP {
                self.on_seccomp_stop(pid);
                continue;
            }
            if sig == libc::SIGTRAP && event != 0 {
                self.on_ptrace_event(pid, event);
                continue;
            }
            if sig == libc::SIGTRAP | 0x80 {
                self.on_syscall_stop(pid);
                continue;
            }
            // Real signal delivery, including a SIGTRAP raised by the
            // program itself: pass it on.
            self.resume_state(pid, sig);
        }
    }

    /// Exit state with the session statistics attached; prints the
    /// summary line.
    fn finish(&mut self) -> ExitState {
        self.drain_rexec_report();
        if self.rexec_report_fd >= 0 {
            // SAFETY: the descriptor is owned by this session.
            unsafe { libc::close(self.rexec_report_fd) };
            self.rexec_report_fd = -1;
        }
        // The caller may exit without running destructors, so the named
        // temporary carriers are removed here.
        if let Ok(mut cache) = self.cfg.rexec_cache.lock() {
            cache.remove_temp_files();
        }
        let mut st = self
            .master_exit
            .unwrap_or_else(|| ExitState::plain(255, None));
        st.stats = self.stats;
        self.print_summary();
        st
    }

    /// Read the child's `--rexec` step bytes and fold them into the
    /// session counters.  The pipe is non-blocking.
    pub(crate) fn drain_rexec_report(&mut self) {
        if self.rexec_report_fd < 0 {
            return;
        }
        let mut buf = [0u8; 32];
        loop {
            // SAFETY: one read from a descriptor owned by this session.
            let n = unsafe {
                libc::read(
                    self.rexec_report_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                return;
            }
            for &b in &buf[..n as usize] {
                match b {
                    b'1' | b'2' | b'3' => self.stats.rexec_fallback += 1,
                    b'4' => {
                        self.stats.rexec_fallback += 1;
                        self.stats.rexec_disk += 1;
                    }
                    _ => {}
                }
            }
        }
    }

    /// Print one residue row for `pid` while it is stopped at its exec
    /// completion.  An interface that cannot be read prints `not
    /// reachable`; it is never printed as a zero.
    pub(super) fn audit_row(&mut self, pid: libc::pid_t) {
        let base = format!("/proc/{}", pid);
        let read = |name: &str| std::fs::read(format!("{}/{}", base, name)).ok();
        let comm = read("comm")
            .map(|b| String::from_utf8_lossy(&b).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "not reachable".to_string());
        let exe = std::fs::read_link(format!("{}/exe", base))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "not reachable".to_string());
        let status = read("status").map(|b| String::from_utf8_lossy(&b).into_owned());
        let tracer = status
            .as_deref()
            .and_then(|s| s.lines().find(|l| l.starts_with("TracerPid:")))
            .and_then(|l| l.split_whitespace().nth(1).map(|v| v.to_string()))
            .unwrap_or_else(|| "not reachable".to_string());
        let cmdline = read("cmdline");
        let (cmdline_bytes, nul_ratio) = match &cmdline {
            Some(b) if !b.is_empty() => {
                let nuls = b.iter().filter(|&&c| c == 0).count();
                (
                    b.len().to_string(),
                    format!("{:.2}", nuls as f64 / b.len() as f64),
                )
            }
            Some(_) => ("0".to_string(), "0.00".to_string()),
            None => ("not reachable".to_string(), "not reachable".to_string()),
        };
        let mut fd_names: Vec<String> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(format!("{}/fd", base)) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let target = std::fs::read_link(e.path())
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "not reachable".to_string());
                fd_names.push(format!("{}:{}", name, target));
            }
        }
        let fds = if fd_names.is_empty() {
            "not reachable".to_string()
        } else {
            fd_names.join(",")
        };
        if !self.audit_header {
            audit_line("pmask audit: header pid comm exe tracer cmdline_bytes nul_ratio fds");
            self.audit_header = true;
        }
        audit_line(&format!(
            "pmask audit: pid={} comm={} exe={} tracer={} cmdline_bytes={} nul_ratio={} fds={}",
            pid, comm, exe, tracer, cmdline_bytes, nul_ratio, fds
        ));
        // The interfaces this row cannot close.  The pid always exists;
        // a readable exe, a readable memory file and a descriptor that
        // names the tool are the other three.
        let mut reasons: Vec<&'static str> = vec!["pid"];
        if exe != "not reachable" {
            reasons.push("exe");
        }
        if std::fs::File::open(format!("{}/mem", base)).is_ok() {
            reasons.push("mem");
        }
        if fd_names.iter().any(|f| f.contains("pmask")) {
            reasons.push("fd");
        }
        if !reasons.is_empty() {
            self.audit_residue += 1;
            for r in reasons {
                self.audit_reasons.insert(r);
            }
        }
    }

    fn print_summary(&self) {
        let s = &self.stats;
        // `--audit` is an explicit report request, so `-q` does not
        // suppress its residue line.
        if self.cfg.audit {
            let reasons: Vec<&str> = self.audit_reasons.iter().copied().collect();
            audit_line(&format!(
                "pmask audit: residue: {} ({})",
                self.audit_residue,
                reasons.join(", ")
            ));
        }
        if self.cfg.quiet {
            return;
        }
        if s.degraded > 0 {
            let mut reasons: Vec<String> = Vec::new();
            let mut add = |name: &str, n: u32| {
                if n == 1 {
                    reasons.push(name.to_string());
                } else if n > 1 {
                    reasons.push(format!("{} x{}", name, n));
                }
            };
            // Every entry here is a degradation, not a disclosure: the
            // exec was redacted, or one part of the treatment was skipped.
            // `unredacted` is the entry that means the real strings may
            // have been visible.
            add("post-exec", s.script);
            add("reexec", s.reexec);
            add("unredacted", s.unredacted);
            add("comm-not-set", s.comm_skipped);
            add("foreign-arch", s.foreign_arch);
            eprintln!(
                "pmask: {} of {} execs degraded ({})",
                s.degraded,
                s.execs,
                reasons.join(", ")
            );
        }
        // A refused window relocation is a degradation in its own right:
        // `/proc/<pid>/stat` still reports the original byte length, so it
        // prints even when nothing else was degraded.
        if s.sized_skipped > 0 {
            eprintln!(
                "pmask: {} of {} execs kept the kernel's argv and environ \
                 windows (PR_SET_MM_MAP refused)",
                s.sized_skipped, s.execs
            );
        }
        // `--detach` trades tree coverage for `TracerPid` 0: every tracee
        // left behind runs unredacted at its later execs.  That is a
        // degradation of the session, not of the exec that detached it.
        if s.detached > 0 {
            eprintln!(
                "pmask: {} tracee(s) left detached after their exec \
                 (--detach: their later execs are not redacted)",
                s.detached
            );
        }
        // A descriptor that could not be closed at a descendant's fork is
        // still readable in that process.  The warning at the fork names
        // the pid; this is the session count.
        if s.secret_close_failed > 0 {
            eprintln!(
                "pmask: {} secret descriptor(s) could not be closed in a descendant",
                s.secret_close_failed
            );
        }
        // A `--rexec` step that failed is a degradation of the preferred
        // carrier, not of the redaction: the child reports the step and
        // this is the count.
        if s.rexec_fallback > 0 {
            eprintln!(
                "pmask: {} --rexec fallback step(s) taken ({} used the on-disk last resort)",
                s.rexec_fallback, s.rexec_disk
            );
        }
        // A rename the redirect had to refuse left `comm` at the label,
        // so the promise held, but the payload's own `PR_SET_NAME` did
        // not take effect.  That is a degradation, and it is counted.
        if s.rename_refused > 0 {
            eprintln!(
                "pmask: {} rename(s) refused because the label address was not available \
                 (comm kept the label)",
                s.rename_refused
            );
        }
    }

    fn seize(&self, pid: libc::pid_t) -> io::Result<()> {
        // SAFETY: seizing our own, running child; the options word is
        // passed in the data slot as the kernel API requires.
        let rc = unsafe {
            libc::ptrace(
                arch::PTRACE_SEIZE as _,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                self.options() as *mut libc::c_void,
            )
        };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    // ------------------------------------------------------------- events --

    fn on_gone(&mut self, pid: libc::pid_t, status: i32) {
        if pid == self.master {
            self.drain_rexec_report();
        }
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            128 + libc::WTERMSIG(status)
        };
        vlog!(self, "pid {} gone ({})", pid, code);
        self.unregister(pid);
        if pid == self.master && self.master_exit.is_none() {
            let signal = if libc::WIFSIGNALED(status) {
                Some(libc::WTERMSIG(status))
            } else {
                None
            };
            self.master_exit = Some(ExitState::plain(code, signal));
            self.begin_session_end();
        }
    }

    /// The master has exited: apply the session-end policy to what is left.
    fn begin_session_end(&mut self) {
        match self.cfg.session_end {
            SessionEnd::WaitTree => {}
            SessionEnd::KillTree => {
                let pids: Vec<libc::pid_t> = self.table.keys().copied().collect();
                for p in pids {
                    // SAFETY: plain kill(2) of a tracee of this session.
                    unsafe { libc::kill(p, libc::SIGKILL) };
                }
            }
            SessionEnd::Detach => {
                if !self.table.is_empty() {
                    vlog!(
                        self,
                        "master gone: detaching {} descendant(s)",
                        self.table.len()
                    );
                    self.drain_deadline = Some(Instant::now() + DETACH_GRACE);
                    self.drain_tick();
                }
            }
        }
    }

    fn draining(&self) -> bool {
        self.master_exit.is_some() && self.drain_deadline.is_some()
    }

    /// True when the loop must poll instead of blocking on the wait queue.
    /// Starts the drain on the first call after the master is gone under
    /// the detach policy. A fork queued behind the master's own exit is
    /// reported after the master is reaped, so the table can gain its
    /// first tracee after `begin_session_end` already saw it empty. That
    /// tracee runs free and never stops again, so blocking on the queue
    /// there waits forever.
    fn drain_ready(&mut self) -> bool {
        if self.master_exit.is_none() {
            return false;
        }
        if self.cfg.session_end == SessionEnd::Detach
            && self.drain_deadline.is_none()
            && !self.table.is_empty()
        {
            vlog!(
                self,
                "master gone: detaching {} late descendant(s)",
                self.table.len()
            );
            self.drain_deadline = Some(Instant::now() + DETACH_GRACE);
            self.drain_tick();
        }
        self.draining()
    }

    fn grace_over(&self) -> bool {
        match self.drain_deadline {
            Some(d) => Instant::now() >= d,
            None => false,
        }
    }

    /// May this tracee be detached now?  Settled tracees always; tracees
    /// still waiting for their first exec only after the grace period; a
    /// tracee inside an exec never (the exec must finish its redaction).
    fn detachable(&self, pid: libc::pid_t) -> bool {
        if !self.draining() {
            return false;
        }
        match self.table.get(&pid).map(|t| t.state) {
            Some(State::Run) => true,
            Some(State::Slow) => self.grace_over(),
            _ => false,
        }
    }

    /// Ask running, detachable tracees to stop so they can be detached.
    fn drain_tick(&mut self) {
        let pids: Vec<libc::pid_t> = self.table.keys().copied().collect();
        for pid in pids {
            if self.interrupted.contains(&pid) || !self.detachable(pid) {
                continue;
            }
            // SAFETY: PTRACE_INTERRUPT on a seized tracee; harmless when
            // the tracee is already stopped.
            let rc = unsafe {
                libc::ptrace(
                    arch::PTRACE_INTERRUPT as _,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            if rc == 0 {
                self.interrupted.insert(pid);
            } else {
                // not ptrace-stoppable (gone): drop it from the table
                // when it no longer exists
                if !proc_exists(pid) {
                    self.unregister(pid);
                }
            }
        }
    }

    pub(super) fn detach(&mut self, pid: libc::pid_t, sig: libc::c_int) {
        // SAFETY: the tracee is in a ptrace-stop at every call site.
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                sig as *mut libc::c_void,
            )
        };
        if rc == -1 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ESRCH) {
                self.warn(format_args!("pid {}: detach failed: {}", pid, e));
            }
        } else {
            // The `--detach` trade, at the moment it is taken: the pid
            // still carries the label and the relocated window, but no
            // supervisor remains, so a later exec of it runs fully real.
            // One line per session; the summary's count covers the rest.
            if self.cfg.detach && !self.detach_warned {
                self.detach_warned = true;
                self.warn(format_args!(
                    "--detach: pid {} is released untraced, so its later execs are not \
                     redacted",
                    pid
                ));
            }
            vlog!(self, "pid {}: detached", pid);
        }
        self.unregister(pid);
    }

    /// True when `parent` is stopped at a `PTRACE_EVENT_VFORK` whose
    /// event message names `child`.  The child's first stop can arrive
    /// before the tracer processes the parent's event, and a vfork child
    /// runs before the parent resumes, so the event set alone races.
    fn parent_is_vfork(&self, parent: libc::pid_t, child: libc::pid_t) -> bool {
        // SAFETY: siginfo_t is plain data; the parent is a tracee.
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_GETSIGINFO,
                parent,
                std::ptr::null_mut::<libc::c_void>(),
                &mut si as *mut libc::siginfo_t as *mut libc::c_void,
            )
        };
        if rc == -1 {
            return false;
        }
        // A ptrace event stop encodes the event in the high bits of
        // si_code; PTRACE_EVENT_VFORK is 2.
        if (si.si_code >> 8) != libc::PTRACE_EVENT_VFORK as libc::c_int {
            return false;
        }
        let mut msg: u64 = 0;
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_GETEVENTMSG,
                parent,
                std::ptr::null_mut::<libc::c_void>(),
                &mut msg as *mut u64 as *mut libc::c_void,
            )
        };
        rc == 0 && msg == child as u64
    }

    fn on_new_tracee(
        &mut self,
        pid: libc::pid_t,
        master: libc::pid_t,
        parent: libc::pid_t,
        parent_depth: Option<u32>,
    ) {
        // Auto-traced newcomer (fork/vfork/clone of an existing tracee).
        let unmasked = !self.cfg.follow_tree && pid != master;
        // A thread inherits its group's position in the exec lifecycle: a
        // `CLONE_THREAD` newcomer cannot exec on its own without becoming
        // the leader, so putting it under syscall supervision would cost
        // two stops per system call for as long as the thread lives and
        // would buy nothing.  A real fork stays Slow: its own first exec
        // is what the entry swap exists for.
        let thread_of = match thread_group_leader(pid) {
            Some(leader) if leader != pid => Some(leader),
            _ => None,
        };
        let settled_with_group = match thread_of {
            Some(leader) => matches!(
                self.table.get(&leader).map(|t| t.state),
                Some(State::Run) | Some(State::Swapped)
            ),
            None => false,
        };
        let start_run = unmasked || settled_with_group;
        // A thread takes its group's depth; only a real fork adds one to
        // its parent's depth.  The parent's depth comes from the fork
        // event, so it is known even when the parent has already exited.
        // Depth 0 and 1 are the program the caller asked for, and
        // everything below that is what it spawned.
        let leader_depth = thread_of.and_then(|l| self.table.get(&l).map(|t| t.depth));
        let parent_table_depth = self.table.get(&parent).map(|t| t.depth);
        let depth = newcomer_depth(thread_of, leader_depth, parent_depth, parent_table_depth);
        let leader_open = thread_of.and_then(|l| self.table.get(&l).map(|t| t.secret_fds_open));
        let parent_open = self
            .table
            .get(&parent)
            .map(|t| t.secret_fds_open)
            .unwrap_or(false);
        let mut t = Tracee::new(if start_run { State::Run } else { State::Slow });
        t.no_redact = unmasked;
        t.vfork_child = self.vfork_children.remove(&pid) || self.parent_is_vfork(parent, pid);
        if t.vfork_child {
            vlog!(self, "pid {}: registered as a vfork child", pid);
        }
        t.depth = depth;
        // A thread shares its group's descriptor table, so it holds the
        // secret descriptors exactly when the group does.  A real fork is
        // recorded as open only when the close below fails.
        t.secret_fds_open = if thread_of.is_some() {
            leader_open.unwrap_or(parent_open)
        } else {
            false
        };
        self.register(pid, t);
        let killed = self.master_exit.is_some() && self.cfg.session_end == SessionEnd::KillTree;
        if killed {
            // A newcomer that arrived after the master left was not in the
            // table when `begin_session_end` killed it.  Kill it now to
            // keep the policy's promise, and resume so the pending signal
            // is delivered.
            // SAFETY: plain kill(2) of a tracee of this session.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            vlog!(self, "pid {}: killed on arrival (master gone)", pid);
        }
        let why = if unmasked {
            " (unmasked: --no-follow)"
        } else if settled_with_group {
            " (thread, group already settled)"
        } else {
            ""
        };
        vlog!(self, "pid {}: new tracee{}", pid, why);
        // The payload keeps its secret descriptors; everything it spawns
        // loses them here, at the fork, before the newcomer runs a single
        // instruction.  A thread shares its group's descriptor table and
        // is skipped.  A deeper descendant re-attempts the close only when
        // its parent's close failed, so the inherited copies are closed as
        // low as the injection reaches.
        if !killed
            && !self.close_secret_fds_at_fork(pid, parent, depth, thread_of.is_some(), parent_open)
        {
            return;
        }
        self.resume_state(pid, 0);
    }

    /// Close the secret descriptors in a newcomer at its fork, before it
    /// runs.  Returns false when the tracee died during the injection; it
    /// is unregistered then and must not be resumed.
    ///
    /// The descriptors are closed with an injected `close(2)` in the
    /// newcomer itself, so the guarantee holds from the fork onward: a
    /// child that reads its descriptor table before it execs finds them
    /// gone.  A `CLONE_THREAD` newcomer shares its group's table and is
    /// skipped.  A `clone(CLONE_FILES)` process without `CLONE_THREAD`
    /// shares its parent's table; closing there would also close the
    /// payload's copy, so the close is skipped and warned about, and the
    /// count marks the degradation.  A deeper descendant re-attempts the
    /// close only when its parent's close failed, so the inherited copies
    /// are closed as low as the injection reaches.  When no syscall
    /// instruction can be found the descriptor stays open, which is
    /// counted and warned about rather than hidden.
    fn close_secret_fds_at_fork(
        &mut self,
        pid: libc::pid_t,
        parent: libc::pid_t,
        depth: u32,
        is_thread: bool,
        parent_open: bool,
    ) -> bool {
        if is_thread || self.cfg.close_secret_fds_in_descendants.is_empty() {
            return true;
        }
        if depth != 1 && !parent_open {
            return true;
        }
        let fds = self.cfg.close_secret_fds_in_descendants.clone();
        if self.fault_close_fds {
            self.warn(format_args!(
                "pid {}: fault injection: the secret descriptors stay open in it and in \
                 what it starts",
                pid
            ));
            self.stats.secret_close_failed += fds.len() as u32;
            self.set_secret_fds_open(pid, true);
            return true;
        }
        if shares_fd_table(pid, parent) == Some(true) {
            self.warn(format_args!(
                "pid {}: shares its parent's descriptor table (clone(CLONE_FILES)); \
                 the secret descriptors stay open in it and in the process it shares \
                 them with",
                pid
            ));
            self.stats.secret_close_failed += fds.len() as u32;
            self.set_secret_fds_open(pid, true);
            return true;
        }
        let Some(orig) = Regs::get(pid).ok() else {
            self.warn(format_args!(
                "pid {}: registers unreadable; the secret descriptors stay open in it \
                 and in what it starts",
                pid
            ));
            self.stats.secret_close_failed += fds.len() as u32;
            self.set_secret_fds_open(pid, true);
            return true;
        };
        let Some(site) = crate::inject::find_syscall_site(pid, None, self.fault_no_vdso) else {
            self.warn(format_args!(
                "pid {}: no syscall instruction found; the secret descriptors stay open \
                 in it and in what it starts",
                pid
            ));
            self.stats.secret_close_failed += fds.len() as u32;
            self.set_secret_fds_open(pid, true);
            return true;
        };
        let mut pending_stop = None;
        let mut gone = false;
        let mut failed = false;
        for fd in fds {
            match crate::inject::run_remote_syscall(
                pid,
                &orig,
                arch::SYS_CLOSE,
                [fd as u64, 0, 0, 0, 0, 0],
                site,
                &mut pending_stop,
            ) {
                Ok(_) => {}
                Err(e) => {
                    if self.injection_failed(pid, "secret-fd close", &e) {
                        gone = true;
                        break;
                    }
                    self.stats.secret_close_failed += 1;
                    failed = true;
                }
            }
        }
        if gone {
            self.unregister(pid);
            return false;
        }
        self.set_secret_fds_open(pid, failed);
        // The injection left the registers at the last close's exit stop.
        if orig.put(pid).is_err() {
            vlog!(
                self,
                "pid {}: regs restore failed after the secret-fd close",
                pid
            );
        }
        vlog!(self, "pid {}: closed the secret descriptors at fork", pid);
        if let Some(sig) = pending_stop {
            // A group-stop signal that arrived inside the injection window
            // was restarted: raise it again.
            // SAFETY: plain kill(2) of a tracee.
            unsafe { libc::kill(pid, sig) };
        }
        true
    }

    fn set_secret_fds_open(&mut self, pid: libc::pid_t, open: bool) {
        if let Some(t) = self.table.get_mut(&pid) {
            t.secret_fds_open = open;
        }
    }

    /// `PTRACE_EVENT_STOP`: a group-stop, the answer to a
    /// `PTRACE_INTERRUPT`, or the initial stop of a seized tracee.
    fn on_event_stop(&mut self, pid: libc::pid_t, sig: libc::c_int) {
        let was_interrupted = self.interrupted.remove(&pid);
        if sig != libc::SIGTRAP {
            // Group-stop: keep the tracee stopped, but let SIGCONT and the
            // real parent's job control see it (PTRACE_LISTEN).
            if self.detachable(pid) {
                self.detach(pid, 0);
                return;
            }
            // SAFETY: tracee is in a seized group-stop.
            let rc = unsafe {
                libc::ptrace(
                    arch::PTRACE_LISTEN as _,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            if rc == -1 {
                self.warn(format_args!(
                    "pid {}: PTRACE_LISTEN failed: {}; resuming instead",
                    pid,
                    io::Error::last_os_error()
                ));
                self.resume_state(pid, 0);
            }
            return;
        }
        let _ = was_interrupted;
        self.resume_state(pid, 0);
    }

    fn on_ptrace_event(&mut self, pid: libc::pid_t, event: u32) {
        const PTRACE_EVENT_FORK: u32 = 1;
        const PTRACE_EVENT_VFORK: u32 = 2;
        const PTRACE_EVENT_CLONE: u32 = 3;
        const PTRACE_EVENT_EXEC: u32 = 4;

        match event {
            PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK | PTRACE_EVENT_CLONE => {
                let cpid = self.event_msg(pid) as libc::pid_t;
                vlog!(self, "pid {} event {} -> {}", pid, event, cpid);
                if cpid > 0 {
                    let depth = self.table.get(&pid).map(|t| t.depth).unwrap_or(0);
                    self.pending_children.insert(cpid, (pid, depth));
                    if event == PTRACE_EVENT_VFORK {
                        self.vfork_children.insert(cpid);
                    }
                }
                self.resume_state(pid, 0);
            }
            PTRACE_EVENT_EXEC => {
                // For an exec by a non-leader thread the kernel resets the
                // tid to the leader's; the former tid is in the event
                // message and holds the entry-stop bookkeeping.
                let former = self.event_msg(pid) as libc::pid_t;
                if former != pid && former > 0 {
                    if let Some(t) = self.table.remove(&former) {
                        vlog!(self, "pid {}: exec by non-leader thread {}", pid, former);
                        if let Ok(mut set) = self.cfg.tree.lock() {
                            set.remove(&former);
                        }
                        self.interrupted.remove(&former);
                        self.table.insert(pid, t);
                    }
                }
                let no_redact = self.table.get(&pid).map(|t| t.no_redact).unwrap_or(false);
                if no_redact {
                    self.set_state(pid, State::Run);
                    self.resume_state(pid, 0);
                } else {
                    self.on_exec_complete(pid, false);
                }
            }
            _ => self.resume_state(pid, 0),
        }
    }

    fn event_msg(&self, pid: libc::pid_t) -> u64 {
        let mut msg: u64 = 0;
        // SAFETY: attached tracee stopped at an event stop.
        unsafe {
            libc::ptrace(
                libc::PTRACE_GETEVENTMSG,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                &mut msg as *mut u64 as *mut libc::c_void,
            )
        };
        msg
    }

    /// `PTRACE_EVENT_SECCOMP`: the children carry a filter that traps
    /// `prctl(PR_SET_NAME)` only.  The rename is redirected to the label when
    /// the label address is reachable, and refused otherwise.
    fn on_seccomp_stop(&mut self, pid: libc::pid_t) {
        let mut si: SyscallInfo = unsafe { std::mem::zeroed() };
        if inject::get_syscall_info(pid, &mut si).is_ok()
            && si.entry_nr() == Some(arch::SYS_PRCTL)
            && self.cfg.watch_prctl
        {
            // SAFETY: the union holds entry-shaped data at a seccomp stop.
            let opt = unsafe { si.detail.seccomp.args[0] };
            if opt == libc::PR_SET_NAME as u64 {
                self.redirect_rename(pid, &si);
            }
        }
        self.resume_state(pid, 0);
    }

    /// Point the tracee's `prctl(PR_SET_NAME)` name argument at the label,
    /// without writing into the tracee when the label is already mapped
    /// there.
    ///
    /// The preferred target is the comm label the completion stop left in
    /// this tracee's presentation block (`Tracee::rename_addr`).  It is a
    /// constant of the session that is already in the tracee's address
    /// space, so pointing at it needs no `process_vm_writev` and no
    /// `PTRACE_POKEDATA`.  That matters under `--no-dumpable`: a
    /// non-dumpable tracee refuses both writes to a non-root tracer, and
    /// the old write-only redirect therefore let the payload's rename
    /// through, leaving `comm` disagreeing with `cmdline` (issue 60).
    ///
    /// Three outcomes, in order:
    ///
    /// 1. the recorded block address holds the label — point at it;
    /// 2. no usable block (this exec was not redacted, or the block is
    ///    gone) — write a fresh copy below the stack pointer and point at
    ///    that, which is what the previous code always did;
    /// 3. neither is available — point at an unmapped address, so the
    ///    kernel refuses the rename with `EFAULT` and `comm` keeps the
    ///    label.  The promise holds, and the session summary counts the
    ///    refusal.  The payload's own name pointer is never left in place.
    fn redirect_rename(&mut self, pid: libc::pid_t, si: &SyscallInfo) {
        let Ok(mut regs) = Regs::get(pid) else { return };
        let n = self.cfg.label_comm.len().min(15);
        let block_addr = self
            .table
            .get(&pid)
            .map(|t| t.rename_addr)
            .filter(|a| *a != 0);
        let target = match block_addr {
            Some(a) if self.block_holds_label(pid, a, n) => a,
            _ => {
                let mut buf = [0u8; 16];
                buf[..n].copy_from_slice(&self.cfg.label_comm[..n]);
                let addr = (si.stack_pointer.wrapping_sub(512)) & !15u64;
                if crate::remote::write_mem(pid, addr, &buf) == buf.len() as isize {
                    addr
                } else {
                    // Fail closed: address 1 is never mapped, so
                    // `PR_SET_NAME` returns `EFAULT` and `comm` keeps the
                    // label.  Letting the payload's own pointer through
                    // is the leak this filter exists to stop.
                    self.stats.rename_refused += 1;
                    self.warn(format_args!(
                        "pid {}: cannot redirect a rename to the label; the rename is refused \
                         so comm keeps the label",
                        pid
                    ));
                    1
                }
            }
        };
        regs.set_arg(2, target);
        if regs.put(pid).is_ok() {
            vlog!(self, "pid {}: rename redirected to {:#x}", pid, target);
        }
    }

    /// Does the tracee's memory at `addr` still start with the comm label?
    ///
    /// A failed read answers "no", and the caller falls through to the
    /// write path.  That is deliberate: a tracee the tracer cannot read is
    /// one the payload may have rewritten, and pointing `PR_SET_NAME` at
    /// memory the payload controls would let it choose its own `comm` —
    /// the exact leak this filter exists to stop.  Under `--no-dumpable`
    /// both the read and the write are refused, so the rename is refused
    /// with `EFAULT` instead: the label wins, and the session counts it.
    fn block_holds_label(&self, pid: libc::pid_t, addr: u64, n: usize) -> bool {
        if n == 0 {
            return true;
        }
        let mut buf = [0u8; 16];
        let want = n.min(buf.len());
        if crate::remote::read_mem(pid, addr, &mut buf[..want]) != want as isize {
            return false;
        }
        buf[..want] == self.cfg.label_comm[..want]
    }

    fn on_syscall_stop(&mut self, pid: libc::pid_t) {
        let mut si: SyscallInfo = unsafe { std::mem::zeroed() };
        if inject::get_syscall_info(pid, &mut si).is_err() {
            self.resume_state(pid, 0);
            return;
        }

        // Entry-shaped stops.  Only op ENTRY occurs for our own tracees
        // (the optional filter traps prctl only); op SECCOMP is accepted
        // too so a tracee already under a foreign RET_TRACE filter is
        // handled.
        if let Some(nr) = si.entry_nr() {
            let (state, no_redact) = match self.table.get(&pid) {
                Some(t) => (t.state, t.no_redact),
                None => (State::Run, false),
            };
            let class = arch::classify_exec(si.arch, nr);
            if class != ExecClass::NotExec && no_redact {
                // no redaction wanted: settle to Run and let the exec
                // proceed normally
                self.set_state(pid, State::Run);
                self.resume_state(pid, 0);
                return;
            }
            if class == ExecClass::Foreign && matches!(state, State::Run | State::Slow) {
                // The register layout and the argument ABI differ.  The
                // exec runs unswapped; the completion stop decides
                // whether the new image can be redacted.
                vlog!(
                    self,
                    "pid {}: foreign-ABI exec entry (arch {:#x}, nr {})",
                    pid,
                    si.arch,
                    nr
                );
                if let Some(t) = self.table.get_mut(&pid) {
                    t.clear_exec_state();
                    // Another ABI's exec replaces the address space; the
                    // block that held the comm label goes with it, and a
                    // stale address must not be used as a rename target.
                    t.rename_addr = 0;
                }
                self.set_state(pid, State::Script);
                self.resume(pid, 0, true);
                return;
            }
            if class == ExecClass::Native && matches!(state, State::Run | State::Slow) {
                match Regs::get(pid) {
                    Ok(regs) => self.on_exec_entry(pid, nr, &regs),
                    Err(_) => {
                        self.set_state(pid, State::Script);
                        self.resume(pid, 0, true);
                    }
                }
                return;
            }
            self.resume_state(pid, 0);
            return;
        }

        // syscall exit
        let state = self.table.get(&pid).map(|t| t.state).unwrap_or(State::Run);
        match state {
            State::Swapped | State::Script => {
                if si.exit_is_error() {
                    // exec failed: put the original inline arrays back
                    // and keep the process syscall-supervised: its first
                    // exec has not settled.
                    self.restore_orig_arrays(pid);
                    if let Some(t) = self.table.get_mut(&pid) {
                        t.clear_exec_state();
                    }
                    self.set_state(pid, State::Slow);
                    self.resume(pid, 0, true);
                } else {
                    // exec succeeded but no PTRACE_EVENT_EXEC stop
                    // arrived: do the completion here, at the exit stop.
                    // The new image is mapped and the program has not
                    // started yet.
                    self.on_exec_complete(pid, true);
                }
            }
            _ => self.resume_state(pid, 0),
        }
    }

    // ---------------------------------------------------------- resume ops --

    /// Resume a tracee in the mode its state asks for, delivering `sig`.
    /// During the detach drain a settled tracee is detached instead.
    pub(super) fn resume_state(&mut self, pid: libc::pid_t, sig: libc::c_int) {
        let slow = self
            .table
            .get(&pid)
            .map(|t| t.state == State::Slow)
            .unwrap_or(false);
        self.resume(pid, sig, slow);
    }

    /// Resume a tracee.  Every resume goes through here so a failure is
    /// reported rather than dropped: a tracee left stopped-and-forgotten
    /// wedges the whole tree.
    ///
    /// ESRCH means either "gone" or "not stopped".  A probe of
    /// `/proc/<pid>` tells them apart; a live tracee that cannot be
    /// resumed is reported.
    pub(super) fn resume(&mut self, pid: libc::pid_t, sig: libc::c_int, syscall: bool) {
        if self.detachable(pid) {
            self.detach(pid, sig);
            return;
        }
        let r = if syscall {
            inject::ptrace_syscall(pid, sig)
        } else {
            inject::ptrace_cont(pid, sig)
        };
        if let Err(e) = r {
            if e.raw_os_error() == Some(libc::ESRCH) && !proc_alive(pid) {
                return;
            }
            self.warn(format_args!("pid {}: resume failed: {}", pid, e));
        }
    }

    // ----------------------------------------------------------- options --

    fn options(&self) -> libc::c_long {
        // Fork/vfork/clone tracing is ALWAYS on, independent of
        // `follow_tree`: the tracer must know about every descendant so
        // its first exec is supervised; `follow_tree` only decides
        // whether newcomers are redacted.
        let mut o: libc::c_long = (libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACEEXEC
            | libc::PTRACE_O_TRACEEXIT
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK
            | libc::PTRACE_O_TRACECLONE) as libc::c_long;
        if self.cfg.exit_kill {
            o |= libc::PTRACE_O_EXITKILL as libc::c_long;
        }
        if self.cfg.watch_prctl {
            o |= arch::PTRACE_O_TRACESECCOMP;
        }
        o
    }
}

/// The thread group leader of `pid`, from `/proc/<pid>/status` `Tgid`.
/// `None` when the file is unreadable, which leaves the caller on the
/// conservative path (syscall supervision).
fn proc_ppid(pid: libc::pid_t) -> Option<libc::pid_t> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    let line = status.lines().find(|l| l.starts_with("PPid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn thread_group_leader(pid: libc::pid_t) -> Option<libc::pid_t> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    let line = status.lines().find(|l| l.starts_with("Tgid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// The fork depth of a newcomer.  A thread takes its group's depth; only a
/// real fork adds one to its parent's depth.  The leader's depth is the
/// group's depth when the leader is still in the table; when it is gone
/// (a zombie the session already reaped), the creating thread's depth is
/// the group's depth too, so it is used without adding one.
fn newcomer_depth(
    thread_of: Option<libc::pid_t>,
    leader_depth: Option<u32>,
    parent_depth: Option<u32>,
    parent_table_depth: Option<u32>,
) -> u32 {
    match thread_of {
        Some(_) => leader_depth
            .or(parent_depth)
            .or(parent_table_depth)
            .unwrap_or(1),
        None => parent_depth
            .or(parent_table_depth)
            .map(|d| d + 1)
            .unwrap_or(1),
    }
}

/// True when the two tasks share one file descriptor table
/// (`clone(CLONE_FILES)` without `CLONE_THREAD`).  `None` when the kernel
/// cannot answer: no `kcmp` (pre-3.5, or a filter that refuses it) or no
/// ptrace access to a non-dumpable tracee.  The caller then keeps the
/// close, and the documented limit applies.
fn shares_fd_table(pid: libc::pid_t, parent: libc::pid_t) -> Option<bool> {
    // `KCMP_FILES` from `include/uapi/linux/kcmp.h`; the libc crate does
    // not export it.
    const KCMP_FILES: libc::c_long = 2;
    // SAFETY: kcmp(2) of two tasks of this session; the tracer has ptrace
    // access to both.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_kcmp,
            pid as libc::c_long,
            parent as libc::c_long,
            KCMP_FILES,
            0 as libc::c_long,
            0 as libc::c_long,
        )
    };
    match rc {
        0 => Some(true),
        // 1 and 2 are the two orderings of "different"; 3 means "not
        // equal but ordering unavailable".
        1..=3 => Some(false),
        _ => None,
    }
}

/// True when `/proc/<pid>` exists and the task is not a zombie or dead.
fn proc_alive(pid: libc::pid_t) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) else {
        return false;
    };
    match stat.rfind(')') {
        Some(i) => !matches!(
            stat[i + 1..].trim_start().chars().next(),
            Some('Z') | Some('X') | None
        ),
        None => false,
    }
}

fn proc_exists(pid: libc::pid_t) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

/// waitpid(-1, __WALL), EINTR-safe.
fn wait_any() -> io::Result<(libc::pid_t, i32)> {
    loop {
        let mut status = 0i32;
        // SAFETY: plain waitpid with a valid status pointer.
        let w = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if w == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok((w, status));
    }
}

/// waitpid(-1, __WALL | WNOHANG): `None` when nothing is ready.  ECHILD
/// reads as "nothing left" and is returned as `None` too.
fn wait_any_nohang() -> io::Result<Option<(libc::pid_t, i32)>> {
    loop {
        let mut status = 0i32;
        // SAFETY: plain waitpid with a valid status pointer.
        let w = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
        if w == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if e.raw_os_error() == Some(libc::ECHILD) {
                return Ok(None);
            }
            return Err(e);
        }
        if w == 0 {
            return Ok(None);
        }
        return Ok(Some((w, status)));
    }
}

/// Wait for the master's initial stop (EINTR-safe, ignores other pids).
fn wait_master_stop(pid: libc::pid_t) -> io::Result<i32> {
    loop {
        let mut status = 0i32;
        // SAFETY: plain waitpid with a valid status pointer.
        let w = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if w == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok(status);
    }
}

fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Write one `--audit` row to stdout, ignoring a failed write.
///
/// The audit rows are a report, not a control channel.  `println!`
/// panics on `EPIPE` (`pmask --audit ... | head -1`), `panic = "abort"`
/// turns that into `SIGABRT`, and `PTRACE_O_EXITKILL` then kills the
/// payload the row is about.  A reader that went away must cost the
/// report and nothing else, so the write result is deliberately dropped
/// (issue 17).
fn audit_line(row: &str) {
    use std::io::Write;
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(row.as_bytes());
    let _ = lock.write_all(b"\n");
    let _ = lock.flush();
}

fn finish_status(pid: libc::pid_t, status: i32) -> ExitState {
    let _ = pid;
    if libc::WIFEXITED(status) {
        ExitState::plain(libc::WEXITSTATUS(status), None)
    } else if libc::WIFSIGNALED(status) {
        ExitState::plain(128 + libc::WTERMSIG(status), Some(libc::WTERMSIG(status)))
    } else {
        ExitState::plain(255, None)
    }
}

/// Injectable errors that are recoverable mid-session are mapped here so
/// callers can treat `InjectError::TraceeDied` uniformly.
impl Tracer {
    pub fn injection_failed(&self, pid: libc::pid_t, what: &str, e: &InjectError) -> bool {
        // returns true if the tracee died (fatal for that tracee)
        match e {
            InjectError::TraceeDied => {
                vlog!(self, "pid {}: tracee died during {} injection", pid, what);
                true
            }
            InjectError::Io(err) => {
                vlog!(self, "pid {}: {} injection failed: {}", pid, what, err);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thread_takes_its_groups_depth_and_a_fork_adds_one() {
        // The master's thread: group depth 0, no fork step.
        assert_eq!(newcomer_depth(Some(1), Some(0), Some(0), Some(0)), 0);
        // A thread of a depth-1 child.
        assert_eq!(newcomer_depth(Some(1), Some(1), Some(1), Some(1)), 1);
        // The leader was reaped: the creating thread's depth is the
        // group's depth, and the old fallback added one (R1-2).
        assert_eq!(newcomer_depth(Some(1), None, Some(0), Some(0)), 0);
        assert_eq!(newcomer_depth(Some(1), None, Some(2), Some(2)), 2);
        // A real fork adds one to its parent's depth.
        assert_eq!(newcomer_depth(None, None, Some(0), Some(0)), 1);
        assert_eq!(newcomer_depth(None, None, Some(2), Some(2)), 3);
        // The table fallback is the parent's depth, plus one only for a
        // fork.
        assert_eq!(newcomer_depth(None, None, None, Some(2)), 3);
        assert_eq!(newcomer_depth(Some(1), None, None, Some(2)), 2);
        // Unknown newcomer: the conservative depth the old code used.
        assert_eq!(newcomer_depth(None, None, None, None), 1);
        assert_eq!(newcomer_depth(Some(1), None, None, None), 1);
    }
}
