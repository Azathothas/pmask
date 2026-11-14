//! `pmask`: redact the command line, environment and process name of
//! an entire Linux process tree in `/proc`, while every program keeps
//! its real arguments and works completely normally.
//!
//! # The problem
//!
//! Everything on a command line is world-readable through
//! `/proc/<pid>/cmdline` while a process runs — and long-lived processes
//! publish their arguments for their whole lifetime.  That makes argv a
//! recognized secrets-hygiene hazard: API tokens and passwords passed as
//! arguments (`vault kv get -token=…`, `mysql -p…`, `curl -H
//! 'Authorization: …'`, CI deploy scripts) are visible to every local
//! account that can run `ps`, and routinely end up in monitoring stacks,
//! bug reports and terminal recordings.
//!
//! # What this crate does
//!
//! [`Mask`] runs a program (plus *every* process it ever spawns —
//! children, grandchildren, double-forking daemons, threads,
//! `posix_spawn`/`system()`/`vfork`, static binaries, scripts) with a
//! presentation label in place of its real command line, environment
//! and `comm`, as seen through `/proc`.  The programs themselves still
//! receive their real `argv`/`envp` — they work completely normally.
//!
//! ```no_run
//! use pmask::Mask;
//!
//! // every local user watching `ps` sees "ci-runner", not the token
//! let st = Mask::new()
//!     .label("ci-runner")
//!     .run("/usr/bin/deploy", &["--token", "ghp_SECRET"])?;
//! println!("exit: {}", st.code);
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! Redaction happens at `execve`/`execveat` system call entry (each
//! process is syscall-supervised until its first exec settles): the
//! kernel never copies the real command line into the new image of an
//! ELF target.  The real arguments are then re-injected
//! into an anonymous mapping injected inside the tracee, where the
//! program's own libc finds them — `argc`, the stack layout and the
//! auxiliary vector are untouched.
//!
//! # Scope and honest limits
//!
//! * Nothing can hide *that* a pid exists from root on the host; this
//!   crate redacts *what* that pid is (cmdline, environ, comm).
//! * `cmdline` and `comm` carry no ptrace check: every local account sees
//!   the label.  `environ`, `exe`, `maps`, `fd/*` and `cwd` need
//!   `PTRACE_MODE_READ_FSCREDS`, which a process of the same uid and root
//!   pass; `Mask::no_dumpable` closes that gap for same-uid observers.
//! * The forked child still holds the parent's argv bytes in its old
//!   image from the fork until the exec entry stop.  The kernel never
//!   copies them into the new image.
//! * `#!` scripts and the second and later execs of one process take the
//!   post-exec path: the kernel copies the real interpreter command line
//!   (including the script's arguments) and, unless `--keep-env`, the
//!   environment, and the tracer zeroes them at the completion stop, which
//!   bounds the window; `tests/compare.sh` prints its duration, the
//!   `SCRIPT-WINDOW` row.
//! * 32-bit programs are not redacted.  The tracer prints a warning and
//!   counts them in the session summary.
//! * Set-uid/set-gid binaries do not gain privileges under supervision
//!   (a general ptrace property); `sudo` under a mask will not elevate.
//! * This is process-metadata hygiene, the same class of dual-use
//!   facility as `memfd_create` (anonymous memory) or filesystem
//!   permissions: it reduces what /proc discloses about your commands
//!   to other local accounts.  It provides no persistence, no
//!   privilege escalation and no way to conceal a pid.
//!
//! # Session contract
//!
//! Like any ptrace supervisor, a session owns the calling process's
//! `waitpid(-1)` domain while it runs.  Sessions are serialized
//! internally; see [`mask`](self) module docs.
//!
//! # Session summary
//!
//! A session prints `pmask: N of M execs degraded (reasons)` to
//! stderr when any exec ran with less than the full entry-swap
//! redaction, unless the mask is [`quiet`](Mask::quiet).  Every entry in
//! the reason list is a degradation, not a disclosure: `script` and
//! `reexec` were redacted after the exec, `comm-not-set` skipped only the
//! process name, and `unredacted` is the one entry that means the real
//! strings may have been visible.  The same counts are in
//! [`ExitState::stats`].
//!
//! # Kernel requirements
//!
//! Linux >= 5.3 (`PTRACE_GET_SYSCALL_INFO`), x86-64 or aarch64.

#[cfg(not(target_os = "linux"))]
compile_error!("pmask requires Linux (ptrace and process_vm_readv)");

// crate-wide logging macros (call the tracer's methods)
macro_rules! vlog {
    ($tr:expr, $($arg:tt)*) => {
        $tr.vlog(format_args!($($arg)*))
    };
}

pub mod agent;
mod arch;
pub mod caps;
pub mod crypto;
pub mod daemon;
mod execimg;
mod inject;
pub mod isolate;
pub mod mask;
pub mod mem;
pub mod presetmm;
mod remote;
mod rexec;
pub mod run;
mod scope;
mod seccomp;
pub mod secret;
mod selfmask;
pub mod store;
pub mod subcmd;
#[doc(hidden)]
pub mod testhooks;
mod tracer;
mod userns;

/// The namespace set a session asks the child to enter.
///
/// Re-exported because [`Mask::namespaces`] takes it: without this the
/// method is unusable from another crate, since the type would be
/// private.  The fields are the four requests the fork helper reads.
pub use userns::ChildNs;

pub use arch::arch_name;
pub use mask::{Mask, MaskedChild};
pub use remote::MAX_HIDDEN;
pub use selfmask::mask_self;
pub use tracer::{ExitState, SessionEnd, SessionStats, TreeRegistry};

/// Crate version, as reported by the CLI.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The commit the binary was built from, or `unknown`.
pub const COMMIT: &str = env!("PMASK_BUILD_COMMIT");

/// Kernel `comm` limit (15 bytes + NUL).
pub const COMM_MAX: usize = 15;
