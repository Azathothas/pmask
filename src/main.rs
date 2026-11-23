//! `pmask` CLI: thin wrapper over the library session API, single-process
//! masking engine, audit/explain tools, and client for a running `pmaskd`.

use pmask::audit::{AuditOptions, Profile};
use pmask::isolate::Isolate;
use pmask::single::{exec_single_with, is_ptrace_refused, SingleOptions};
use pmask::{ExitState, RexecMode};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::FromRawFd;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

mod cli;

extern "C" fn ignore_sigpipe(_: libc::c_int) {}

/// Format a non-negative integer as ASCII decimal into `dst`, returning the
/// number of bytes written.  Async-signal-safe (no heap allocation).
fn fmt_u32_buf(mut n: u32, dst: &mut [u8]) -> usize {
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    if n == 0 {
        tmp[0] = b'0';
        len = 1;
    } else {
        while n > 0 && len < tmp.len() {
            tmp[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
    }
    let out = len.min(dst.len());
    for i in 0..out {
        dst[i] = tmp[len - 1 - i];
    }
    out
}

/// Parse `ppid` (field 4) from a `/proc/<pid>/stat` slice without allocation.
fn parse_stat_ppid(buf: &[u8]) -> Option<libc::pid_t> {
    let rparen = buf.iter().rposition(|&b| b == b')')?;
    let mut i = rparen + 1;
    while i < buf.len() && buf[i] == b' ' {
        i += 1;
    }
    // Skip state token (e.g. 'S', 'R', 't').
    while i < buf.len() && buf[i] != b' ' {
        i += 1;
    }
    while i < buf.len() && buf[i] == b' ' {
        i += 1;
    }
    let start = i;
    let mut val: i32 = 0;
    while i < buf.len() && buf[i].is_ascii_digit() {
        val = val.checked_mul(10)?.checked_add((buf[i] - b'0') as i32)?;
        i += 1;
    }
    if i == start {
        None
    } else {
        Some(val)
    }
}

/// Parse an ASCII decimal PID from `bytes`, returning `None` if empty or non-digit.
fn parse_pid_bytes(bytes: &[u8]) -> Option<libc::pid_t> {
    if bytes.is_empty() {
        return None;
    }
    let mut val: i32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((b - b'0') as i32)?;
    }
    if val > 0 {
        Some(val)
    } else {
        None
    }
}

/// Find the direct child PID of this single-threaded supervisor using only
/// async-signal-safe syscalls and stack buffers.
fn find_direct_child_async_safe() -> libc::pid_t {
    // SAFETY: `getpid` is async-signal-safe.
    let my_pid = unsafe { libc::getpid() };
    if my_pid <= 0 {
        return 0;
    }

    // Fast path: `/proc/self/task/<pid>/children` when `CONFIG_PROC_CHILDREN`
    // is enabled in the kernel.
    let mut path = [0u8; 64];
    let prefix = b"/proc/self/task/";
    let suffix = b"/children\0";
    let mut off = 0usize;
    path[..prefix.len()].copy_from_slice(prefix);
    off += prefix.len();
    off += fmt_u32_buf(my_pid as u32, &mut path[off..]);
    path[off..off + suffix.len()].copy_from_slice(suffix);

    // SAFETY: NUL-terminated stack path; raw open/read/close are async-signal-safe.
    let cfd = unsafe {
        libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if cfd >= 0 {
        let mut cbuf = [0u8; 64];
        let n = unsafe { libc::read(cfd, cbuf.as_mut_ptr() as *mut libc::c_void, cbuf.len()) };
        unsafe { libc::close(cfd) };
        if n > 0 {
            let slice = &cbuf[..n as usize];
            let mut s = 0;
            while s < slice.len() && (slice[s] == b' ' || slice[s] == b'\n') {
                s += 1;
            }
            let mut e = s;
            while e < slice.len() && slice[e].is_ascii_digit() {
                e += 1;
            }
            if let Some(child) = parse_pid_bytes(&slice[s..e]) {
                return child;
            }
        }
        return 0;
    }

    // Fallback for kernels without `CONFIG_PROC_CHILDREN` (e.g. WSL2):
    // scan `/proc` with raw `SYS_getdents64` on a stack buffer.
    // SAFETY: static NUL-terminated path; raw open/getdents64/read/close are async-signal-safe.
    let pfd = unsafe {
        libc::open(
            c"/proc".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if pfd < 0 {
        return 0;
    }
    let mut dbuf = [0u8; 4096];
    let mut found: libc::pid_t = 0;
    loop {
        // SAFETY: stack buffer passed to `SYS_getdents64`.
        let n = unsafe { libc::syscall(libc::SYS_getdents64, pfd, dbuf.as_mut_ptr(), dbuf.len()) };
        if n <= 0 {
            break;
        }
        let mut pos = 0usize;
        let limit = n as usize;
        while pos + 19 < limit {
            let reclen = u16::from_ne_bytes([dbuf[pos + 16], dbuf[pos + 17]]) as usize;
            if reclen == 0 || pos + reclen > limit {
                break;
            }
            let name_start = pos + 19;
            let name_end = dbuf[name_start..pos + reclen]
                .iter()
                .position(|&b| b == 0)
                .map(|i| name_start + i)
                .unwrap_or(pos + reclen);
            let name = &dbuf[name_start..name_end];
            if let Some(pid) = parse_pid_bytes(name) {
                if pid != my_pid {
                    let mut spath = [0u8; 48];
                    let pfx = b"/proc/";
                    let sfx = b"/stat\0";
                    if pfx.len() + name.len() + sfx.len() <= spath.len() {
                        spath[..pfx.len()].copy_from_slice(pfx);
                        spath[pfx.len()..pfx.len() + name.len()].copy_from_slice(name);
                        spath[pfx.len() + name.len()..pfx.len() + name.len() + sfx.len()]
                            .copy_from_slice(sfx);
                        // SAFETY: NUL-terminated stack path.
                        let sfd = unsafe {
                            libc::open(
                                spath.as_ptr() as *const libc::c_char,
                                libc::O_RDONLY | libc::O_CLOEXEC,
                            )
                        };
                        if sfd >= 0 {
                            let mut sbuf = [0u8; 256];
                            let sn = unsafe {
                                libc::read(sfd, sbuf.as_mut_ptr() as *mut libc::c_void, sbuf.len())
                            };
                            unsafe { libc::close(sfd) };
                            if sn > 0 && parse_stat_ppid(&sbuf[..sn as usize]) == Some(my_pid) {
                                found = pid;
                                break;
                            }
                        }
                    }
                }
            }
            pos += reclen;
        }
        if found > 0 {
            break;
        }
    }
    // SAFETY: closing our own directory descriptor.
    unsafe { libc::close(pfd) };
    found
}

extern "C" fn proxy_signal(sig: libc::c_int) {
    let pid = find_direct_child_async_safe();
    if pid > 0 {
        // SAFETY: `kill(2)` is async-signal-safe.
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

fn install_signal_handlers() {
    const PROXIED: [libc::c_int; 7] = [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGWINCH,
    ];
    // SAFETY: installing async-signal-safe `proxy_signal` with `SA_RESTART`
    // and a no-op handler for `SIGPIPE`.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = proxy_signal as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        for s in PROXIED {
            libc::sigaction(s, &sa, std::ptr::null_mut());
        }
        libc::signal(libc::SIGPIPE, ignore_sigpipe as *const () as usize);
    }
}

/// Exit the way the supervised program did.
fn finish(st: ExitState) -> ! {
    if let Some(sig) = st.signal {
        // SAFETY: restoring default disposition and re-raising the fatal signal.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
    std::process::exit(st.code);
}

/// Print the warning for mask options that a daemon job ignores.
fn warn_daemon_options(opts: &[&'static str], quiet: bool) {
    if opts.is_empty() || quiet {
        return;
    }
    eprintln!(
        "pmask: warning: {} ignored with --daemon (the daemon owns the masking policy)",
        opts.join(", ")
    );
}

/// The secret names whose source puts the value where `/proc` shows it.
fn plain_sight_secrets(cli: &cli::Cli) -> Vec<(&str, &str)> {
    cli.secrets
        .iter()
        .filter(|(_, src)| src.is_in_plain_sight())
        .map(|(name, src)| {
            (
                name.as_str(),
                match src {
                    pmask::secret::Source::Literal(_) => "literal:",
                    pmask::secret::Source::Env(_) => "env:",
                    _ => "a plain-sight source",
                },
            )
        })
        .collect()
}

/// `PMASK_NO_SELFMASK` is a documented debugging escape: it leaves this
/// process's own argv, environment and `comm` readable.
fn check_no_selfmask(cli: &cli::Cli, no_selfmask: bool) {
    if !no_selfmask {
        return;
    }
    let exposed = plain_sight_secrets(cli);
    if exposed.is_empty() {
        return;
    }
    let named: Vec<String> = exposed
        .iter()
        .map(|(name, kind)| format!("'{}' ({})", name, kind))
        .collect();
    let list = named.join(", ");
    let generic_shown = !cli.quiet && cli.daemon.is_none();
    let advice = if generic_shown {
        ""
    } else {
        "; keep the command out of the supervisor's argv with --args-from-fd, or use \
         file:PATH or agent:NAME"
    };
    let mut runner = pmask::run::Runner::new();
    if cli.no_redact {
        runner = runner.no_redaction();
    }
    if let Some(iso) = cli.isolate {
        runner = runner.isolate(iso);
    }
    let mode = runner.mode();
    if mode != pmask::run::Mode::Plain {
        eprintln!(
            "pmask: warning: PMASK_NO_SELFMASK=1 is overridden in {} mode: the supervisor masks \
             its own /proc entry after the fork, so secret {} is readable in its argv or \
             environment only until then, not for the whole run{}",
            mode.as_str(),
            list,
            advice
        );
        return;
    }
    if !cli.allow_argv_secret && pmask::caps::kernel_audit_reachable() {
        eprintln!(
            "pmask: PMASK_NO_SELFMASK=1 with secret {} leaves the value in this process's own \
             argv or environment for the whole run ({} mode does not mask it), and this host's \
             audit subsystem is reachable, so the supervisor's exec is also written to the audit \
             log; drop PMASK_NO_SELFMASK, use file:PATH or agent:NAME, or pass \
             --allow-argv-secret to run anyway",
            list,
            mode.as_str()
        );
        std::process::exit(255);
    }
    eprintln!(
        "pmask: warning: PMASK_NO_SELFMASK=1 leaves this process's own /proc entry readable for \
         the whole run in {} mode, so secret {} is in its argv or environment the entire time; \
         every local account can read it{}",
        mode.as_str(),
        list,
        advice
    );
}

/// Warn when `--keep-env` publishes an `env:` secret source.
fn warn_keep_env_secret(cli: &cli::Cli) {
    if !cli.keep_env_all && cli.keep_env_names.is_empty() {
        return;
    }
    let exposes: Vec<String> = {
        let mut v = Vec::new();
        for (name, src) in &cli.secrets {
            let pmask::secret::Source::Env(var) = src else {
                continue;
            };
            let kept = cli.keep_env_all
                || cli
                    .keep_env_names
                    .iter()
                    .any(|n| n.as_bytes() == var.as_bytes());
            if kept {
                v.push(format!("'{}' (env:{})", name, var));
            }
        }
        v
    };
    if exposes.is_empty() {
        return;
    }
    let scope = if cli.keep_env_all {
        "the whole inherited environment".to_string()
    } else {
        cli.keep_env_names.join(",")
    };
    eprintln!(
        "pmask: warning: --keep-env publishes /proc/<pid>/environ, and secret {} takes its value \
         from a variable this run keeps visible, so the value is readable there for the whole run \
         ({} stays visible); drop --keep-env, or use file:PATH or agent:NAME, which deliver over a \
         descriptor",
        exposes.join(", "),
        scope
    );
}

/// Re-exec once through `systemd-run --scope`.
fn reexec_in_scope(name: &str, reexec_argv: &[OsString], quiet: bool) {
    use std::os::unix::process::CommandExt;
    let Some(prefix) = pmask::mask::scope_wrap_command(name) else {
        if !quiet {
            eprintln!("pmask: --scope-name unavailable: systemd-run not usable, continuing");
        }
        return;
    };
    if prefix.is_empty() {
        if !quiet {
            eprintln!("pmask: --scope-name unavailable: empty systemd-run command, continuing");
        }
        return;
    }
    let me = match std::env::current_exe() {
        Ok(p) => p.into_os_string(),
        Err(_) => match std::env::args_os().next() {
            Some(a) => a,
            None => return,
        },
    };
    let mut cmd = std::process::Command::new(&prefix[0]);
    cmd.args(&prefix[1..]);
    cmd.arg(me);
    cmd.args(reexec_argv);
    let e = cmd.exec();
    if !quiet {
        eprintln!("pmask: --scope-name unavailable: {}, continuing", e);
    }
}

/// Check whether `program` resolves to a regular file beginning with `\x7fELF`.
/// Fast zero-fork check used only to decide whether profile-default `--rexec`
/// should be enabled (scripts and non-existent paths skip profile-default
/// rexec while explicit `--rexec` keeps its strict error behavior).
fn is_elf_program(program: &OsStr, env_overrides: &[(OsString, OsString)]) -> bool {
    if program.is_empty() {
        return false;
    }
    let check_path = |p: &Path| -> bool {
        let Ok(mut f) = File::open(p) else {
            return false;
        };
        let mut magic = [0u8; 4];
        f.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F']
    };
    if program.as_bytes().contains(&b'/') {
        return check_path(Path::new(program));
    }
    let path_override = env_overrides
        .iter()
        .rev()
        .find(|(k, _)| k.as_bytes() == b"PATH")
        .map(|(_, v)| v.clone());
    let path_var = path_override.or_else(|| std::env::var_os("PATH"));
    let Some(path_var) = path_var else {
        return false;
    };
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return check_path(&candidate);
        }
    }
    false
}

/// Read an optional audit/profile token from `--token-env` or `--token-fd`.
fn load_audit_token(cli: &cli::Cli) -> Option<Zeroizing<Vec<u8>>> {
    if cli.token_env.is_some() && cli.token_fd.is_some() {
        eprintln!("pmask: --token-env and --token-fd are mutually exclusive");
        std::process::exit(255);
    }
    if let Some(ref var) = cli.token_env {
        let Some(val) = std::env::var_os(var) else {
            eprintln!(
                "pmask: --token-env {}: environment variable is not set",
                var
            );
            std::process::exit(2);
        };
        std::env::remove_var(var);
        let bytes = Zeroizing::new(val.into_vec());
        return Some(bytes);
    }
    if let Some(fd) = cli.token_fd {
        // SAFETY: duplicate caller-provided fd with CLOEXEC so caller's fd stays intact.
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if dup < 0 {
            eprintln!(
                "pmask: --token-fd {}: {}",
                fd,
                std::io::Error::last_os_error()
            );
            std::process::exit(2);
        }
        // SAFETY: `dup` is owned by this `File`.
        let file = unsafe { File::from_raw_fd(dup) };
        let mut buf = Zeroizing::new(Vec::new());
        let mut limited = file.take(64 * 1024 + 1);
        if let Err(e) = limited.read_to_end(&mut buf) {
            eprintln!("pmask: --token-fd {}: {}", fd, e);
            std::process::exit(2);
        }
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }
        return Some(buf);
    }
    None
}

/// Internal hidden target for `pmask --audit` self-audit mode.
/// Reads the synthetic token from `PMASK_SECRET_FD`, keeps a live heap copy
/// so `/proc/<pid>/mem` scanning genuinely tests `PR_SET_DUMPABLE=0`, signals
/// readiness on `ready_fd`, and sleeps until terminated.
fn run_audit_target(ready_fd_arg: &OsStr) -> ! {
    let ready_fd: libc::c_int = ready_fd_arg.to_string_lossy().parse().unwrap_or(-1);

    let mut heap_token: Option<Box<[u8]>> = None;
    if let Ok(fd_str) = std::env::var("PMASK_SECRET_FD") {
        if let Ok(fd) = fd_str.parse::<libc::c_int>() {
            if fd >= 0 {
                // SAFETY: `fd` was handed to this internal child by `run_self_audit`.
                let mut f = unsafe { File::from_raw_fd(fd) };
                let mut buf = Vec::new();
                let _ = f.read_to_end(&mut buf);
                if !buf.is_empty() {
                    heap_token = Some(buf.into_boxed_slice());
                }
            }
        }
    }
    std::hint::black_box(&heap_token);

    if ready_fd >= 0 {
        let my_pid = unsafe { libc::getpid() };
        let msg = my_pid.to_ne_bytes();
        // SAFETY: writing 4 bytes to the parent's readiness socket/pipe.
        unsafe {
            let _ = libc::write(ready_fd, msg.as_ptr() as *const libc::c_void, msg.len());
            libc::close(ready_fd);
        }
    }

    // Wait for parent's SIGKILL/SIGTERM; safety alarm prevents orphaned target.
    // SAFETY: alarm(2) and pause(2) are standard POSIX syscalls.
    unsafe {
        libc::alarm(15);
        loop {
            libc::pause();
        }
    }
}

/// Generate a fresh 32-byte random synthetic token (`TOK-SELF-<hex>`).
fn generate_self_audit_token() -> Zeroizing<Vec<u8>> {
    let mut rnd = [0u8; 16];
    let got = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            rnd.as_mut_ptr() as *mut libc::c_void,
            rnd.len(),
            0 as libc::c_uint,
        )
    };
    if got != rnd.len() as libc::c_long {
        if let Ok(mut f) = File::open("/dev/urandom") {
            let _ = f.read_exact(&mut rnd);
        }
    }
    let mut out = Zeroizing::new(Vec::with_capacity(41));
    out.extend_from_slice(b"TOK-SELF-");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in rnd {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    rnd.zeroize();
    out
}

/// Receive readiness message and kernel-translated `SCM_CREDENTIALS` PID from
/// the Unix `SOCK_DGRAM` readiness socket.
fn recv_audit_target_pid(sock_fd: libc::c_int) -> std::io::Result<libc::pid_t> {
    let mut data = [0u8; 4];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let mut cbuf = [0u8; 64];
    // SAFETY: `msghdr` is POD and zero-initialized before populating pointers.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cbuf.len() as _;

    let n = loop {
        // SAFETY: valid buffers owned by this stack frame.
        let rc = unsafe { libc::recvmsg(sock_fd, &mut msg, 0) };
        if rc >= 0 {
            break rc;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(err);
    };

    // Extract kernel-translated host PID from SCM_CREDENTIALS when present.
    let mut cred_pid: Option<libc::pid_t> = None;
    // SAFETY: standard CMSG traversal over kernel-populated `msg`.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_CREDENTIALS
            {
                let mut cred: libc::ucred = std::mem::zeroed();
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    &mut cred as *mut libc::ucred as *mut u8,
                    std::mem::size_of::<libc::ucred>(),
                );
                if cred.pid > 0 {
                    cred_pid = Some(cred.pid);
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    if let Some(p) = cred_pid {
        return Ok(p);
    }
    if n == 4 {
        let p = libc::pid_t::from_ne_bytes(data);
        if p > 0 {
            return Ok(p);
        }
    }
    Err(std::io::Error::other(
        "self-audit target exited before signalling readiness",
    ))
}

/// Run `pmask --audit` self-audit mode (no `--pid`, no `COMMAND`):
/// launches a live masked child under `pmask` itself with a fresh synthetic
/// secret token held on the child's heap, audits every `/proc` surface and
/// `/proc/<pid>/mem`, cleans up, prints the report, and exits 0 (pass) or 1 (fail).
fn run_self_audit(cli: &cli::Cli) -> i32 {
    let target_profile = match cli.profile {
        Profile::Auto | Profile::Single => Profile::Single,
        Profile::Tree => Profile::Tree,
        Profile::Tee => Profile::Tee,
        Profile::Compat => Profile::Compat,
    };
    let label = cli
        .label_text
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "pmask-audit".to_string());

    if let Err(e) = pmask::audit::check_label_policy(
        Some(&label),
        cli.comm_text.as_deref(),
        cli.allow_impersonation,
    ) {
        eprintln!("pmask: {}", e);
        return 2;
    }

    let self_exe = match std::fs::read_link("/proc/self/exe") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pmask: self-audit: cannot resolve /proc/self/exe: {}", e);
            return 1;
        }
    };
    let real_exe = self_exe.to_string_lossy().into_owned();
    let real_cwd_path = std::env::current_dir().ok();
    let real_cwd = real_cwd_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    let norm_cwd = if real_cwd.as_deref() == Some("/") {
        "/tmp"
    } else {
        "/"
    };

    let mut token = generate_self_audit_token();

    // Pipe carrying the synthetic token to the masked child via `--secret-fd`.
    let mut tok_pipe = [-1 as libc::c_int; 2];
    if unsafe { libc::pipe2(tok_pipe.as_mut_ptr(), 0) } != 0 {
        eprintln!(
            "pmask: self-audit: pipe2 failed: {}",
            std::io::Error::last_os_error()
        );
        return 1;
    }
    // SAFETY: write token into pipe and close write end; read end is inherited by child.
    unsafe {
        let mut off = 0usize;
        while off < token.len() {
            let n = libc::write(
                tok_pipe[1],
                token.as_ptr().add(off) as *const libc::c_void,
                token.len() - off,
            );
            if n <= 0 {
                break;
            }
            off += n as usize;
        }
        libc::close(tok_pipe[1]);
    }
    let tok_r = tok_pipe[0];

    // Unix SOCK_DGRAM socketpair for readiness + host-namespace PID via SCM_CREDENTIALS.
    let mut ready_sv = [-1 as libc::c_int; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, ready_sv.as_mut_ptr()) } != 0 {
        unsafe { libc::close(tok_r) };
        eprintln!(
            "pmask: self-audit: socketpair failed: {}",
            std::io::Error::last_os_error()
        );
        return 1;
    }
    let (ready_p, ready_c) = (ready_sv[0], ready_sv[1]);
    let one: libc::c_int = 1;
    let timeout = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    // SAFETY: configuring our own socket `ready_p`.
    unsafe {
        libc::fcntl(ready_p, libc::F_SETFD, libc::FD_CLOEXEC);
        libc::setsockopt(
            ready_p,
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            ready_p,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::socklen_t as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut cmd = std::process::Command::new(&self_exe);
    cmd.arg("--profile").arg(target_profile.as_str());
    cmd.arg("--label").arg(&label);
    cmd.arg("--cwd").arg(norm_cwd);
    cmd.arg("--secret-fd").arg(tok_r.to_string());
    if target_profile == Profile::Single {
        // Reparent so `PPid` is init/subreaper rather than this `pmask`
        // auditor process, matching real standalone single-mode execution.
        cmd.arg("--reparent");
    }
    if let Some(mode) = cli.rexec_mode {
        let mode_word = match mode {
            RexecMode::Auto => "auto",
            RexecMode::Path => "path",
            RexecMode::Memfd => "memfd",
        };
        cmd.arg("--rexec-mode").arg(mode_word);
    }
    if cli.no_rexec {
        cmd.arg("--no-rexec");
    }
    if cli.allow_dumpable {
        cmd.arg("--allow-dumpable");
    }
    if cli.allow_impersonation {
        cmd.arg("--allow-impersonation");
    }
    cmd.arg("--")
        .arg(&self_exe)
        .arg("__audit-target")
        .arg(ready_c.to_string());
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());

    let mut sup_child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            unsafe {
                libc::close(tok_r);
                libc::close(ready_p);
                libc::close(ready_c);
            }
            eprintln!("pmask: self-audit: failed to launch target: {}", e);
            return 1;
        }
    };
    unsafe {
        libc::close(tok_r);
        libc::close(ready_c);
    }

    let target_pid = match recv_audit_target_pid(ready_p) {
        Ok(p) => p,
        Err(e) => {
            unsafe { libc::close(ready_p) };
            let _ = sup_child.kill();
            let _ = sup_child.wait();
            eprintln!("pmask: self-audit: {}", e);
            return 1;
        }
    };
    unsafe { libc::close(ready_p) };

    if target_profile == Profile::Single {
        // Reap the completed reparenting launcher so no `pmask` parent remains.
        let _ = sup_child.wait();
    }

    let mut opts = AuditOptions::new(target_pid, target_profile);
    opts.observer = cli.observer;
    opts.label = Some(label);
    opts.token = Some(token.to_vec());
    opts.real_exe = Some(real_exe);
    opts.real_cwd = real_cwd;
    opts.allow_memfd = cli.allow_memfd;

    let report_res = pmask::audit::audit_pid(&opts);

    // Clean up target and supervisor immediately after probing.
    // SAFETY: killing the temporary self-audit target we launched.
    unsafe {
        libc::kill(target_pid, libc::SIGKILL);
    }
    if target_profile != Profile::Single {
        let _ = sup_child.kill();
        let _ = sup_child.wait();
    } else {
        let proc_path = format!("/proc/{}", target_pid);
        for _ in 0..20 {
            if !Path::new(&proc_path).exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    token.zeroize();

    match report_res {
        Ok(report) => {
            if cli.json {
                print!("{}", report.to_json());
            } else {
                print!("{}", report.to_text());
            }
            if report.passed() {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("pmask: self-audit: {}", e);
            1
        }
    }
}

/// Dispatch standalone informational / audit commands (`--explain`,
/// `--profile-json`, `--audit --pid PID`, and standalone `--audit` self-audit).
fn maybe_run_standalone(cli: &cli::Cli) -> Option<i32> {
    if cli.explain {
        let label = cli
            .label_text
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("ci-runner");
        print!(
            "{}",
            pmask::audit::render_explain(cli.profile, label, cli.json)
        );
        return Some(0);
    }

    if cli.profile_json {
        if let Some(pid) = cli.pid {
            let token = load_audit_token(cli);
            let prof = match cli.profile {
                Profile::Auto => Profile::Single,
                p => p,
            };
            match pmask::audit::export_profile_for_pid(
                pid,
                prof,
                cli.label_text.as_deref(),
                token.as_deref().map(Vec::as_slice),
            ) {
                Ok(json) => {
                    print!("{}", json);
                    return Some(0);
                }
                Err(e) => {
                    eprintln!("pmask: --profile-json --pid {}: {}", pid, e);
                    return Some(1);
                }
            }
        }
        let label = cli
            .label_text
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("ci-runner");
        let prof = match cli.profile {
            Profile::Auto => Profile::Single,
            p => p,
        };
        let cmdline = vec![label.to_string()];
        let tpl_opts = pmask::audit::TemplateOptions {
            reparent: cli.reparent,
            allow_dumpable: cli.allow_dumpable,
            no_dumpable: cli.no_dumpable,
            cwd_override: cli.cwd.is_some(),
            no_rexec: cli.no_rexec,
            memfd_rexec: cli.prefers_memfd || cli.rexec_mode == Some(RexecMode::Memfd),
        };
        print!(
            "{}",
            pmask::audit::export_profile_template_with(prof, label, &cmdline, &tpl_opts)
        );
        return Some(0);
    }

    if cli.audit {
        if let Some(pid) = cli.pid {
            let token = load_audit_token(cli);
            let prof = match cli.profile {
                Profile::Auto => Profile::Single,
                p => p,
            };
            let mut opts = AuditOptions::new(pid, prof);
            opts.observer = cli.observer;
            opts.label = cli.label_text.clone();
            opts.token = token.as_deref().cloned();
            opts.real_exe = cli.real_exe.clone();
            opts.real_cwd = cli.real_cwd.clone();
            opts.allow_memfd = cli.allow_memfd;
            return match pmask::audit::audit_pid(&opts) {
                Ok(report) => {
                    if cli.json {
                        print!("{}", report.to_json());
                    } else {
                        print!("{}", report.to_text());
                    }
                    Some(if report.passed() { 0 } else { 1 })
                }
                Err(e) => {
                    eprintln!("pmask: --audit --pid {}: {}", pid, e);
                    Some(1)
                }
            };
        }
        if cli.program.is_empty() && cli.args_fd.is_none() {
            return Some(run_self_audit(cli));
        }
    }

    None
}

/// The secret side of a local run: descriptor delivery, isolation, `--profile tee`,
/// or a forced plain exec.
fn run_with_secrets(mut cli: cli::Cli) -> i32 {
    use pmask::run::{Mode, Runner};
    let mut r = Runner::new()
        .mask(cli.mask.clone())
        .requested_options(&cli.mask_opts);
    for (name, src) in &cli.secrets {
        r = r.secret(name.clone(), src.clone());
    }
    for &(_, fd) in &cli.secret_fds {
        r = r.preserve_fd(fd);
    }
    if let Some(ref dir) = cli.cwd {
        r = r.cwd(dir.clone());
    }
    for (k, v) in &cli.env_overrides {
        r = r.env(k.clone(), v.clone());
    }
    match &cli.remote_label {
        pmask::daemon::RemoteLabel::Text(t) => r = r.label(t.clone()),
        pmask::daemon::RemoteLabel::Empty => r = r.label(""),
        pmask::daemon::RemoteLabel::Default => {}
    }
    if let Some(sock) = &cli.agent_socket {
        r = r.daemon_socket(sock.clone());
    }
    match (cli.redact, cli.isolate) {
        (true, Some(iso)) => r = r.redact_with_isolate(iso),
        (_, Some(iso)) => r = r.isolate(iso),
        (_, None) => {}
    }
    if cli.no_redact {
        r = r.no_redaction();
    }
    if cli.allow_argv_secret {
        r = r.allow_argv_secret();
    }
    if cli.secret_burn {
        r = r.delivery_mode(pmask::secret::DeliveryMode::Burn);
    }
    if cli.secret_close_on_exec {
        r = r.close_on_exec();
    }
    if cli.no_dumpable || cli.hide_pid || cli.encrypt_memory {
        r = r.no_dumpable(true);
    }
    if cli.hide_pid {
        r = r.hide_pid(true);
    }
    if cli.encrypt_memory {
        r = r.encrypt_memory(true);
    }
    if cli.audit {
        r = r.audit();
    }
    if cli.quiet {
        r = r.quiet();
    }
    if cli.verbose {
        r = r.verbose();
    }
    let sink = if cli.report_json {
        ReportSink::open(cli.report_file.as_deref(), cli.report_fd)
    } else {
        None
    };
    let args = std::mem::take(&mut cli.args);
    cli.scrub_values();
    cli.mask.scrub_env_values();
    let result = r.run_owned(&cli.program, args);
    r.scrub();
    match result {
        Ok(outcome) => {
            if let Some(sink) = sink {
                sink.write(&outcome.report_json());
            }
            if !cli.quiet && !cli.report_json {
                eprintln!(
                    "pmask: mode={} secrets={} exit={}",
                    outcome.mode.as_str(),
                    outcome.secrets_delivered,
                    outcome.exit.code
                );
                for n in &outcome.notes {
                    eprintln!("pmask: note: {}", n);
                }
                if outcome.mode == Mode::Plain {
                    eprintln!(
                        "pmask: note: /proc metadata was not redacted here; \
secrets travelled over descriptors (a literal: or env: source still \
sat in pmask's own argv or environ)"
                    );
                }
            }
            if let Some(sig) = outcome.exit.signal {
                // SAFETY: restoring default handler and re-raising fatal signal.
                unsafe {
                    libc::signal(sig, libc::SIG_DFL);
                    libc::raise(sig);
                }
            }
            outcome.exit.code
        }
        Err(e) => {
            eprintln!("pmask: {}", e);
            let text = e.to_string();
            if text.starts_with("--rexec:") {
                if e.kind() == std::io::ErrorKind::NotFound {
                    127
                } else {
                    126
                }
            } else {
                255
            }
        }
    }
}

/// Where the `--report` document goes.
enum ReportSink {
    Stdout,
    File {
        file: File,
        final_path: std::path::PathBuf,
        temp_path: Option<std::path::PathBuf>,
        unnamed: bool,
    },
}

fn report_temp_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!(".pmask-report-{}-{:08x}", std::process::id(), nanos)
}

impl ReportSink {
    fn open(file: Option<&Path>, fd: Option<libc::c_int>) -> Option<ReportSink> {
        if let Some(path) = file {
            use std::os::unix::fs::OpenOptionsExt;
            use std::os::unix::io::AsRawFd;
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let temp_path = parent.join(report_temp_name());
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_TMPFILE | libc::O_CLOEXEC)
                .open(parent)
            {
                Ok(f) => {
                    return Some(ReportSink::File {
                        file: f,
                        final_path: path.to_path_buf(),
                        temp_path: Some(temp_path),
                        unnamed: true,
                    });
                }
                Err(_) => {
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&temp_path)
                    {
                        Ok(f) => {
                            let _ = f.as_raw_fd();
                            return Some(ReportSink::File {
                                file: f,
                                final_path: path.to_path_buf(),
                                temp_path: Some(temp_path),
                                unnamed: false,
                            });
                        }
                        Err(e) => {
                            eprintln!("pmask: --report-file {}: {}", path.display(), e);
                            std::process::exit(255);
                        }
                    }
                }
            }
        }
        if let Some(n) = fd {
            if n <= 2 {
                eprintln!(
                    "pmask: --report-fd {}: descriptors 0, 1 and 2 are the payload's stdin, \
                     stdout and stderr, and the report descriptor is close-on-exec, so the \
                     payload would start with that stream closed; pass a descriptor above 2",
                    n
                );
                std::process::exit(255);
            }
            // SAFETY: `dup` on a caller-provided descriptor.
            let dup = unsafe { libc::fcntl(n, libc::F_DUPFD_CLOEXEC, 3) };
            if dup < 0 {
                eprintln!(
                    "pmask: --report-fd {}: {}",
                    n,
                    std::io::Error::last_os_error()
                );
                std::process::exit(255);
            }
            // SAFETY: marking caller's report fd close-on-exec.
            unsafe { libc::fcntl(n, libc::F_SETFD, libc::FD_CLOEXEC) };
            let f = unsafe { File::from_raw_fd(dup) };
            return Some(ReportSink::File {
                file: f,
                final_path: std::path::PathBuf::new(),
                temp_path: None,
                unnamed: false,
            });
        }
        Some(ReportSink::Stdout)
    }

    fn write(mut self, text: &str) {
        use std::io::Write;
        match &mut self {
            ReportSink::Stdout => {
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(text.as_bytes());
                let _ = out.flush();
            }
            ReportSink::File {
                file,
                final_path,
                temp_path,
                unnamed,
            } => {
                let wrote = file
                    .write_all(text.as_bytes())
                    .and_then(|_| file.flush())
                    .and_then(|_| file.sync_all());
                if let Err(e) = wrote {
                    if !*unnamed {
                        if let Some(tmp) = temp_path.take() {
                            let _ = std::fs::remove_file(&tmp);
                        }
                    }
                    if final_path.as_os_str().is_empty() {
                        eprintln!("pmask: --report-fd: {}", e);
                    } else {
                        eprintln!("pmask: --report-file {}: {}", final_path.display(), e);
                    }
                    std::process::exit(255);
                }
                if let Some(tmp) = temp_path.take() {
                    let linked = if *unnamed {
                        link_tmpfile(file, &tmp)
                    } else {
                        Ok(())
                    };
                    if let Err(e) = linked.and_then(|_| std::fs::rename(&tmp, &*final_path)) {
                        let _ = std::fs::remove_file(&tmp);
                        eprintln!("pmask: --report-file {}: {}", final_path.display(), e);
                        std::process::exit(255);
                    }
                }
            }
        }
    }
}

impl Drop for ReportSink {
    fn drop(&mut self) {
        if let ReportSink::File {
            temp_path: Some(tmp),
            unnamed: false,
            ..
        } = self
        {
            let _ = std::fs::remove_file(tmp);
        }
    }
}

fn link_tmpfile(file: &File, temp: &Path) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let proc_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    let from = std::ffi::CString::new(proc_path).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in report fd path")
    })?;
    let to = std::ffi::CString::new(temp.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in report path"))?;
    // SAFETY: both paths are valid NUL-terminated C strings.
    let rc = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The reason a failed ptrace session gives, when the probe names one.
fn ptrace_refusal() -> Option<String> {
    let caps = pmask::caps::Caps::cached();
    if caps.seccomp_filter {
        return Some(
            "ptrace is banned by a seccomp filter here; command lines stay visible".to_string(),
        );
    }
    if caps.ptrace_scope.is_some_and(|scope| scope >= 3) {
        return Some(
            "the kernel refuses ptrace attaches here (kernel.yama.ptrace_scope >= 3); \
             command lines stay visible"
                .to_string(),
        );
    }
    if caps.ptrace {
        return None;
    }
    caps.rows()
        .into_iter()
        .find(|(n, _)| *n == "metadata redaction")
        .map(|(_, st)| st.reason().to_string())
}

/// Validate and wire `--secret-fd [NAME=]N` onto `cli.mask` and `cli.env_overrides`.
fn apply_secret_fds(cli: &mut cli::Cli) {
    let mut unnamed_exported = false;
    for (opt_name, fd) in cli.secret_fds.clone() {
        // SAFETY: validating that caller-passed fd is open.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            eprintln!(
                "pmask: --secret-fd {}: invalid or closed file descriptor: {}",
                fd,
                std::io::Error::last_os_error()
            );
            std::process::exit(2);
        }
        cli.mask = cli.mask.clone().secret_fd(fd);
        let fd_val = fd.to_string();
        let env_key = match opt_name {
            Some(ref name) => Some(pmask::secret::env_var_for(name)),
            None if !unnamed_exported => {
                unnamed_exported = true;
                Some("PMASK_SECRET_FD".to_string())
            }
            None => None,
        };
        if let Some(key) = env_key {
            cli.mask = cli.mask.clone().env(&key, &fd_val);
            cli.env_overrides
                .push((OsString::from(key), OsString::from(fd_val)));
        }
    }
}

/// Refuse flags that are incompatible with explicit `--profile single`.
fn check_single_profile_conflicts(cli: &cli::Cli) {
    let mut conflicts: Vec<&str> = Vec::new();
    if cli.stealth {
        conflicts.push("--stealth");
    } else if cli.mask.watch_rename_enabled() {
        conflicts.push("--watch-rename");
    }
    if cli.mask.exec_once_enabled() {
        conflicts.push("--exec-once");
    }
    if cli.hide_pid {
        conflicts.push("--hide-pid");
    }
    if cli.daemon.is_some() {
        conflicts.push("--daemon");
    }
    if cli.report_json {
        conflicts.push("--report");
    }
    if cli.secret_close_on_exec {
        conflicts.push("--secret-close-on-exec");
    }
    if cli.isolate.is_some() {
        conflicts.push("--isolate");
    }
    if cli.unshare {
        conflicts.push("--unshare");
    }
    if cli.follow_explicit {
        conflicts.push("--follow");
    }
    if cli.no_follow {
        conflicts.push("--no-follow");
    }
    if cli.parent_label.is_some() {
        conflicts.push("--parent-label");
    }
    if cli.audit {
        conflicts.push("--audit");
    }
    if cli.mask.session_end_explicit() && cli.mask.session_end_value() != pmask::SessionEnd::Detach
    {
        conflicts.push("--on-exit");
    }
    if !conflicts.is_empty() {
        eprintln!(
            "pmask: --profile single cannot be combined with {}: these features require a \
             persistent supervisor; use --profile tree instead",
            conflicts.join(", ")
        );
        std::process::exit(255);
    }
}

/// Sanitize a long presentation label into a safe <= 64-byte carrier name for
/// profile-default `--rexec` so labels longer than 200 bytes (valid for
/// `cmdline`) never fail memfd/path carrier creation.
fn safe_profile_carrier_name(label: &str) -> String {
    let mut out = String::with_capacity(64);
    for ch in label.chars() {
        if out.len() >= 64 {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        }
    }
    if out.is_empty() || out.chars().all(|c| c == '.') {
        "worker".to_string()
    } else {
        out
    }
}

/// Apply profile-default `--rexec` and `--rexec-mode` when the operator did
/// not opt out via `--no-rexec` and the target is a native ELF (or `--rexec`
/// was explicitly requested).
fn apply_profile_rexec(cli: &mut cli::Cli, default_mode: RexecMode) {
    if cli.no_rexec {
        return;
    }
    let long_label_carrier = if !cli.prefers_memfd {
        cli.label_text
            .as_deref()
            .filter(|l| l.len() > 180)
            .map(safe_profile_carrier_name)
    } else {
        None
    };
    if let Some(mode) = cli.rexec_mode {
        cli.mask = cli.mask.clone().rexec_mode(mode);
        if !cli.rexec_explicit
            && !cli.mask.has_image()
            && is_elf_program(&cli.program, &cli.env_overrides)
        {
            cli.mask = cli.mask.clone().rexec();
            if let Some(name) = long_label_carrier {
                cli.mask = cli.mask.clone().memfd_name(name);
            }
        }
        return;
    }
    if cli.rexec_explicit || cli.mask.has_image() {
        // Preserve explicit `--rexec`, `--hugetlb`, `--memfd-name`, `--image*`,
        // `--exec-once` memfd carrier unless `--rexec-mode` was explicitly set.
        if cli.prefers_memfd {
            cli.mask = cli.mask.clone().rexec_mode(RexecMode::Memfd);
        }
        return;
    }
    if is_elf_program(&cli.program, &cli.env_overrides) {
        cli.mask = cli.mask.clone().rexec().rexec_mode(default_mode);
        if let Some(name) = long_label_carrier {
            cli.mask = cli.mask.clone().memfd_name(name);
        }
    }
}

/// Run `Profile::Single` via `exec_single_with`, optionally loading `--secret`
/// specs into sealed descriptors beforehand.
fn run_single_profile(mut cli: cli::Cli) -> ! {
    // Hold any `--secret` delivery alive until `execve` replaces this process
    // (or `exec_single_with` returns in `--reparent` / error paths).
    let mut _delivery_guard = None;
    if !cli.secrets.is_empty() {
        let _ = pmask::mem::harden_self();
        let mut loaded = Vec::with_capacity(cli.secrets.len());
        let socket = cli.agent_socket.clone();
        for idx in 0..cli.secrets.len() {
            let res = {
                let (name, src) = &cli.secrets[idx];
                pmask::secret::load(name, src, socket.as_ref())
            };
            cli.secrets[idx].1.scrub();
            match res {
                Ok(s) => loaded.push(s),
                Err(e) => {
                    for (_, rest) in &mut cli.secrets[idx + 1..] {
                        rest.scrub();
                    }
                    eprintln!("pmask: {}", e);
                    std::process::exit(255);
                }
            }
        }
        let delivery_mode = if cli.secret_burn {
            pmask::secret::DeliveryMode::Burn
        } else {
            pmask::secret::DeliveryMode::Inherit
        };
        let delivery = match pmask::secret::Delivery::with_mode_named(
            &loaded,
            delivery_mode,
            cli.mask.secret_fd_name_value(),
        ) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("pmask: {}", e);
                std::process::exit(255);
            }
        };
        if let Err(e) = delivery.preflight() {
            eprintln!("pmask: {}", e);
            std::process::exit(255);
        }
        for (k, v) in delivery.env() {
            cli.mask = cli.mask.clone().env(k, v);
        }
        cli.mask = cli.mask.clone().inherit_fds_with(delivery.raw_fds(), false);
        _delivery_guard = Some(delivery);
    }

    let opts = SingleOptions::new().reparent(cli.reparent);
    match exec_single_with(&cli.mask, &cli.program, &cli.args, &opts) {
        Ok(st) => finish(st),
        Err(e) => {
            if is_ptrace_refused(&e) {
                if let Some(reason) = ptrace_refusal() {
                    eprintln!("pmask: cannot redact here: {}", reason);
                } else {
                    eprintln!("pmask: cannot redact here: {}", e);
                }
                eprintln!(
                    "pmask: this run needed ptrace; use --no-redact with --secret / --secret-fd \
                     to deliver secrets without ptrace, or run where ptrace is permitted"
                );
                std::process::exit(126);
            }
            eprintln!("pmask: {}: {}", cli.program.to_string_lossy(), e);
            let text = e.to_string();
            if e.raw_os_error() == Some(libc::ENOENT) || e.kind() == std::io::ErrorKind::NotFound {
                std::process::exit(127);
            }
            if e.raw_os_error() == Some(libc::EACCES)
                || e.raw_os_error() == Some(libc::ENOEXEC)
                || text.starts_with("--rexec:")
            {
                std::process::exit(126);
            }
            std::process::exit(255);
        }
    }
}

fn main() {
    let mut argv = pmask::mask::snapshot_argv();

    // Hidden internal target for standalone `pmask --audit` self-audit mode.
    // Checked before `zero_argv_block()` / `parse_from()` so it is never a
    // public flag and does not perturb CLI parsing.
    if argv.len() >= 3 && argv[1].as_bytes() == b"__audit-target" {
        run_audit_target(&argv[2]);
    }

    let mut original_argv = argv.clone();
    if std::env::var_os("PMASK_NO_SELFMASK").is_none() {
        let _ = pmask::mask::zero_argv_block();
    }

    // Secret-side subcommands (store, agent, get, read, probe, doctor, help, version).
    if argv.len() >= 2 && pmask::subcmd::is_subcommand(&argv[1]) {
        for a in &mut original_argv {
            cli::scrub_os_string(a);
        }
        original_argv.clear();
        std::process::exit(pmask::subcmd::dispatch(&argv, &cli::full_help_text()));
    }
    // `pmask run ...` shares the mask parser.
    if argv.len() >= 2 && argv[1].as_bytes() == b"run" {
        argv.remove(1);
        if argv.iter().any(|a| a.as_bytes() == b"--run-help") {
            print!("{}", cli::full_help_text());
            std::process::exit(0);
        }
    }
    let mut cli = cli::parse_from(argv);

    // Standalone informational / audit modes (--explain, --profile-json,
    // --audit --pid PID, standalone --audit self-audit).
    if let Some(code) = maybe_run_standalone(&cli) {
        for a in &mut original_argv {
            cli::scrub_os_string(a);
        }
        std::process::exit(code);
    }

    // Label impersonation policy check (kernel-thread bracket syntax and
    // critical system service names require `--allow-impersonation`).
    if let Err(e) = pmask::audit::check_label_policy(
        cli.label_text.as_deref(),
        cli.comm_text.as_deref(),
        cli.allow_impersonation,
    ) {
        eprintln!("pmask: {}", e);
        std::process::exit(2);
    }
    if let Some(ref pl) = cli.parent_label {
        if let Err(e) = pmask::audit::check_label_policy(Some(pl), None, cli.allow_impersonation) {
            eprintln!("pmask: {}", e);
            std::process::exit(2);
        }
    }

    if cli.redact && cli.no_redact {
        eprintln!("pmask: --redact and --no-redact contradict each other; pass one");
        std::process::exit(255);
    }

    // `--daemon` hands the job to a pmaskd, which owns the masking policy
    // and builds the job environment itself.
    if cli.daemon.is_some() {
        let mut local_only: Vec<&str> = Vec::new();
        if !cli.secrets.is_empty() {
            local_only.push("--secret");
        }
        if !cli.secret_fds.is_empty() {
            local_only.push("--secret-fd");
        }
        if cli.isolate.is_some() {
            local_only.push("--isolate");
        }
        if cli.no_redact {
            local_only.push("--no-redact");
        }
        if cli.hide_pid {
            local_only.push("--hide-pid");
        }
        if cli.encrypt_memory {
            local_only.push("--encrypt-memory");
        }
        if cli.mask.has_image() {
            local_only.push("--image or --image-from-fd");
        }
        if cli.profile_explicit && matches!(cli.profile, Profile::Single | Profile::Tee) {
            local_only.push(if cli.profile == Profile::Single {
                "--profile single"
            } else {
                "--profile tee"
            });
        }
        if !local_only.is_empty() {
            eprintln!(
                "pmask: --daemon cannot be combined with {}: the daemon owns the masking \
                 policy and the job environment, so this flag would be dropped; run the job \
                 without --daemon",
                local_only.join(", ")
            );
            std::process::exit(255);
        }
    }

    let audit_refused = cli.audit
        && (cli.no_redact
            || (cli.isolate.is_some() && !cli.redact && !cli.isolate.is_some_and(|iso| iso.none)));
    if audit_refused {
        eprintln!(
            "pmask: --audit needs the redaction mode; {} mode has no tracer to \
             describe the tree, so drop --audit or the flag that forces the mode",
            if cli.isolate.is_some() {
                "isolate"
            } else {
                "plain"
            }
        );
        std::process::exit(255);
    }

    if cli.report_json && cli.daemon.is_some() {
        let which = if cli.report_file.is_some() {
            "--report-file"
        } else if cli.report_fd.is_some() {
            "--report-fd"
        } else {
            "--report=json"
        };
        eprintln!(
            "pmask: {}: a --daemon job does not produce a report; the daemon owns the run, \
             so drop the report option or run the job without --daemon",
            which
        );
        std::process::exit(255);
    }

    if cli.daemon.is_none() {
        if let Some(name) = cli.scope_name.clone() {
            reexec_in_scope(&name, &cli.reexec_argv, cli.quiet);
        }
    }

    let no_selfmask = std::env::var_os("PMASK_NO_SELFMASK").is_some();
    check_no_selfmask(&cli, no_selfmask);
    if no_selfmask {
        cli.mask = cli.mask.clone().supervisor_non_dumpable(true);
    }
    warn_keep_env_secret(&cli);

    cli.load_args_fd();

    // Validate and wire `--secret-fd` descriptors before selecting execution mode.
    if !cli.secret_fds.is_empty() {
        apply_secret_fds(&mut cli);
    }

    // Resolve effective execution profile (`single`, `tree`, `tee`, `compat`)
    // before probing ptrace so the fast `single` path skips `ptrace_usable_fast`
    // and lets its transient helper `G` try `PTRACE_SEIZE` directly.
    let needs_tree = cli.follow_explicit
        || cli.no_follow
        || cli.mask.watch_rename_enabled()
        || cli.mask.exec_once_enabled()
        || (cli.mask.session_end_explicit()
            && cli.mask.session_end_value() != pmask::SessionEnd::Detach)
        || cli.hide_pid
        || cli.report_json
        || cli.secret_close_on_exec
        || cli.daemon.is_some()
        || cli.unshare
        || cli.isolate.is_some()
        || cli.stealth
        || cli.audit
        || cli.mask.has_image()
        || cli.parent_label.is_some()
        || cli.detach
        || cli.no_redact;

    let effective_profile = match cli.profile {
        Profile::Auto => {
            if cli.no_redact {
                Profile::Compat
            } else {
                pmask::audit::select_auto_profile(&cli.program, needs_tree)
            }
        }
        explicit => explicit,
    };

    let single_fast_path = effective_profile == Profile::Single
        && cli.daemon.is_none()
        && !cli.no_redact
        && cli.isolate.is_none()
        && !cli.report_json
        && !cli.hide_pid;

    // Zero-fork fast ptrace check only when not taking the `single` fast path
    // (where `G` probes `PTRACE_SEIZE` directly without any `PTRACE_TRACEME` fork).
    let ptrace_ok = if single_fast_path {
        true
    } else {
        pmask::caps::Caps::ptrace_usable_fast()
    };
    let plain_mode = cli.no_redact || !ptrace_ok;
    if plain_mode
        && std::env::var_os("PMASK_NO_SELFMASK").is_none()
        && plain_sight_secrets(&cli).is_empty()
    {
        let _ = pmask::restore_own_argv(&original_argv);
    }
    for a in &mut original_argv {
        cli::scrub_os_string(a);
    }
    original_argv.clear();

    if cli.mask.exec_once_enabled()
        && (cli.no_dumpable
            || cli.hide_pid
            || !cli.mask.payload_is_dumpable()
            || (!cli.secrets.is_empty() && !cli.allow_dumpable))
    {
        eprintln!(
            "pmask: --exec-once needs a dumpable tracee at its later exec's entry stop; \
             --no-dumpable, --hide-pid and --stealth (on a non-hidepid host) make that write \
             fail, so the cached carrier could not be used.  Drop one flag, or use --rexec \
             without --exec-once."
        );
        std::process::exit(255);
    }

    // Enforce profile-specific refusals.
    if cli.profile == Profile::Single {
        check_single_profile_conflicts(&cli);
    }
    if cli.reparent && effective_profile != Profile::Single {
        eprintln!(
            "pmask: --reparent is only supported with --profile single (resolved profile is {})",
            effective_profile.as_str()
        );
        std::process::exit(255);
    }
    if effective_profile == Profile::Tee {
        if cli.no_redact {
            eprintln!("pmask: --profile tee cannot be combined with --no-redact");
            std::process::exit(255);
        }
        if cli.isolate.is_some_and(|i| i.none) {
            eprintln!("pmask: --profile tee cannot be combined with --isolate=none");
            std::process::exit(255);
        }
        // `tee` is not on the hot path; probe userns explicitly and fail closed.
        if !pmask::caps::Caps::detect().userns {
            eprintln!(
                "pmask: --profile tee requires unprivileged user namespaces, and this host \
                 refuses them; run where userns is permitted, or use --profile single / tree"
            );
            std::process::exit(255);
        }
        cli.redact = true;
        if cli.isolate.is_none() {
            cli.isolate = Some(Isolate::new(true, false, true));
        }
    }

    // Apply profile defaults for `no_dumpable`, `encrypt_memory`, and `rexec`.
    let profile_defaults_nodumpable = matches!(
        effective_profile,
        Profile::Single | Profile::Tree | Profile::Tee
    );
    match effective_profile {
        Profile::Single => {
            if !cli.allow_dumpable {
                cli.mask = cli.mask.no_dumpable().supervisor_non_dumpable(true);
            }
            // In `single`, the transient helper `G` is non-dumpable, wipes its
            // buffers right after `PTRACE_DETACH`, and exits before payload
            // `main()` runs (~500us).  Do not force `SessionKey::generate()`
            // (`memfd_secret` + `mlock` + AEAD) unless `--encrypt-memory` was
            // explicitly passed; the redaction block still receives
            // `MADV_DONTDUMP` via `no_dumpable`.
            apply_profile_rexec(&mut cli, RexecMode::Auto);
        }
        Profile::Tree => {
            let hidepid_blocks =
                cli.stealth && pmask::caps::Caps::proc_hidepid_fast().hides_non_dumpable();
            if !cli.allow_dumpable && !cli.mask.exec_once_enabled() && !hidepid_blocks {
                cli.mask = cli.mask.no_dumpable().supervisor_non_dumpable(true);
            }
            cli.mask = cli.mask.encrypt_memory(true);
            if !cli.no_follow {
                cli.mask = cli.mask.follow_tree(true);
            }
            apply_profile_rexec(&mut cli, RexecMode::Auto);
        }
        Profile::Tee => {
            if !cli.allow_dumpable && !cli.mask.exec_once_enabled() {
                cli.mask = cli.mask.no_dumpable().supervisor_non_dumpable(true);
                cli.no_dumpable = true;
            }
            // Linux `cap_capable()` grants the userns creator uid `CAP_SYS_PTRACE`
            // over the child userns, leaving `/proc/<pid>/cwd` readable to same-uid
            // host observers even with `PR_SET_DUMPABLE=0`.  Normalize `cwd` to `/`
            // by default (after executable resolution / rexec staging) so `tee`
            // never leaks the caller's working directory unless `--cwd` overrides it.
            if cli.cwd.is_none() {
                let norm = std::path::PathBuf::from("/");
                cli.mask = cli.mask.cwd(&norm);
                cli.cwd = Some(norm);
            }
            cli.mask = cli.mask.encrypt_memory(true);
            apply_profile_rexec(&mut cli, RexecMode::Auto);
        }
        Profile::Compat | Profile::Auto => {
            // Preserve exact v0.1.0 defaults (`follow_tree=true`, `dumpable=1`,
            // no forced `rexec`, no forced `encrypt_memory`).
            if let Some(mode) = cli.rexec_mode {
                cli.mask = cli.mask.rexec_mode(mode);
            }
        }
    }

    // Delivered `--secret` or `--secret-fd` requires non-dumpable payload
    // unless `--allow-dumpable` was passed.  Stay quiet when the active
    // profile already enables `no_dumpable` by default.
    let has_any_secret = !cli.secrets.is_empty() || !cli.secret_fds.is_empty();
    if has_any_secret && !cli.allow_dumpable && !cli.no_dumpable {
        let no_tracer = plain_mode || (cli.isolate.is_some() && !cli.redact);
        if no_tracer {
            if !cli.quiet {
                eprintln!(
                    "pmask: --secret: this mode runs the payload without a tracer, so the \
                     same-uid descriptor read stays open; use the redaction mode or \
                     --allow-dumpable to accept it"
                );
            }
        } else if !profile_defaults_nodumpable {
            cli.mask = cli.mask.no_dumpable().supervisor_non_dumpable(true);
            cli.no_dumpable = true;
            if !cli.quiet {
                eprintln!(
                    "pmask: --secret: the payload is non-dumpable so a same-uid process \
                     cannot read the delivered value or its memory; pass --allow-dumpable \
                     to opt out"
                );
            }
        }
    }

    if cli.mask.watch_rename_enabled() {
        if cli.mask.session_end_explicit() {
            if cli.mask.session_end_value() == pmask::SessionEnd::Detach {
                eprintln!(
                    "pmask: --watch-rename installs a seccomp filter that cannot be removed; \
                     --on-exit detach would leave it in a descendant with no tracer to \
                     service it.  Drop --detach, or use --on-exit wait or kill."
                );
                std::process::exit(255);
            }
        } else {
            cli.mask = cli.mask.session_end(pmask::SessionEnd::WaitTree);
            if !cli.quiet {
                eprintln!(
                    "pmask: --watch-rename: waiting for the tree so the filter keeps a tracer; \
                     pass --on-exit detach to be refused, or wait/kill to choose"
                );
            }
        }
    }

    if cli.mask.strict_exec_enabled() && cli.mask.detach_after_exec_enabled() {
        eprintln!(
            "pmask: --strict-exec and --detach cannot be combined: --detach releases each \
             tracee after its first exec, so later execs run unredacted; drop --detach \
             to keep strict exec enforcement"
        );
        std::process::exit(255);
    }

    if cli.audit && cli.report_json && cli.report_file.is_none() && cli.report_fd.is_none() {
        eprintln!(
            "pmask: --audit writes its residue rows to stdout, and --report writes the JSON \
             document there too; use --report-file PATH or --report-fd N, or drop one flag"
        );
        std::process::exit(255);
    }

    if cli.report_json && !plain_mode {
        if !cli.mask.session_end_explicit() {
            cli.mask = cli.mask.session_end(pmask::SessionEnd::WaitTree);
            if !cli.quiet {
                eprintln!(
                    "pmask: --report: waiting for the tree so the document is written after \
                     it; pass --on-exit detach to opt out"
                );
            }
        } else if cli.mask.session_end_value() == pmask::SessionEnd::Detach && !cli.quiet {
            eprintln!(
                "pmask: warning: --on-exit detach lets a descendant outlive this process, \
                 and the report is a file it can append to after it is written"
            );
        }
        cli.mask = cli.mask.supervisor_non_dumpable(true);
    }

    if cli.report_json && !cli.needs_runner_without_report() && !ptrace_ok {
        eprintln!(
            "pmask: --report=json: the report needs the redaction mode, and this host \
             refuses ptrace; the payload would run unredacted.  Run where ptrace is \
             permitted, or drop the report option."
        );
        std::process::exit(255);
    }

    // Fast in-place single-process execution (`--profile single` or `auto` -> `single`).
    if single_fast_path {
        if !cli.quiet && cli.mask.secret_fd_name_value().is_some() && cli.secrets.is_empty() {
            eprintln!(
                "pmask: --secret-fd-name has no effect: no --secret was given, so no \
                 descriptor is delivered"
            );
        }
        run_single_profile(cli);
    }

    if cli.needs_runner() && cli.daemon.is_none() {
        std::process::exit(run_with_secrets(cli));
    }

    if !cli.quiet && cli.mask.secret_fd_name_value().is_some() {
        eprintln!(
            "pmask: --secret-fd-name has no effect: no --secret was given, so no \
             descriptor is delivered"
        );
    }

    if let Some(socket) = cli.daemon.take() {
        warn_daemon_options(&cli.mask_opts, cli.quiet);
        if let pmask::daemon::RemoteLabel::Text(t) = &cli.remote_label {
            if let Err(e) = pmask::mask::validate_label(t) {
                eprintln!("pmask: {}", e);
                std::process::exit(255);
            }
        }
        let argv = pmask::daemon::client_argv(&cli.program, &cli.args);
        let path = Path::new(&socket);
        match pmask::daemon::run_remote(path, cli.remote_label, &argv) {
            Ok(st) => finish(st),
            Err(e) => {
                eprintln!("pmask: daemon {}: {}", Path::new(&socket).display(), e);
                std::process::exit(255);
            }
        }
    }

    // Direct supervisor path (`tree` and `compat`): prepare, scrub, self-mask,
    // and supervise directly on the calling thread (`Threads: 1`).
    let prepared = match cli.mask.prepare(&cli.program, &cli.args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pmask: {}: {}", cli.program.to_string_lossy(), e);
            let text = e.to_string();
            if text.starts_with("--rexec:") {
                let code = if e.kind() == std::io::ErrorKind::NotFound {
                    127
                } else {
                    126
                };
                std::process::exit(code);
            }
            std::process::exit(255);
        }
    };
    cli.scrub_values();
    cli.mask.scrub_env_values();

    if !no_selfmask {
        if let Err(e) = prepared.mask_self_opts(cli.mask.supervisor_is_non_dumpable()) {
            if !cli.quiet {
                eprintln!(
                    "pmask: warning: the supervisor's own /proc entry could not be fully \
                     treated: {}",
                    e
                );
            }
        }
    }

    install_signal_handlers();

    match cli.mask.run_prepared_on_current_thread(prepared) {
        Ok(st) => finish(st),
        Err(e) => {
            if e.raw_os_error() == Some(libc::EPERM) {
                if let Some(reason) = ptrace_refusal() {
                    eprintln!("pmask: cannot redact here: {}", reason);
                    eprintln!(
                        "pmask: this run needed ptrace; the secret side does not: use \
                         --secret NAME=file:PATH or --secret NAME=agent:NAME, which deliver \
                         over descriptors, or run pmask where ptrace is permitted"
                    );
                }
            }
            eprintln!("pmask: session error: {}", e);
            std::process::exit(255);
        }
    }
}
