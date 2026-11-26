//! `pmaskd`: the long-running half of pmask.
//!
//! Holds the job environment (tokens included) in memory, masks its own
//! `/proc` entry, and runs jobs on request from local clients of the same
//! uid.  An allowed uid may execute arbitrary programs with the daemon's privileges and inherit its environment.
//! See `pmask::daemon` for the protocol.

use pmask::daemon::{self, DaemonConfig};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::exit;

const HELP: &str = r#"
pmaskd {version} - confidential job supervisor

Runs jobs for local clients without the client ever holding the
environment they need.  The daemon keeps the job environment (loaded
from --env-file, so tokens never appear in a command line), masks its
own /proc entry, and hands each job the client's stdio and exit status.

Warning: an allowed uid may execute arbitrary programs with the daemon's privileges and inherit its environment.

Usage: pmaskd [OPTIONS]

Options:
  -S, --socket PATH     Unix socket to bind (default: $XDG_RUNTIME_DIR/
                        pmask.sock when that directory is owned by
                        you and not group or other writable, else
                        /run/pmask.sock as root; otherwise there is
                        no default and --socket is required.  There is
                        no /tmp fallback: a world-writable directory
                        cannot be checked for ownership.)
  -l, --label NAME      Label for a job whose client sends no label
                        (default: 'pmask-job').  A client --label
                        replaces it.  A client --label-empty gives the
                        job an empty label.  NAME has no NUL, LF or CR.
  -e, --env-file FILE   Load KEY=VALUE lines as the job environment
                        (repeatable; later files win).  Grammar: blank
                        lines and lines that start with # are skipped;
                        'export ' before KEY is allowed; KEY has
                        printable ASCII only, no space and no '=';
                        VALUE loses surrounding blanks, and one pair of
                        matching ' or " quotes around it is removed;
                        there are no escapes; a NUL byte is an error.
                        Errors name the file and the line.  A warning
                        appears when the file is readable by group or
                        other.
      --no-inherit-env  Jobs get the --env-file variables only, not the
                        environment the daemon started with
      --keep-env        Leave /proc/<pid>/environ visible for jobs
      --allow-uid UID   Also accept connections from this uid (repeatable;
                        the daemon's own uid and root are always accepted)
      --run-as-uid[=UID[:GID]]
                        Root daemon only.  Without a value, run each job
                        with the uid and gid of the client instead of
                        root.  With =UID or =UID:GID, run every job as
                        that dedicated helper uid/gid (omitted GID uses
                        /etc/passwd or defaults to UID).  Cross-UID jobs
                        stay dumpable=1 by default because kernel Unix
                        DAC already isolates them from the client.  A
                        daemon that serves other uids also needs a
                        socket mode they can reach, for example
                        --socket-mode 666.
      --no-dumpable     Force PR_SET_DUMPABLE=0 on every job, even
                        cross-UID jobs
      --allow-dumpable  Keep jobs dumpable (PR_SET_DUMPABLE=1), even for
                        same-UID clients (the daemon itself always stays
                        non-dumpable)
      --rexec           Stage ELF job binaries into an unlinked or
                        private carrier so /proc/<pid>/exe and maps do
                        not name the on-disk path (default: on for
                        readable ELF jobs; #! scripts still run directly)
      --no-rexec        Execute job binaries directly from their on-disk
                        path without staging
      --rexec-mode MODE Carrier mode for --rexec: auto, path, tmpfile,
                        or memfd (default: auto; implies --rexec)
      --socket-mode OCT Socket permission bits, 001 to 777 (default: 600)
      --io-timeout SECONDS
                        Drop a client that stalls while it sends its
                        request or reads the response (default: 30;
                        0 means no limit; at most 315360000, ten years)
      --job-timeout SECONDS
                        Kill a job tree that runs longer than this and
                        return code 137 (default: no limit; at most
                        315360000, ten years)
      --jobs N          Run up to N jobs at once, one worker process per
                        connection (default: 1)
      --max-job-bytes N Largest total size of the job arguments, each
                        counted with its NUL byte (default: 1048576)
  -q, --quiet           Suppress diagnostics
  -v, --verbose         Log each accepted job
  -V, --version         Print version
  -h, --help            This help

By default the daemon runs one job at a time: a masking session owns the
process-wide waitpid domain, so sessions cannot overlap in one process.
With --jobs N a forked worker runs each job.

The daemon locks its copy of the job environment in memory.  On SIGTERM
or SIGINT it kills running jobs, overwrites the stored environment,
removes the socket and exits with code 0.

The daemon refuses to start when the socket path is a symbolic link, is
not a socket, or has a live daemon behind it.

Examples:
  # secrets live in a root-owned file; the runner never reads it
  pmaskd --label ci-runner --env-file /etc/pmask/runner.env
  pmask --daemon /run/pmask.sock -- ./deploy.sh --env prod
"#;

struct Args {
    cfg: DaemonConfig,
    env_files: Vec<OsString>,
    no_inherit_env: bool,
}

fn die(text: &str) -> ! {
    eprintln!("pmaskd: {}", text);
    exit(255);
}

fn main() {
    // A closed 0, 1 or 2 would let a later open() return a low number
    // that a job then inherits as its stdio.
    if let Err(e) = daemon::ensure_stdio_open() {
        die(&format!("cannot open /dev/null: {}", e));
    }
    // Always disable core dumps on startup (even without `--env-file`) so
    // neither `pmaskd` nor any job it spawns ever dumps core (`RLIMIT_CORE=0`
    // survives `execve`).
    let core_limit_err = {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `zero` is a valid `rlimit` struct for the calling process.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        }
    };
    let args = parse();
    if let Some(e) = core_limit_err {
        if !args.cfg.quiet {
            eprintln!(
                "pmaskd: warning: could not disable core dumps (RLIMIT_CORE=0): {}",
                e
            );
        }
    }
    // `--env-file` can hold secrets, and a large file takes long enough
    // that a same-uid scanner reads the staging copy while it loads.  A
    // daemon that carries job environment values is hardened before the
    // first read; a host that refuses the call still gets the run, and
    // the existing warnings say what is open.
    if !args.env_files.is_empty() {
        let notes = pmask::mem::harden_self();
        if !args.cfg.quiet {
            for note in notes {
                eprintln!("pmaskd: warning: self-hardening incomplete: {}", note);
            }
        }
    }
    let mut overrides: Vec<(OsString, OsString)> = Vec::new();
    for f in &args.env_files {
        let path = std::path::Path::new(f);
        match daemon::parse_env_file(path) {
            Ok(mut vars) => overrides.append(&mut vars),
            Err(e) => die(&e.to_string()),
        }
        if !args.cfg.quiet {
            if let Ok(true) = daemon::env_file_readable_by_others(path) {
                eprintln!(
                    "pmaskd: warning: {} is readable by group or other",
                    path.display()
                );
            }
        }
    }

    // Capture the job environment *before* masking ourselves: after the
    // self-mask this process's own environ is gone by design.
    let mut cfg = args.cfg;
    cfg.env = daemon::job_env(!args.no_inherit_env, &overrides);
    daemon::wipe_env(&mut overrides);

    let comm = cfg
        .label
        .as_bytes()
        .iter()
        .take(15)
        .copied()
        .collect::<Vec<u8>>();
    if let Err(e) = pmask::mask_self(&comm, true) {
        if !cfg.quiet {
            eprintln!("pmaskd: warning: self-mask incomplete: {}", e);
        }
    }

    if let Err(e) = daemon::serve(cfg) {
        die(&e.to_string());
    }
}

fn number(flag: &str, text: &str) -> u64 {
    match text.parse::<u64>() {
        Ok(n) => n,
        Err(_) => die(&format!("{} needs a number", flag)),
    }
}

/// Read a seconds value and refuse one above [`pmask::daemon::MAX_TIMEOUT_SECS`].
///
/// The bound is checked here, at parse time, so a value that would make a
/// deadline overflow never reaches the daemon.  `u64::MAX` seconds is
/// about 5.8e11 years; the deadline is `Instant::now() + Duration`, which
/// panics, and the panic would take the daemon down with it (issue 18).
/// The limit is ten years, which is far past any real job and stays away
/// from the edge of the clock on every architecture.
fn seconds(flag: &str, text: &str) -> u64 {
    let n = number(flag, text);
    if n > daemon::MAX_TIMEOUT_SECS {
        die(&format!(
            "{} is {} s; the limit is {} s (ten years).  A value near u64::MAX would overflow \
             the deadline and panic the daemon, so the limit is enforced rather than clamped",
            flag,
            n,
            daemon::MAX_TIMEOUT_SECS
        ));
    }
    n
}

fn parse() -> Args {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let mut cfg = DaemonConfig::new();
    let mut env_files = Vec::new();
    let mut no_inherit_env = false;
    let mut saw_rexec = false;
    let mut saw_no_rexec = false;
    let mut i = 1usize;

    while i < argv.len() {
        let bytes = argv[i].as_bytes().to_vec();
        if bytes.len() < 2 || bytes[0] != b'-' {
            die(&format!(
                "unexpected argument: {}",
                String::from_utf8_lossy(&bytes)
            ));
        }
        if bytes.starts_with(b"--") {
            let body = &bytes[2..];
            let (name, inline) = match body.iter().position(|&b| b == b'=') {
                Some(p) => (&body[..p], Some(body[p + 1..].to_vec())),
                None => (body, None),
            };
            let name = String::from_utf8_lossy(name).into_owned();
            let flag = format!("--{}", name);
            match name.as_str() {
                "socket" => {
                    cfg.socket =
                        PathBuf::from(OsString::from_vec(take(&flag, inline, &argv, &mut i)))
                }
                "label" => cfg.label = lossy(take(&flag, inline, &argv, &mut i)),
                "env-file" => {
                    env_files.push(OsString::from_vec(take(&flag, inline, &argv, &mut i)))
                }
                "no-inherit-env" => no_inherit_env = true,
                "keep-env" => cfg.keep_env = true,
                "run-as-uid" => match inline {
                    None => {
                        cfg.run_as_uid = true;
                        cfg.run_as_fixed = None;
                    }
                    Some(v) => {
                        let text = lossy(v);
                        let (u, g) = parse_uid_gid(&text);
                        cfg.run_as_fixed = Some((u, g));
                        cfg.run_as_uid = false;
                    }
                },
                "no-dumpable" => {
                    if inline.is_some() {
                        die("--no-dumpable takes no value");
                    }
                    cfg.force_no_dumpable = true;
                }
                "allow-dumpable" => {
                    if inline.is_some() {
                        die("--allow-dumpable takes no value");
                    }
                    cfg.allow_dumpable = true;
                }
                "rexec" => {
                    if inline.is_some() {
                        die("--rexec takes no value");
                    }
                    cfg.rexec = true;
                    saw_rexec = true;
                }
                "no-rexec" => {
                    if inline.is_some() {
                        die("--no-rexec takes no value");
                    }
                    cfg.rexec = false;
                    saw_no_rexec = true;
                }
                "rexec-mode" => {
                    let v = take(&flag, inline, &argv, &mut i);
                    cfg.rexec_mode = parse_rexec_mode(&v);
                    cfg.rexec = true;
                    saw_rexec = true;
                }
                "allow-uid" => {
                    let v = lossy(take(&flag, inline, &argv, &mut i));
                    match v.parse::<u32>() {
                        Ok(u) => cfg.allow_uids.push(u),
                        Err(_) => die("--allow-uid needs a number"),
                    }
                }
                "socket-mode" => {
                    let v = lossy(take(&flag, inline, &argv, &mut i));
                    match u32::from_str_radix(v.trim_start_matches("0o"), 8) {
                        Ok(m) if (1..=0o777).contains(&m) => cfg.socket_mode = m,
                        Ok(_) => die(
                            "--socket-mode needs permission bits from 001 to 777; 0 makes the \
                             socket unreachable",
                        ),
                        Err(_) => die("--socket-mode needs an octal number"),
                    }
                }
                "io-timeout" => {
                    cfg.io_timeout_secs =
                        seconds(&flag, &lossy(take(&flag, inline, &argv, &mut i)));
                }
                "job-timeout" => {
                    cfg.job_timeout_secs =
                        seconds(&flag, &lossy(take(&flag, inline, &argv, &mut i)));
                }
                "jobs" => {
                    let n = number(&flag, &lossy(take(&flag, inline, &argv, &mut i)));
                    if n == 0 {
                        die("--jobs needs a number of at least 1");
                    }
                    cfg.jobs = n as usize;
                }
                "max-job-bytes" => {
                    let n = number(&flag, &lossy(take(&flag, inline, &argv, &mut i)));
                    if n == 0 {
                        die("--max-job-bytes needs a number of at least 1");
                    }
                    cfg.max_job_bytes = n as usize;
                }
                "quiet" => cfg.quiet = true,
                "verbose" => cfg.verbose = true,
                "version" => {
                    println!("pmaskd {} ({})", pmask::VERSION, pmask::COMMIT);
                    exit(0);
                }
                "help" => {
                    print_help(true);
                    exit(0);
                }
                _ => die(&format!("unknown option --{}", name)),
            }
            i += 1;
            continue;
        }
        let mut j = 1usize;
        while j < bytes.len() {
            match bytes[j] {
                b'S' => {
                    let inline = if j + 1 < bytes.len() {
                        Some(bytes[j + 1..].to_vec())
                    } else {
                        None
                    };
                    cfg.socket =
                        PathBuf::from(OsString::from_vec(take("-S", inline, &argv, &mut i)));
                    j = bytes.len();
                    continue;
                }
                b'l' => {
                    let inline = if j + 1 < bytes.len() {
                        Some(bytes[j + 1..].to_vec())
                    } else {
                        None
                    };
                    cfg.label = lossy(take("-l", inline, &argv, &mut i));
                    j = bytes.len();
                    continue;
                }
                b'e' => {
                    let inline = if j + 1 < bytes.len() {
                        Some(bytes[j + 1..].to_vec())
                    } else {
                        None
                    };
                    env_files.push(OsString::from_vec(take("-e", inline, &argv, &mut i)));
                    j = bytes.len();
                    continue;
                }
                b'q' => cfg.quiet = true,
                b'v' => cfg.verbose = true,
                b'V' => {
                    println!("pmaskd {} ({})", pmask::VERSION, pmask::COMMIT);
                    exit(0);
                }
                b'h' => {
                    print_help(true);
                    exit(0);
                }
                other => die(&format!(
                    "unknown option -{}",
                    String::from_utf8_lossy(&[other])
                )),
            }
            j += 1;
        }
        i += 1;
    }

    if cfg.force_no_dumpable && cfg.allow_dumpable {
        die("--no-dumpable and --allow-dumpable contradict each other; pass one");
    }
    if saw_rexec && saw_no_rexec {
        die("--rexec/--rexec-mode and --no-rexec contradict each other; pass one");
    }

    Args {
        cfg,
        env_files,
        no_inherit_env,
    }
}

fn parse_rexec_mode(v: &[u8]) -> pmask::RexecMode {
    let lower = v.to_ascii_lowercase();
    match lower.as_slice() {
        b"auto" => pmask::RexecMode::Auto,
        b"path" => pmask::RexecMode::Path,
        b"tmpfile" => pmask::RexecMode::Tmpfile,
        b"memfd" => pmask::RexecMode::Memfd,
        _ => die("--rexec-mode takes auto, path, tmpfile or memfd"),
    }
}

/// Value of an option.  `flag` is the option as the user types it
/// (`-S` or `--socket`), used in the error message.
fn take(flag: &str, inline: Option<Vec<u8>>, argv: &[OsString], i: &mut usize) -> Vec<u8> {
    match inline {
        Some(v) => v,
        None => {
            *i += 1;
            match argv.get(*i) {
                Some(v) => v.as_bytes().to_vec(),
                None => die(&format!("option {} needs a value", flag)),
            }
        }
    }
}

fn lossy(b: Vec<u8>) -> String {
    String::from_utf8_lossy(&b).into_owned()
}

fn parse_uid_gid(text: &str) -> (u32, u32) {
    match text.split_once(':') {
        Some((us, gs)) => {
            let u = us
                .parse::<u32>()
                .unwrap_or_else(|_| die("--run-as-uid=UID[:GID] needs numeric UID and GID"));
            let g = gs
                .parse::<u32>()
                .unwrap_or_else(|_| die("--run-as-uid=UID[:GID] needs numeric UID and GID"));
            (u, g)
        }
        None => {
            let u = text
                .parse::<u32>()
                .unwrap_or_else(|_| die("--run-as-uid=UID[:GID] needs a numeric UID"));
            let g = lookup_passwd_gid(u).unwrap_or(u);
            (u, g)
        }
    }
}

fn lookup_passwd_gid(uid: u32) -> Option<u32> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let mut fields = line.split(':');
        let Some(_) = fields.next() else {
            continue;
        };
        let Some(_) = fields.next() else {
            continue;
        };
        let Some(Ok(f_uid)) = fields.next().map(str::parse::<u32>) else {
            continue;
        };
        let Some(Ok(f_gid)) = fields.next().map(str::parse::<u32>) else {
            continue;
        };
        if f_uid == uid {
            return Some(f_gid);
        }
    }
    None
}

fn print_help(stdout: bool) {
    let text = HELP.replace("{version}", pmask::VERSION);
    if stdout {
        println!("{}", text);
    } else {
        eprintln!("{}", text);
    }
}
