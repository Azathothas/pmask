//! CLI argument parsing for `pmask`.

use pmask::daemon::RemoteLabel;
use pmask::isolate::Isolate;
use pmask::mask::Mask;
use pmask::secret::Source;
use pmask::SessionEnd;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::process::exit;

pub const HELP: &str = r#"
pmask {version} ({arch}) - redact the /proc metadata of a whole process tree

Run COMMAND with a presentation label in place of its real command line,
environment and process name as seen through /proc (and therefore ps, top,
htop, btop and any other process monitor).  Every process the command ever
spawns - children, grandchildren, daemons, threads, posix_spawn/system(),
static binaries, scripts - is covered.  Programs keep their real argv/envp
and work completely normally.

Use it to keep secrets off the process table: tokens, passwords or internal
hostnames passed as arguments are otherwise readable by every local account
that can run `ps`, for the whole lifetime of a process.

Usage: pmask [OPTIONS] [--] COMMAND [ARGS...]
       pmask [OPTIONS] --args-from-fd N
       pmask [OPTIONS] --image PATH [ARGS...]

Options:
  -l, --label NAME     Presentation label for every process' /proc cmdline
                       and comm (e.g. --label 'ci-runner').  The value '-'
                       gives a blank label (one space); '-l-', '-l -',
                       '--label=-' and '--label -' all mean the same.
                       The label must not contain NUL, LF or CR.
                       Default: the program name, with all arguments
                       removed.  Everything the command spawns inherits
                       the label.
      --label-empty    Empty label (cmdline shows nothing at all).
      --argv0 NAME     argv[0] of the program.  Default: COMMAND exactly as
                       typed (not the resolved path).
      --comm NAME      comm name (what top shows), at most 15 bytes.
                       Default: the label cut to 15 bytes.
      --keep-env       Leave /proc/<pid>/environ visible (default: redacted).
      --keep-env=NAME[,NAME...]
                       Keep only the named variables visible in
                       /proc/<pid>/environ; the rest stays redacted.  The
                       inline '=' form is required.  Repeatable.
                       `--keep-env NAME` (space form) passes NAME to the
                       program as its own argument; it keeps the whole
                       environment and is refused when no program follows.
      --env K=V        Add or replace one variable for the program.
                       Repeatable.
      --env-file PATH  Read variables for the program from PATH: one KEY=VALUE
                       per line, '#' starts a comment line, blank lines are
                       skipped, no quoting, values are taken as written.
                       Repeatable.
      --args-from-fd N Read the command from file descriptor N: NUL-separated
                       program and arguments.  The secrets then never appear
                       in pmask's own command line.  The vector is capped
                       at 8 MiB; a larger one is refused without buffering
                       it all.
                         pmask -l ci-runner --args-from-fd 3 3<args.bin
      --on-exit POLICY What happens to descendants still running when the
                       command exits: detach (default), wait or kill.
      --no-follow      Redact only the direct child; descendants run
                       unredacted (still traced, but never redacted).
      --no-exit-kill   Let the tree survive if pmask dies (default: kill
                       the whole tree, so no half-redacted orphans remain).
      --no-dumpable    Set PR_SET_DUMPABLE=0 in every process of the tree.
                       Same-uid observers cannot read environ, maps, exe or
                       fd.  Core dumps and debugger attach stop working.
      --no-new-privs   Set no_new_privs before exec.  Set-uid and file
                       capabilities give nothing, for the whole tree.
      --no-exact       Keep the original cmdline byte extent: the label is
                       written over the real arguments but /proc/<pid>/stat
                       still reports how many bytes they took.  By default
                       the kernel's argv and environment windows are moved
                       onto the label with prctl(PR_SET_MM_MAP), so the
                       cmdline is exactly the label and environ is empty
                       (or, with --keep-env, keeps those variables).
      --detach         PTRACE_DETACH each process once its exec has
                       settled, so TracerPid reads 0 for the payload.  The
                       cost is coverage: a detached process is not
                       followed at all, so nothing it forks and none of
                       its own later execs are seen or redacted.  The
                       session summary counts each detach.  Use --on-exit
                       and --no-follow with care in this mode.
      --watch-rename   Keep the label as comm when a program renames itself
                       (prctl PR_SET_NAME).  Uses a seccomp filter; implies
                       --no-new-privs.  If the filter cannot be installed,
                       the run exits 126 naming the failure instead of
                       running without the promise.
      --rexec          Exec the program from a sealed memfd so that
                       /proc/<pid>/exe names the label, not the file.  The
                       child tries execveat(AT_EMPTY_PATH), then
                       /proc/self/fd/N, then a temporary file on a mount
                       that allows execution.  Each failed step is reported
                       and counted.  Without --rexec-allow-disk a refused
                       image ends the child with 126 (127 when the image is
                       missing) instead of running the on-disk file.
      --rexec-allow-disk
                       Add the on-disk path as the explicit last resort of
                       the --rexec chain.  The fallback is reported and
                       counted; it is never automatic.
      --image PATH     Read the program bytes from PATH and exec them from
                       a sealed image.  PATH is opened as given, not
                       searched in PATH.  `--image -` reads standard input
                       to end of file.  Only ELF images work; a script needs
                       an interpreter that opens a path.  Implies --rexec.
      --image-from-fd N
                       Read the program bytes from descriptor N.  Implies
                       --rexec.  The payload's argv[0] is the placeholder
                       '<fd image>' unless --argv0 gives one, because a
                       descriptor has no path to name.
      --exec-once      Reuse one sealed image per distinct program, keyed
                       by the resolved path and its mtime, across the
                       execs of the session.  Later execs use a guarded
                       temporary-file image, because the supervisor is
                       non-dumpable.  Implies --rexec.
      --hugetlb        Ask for a hugetlbfs-backed image and report the
                       backing it got.  When huge pages are unavailable
                       the run reports it and uses an ordinary memfd.
                       Implies --rexec.
      --unshare        Run in new user, pid and mount namespaces with a
                       private /proc, when the kernel allows it.  Otherwise
                       one 'pmask: --unshare unavailable:' line is printed
                       and the run continues without it.
      --scope-name NAME
                       Re-exec once through 'systemd-run --scope' so the tree
                       runs in a transient scope named NAME.  The name is
                       visible in /proc/<pid>/cgroup.  Without systemd one
                       line is printed and the run continues.
  -q, --quiet          Suppress diagnostics.
  -v, --verbose        Trace every redaction event to stderr.
  -V, --version        Print version.
  -h, --help           This help.

Compatibility aliases: -a NAME (= --label), -a- (= -l-), -E (= --keep-env),
-F (= --no-follow), -K (= --no-exit-kill), -f/-c (accepted, no effect).

Label limits: the label is cut at three places.  comm keeps 15 bytes.  The
exec entry path keeps 254 bytes of the label.  The post-exec path (scripts)
cuts the label to the span of the argument area.  A warning is printed once
when the label is longer than 254 bytes.

With --daemon PATH the job runs inside a pmaskd.  The daemon owns the
masking policy and the environment: it refuses an environment from the
client on purpose, so a client cannot change what the job inherits.  Mask
options other than --label and --label-empty have no effect there and
produce a warning.  --secret, --isolate and --no-redact are refused
outright, because the daemon cannot honour them.

Environment: PMASK_NO_SELFMASK=1 disables the redaction of pmask's own
/proc entry (argv, environ, comm).  Use it only for debugging.

Secret side (works even where ptrace is refused):
  --secret NAME=SRC    deliver a secret on descriptor 3, 4, ...  SRC is
                       file:PATH | env:VAR | agent:NAME | stdin | literal:VAL.
                       Repeatable.  The child reads the descriptor from
                       PMASK_SECRET_<NAME> (the name upper-cased, with
                       every non-alphanumeric byte turned into '_'), and
                       `pmask read NAME` prints it there.
  --socket PATH        secret-agent socket for agent:NAME sources.
  --isolate[=LIST]     run the payload in fresh namespaces: pid,net,tmp |
                       all | none (default all).  `none` runs the payload
                       with the host's view unchanged: no namespace, no
                       no_new_privs and no Landlock.  A host that cannot
                       create user namespaces runs the plain path and
                       says so.
  --audit              print one residue row per tracee at each exec
                       completion, then a residue count: what the tree
                       still discloses.  Needs the redaction mode, so it
                       is refused with --no-redact, --isolate and on a
                       host that cannot ptrace (the refusal names the
                       mode).
  --redact             ask for /proc redaction explicitly (the default).
                       With --isolate it composes: the tree is redacted
                       and the payload gets exactly the namespaces LIST
                       names, in one run.  A LIST the host cannot grant is
                       reported as a degradation; it is never replaced by
                       a different namespace set.
  --no-redact          never touch /proc metadata, even where ptrace works.
                       With --isolate the payload still gets its
                       namespaces: isolation does not need ptrace, and
                       dropping it would be a silent fallback.
  --allow-argv-secret  keep a literal: or env: secret source in a mode that
                       cannot redact /proc, and warn instead of refusing.
  --secret-close-on-exec
                       close each delivered descriptor in every process the
                       supervised program starts, at that process's fork:
                       the payload reads the value, and a child it spawns
                       finds the descriptor gone before it runs.  Needs the
                       ptrace supervisor; a plain or isolate run refuses
                       the flag when a secret is delivered, and a run with
                       no --secret has nothing to close.
  --secret-burn        seal the descriptors without F_SEAL_SHRINK, so the
                       reader can truncate a value to zero once it has used
                       it and cannot grow or rewrite it afterwards.
  --report=json        print the run as one JSON object.  The report is
                       written after the payload has exited, so a payload
                       that writes to stdout shares fd 1 with it: use
                       --report-file PATH or --report-fd N when a consumer
                       has to parse the document.  The report describes a
                       secret-side run, so it needs --secret, --isolate or
                       --no-redact; a plain mask run and a --daemon job
                       refuse the flag.
  --report-file PATH   write the --report document to PATH instead of
                       stdout; the payload keeps fd 1 to itself.
  --report-fd N        write the --report document to descriptor N, which
                       is inherited by pmask and closed afterwards.  The
                       descriptor is checked before the payload runs.

  `pmask run ...` is this same parser; `pmask help` lists the rest
  (store, agent, get, read, probe, doctor).  `pmask help <topic>` prints
  one section (`redact`, `isolate`, `secret`, `report`, `daemon`).

Examples:
  # a deployment whose token must not land in `ps` output:
  pmask --label 'ci-runner' ./deploy.sh --token "$TOKEN" --env prod

  # long-lived worker started by a service manager:
  pmask -q --label 'app-worker' python worker.py --queue=rediss://...

Honest scope: root on the host always sees THAT a pid exists; pmask
redacts WHAT it is.  /proc/<pid>/exe, maps, open files and cgroups still
describe the real binary unless --rexec, --no-dumpable or --unshare is
used.  Set-uid programs do not gain privileges under supervision (a
general ptrace property)."#;

pub struct Cli {
    pub mask: Mask,
    pub program: OsString,
    pub args: Vec<OsString>,
    /// `--daemon PATH`: ask a running pmaskd to run the job instead of
    /// supervising it here.
    pub daemon: Option<OsString>,
    /// Label to send to the daemon.
    pub remote_label: RemoteLabel,
    /// `-q` is the last of `-q` and `-v`.
    pub quiet: bool,
    /// `-v` (the last of the pair); false when `-q` came last.
    pub verbose: bool,
    /// Mask options given on the command line that a daemon ignores.
    pub mask_opts: Vec<&'static str>,
    /// `--scope-name NAME`.
    pub scope_name: Option<String>,
    /// The command line without `--scope-name`, for the one re-exec.
    pub reexec_argv: Vec<OsString>,
    /// `--args-from-fd N`, until `load_args_fd` has read it.
    pub args_fd: Option<libc::c_int>,
    /// `--env` and `--env-file` pairs, in the order given.  The mask
    /// carries the same pairs for the redaction mode; the runner needs
    /// its own copy for the isolate and plain modes, which build their
    /// own environment.
    pub env_overrides: Vec<(OsString, OsString)>,
    /// `--secret NAME=SRC`, delivered over descriptors.
    pub secrets: Vec<(String, Source)>,
    /// `--socket PATH`: the secret agent to ask for `agent:NAME` sources.
    pub agent_socket: Option<PathBuf>,
    /// `--isolate[=LIST]`: a private namespace set for the payload.
    pub isolate: Option<Isolate>,
    /// `--no-redact`: never touch /proc metadata.
    pub no_redact: bool,
    /// `--audit`: print one residue row per tracee and a residue count.
    pub audit: bool,
    /// `--redact`: ask for the default redaction explicitly.  With
    /// `--isolate` it is the composed spelling of `--unshare`.
    pub redact: bool,
    /// `--allow-argv-secret`: keep a literal or env source even in a mode
    /// that cannot redact, and warn instead of refusing.
    pub allow_argv_secret: bool,
    /// `--secret-burn`, `--secret-close-on-exec`: how the delivered
    /// descriptors behave.
    pub secret_burn: bool,
    pub secret_close_on_exec: bool,
    /// `--no-dumpable`: the run report's `payload_dumpable` is false.
    pub no_dumpable: bool,
    /// `--report=json`: print the run as one JSON object.
    pub report_json: bool,
    /// `--report-file PATH`: write that object to PATH instead of stdout.
    pub report_file: Option<PathBuf>,
    /// `--report-fd N`: write that object to an inherited descriptor.
    pub report_fd: Option<libc::c_int>,
}

impl Cli {
    /// True when the run needs the secret machinery rather than the plain
    /// mask path: any secret, isolation, or an explicit `--no-redact`.
    ///
    /// `--report` is not part of this decision.  The report is produced by
    /// the runner, so the plain mask path and the `--daemon` client refuse
    /// the flag instead of dropping it (`main`).
    pub fn needs_runner(&self) -> bool {
        !self.secrets.is_empty() || self.isolate.is_some() || self.no_redact
    }
}

fn die(msg: &str) -> ! {
    eprintln!("pmask: {}", msg);
    exit(255);
}

/// Fetch an option value: the attached bytes when present, otherwise the
/// next argv element whatever it looks like (`-l -x` labels the process
/// `-x`, matching the C tool).
fn take_value(flag: &str, inline: Option<Vec<u8>>, argv: &[OsString], i: &mut usize) -> Vec<u8> {
    match inline {
        Some(v) => v,
        None => {
            *i += 1;
            match argv.get(*i) {
                Some(v) => v.as_bytes().to_vec(),
                None => {
                    eprintln!("pmask: option {} needs a value", flag);
                    exit(255);
                }
            }
        }
    }
}

/// Labels are presentation text, so they are decoded as UTF-8 (lossily).
/// Program arguments are not: those are passed through byte for byte.
fn label_from(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The label for a `-l`/`--label` value: `-` means blank (one space) in
/// every spelling.
fn label_arg(bytes: &[u8]) -> String {
    if bytes == b"-" {
        " ".to_string()
    } else {
        label_from(bytes)
    }
}

/// Parse an `--env-file`: `KEY=VALUE` lines, `#` comment lines, blank
/// lines skipped.  Keys must be non-empty and free of NUL; values are
/// taken as written.
fn read_env_file(path: &[u8]) -> Vec<(OsString, OsString)> {
    let shown = String::from_utf8_lossy(path).into_owned();
    let p = std::path::Path::new(std::ffi::OsStr::from_bytes(path));
    let data = match std::fs::read(p) {
        Ok(d) => d,
        Err(e) => die(&format!("--env-file {}: {}", shown, e)),
    };
    let mut out = Vec::new();
    for (n, line) in data.split(|&b| b == b'\n').enumerate() {
        let lineno = n + 1;
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if line.contains(&0) {
            die(&format!("--env-file {}: line {}: NUL byte", shown, lineno));
        }
        let eq = match line.iter().position(|&b| b == b'=') {
            Some(p) if p > 0 => p,
            _ => die(&format!(
                "--env-file {}: line {}: expected KEY=VALUE",
                shown, lineno
            )),
        };
        out.push((
            OsString::from_vec(line[..eq].to_vec()),
            OsString::from_vec(line[eq + 1..].to_vec()),
        ));
    }
    out
}

fn parse_on_exit(v: &[u8]) -> SessionEnd {
    match v {
        b"detach" => SessionEnd::Detach,
        b"wait" => SessionEnd::WaitTree,
        b"kill" => SessionEnd::KillTree,
        _ => die("--on-exit takes detach, wait or kill"),
    }
}

/// True when `s` is a plausible `--keep-env` name list: one or more
/// non-empty names of `[A-Za-z0-9_]`, separated by commas.  Used only to
/// explain a command line that almost certainly meant the inline form.
fn looks_like_env_names(s: &[u8]) -> bool {
    !s.is_empty()
        && s.split(|&b| b == b',').all(|n| {
            !n.is_empty()
                && n.iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.')
        })
}

/// Check a `comm` name the way `Mask::validate` does, at parse time.
///
/// `--no-redact` and `--isolate` never build a `Mask`, so the mask's own
/// validation never runs in those modes: `--comm` over 15 bytes was
/// accepted by plain mode and refused by redaction mode (issues 14 N2 and
/// 33).  The parser is the one place every mode shares.
fn check_comm(comm: &str) {
    if comm.len() > pmask::COMM_MAX {
        die("comm must be at most 15 bytes");
    }
    if comm.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
        die("comm must not contain NUL, LF or CR bytes");
    }
}

fn note_opt(list: &mut Vec<&'static str>, name: &'static str) {
    if !list.contains(&name) {
        list.push(name);
    }
}

/// Parse an already-copied argument vector.
///
/// `main` passes the copy it took before it zeroed the kernel-served argv
/// block, so option parsing never depends on the process's own /proc
/// entry.  The vector is `args_os` style: `std::env::args()` panics on a
/// non-UTF-8 argument, and a supervisor must forward bytes exactly.
pub fn parse_from(argv: Vec<OsString>) -> Cli {
    let mut mask = Mask::new();
    let mut daemon: Option<OsString> = None;
    let mut remote_label = RemoteLabel::Default;
    let mut quiet = false;
    let mut verbose = false;
    let mut mask_opts: Vec<&'static str> = Vec::new();
    let mut scope_name: Option<String> = None;
    let mut skip: Vec<usize> = Vec::new();
    let mut args_fd: Option<libc::c_int> = None;
    let mut env_overrides: Vec<(OsString, OsString)> = Vec::new();
    let mut secrets: Vec<(String, Source)> = Vec::new();
    let mut agent_socket: Option<PathBuf> = None;
    let mut allow_argv_secret = false;
    let mut secret_burn = false;
    let mut secret_close_on_exec = false;
    let mut no_dumpable = false;
    let mut report_json = false;
    let mut report_file: Option<PathBuf> = None;
    let mut report_fd: Option<libc::c_int> = None;
    let mut isolate: Option<Isolate> = None;
    let mut no_redact = false;
    let mut redact = false;
    let mut audit = false;
    let mut image_program: Option<OsString> = None;
    let mut end_opts = false;
    let mut i = 1usize;

    while i < argv.len() {
        let bytes = argv[i].as_bytes().to_vec();
        // A token is an option only if it starts with '-' and has another
        // byte; "-" alone is the command word.
        if end_opts || bytes.len() < 2 || bytes[0] != b'-' {
            break;
        }
        if bytes == b"--" {
            end_opts = true;
            i += 1;
            continue;
        }
        if bytes.starts_with(b"--") {
            let body = &bytes[2..];
            let (name_b, inline) = match body.iter().position(|&b| b == b'=') {
                Some(p) => (&body[..p], Some(body[p + 1..].to_vec())),
                None => (body, None),
            };
            let Ok(name) = std::str::from_utf8(name_b) else {
                eprintln!(
                    "pmask: unknown option --{}",
                    String::from_utf8_lossy(name_b)
                );
                exit(255);
            };
            match name {
                "label" => {
                    let v = take_value("--label", inline, &argv, &mut i);
                    let text = label_arg(&v);
                    remote_label = RemoteLabel::Text(text.clone());
                    mask = mask.label(text);
                }
                "daemon" => {
                    let v = take_value("--daemon", inline, &argv, &mut i);
                    daemon = Some(OsString::from_vec(v));
                }
                "label-empty" => {
                    mask = mask.label("");
                    remote_label = RemoteLabel::Empty;
                }
                "argv0" => {
                    let v = take_value("--argv0", inline, &argv, &mut i);
                    mask = mask.argv0(OsString::from_vec(v));
                    note_opt(&mut mask_opts, "--argv0");
                }
                "comm" => {
                    let v = take_value("--comm", inline, &argv, &mut i);
                    let c = label_from(&v);
                    check_comm(&c);
                    mask = mask.comm(c);
                    note_opt(&mut mask_opts, "--comm");
                }
                "keep-env" => {
                    match inline {
                        None => {
                            // `--keep-env PATH` (the space form) keeps the
                            // whole environment and makes PATH the program.
                            // When the word after the value is the `--`
                            // separator and a command follows it, the
                            // value cannot be the program the operator
                            // meant: they wrote the inline form with a
                            // space, and the run would fail on a name that
                            // looks like a program (issue 14 N3).  Name the
                            // spelling rather than guess.
                            if let (Some(next), Some(after)) = (argv.get(i + 1), argv.get(i + 2)) {
                                if after.as_bytes() == b"--"
                                    && argv.len() > i + 3
                                    && looks_like_env_names(next.as_bytes())
                                {
                                    die(&format!(
                                        "--keep-env takes no value; did you mean \
                                         --keep-env={}?  The space form keeps the whole \
                                         environment and treats the next word as the program",
                                        next.to_string_lossy()
                                    ));
                                }
                            }
                            mask = mask.keep_environ_visible();
                        }
                        Some(list) => {
                            let names: Vec<String> = list
                                .split(|&b| b == b',')
                                .filter(|n| !n.is_empty())
                                .map(label_from)
                                .collect();
                            if names.is_empty() {
                                die("--keep-env= needs at least one name");
                            }
                            mask = mask.keep_env_vars(names);
                        }
                    }
                    note_opt(&mut mask_opts, "--keep-env");
                }
                "env" => {
                    let v = take_value("--env", inline, &argv, &mut i);
                    match v.iter().position(|&b| b == b'=') {
                        // An empty key (`--env =VALUE`) is not a variable:
                        // execve would see a leading '=' and every backend
                        // treats it differently (the redaction path refuses
                        // it, the plain path used to pass it through).  The
                        // parser is the one place every mode shares.
                        Some(0) | None => die(&format!(
                            "--env needs KEY=VALUE with a non-empty KEY, not '{}'",
                            String::from_utf8_lossy(&v)
                        )),
                        Some(p) => {
                            let key = OsString::from_vec(v[..p].to_vec());
                            let val = OsString::from_vec(v[p + 1..].to_vec());
                            mask = mask.env(key.clone(), val.clone());
                            env_overrides.push((key, val));
                        }
                    }
                    note_opt(&mut mask_opts, "--env");
                }
                "env-file" => {
                    let v = take_value("--env-file", inline, &argv, &mut i);
                    for (k, val) in read_env_file(&v) {
                        mask = mask.env(k.clone(), val.clone());
                        env_overrides.push((k, val));
                    }
                    note_opt(&mut mask_opts, "--env-file");
                }
                "args-from-fd" => {
                    let v = take_value("--args-from-fd", inline, &argv, &mut i);
                    let n = std::str::from_utf8(&v)
                        .ok()
                        .and_then(|s| s.parse::<libc::c_int>().ok())
                        .filter(|n| *n >= 0);
                    match n {
                        Some(n) => args_fd = Some(n),
                        // Naming the offending value is what makes a typo
                        // (`--args-from-fd abc`) obvious without a re-read
                        // of the whole command line.
                        None => die(&format!(
                            "--args-from-fd needs a file descriptor number, not '{}'",
                            String::from_utf8_lossy(&v)
                        )),
                    }
                }
                "on-exit" => {
                    let v = take_value("--on-exit", inline, &argv, &mut i);
                    mask = mask.session_end(parse_on_exit(&v));
                    note_opt(&mut mask_opts, "--on-exit");
                }
                "no-follow" => {
                    mask = mask.follow_tree(false);
                    note_opt(&mut mask_opts, "--no-follow");
                }
                "no-exit-kill" | "no-exitkill" => {
                    mask = mask.let_tree_survive_self_death();
                    note_opt(&mut mask_opts, "--no-exit-kill");
                }
                "no-dumpable" => {
                    mask = mask.no_dumpable();
                    no_dumpable = true;
                    note_opt(&mut mask_opts, "--no-dumpable");
                }
                "no-new-privs" => {
                    mask = mask.no_new_privs();
                    note_opt(&mut mask_opts, "--no-new-privs");
                }
                "no-exact" => {
                    mask = mask.exact_windows(false);
                    note_opt(&mut mask_opts, "--no-exact");
                }
                "detach" => {
                    mask = mask.detach_after_exec(true);
                    note_opt(&mut mask_opts, "--detach");
                }
                "watch-rename" => {
                    mask = mask.watch_rename();
                    note_opt(&mut mask_opts, "--watch-rename");
                }
                "rexec" => {
                    mask = mask.rexec();
                    note_opt(&mut mask_opts, "--rexec");
                }
                "image" => {
                    let v = take_value("--image", inline, &argv, &mut i);
                    if image_program.is_some() {
                        die("--image and --image-from-fd are exclusive");
                    }
                    if v == b"-" {
                        mask = mask.image_stdin();
                        image_program = Some(OsString::from("-"));
                    } else {
                        let path = OsString::from_vec(v);
                        mask = mask.image_path(path.clone());
                        image_program = Some(path);
                    }
                    note_opt(&mut mask_opts, "--image");
                }
                "image-from-fd" => {
                    let v = take_value("--image-from-fd", inline, &argv, &mut i);
                    if image_program.is_some() {
                        die("--image and --image-from-fd are exclusive");
                    }
                    let n = std::str::from_utf8(&v)
                        .ok()
                        .and_then(|s| s.parse::<libc::c_int>().ok())
                        .filter(|n| *n >= 0);
                    match n {
                        Some(n) => {
                            mask = mask.image_fd(n);
                            image_program = Some(OsString::from("<fd image>"));
                        }
                        None => die(&format!(
                            "--image-from-fd needs a file descriptor number, not '{}'",
                            String::from_utf8_lossy(&v)
                        )),
                    }
                    note_opt(&mut mask_opts, "--image-from-fd");
                }
                "exec-once" => {
                    mask = mask.exec_once();
                    note_opt(&mut mask_opts, "--exec-once");
                }
                "hugetlb" => {
                    mask = mask.hugetlb();
                    note_opt(&mut mask_opts, "--hugetlb");
                }
                "rexec-allow-disk" => {
                    mask = mask.rexec_allow_disk();
                    note_opt(&mut mask_opts, "--rexec-allow-disk");
                }
                "unshare" => {
                    mask = mask.unshare();
                    note_opt(&mut mask_opts, "--unshare");
                }
                "scope-name" => {
                    let has_inline = inline.is_some();
                    let v = take_value("--scope-name", inline, &argv, &mut i);
                    // i now indexes the value token when it was separate
                    skip.push(i);
                    if !has_inline {
                        skip.push(i - 1);
                    }
                    let text = label_from(&v);
                    mask = mask.scope_name(text.clone());
                    scope_name = Some(text);
                    note_opt(&mut mask_opts, "--scope-name");
                }
                "secret" => {
                    let v = take_value("--secret", inline, &argv, &mut i);
                    match Source::parse(&String::from_utf8_lossy(&v)) {
                        Ok(pair) => secrets.push(pair),
                        Err(e) => die(&format!("--secret: {}", e)),
                    }
                }
                "socket" => {
                    let v = take_value("--socket", inline, &argv, &mut i);
                    agent_socket = Some(PathBuf::from(OsString::from_vec(v)));
                }
                "isolate" => {
                    isolate = match inline {
                        None => Some(Isolate::all()),
                        Some(list) => match pmask::subcmd::parse_isolate(&list) {
                            Some(iso) => Some(iso),
                            None => die("--isolate takes pid,net,tmp,all or none"),
                        },
                    };
                    note_opt(&mut mask_opts, "--isolate");
                }
                "no-redact" => {
                    no_redact = true;
                    note_opt(&mut mask_opts, "--no-redact");
                }
                "redact" => {
                    redact = true;
                }
                "audit" => {
                    audit = true;
                    mask = mask.audit();
                    note_opt(&mut mask_opts, "--audit");
                }
                "allow-argv-secret" => {
                    allow_argv_secret = true;
                    note_opt(&mut mask_opts, "--allow-argv-secret");
                }
                "secret-burn" => {
                    secret_burn = true;
                    note_opt(&mut mask_opts, "--secret-burn");
                }
                "secret-close-on-exec" => {
                    secret_close_on_exec = true;
                    note_opt(&mut mask_opts, "--secret-close-on-exec");
                }
                "report" => {
                    let v = take_value("--report", inline, &argv, &mut i);
                    match &v[..] {
                        b"json" => report_json = true,
                        // `text` and `plain` used to be accepted and did
                        // nothing, which made `--report=text` look like a
                        // format request that was honoured.  The only
                        // format is json; the default output is the
                        // human-readable `pmask: mode=...` line on stderr.
                        b"text" | b"plain" => {
                            die("--report takes json; text is the default output (the \
                             'pmask: mode=...' summary on stderr), so drop --report")
                        }
                        _ => die("--report takes json"),
                    }
                }
                "report-file" => {
                    let v = take_value("--report-file", inline, &argv, &mut i);
                    if v.is_empty() {
                        die("--report-file needs a path");
                    }
                    report_file = Some(PathBuf::from(OsString::from_vec(v)));
                    report_json = true;
                }
                "report-fd" => {
                    let v = take_value("--report-fd", inline, &argv, &mut i);
                    let n = std::str::from_utf8(&v)
                        .ok()
                        .and_then(|s| s.parse::<libc::c_int>().ok())
                        .filter(|n| *n >= 0);
                    match n {
                        Some(n) => {
                            report_fd = Some(n);
                            report_json = true;
                        }
                        None => die(&format!(
                            "--report-fd needs a file descriptor number, not '{}'",
                            String::from_utf8_lossy(&v)
                        )),
                    }
                }
                "quiet" => {
                    mask = mask.quiet();
                    quiet = true;
                    verbose = false;
                }
                "verbose" => {
                    mask = mask.verbose();
                    quiet = false;
                    verbose = true;
                }
                "version" => {
                    println!("pmask {} ({})", pmask::VERSION, pmask::COMMIT);
                    exit(0);
                }
                "help" => {
                    if let Some(topic) = inline {
                        print_topic(&topic);
                    } else {
                        print_help(true);
                    }
                    exit(0);
                }
                _ => {
                    eprintln!("pmask: unknown option --{}", name);
                    exit(255);
                }
            }
            i += 1;
            continue;
        }
        // short cluster: -qv, -afoo, -l-
        let mut j = 1usize;
        while j < bytes.len() {
            match bytes[j] {
                b'l' | b'a' => {
                    let flag = if bytes[j] == b'l' { "-l" } else { "-a" };
                    let inline: Option<Vec<u8>> = if j + 1 < bytes.len() {
                        Some(bytes[j + 1..].to_vec())
                    } else {
                        None
                    };
                    let v = take_value(flag, inline, &argv, &mut i);
                    let text = label_arg(&v);
                    remote_label = RemoteLabel::Text(text.clone());
                    mask = mask.label(text);
                    j = bytes.len();
                    continue;
                }
                b'E' => {
                    mask = mask.keep_environ_visible();
                    note_opt(&mut mask_opts, "--keep-env");
                }
                b'F' => {
                    mask = mask.follow_tree(false);
                    note_opt(&mut mask_opts, "--no-follow");
                }
                b'K' => {
                    mask = mask.let_tree_survive_self_death();
                    note_opt(&mut mask_opts, "--no-exit-kill");
                }
                b'f' | b'c' => {} // compat no-ops
                b'q' => {
                    mask = mask.quiet();
                    quiet = true;
                    verbose = false;
                }
                b'v' => {
                    mask = mask.verbose();
                    quiet = false;
                    verbose = true;
                }
                b'V' => {
                    println!("pmask {} ({})", pmask::VERSION, pmask::COMMIT);
                    exit(0);
                }
                b'h' => {
                    print_help(true);
                    exit(0);
                }
                other => {
                    eprintln!(
                        "pmask: unknown option -{}",
                        String::from_utf8_lossy(&[other])
                    );
                    exit(255);
                }
            }
            j += 1;
        }
        i += 1;
    }

    if image_program.is_some() && args_fd.is_some() {
        die("--image and --args-from-fd are exclusive");
    }

    let reexec_argv: Vec<OsString> = argv
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(idx, _)| !skip.contains(idx))
        .map(|(_, a)| a.clone())
        .collect();

    let (program, args) = if args_fd.is_some() {
        if i < argv.len() {
            die("--args-from-fd replaces COMMAND: no command may follow the options");
        }
        (OsString::new(), Vec::new())
    } else if let Some(p) = image_program {
        if args_fd.is_some() {
            die("--image replaces COMMAND: no command may follow the options");
        }
        // With --image the remaining words are the program's arguments;
        // there is no command word to take.
        (p, argv[i..].to_vec())
    } else {
        if i >= argv.len() {
            print_help(false);
            exit(255);
        }
        // Program and arguments keep their exact bytes.
        (argv[i].clone(), argv[i + 1..].to_vec())
    };

    Cli {
        mask,
        program,
        args,
        daemon,
        remote_label,
        quiet,
        verbose,
        mask_opts,
        scope_name,
        reexec_argv,
        args_fd,
        env_overrides,
        secrets,
        allow_argv_secret,
        secret_burn,
        secret_close_on_exec,
        no_dumpable,
        report_json,
        report_file,
        report_fd,
        agent_socket,
        isolate,
        no_redact,
        redact,
        audit,
    }
}

/// The largest `--args-from-fd` vector read into memory.  The cap bounds
/// the allocation and matches the daemon's frame budget (`MAX_REQUEST`),
/// but not its argv limit: the daemon caps the argument bytes at
/// `--max-job-bytes` (default 1 MiB, `MAX_JOB_ARGV`), so a vector between
/// the two limits is accepted here and refused by the daemon.  A larger
/// vector is refused before it is buffered.
pub const ARGS_FD_MAX: u64 = 8 * 1024 * 1024;

impl Cli {
    /// Read the command from the `--args-from-fd` descriptor, when one
    /// was given.  The descriptor is closed afterwards.
    pub fn load_args_fd(&mut self) {
        let Some(fd) = self.args_fd.take() else {
            return;
        };
        // SAFETY: the descriptor number comes from the operator, who
        // passes it open on purpose.  The File closes it after the read.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut data = Vec::new();
        // Read one byte past the limit so an oversize vector is detected
        // without buffering all of it.
        let mut limited = file.take(ARGS_FD_MAX + 1);
        if let Err(e) = limited.read_to_end(&mut data) {
            die(&format!("--args-from-fd {}: {}", fd, e));
        }
        drop(limited);
        if data.len() as u64 > ARGS_FD_MAX {
            die(&format!(
                "--args-from-fd {}: the vector is larger than the {} MiB limit",
                fd,
                ARGS_FD_MAX / (1024 * 1024)
            ));
        }
        let mut parts: Vec<Vec<u8>> = data.split(|&b| b == 0).map(|s| s.to_vec()).collect();
        if data.last() == Some(&0) {
            parts.pop(); // the empty piece after the final NUL
        }
        if parts.is_empty() || parts[0].is_empty() {
            die(&format!("--args-from-fd {}: no program given", fd));
        }
        let mut it = parts.into_iter();
        self.program = OsString::from_vec(it.next().unwrap_or_default());
        self.args = it.map(OsString::from_vec).collect();
    }
}

/// `-h`/`--help` go to stdout and exit 0; a usage error goes to stderr
/// and exits 255, like the C tool.
/// The mask help text, with version and arch filled in.
pub fn help_text() -> String {
    HELP.replace("{version}", pmask::VERSION)
        .replace("{arch}", arch_name())
}

/// Print one help topic (`--help=<topic>`).  `short` is the option index;
/// `redact`, `isolate`, `secret`, `report` and `daemon` print one option
/// group each.  An unknown topic prints the index and exits 255, so a typo
/// is visible to a script.
fn print_topic(topic: &[u8]) {
    let text = help_text();
    let t = String::from_utf8_lossy(topic).into_owned();
    if t == "short" {
        print!("{}", pmask::subcmd::short_help(&text));
        exit(0);
    }
    let code = pmask::subcmd::help_topic(&text, &t);
    exit(code);
}

fn print_help(stdout: bool) {
    let text = HELP
        .replace("{version}", pmask::VERSION)
        .replace("{arch}", arch_name());
    if stdout {
        println!("{}", text);
    } else {
        eprintln!("{}", text);
    }
}

fn arch_name() -> &'static str {
    pmask::arch_name()
}
