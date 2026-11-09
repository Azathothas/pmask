//! The subcommands that are not the mask: the encrypted store, the secret
//! agent, the child-side `read`, and the capability report.
//!
//! `pmask` has two faces.  The default face is the mask: `pmask
//! --label L -- cmd` redacts `/proc` metadata.  These subcommands are the
//! other face, the one that turns a secret into a file descriptor, and
//! they are what still works on a host that bans `ptrace`.
//!
//! The dispatcher returns `None` when the argument vector is not a
//! subcommand, so the caller falls through to the mask parser.

use crate::agent;
use crate::caps::Caps;
use crate::isolate::Isolate;
use crate::secret;
use crate::store::{self, Passphrase, Store};
use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// The subcommand names.  `run` is handled by the caller (it is the mask
/// parser with secret options), so it is not listed here.
pub fn is_subcommand(word: &OsStr) -> bool {
    matches!(
        word.as_bytes(),
        b"store" | b"agent" | b"get" | b"read" | b"probe" | b"doctor" | b"help" | b"version"
    )
}

/// Run a subcommand.  `argv[0]` is the program name, `argv[1]` the
/// subcommand word.
pub fn dispatch(argv: &[OsString], mask_help: &str) -> i32 {
    let args = &argv[2..];
    match argv.get(1).map(|a| a.as_bytes()) {
        Some(b"store") => cmd_store(args),
        Some(b"agent") => cmd_agent(args),
        Some(b"get") => cmd_get(args),
        Some(b"read") => cmd_read(args),
        Some(b"probe") => cmd_probe(args),
        Some(b"doctor") => cmd_doctor(args),
        Some(b"help") => match args.first().map(|a| a.to_string_lossy().into_owned()) {
            // `pmask help <topic>` prints one section, so a reader does not
            // have to page the whole 13 KB for one option group.
            Some(topic) => help_topic(mask_help, &topic),
            None => {
                print!("{}", help(mask_help));
                0
            }
        },
        Some(b"version") => {
            println!("pmask {} ({})", crate::VERSION, crate::arch_name());
            0
        }
        _ => 255,
    }
}

fn help(mask_help: &str) -> String {
    format!(
        "{}\n{}",
        mask_help,
        SUBCOMMAND_HELP.replace("{version}", crate::VERSION)
    )
}

const SUBCOMMAND_HELP: &str = "\
Commands (the secret side; these work even where ptrace is refused):
  run [OPTIONS] [--] CMD  run a command; accepts every mask option, plus:
      --secret N=SRC        deliver a secret on descriptor 3, 4, ...; SRC is
                            file:PATH | env:VAR | agent:NAME | stdin | literal:VAL
                            (repeatable; PMASK_SECRET_<N> names the descriptor)
      --socket PATH         secret-agent socket for agent:NAME sources
      --isolate[=LIST]      private namespaces: pid,net,tmp | all | none
      --no-redact           never touch /proc metadata, even where ptrace works
  read NAME             print a secret that `run` delivered to this process
  store <sub>           the encrypted store:
      init | set NAME | get NAME | list | rm NAME | path
      --store PATH          store file (default: $XDG_DATA_HOME/pmask/store.enc)
      --passphrase-file P   read the passphrase from P
  agent [OPTIONS]       hold the store unlocked and serve it:
      --store PATH, --socket PATH, --passphrase-file P, --allow EXE
  get NAME [--socket P] ask a running agent for one secret
  probe [--json]        what this host allows, and what that means
  doctor [--json] [--require LIST]
                        the store, the agent and the verdict, in one report.
                        Exit 0 when every requested guarantee is active, 3
                        when one is degraded, 4 when one is unavailable.
                        LIST is any of redact, exact, isolate, secret-mem,
                        mlock, no-new-privs, non-dumpable, landlock.
";

// ------------------------------------------------------------------ probe

fn cmd_probe(args: &[OsString]) -> i32 {
    let mut json = false;
    for a in args {
        match a.as_bytes() {
            b"--json" => json = true,
            b"-h" | b"--help" => {
                println!("pmask probe [--json]");
                return 0;
            }
            _ => {
                eprintln!("pmask: probe: unknown option '{}'", a.to_string_lossy());
                return 255;
            }
        }
    }
    let caps = Caps::detect();
    if json {
        print!("{}", caps.report_json());
    } else {
        print!("{}", caps.report());
    }
    0
}

// ----------------------------------------------------------------- doctor

/// `pmask doctor [--json] [--require LIST]`
///
/// `--require` names guarantees the caller depends on: `redact`,
/// `isolate`, `exact`, `secret-mem`, `mlock`, `no-new-privs`,
/// `non-dumpable`, `landlock`.  The exit code is 0 when every requested
/// guarantee is active, 3 when one is degraded, and 4 when one is
/// unavailable, so a CI job asserts instead of assuming.
fn cmd_doctor(args: &[OsString]) -> i32 {
    let mut json = false;
    let mut require: Vec<String> = Vec::new();
    // A `--require` that names nothing (`--require ''`, `--require ,`) is
    // a usage error.  Accepting it would exit 0 and make a CI assertion
    // that was meant to fail pass silently (issue 29).
    let mut saw_require = false;
    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        match a.as_bytes() {
            b"--json" => json = true,
            b"-h" | b"--help" => {
                println!(
                    "pmask doctor [--json] [--require redact,isolate,exact,secret-mem,mlock,no-new-privs,non-dumpable,landlock]"
                );
                return 0;
            }
            b"--require" => match args.get(i + 1) {
                Some(v) => {
                    push_required(&v.to_string_lossy(), &mut require);
                    saw_require = true;
                    i += 1;
                }
                None => {
                    eprintln!("pmask: doctor: --require needs a list");
                    return 255;
                }
            },
            other if other.starts_with(b"--require=") => {
                let v = String::from_utf8_lossy(&other[b"--require=".len()..]).into_owned();
                push_required(&v, &mut require);
                saw_require = true;
            }
            _ => {
                eprintln!("pmask: doctor: unknown option '{}'", a.to_string_lossy());
                return 255;
            }
        }
        i += 1;
    }

    // An empty requirement is an assertion that anything passes: the CI
    // job that wrote `--require ''` gets exit 0 whatever this host lacks.
    // Refuse it rather than answer a question nobody asked.
    if saw_require && require.is_empty() {
        eprintln!(
            "pmask: doctor: --require needs at least one guarantee name; an empty list \
             asserts nothing (drop --require, or name redact, isolate, exact, secret-mem, \
             mlock, no-new-privs, non-dumpable or landlock)"
        );
        return 255;
    }

    let caps = Caps::detect();
    let verdict = verdict_of(&caps, &require);

    if json {
        print!("{}", doctor_json(&caps, &require, verdict));
        return verdict;
    }

    print!("{}", caps.report());

    println!("store:");
    let sp = store::default_path();
    match std::fs::metadata(&sp) {
        Ok(md) => {
            use std::os::unix::fs::PermissionsExt;
            println!(
                "  {} ({} bytes, mode {:04o})",
                sp.display(),
                md.len(),
                md.permissions().mode() & 0o777
            );
        }
        Err(_) => println!("  {} (not created yet)", sp.display()),
    }

    let sock = agent::default_socket();
    println!(
        "agent:\n  {} {}",
        sock.display(),
        if agent::ping(None) {
            "(answering)"
        } else {
            "(not running)"
        }
    );

    println!("\nverdict:");
    for name in &require {
        match guarantee(&caps, name) {
            Some(st) => println!(
                "  {:<14} {} ({})",
                name,
                st.as_word(),
                if st.reason().is_empty() {
                    "requested"
                } else {
                    st.reason()
                }
            ),
            None => println!("  {:<14} unknown guarantee", name),
        }
    }
    if require.is_empty() {
        if caps.ptrace {
            println!("  command lines can be redacted here (ptrace permitted)");
        } else {
            println!("  command lines CANNOT be redacted here (ptrace refused).");
            println!("  keep secrets out of argv: use --secret with file:/agent: sources,");
            println!("  which deliver over descriptors and work without ptrace.");
        }
        if caps.userns {
            println!("  --isolate is available (unprivileged user namespaces)");
        } else {
            println!("  --isolate is NOT available (no unprivileged user namespaces)");
        }
        println!("  tier={}", caps.tier_word());
    }

    let code = if require.is_empty() { 0 } else { verdict };
    match code {
        0 => {}
        3 => println!("\n  a requested guarantee is degraded here"),
        4 => println!("\n  a requested guarantee is unavailable here"),
        _ => {}
    }
    code
}

/// The state of a named guarantee, or `None` for a name this build does
/// not know.
fn guarantee(caps: &Caps, name: &str) -> Option<crate::caps::State> {
    let row = |want: &str| -> Option<crate::caps::State> {
        caps.rows()
            .into_iter()
            .find(|(n, _)| *n == want)
            .map(|(_, s)| s)
    };
    match name {
        "redact" => row("metadata redaction"),
        "exact" => row("exact cmdline window"),
        "isolate" => row("isolation"),
        "secret-mem" => row("memfd_secret"),
        "mlock" => row("mlock"),
        "no-new-privs" => row("no_new_privs"),
        "non-dumpable" => row("non-dumpable"),
        "landlock" => row("landlock"),
        // the report's own row names work too, so `--require` can name
        // whatever `probe` printed
        other => row(other),
    }
}

/// 0 when every requested guarantee is active, 3 when one is degraded,
/// 4 when one is unavailable, and 255 when a requested name is not one
/// this build knows.
fn verdict_of(caps: &Caps, require: &[String]) -> i32 {
    let mut worst = 0;
    for name in require {
        match guarantee(caps, name) {
            Some(crate::caps::State::Active) => {}
            Some(crate::caps::State::Degraded(_)) => worst = worst.max(3),
            Some(crate::caps::State::Unavailable(_)) => worst = worst.max(4),
            // A mechanism that cannot take effect because the mechanism it
            // belongs to is unavailable is a degraded guarantee, not an
            // active one: `--require=exact` on a host with no ptrace must
            // not report success for a redaction property (issue 13).
            Some(crate::caps::State::Inapplicable(_)) => worst = worst.max(3),
            None => worst = worst.max(255),
        }
    }
    worst
}

/// Add the guarantee names from one `--require` value, dropping empty
/// pieces so `--require a,,b` still names both.  Whether the value named
/// anything at all is decided by the caller, which also sees the values
/// of the other `--require` options.
fn push_required(value: &str, out: &mut Vec<String>) {
    for name in value.split(',') {
        let n = name.trim();
        if !n.is_empty() {
            out.push(n.to_string());
        }
    }
}

/// Escape a string for a JSON string literal.
///
/// Every string this module writes into a report by hand goes through
/// here: the store path and the agent socket path come from
/// `XDG_DATA_HOME`, `PMASK_STORE` and `PMASK_SOCKET`, and the
/// `--require` names come from argv, so `"`, `\` and a control byte are
/// all reachable from an environment the operator controls.  A control
/// byte becomes its `\u00XX` escape rather than a replacement character,
/// so the value still reads back as what the host reported.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The machine-readable form of `doctor`: the same rows as `probe
/// --json`, plus the store and agent lines and the per-request verdict.
///
/// Every string that came from outside this process is escaped; the
/// report must parse whatever the environment holds.
fn doctor_json(caps: &Caps, require: &[String], code: i32) -> String {
    let sp = store::default_path();
    let store_path = json_escape(&sp.display().to_string());
    let store_line = match std::fs::metadata(&sp) {
        Ok(md) => format!(
            "{{\"path\": \"{}\", \"bytes\": {}, \"exists\": true}}",
            store_path,
            md.len()
        ),
        Err(_) => format!("{{\"path\": \"{}\", \"exists\": false}}", store_path),
    };
    let sock = agent::default_socket();
    let mut wanted = String::new();
    for (i, name) in require.iter().enumerate() {
        if i > 0 {
            wanted.push(',');
        }
        let st = guarantee(caps, name);
        wanted.push_str(&format!(
            "\n    {{\"name\": \"{}\", \"state\": \"{}\"}}",
            json_escape(name),
            st.map(|s| s.as_word()).unwrap_or("unknown")
        ));
    }
    let base = caps.report_json();
    // splice the extra keys before the closing brace of the capability
    // report, so the two reports share one schema
    let body = base.trim_end().trim_end_matches('}');
    format!(
        "{},\n  \"store\": {},\n  \"agent\": {{\"socket\": \"{}\", \"answering\": {}}},\n  \"required\": [{}],\n  \"exit\": {}\n}}\n",
        body,
        store_line,
        json_escape(&sock.display().to_string()),
        agent::ping(None),
        wanted,
        code
    )
}

// ------------------------------------------------------------------ store

fn opt_value(args: &[OsString], i: &mut usize, flag: &str) -> Option<OsString> {
    match args.get(*i + 1) {
        Some(v) => {
            *i += 1;
            Some(v.clone())
        }
        None => {
            eprintln!("pmask: {} needs a value", flag);
            None
        }
    }
}

fn inline_arg<'a>(s: &'a [u8], flag: &str) -> Option<&'a [u8]> {
    let p = flag.as_bytes();
    if s.len() > p.len() && s.starts_with(p) && s[p.len()] == b'=' {
        Some(&s[p.len() + 1..])
    } else {
        None
    }
}

fn path_from(v: &OsStr) -> PathBuf {
    PathBuf::from(v)
}

const STORE_HELP: &str = "\
pmask store init|set NAME|get NAME|list|rm NAME|path \
 [--store PATH] [--passphrase-file PATH]

  init                  create the encrypted store (refuses an existing file)
  set NAME              read the value from stdin or --from-file and store it
  get NAME              print one stored value
  list                  print every stored name
  rm NAME               remove one stored name
  path                  print the store file path

  --store PATH          store file (default: $XDG_DATA_HOME/pmask/store.enc)
  --passphrase-file P   read the passphrase from P
  --from-file P         read the value for `set` from P instead of stdin

The passphrase is read from --passphrase-file, $PMASK_PASSPHRASE_FILE,
$PMASK_PASSPHRASE, or the terminal, in that order.";

const GET_HELP: &str = "\
pmask get NAME [--socket PATH]

Ask a running `pmask agent` for one secret and print it.  The name is the
one the agent holds in the encrypted store.";

fn cmd_store(args: &[OsString]) -> i32 {
    let mut path = store::default_path();
    let mut pass_file: Option<PathBuf> = None;
    let mut from_file: Option<PathBuf> = None;
    let mut positional: Vec<OsString> = Vec::new();
    let mut end_opts = false;
    let mut i = 0usize;
    while i < args.len() {
        let b = args[i].as_bytes();
        if end_opts || b.len() < 2 || b[0] != b'-' || b == b"-" {
            positional.push(args[i].clone());
            i += 1;
            continue;
        }
        if b == b"--" {
            end_opts = true;
            i += 1;
            continue;
        }
        if let Some(v) = inline_arg(b, "--store") {
            path = path_from(OsStr::from_bytes(v));
        } else if let Some(v) = inline_arg(b, "--passphrase-file") {
            pass_file = Some(path_from(OsStr::from_bytes(v)));
        } else if let Some(v) = inline_arg(b, "--from-file") {
            from_file = Some(path_from(OsStr::from_bytes(v)));
        } else {
            match b {
                b"--store" => match opt_value(args, &mut i, "--store") {
                    Some(v) => path = path_from(&v),
                    None => return 255,
                },
                b"--passphrase-file" => match opt_value(args, &mut i, "--passphrase-file") {
                    Some(v) => pass_file = Some(path_from(&v)),
                    None => return 255,
                },
                b"--from-file" => match opt_value(args, &mut i, "--from-file") {
                    Some(v) => from_file = Some(path_from(&v)),
                    None => return 255,
                },
                b"-h" | b"--help" => {
                    println!("{}", STORE_HELP);
                    return 0;
                }
                other => {
                    eprintln!(
                        "pmask: store: unknown option '{}' (see 'pmask store --help')",
                        String::from_utf8_lossy(other)
                    );
                    return 255;
                }
            }
        }
        i += 1;
    }

    let Some(sub) = positional.first().map(|s| s.to_string_lossy().into_owned()) else {
        eprintln!(
            "pmask: store needs a subcommand (init|set|get|list|rm|path; see 'pmask store --help')"
        );
        return 255;
    };
    positional.remove(0);
    // Refuse an unknown verb before the passphrase prompt: a typo must not
    // ask for the store's passphrase, and must not look like a hang.
    if !matches!(
        sub.as_str(),
        "init" | "set" | "get" | "list" | "rm" | "path"
    ) {
        eprintln!(
            "pmask: store: unknown subcommand '{}'; expected init, set, get, \
             list, rm or path (see 'pmask store --help')",
            sub
        );
        return 255;
    }
    if sub == "path" {
        println!("{}", path.display());
        return 0;
    }

    let pp = match resolve_passphrase(pass_file.as_deref(), sub == "init") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pmask: {}", e);
            return 255;
        }
    };

    match sub.as_str() {
        "init" => {
            if path.exists() {
                eprintln!("pmask: {} already exists", path.display());
                return 255;
            }
            match Store::create(&path, &pp) {
                Ok(_) => {
                    println!("created {}", path.display());
                    0
                }
                Err(e) => {
                    eprintln!("pmask: {}", e);
                    255
                }
            }
        }
        "set" => {
            let Some(name) = positional.first() else {
                eprintln!("pmask: store set needs a NAME");
                return 255;
            };
            let name = name.to_string_lossy().into_owned();
            let mut bytes = match &from_file {
                Some(p) => match std::fs::read(p) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("pmask: {}: {}", p.display(), e);
                        return 255;
                    }
                },
                None => {
                    let mut v = Vec::new();
                    if let Err(e) = io::stdin().read_to_end(&mut v) {
                        eprintln!("pmask: {}", e);
                        return 255;
                    }
                    v
                }
            };
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            let mut st = match open_or_create(&path, &pp) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("pmask: {}", e);
                    return 255;
                }
            };
            if let Err(e) = st.set(&name, &bytes) {
                eprintln!("pmask: {}", e);
                return 255;
            }
            use zeroize::Zeroize;
            bytes.zeroize();
            match st.save(&pp) {
                Ok(()) => {
                    println!("set {}", name);
                    0
                }
                Err(e) => {
                    eprintln!("pmask: {}", e);
                    255
                }
            }
        }
        "get" => {
            let Some(name) = positional.first() else {
                eprintln!("pmask: store get needs a NAME");
                return 255;
            };
            let st = match Store::open(&path, &pp) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("pmask: {}", e);
                    return 255;
                }
            };
            match st.get(&name.to_string_lossy()) {
                Some(v) => {
                    let mut out = io::stdout();
                    let _ = out.write_all(v);
                    let _ = out.write_all(b"\n");
                    0
                }
                None => {
                    eprintln!("pmask: no secret named '{}'", name.to_string_lossy());
                    1
                }
            }
        }
        "list" => {
            let st = match Store::open(&path, &pp) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("pmask: {}", e);
                    return 255;
                }
            };
            for n in st.names() {
                println!("{}", n);
            }
            0
        }
        "rm" => {
            let Some(name) = positional.first() else {
                eprintln!("pmask: store rm needs a NAME");
                return 255;
            };
            let name = name.to_string_lossy().into_owned();
            let mut st = match Store::open(&path, &pp) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("pmask: {}", e);
                    return 255;
                }
            };
            if !st.remove(&name) {
                eprintln!("pmask: no secret named '{}'", name);
                return 1;
            }
            match st.save(&pp) {
                Ok(()) => {
                    println!("removed {}", name);
                    0
                }
                Err(e) => {
                    eprintln!("pmask: {}", e);
                    255
                }
            }
        }
        other => {
            eprintln!("pmask: unknown store subcommand '{}'", other);
            255
        }
    }
}

fn open_or_create(path: &Path, pp: &Passphrase) -> io::Result<Store> {
    if path.exists() {
        Store::open(path, pp)
    } else {
        Store::create(path, pp)
    }
}

fn resolve_passphrase(explicit: Option<&Path>, creating: bool) -> io::Result<Passphrase> {
    if let Some(p) = explicit {
        return Passphrase::from_file(p);
    }
    if let Some(p) = std::env::var_os("PMASK_PASSPHRASE_FILE") {
        return Passphrase::from_file(&path_from(&p));
    }
    if let Some(v) = std::env::var_os("PMASK_PASSPHRASE") {
        eprintln!(
            "pmask: warning: PMASK_PASSPHRASE is set; it is visible in this process's environ"
        );
        return Passphrase::new(v.as_bytes());
    }
    prompt_passphrase(creating)
}

/// Read a passphrase from the controlling terminal with echo off.
fn prompt_passphrase(creating: bool) -> io::Result<Passphrase> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no terminal to ask for a passphrase; use --passphrase-file PATH \
                 or PMASK_PASSPHRASE_FILE",
            )
        })?;
    let fd = tty.as_raw_fd();
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr/tcsetattr on the descriptor of an open tty.
    let have_term = unsafe { libc::tcgetattr(fd, &mut term) } == 0;
    let orig = term;
    if have_term {
        term.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
    }
    let mut w = &tty;
    let prompt = if creating {
        "new passphrase: "
    } else {
        "passphrase: "
    };
    let _ = w.write_all(prompt.as_bytes());
    let _ = w.flush();

    let mut line = String::new();
    let mut r = io::BufReader::new(&tty);
    let res = r.read_line(&mut line);
    if have_term {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
    }
    let _ = w.write_all(b"\n");
    res?;
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
    let pp = Passphrase::new(line.as_bytes())?;
    use zeroize::Zeroize;
    line.zeroize();
    Ok(pp)
}

// ------------------------------------------------------------------ agent

fn cmd_agent(args: &[OsString]) -> i32 {
    let mut path = store::default_path();
    let mut sock = agent::default_socket();
    let mut pass_file: Option<PathBuf> = None;
    let mut allow: Vec<PathBuf> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let b = args[i].as_bytes();
        if let Some(v) = inline_arg(b, "--store") {
            path = path_from(OsStr::from_bytes(v));
        } else if let Some(v) = inline_arg(b, "--socket") {
            sock = path_from(OsStr::from_bytes(v));
        } else if let Some(v) = inline_arg(b, "--passphrase-file") {
            pass_file = Some(path_from(OsStr::from_bytes(v)));
        } else if let Some(v) = inline_arg(b, "--allow") {
            allow.push(path_from(OsStr::from_bytes(v)));
        } else {
            match b {
                b"--store" => match opt_value(args, &mut i, "--store") {
                    Some(v) => path = path_from(&v),
                    None => return 255,
                },
                b"--socket" => match opt_value(args, &mut i, "--socket") {
                    Some(v) => sock = path_from(&v),
                    None => return 255,
                },
                b"--passphrase-file" => match opt_value(args, &mut i, "--passphrase-file") {
                    Some(v) => pass_file = Some(path_from(&v)),
                    None => return 255,
                },
                b"--allow" => match opt_value(args, &mut i, "--allow") {
                    Some(v) => allow.push(path_from(&v)),
                    None => return 255,
                },
                b"-h" | b"--help" => {
                    println!(
                        "pmask agent [--store PATH] [--socket PATH] \
                         [--passphrase-file PATH] [--allow EXE]..."
                    );
                    return 0;
                }
                other => {
                    eprintln!(
                        "pmask: agent: unknown option '{}'",
                        String::from_utf8_lossy(other)
                    );
                    return 255;
                }
            }
        }
        i += 1;
    }
    let pp = match resolve_passphrase(pass_file.as_deref(), false) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pmask: {}", e);
            return 255;
        }
    };
    // The store is decrypted through `Daemon::open`, which hardens this
    // process first: opening it here would leave plaintext in a dumpable
    // process for the whole of `Store::open`.
    let mut config = agent::AgentConfig::new(sock);
    for entry in allow {
        let text = entry.as_os_str().to_string_lossy().into_owned();
        if text.contains(':') {
            match agent::PolicyRule::parse(&text) {
                Ok(rule) => config.policy.add_rule(rule),
                Err(e) => {
                    eprintln!("pmask: agent: --allow: {}", e);
                    return 255;
                }
            }
        } else {
            config.policy.allow_exact(entry);
        }
    }
    match agent::Daemon::open(&path, &pp, config).and_then(|d| d.serve()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("pmask: agent: {}", e);
            255
        }
    }
}

// -------------------------------------------------------------------- get

fn cmd_get(args: &[OsString]) -> i32 {
    let mut sock: Option<PathBuf> = None;
    let mut name: Option<String> = None;
    let mut end_opts = false;
    let mut i = 0usize;
    while i < args.len() {
        let b = args[i].as_bytes();
        if end_opts || b.len() < 2 || b[0] != b'-' || b == b"-" {
            if name.is_some() {
                eprintln!("pmask: get takes one NAME (see 'pmask get --help')");
                return 255;
            }
            name = Some(args[i].to_string_lossy().into_owned());
            i += 1;
            continue;
        }
        if b == b"--" {
            end_opts = true;
        } else if let Some(v) = inline_arg(b, "--socket") {
            sock = Some(path_from(OsStr::from_bytes(v)));
        } else if b == b"--socket" {
            match opt_value(args, &mut i, "--socket") {
                Some(v) => sock = Some(path_from(&v)),
                None => return 255,
            }
        } else if b == b"-h" || b == b"--help" {
            println!("{}", GET_HELP);
            return 0;
        } else {
            eprintln!(
                "pmask: get: unknown option '{}' (see 'pmask get --help')",
                String::from_utf8_lossy(b)
            );
            return 255;
        }
        i += 1;
    }
    let Some(name) = name else {
        eprintln!("pmask: get needs a NAME (see 'pmask get --help')");
        return 255;
    };
    match agent::fetch(sock.as_ref(), &name) {
        Ok(v) => {
            let mut out = io::stdout();
            let _ = out.write_all(v.as_slice());
            let _ = out.write_all(b"\n");
            0
        }
        Err(e) => {
            eprintln!("pmask: {}", e);
            1
        }
    }
}

// ------------------------------------------------------------------- read

/// Read a secret that `pmask run` delivered to this process, by name.
/// `pmask read [--fd N] [--no-newline] [--tty] NAME`
///
/// Prints the value of a secret `run` delivered to this process.  The
/// descriptor is shared with the parent, so its offset persists: the read
/// seeks to the start first, which makes a second read in the same tree
/// return the whole value instead of nothing.  The buffer is zeroised
/// before return, the descriptor is closed, and a newline is added only
/// when the value does not already end with one.
fn cmd_read(args: &[OsString]) -> i32 {
    let mut name: Option<String> = None;
    let mut explicit_fd: Option<libc::c_int> = None;
    let mut newline: Option<bool> = None;
    let mut allow_tty = false;
    let mut i = 0usize;
    while i < args.len() {
        let b = args[i].as_bytes();
        match b {
            b"--no-newline" => {
                newline = Some(false);
            }
            b"--newline" => {
                newline = Some(true);
            }
            b"--tty" => {
                allow_tty = true;
            }
            b"--fd" => match args.get(i + 1) {
                Some(v) => match v.to_string_lossy().parse::<libc::c_int>() {
                    Ok(n) if n >= 0 => {
                        explicit_fd = Some(n);
                        i += 1;
                    }
                    _ => {
                        eprintln!("pmask: read: --fd needs a descriptor number");
                        return 255;
                    }
                },
                None => {
                    eprintln!("pmask: read: --fd needs a descriptor number");
                    return 255;
                }
            },
            b"-h" | b"--help" => {
                println!("pmask read [--fd N] [--no-newline|--newline] [--tty] NAME");
                return 0;
            }
            other if other.starts_with(b"--fd=") => {
                let v = String::from_utf8_lossy(&other[b"--fd=".len()..]);
                match v.parse::<libc::c_int>() {
                    Ok(n) if n >= 0 => explicit_fd = Some(n),
                    _ => {
                        eprintln!("pmask: read: --fd needs a descriptor number");
                        return 255;
                    }
                }
            }
            other if other.starts_with(b"-") && other.len() > 1 => {
                eprintln!(
                    "pmask: read: unknown option '{}'",
                    String::from_utf8_lossy(other)
                );
                return 255;
            }
            _ => {
                if name.is_some() {
                    eprintln!("pmask: read takes one NAME");
                    return 255;
                }
                name = Some(args[i].to_string_lossy().into_owned());
            }
        }
        i += 1;
    }

    let fd = match explicit_fd {
        Some(n) => n,
        None => {
            let Some(name) = name.as_deref() else {
                eprintln!("pmask: read needs a NAME or --fd N");
                return 255;
            };
            let var = secret::env_var_for(name);
            let fd_s = match std::env::var(&var) {
                Ok(v) => v,
                Err(_) => {
                    eprintln!(
                        "pmask: no secret named '{}' in this process ({} is not set)",
                        name, var
                    );
                    return 1;
                }
            };
            match fd_s.parse::<libc::c_int>() {
                Ok(v) => v,
                Err(_) => {
                    eprintln!("pmask: {} holds '{}', not a descriptor", var, fd_s);
                    return 255;
                }
            }
        }
    };

    // SAFETY: fstat on a descriptor the caller was told about by `run`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        eprintln!("pmask: read fd {}: {}", fd, io::Error::last_os_error());
        return 1;
    }
    // SAFETY: isatty takes the descriptor number only.
    let tty = unsafe { libc::isatty(fd) } == 1 || unsafe { libc::isatty(1) } == 1;
    if tty && !allow_tty {
        eprintln!("pmask: refusing to write a secret to a terminal; pass --tty if you are sure");
        return 2;
    }

    // The descriptor is the same open file description the parent made, so
    // its offset survives an exec and is shared with every other reader.
    // Seeking first is what makes a second `pmask read` work.
    // SAFETY: lseek on the caller's descriptor.
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ESPIPE) {
            eprintln!("pmask: read fd {}: cannot rewind: {}", fd, e);
            return 1;
        }
        // A pipe cannot seek; the value is still readable once.
    }

    let mut out = io::stdout();
    let mut buf = [0u8; 8192];
    let mut last_byte = 0u8;
    let mut wrote = 0usize;
    let mut rc = 0i32;
    loop {
        // SAFETY: reading into a local buffer through the caller's
        // descriptor.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("pmask: read fd {}: {}", fd, e);
            rc = 1;
            break;
        }
        let chunk = &buf[..n as usize];
        last_byte = chunk[chunk.len() - 1];
        if out.write_all(chunk).is_err() {
            rc = 1;
            break;
        }
        wrote += chunk.len();
    }
    // The plaintext stays on this stack until something reuses the frame;
    // a process whose whole job is to print a secret should not leave it.
    buf.zeroize();
    // SAFETY: close the caller's descriptor; nothing later reads it.
    unsafe { libc::close(fd) };

    if rc == 0 {
        let add = match newline {
            Some(v) => v,
            // Default: complete the line only when the value is not
            // already one, so `| tool` receives the bytes as written.
            None => wrote > 0 && last_byte != b'\n',
        };
        if add {
            let _ = out.write_all(b"\n");
        }
        let _ = out.flush();
    }
    rc
}

/// Parse `--isolate[=LIST]`.
///
/// `all`, `none` and a comma-separated subset of `pid`, `net` and `tmp`
/// are the only accepted spellings.  `none` means no isolation at all and
/// is a distinct value ([`Isolate::none`]) rather than "all three fields
/// false", which would still create the unconditional namespaces.
pub fn parse_isolate(v: &[u8]) -> Option<Isolate> {
    if v == b"all" || v.is_empty() {
        return Some(Isolate::all());
    }
    if v == b"none" {
        return Some(Isolate::none());
    }
    let mut iso = Isolate::minimal();
    for part in v.split(|&b| b == b',') {
        match part {
            b"pid" => iso.pid = true,
            b"net" => iso.net = true,
            b"tmp" => iso.private_tmp = true,
            _ => return None,
        }
    }
    Some(iso)
}

// ------------------------------------------------------------- help text

/// One option of the short help index.  The table is explicit because
/// parsing the long text back out of its columns is how an option ends up
/// listed under a name it does not have.  `short_help_names_are_in_the_
/// full_text` keeps the two in step.
pub const SHORT_HELP: &[(&str, &str)] = &[
    (
        "-l, --label NAME",
        "presentation label for every process' /proc entry",
    ),
    ("--label-empty", "empty label: cmdline shows nothing"),
    (
        "--argv0 NAME",
        "argv[0] of the program (default: the command as typed)",
    ),
    ("--comm NAME", "comm name for top, at most 15 bytes"),
    ("--keep-env", "leave /proc/<pid>/environ visible"),
    (
        "--keep-env=NAME[,NAME...]",
        "keep only the named variables visible",
    ),
    ("--env K=V", "add or replace one variable for the program"),
    ("--env-file PATH", "read KEY=VALUE lines from a file"),
    ("--args-from-fd N", "read the command from descriptor N"),
    (
        "--on-exit POLICY",
        "what happens to descendants: detach, wait or kill",
    ),
    ("--no-follow", "redact the direct child only"),
    ("--no-exit-kill", "let the tree survive pmask's own death"),
    (
        "--no-dumpable",
        "PR_SET_DUMPABLE=0 in every process of the tree",
    ),
    ("--no-new-privs", "set no_new_privs before exec"),
    ("--no-exact", "keep the original cmdline byte extent"),
    (
        "--detach",
        "PTRACE_DETACH each process after its exec settles",
    ),
    (
        "--watch-rename",
        "keep the label as comm across PR_SET_NAME",
    ),
    (
        "--rexec",
        "exec from a sealed memfd so /proc/<pid>/exe is the label",
    ),
    (
        "--rexec-allow-disk",
        "on-disk path as the explicit last resort",
    ),
    ("--image PATH", "exec the ELF image in PATH"),
    ("--image-from-fd N", "exec the ELF image on descriptor N"),
    ("--exec-once", "reuse one sealed image per distinct program"),
    ("--hugetlb", "ask for a hugetlb-backed image"),
    (
        "--unshare",
        "new user, pid and mount namespaces with a private /proc",
    ),
    ("--scope-name NAME", "re-exec through systemd-run --scope"),
    ("-q, --quiet", "suppress diagnostics"),
    ("-v, --verbose", "trace every redaction event to stderr"),
    ("-V, --version", "print version"),
    (
        "-h, --help",
        "print this index (--help prints the full text)",
    ),
    (
        "--secret NAME=SRC",
        "deliver a secret on descriptor 3, 4, ...",
    ),
    (
        "--socket PATH",
        "secret-agent socket for agent:NAME sources",
    ),
    (
        "--isolate[=LIST]",
        "fresh namespaces: pid,net,tmp | all | none",
    ),
    (
        "--audit",
        "one residue row per tracee, then a residue count",
    ),
    (
        "--redact",
        "ask for /proc redaction explicitly (the default)",
    ),
    ("--no-redact", "never touch /proc metadata"),
    (
        "--allow-argv-secret",
        "allow a literal:/env: source where /proc is not redacted",
    ),
    (
        "--secret-close-on-exec",
        "close the descriptor in each descendant at its fork",
    ),
    ("--secret-burn", "let the reader truncate a value to zero"),
    ("--report=json", "print the run as one JSON object"),
    (
        "--report-file PATH",
        "write that object to PATH instead of stdout",
    ),
    ("--report-fd N", "write that object to descriptor N"),
];

/// The short form of the mask help: usage, every option and a one-line
/// summary each, so a terminal reader gets an index instead of the full
/// text.  `--help=short` and `pmask help short` print it.
pub fn short_help(mask_help: &str) -> String {
    let mut out = String::new();
    out.push_str(
        mask_help
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("pmask")
            .trim_end(),
    );
    out.push_str("\n\nUsage: pmask [OPTIONS] [--] COMMAND [ARGS...]\n");
    out.push_str("       pmask [OPTIONS] --args-from-fd N\n");
    out.push_str("       pmask [OPTIONS] --image PATH [ARGS...]\n\n");
    out.push_str("Options (see `pmask --help` or `man pmask` for the full text):\n");
    for (name, doc) in SHORT_HELP {
        out.push_str(&format!("  {:<26} {}\n", name, doc));
    }
    out.push_str(
        "\n`pmask --help` prints the full text; `pmask help <topic>` prints one section\n\
         (redact, isolate, secret, report, daemon, short).\n",
    );
    out
}

/// Print one help topic over the mask help text.  Returns 0 for a known
/// topic, 255 for an unknown one after printing the index, so a typo stays
/// visible to a script.
///
/// The full text is parsed into option blocks (a header line at the option
/// indent, then its continuation lines), so a topic prints the whole block
/// including the prose that wraps.  A substring match over single lines
/// would print a continuation line of a block it did not select.
pub fn help_topic(mask_help: &str, topic: &str) -> i32 {
    if topic == "short" {
        print!("{}", short_help(mask_help));
        return 0;
    }
    let want: &[&str] = match topic {
        "redact" => &["--label", "--argv0", "--comm", "--keep-env", "--no-exact"],
        "isolate" => &["--isolate", "--redact", "--no-redact", "--unshare"],
        "secret" => &[
            "--secret",
            "--socket",
            "--secret-burn",
            "--secret-close-on-exec",
        ],
        "report" => &["--report", "--report-file", "--report-fd", "--audit"],
        "daemon" => &["--daemon"],
        _ => {
            print!("{}", short_help(mask_help));
            eprintln!(
                "pmask: help: unknown topic '{}'; try redact, isolate, secret, report, \
                 daemon or short",
                topic
            );
            return 255;
        }
    };
    let blocks = option_blocks(mask_help);
    let mut printed = 0usize;
    for (name, block) in &blocks {
        if want.contains(&name.as_str()) {
            print!("{}", block);
            printed += 1;
        }
    }
    if printed == 0 {
        eprintln!(
            "pmask: help: the topic '{}' names no option in this build; see `pmask --help`",
            topic
        );
        return 255;
    }
    0
}

/// Split the full help into `(option name, full block)` pairs.  An option
/// header is a line that starts with `-` after two or six spaces of
/// indent; its block runs until the next header or a blank line.
fn option_blocks(mask_help: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in mask_help.lines() {
        let indent = line.len() - line.trim_start().len();
        let t = line.trim_start();
        let is_header = (indent == 2 || indent == 6) && t.starts_with('-');
        if is_header {
            if let Some(entry) = current.take() {
                out.push(entry);
            }
            let name = t
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches(',')
                .to_string();
            current = Some((name, format!("{}\n", line)));
        } else if let Some((_, block)) = current.as_mut() {
            if line.trim().is_empty() {
                out.push(current.take().expect("checked above"));
            } else {
                block.push_str(line);
                block.push('\n');
            }
        }
    }
    if let Some(entry) = current {
        out.push(entry);
    }
    out
}

#[cfg(test)]
mod short_help_tests {
    use super::*;

    /// The full help text, read from the parser's own source.  The binary
    /// crate owns `HELP` and the library must not depend on a bin, so the
    /// test reads the file the const lives in.
    fn mask_help_for_test() -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cli.rs");
        std::fs::read_to_string(path).unwrap_or_default()
    }

    // A short index that drifts from the long text is worse than no
    // index: a reader trusts it and misses the option they needed.  Every
    // entry's first spelling has to appear in the full help.
    #[test]
    fn short_help_names_are_in_the_full_text() {
        let full = mask_help_for_test();
        assert!(full.contains("--secret"), "the help source was not read");
        for (name, _) in SHORT_HELP {
            let first = name.split_whitespace().next().unwrap_or("");
            let bare = first.trim_end_matches(',');
            assert!(
                full.contains(bare),
                "short help names {:?}, which the full text does not",
                bare
            );
        }
    }

    // Every entry has to be an option spelling, not prose, or the index
    // reads as an option that does not exist.
    #[test]
    fn every_short_entry_is_an_option_spelling() {
        let full = mask_help_for_test();
        assert!(full.contains("--report-fd"));
        for (name, doc) in SHORT_HELP {
            let first = name.split_whitespace().next().unwrap_or("");
            let bare = first.trim_end_matches(',');
            assert!(bare.starts_with('-'), "{:?} is not an option", name);
            assert!(!doc.is_empty(), "{} has no description", name);
        }
    }

    #[test]
    fn unknown_topic_is_not_a_success() {
        // A topic the code does not know must not exit 0, or a script
        // asking for a section silently gets the index.
        assert_eq!(help_topic("pmask help", "no-such-topic"), 255);
    }

    #[test]
    fn known_topics_print_their_block() {
        let full = mask_help_for_test();
        assert_eq!(help_topic(&full, "isolate"), 0);
        assert_eq!(help_topic(&full, "report"), 0);
    }

    #[test]
    fn parse_isolate_distinguishes_none_from_empty() {
        // issue 26: `none` must not be "all three switches off", which
        // still creates the unconditional namespaces.
        let none = parse_isolate(b"none").expect("none parses");
        assert!(none.none);
        assert!(parse_isolate(b"pid=0").is_none(), "a bad spelling parses");
        let one = parse_isolate(b"pid").expect("pid parses");
        assert!(!one.none);
        assert!(one.pid && !one.net && !one.private_tmp);
        let all = parse_isolate(b"all").expect("all parses");
        assert!(!all.none);
        assert!(all.pid && all.net && all.private_tmp);
    }
    #[test]
    fn json_escape_covers_every_byte_json_forbids_in_a_string() {
        // The three that reach this module from the environment: the quote
        // (XDG_DATA_HOME), the backslash (a Windows-style path or a
        // templating artefact) and the control byte.
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("a\rb"), "a\\rb");
        assert_eq!(json_escape("a\tb"), "a\\tb");
        assert_eq!(json_escape("a\x08b"), "a\\bb");
        assert_eq!(json_escape("a\x0cb"), "a\\fb");
        assert_eq!(json_escape("a\x01b"), "a\\u0001b");
        // Printable and non-ASCII characters pass through unchanged, so a
        // path keeps the bytes the host reported.
        assert_eq!(json_escape("/tmp/plain"), "/tmp/plain");
        assert_eq!(json_escape("/tmp/naïve"), "/tmp/naïve");
    }

    /// Count the `"` bytes that are not preceded by an odd number of
    /// backslashes: a well-formed JSON string has exactly two per string.
    fn unescaped_quotes(s: &str) -> usize {
        let mut n = 0usize;
        let mut escaped = false;
        for c in s.chars() {
            match c {
                '\\' if !escaped => escaped = true,
                '"' if !escaped => {
                    n += 1;
                    escaped = false;
                }
                _ => escaped = false,
            }
        }
        n
    }

    #[test]
    fn a_quoted_store_path_survives_the_report() {
        // The issue's reproducer: XDG_DATA_HOME with a `"` in it.  The
        // value must appear escaped, and no bare `"` may reach the report.
        // `"path"`, the value string and `"exists"` are the only three
        // string literals, so six unescaped quotes is a well-formed line.
        let name = "qa\"path";
        let line = format!(
            "{{\"path\": \"{}\", \"exists\": false}}",
            json_escape(&format!("/tmp/{}/pmask/store.enc", name))
        );
        assert_eq!(unescaped_quotes(&line), 6, "{}", line);
        assert!(line.contains("qa\\\"path"), "{}", line);
    }

    #[test]
    fn push_required_drops_empty_pieces_and_keeps_names() {
        let mut out = Vec::new();
        push_required("redact,, isolate", &mut out);
        assert_eq!(out, vec!["redact".to_string(), "isolate".to_string()]);
        let mut none = Vec::new();
        push_required("", &mut none);
        push_required(" , ", &mut none);
        assert!(none.is_empty());
    }
}
