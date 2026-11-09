//! `pmask` CLI: thin wrapper over the library session API, plus a
//! client for a running `pmaskd`.

use pmask::ExitState;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicI32, Ordering};

mod cli;

/// pid of the supervised child, for the signal proxy
static CHILD: AtomicI32 = AtomicI32::new(0);

extern "C" fn proxy(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

extern "C" fn ignore_sigpipe(_: libc::c_int) {}

fn install_handlers() {
    const PROXIED: [libc::c_int; 7] = [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGWINCH,
    ];
    unsafe {
        for s in PROXIED {
            libc::signal(s, proxy as *const () as usize);
        }
        libc::signal(libc::SIGPIPE, ignore_sigpipe as *const () as usize);
    }
}

/// Exit the way the supervised program did.
fn finish(st: ExitState) -> ! {
    if let Some(sig) = st.signal {
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
///
/// Measured (`evidence/bteam1/39/window-measure.log`): the escape is
/// honoured on the plain path, and overridden on every path that runs the
/// secret-side runner — the redact and isolate branches of `run` apply
/// the self-mask unconditionally after the fork.  So the exposure is
/// "for the whole run" in plain mode and "until the self-mask runs" in
/// redact mode, and the warning must say which, or it is a claim the
/// measurement refutes.
///
/// In plain mode the value stays in this process's argv for the whole
/// run.  On a host whose audit subsystem answers, the supervisor's own
/// exec is also written to the audit log, so the exposure becomes a
/// durable record; that combination is refused unless
/// `--allow-argv-secret` accepts it.  Where audit is blocked
/// (containers, most CI sandboxes) a refusal would only make the
/// documented escape unusable, so the run warns instead.  The warning
/// ignores `-q`: a quiet run that publishes a secret is the silent
/// degradation invariant 13 forbids.
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
    // The same selection rule `run` uses, so the message describes the
    // mode this invocation will actually take.
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
             environment only until then, not for the whole run; keep the command out of the \
             supervisor's argv with --args-from-fd, or use file:PATH or agent:NAME",
            mode.as_str(),
            list
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
         every local account can read it.  Keep the command out of the supervisor's argv with \
         --args-from-fd, or use file:PATH or agent:NAME",
        mode.as_str(),
        list
    );
}

/// `--keep-env` and `--keep-env=NAME` leave `/proc/<pid>/environ` visible
/// on purpose.  An `env:` secret source reads its value from the
/// environment, so those two asks contradict each other: the operator
/// asked to hide the value and to publish the place it lives.
///
/// Only `env:` is warned about, and that is a measurement, not a
/// simplification: the payload's environment carries the variable itself
/// plus `PMASK_SECRET_<N>=<fd>`, never a `literal:` value (see
/// `evidence/bteam1/41/`).  A `literal:` value lives in the supervisor's
/// own argv, which the self-mask removes; `--keep-env` does not publish
/// it, so warning there would be false.
///
/// The variables are still kept.  This is a warning, not a refusal:
/// keeping them is the documented behaviour of the flag.
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

/// Re-exec once through `systemd-run --scope`.  The re-exec argv has no
/// `--scope-name`, so the second run cannot take this path again.
fn reexec_in_scope(name: &str, reexec_argv: &[std::ffi::OsString], quiet: bool) {
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
    // exec only returns on failure
    let e = cmd.exec();
    if !quiet {
        eprintln!("pmask: --scope-name unavailable: {}, continuing", e);
    }
}

/// The secret side of a local run: descriptor delivery, isolation, or a
/// forced plain exec.  Every mask option parsed from the command line is
/// handed to the session as-is, so `--secret` composes with `--comm`,
/// `--rexec`, `--unshare`, `--no-dumpable` and the rest.
fn run_with_secrets(cli: cli::Cli) -> i32 {
    use pmask::run::{Mode, Runner};
    let mut r = Runner::new().mask(cli.mask);
    for (name, src) in &cli.secrets {
        r = r.secret(name.clone(), src.clone());
    }
    // `--env` and `--env-file` are already on the mask, which covers the
    // redaction mode.  The runner also needs them for the isolate and
    // plain modes, which build their own environment.
    for (k, v) in &cli.env_overrides {
        r = r.env(k.clone(), v.clone());
    }
    // The mask carries the label for the redaction mode.  The runner keeps
    // its own copy so a mode that cannot redact can say the label was not
    // applied instead of dropping it silently.
    match &cli.remote_label {
        pmask::daemon::RemoteLabel::Text(t) => r = r.label(t.clone()),
        pmask::daemon::RemoteLabel::Empty => r = r.label(""),
        pmask::daemon::RemoteLabel::Default => {}
    }
    if let Some(sock) = &cli.agent_socket {
        r = r.daemon_socket(sock.clone());
    }
    if let Some(iso) = cli.isolate {
        r = r.isolate(iso);
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
    if cli.no_dumpable {
        r = r.no_dumpable(true);
    }
    match r.run(&cli.program, &cli.args) {
        Ok(outcome) => {
            if cli.report_json {
                print!("{}", outcome.report_json());
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
                // SAFETY: the default handler for a signal the program
                // died from always terminates this process.
                unsafe {
                    libc::signal(sig, libc::SIG_DFL);
                    libc::raise(sig);
                }
            }
            outcome.exit.code
        }
        Err(e) => {
            eprintln!("pmask: {}", e);
            255
        }
    }
}

fn main() {
    // Take an owned copy of the argument vector, then remove the bytes the
    // kernel serves from /proc/<pid>/cmdline.  This is the earliest point a
    // supervisor can redact itself; everything after it (option parsing,
    // executable resolution, probes) runs with the secret already gone
    // from the process table.
    let mut argv = pmask::mask::snapshot_argv();
    if std::env::var_os("PMASK_NO_SELFMASK").is_none() {
        let _ = pmask::mask::zero_argv_block();
    }

    // The secret-side subcommands (store, agent, read, probe, ...).  Each
    // one is a distinct verb; the default face of the program is the mask.
    if argv.len() >= 2 && pmask::subcmd::is_subcommand(&argv[1]) {
        std::process::exit(pmask::subcmd::dispatch(&argv, &cli::help_text()));
    }
    // `pmask run ...` is the mask parser with the secret options; the
    // word is dropped so both spellings share one implementation.
    if argv.len() >= 2 && argv[1].as_bytes() == b"run" {
        argv.remove(1);
        if argv.iter().any(|a| a.as_bytes() == b"--run-help") {
            print!("{}", cli::help_text());
            std::process::exit(0);
        }
    }
    let mut cli = cli::parse_from(argv);

    // The two spellings ask for opposite treatments of the same surface.
    if cli.redact && cli.no_redact {
        eprintln!("pmask: --redact and --no-redact contradict each other; pass one");
        std::process::exit(255);
    }

    // `--daemon` hands the job to a pmaskd, which owns the masking
    // policy and builds the job environment itself.  A flag that changes
    // what this process would do locally cannot be honoured there, and a
    // secret that is silently not delivered is worse than a refusal.
    if cli.daemon.is_some() {
        let mut local_only: Vec<&str> = Vec::new();
        if !cli.secrets.is_empty() {
            local_only.push("--secret");
        }
        if cli.isolate.is_some() {
            local_only.push("--isolate");
        }
        if cli.no_redact {
            local_only.push("--no-redact");
        }
        if cli.mask.has_image() {
            local_only.push("--image");
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

    // `--redact --isolate` is the composed spelling of `--unshare`: the
    // redaction path with a private pid namespace and procfs.  The pair is
    // accepted here, before `needs_runner`, so the run takes the redaction
    // path instead of the namespace-only isolate path.
    if cli.redact && cli.isolate.is_some() {
        cli.mask = cli.mask.unshare();
        cli.isolate = None;
    }

    // `--audit` describes the tree the tracer owns.  A mode without a
    // tracer has no tree to describe, so refuse rather than print nothing.
    if cli.audit && (cli.no_redact || cli.isolate.is_some()) {
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

    // `--report=json` is produced by the secret-side runner.  The plain
    // mask path and the `--daemon` client have no report to print, and a
    // flag that is silently dropped is a degradation the operator cannot
    // see (invariant 13), so name the mode and refuse.  This runs before
    // the scope re-exec and `--args-from-fd`: neither can make the run
    // produce a report, and the scope and the descriptor must not be
    // consumed for a command that cannot work.
    if cli.report_json && !cli.needs_runner() {
        if cli.daemon.is_some() {
            eprintln!(
                "pmask: --report=json: a --daemon job does not produce a report; the \
                 daemon owns the run, so drop --report"
            );
        } else {
            eprintln!(
                "pmask: --report=json: the plain mask path does not produce a report; the \
                 report describes a secret-side run, so add --secret, --isolate or --no-redact, \
                 or drop --report"
            );
        }
        std::process::exit(255);
    }

    // The scope re-exec replaces this process, so it runs before anything
    // consumes `--args-from-fd`: the new process reads the descriptor.
    // Daemon mode is not re-exec'd; the daemon owns the scope.
    if cli.daemon.is_none() {
        if let Some(name) = cli.scope_name.clone() {
            reexec_in_scope(&name, &cli.reexec_argv, cli.quiet);
        }
    }
    // Two documented escapes publish the place a `literal:` or `env:`
    // secret lives: `PMASK_NO_SELFMASK` leaves the supervisor's own
    // /proc entry real, and `--keep-env` leaves the payload's environ
    // visible.  Name the exposure before any secret is read, so the
    // operator can still change the command.  This runs after every
    // refusal that makes the run impossible (`--daemon` with a local-only
    // flag, a contradictory `--redact`/`--no-redact`, `--report` on a
    // path with no report), so a warning never describes a run that will
    // not happen.  The check is CLI policy; a library caller chooses for
    // itself.
    let no_selfmask = std::env::var_os("PMASK_NO_SELFMASK").is_some();
    check_no_selfmask(&cli, no_selfmask);
    warn_keep_env_secret(&cli);

    // Read the command before every path that needs it: the runner path
    // and the mask path both consume it, so `--secret` with
    // `--args-from-fd` runs the program the descriptor names.
    cli.load_args_fd();

    if cli.needs_runner() {
        std::process::exit(run_with_secrets(cli));
    }

    // `--secret-fd-name` with no `--secret` is the one name option the
    // mask path cannot report: the descriptor name is applied by the
    // runner, which is not reached here.  `--memfd-name` is reported by
    // `Mask::to_config`, which every local run goes through.
    if !cli.quiet && cli.mask.secret_fd_name_value().is_some() {
        eprintln!(
            "pmask: --secret-fd-name has no effect: no --secret was given, so no \
             descriptor is delivered"
        );
    }

    if let Some(socket) = cli.daemon.take() {
        // Remote mode: the daemon holds the environment and supervises
        // the job; this process only forwards argv, stdio and the result.
        warn_daemon_options(&cli.mask_opts, cli.quiet);
        if let pmask::daemon::RemoteLabel::Text(t) = &cli.remote_label {
            if let Err(e) = pmask::mask::validate_label(t) {
                eprintln!("pmask: {}", e);
                std::process::exit(255);
            }
        }
        let argv = pmask::daemon::client_argv(&cli.program, &cli.args);
        let path = std::path::Path::new(&socket);
        match pmask::daemon::run_remote(path, cli.remote_label, &argv) {
            Ok(st) => finish(st),
            Err(e) => {
                eprintln!(
                    "pmask: daemon {}: {}",
                    std::path::Path::new(&socket).display(),
                    e
                );
                std::process::exit(255);
            }
        }
    }

    // Local mode.  Order matters: build the exec plan (argv and a
    // snapshot of the environment) first, redact this process, and only
    // then fork.  The secrets are never in this process's argv or
    // environ once the fork has happened.
    let prepared = match cli.mask.prepare(&cli.program, &cli.args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pmask: {}: {}", cli.program.to_string_lossy(), e);
            std::process::exit(255);
        }
    };

    if !no_selfmask {
        if let Err(e) = prepared.mask_self() {
            if !cli.quiet {
                eprintln!(
                    "pmask: warning: the supervisor's own /proc entry could not be fully \
                     treated: {}",
                    e
                );
            }
        }
    }

    let child = match cli.mask.spawn_prepared(prepared) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("pmask: {}: {}", cli.program.to_string_lossy(), e);
            std::process::exit(255);
        }
    };

    CHILD.store(child.id() as i32, Ordering::Relaxed);
    install_handlers();

    match child.wait() {
        Ok(st) => finish(st),
        Err(e) => {
            eprintln!("pmask: session error: {}", e);
            std::process::exit(255);
        }
    }
}
