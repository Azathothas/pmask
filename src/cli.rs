//! CLI argument parsing for `pmask`.

use pmask::audit::{ObserverRole, Profile};
use pmask::daemon::RemoteLabel;
use pmask::isolate::Isolate;
use pmask::mask::Mask;
use pmask::secret::Source;
use pmask::{RexecMode, SessionEnd};
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::exit;
use zeroize::{Zeroize, Zeroizing};

pub const HELP: &str = r#"
pmask {version} ({arch}) - redact the /proc metadata of a process or process tree

Run COMMAND with a presentation label in place of its real command line,
environment and process name as seen through /proc (and therefore ps, top,
htop, btop and any other process monitor).  Programs keep their real
argv/envp and work normally.

Use it to keep secrets off the process table: tokens, passwords or internal
hostnames passed as arguments are otherwise readable by every local account
that can run `ps`, for the whole lifetime of a process.

Usage: pmask [OPTIONS] [--] COMMAND [ARGS...]
       pmask [OPTIONS] --args-from-fd N
       pmask [OPTIONS] --image PATH [ARGS...]
       pmask --explain [--profile NAME] [--label NAME] [--json]
       pmask --audit [--pid PID] [--profile NAME] [--observer ROLE] [--json]
       pmask --profile-json [--pid PID] [--profile NAME] [--label NAME]

Profiles:
      --profile NAME   Select an execution and stealth profile:
                         auto   (default) single for native ELFs, tree for
                                shells, launchers, #! scripts, and tree flags.
                         single (#1 strongest single-process shape) In-place
                                masked exec with a transient helper: zero
                                persistent supervisor, TracerPid: 0,
                                Threads: 1, zero added seccomp/NoNewPrivs,
                                rexec, no-dumpable, and MADV_DONTDUMP
                                scratchpad by default.
                         tree   Single-threaded supervisor covering forks,
                                shells, scripts, and descendants, with rexec,
                                no-dumpable, and encrypted at-rest copies by
                                default.
                         tee    Redaction composed with user/pid/mount
                                namespaces and a private /proc (fails closed
                                when unprivileged userns is unavailable).
                         compat Legacy v0.1.0 flag-driven defaults.
      --auto           Alias for --profile auto (the default).
      --follow         Follow and redact all descendants (selects tree mode;
                       inverse of --no-follow).
      --reparent       In single profile, double-fork the masked payload so it
                       runs reparented to PID 1 (or the nearest subreaper) and
                       return 0 once the masked exec completes.
      --parent-label NAME
                       Separate presentation label for the supervisor process
                       in tree mode, avoiding a supervisor/payload label twin.
      --cwd PATH       Change the child's working directory to PATH after
                       resolving COMMAND, normalizing /proc/<pid>/cwd.
      --rexec-mode MODE
                       Choose the --rexec image carrier:
                         auto    (default) prefer private 0500 staged path,
                                 falling back to sealed memfd on noexec mounts.
                         path    private 0500 executable inside a 0700 staging
                                 dir (zero /memfd: fingerprint in exe/maps).
                         tmpfile unnamed O_TMPFILE executable via
                                 execveat(AT_EMPTY_PATH): zero directory entry
                                 on disk and zero /memfd: fingerprint.
                         memfd   sealed anonymous memfd_create carrier.
      --no-rexec       Opt out of profile-default --rexec image staging.
      --allow-impersonation
                       Allow labels or comm names that match kernel-thread
                       bracket syntax ([...]) or critical system services
                       (sshd, systemd, init, cron, auditd, etc.).

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
                       Writing `--keep-env FOO /bin/cmd` (space form) fails
                       fast with exit code 2 and points to `--keep-env=FOO`
                       or `--` before the command.
      --env K=V        Add or replace one variable for the program.
                       Repeatable.
      --env-file PATH  Read variables for the program from PATH: one KEY=VALUE
                       per line, '#' starts a comment line, blank lines are
                       skipped, a trailing CR is stripped, an 'export '
                       prefix is allowed, a key with a blank or control byte
                       is refused, and one pair of matching ' or " quotes
                       around a value is removed.  The grammar is shared
                       with pmaskd's --env-file.  Repeatable.
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
                       Same-uid observers receive EACCES on environ, maps,
                       auxv, exe, fd, cwd and mem.  Core dumps and debugger
                       attach stop working.
      --allow-dumpable Keep the payload dumpable (opt out of profile-default
                       or secret-triggered PR_SET_DUMPABLE=0).
      --strict-exec    Refuse any exec that cannot be redacted at entry (a
                       script, vfork child, entry-swap failure or settled
                       re-exec); kills the payload instead of falling back to
                       post-exec redaction.  Refused with --detach.
      --allow-foreign  Run a 32-bit (foreign-ABI) image unredacted.  The
                       default refuses it: a 32-bit payload keeps its real
                       command line, environment and comm.
      --stealth        Compose a rename-watched tree shape (for tree mode;
                       not stronger than --profile single on a single native
                       ELF): --rexec (private staged path via auto by default,
                       zero /memfd: fingerprint unless --rexec-mode=memfd,
                       --hugetlb or --memfd-name is passed), --watch-rename
                       (comm stays the label), and --no-dumpable (same-uid
                       /proc reads return EACCES) unless /proc uses
                       hidepid=invisible or ptraceable, where a non-dumpable
                       process is a hidden pid.  The network identity is not
                       part of the mask; add --isolate=net for that.
                       It is not the write-time variant: a symlink alias or
                       an fd received over SCM_RIGHTS still reaches comm, and
                       the filter shows in /proc/<pid>/status as Seccomp: 2.
                       Add --watch-rename=strict to close the first; the
                       second no flag can close.
      --hide-pid       Hide the tree's pids from same-uid /proc readers.
                       Opt in, never the default.  Needs /proc mounted
                       with hidepid=invisible or hidepid=ptraceable; the
                       run is refused on a weaker mount.  cgroup.procs,
                       cgroup.threads, kill(0), pidfd, sched_getaffinity,
                       getpriority, prlimit and root still see the pid.
                       Refused with --no-follow or --detach, which take a
                       process off the path that re-applies the flag; a
                       descendant left running by --on-exit detach stays
                       hidden only until its next exec.
      --encrypt-memory Encrypt the supervisor's at-rest argv/environ
                       with XChaCha20-Poly1305 under a key in
                       memfd_secret when the kernel offers it, and keep
                       the payload's block anonymous and MADV_DONTDUMP.
                       Enabled by default in tree and tee profiles (in
                       single, the transient helper exits before main()
                       runs; pass --encrypt-memory to seal even that
                       brief window).  The payload's heap and stack are
                       not encrypted.
      --no-new-privs   Set no_new_privs before exec.  Set-uid and file
                       capabilities give nothing, for the whole tree.
      --no-exact       Leave the kernel's argv window where it is: the
                       label is written over the real arguments and padded
                       with spaces, so the window reads as one command line
                       rather than a NUL run; environ gets a plausible
                       decoy (or the --keep-env variables).
                       By default the kernel's argv and environment windows
                       are moved onto the presentation block with
                       prctl(PR_SET_MM_MAP), so cmdline is exactly the label
                       and environ shows a minimal decoy environment
                       (PATH, HOME, LANG, TERM) (or, with --keep-env, keeps
                       those variables).
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
                       running without the promise.  The filter traps a
                       write-mode open of /proc/.../comm; a symlink alias
                       or a descriptor received over SCM_RIGHTS reaches
                       comm without that path, so
                       --watch-rename=strict also checks the descriptor
                       target on every write at one stop per write.  The
                       filter is kernel state: /proc/<pid>/status then
                       reports Seccomp: 2 and NoNewPrivs: 1, which names
                       the process as filtered.  Neither mode hides that,
                       and no flag can.
      --rexec          Exec the program from a staged image so /proc/<pid>/exe
                       does not name the real file.  Use --rexec-mode to
                       choose auto, path, tmpfile or memfd.  In memfd mode the child
                       tries execveat(AT_EMPTY_PATH), then /proc/self/fd/N,
                       then a temporary file on an executable mount.  Each
                       failed step is reported and counted.  Without
                       --rexec-allow-disk a refused image ends the child with
                       126 (127 when missing) instead of running the on-disk
                       file.
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
                       temporary-file image, because the image descriptor
                       is CLOEXEC and the tracee has no copy after its
                       first exec.  With --on-exit wait or kill, a
                       seccomp filter traps only execve, so the tracee
                       runs free between execs.  Implies --rexec.
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
      --daemon PATH    Send the job to a running pmaskd on socket PATH.  The
                       daemon owns the masking policy and the environment;
                       only --label and --label-empty are forwarded.
  -q, --quiet          Suppress diagnostics.
  -v, --verbose        Trace every redaction event to stderr.
  -V, --version        Print version.
  -h, --help           Concise one-screen overview (--help=all or --help-all
                       for this full reference; --help=<topic> for one
                       section).

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
produce a warning.  --secret, --secret-fd, --isolate, --no-redact,
--hide-pid, --encrypt-memory, --image, --image-from-fd, --report* and
--profile single|tee are refused outright, because the daemon cannot honour
them.

Environment: PMASK_NO_SELFMASK=1 disables the redaction of pmask's own
/proc entry (argv, environ, comm).  Use it only for debugging.

Secret side (works even where ptrace is refused):
      --secret-fd [NAME=]N
                       Keep caller-opened file descriptor N open across exec
                       at its existing number and export PMASK_SECRET_FD=N
                       (unnamed) or PMASK_SECRET_<NAME>=N (named) in the
                       payload's real environment.  Repeatable.  Enables
                       --no-dumpable in redaction mode unless
                       --allow-dumpable is passed (plain --no-redact mode
                       runs without a tracer and sets RLIMIT_CORE=0).
      --secret NAME=SRC
                       Deliver a secret on descriptor 3, 4, ...  SRC is
                       file:PATH | env:VAR | agent:NAME | stdin | literal:VAL.
                       A SRC that starts with 'word:' where word is not one
                       of those schemes is delivered whole as a literal and
                       one warning names the word; a bare value
                       (--secret T=abc) is a literal with no warning.
                       Repeatable.  The child reads the descriptor from
                       PMASK_SECRET_<NAME> (the name upper-cased, with
                       every non-alphanumeric byte turned into '_'), and
                       `pmask read NAME` prints it there.
      --socket PATH    Secret-agent socket for agent:NAME sources.
      --isolate[=LIST] Run the payload in fresh namespaces: pid,net,tmp |
                       all | none (default all).  `none` runs the payload
                       with the host's view unchanged: no namespace, no
                       no_new_privs and no Landlock.  A host that cannot
                       create user namespaces runs the plain path and
                       says so.
      --redact         Ask for /proc redaction explicitly (the default).
                       With --isolate it composes: the tree is redacted
                       and the payload gets exactly the namespaces LIST
                       names, in one run.  A LIST the host cannot grant is
                       reported as a degradation; it is never replaced by
                       a different namespace set.
      --no-redact      Never touch /proc metadata, even where ptrace works.
                       With --isolate the payload still gets its
                       namespaces: isolation does not need ptrace, and
                       dropping it would be a silent fallback.
      --allow-argv-secret
                       Keep a literal: or env: secret source in a mode that
                       cannot redact /proc, and warn instead of refusing.
      --secret-close-on-exec
                       Close each delivered descriptor in every process the
                       supervised program starts, at that process's fork:
                       the payload reads the value, and a child it spawns
                       finds the descriptor gone before it runs.  Needs the
                       ptrace supervisor; a plain or isolate run refuses
                       the flag when a secret is delivered, and a run with
                       no --secret has nothing to close.
      --secret-burn    Seal the descriptors without F_SEAL_SHRINK, so the
                       reader can truncate a value to zero once it has used
                       it and cannot grow or rewrite it afterwards.
      --secret-fd-name NAME
                       Name the delivered secret memfd NAME instead of the
                       default 'pmask-secret'.  /proc/<pid>/fd/N then reads
                       '/memfd:NAME (deleted)', so a host-wide sweep for
                       the default literal finds nothing.  NAME must be
                       1..=200 bytes and must not contain '/', NUL, LF or
                       CR.  The descriptor's seals and content are
                       unchanged.
      --memfd-name NAME
                       Name the image memfd NAME instead of the label.
                       /proc/<pid>/exe and the executable maps entries then
                       read '/memfd:NAME (deleted)'.  Applies to --rexec,
                       --image, --image-from-fd, --exec-once and --hugetlb,
                       and to the temporary-file carrier's tag.  NAME is
                       checked like --secret-fd-name.  Has no effect on a
                       run that prepares no image.

Audit, explain, and reporting:
      --explain        Print the named observer, host capabilities, hidden
                       surfaces, EACCES denial tradeoff, and honest residuals
                       for the selected --profile, then exit 0.
      --profile-json   Emit native psgen schema: 2 JSON for --pid PID or a
                       static template for --profile/--label (never emitting
                       raw secret bytes), then exit 0.
      --audit          In standalone mode (`pmask --audit [--json]` with no
                       COMMAND, or `pmask --audit --pid PID [--json]`), probe
                       every /proc surface plus a full-VMA /proc/<pid>/mem
                       scan against invariants INV-1..INV-10 and exit 0 on
                       pass or 1 on failure.
                       With COMMAND, print one residue row per tracee at each
                       exec completion (requires redaction mode; allowed with
                       --redact --isolate and --isolate=none, refused with
                       --no-redact or standalone --isolate).
      --pid PID        Target PID for standalone --audit or --profile-json.
      --observer ROLE  Observer perspective for --audit: same-uid (default)
                       or other-uid.
      --json           Emit JSON output for --audit, --explain, or
                       --profile-json.
      --token-env VAR  Read the secret token to hunt during --audit --pid PID
                       or --profile-json --pid PID from environment variable
                       VAR (scrubbed immediately, never emitted verbatim).
      --token-fd N     Read the secret token to hunt during --audit --pid PID
                       or --profile-json --pid PID from file descriptor N.
      --real-exe PATH  Expected real executable path to verify is hidden
                       during --audit --pid PID (INV-4).
      --real-cwd PATH  Expected real working directory to verify is hidden
                       during --audit --pid PID (INV-6).
      --allow-memfd    Permit /memfd: executable paths in single profile
                       during --audit without failing INV-4.
      --report=json    Print the run as one JSON object on stdout.  The
                       report is written after the payload has exited, so a
                       payload that writes to stdout shares fd 1 with it: use
                       --report-file PATH or --report-fd N when a consumer
                       has to parse the document.  Every local path produces
                       one, including plain redaction; only a --daemon job
                       refuses the flag.
      --report-file PATH
                       Write the --report document to PATH instead of stdout;
                       the payload keeps fd 1 to itself.
      --report-fd N    Write the --report document to descriptor N, which is
                       inherited by pmask and closed afterwards.  The
                       descriptor is checked before the payload runs.

  `pmask run ...` is this same parser; `pmask help` prints the concise
  overview and subcommands (store, agent, get, read, probe, doctor).
  `pmask help <topic>` prints one section (`profiles`, `redact`, `secrets`,
  `isolate`, `daemon`, `audit`, `report`, `all`).

Examples:
  # single-process native binary (auto selects single: TracerPid: 0):
  pmask --label 'ci-runner' -- ./worker --config prod.toml

  # process tree / shell script with secret on an open descriptor:
  pmask --profile tree --label 'ci-runner' --secret-fd 3 -- sh -c './deploy.sh' 3<token

  # isolated redaction (user/pid/mount namespaces + private /proc):
  pmask --profile tee --label 'ci-runner' -- ./worker

Honest scope: root on the host always sees THAT a pid exists; pmask
redacts WHAT it is.  Same-uid /proc/<pid>/mem, environ, auxv, exe, maps,
fd, and cwd are closed by PR_SET_DUMPABLE=0 (EACCES).  Set-uid programs do
not gain privileges under supervision (a general ptrace property)."#;

#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    pub mask: Mask,
    pub program: OsString,
    pub args: Vec<OsString>,
    /// `--profile <auto|single|tree|tee|compat>` (default `Auto`).
    pub profile: Profile,
    /// True when `--profile` or `--auto` was passed explicitly.
    pub profile_explicit: bool,
    /// `--follow` explicitly asked for tree mode.
    pub follow_explicit: bool,
    /// `--no-follow` / `-F`.
    pub no_follow: bool,
    /// Explicit `--rexec` (or `--image*` / `--exec-once` / `--hugetlb`).
    pub rexec_explicit: bool,
    /// `--no-rexec` opted out of profile-default `--rexec`.
    pub no_rexec: bool,
    /// `--rexec-mode <memfd|path|tmpfile|auto>`, if explicitly set.
    pub rexec_mode: Option<RexecMode>,
    /// `--cwd PATH`.
    pub cwd: Option<PathBuf>,
    /// `--parent-label NAME`.
    pub parent_label: Option<String>,
    /// Explicit label string from `-l`/`--label`/`-a`/`--label-empty`.
    pub label_text: Option<String>,
    /// Explicit comm string from `--comm`.
    pub comm_text: Option<String>,
    /// `--reparent`: double-fork payload to PID 1 in `single` profile.
    pub reparent: bool,
    /// `--allow-impersonation`: bypass kernel-thread/critical-service guard.
    pub allow_impersonation: bool,
    /// `--secret-fd [NAME=]N`: caller-opened fds preserved across exec.
    pub secret_fds: Vec<(Option<String>, libc::c_int)>,
    /// `--explain`: render profile explanation and exit 0.
    pub explain: bool,
    /// `--profile-json`: emit native `psgen` `schema: 2` JSON and exit 0.
    pub profile_json: bool,
    /// `--pid PID`: target PID for standalone `--audit` / `--profile-json`.
    pub pid: Option<libc::pid_t>,
    /// `--observer <same-uid|other-uid>` for standalone `--audit`.
    pub observer: ObserverRole,
    /// `--json`: JSON output for `--audit`, `--explain`, `--profile-json`.
    pub json: bool,
    /// `--token-env VAR` for standalone `--audit` / `--profile-json`.
    pub token_env: Option<String>,
    /// `--token-fd N` for standalone `--audit` / `--profile-json`.
    pub token_fd: Option<libc::c_int>,
    /// `--real-exe PATH` for standalone `--audit`.
    pub real_exe: Option<String>,
    /// `--real-cwd PATH` for standalone `--audit`.
    pub real_cwd: Option<String>,
    /// `--allow-memfd` for standalone `--audit`.
    pub allow_memfd: bool,
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
    /// `--keep-env`: the whole environment stays visible.
    pub keep_env_all: bool,
    /// `--keep-env=NAME`: these variables stay visible.
    pub keep_env_names: Vec<String>,
    /// `--socket PATH`: the secret agent to ask for `agent:NAME` sources.
    pub agent_socket: Option<PathBuf>,
    /// `--isolate[=LIST]`: a private namespace set for the payload.
    pub isolate: Option<Isolate>,
    /// `--no-redact`: never touch /proc metadata.
    pub no_redact: bool,
    /// `--audit`: standalone live/self audit or tracee residue rows.
    pub audit: bool,
    /// `--redact`: ask for the default redaction explicitly.
    pub redact: bool,
    /// `--allow-argv-secret`: keep a literal or env source even in a mode
    /// that cannot redact, and warn instead of refusing.
    pub allow_argv_secret: bool,
    /// `--secret-burn`, `--secret-close-on-exec`: how the delivered
    /// descriptors behave.
    pub secret_burn: bool,
    pub secret_close_on_exec: bool,
    /// `--no-dumpable`: explicitly requested by user (or `--stealth`).
    pub no_dumpable: bool,
    /// `--allow-dumpable`: keep the payload dumpable.
    pub allow_dumpable: bool,
    /// `--hide-pid`: hide the tree from same-uid `/proc` readers.
    pub hide_pid: bool,
    /// `--encrypt-memory`: explicitly requested by user.
    pub encrypt_memory: bool,
    /// Profile-default at-rest encryption (`tree`/`tee`), kept separate from
    /// `encrypt_memory` so plain profile runs do not enter `Runner`.
    pub profile_encrypt_memory: bool,
    /// `--stealth`: composed tree mode.
    pub stealth: bool,
    /// `--unshare`: explicit unshare flag.
    pub unshare: bool,
    /// `--detach`: explicit detach-after-exec flag.
    pub detach: bool,
    /// `--hugetlb` or `--memfd-name`: explicitly requested memfd carrier.
    pub prefers_memfd: bool,
    /// `--report=json`: print the run as one JSON object.
    pub report_json: bool,
    /// `--report-file PATH`: write that object to PATH instead of stdout.
    pub report_file: Option<PathBuf>,
    /// `--report-fd N`: write that object to an inherited descriptor.
    pub report_fd: Option<libc::c_int>,
}

impl Cli {
    /// True when the run needs the secret machinery rather than the direct
    /// mask/single path: any secret (in non-single modes), isolation, an
    /// explicit `--no-redact`, `--hide-pid`, explicit `--encrypt-memory`, or
    /// a run report.
    pub fn needs_runner(&self) -> bool {
        self.needs_runner_without_report() || self.report_json
    }

    /// True when a secret, isolation, or a redaction option selects the
    /// runner.  A report alone does not: on a host that cannot redact, a
    /// report must not turn the run into plain mode.
    pub fn needs_runner_without_report(&self) -> bool {
        !self.secrets.is_empty()
            || self.isolate.is_some()
            || self.no_redact
            || self.hide_pid
            || self.encrypt_memory
    }

    /// Zero the argument and environment values this process still holds
    /// after the child's exec plan has been built.
    pub fn scrub_values(&mut self) {
        for a in &mut self.args {
            scrub_os_string(a);
        }
        for a in &mut self.reexec_argv {
            scrub_os_string(a);
        }
        for (_, v) in &mut self.env_overrides {
            scrub_os_string(v);
        }
        for (_, src) in &mut self.secrets {
            src.scrub();
        }
    }
}

/// Overwrite an `OsString`'s bytes in place, then replace it with an
/// empty string.
pub fn scrub_os_string(s: &mut OsString) {
    let mut bytes = std::mem::take(s).into_vec();
    bytes.zeroize();
    *s = OsString::new();
}

fn die(msg: &str) -> ! {
    eprintln!("pmask: {}", msg);
    exit(255);
}

fn die_usage(msg: &str) -> ! {
    eprintln!("pmask: {}", msg);
    exit(2);
}

/// Fetch an option value: the attached bytes when present, otherwise the
/// next argv element whatever it looks like (`-l -x` labels the process
/// `-x`, matching the C tool).
fn take_value(
    flag: &str,
    inline: Option<Zeroizing<Vec<u8>>>,
    argv: &[OsString],
    i: &mut usize,
) -> Zeroizing<Vec<u8>> {
    match inline {
        Some(v) => v,
        None => {
            *i += 1;
            match argv.get(*i) {
                Some(v) => Zeroizing::new(v.as_bytes().to_vec()),
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

/// Parse an `--env-file` with the daemon's parser.
fn read_env_file(path: &[u8]) -> Vec<(OsString, OsString)> {
    let p = Path::new(std::ffi::OsStr::from_bytes(path));
    match pmask::daemon::parse_env_file(p) {
        Ok(v) => v,
        Err(e) => die(&e.to_string()),
    }
}

fn parse_on_exit(v: &[u8]) -> SessionEnd {
    match v {
        b"detach" => SessionEnd::Detach,
        b"wait" => SessionEnd::WaitTree,
        b"kill" => SessionEnd::KillTree,
        _ => die("--on-exit takes detach, wait or kill"),
    }
}

fn parse_rexec_mode(v: &[u8]) -> RexecMode {
    let lower = v.to_ascii_lowercase();
    match lower.as_slice() {
        b"memfd" => RexecMode::Memfd,
        b"path" => RexecMode::Path,
        b"tmpfile" => RexecMode::Tmpfile,
        b"auto" => RexecMode::Auto,
        _ => die("--rexec-mode takes auto, path, tmpfile or memfd"),
    }
}

fn parse_secret_fd(raw: &[u8]) -> (Option<String>, libc::c_int) {
    let text = String::from_utf8_lossy(raw);
    let (name, fd_str) = match text.split_once('=') {
        Some((n, f)) => {
            if n.is_empty() {
                die_usage("--secret-fd NAME=N needs a non-empty NAME");
            }
            if let Err(e) = pmask::secret::validate_name(n) {
                die_usage(&format!("--secret-fd: {}", e));
            }
            if n.len() > pmask::secret::MAX_NAME_LEN {
                die_usage(&format!(
                    "--secret-fd: secret name '{}' is {} bytes; the limit is {}",
                    n,
                    n.len(),
                    pmask::secret::MAX_NAME_LEN
                ));
            }
            (Some(n.to_string()), f)
        }
        None => (None, text.as_ref()),
    };
    let fd = fd_str
        .parse::<libc::c_int>()
        .ok()
        .filter(|n| *n >= 0)
        .unwrap_or_else(|| {
            die_usage(&format!(
                "--secret-fd needs a non-negative file descriptor number, not '{}'",
                text
            ))
        });
    (name, fd)
}

/// True when `s` is a plausible `--keep-env` name list: one or more
/// non-empty names of `[A-Za-z0-9_.]`, separated by commas.
fn looks_like_env_names(s: &[u8]) -> bool {
    !s.is_empty()
        && s.split(|&b| b == b',').all(|n| {
            !n.is_empty()
                && n.iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.')
        })
}

/// True when `s` looks like one or more uppercase environment variable names
/// (`^[A-Z_][A-Z0-9_]*$`, optionally comma-separated).
fn looks_like_upper_env_names(s: &[u8]) -> bool {
    !s.is_empty()
        && s.split(|&b| b == b',').all(|n| {
            let Some(&first) = n.first() else {
                return false;
            };
            (first.is_ascii_uppercase() || first == b'_')
                && n.iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
        })
}

/// Check whether `cmd` names an existing executable file directly or on `PATH`.
fn is_executable_on_path(cmd: &std::ffi::OsStr) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let is_exec = |p: &Path| -> bool {
        std::fs::metadata(p)
            .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
            .unwrap_or(false)
    };
    if cmd.as_bytes().contains(&b'/') {
        return is_exec(Path::new(cmd));
    }
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path_var) {
        if is_exec(&dir.join(cmd)) {
            return true;
        }
    }
    false
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
pub fn parse_from(mut argv: Vec<OsString>) -> Cli {
    let mut mask = Mask::new();
    let mut profile = Profile::Auto;
    let mut profile_explicit = false;
    let mut follow_explicit = false;
    let mut no_follow = false;
    let mut rexec_explicit = false;
    let mut no_rexec = false;
    let mut rexec_mode: Option<RexecMode> = None;
    let mut cwd: Option<PathBuf> = None;
    let mut parent_label: Option<String> = None;
    let mut label_text: Option<String> = None;
    let mut comm_text: Option<String> = None;
    let mut reparent = false;
    let mut allow_impersonation = false;
    let mut secret_fds: Vec<(Option<String>, libc::c_int)> = Vec::new();
    let mut explain = false;
    let mut profile_json = false;
    let mut pid: Option<libc::pid_t> = None;
    let mut observer = ObserverRole::SameUid;
    let mut json = false;
    let mut token_env: Option<String> = None;
    let mut token_fd: Option<libc::c_int> = None;
    let mut real_exe: Option<String> = None;
    let mut real_cwd: Option<String> = None;
    let mut allow_memfd = false;

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
    let mut keep_env_all = false;
    let mut keep_env_names: Vec<String> = Vec::new();
    let mut unknown_schemes: Vec<(String, String)> = Vec::new();
    let mut agent_socket: Option<PathBuf> = None;
    let mut allow_argv_secret = false;
    let mut secret_burn = false;
    let mut secret_close_on_exec = false;
    let mut no_dumpable = false;
    let mut allow_dumpable = false;
    let mut no_dumpable_hidepid = false;
    let mut hide_pid = false;
    let mut encrypt_memory = false;
    let mut stealth = false;
    let mut stealth_hidepid_warn = false;
    let mut stealth_nodumpable = false;
    let mut unshare = false;
    let mut detach = false;
    let mut prefers_memfd = false;
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
        let bytes = Zeroizing::new(argv[i].as_bytes().to_vec());
        // A token is an option only if it starts with '-' and has another
        // byte; "-" alone is the command word.
        if end_opts || bytes.len() < 2 || bytes[0] != b'-' {
            break;
        }
        if bytes.as_slice() == b"--" {
            end_opts = true;
            i += 1;
            continue;
        }
        if bytes.starts_with(b"--") {
            let body = &bytes[2..];
            let (name_b, inline) = match body.iter().position(|&b| b == b'=') {
                Some(p) => (&body[..p], Some(Zeroizing::new(body[p + 1..].to_vec()))),
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
                "profile" => {
                    let v = take_value("--profile", inline, &argv, &mut i);
                    let raw = label_from(&v);
                    match Profile::parse(&raw) {
                        Some(p) => {
                            profile = p;
                            profile_explicit = true;
                        }
                        None => die(&format!(
                            "--profile takes auto, single, tree, tee or compat, not '{}'",
                            raw
                        )),
                    }
                    note_opt(&mut mask_opts, "--profile");
                }
                "auto" => {
                    profile = Profile::Auto;
                    profile_explicit = true;
                }
                "follow" => {
                    follow_explicit = true;
                    no_follow = false;
                    mask = mask.follow_tree(true);
                    note_opt(&mut mask_opts, "--follow");
                }
                "no-rexec" => {
                    no_rexec = true;
                    note_opt(&mut mask_opts, "--no-rexec");
                }
                "rexec-mode" => {
                    let v = take_value("--rexec-mode", inline, &argv, &mut i);
                    let mode = parse_rexec_mode(&v);
                    rexec_mode = Some(mode);
                    mask = mask.rexec_mode(mode);
                    note_opt(&mut mask_opts, "--rexec-mode");
                }
                "cwd" => {
                    let mut v = take_value("--cwd", inline, &argv, &mut i);
                    if v.is_empty() {
                        die("--cwd needs a non-empty path");
                    }
                    if v.contains(&0) {
                        die("--cwd path must not contain NUL");
                    }
                    let path = PathBuf::from(OsString::from_vec(std::mem::take(&mut *v)));
                    mask = mask.cwd(&path);
                    cwd = Some(path);
                    note_opt(&mut mask_opts, "--cwd");
                }
                "parent-label" => {
                    let v = take_value("--parent-label", inline, &argv, &mut i);
                    let text = label_arg(&v);
                    if let Err(e) = pmask::mask::validate_label(&text) {
                        die(&format!("--parent-label: {}", e));
                    }
                    mask = mask.parent_label(&text);
                    parent_label = Some(text);
                    note_opt(&mut mask_opts, "--parent-label");
                }
                "reparent" => {
                    reparent = true;
                    note_opt(&mut mask_opts, "--reparent");
                }
                "allow-impersonation" => {
                    allow_impersonation = true;
                }
                "secret-fd" => {
                    let v = take_value("--secret-fd", inline, &argv, &mut i);
                    let (opt_name, fd) = parse_secret_fd(&v);
                    secret_fds.push((opt_name, fd));
                    note_opt(&mut mask_opts, "--secret-fd");
                }
                "explain" => {
                    explain = true;
                }
                "profile-json" => {
                    profile_json = true;
                }
                "pid" => {
                    let v = take_value("--pid", inline, &argv, &mut i);
                    let raw = label_from(&v);
                    let parsed = raw
                        .parse::<libc::pid_t>()
                        .ok()
                        .filter(|p| *p > 0)
                        .unwrap_or_else(|| {
                            die(&format!("--pid needs a positive integer, not '{}'", raw))
                        });
                    pid = Some(parsed);
                }
                "observer" => {
                    let v = take_value("--observer", inline, &argv, &mut i);
                    let raw = label_from(&v);
                    match ObserverRole::parse(&raw) {
                        Some(role) => observer = role,
                        None => die(&format!(
                            "--observer takes same-uid or other-uid, not '{}'",
                            raw
                        )),
                    }
                }
                "json" => {
                    json = true;
                }
                "token-env" => {
                    let v = take_value("--token-env", inline, &argv, &mut i);
                    let raw = label_from(&v);
                    if raw.is_empty() {
                        die("--token-env needs an environment variable name");
                    }
                    token_env = Some(raw);
                }
                "token-fd" => {
                    let v = take_value("--token-fd", inline, &argv, &mut i);
                    let raw = label_from(&v);
                    let n = raw
                        .parse::<libc::c_int>()
                        .ok()
                        .filter(|n| *n >= 0)
                        .unwrap_or_else(|| {
                            die(&format!(
                                "--token-fd needs a file descriptor number, not '{}'",
                                raw
                            ))
                        });
                    token_fd = Some(n);
                }
                "real-exe" => {
                    let v = take_value("--real-exe", inline, &argv, &mut i);
                    real_exe = Some(label_from(&v));
                }
                "real-cwd" => {
                    let v = take_value("--real-cwd", inline, &argv, &mut i);
                    real_cwd = Some(label_from(&v));
                }
                "allow-memfd" => {
                    allow_memfd = true;
                }
                "label" => {
                    let v = take_value("--label", inline, &argv, &mut i);
                    let text = label_arg(&v);
                    remote_label = RemoteLabel::Text(text.clone());
                    label_text = Some(text.clone());
                    mask = mask.label(text);
                }
                "daemon" => {
                    let mut v = take_value("--daemon", inline, &argv, &mut i);
                    daemon = Some(OsString::from_vec(std::mem::take(&mut *v)));
                }
                "label-empty" => {
                    mask = mask.label("");
                    label_text = Some(String::new());
                    remote_label = RemoteLabel::Empty;
                }
                "argv0" => {
                    let mut v = take_value("--argv0", inline, &argv, &mut i);
                    mask = mask.argv0(OsString::from_vec(std::mem::take(&mut *v)));
                    note_opt(&mut mask_opts, "--argv0");
                }
                "comm" => {
                    let v = take_value("--comm", inline, &argv, &mut i);
                    let c = label_from(&v);
                    if let Err(e) = pmask::mask::validate_comm(&c) {
                        die(&e.to_string());
                    }
                    comm_text = Some(c.clone());
                    mask = mask.comm(c);
                    note_opt(&mut mask_opts, "--comm");
                }
                "keep-env" => {
                    match inline {
                        None => {
                            // Fail fast on the `--keep-env FOO /bin/cmd` or
                            // `--keep-env FOO -- /bin/cmd` space-form trap
                            // instead of silently keeping the whole env and
                            // executing FOO as COMMAND.
                            if let Some(next) = argv.get(i + 1) {
                                let nb = next.as_bytes();
                                if !nb.is_empty() && !nb.starts_with(b"-") {
                                    let followed_by_dashdash =
                                        argv.get(i + 2).is_some_and(|a| a.as_bytes() == b"--")
                                            && argv.len() > i + 3;
                                    let is_upper_env = looks_like_upper_env_names(nb);
                                    let is_comma_env =
                                        nb.contains(&b',') && looks_like_env_names(nb);
                                    let exec_exists = is_executable_on_path(next);
                                    let trap = (followed_by_dashdash
                                        && looks_like_env_names(nb)
                                        && (!exec_exists || is_upper_env))
                                        || ((is_upper_env || is_comma_env) && !exec_exists);
                                    if trap {
                                        eprintln!(
                                            "pmask: --keep-env takes its list with '=' (use --keep-env={}), or place '--' before the command",
                                            next.to_string_lossy()
                                        );
                                        exit(2);
                                    }
                                }
                            }
                            mask = mask.keep_environ_visible();
                            keep_env_all = true;
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
                            keep_env_names.extend(names.iter().cloned());
                            mask = mask.keep_env_vars(names);
                        }
                    }
                    note_opt(&mut mask_opts, "--keep-env");
                }
                "env" => {
                    let v = take_value("--env", inline, &argv, &mut i);
                    match v.iter().position(|&b| b == b'=') {
                        Some(0) => die("environment variable name \"\" must not be empty"),
                        None => die(&format!(
                            "--env needs KEY=VALUE, not '{}'",
                            String::from_utf8_lossy(&v)
                        )),
                        Some(p) => {
                            let key = OsString::from_vec(v[..p].to_vec());
                            let val = OsString::from_vec(v[p + 1..].to_vec());
                            if let Err(e) = pmask::mask::validate_env_key(&key) {
                                die(&e.to_string());
                            }
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
                    no_follow = true;
                    follow_explicit = false;
                    mask = mask.follow_tree(false);
                    note_opt(&mut mask_opts, "--no-follow");
                }
                "no-exit-kill" | "no-exitkill" => {
                    mask = mask.let_tree_survive_self_death();
                    note_opt(&mut mask_opts, "--no-exit-kill");
                }
                "no-dumpable" => {
                    mask = mask.no_dumpable().supervisor_non_dumpable(true);
                    no_dumpable = true;
                    no_dumpable_hidepid =
                        pmask::caps::Caps::proc_hidepid_fast().hides_non_dumpable();
                    note_opt(&mut mask_opts, "--no-dumpable");
                }
                "allow-dumpable" => {
                    allow_dumpable = true;
                    note_opt(&mut mask_opts, "--allow-dumpable");
                }
                "strict-exec" => {
                    mask = mask.strict_exec();
                    note_opt(&mut mask_opts, "--strict-exec");
                }
                "allow-foreign" => {
                    mask = mask.allow_foreign(true);
                    note_opt(&mut mask_opts, "--allow-foreign");
                }
                "hide-pid" => {
                    mask = mask.hide_pid(true);
                    hide_pid = true;
                    note_opt(&mut mask_opts, "--hide-pid");
                }
                "encrypt-memory" => {
                    mask = mask.encrypt_memory(true);
                    encrypt_memory = true;
                    if pmask::caps::Caps::proc_hidepid_fast().hides_non_dumpable() && !quiet {
                        eprintln!(
                            "pmask: --encrypt-memory: the supervisor is non-dumpable to protect \
                             the key; on this hidepid mount it can be named by chkproc/unhide"
                        );
                    }
                    note_opt(&mut mask_opts, "--encrypt-memory");
                }
                "stealth" => {
                    mask = mask.watch_rename();
                    let hidepid = pmask::caps::Caps::proc_hidepid_fast();
                    if hidepid.hides_non_dumpable() {
                        stealth_hidepid_warn = true;
                    } else {
                        mask = mask.no_dumpable().supervisor_non_dumpable(true);
                        no_dumpable = true;
                        stealth_nodumpable = true;
                    }
                    stealth = true;
                    note_opt(&mut mask_opts, "--stealth");
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
                    detach = true;
                    note_opt(&mut mask_opts, "--detach");
                }
                "watch-rename" => {
                    match inline.as_deref().map(Vec::as_slice) {
                        None => mask = mask.watch_rename(),
                        Some(b"strict") => mask = mask.watch_rename_strict(),
                        Some(other) => die(&format!(
                            "--watch-rename takes 'strict' or no value, not '{}'",
                            String::from_utf8_lossy(other)
                        )),
                    }
                    note_opt(&mut mask_opts, "--watch-rename");
                }
                "rexec" => {
                    mask = mask.rexec();
                    rexec_explicit = true;
                    no_rexec = false;
                    note_opt(&mut mask_opts, "--rexec");
                }
                "image" => {
                    let mut v = take_value("--image", inline, &argv, &mut i);
                    if image_program.is_some() {
                        die("--image and --image-from-fd are exclusive");
                    }
                    if v.as_slice() == b"-" {
                        mask = mask.image_stdin();
                        image_program = Some(OsString::from("-"));
                    } else {
                        let path = OsString::from_vec(std::mem::take(&mut *v));
                        mask = mask.image_path(path.clone());
                        image_program = Some(path);
                    }
                    rexec_explicit = true;
                    prefers_memfd = true;
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
                    rexec_explicit = true;
                    prefers_memfd = true;
                    note_opt(&mut mask_opts, "--image-from-fd");
                }
                "exec-once" => {
                    mask = mask.exec_once();
                    rexec_explicit = true;
                    prefers_memfd = true;
                    note_opt(&mut mask_opts, "--exec-once");
                }
                "hugetlb" => {
                    mask = mask.hugetlb();
                    rexec_explicit = true;
                    prefers_memfd = true;
                    note_opt(&mut mask_opts, "--hugetlb");
                }
                "memfd-name" => {
                    let v = take_value("--memfd-name", inline, &argv, &mut i);
                    let name = label_from(&v);
                    if let Err(e) = pmask::mem::validate_memfd_name(&name) {
                        die(&format!("--memfd-name: {}", e));
                    }
                    mask = mask.memfd_name(name);
                    prefers_memfd = true;
                    note_opt(&mut mask_opts, "--memfd-name");
                }
                "rexec-allow-disk" => {
                    mask = mask.rexec_allow_disk();
                    rexec_explicit = true;
                    note_opt(&mut mask_opts, "--rexec-allow-disk");
                }
                "unshare" => {
                    mask = mask.unshare();
                    unshare = true;
                    note_opt(&mut mask_opts, "--unshare");
                }
                "scope-name" => {
                    let has_inline = inline.is_some();
                    let v = take_value("--scope-name", inline, &argv, &mut i);
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
                    let spec = Zeroizing::new(String::from_utf8_lossy(&v).into_owned());
                    let parsed = Source::parse_spec(&spec);
                    drop(spec);
                    drop(v);
                    match parsed {
                        Ok((name, source, unknown)) => {
                            if let Some(scheme) = unknown {
                                unknown_schemes.push((name.clone(), scheme));
                            }
                            secrets.push((name, source));
                        }
                        Err(e) => die(&format!("--secret: {}", e)),
                    }
                }
                "socket" => {
                    let mut v = take_value("--socket", inline, &argv, &mut i);
                    agent_socket = Some(PathBuf::from(OsString::from_vec(std::mem::take(&mut *v))));
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
                "secret-fd-name" => {
                    let v = take_value("--secret-fd-name", inline, &argv, &mut i);
                    let name = label_from(&v);
                    if let Err(e) = pmask::mem::validate_memfd_name(&name) {
                        die(&format!("--secret-fd-name: {}", e));
                    }
                    mask = mask.secret_fd_name(name);
                    note_opt(&mut mask_opts, "--secret-fd-name");
                }
                "secret-close-on-exec" => {
                    secret_close_on_exec = true;
                    note_opt(&mut mask_opts, "--secret-close-on-exec");
                }
                "report" => {
                    let v = take_value("--report", inline, &argv, &mut i);
                    match v.as_slice() {
                        b"json" => report_json = true,
                        b"text" | b"plain" => {
                            die("--report takes json; text is the default output (the \
                             'pmask: mode=...' summary on stderr), so drop --report")
                        }
                        _ => die("--report takes json"),
                    }
                }
                "report-file" => {
                    let mut v = take_value("--report-file", inline, &argv, &mut i);
                    if v.is_empty() {
                        die("--report-file needs a path");
                    }
                    report_file = Some(PathBuf::from(OsString::from_vec(std::mem::take(&mut *v))));
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
                "help-all" => {
                    print_topic(b"all");
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
                    let inline: Option<Zeroizing<Vec<u8>>> = if j + 1 < bytes.len() {
                        Some(Zeroizing::new(bytes[j + 1..].to_vec()))
                    } else {
                        None
                    };
                    let v = take_value(flag, inline, &argv, &mut i);
                    let text = label_arg(&v);
                    remote_label = RemoteLabel::Text(text.clone());
                    label_text = Some(text.clone());
                    mask = mask.label(text);
                    j = bytes.len();
                    continue;
                }
                b'E' => {
                    mask = mask.keep_environ_visible();
                    keep_env_all = true;
                    note_opt(&mut mask_opts, "--keep-env");
                }
                b'F' => {
                    no_follow = true;
                    follow_explicit = false;
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

    if !quiet {
        for (name, scheme) in &unknown_schemes {
            eprintln!(
                "pmask: {}",
                pmask::secret::unknown_scheme_warning(name, scheme)
            );
        }
    }

    let reexec_argv: Vec<OsString> = argv
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(idx, _)| !skip.contains(idx))
        .map(|(_, a)| a.clone())
        .collect();

    if !quiet && daemon.is_none() {
        if let Some(warning) = pmask::run::argv_secret_warning(&secrets) {
            eprintln!("pmask: warning: {}", warning);
        }
    }
    if !quiet && no_dumpable_hidepid && !hide_pid {
        eprintln!(
            "pmask: warning: --no-dumpable on a hidepid=invisible or ptraceable host hides the tree \
             from same-uid observers; chkproc and unhide can name it as a hidden pid. \
             --stealth picks the other trade."
        );
    }
    if !quiet && stealth_hidepid_warn && !hide_pid {
        eprintln!(
            "pmask: --stealth: /proc uses hidepid={}; --no-dumpable is not applied, because \
             a non-dumpable process is hidden from same-uid observers and chkproc/unhide can \
             name it.  The same-uid memory read stays open.",
            pmask::caps::Caps::proc_hidepid_fast().as_word()
        );
    }
    if verbose && stealth_nodumpable && !hide_pid {
        eprintln!(
            "pmask: --stealth: /proc uses hidepid={}; --no-dumpable is applied, so a same-uid \
             reader loses environ, maps, auxv, exe, fd, cwd and /proc/<pid>/mem.  Those EACCES \
             refusals are themselves a signal.",
            pmask::caps::Caps::proc_hidepid_fast().as_word()
        );
    }
    if !quiet && stealth && hide_pid {
        eprintln!(
            "pmask: --stealth and --hide-pid: --hide-pid wins; the tree is non-dumpable and \
             hidden from same-uid /proc readers, and the hidden-pid sweepers can name it."
        );
    }

    let standalone_mode = explain || profile_json || (audit && (pid.is_some() || i >= argv.len()));

    let (program, args) = if standalone_mode && args_fd.is_none() && image_program.is_none() {
        (OsString::new(), Vec::new())
    } else if args_fd.is_some() {
        if i < argv.len() {
            die("--args-from-fd replaces COMMAND: no command may follow the options");
        }
        (OsString::new(), Vec::new())
    } else if let Some(p) = image_program {
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

    for a in &mut argv {
        scrub_os_string(a);
    }

    Cli {
        mask,
        program,
        args,
        profile,
        profile_explicit,
        follow_explicit,
        no_follow,
        rexec_explicit,
        no_rexec,
        rexec_mode,
        cwd,
        parent_label,
        label_text,
        comm_text,
        reparent,
        allow_impersonation,
        secret_fds,
        explain,
        profile_json,
        pid,
        observer,
        json,
        token_env,
        token_fd,
        real_exe,
        real_cwd,
        allow_memfd,
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
        keep_env_all,
        keep_env_names,
        allow_argv_secret,
        secret_burn,
        secret_close_on_exec,
        no_dumpable,
        allow_dumpable,
        hide_pid,
        encrypt_memory,
        profile_encrypt_memory: false,
        stealth,
        unshare,
        detach,
        prefers_memfd,
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

/// The largest `--args-from-fd` vector read into memory.
pub const ARGS_FD_MAX: u64 = 8 * 1024 * 1024;

impl Cli {
    /// Read the command from the `--args-from-fd` descriptor, when one
    /// was given.
    pub fn load_args_fd(&mut self) {
        let Some(fd) = self.args_fd.take() else {
            return;
        };
        // SAFETY: F_DUPFD_CLOEXEC on a descriptor the operator passed
        // open on purpose.  The duplicate is ours; the caller's
        // descriptor is untouched.
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if dup < 0 {
            die(&format!(
                "--args-from-fd {}: cannot duplicate the descriptor: {}",
                fd,
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: `dup` is the duplicate above.
        let file = unsafe { std::fs::File::from_raw_fd(dup) };
        let mut data = Zeroizing::new(Vec::new());
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
        let mut parts: Vec<Zeroizing<Vec<u8>>> = data
            .split(|&b| b == 0)
            .map(|s| Zeroizing::new(s.to_vec()))
            .collect();
        if data.last() == Some(&0) {
            parts.pop();
        }
        if parts.is_empty() || parts[0].is_empty() {
            die(&format!("--args-from-fd {}: no program given", fd));
        }
        let mut it = parts.into_iter();
        self.program = OsString::from_vec(
            it.next()
                .map(|mut p| std::mem::take(&mut *p))
                .unwrap_or_default(),
        );
        self.args = it
            .map(|mut p| OsString::from_vec(std::mem::take(&mut *p)))
            .collect();
    }
}

/// The complete reference help text, with version and arch filled in.
pub fn full_help_text() -> String {
    HELP.trim_start_matches('\n')
        .replace("{version}", pmask::VERSION)
        .replace("{arch}", arch_name())
}

/// Print one help topic (`--help=<topic>`).  `short` prints the concise
/// one-screen overview; `all` prints the complete reference; topic names
/// print one option group each.
fn print_topic(topic: &[u8]) {
    let text = full_help_text();
    let t = String::from_utf8_lossy(topic).into_owned();
    if t == "short" {
        print!("{}", pmask::subcmd::short_help(&text));
        exit(0);
    }
    if t == "all" {
        println!("{}", text);
        exit(0);
    }
    let code = pmask::subcmd::help_topic(&text, &t);
    exit(code);
}

/// `-h`/`--help` print the concise one-screen overview to stdout and exit 0;
/// a usage error goes to stderr and exits 255.
fn print_help(stdout: bool) {
    let text = pmask::subcmd::short_help(&full_help_text());
    if stdout {
        print!("{}", text);
    } else {
        eprint!("{}", text);
    }
}

fn arch_name() -> &'static str {
    pmask::arch_name()
}
