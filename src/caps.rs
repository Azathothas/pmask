//! What this host actually allows.
//!
//! Every mechanism `pmask` uses is optional, and a host may refuse any
//! of them: seccomp profiles ban `ptrace`, `/proc/sys/kernel/
//! unprivileged_userns_clone` may be 0, `memfd_secret` may be compiled
//! out, `RLIMIT_MEMLOCK` may be 64 KiB.  The tool therefore never assumes
//! a tier exists.  It probes, reports, and runs with whatever is left.
//!
//! Each mechanism carries a [`State`]: `Active` when the probe succeeded,
//! `Degraded` when it works with a named limitation, and `Unavailable`
//! when it does not work here.  Absence is never silent: the report names
//! what the operator loses, and `pmask doctor` exits non-zero when a
//! *requested* guarantee is unavailable.
//!
//! The probe runs each check in a forked child, so a refused call cannot
//! leave the caller in a half-changed state.  `PMASK_PROBE_<NAME>`
//! replaces one probe's answer and skips the real syscall; it is a test
//! hook for the host-profile matrix, not a production setting.

use std::io;
use std::sync::OnceLock;

/// `landlock_create_ruleset(2)`; same number on x86-64 and aarch64.
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
/// `pidfd_open(2)`.
const SYS_PIDFD_OPEN: libc::c_long = 434;
/// `LANDLOCK_CREATE_RULESET_VERSION`: turn the call into a query.
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Secrets are delivered as sealed file descriptors and kept in
    /// locked, dump-excluded memory.  Needs nothing beyond a kernel.
    SecretFds,
    /// `memfd_secret` keeps the pages out of the kernel direct map.
    SecretMem,
    /// `/proc` metadata of the whole tree is redacted (needs `ptrace`).
    MetadataRedaction,
    /// A private mount/pid/net namespace for the payload (needs
    /// unprivileged user namespaces).
    Isolation,
}

/// What the host does with one mechanism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// The probe succeeded and nothing limits it here.
    Active,
    /// The mechanism works with a named limitation.
    Degraded(String),
    /// The mechanism does not work here.
    Unavailable(String),
}

impl State {
    pub fn ok(&self) -> bool {
        !matches!(self, State::Unavailable(_))
    }

    pub fn as_word(&self) -> &'static str {
        match self {
            State::Active => "active",
            State::Degraded(_) => "degraded",
            State::Unavailable(_) => "unavailable",
        }
    }

    /// The reason a mechanism is not fully active, or the empty string.
    pub fn reason(&self) -> &str {
        match self {
            State::Active => "",
            State::Degraded(r) | State::Unavailable(r) => r,
        }
    }

    fn from_bool(ok: bool, why: &str) -> State {
        if ok {
            State::Active
        } else {
            State::Unavailable(why.to_string())
        }
    }
}

#[derive(Debug, Clone)]
pub struct Caps {
    pub arch: &'static str,
    pub kernel: String,
    /// `PTRACE_TRACEME` from a child succeeds.
    pub ptrace: bool,
    /// `unshare(CLONE_NEWUSER)` succeeds unprivileged.
    pub userns: bool,
    /// `memfd_secret(2)` returns a usable descriptor.
    pub memfd_secret: bool,
    /// `mlock` on a fresh page succeeds (so secrets cannot be swapped).
    pub mlock: bool,
    /// `PR_SET_DUMPABLE` is permitted.
    pub non_dumpable: bool,
    /// A seccomp filter is already installed on this process, which is
    /// what usually explains a refused `ptrace`.
    pub seccomp_filter: bool,
    /// `RLIMIT_MEMLOCK` in bytes.
    pub memlock_limit: u64,
    /// Landlock ABI version the kernel implements, or 0.
    pub landlock_abi: u32,
    /// `pidfd_open` on our own pid succeeds.
    pub pidfd_open: bool,
    /// `getsockopt(SO_PEERPIDFD)` answered on a connected socketpair.
    pub peerpidfd: bool,
    /// `prctl(PR_SET_MM, PR_SET_MM_MAP)` is reachable here.
    pub set_mm_map: bool,
    /// `prctl(PR_SET_NO_NEW_PRIVS)` succeeds.
    pub no_new_privs: bool,
    /// `kernel.yama.ptrace_scope`, when readable.
    pub ptrace_scope: Option<u32>,
    /// This caller cannot see other accounts' processes: `hidepid` on
    /// procfs, or a `ProtectProc=invisible` unit.
    pub proc_hidden: bool,
    /// `vm.memfd_noexec` is 1 or 2.
    pub memfd_noexec: bool,
    /// `fs.protected_regular` is 2.
    pub protected_regular: bool,
    /// The numbers held in the effective capability set.
    pub cap_effective: u64,
}

/// Test-only replacements for the host probes, read once by
/// [`Caps::detect`].
///
/// Each `PMASK_PROBE_<NAME>` variable replaces one probe's answer and
/// skips the real syscall, so the host-profile matrix in
/// `tests/isolation.sh` can run every profile on one host.  A value that
/// does not parse is ignored and the real probe runs.  The variables are
/// read once per `detect` call, not inside the probe.
#[derive(Debug, Default, Clone, Copy)]
struct ProbeOverrides {
    ptrace: Option<bool>,
    userns: Option<bool>,
    landlock_abi: Option<u32>,
    memfd_secret: Option<bool>,
    memlock: Option<u64>,
    proc_hidden: Option<bool>,
    peerpidfd: Option<bool>,
}

impl ProbeOverrides {
    fn from_env() -> ProbeOverrides {
        ProbeOverrides {
            ptrace: bool_probe("PMASK_PROBE_PTRACE"),
            userns: bool_probe("PMASK_PROBE_USERNS"),
            landlock_abi: number_probe("PMASK_PROBE_LANDLOCK_ABI"),
            memfd_secret: bool_probe("PMASK_PROBE_MEMFD_SECRET"),
            memlock: number_probe("PMASK_PROBE_MEMLOCK"),
            proc_hidden: bool_probe("PMASK_PROBE_PROC_HIDDEN"),
            peerpidfd: bool_probe("PMASK_PROBE_PEERPIDFD"),
        }
    }
}

/// Parse `0` or `1`; any other value leaves the probe in place.
fn bool_probe(name: &str) -> Option<bool> {
    bool_value(&std::env::var(name).ok()?)
}

fn bool_value(v: &str) -> Option<bool> {
    match v {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

/// Parse a decimal number; any other value leaves the probe in place.
fn number_probe<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok()?.parse().ok()
}

impl Caps {
    /// Probe every mechanism this host offers.
    ///
    /// `PMASK_PROBE_<NAME>` overrides are read once, before any probe
    /// runs. An override replaces that probe's answer and the real
    /// syscall is not made.
    pub fn detect() -> Caps {
        Caps::detect_with(ProbeOverrides::from_env())
    }

    fn detect_with(overrides: ProbeOverrides) -> Caps {
        let ptrace = match overrides.ptrace {
            Some(v) => v,
            None => probe_in_child(|| {
                // SAFETY: plain ptrace; the child exits immediately after, so
                // there is no stopped tracee to leave behind.
                unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == 0 }
            }),
        };

        let userns = match overrides.userns {
            Some(v) => v,
            None => probe_in_child(|| {
                // SAFETY: unshare in a throwaway child.
                unsafe { libc::unshare(libc::CLONE_NEWUSER) == 0 }
            }),
        };

        let memfd_secret = match overrides.memfd_secret {
            Some(v) => v,
            // The probe creates the descriptor through the same helper
            // the real buffers use, so a probe that succeeds cannot
            // disagree with the allocation about `MFD_CLOEXEC`, and
            // there is only one creation site to audit (issue 15).
            None => crate::mem::secret_memfd_available(),
        };

        let mlock = probe_in_child(|| {
            // SAFETY: anonymous one-page mapping, locked and released.
            unsafe {
                let p = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if p == libc::MAP_FAILED {
                    return false;
                }
                let ok = libc::mlock(p, 4096) == 0;
                libc::munlock(p, 4096);
                libc::munmap(p, 4096);
                ok
            }
        });

        let non_dumpable = probe_in_child(|| {
            // SAFETY: prctl in a throwaway child.
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) == 0 }
        });

        let no_new_privs = probe_in_child(|| {
            // SAFETY: prctl in a throwaway child.
            unsafe { libc::prctl(38, 1 as libc::c_ulong, 0, 0, 0) == 0 }
        });

        // The kernel's own sizeof(struct prctl_mm_map) must equal the
        // layout `presetmm::encode` writes. A kernel that reports a
        // different size would reinterpret every field of the struct,
        // and the relocation would fail silently or corrupt the tracee.
        let set_mm_map = matches!(
            crate::presetmm::map_size(),
            Some(n) if n == crate::presetmm::MM_MAP_LEN as u32
        );

        let pidfd_open = probe_in_child(|| {
            // SAFETY: plain syscall on our own pid; a failure is the answer.
            let fd = unsafe { libc::syscall(SYS_PIDFD_OPEN, libc::getpid(), 0 as libc::c_long) }
                as libc::c_int;
            if fd >= 0 {
                // SAFETY: fd is ours.
                unsafe { libc::close(fd) };
                true
            } else {
                false
            }
        });

        let landlock_abi = match overrides.landlock_abi {
            Some(v) => v,
            None => {
                // SAFETY: the version query takes a null ruleset and a zero
                // size; a negative answer encodes the errno.
                let rc = unsafe {
                    libc::syscall(
                        SYS_LANDLOCK_CREATE_RULESET,
                        std::ptr::null::<libc::c_void>(),
                        0usize,
                        LANDLOCK_CREATE_RULESET_VERSION,
                    )
                };
                if rc > 0 {
                    rc as u32
                } else {
                    0
                }
            }
        };

        let seccomp_filter = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Seccomp:"))
                    .and_then(|l| l.split_whitespace().nth(1).map(|v| v != "0"))
            })
            .unwrap_or(false);

        let memlock_limit = match overrides.memlock {
            Some(v) => v,
            None => {
                let mut rl = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                // SAFETY: getrlimit on owned storage.
                if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl) } == 0 {
                    rl.rlim_cur
                } else {
                    0
                }
            }
        };

        let cap_effective = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("CapEff:"))
                    .and_then(|l| u64::from_str_radix(l.split_whitespace().nth(1)?, 16).ok())
            })
            .unwrap_or(0);

        let ptrace_scope = sysctl("kernel/yama/ptrace_scope").and_then(|v| v.parse().ok());
        let memfd_noexec = sysctl("vm/memfd_noexec")
            .and_then(|v| v.parse::<u32>().ok())
            .map(|v| v >= 1)
            .unwrap_or(false);
        let protected_regular = sysctl("fs/protected_regular")
            .and_then(|v| v.parse::<u32>().ok())
            .map(|v| v >= 2)
            .unwrap_or(false);

        Caps {
            arch: std::env::consts::ARCH,
            kernel: kernel_release(),
            ptrace,
            userns,
            memfd_secret,
            mlock,
            non_dumpable,
            seccomp_filter,
            memlock_limit,
            landlock_abi,
            pidfd_open,
            peerpidfd: match overrides.peerpidfd {
                Some(v) => v,
                None => probe_peerpidfd(),
            },
            set_mm_map,
            no_new_privs,
            ptrace_scope,
            proc_hidden: match overrides.proc_hidden {
                Some(v) => v,
                None => procfs_hides_other_uids(),
            },
            memfd_noexec,
            protected_regular,
            cap_effective,
        }
    }

    /// The probe is deterministic for the life of the process, and several
    /// code paths want it, so it is computed once.
    pub fn cached() -> &'static Caps {
        static CACHE: OnceLock<Caps> = OnceLock::new();
        CACHE.get_or_init(Caps::detect)
    }

    /// Which mechanisms are available, in the order they matter.
    pub fn tiers(&self) -> Vec<(Tier, bool)> {
        vec![
            (Tier::SecretFds, true),
            (Tier::SecretMem, self.memfd_secret),
            (Tier::MetadataRedaction, self.ptrace),
            (Tier::Isolation, self.userns),
        ]
    }

    /// One row per mechanism with its [`State`], in report order.
    pub fn rows(&self) -> Vec<(&'static str, State)> {
        vec![
            ("secret fds", State::Active),
            (
                "memfd_secret",
                State::from_bool(
                    self.memfd_secret,
                    "pages are locked but still reachable through the kernel direct map",
                ),
            ),
            (
                "mlock",
                if self.mlock {
                    State::Active
                } else {
                    State::Unavailable(format!(
                        "RLIMIT_MEMLOCK is {} bytes; secrets may reach swap",
                        self.memlock_limit
                    ))
                },
            ),
            (
                "non-dumpable",
                State::from_bool(self.non_dumpable, "the holding process may be dumpable"),
            ),
            (
                "metadata redaction",
                if self.ptrace {
                    State::Active
                } else if self.seccomp_filter {
                    State::Unavailable(
                        "ptrace is banned by a seccomp filter here; command lines stay visible"
                            .into(),
                    )
                } else {
                    State::Unavailable(
                        "ptrace is not permitted here; command lines stay visible".into(),
                    )
                },
            ),
            (
                "exact cmdline window",
                if self.set_mm_map {
                    State::Active
                } else {
                    State::Unavailable(
                        "prctl(PR_SET_MM_MAP) is refused; the cmdline keeps its original byte length"
                            .into(),
                    )
                },
            ),
            (
                "isolation",
                State::from_bool(
                    self.userns,
                    "no unprivileged user namespaces; the payload sees the host",
                ),
            ),
            (
                "landlock",
                if self.landlock_abi > 0 {
                    State::Active
                } else {
                    State::Unavailable(
                        "Landlock is not available; the payload's filesystem view is unrestricted"
                            .into(),
                    )
                },
            ),
            (
                "no_new_privs",
                State::from_bool(
                    self.no_new_privs,
                    "set-uid binaries can elevate the payload",
                ),
            ),
            (
                "pidfd",
                State::from_bool(
                    self.pidfd_open,
                    "a pidfd cannot be opened; a peer identity is a racy pid",
                ),
            ),
            (
                "SO_PEERPIDFD",
                State::from_bool(
                    self.peerpidfd,
                    "the kernel predates 6.5; daemon peers are checked by uid and exe",
                ),
            ),
            (
                "procfs hides other uids",
                if self.proc_hidden {
                    State::Active
                } else {
                    State::Degraded(
                        "this host shows you every process; redaction is doing the work alone"
                            .into(),
                    )
                },
            ),
            (
                "memfd cannot be executed",
                if self.memfd_noexec {
                    State::Active
                } else if self.memfd_secret {
                    State::Degraded(
                        "vm.memfd_noexec is 0; memfd_secret is the remaining guard".into(),
                    )
                } else {
                    State::Degraded("vm.memfd_noexec is 0 and there is no memfd_secret".into())
                },
            ),
            (
                "protected_regular",
                if self.protected_regular {
                    State::Active
                } else {
                    State::Degraded(
                        "an O_CREAT in a sticky world-writable directory may follow another user's file"
                            .into(),
                    )
                },
            ),
        ]
    }

    /// The single word a CI job can assert on.
    pub fn tier_word(&self) -> &'static str {
        if self.ptrace && self.userns && self.memfd_secret {
            "redact+isolate+secret-mem"
        } else if self.ptrace && self.userns {
            "redact+isolate"
        } else if self.ptrace {
            "redact"
        } else {
            "sealed-fds"
        }
    }

    /// One line per mechanism: its state and what its absence costs.
    pub fn report(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "pmask capability report\n  arch={} kernel={} tier={}\n\n",
            self.arch,
            self.kernel,
            self.tier_word()
        ));
        for (name, st) in self.rows() {
            s.push_str(&format!(
                "  {:<24} {:<12} {}\n",
                name,
                st.as_word(),
                st.reason()
            ));
        }
        s.push_str(&format!(
            "\n  limits: memlock={} bytes, landlock ABI {}, yama.ptrace_scope={}, \
             CapEff={:016x}\n",
            self.memlock_limit,
            self.landlock_abi,
            self.ptrace_scope
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".into()),
            self.cap_effective
        ));
        s.push_str(
            "\n  What this means: with no ptrace, a secret passed as a command\n  \
             line argument is visible to every local account through\n  \
             /proc/<pid>/cmdline.  pmask's answer on such a host is to keep\n  \
             secrets out of argv and the environment entirely (fd delivery),\n  \
             which does not need ptrace at all.\n",
        );
        s
    }

    /// The same report as one JSON object, for a supervisor or a CI job
    /// that wants to decide without parsing prose.
    pub fn report_json(&self) -> String {
        let b = |v: bool| if v { "true" } else { "false" };
        let mut caps = String::new();
        for (i, (name, st)) in self.rows().into_iter().enumerate() {
            let key = name.replace([' ', '-'], "_");
            if i > 0 {
                caps.push(',');
            }
            caps.push_str(&format!(
                "\n    \"{}\": {{\"state\": \"{}\", \"reason\": \"{}\"}}",
                key,
                st.as_word(),
                json_escape(st.reason())
            ));
        }
        format!(
            concat!(
                "{{\n",
                "  \"arch\": \"{}\",\n",
                "  \"kernel\": \"{}\",\n",
                "  \"tier\": \"{}\",\n",
                "  \"secret_fds\": true,\n",
                "  \"memfd_secret\": {},\n",
                "  \"mlock\": {},\n",
                "  \"non_dumpable\": {},\n",
                "  \"seccomp_filter\": {},\n",
                "  \"metadata_redaction\": {},\n",
                "  \"exact_window\": {},\n",
                "  \"isolation\": {},\n",
                "  \"landlock_abi\": {},\n",
                "  \"no_new_privs\": {},\n",
                "  \"pidfd\": {},\n",
                "  \"peerpidfd\": {},\n",
                "  \"proc_hidden\": {},\n",
                "  \"memfd_noexec\": {},\n",
                "  \"protected_regular\": {},\n",
                "  \"limits\": {{\"memlock_bytes\": {}, \"ptrace_scope\": {}}},\n",
                "  \"caps\": {{{}\n  }}\n",
                "}}\n"
            ),
            json_escape(self.arch),
            json_escape(&self.kernel),
            self.tier_word(),
            b(self.memfd_secret),
            b(self.mlock),
            b(self.non_dumpable),
            b(self.seccomp_filter),
            b(self.ptrace),
            b(self.set_mm_map),
            b(self.userns),
            self.landlock_abi,
            b(self.no_new_privs),
            b(self.pidfd_open),
            b(self.peerpidfd),
            b(self.proc_hidden),
            b(self.memfd_noexec),
            b(self.protected_regular),
            self.memlock_limit,
            self.ptrace_scope
                .map(|v| v.to_string())
                .unwrap_or_else(|| "null".into()),
            caps
        )
    }
}

/// Read a sysctl through `/proc/sys`, trimmed.
fn sysctl(rel: &str) -> Option<String> {
    std::fs::read_to_string(format!("/proc/sys/{}", rel))
        .ok()
        .map(|s| s.trim().to_string())
}

/// True when `/proc` does not show this caller another uid's processes:
/// a `hidepid=2` or `hidepid=invisible` mount, or a `ProtectProc=invisible`
/// unit, which makes pid 1 unreadable.
fn procfs_hides_other_uids() -> bool {
    if let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") {
        for line in mounts.lines() {
            let mut f = line.split_whitespace();
            let _dev = f.next();
            let Some(mp) = f.next() else { continue };
            if mp != "/proc" {
                continue;
            }
            let _fs = f.next();
            let Some(opts) = f.next() else { continue };
            for o in opts.split(',') {
                if o == "hidepid=2" || o == "hidepid=invisible" {
                    return true;
                }
            }
        }
    }
    std::fs::read_to_string("/proc/1/status").is_err()
}

/// True when the kernel answers `getsockopt(SO_PEERPIDFD)` on a
/// connected socketpair.  The option is the mechanism the agent and the
/// daemon use; a release string is not evidence that it exists, because
/// a kernel can be built without it and a seccomp filter can refuse it.
fn probe_peerpidfd() -> bool {
    probe_in_child(|| {
        // SAFETY: a socketpair and getsockopt in a throwaway child.  The
        // child exits, so the descriptors are released either way.
        unsafe {
            let mut sv = [0 as libc::c_int; 2];
            if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
                return false;
            }
            let mut pidfd: libc::c_int = -1;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let rc = libc::getsockopt(
                sv[0],
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                &mut pidfd as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            );
            libc::close(sv[0]);
            libc::close(sv[1]);
            if rc != 0 || pidfd < 0 {
                return false;
            }
            libc::close(pidfd);
            true
        }
    })
}

fn kernel_release() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: plain uname into owned storage.
    if unsafe { libc::uname(&mut u) } == 0 {
        // SAFETY: release is a NUL-terminated array inside `u`.
        let s = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) };
        return s.to_string_lossy().into_owned();
    }
    "unknown".to_string()
}

/// Run `f` in a forked child and return its boolean verdict.
fn probe_in_child<F: FnOnce() -> bool>(f: F) -> bool {
    // SAFETY: single-threaded at probe time; the child only runs `f` and
    // `_exit`.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        let ok = f();
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    let mut status = 0i32;
    loop {
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        if w == -1 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        break;
    }
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

/// Escape the characters JSON requires, and drop the rest of the C0 range
/// (kernel release strings never contain them, but a report must be valid
/// JSON whatever it is handed).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str("\\uFFFD"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_does_not_panic() {
        let c = Caps::detect();
        assert!(!c.arch.is_empty());
        assert!(!c.kernel.is_empty());
        assert!(c.report().contains("capability report"));
    }

    #[test]
    fn json_is_well_formed() {
        let c = Caps::detect();
        let j = c.report_json();
        assert!(j.starts_with('{') && j.ends_with("}\n"));
        assert_eq!(j.matches('{').count(), j.matches('}').count());
        assert!(j.contains("\"tier\": \""));
        assert!(j.contains("\"memlock_bytes\": "));
        assert!(j.contains("\"landlock_abi\": "));
    }

    #[test]
    fn every_row_has_a_state_word() {
        let c = Caps::detect();
        for (name, st) in c.rows() {
            assert!(!name.is_empty());
            assert!(["active", "degraded", "unavailable"].contains(&st.as_word()));
        }
    }

    #[test]
    fn peerpidfd_comes_from_the_socket_option() {
        // The row is the probe's answer, not a comparison of the release
        // string: the probe is deterministic, and `detect` copies it.
        let probed = probe_peerpidfd();
        assert_eq!(probed, probe_peerpidfd());
        assert_eq!(Caps::detect().peerpidfd, probed);
    }

    #[test]
    fn probe_override_parses_only_zero_and_one() {
        assert_eq!(bool_value("0"), Some(false));
        assert_eq!(bool_value("1"), Some(true));
        assert_eq!(bool_value("true"), None);
        assert_eq!(bool_value(""), None);
        assert_eq!(bool_value("2"), None);
    }

    #[test]
    fn probe_overrides_replace_every_answer() {
        let c = Caps::detect_with(ProbeOverrides {
            ptrace: Some(false),
            userns: Some(false),
            landlock_abi: Some(0),
            memfd_secret: Some(false),
            memlock: Some(65536),
            proc_hidden: Some(true),
            peerpidfd: Some(false),
        });
        assert!(!c.ptrace);
        assert!(!c.userns);
        assert_eq!(c.landlock_abi, 0);
        assert!(!c.memfd_secret);
        assert_eq!(c.memlock_limit, 65536);
        assert!(c.proc_hidden);
        assert!(!c.peerpidfd);
    }

    #[test]
    fn probe_overrides_can_force_a_capability_on() {
        let c = Caps::detect_with(ProbeOverrides {
            ptrace: Some(true),
            userns: Some(true),
            landlock_abi: Some(6),
            memfd_secret: Some(true),
            memlock: Some(8388608),
            proc_hidden: Some(false),
            peerpidfd: Some(true),
        });
        assert!(c.ptrace);
        assert!(c.userns);
        assert_eq!(c.landlock_abi, 6);
        assert!(c.memfd_secret);
        assert_eq!(c.memlock_limit, 8388608);
        assert!(!c.proc_hidden);
        assert!(c.peerpidfd);
    }
}
