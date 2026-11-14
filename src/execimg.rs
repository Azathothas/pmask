//! exec-image surgery: redacting argv/envp at system call entry and
//! re-injecting the real arguments into hidden stack space at exec
//! completion.
//!
//! Entry (ELF targets): the inline `argv[]`/`envp[]` pointer arrays in
//! the *old* image are rewritten to point at a label string / empty
//! strings in scratch space, so the kernel never copies the real command
//! line or environment into the new image.  There is no window, however
//! short, in which the real data is visible through /proc.
//!
//! Completion (`PTRACE_EVENT_EXEC`): the saved real argv/envp strings are
//! written into an anonymous mapping injected inside the tracee and the
//! stack's inline arrays are repointed there.  `argc`, the array
//! positions and the auxiliary vector stay untouched, so every libc
//! (glibc, musl, static) starts up normally and sees its own arguments.
//! `prctl(PR_SET_NAME)` is injected through the tracee's vDSO in the
//! same stop.
//!
//! Scripts (`#!` files) are the exception: the kernel needs the real argv
//! to build the interpreter command line, so for those the copied strings
//! are zeroed and replaced by hidden copies after completion
//! (sub-millisecond exposure for the interpreter line only).

use crate::arch::{self, Regs};
use crate::remote::{
    dup_strings, peek_word, poke_word, read_cstr, read_ptr_array, write_mem, zero_range, MAX_ARGV,
    MAX_ENVV, MAX_HIDDEN, MAX_STRLEN,
};
use crate::tracer::{State, Tracer};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::time::Instant;
use zeroize::Zeroize;

/// A saved argv/envp vector that zeroes its strings when it goes out of
/// scope.  The supervisor must not keep the payload's real strings after
/// the redaction block has been written.
struct ScrubStrings(Vec<Vec<u8>>);

impl Drop for ScrubStrings {
    fn drop(&mut self) {
        for s in &mut self.0 {
            s.zeroize();
        }
    }
}

impl std::ops::Deref for ScrubStrings {
    type Target = Vec<Vec<u8>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ScrubStrings {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// syscall flavor of the exec currently in flight
#[derive(Clone, Copy, PartialEq)]
enum ExecFlavor {
    Execve,
    Execveat { dirfd: u64, flags: u64 },
}

impl ExecFlavor {
    /// (argv pointer, envp pointer) in the tracee.
    fn args(self, regs: &Regs) -> (u64, u64) {
        match self {
            ExecFlavor::Execve => (regs.arg(2), regs.arg(3)),
            ExecFlavor::Execveat { .. } => (regs.arg(3), regs.arg(4)),
        }
    }
}

fn flavor_of(nr: u64, regs: &Regs) -> ExecFlavor {
    if nr == arch::SYS_EXECVEAT {
        ExecFlavor::Execveat {
            dirfd: regs.arg(1),
            flags: regs.arg(5),
        }
    } else {
        ExecFlavor::Execve
    }
}

const AT_FDCWD: i32 = -100;
const AT_EMPTY_PATH: u64 = 0x1000;

struct RedactionBlock {
    str_addrs: Vec<u64>,
    comm_addr: u64,
    /// The anonymous mapping the block lives in, and the size the kernel
    /// actually mapped.
    base: u64,
    mapped: u64,
    /// Bytes reserved at the front of the mapping for the presentation
    /// area: the label, the NUL padding an audit reader walks, and the
    /// `AT_EXECFN` copy at `env_end`.
    pres: u64,
    /// First byte after the real strings: scratch for the
    /// `PR_SET_MM_MAP` struct and the auxiliary vector copy, so writing
    /// them can never land on the strings the payload reads.
    scratch: u64,
    /// Address of the second label copy, which is what `AT_EXECFN` is
    /// repointed at.
    execfn: u64,
    /// The compact kept-only environment span, when `--keep-env` names
    /// variables.  The kernel's environment window points here, so
    /// `/proc/<pid>/environ` reads the kept variables with no NUL
    /// padding from the original extent.
    env_window: Option<(u64, u64)>,
}

/// Why a completion stop could not fully redact an exec.
enum Fail {
    /// The tracee runs another ABI (32-bit): not redacted.
    Foreign,
    /// Redaction failed or was skipped: disclosure.
    Unredacted(String),
}

/// What moving the kernel's argv and environment windows did.
enum WindowOutcome {
    /// `PR_SET_MM_MAP` accepted the compact block.
    Moved,
    /// The kernel refused, with the errno it returned as a positive
    /// number (0 when the injection itself failed).
    Refused(i32),
    /// The tracee died during the injection.
    Gone,
}

/// What a completion stop did short of the zero-exposure path.
#[derive(Default)]
struct ExecFlags {
    script: bool,
    reexec: bool,
    comm_skipped: bool,
    failed: bool,
    foreign: bool,
    /// `PR_SET_MM_MAP` moved the kernel's argv window onto the compact
    /// presentation block, so `/proc/<pid>/cmdline` is exactly
    /// `label + 1` bytes and the environment window is empty.
    sized: bool,
    /// `PR_SET_MM_MAP` was refused: the kernel's own windows stay, so
    /// `cmdline` is the label padded with spaces and one final NUL, and
    /// `/proc/<pid>/environ` reads back as a decoy (or the kept
    /// variables) instead of empty.  The program's real argv is never in
    /// the kernel's window: the entry swap sees to that.
    sized_skipped: bool,
    /// The tracee was left detached: no supervisor remains for this pid.
    detached: bool,
    /// `--no-dumpable`/`--hide-pid`: the `PR_SET_DUMPABLE` injection
    /// was attempted on this completion.
    dumpable_done: bool,
    /// The injection failed or the completion returned before it ran, so
    /// this tracee stayed readable to its own uid.
    dumpable_failed: bool,
}

impl Tracer {
    /// execve/execveat entry stop: save the real strings, swap the inline
    /// arrays for ELF targets, defer to post-exec hiding otherwise.
    pub(super) fn on_exec_entry(&mut self, pid: libc::pid_t, nr: u64, regs: &Regs) {
        let flavor = flavor_of(nr, regs);
        let (av, ev) = flavor.args(regs);
        // `--exec-once` redirects a settled tracee's next exec and every
        // descendant's first exec.  The master's first exec already runs
        // from the image the child carries.
        let (was_settled, depth) = self
            .table
            .get(&pid)
            .map(|t| (t.state == State::Run, t.depth))
            .unwrap_or((false, 0));
        let redirect_ok = was_settled || depth > 0;

        {
            let Some(t) = self.table.get_mut(&pid) else {
                return;
            };
            t.clear_exec_state();
            t.av_addr = av;
            t.ev_addr = ev;
            // The exec is about to replace the address space, so the
            // presentation block that held the comm label goes with it.
            // The completion stop records the new block's address.
            t.rename_addr = 0;
        }

        // A vfork child shares its parent's address space until the exec.
        // Writing the entry swap there would change the parent's memory;
        // gcc's clone3(CLONE_VM|CLONE_VFORK) run of cc1 is the measured
        // case, and it corrupted the parent's heap.  The child takes the
        // post-exec path instead: the exec runs unswapped and the
        // completion redacts the new image.
        if self.table.get(&pid).map(|t| t.vfork_child).unwrap_or(false) {
            vlog!(self, "pid {}: vfork child, post-exec mode", pid);
            if self.cfg.rexec_per_exec {
                self.stats.vfork_cache_skipped += 1;
                vlog!(
                    self,
                    "pid {}: vfork child takes the post-exec path; --exec-once cache tag not applied",
                    pid
                );
            }
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        let mut overflow = false;
        let avarr = if av != 0 {
            read_ptr_array(pid, av, MAX_ARGV)
        } else {
            None
        };
        let evarr = if ev != 0 {
            read_ptr_array(pid, ev, MAX_ENVV)
        } else {
            None
        };
        // An array without its terminator inside the cap is incomplete:
        // the swap would leave the tail entries real.
        if matches!(avarr, Some((_, false))) || matches!(evarr, Some((_, false))) {
            overflow = true;
        }
        let avarr = avarr.map(|(v, _)| v);
        let evarr = evarr.map(|(v, _)| v);

        let mut seal_errors: Vec<String> = Vec::new();
        {
            let key = self.cfg.session_key.clone();
            let Some(t) = self.table.get_mut(&pid) else {
                return;
            };
            if let Some(arr) = &avarr {
                let mut v = dup_strings(pid, arr, &mut overflow);
                t.av_save = Some(arr.clone());
                if let (Some(key), Some(strings)) = (&key, &v) {
                    match crate::crypto::EncryptedStrings::seal(key, strings) {
                        Ok(sealed) => {
                            t.sealed_argv = Some(sealed);
                            crate::tracer::zeroize_strings(&mut v);
                        }
                        Err(e) => seal_errors.push(format!("pid {}: argv seal failed: {}", pid, e)),
                    }
                }
                t.argv = v;
            }
            if let Some(arr) = &evarr {
                let mut v = dup_strings(pid, arr, &mut overflow);
                t.ev_save = Some(arr.clone());
                if let (Some(key), Some(strings)) = (&key, &v) {
                    match crate::crypto::EncryptedStrings::seal(key, strings) {
                        Ok(sealed) => {
                            t.sealed_envp = Some(sealed);
                            crate::tracer::zeroize_strings(&mut v);
                        }
                        Err(e) => seal_errors.push(format!("pid {}: env seal failed: {}", pid, e)),
                    }
                }
                t.envp = v;
            }
        }
        if !seal_errors.is_empty() {
            // The note says "at-rest copies", so count each copy: an exec
            // whose argv and envp both failed to seal leaves two.
            self.stats.seal_failures += seal_errors.len() as u32;
            for msg in seal_errors {
                self.warn(format_args!("{}", msg));
            }
        }
        // Count the copies that are sealed now.  `clear_exec_state`
        // cleared both fields before this entry stop, so a `Some` here
        // is a seal this exec produced, not one inherited from before.
        let sealed_now = self
            .table
            .get(&pid)
            .map(|t| t.sealed_argv.is_some() as u32 + t.sealed_envp.is_some() as u32)
            .unwrap_or(0);
        self.stats.sealed += sealed_now;
        if self
            .table
            .get(&pid)
            .map(|t| t.argv.is_some() || t.envp.is_some())
            .unwrap_or(false)
        {
            self.set_pending(pid, true);
        }

        let avn = avarr.as_ref().map(|v| v.len()).unwrap_or(0);
        let evn = evarr.as_ref().map(|v| v.len()).unwrap_or(0);

        if overflow || avarr.is_none() {
            vlog!(self, "pid {}: argv unreadable/huge, post-exec mode", pid);
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        let image = self.exec_path(pid, flavor, regs);
        let elf = image
            .as_ref()
            .map(|p| self.path_is_elf(pid, p))
            .unwrap_or(false);
        // A 64-bit supervisor cannot read or write the registers of a
        // 32-bit image, so it cannot redact it.  Refuse loudly instead
        // of swapping argv and then failing: the program keeps its real
        // arguments and the session summary names the exec.
        let foreign_image = elf
            && image
                .as_ref()
                .map(|p| self.elf_is_32(pid, p))
                .unwrap_or(false);
        if foreign_image {
            if self.cfg.allow_foreign {
                vlog!(
                    self,
                    "pid {}: 32-bit image, running unredacted (--allow-foreign)",
                    pid
                );
                self.set_state(pid, State::Foreign);
                self.resume_exec_entry(pid);
                return;
            }
            // The image would run with its real argv, environ and comm.
            // Refuse before the exec: kill the tracee at the entry stop.
            self.stats.foreign_refused += 1;
            self.warn(format_args!(
                "pid {}: 32-bit (foreign ABI) program refused; a 32-bit image cannot \
                 be redacted, so it is not run unless --allow-foreign is set",
                pid
            ));
            self.set_state(pid, State::Foreign);
            // SAFETY: plain kill(2) of a stopped tracee; the pending
            // SIGKILL is delivered when it resumes.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            self.resume(pid, 0, false);
            return;
        }

        if !elf {
            // script / unknown: the kernel needs the real argv to build
            // the interpreter line; redact after completion instead.
            vlog!(self, "pid {}: script/unknown exec, post-exec mode", pid);
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        // `--exec-once`: point a settled tracee's exec at a cached image
        // the tracer holds.  The image is written to the scratch area
        // below the stack and the filename argument is repointed at it.
        let mut rexec_redirect: Option<(std::sync::Arc<crate::rexec::Image>, Vec<u8>)> = None;
        if self.cfg.rexec_per_exec && redirect_ok {
            if let Some(path) = &image {
                match self.rexec_redirect_for(pid, path) {
                    Ok(Some((img, text))) => {
                        let mut bytes = text.into_bytes();
                        bytes.push(0);
                        rexec_redirect = Some((img, bytes));
                    }
                    Ok(None) => {}
                    Err(e) => self.warn(format_args!(
                        "pid {}: --exec-once image unavailable: {}",
                        pid, e
                    )),
                }
            }
        }

        // scratch below the old SP: [label][NUL][zero-filled remainder]
        let sp = regs.sp();
        let label = self.cfg.label.clone();
        // `fl` is capped at 255 so `empty_str` (base+fl) always lands on a
        // byte inside the zeroed scratch; a longer label would otherwise
        // point at uninitialised stack memory.
        let mut scratch = [0u8; 256];
        let fl = (label.len() + 1).clamp(1, 255);
        scratch[..fl - 1].copy_from_slice(&label[..fl - 1]);
        let base = sp - 4096;
        let fake_str = base;
        let empty_str = base + fl as u64;
        if write_mem(pid, base, &scratch) != scratch.len() as isize {
            vlog!(self, "pid {}: scratch write failed, post-exec mode", pid);
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        // The redirect path lives after the 256-byte label scratch, so a
        // long label cannot overwrite it and it cannot overwrite the
        // label.  It must also stay below the stack pointer: a path that
        // reached `sp` would overwrite the tracee's live stack, and a
        // truncated path names a different file, so the redirect is
        // dropped and the exec runs the original path.
        let redirect_addr = base + 512;
        if let Some((_, bytes)) = &rexec_redirect {
            if redirect_addr + bytes.len() as u64 > sp {
                vlog!(
                    self,
                    "pid {}: --exec-once redirect path ({} bytes at {:#x}) would reach the stack at {:#x}; not applied",
                    pid,
                    bytes.len(),
                    redirect_addr,
                    sp
                );
                rexec_redirect = None;
            } else if write_mem(pid, redirect_addr, bytes) != bytes.len() as isize {
                self.warn(format_args!(
                    "pid {}: --exec-once redirect path could not be written",
                    pid
                ));
                rexec_redirect = None;
            }
        }

        // rewrite the inline argv array: label, then empty strings
        let mut nv = vec![empty_str; avn + 1];
        if avn > 0 {
            nv[0] = fake_str;
        }
        nv[avn] = 0;
        let nv_bytes = ptr_words_bytes(&nv);
        if write_mem(pid, av, &nv_bytes) != nv_bytes.len() as isize {
            // A partial write leaves a mix: put the originals back.
            if let Some(t) = self.table.get(&pid) {
                if let Some(save) = &t.av_save {
                    let _ = write_mem(pid, av, &ptr_words_bytes(save));
                }
            }
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        // same treatment for the environment, except for variables the
        // caller asked to keep visible
        if self.cfg.redact_environ && evarr.is_some() {
            let envp = self
                .table
                .get(&pid)
                .and_then(|t| t.envp.clone())
                .unwrap_or_default();
            let orig_ptrs = evarr.clone().unwrap_or_default();
            let mut ne = vec![empty_str; evn + 1];
            for (i, slot) in ne.iter_mut().enumerate().take(evn) {
                if self.is_kept_env(envp.get(i)) {
                    *slot = orig_ptrs[i];
                }
            }
            ne[evn] = 0;
            let ne_bytes = ptr_words_bytes(&ne);
            if write_mem(pid, ev, &ne_bytes) == ne_bytes.len() as isize {
                if let Some(t) = self.table.get_mut(&pid) {
                    t.env_swapped = true;
                }
            } else if let Some(t) = self.table.get(&pid) {
                if let Some(save) = &t.ev_save {
                    let _ = write_mem(pid, ev, &ptr_words_bytes(save));
                }
            }
        }

        if let Some((image, _)) = rexec_redirect {
            let mut r = *regs;
            match flavor {
                ExecFlavor::Execve => r.set_arg(1, redirect_addr),
                ExecFlavor::Execveat { .. } => {
                    r.set_arg(1, AT_FDCWD as u64);
                    r.set_arg(2, redirect_addr);
                }
            }
            match r.put(pid) {
                Ok(()) => {
                    if let Some(t) = self.table.get_mut(&pid) {
                        t.rexec_image = Some(image);
                    }
                    vlog!(
                        self,
                        "pid {}: exec redirected to a cached image at {:#x}",
                        pid,
                        redirect_addr
                    );
                }
                Err(e) => self.warn(format_args!(
                    "pid {}: --exec-once redirect not applied: {}",
                    pid, e
                )),
            }
        }

        self.set_state(pid, State::Swapped);
        self.resume_exec_entry(pid);
        vlog!(
            self,
            "pid {}: entry pointer-swap (ELF) argc={} envc={}",
            pid,
            avn,
            evn
        );
    }

    /// Open a sealed argv/envp copy, or pass the plaintext copy through.
    /// A failed open is a disclosure risk, so it is reported and the
    /// caller fails closed.
    fn open_sealed(
        &self,
        pid: libc::pid_t,
        sealed: Option<crate::crypto::EncryptedStrings>,
        plain: Option<Vec<Vec<u8>>>,
    ) -> Option<Vec<Vec<u8>>> {
        match (sealed, &self.cfg.session_key) {
            (Some(s), Some(key)) => match s.open(key) {
                Ok(v) => Some(v),
                Err(e) => {
                    self.warn(format_args!(
                        "pid {}: sealed strings could not be opened: {}",
                        pid, e
                    ));
                    None
                }
            },
            (Some(_), None) => {
                self.warn(format_args!(
                    "pid {}: sealed strings have no session key",
                    pid
                ));
                None
            }
            (None, _) => plain,
        }
    }

    /// Does this environment string name a variable that stays visible?
    fn is_kept_env(&self, s: Option<&Vec<u8>>) -> bool {
        let Some(s) = s else { return false };
        if self.cfg.keep_env.is_empty() {
            return false;
        }
        let name = match s.iter().position(|&b| b == b'=') {
            Some(p) => &s[..p],
            None => &s[..],
        };
        self.cfg.keep_env.iter().any(|k| k.as_slice() == name)
    }

    /// Restore the original inline arrays after a failed exec.
    pub(super) fn restore_orig_arrays(&mut self, pid: libc::pid_t) {
        let (av_addr, av_save, ev_addr, ev_save, env_swapped) = {
            let Some(t) = self.table.get_mut(&pid) else {
                return;
            };
            if t.state != State::Swapped {
                return;
            }
            (
                t.av_addr,
                t.av_save.clone(),
                t.ev_addr,
                t.ev_save.clone(),
                t.env_swapped,
            )
        };
        if av_addr != 0 {
            if let Some(save) = &av_save {
                let _ = write_mem(pid, av_addr, &ptr_words_bytes(save));
            }
        }
        if env_swapped && ev_addr != 0 {
            if let Some(save) = &ev_save {
                let _ = write_mem(pid, ev_addr, &ptr_words_bytes(save));
            }
        }
        let sealed = self
            .table
            .get(&pid)
            .map(|t| t.sealed_argv.is_some() as u32 + t.sealed_envp.is_some() as u32)
            .unwrap_or(0);
        if let Some(t) = self.table.get_mut(&pid) {
            t.av_save = None;
            t.ev_save = None;
            crate::tracer::zeroize_strings(&mut t.argv);
            crate::tracer::zeroize_strings(&mut t.envp);
            t.sealed_argv = None;
            t.sealed_envp = None;
            t.env_swapped = false;
        }
        // The exec failed, so the copies sealed at its entry stop were
        // never used.  Do not let a failed attempt make the run report
        // `encrypted`.
        self.stats.sealed = self.stats.sealed.saturating_sub(sealed);
        self.set_pending(pid, false);
    }

    /// exec completed (`PTRACE_EVENT_EXEC`, or the exec's syscall-exit
    /// stop on kernels that skip the event): re-inject the real arguments
    /// into the injected anonymous mapping, zero the visible copies,
    /// inject the comm label.
    ///
    /// Every path ends in `finish_exec_complete`, which resumes the
    /// tracee: a tracee left stopped wedges the whole tree.
    pub(super) fn on_exec_complete(&mut self, pid: libc::pid_t, at_exit_stop: bool) {
        self.drain_rexec_report();
        if self
            .table
            .get(&pid)
            .map(|t| t.foreign_done)
            .unwrap_or(false)
        {
            // The tracee already ran a 32-bit image under --allow-foreign.
            // A later exec cannot be redacted; kill it before the new
            // image runs.
            self.stats.foreign_refused += 1;
            self.warn(format_args!(
                "pid {}: a later exec of a tracee that already ran a 32-bit image is refused; the 64-bit tracer cannot redact it",
                pid
            ));
            // SAFETY: plain kill(2) of a stopped tracee.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            self.resume(pid, 0, false);
            return;
        }
        let started = Instant::now();
        let reads0 = crate::remote::READ_CALLS.load(std::sync::atomic::Ordering::Relaxed);
        self.stats.execs += 1;
        let mut flags = ExecFlags::default();
        let mut pending_stop: Option<i32> = None;
        match self.redact_after_exec(pid, &mut flags, &mut pending_stop) {
            Ok(()) => {}
            Err(Fail::Foreign) => {
                flags.foreign = true;
                self.warn(format_args!(
                    "pid {}: 32-bit (foreign ABI) program is not redacted",
                    pid
                ));
            }
            Err(Fail::Unredacted(why)) => {
                flags.failed = true;
                self.warn(format_args!("pid {}: exec not redacted: {}", pid, why));
            }
        }
        // A completion that returned before the dumpable injection leaves
        // the payload dumpable, even though the mask asked for the
        // opposite.  The report must say so.
        if self.cfg.no_dumpable && !flags.dumpable_done {
            flags.dumpable_failed = true;
        }
        if flags.foreign && !self.cfg.allow_foreign {
            // A 32-bit image that bypassed the entry refusal (a foreign
            // `execve` from a settled tracee, a vfork child, or a
            // post-exec path) reaches its completion stop with the real
            // argv already copied by the kernel.  Refuse it before the
            // image runs.  It is counted as refused, not as a foreign
            // exec that ran, so `account` is skipped.
            self.stats.foreign_refused += 1;
            self.warn(format_args!(
                "pid {}: 32-bit (foreign ABI) program refused at completion; a 32-bit \
                 image cannot be redacted, so it is not run unless --allow-foreign is set",
                pid
            ));
            // SAFETY: plain kill(2) of a stopped tracee; the pending
            // SIGKILL is delivered when it resumes.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            self.resume(pid, 0, false);
            return;
        }
        self.account(&flags);
        if flags.foreign && self.cfg.allow_foreign {
            if let Some(t) = self.table.get_mut(&pid) {
                t.foreign_done = true;
            }
            vlog!(
                self,
                "pid {}: 32-bit image settled, later execs will be refused",
                pid
            );
        }
        if self.cfg.audit {
            self.audit_row(pid);
        }
        let reads = crate::remote::READ_CALLS.load(std::sync::atomic::Ordering::Relaxed) - reads0;
        vlog!(
            self,
            "pid {}: completion-stop {}us reads={}",
            pid,
            started.elapsed().as_micros(),
            reads
        );
        self.finish_exec_complete(pid, at_exit_stop);
        if let Some(sig) = pending_stop {
            // A group-stop signal that arrived inside the injection
            // window was restarted: raise it again.
            // SAFETY: plain kill(2) of a tracee.
            unsafe { libc::kill(pid, sig) };
        }
    }

    fn account(&mut self, f: &ExecFlags) {
        let s = &mut self.stats;
        if f.script {
            s.script += 1;
        }
        if f.reexec {
            s.reexec += 1;
        }
        if f.comm_skipped {
            s.comm_skipped += 1;
        }
        if f.failed {
            s.unredacted += 1;
        }
        if f.foreign {
            s.foreign_arch += 1;
        }
        if f.sized {
            s.sized += 1;
        }
        if f.sized_skipped {
            s.sized_skipped += 1;
        }
        if f.detached {
            s.detached += 1;
        }
        if f.dumpable_failed {
            s.dumpable_failed += 1;
        }
        if f.script || f.reexec || f.comm_skipped || f.failed || f.foreign {
            s.degraded += 1;
        }
    }

    fn poke(&mut self, pid: libc::pid_t, addr: u64, val: u64) -> bool {
        self.poke_count += 1;
        if self.fault_poke_at != 0 && self.poke_count == self.fault_poke_at {
            vlog!(
                self,
                "pid {}: fault injection: repoint write {} fails",
                pid,
                self.poke_count
            );
            return false;
        }
        poke_word(pid, addr, val)
    }

    /// Zero the argv and environment string regions the kernel copied.
    ///
    /// Every failure after the spans are known calls this: a redaction
    /// that cannot place the real strings in the hidden block must not
    /// leave them in the region `/proc` serves.  The program may then see
    /// empty arguments, and the session summary counts the exec as
    /// unredacted.  With `redact_environ` off the environment is the
    /// caller's to keep, so only the argv span is zeroed.
    fn zero_visible_spans(
        &self,
        pid: libc::pid_t,
        arg_lo: u64,
        arg_hi: u64,
        env_lo: u64,
        env_hi: u64,
    ) {
        if arg_lo < arg_hi {
            zero_range(pid, arg_lo, arg_hi);
        }
        if self.cfg.redact_environ && env_lo < env_hi {
            zero_range(pid, env_lo, env_hi);
        }
    }

    fn redact_after_exec(
        &mut self,
        pid: libc::pid_t,
        flags: &mut ExecFlags,
        pending_stop: &mut Option<i32>,
    ) -> Result<(), Fail> {
        let orig_regs = match Regs::get(pid) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::Unsupported => return Err(Fail::Foreign),
            Err(e) => return Err(Fail::Unredacted(format!("registers unreadable: {}", e))),
        };
        let sp = orig_regs.sp();

        let state = match self.table.get(&pid) {
            Some(t) => t.state,
            None => return Err(Fail::Unredacted("no bookkeeping for the tracee".into())),
        };
        let reread = state != State::Swapped;
        match state {
            State::Foreign => return Err(Fail::Foreign),
            State::Script => flags.script = true,
            State::Swapped => {}
            State::Run | State::Slow => flags.reexec = true,
        }
        // The reread path copies the real strings into this process
        // before it builds the block.  The swapped path already marked
        // the tracee pending at the entry stop.
        if reread {
            self.set_pending(pid, true);
        }

        let Some(kargc) = peek_word(pid, sp).filter(|v| *v <= MAX_ARGV as u64) else {
            return Err(Fail::Unredacted("argc unreadable or implausible".into()));
        };
        let kargv = sp + 8;
        let kenvp = kargv + (kargc + 1) * 8;
        let Some((kav, kav_done)) = read_ptr_array(pid, kargv, MAX_ARGV + 1) else {
            return Err(Fail::Unredacted("kernel argv array unreadable".into()));
        };
        let Some((kev, kev_done)) = read_ptr_array(pid, kenvp, MAX_ENVV + 1) else {
            return Err(Fail::Unredacted("kernel envp array unreadable".into()));
        };

        // 1. the visible string regions the kernel filled (zeroed on every
        //    failure below): exact bounds from /proc/<pid>/stat; inferred
        //    from the pointer arrays when the kernel hides them
        //    (non-dumpable tracee).
        let (arg_lo, arg_hi, env_lo, env_hi) = match proc_stat_bounds(pid, sp) {
            Some(b) => b,
            None => {
                vlog!(self, "pid {}: no stat bounds, inferring string spans", pid);
                let (al, ah) = string_span(pid, &kav);
                let (el, eh) = if self.cfg.redact_environ {
                    string_span(pid, &kev)
                } else {
                    (u64::MAX, 0)
                };
                (al, ah, el, eh)
            }
        };
        // An array without its terminator inside the cap is incomplete:
        // the real tail would stay visible, so fail closed on the span.
        if !kav_done || !kev_done {
            self.zero_visible_spans(pid, arg_lo, arg_hi, env_lo, env_hi);
            return Err(Fail::Unredacted("argv or envp array too large".into()));
        }

        // 2. real argv/envp strings: from the saved copy (swapped path) or
        //    re-read from the kernel-copied stack (script / missed entry).
        //    Every failure from here on zeroes the visible spans first: a
        //    redaction that cannot place the real strings in the hidden
        //    block must not leave them where /proc serves them.
        let (argv, envp) = if !reread {
            let (sealed_a, sealed_e, plain_a, plain_e) = match self.table.get_mut(&pid) {
                Some(t) => (
                    t.sealed_argv.take(),
                    t.sealed_envp.take(),
                    t.argv.take(),
                    t.envp.take(),
                ),
                None => (None, None, None, None),
            };
            (
                self.open_sealed(pid, sealed_a, plain_a),
                self.open_sealed(pid, sealed_e, plain_e),
            )
        } else {
            let mut overflow = false;
            let n = kav.len().min(kargc as usize);
            let a = dup_strings(pid, &kav[..n], &mut overflow);
            let e = dup_strings(pid, &kev, &mut overflow);
            if overflow {
                self.zero_visible_spans(pid, arg_lo, arg_hi, env_lo, env_hi);
                return Err(Fail::Unredacted(
                    "argv/env strings too large to relocate".into(),
                ));
            }
            (a, e)
        };
        let Some(mut argv) = argv else {
            self.zero_visible_spans(pid, arg_lo, arg_hi, env_lo, env_hi);
            return Err(Fail::Unredacted("real argv unavailable".into()));
        };
        let mut envp = envp.unwrap_or_default();
        if argv.len() as u64 != kargc {
            self.zero_visible_spans(pid, arg_lo, arg_hi, env_lo, env_hi);
            return Err(Fail::Unredacted(format!(
                "argc mismatch: saved {} kernel {}",
                argv.len(),
                kargc
            )));
        }
        let argc = argv.len();
        let envc = envp.len().min(kev.len());
        vlog!(
            self,
            "pid {}: exec-done reread={} argc={} envc={}",
            pid,
            reread as u8,
            kargc,
            envc
        );

        // 3. build the redaction block with the real strings in the
        //    injected anonymous mapping.  The build ends with the tracee
        //    stopped at the exit of an injected syscall (or untouched when
        //    it failed before one), so put the pristine exec-exit
        //    registers back before anything else runs.
        let block = match self.build_redaction_block(pid, &argv, &envp[..envc], pending_stop) {
            Ok(b) => b,
            Err(e) => {
                let _ = orig_regs.put(pid);
                // Fail closed on the visible strings: empty is better
                // than real.  The program may misbehave; the secret does
                // not leak.
                self.zero_visible_spans(pid, arg_lo, arg_hi, env_lo, env_hi);
                for s in &mut argv {
                    s.zeroize();
                }
                for s in &mut envp {
                    s.zeroize();
                }
                return Err(Fail::Unredacted(format!("redaction block failed: {}", e)));
            }
        };
        let _ = orig_regs.put(pid);
        // The block now holds the real strings in the tracee.  Zero the
        // supervisor's copies when this function returns, on every path.
        let _argv = ScrubStrings(argv);
        let envp = ScrubStrings(envp);

        // From here until the tracee's next exec, a `prctl(PR_SET_NAME)`
        // redirect can point at the label that already sits in this
        // block.  `--watch-rename` uses that instead of writing a fresh
        // copy into the tracee, which a `--no-dumpable` tracee refuses
        // (issue 60).
        if let Some(t) = self.table.get_mut(&pid) {
            t.rename_addr = block.comm_addr;
        }

        // 4. repoint the inline arrays at the hidden strings
        let mut repoint_ok = true;
        for i in 0..argc {
            if !self.poke(pid, kargv + (i as u64) * 8, block.str_addrs[i]) {
                repoint_ok = false;
                break;
            }
        }
        if repoint_ok {
            for i in 0..envc {
                if !self.poke(pid, kenvp + (i as u64) * 8, block.str_addrs[argc + i]) {
                    repoint_ok = false;
                    break;
                }
            }
        }
        if !repoint_ok {
            // At least one pointer still names the kernel copy.  Zero the
            // whole kernel region: the worst visible result is empties.
            flags.failed = true;
            self.warn(format_args!(
                "pid {}: repoint failed, zeroing the visible argv and environ",
                pid
            ));
            self.zero_visible_spans(pid, arg_lo, arg_hi, env_lo, env_hi);
            // The pristine registers were restored after the block build
            // and this path changes none; restore again so the invariant
            // is local to the failure: the tracee resumes through
            // `Tracer::resume` with its own registers.
            let _ = orig_regs.put(pid);
            return Ok(());
        }

        // 5. present the visible spans.  The exact path has already
        //    moved the kernel's windows onto the block, so this only
        //    clears the dead original extent.  The `--no-exact` path
        //    (or a kernel that refused PR_SET_MM_MAP) keeps the original
        //    windows, so the presentation is what `/proc` serves: the
        //    label padded with spaces (no NUL run) and a plausible
        //    environment (the kept variables, then a fixed decoy).
        let label = self.cfg.label.clone();
        if arg_lo < arg_hi {
            fill_arg_window(pid, arg_lo, arg_hi, &label);
        }
        if self.cfg.redact_environ && env_lo < env_hi {
            let kept: Vec<&[u8]> = if self.cfg.keep_env.is_empty() {
                Vec::new()
            } else {
                envp.iter()
                    .filter(|s| self.is_kept_env(Some(s)))
                    .map(|s| s.as_slice())
                    .collect()
            };
            fill_env_window(pid, env_lo, env_hi, &kept);
        }

        // 6. inject the comm label (and the dumpable flag) via a syscall
        //    instruction of the tracee itself
        let auxv_at = kenvp + (kev.len() as u64 + 1) * 8;
        let Some(site) = crate::inject::find_syscall_site(pid, Some(auxv_at), self.fault_no_vdso)
        else {
            flags.comm_skipped = true;
            self.warn(format_args!(
                "pid {}: no syscall instruction found; comm not set",
                pid
            ));
            return Ok(());
        };
        let save = match Regs::get(pid) {
            Ok(r) => r,
            Err(_) => {
                flags.comm_skipped = true;
                return Ok(());
            }
        };

        // 6a. give the kernel the compact presentation block as the argv
        //     and environment window.  This runs after the visible spans
        //     were zeroed, so nothing can read the old extent.
        if self.cfg.exact {
            if self.fault_refuse_map {
                // Reachability hook for the degraded path: a kernel without
                // CAP_SYS_RESOURCE refuses this call, and the fault suite
                // must see the same summary line.
                flags.sized_skipped = true;
                vlog!(
                    self,
                    "pid {}: fault injection: PR_SET_MM_MAP refused (EPERM)",
                    pid
                );
            } else {
                match self.relocate_windows(pid, &save, site, &block, argc, pending_stop) {
                    WindowOutcome::Moved => flags.sized = true,
                    WindowOutcome::Refused(errno) => {
                        flags.sized_skipped = true;
                        vlog!(
                            self,
                            "pid {}: PR_SET_MM_MAP refused ({}), window keeps its extent",
                            pid,
                            errno
                        );
                    }
                    WindowOutcome::Gone => return Ok(()),
                }
            }
        }

        let r1 = crate::inject::run_remote_syscall(
            pid,
            &save,
            arch::SYS_PRCTL,
            [libc::PR_SET_NAME as u64, block.comm_addr, 0, 0, 0, 0],
            site,
            pending_stop,
        );
        let mut tracee_gone = false;
        match r1 {
            Ok(0) => {}
            Ok(rv) => {
                flags.comm_skipped = true;
                self.warn(format_args!("pid {}: PR_SET_NAME returned {}", pid, rv));
            }
            Err(e) => {
                flags.comm_skipped = true;
                tracee_gone = self.injection_failed(pid, "comm", &e);
            }
        }
        if !tracee_gone && self.cfg.no_dumpable {
            flags.dumpable_done = true;
            let r2 = crate::inject::run_remote_syscall(
                pid,
                &save,
                arch::SYS_PRCTL,
                [libc::PR_SET_DUMPABLE as u64, 0, 0, 0, 0, 0],
                site,
                pending_stop,
            );
            match r2 {
                Ok(0) => {}
                Ok(rv) => {
                    flags.failed = true;
                    flags.dumpable_failed = true;
                    self.warn(format_args!("pid {}: PR_SET_DUMPABLE returned {}", pid, rv));
                }
                Err(e) => {
                    flags.failed = true;
                    flags.dumpable_failed = true;
                    tracee_gone = self.injection_failed(pid, "dumpable", &e);
                }
            }
        }
        if !tracee_gone && self.cfg.fast_exec {
            let installed = self
                .table
                .get(&pid)
                .map(|t| t.exec_filter_installed)
                .unwrap_or(false);
            if !installed {
                match self.install_exec_filter(pid, site, &block, pending_stop) {
                    Ok(()) => {
                        if let Some(t) = self.table.get_mut(&pid) {
                            t.exec_filter_installed = true;
                            // A later successful install clears an earlier
                            // failure; otherwise the tracee stays
                            // syscall-supervised for the rest of its life.
                            t.fast_exec_failed = false;
                        }
                    }
                    Err(e) => {
                        flags.failed = true;
                        if let Some(t) = self.table.get_mut(&pid) {
                            t.fast_exec_failed = true;
                        }
                        self.warn(format_args!(
                            "pid {}: seccomp exec filter not installed ({}); the tracee stays \
                             syscall-supervised",
                            pid, e
                        ));
                    }
                }
            }
        }
        if !tracee_gone {
            // final registers: the pristine exec-exit state
            if orig_regs.put(pid).is_err() {
                vlog!(self, "pid {}: regs restore failed", pid);
            }
            vlog!(self, "pid {}: redacted", pid);
        }
        Ok(())
    }

    // ------------------------------------------------------------ helpers --

    /// Move the kernel's argv and environment windows onto the compact
    /// presentation block at the front of `block`.
    ///
    /// The map replaces every `mm_struct` address the kernel validates,
    /// so the values for the segments this exec has come from
    /// `/proc/<pid>/stat` and `brk(0)`; a zero or absent value is what
    /// makes the kernel answer `EINVAL`.  `AT_EXECFN` in `saved_auxv` is
    /// rewritten to the label in the same call, so `/proc/<pid>/auxv`
    /// agrees with `/proc/<pid>/cmdline`.
    fn relocate_windows(
        &mut self,
        pid: libc::pid_t,
        regs: &Regs,
        site: u64,
        block: &RedactionBlock,
        argc: usize,
        pending_stop: &mut Option<i32>,
    ) -> WindowOutcome {
        let label = self.cfg.label.clone();
        let brk = match crate::inject::run_remote_syscall(
            pid,
            regs,
            arch::SYS_BRK,
            [0, 0, 0, 0, 0, 0],
            site,
            pending_stop,
        ) {
            Ok(b) if b > 0 => b as u64,
            Ok(_) => 0,
            Err(_) => return WindowOutcome::Gone,
        };
        let Some(mut fields) = crate::presetmm::read_fields(pid, brk) else {
            return WindowOutcome::Refused(0);
        };

        // The presentation is `label` then `argc` NULs, which satisfies
        // both readers: cmdline stops at the first NUL, audit walks argc
        // NUL-terminated strings and never faults.
        let arg_end = block.base + label.len() as u64 + 1;
        let audit_end = arg_end + argc as u64;
        if audit_end > block.base + block.pres {
            return WindowOutcome::Refused(0);
        }
        fields.arg_start = block.base;
        fields.arg_end = arg_end;
        if self.cfg.redact_environ {
            if let Some((start, end)) = block.env_window {
                // `--keep-env=NAME`: the window is the compact kept-only
                // span in the block, not the original extent.
                fields.env_start = start;
                fields.env_end = end;
            } else {
                fields.env_start = audit_end;
                fields.env_end = audit_end;
            }
        } else {
            // `--keep-env` with no names keeps the whole environment
            // visible; the window stays where the kernel put it.
            let _ = audit_end;
        }
        // `start_stack` must be a real address above `mmap_min_addr` and
        // is otherwise unconstrained; pointing it at the block keeps a
        // `[stack]` entry in `/proc/<pid>/maps` exactly as before.
        fields.start_stack = block.base;

        let auxv = crate::presetmm::read_auxv(pid).map(|a| (a, block.execfn));
        let scratch = crate::presetmm::Scratch {
            site,
            addr: block.scratch,
        };
        let _ = block.mapped;
        match crate::presetmm::relocate(
            pid,
            regs,
            scratch,
            &fields,
            auxv.as_ref().map(|(a, f)| (a.as_slice(), *f)),
            pending_stop,
        ) {
            crate::presetmm::Relocated::Yes => WindowOutcome::Moved,
            crate::presetmm::Relocated::Refused(e) => WindowOutcome::Refused(e),
            crate::presetmm::Relocated::NoFields => WindowOutcome::Refused(0),
        }
    }

    /// Resume from the entry stop; the next stop is either
    /// `PTRACE_EVENT_EXEC` (completion runs there) or, on kernels that
    /// skip the exec event for seccomp-resumed entries, the exec's
    /// syscall-exit stop (completion runs there, for the swapped and the
    /// script path alike).  Both leave the tracee in Run.
    fn resume_exec_entry(&mut self, pid: libc::pid_t) {
        self.resume(pid, 0, true);
    }

    /// Common tail of `on_exec_complete`.
    ///
    /// `at_exit_stop`: the completion is running at the exec's
    /// syscall-exit stop (answering that stop) rather than at
    /// `PTRACE_EVENT_EXEC` (whose syscall-exit stop still has to be
    /// consumed).  In both cases the tracee settles straight back to
    /// Run: the exec is done.
    fn finish_exec_complete(&mut self, pid: libc::pid_t, at_exit_stop: bool) {
        self.set_pending(pid, false);
        // Every early return in the completion path lands here.  If the
        // exec filter was never installed, the settled tracee must stay
        // syscall-supervised: `resume_state` checks this flag.  Without
        // it a completion that failed before the install would be
        // resumed with PTRACE_CONT and its next exec would run with no
        // entry swap and no filter.
        if self.cfg.fast_exec
            && self
                .table
                .get(&pid)
                .map(|t| !t.exec_filter_installed)
                .unwrap_or(false)
        {
            if let Some(t) = self.table.get_mut(&pid) {
                t.fast_exec_failed = true;
            }
        }
        if let Some(t) = self.table.get_mut(&pid) {
            t.state = State::Run;
            t.clear_exec_state();
        }
        if self.cfg.detach {
            // The swap is one-shot and this tracee has just settled, so
            // there is nothing left for the supervisor to do on its path
            // unless it execs again.  Detaching now is the only way to
            // get `TracerPid` back to 0, and it costs tree coverage: a
            // detached tracee and everything it forks later run without
            // redaction, which the session summary counts.
            //
            // Say it at the release, per tracee: this is the last moment
            // the operator can be told that this process, from now on,
            // runs its own later execs unredacted.  The session summary
            // counts the releases; this line names the process and the
            // consequence.  Watching for the later exec would need a
            // tracer, which is exactly what --detach gives up.
            self.warn(format_args!(
                "--detach released pid {} untraced; a later exec in that process is not \
                 redacted",
                pid
            ));
            self.stats.detached += 1;
            self.detach(pid, 0);
            return;
        }
        if at_exit_stop {
            self.resume(pid, 0, false);
        } else {
            self.resume(pid, 0, true);
        }
    }

    pub(super) fn set_state(&mut self, pid: libc::pid_t, s: State) {
        if let Some(t) = self.table.get_mut(&pid) {
            t.state = s;
        }
    }

    /// Map the redaction block inside the tracee.  The block is always
    /// anonymous; with `--encrypt-memory` it is also marked
    /// `MADV_DONTDUMP`.  A `memfd_secret` block would leave a
    /// `/secretmem` VMA in the payload, which is a tool fingerprint.
    fn map_block(
        &mut self,
        pid: libc::pid_t,
        map_len: usize,
        site: u64,
        pending_stop: &mut Option<i32>,
    ) -> io::Result<(u64, bool)> {
        if self.cfg.encrypt_memory {
            // The block is anonymous on every path, including with
            // --encrypt-memory.  A memfd_secret mapping leaves a
            // `/secretmem` VMA in the payload's maps, which no ordinary
            // process has, so it is a tool fingerprint.  The pages are
            // marked MADV_DONTDUMP below, and the session key still uses
            // memfd_secret in the supervisor.
            self.stats.block_anonymous += 1;
        }
        let regs = Regs::get(pid)?;
        let addr = crate::inject::run_remote_syscall(
            pid,
            &regs,
            arch::SYS_MMAP,
            [
                0,
                map_len as u64,
                libc::PROT_READ as u64 | libc::PROT_WRITE as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                u64::MAX,
                0,
            ],
            site,
            pending_stop,
        )
        .map_err(|e| io::Error::other(format!("mmap injection failed: {:?}", e)))?;
        if addr <= 0 {
            return Err(io::Error::other(format!(
                "mmap injection returned {}",
                addr
            )));
        }
        if self.cfg.encrypt_memory {
            match Regs::get(pid) {
                Ok(regs) => match crate::inject::run_remote_syscall(
                    pid,
                    &regs,
                    arch::SYS_MADVISE,
                    [
                        addr as u64,
                        map_len as u64,
                        libc::MADV_DONTDUMP as u64,
                        0,
                        0,
                        0,
                    ],
                    site,
                    pending_stop,
                ) {
                    Ok(0) => {}
                    Ok(rv) => {
                        self.stats.dontdump_failed += 1;
                        self.warn(format_args!(
                            "pid {}: MADV_DONTDUMP on the redaction block returned {}",
                            pid, rv
                        ));
                    }
                    Err(e) => {
                        self.stats.dontdump_failed += 1;
                        self.warn(format_args!(
                            "pid {}: MADV_DONTDUMP on the redaction block failed: {:?}",
                            pid, e
                        ));
                    }
                },
                Err(e) => {
                    self.stats.dontdump_failed += 1;
                    self.warn(format_args!(
                        "pid {}: MADV_DONTDUMP skipped, registers unreadable: {}",
                        pid, e
                    ));
                }
            }
        }
        Ok((addr as u64, false))
    }

    /// Install the `execve`/`execveat` seccomp filter in the tracee.
    ///
    /// The filter lives in the block's scratch area, so it needs no
    /// supervisor fd and no extra mapping.  `PR_SET_NO_NEW_PRIVS` is
    /// required for an unprivileged filter; the child already set it, but
    /// the call is repeated here so a tracee that cleared it cannot make
    /// the install fail.
    fn install_exec_filter(
        &mut self,
        pid: libc::pid_t,
        site: u64,
        block: &RedactionBlock,
        pending_stop: &mut Option<i32>,
    ) -> io::Result<()> {
        let filter = crate::seccomp::exec_watch_filter();
        let bytes = unsafe {
            std::slice::from_raw_parts(
                filter.as_ptr() as *const u8,
                filter.len() * std::mem::size_of::<libc::sock_filter>(),
            )
        };
        let filter_addr = block.scratch;
        write_block(pid, filter_addr, bytes)?;
        let prog_addr = filter_addr + bytes.len() as u64;
        let mut prog = vec![0u8; std::mem::size_of::<libc::sock_fprog>()];
        prog[0..2].copy_from_slice(&(filter.len() as u16).to_ne_bytes());
        let ptr_off = std::mem::size_of::<libc::sock_fprog>() - std::mem::size_of::<usize>();
        prog[ptr_off..].copy_from_slice(&(filter_addr as usize).to_ne_bytes());
        write_block(pid, prog_addr, &prog)?;

        let regs = Regs::get(pid)?;
        let r = crate::inject::run_remote_syscall(
            pid,
            &regs,
            arch::SYS_PRCTL,
            [38, 1, 0, 0, 0, 0], // PR_SET_NO_NEW_PRIVS
            site,
            pending_stop,
        )
        .map_err(|e| io::Error::other(format!("PR_SET_NO_NEW_PRIVS injection failed: {:?}", e)))?;
        if r != 0 {
            return Err(io::Error::other(format!(
                "PR_SET_NO_NEW_PRIVS returned {}",
                r
            )));
        }
        let r = crate::inject::run_remote_syscall(
            pid,
            &regs,
            arch::SYS_PRCTL,
            [22, 2, prog_addr, 0, 0, 0], // PR_SET_SECCOMP, SECCOMP_MODE_FILTER
            site,
            pending_stop,
        )
        .map_err(|e| io::Error::other(format!("PR_SET_SECCOMP injection failed: {:?}", e)))?;
        if r != 0 {
            return Err(io::Error::other(format!("PR_SET_SECCOMP returned {}", r)));
        }
        vlog!(self, "pid {}: seccomp exec filter installed", pid);
        Ok(())
    }

    /// Build and write the redaction block: the real argv/envp strings
    /// and the comm label, in an anonymous mapping inside the tracee.
    /// Returns absolute tracee addresses.
    fn build_redaction_block(
        &mut self,
        pid: libc::pid_t,
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
        pending_stop: &mut Option<i32>,
    ) -> io::Result<RedactionBlock> {
        let comm = self.cfg.label_comm.clone();

        // pass 1: layout
        let mut need = 0usize;
        let mut aoff = Vec::with_capacity(argv.len());
        for s in argv {
            aoff.push(need);
            need += s.len() + 1;
        }
        let mut eoff = Vec::with_capacity(envp.len());
        for s in envp {
            eoff.push(need);
            need += s.len() + 1;
        }
        let comm_off = need;
        need += comm.len() + 1;
        // `--keep-env=NAME`: a compact copy of only the kept variables.
        // The kernel's environment window points at this span, so
        // `/proc/<pid>/environ` reads back as `KEEP=value\0` with no
        // leading NUL padding from the original extent.
        let kept_start = need;
        let mut kept_pos = Vec::new();
        if !self.cfg.keep_env.is_empty() {
            for (i, s) in envp.iter().enumerate() {
                if self.is_kept_env(Some(s)) {
                    kept_pos.push((i, need));
                    need += s.len() + 1;
                }
            }
        }
        let kept_end = need;
        if need > MAX_HIDDEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "argv/env too large to relocate",
            ));
        }
        let total = (need + 15) & !15usize;

        // pass 2: fill (buffer starts zeroed: NUL terminators in place)
        let mut buf = vec![0u8; total];
        for (i, s) in argv.iter().enumerate() {
            buf[aoff[i]..aoff[i] + s.len()].copy_from_slice(s);
        }
        for (i, s) in envp.iter().enumerate() {
            buf[eoff[i]..eoff[i] + s.len()].copy_from_slice(s);
        }
        buf[comm_off..comm_off + comm.len()].copy_from_slice(&comm);
        for (i, off) in &kept_pos {
            buf[*off..*off + envp[*i].len()].copy_from_slice(&envp[*i]);
        }

        // The strings cannot be parked in the tracee stack: the block
        // would sit below `SP - 4096`, and the tracee's own runtime
        // frames grow downward into exactly that region once it resumes,
        // overwriting the middle of the parked argv and truncating the
        // strings the child reads at startup.  An anonymous mapping is
        // created inside the tracee instead.  It costs one mapping in
        // /proc/<pid>/maps and is stable against stack growth.
        //
        // The front of the mapping holds the presentation area: the
        // label, then `argc` NULs, then scratch for the PR_SET_MM_MAP
        // struct and the auxiliary vector copy.  `get_mm_cmdline()` stops
        // at the first NUL and `audit_log_execve_info()` needs `argc`
        // NUL-terminated strings from `arg_start`, so one block serves
        // both readers.
        let label = self.cfg.label.clone();
        let pres = label_presentation_len(label.len(), argv.len());
        let strings = pres as usize + total;
        let map_len = (strings + SCRATCH_ROOM + 15) & !15usize;
        let site = crate::inject::find_syscall_site(pid, None, self.fault_no_vdso)
            .ok_or_else(|| io::Error::other("no syscall instruction for mmap"))?;
        let (base, _secretmem) = self.map_block(pid, map_len, site, pending_stop)?;
        let mut front = vec![0u8; pres as usize];
        let fl = label.len();
        front[..fl].copy_from_slice(&label);
        let execfn = 1 + fl + argv.len();
        front[execfn..execfn + fl].copy_from_slice(&label);
        write_block(pid, base, &front)?;
        write_block(pid, base + pres, &buf)?;
        // The tracee has its copy; the supervisor's staging buffer must
        // not keep the real strings.
        buf.zeroize();
        front.zeroize();
        vlog!(
            self,
            "pid {}: hidden block in an anonymous mapping at {:#x} (presentation {} bytes)",
            pid,
            base,
            pres
        );
        Ok(RedactionBlock {
            str_addrs: offsets_to_addrs(&aoff, &eoff, base + pres),
            comm_addr: base + pres + comm_off as u64,
            base,
            mapped: map_len as u64,
            pres,
            scratch: base + pres + total as u64,
            execfn: base + execfn as u64,
            env_window: if kept_pos.is_empty() {
                None
            } else {
                Some((
                    base + pres + kept_start as u64,
                    base + pres + kept_end as u64,
                ))
            },
        })
    }

    /// Is the ELF image at `path` 32-bit (`EI_CLASS == ELFCLASS32`)?
    fn elf_is_32(&self, pid: libc::pid_t, path: &[u8]) -> bool {
        let os = std::ffi::OsStr::from_bytes(path);
        let mut candidates: Vec<std::path::PathBuf> = Vec::with_capacity(2);
        if path.first() == Some(&b'/') {
            let mut p = std::path::PathBuf::from(format!("/proc/{}/root", pid));
            p.push(std::ffi::OsStr::from_bytes(&path[1..]));
            candidates.push(p);
        } else {
            let mut p = std::path::PathBuf::from(format!("/proc/{}/cwd", pid));
            p.push(os);
            candidates.push(p);
        }
        candidates.push(std::path::PathBuf::from(os));
        for c in candidates {
            use std::io::Read;
            let mut f = match std::fs::File::open(&c) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let mut hdr = [0u8; 20];
            if f.read_exact(&mut hdr).is_ok() && hdr[..4] == [0x7f, b'E', b'L', b'F'] {
                return hdr[4] == 1; // EI_CLASS: 1 = ELFCLASS32
            }
        }
        false
    }

    /// Return the cached image for a settled tracee's next exec, with the
    /// `/proc/<tracer>/fd/N` path the tracee will exec.
    ///
    /// The path is resolved against the tracee (`/proc/<pid>/root` or
    /// `/proc/<pid>/cwd`), and the cache key is the canonical target plus
    /// its mtime.  A path that already names a memfd is left alone, so a
    /// re-exec of an image does not copy it again.
    fn rexec_redirect_for(
        &self,
        pid: libc::pid_t,
        path: &[u8],
    ) -> io::Result<Option<(std::sync::Arc<crate::rexec::Image>, String)>> {
        // A re-exec of an image this session already placed, or of a
        // memfd, is left alone: copying it again would only rename it.
        if path
            .windows(b".pmask-rexec-".len())
            .any(|w| w == b".pmask-rexec-")
        {
            return Ok(None);
        }
        let open = tracee_open_path(pid, path)?;
        if let Ok(target) = std::fs::read_link(&open) {
            if crate::rexec::is_memfd_path(&target.to_string_lossy()) {
                return Ok(None);
            }
        }
        let key = std::fs::canonicalize(&open).unwrap_or(open);
        let label = String::from_utf8_lossy(&self.cfg.label).into_owned();
        let opts = crate::rexec::Options {
            hugetlb: self.cfg.rexec_hugetlb,
            memfd_name: self.cfg.rexec_memfd_name.clone(),
        };
        let mut cache = self
            .cfg
            .rexec_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let image = cache.get_temp(&key, &label, opts)?;
        let Some(path) = &image.path else {
            return Ok(None);
        };
        let text = path.to_string_lossy().into_owned();
        Ok(Some((image, text)))
    }

    /// Resolve the executable path of the exec in flight, or `None`.
    fn exec_path(&self, pid: libc::pid_t, flavor: ExecFlavor, regs: &Regs) -> Option<Vec<u8>> {
        match flavor {
            ExecFlavor::Execve => read_cstr(pid, regs.arg(1), 4096),
            ExecFlavor::Execveat { dirfd, flags } => {
                let path = read_cstr(pid, regs.arg(2), 4096).unwrap_or_default();
                let dirfd = dirfd as u32 as i32;
                if dirfd == AT_FDCWD || path.starts_with(b"/") {
                    return Some(path);
                }
                if path.is_empty() && flags & AT_EMPTY_PATH != 0 {
                    return Some(format!("/proc/{}/fd/{}", pid, dirfd).into_bytes());
                }
                let dir = format!("/proc/{}/fd/{}", pid, dirfd);
                let link = std::fs::read_link(&dir).ok()?;
                let mut full = link.as_os_str().to_os_string();
                full.push("/");
                full.push(std::ffi::OsStr::from_bytes(&path));
                Some(full.as_os_str().as_encoded_bytes().to_vec())
            }
        }
    }

    /// Is the file at `path` an ELF image?
    ///
    /// The path is relative to the *tracee*, not to the tracer: after a
    /// `chdir()` inside the supervised tree, `execve("./prog")` must be
    /// resolved against `/proc/<pid>/cwd` (and an absolute path against
    /// `/proc/<pid>/root` for a chrooted tracee).  Opening it relative to
    /// the tracer would misclassify the target and silently drop the
    /// zero-exposure path.
    ///
    /// Unreadable paths are treated as non-ELF (conservative: post-exec
    /// redaction).
    fn path_is_elf(&self, pid: libc::pid_t, path: &[u8]) -> bool {
        let os = std::ffi::OsStr::from_bytes(path);
        if path.first() == Some(&b'/') {
            let mut p = std::path::PathBuf::from(format!("/proc/{}/root", pid));
            p.push(std::ffi::OsStr::from_bytes(&path[1..]));
            if p.exists() {
                return is_elf_file(&p);
            }
            // The root link is hidden (non-dumpable tracee): the absolute
            // path as the supervisor sees it.
            return is_elf_file(std::path::Path::new(os));
        }
        let mut p = std::path::PathBuf::from(format!("/proc/{}/cwd", pid));
        p.push(os);
        // A hidden cwd link (non-dumpable tracee) cannot be resolved:
        // treat the target as unknown, which takes the safe post-exec path.
        is_elf_file(&p)
    }
}

/// Resolve an exec path the way the tracee sees it.
///
/// An absolute path is opened under `/proc/<pid>/root`; a relative one
/// under `/proc/<pid>/cwd`.  This is the same rule `path_is_elf` uses,
/// and it is what makes a `chdir()` inside the tree work.
fn tracee_open_path(pid: libc::pid_t, path: &[u8]) -> io::Result<std::path::PathBuf> {
    if path.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty exec path",
        ));
    }
    if path[0] == b'/' {
        let rel: Vec<u8> = path.iter().skip_while(|&&b| b == b'/').copied().collect();
        let mut p = std::path::PathBuf::from(format!("/proc/{}/root", pid));
        p.push(std::ffi::OsStr::from_bytes(&rel));
        Ok(p)
    } else {
        let mut p = std::path::PathBuf::from(format!("/proc/{}/cwd", pid));
        p.push(std::ffi::OsStr::from_bytes(path));
        Ok(p)
    }
}

/// Read the 4-byte magic of `path`; true only for an ELF image.
fn is_elf_file(path: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    match f.read_exact(&mut magic) {
        Ok(()) => magic == [0x7f, b'E', b'L', b'F'],
        Err(_) => false,
    }
}

/// Exact bounds of the argv and environment string regions of the new
/// image: `(arg_start, arg_end, env_start, env_end)` from
/// `/proc/<pid>/stat` fields 48 to 51.  `None` when the kernel hides
/// them (they read as zero for a non-dumpable tracee) or they do not lie
/// above `sp`.
fn proc_stat_bounds(pid: libc::pid_t, sp: u64) -> Option<(u64, u64, u64, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = after.split_whitespace().collect();
    // fields[0] is field 3 (state)
    let get = |n: usize| -> Option<u64> { fields.get(n - 3)?.parse().ok() };
    let (a0, a1, e0, e1) = (get(48)?, get(49)?, get(50)?, get(51)?);
    if a0 == 0 || a1 <= a0 || e1 < e0 || a0 < sp {
        return None;
    }
    Some((a0, a1, e0, e1))
}

/// Min/max span covering all strings behind a pointer array (by current
/// tracee content).  `(u64::MAX, 0)` when empty/unreadable.  Fallback for
/// `proc_stat_bounds`.
fn string_span(pid: libc::pid_t, ptrs: &[u64]) -> (u64, u64) {
    let (mut lo, mut hi) = (u64::MAX, 0u64);
    for &p in ptrs {
        let l = if p != 0 {
            read_cstr(pid, p, MAX_STRLEN).map(|s| s.len()).unwrap_or(0)
        } else {
            0
        };
        if p < lo {
            lo = p;
        }
        if p + l as u64 + 1 > hi {
            hi = p + l as u64 + 1;
        }
    }
    (lo, hi)
}

/// Write `buf` at `base` in page-sized pieces.  The first failing piece
/// reports its offset, so a refused write names where it stopped.
fn write_block(pid: libc::pid_t, base: u64, buf: &[u8]) -> io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let n = (buf.len() - done).min(4096);
        let wrote = write_mem(pid, base + done as u64, &buf[done..done + n]);
        if wrote != n as isize {
            return Err(io::Error::other(format!(
                "block write failed at offset {} of {} (wrote {}): {}",
                done,
                buf.len(),
                wrote,
                io::Error::last_os_error()
            )));
        }
        done += n;
    }
    Ok(())
}

/// Write the presentation of the argv window when the kernel keeps the
/// original extent (`--no-exact`, or a refused `PR_SET_MM_MAP`).
///
/// The label is followed by spaces, not NULs, and the last byte is the
/// only NUL.  `get_mm_cmdline()` serves `[arg_start, arg_end)` and stops
/// at the first NUL, so the reader sees one string with trailing spaces.
/// The old shape, `label` plus one NUL per argument, was a fingerprint.
fn fill_arg_window(pid: libc::pid_t, lo: u64, hi: u64, label: &[u8]) {
    let span = (hi - lo) as usize;
    if span == 0 {
        return;
    }
    let n = label.len().min(span.saturating_sub(1));
    if n > 0 {
        let _ = write_mem(pid, lo, &label[..n]);
    }
    let mut off = n;
    while off < span - 1 {
        let chunk = (span - 1 - off).min(4096);
        let spaces = vec![b' '; chunk];
        let _ = write_mem(pid, lo + off as u64, &spaces);
        off += chunk;
    }
    let _ = write_mem(pid, hi - 1, &[0u8]);
}

/// Write the presentation of the environment window when the kernel
/// keeps the original extent.  The kept variables (if any) come first,
/// then a fixed decoy environment; the last byte is NUL.  The payload's
/// `envp` points at the hidden block, so this is only what `/proc` and a
/// `/proc/self/environ` reader see.
fn fill_env_window(pid: libc::pid_t, lo: u64, hi: u64, kept: &[&[u8]]) {
    let span = (hi - lo) as usize;
    if span == 0 {
        return;
    }
    let mut buf = vec![0u8; span];
    let mut off = 0usize;
    for s in kept {
        if off + s.len() + 1 > span {
            break;
        }
        buf[off..off + s.len()].copy_from_slice(s);
        off += s.len() + 1;
    }
    const DECOY: &[u8] = b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0\
HOME=/tmp\0LANG=C.UTF-8\0";
    let mut di = 0usize;
    while off < span - 1 {
        let b = DECOY[di % DECOY.len()];
        buf[off] = b;
        off += 1;
        di += 1;
    }
    buf[span - 1] = 0;
    let _ = write_mem(pid, lo, &buf);
}

/// Bytes reserved for the `PR_SET_MM_MAP` struct, which is 104, and for
/// the auxiliary vector copy, which is at most `AT_VECTOR_SIZE` entries
/// of 16 bytes.
const SCRATCH_ROOM: usize = 2048;

/// Size of the presentation area at the front of a redaction block.
///
/// Layout: the label, its NUL, `argc` NULs, then a second copy of the
/// label.  `get_mm_cmdline()` stops at the first NUL and
/// `audit_log_execve_info()` walks `argc` NUL-terminated strings from
/// `arg_start`, so it finds the label and `argc - 1` empty strings and
/// never reads past the block.  The second copy sits at `env_end`, which
/// is where the kernel puts the executed file name on a normal exec, and
/// `AT_EXECFN` is repointed at it: `/proc/<pid>/auxv` then reports the
/// label and keeps the `AT_EXECFN == env_end` relation a normal exec has.
fn label_presentation_len(label_len: usize, argc: usize) -> u64 {
    (2 * label_len + 2 + argc) as u64
}

/// Absolute addresses of the argv and envp strings in a block at `base`.
fn offsets_to_addrs(aoff: &[usize], eoff: &[usize], base: u64) -> Vec<u64> {
    aoff.iter()
        .chain(eoff.iter())
        .map(|off| base + *off as u64)
        .collect()
}

/// Serialize a NUL-terminated u64 pointer array to bytes.  Both supported
/// targets (x86-64, aarch64) are little-endian, so the byte order of the
/// tracee equals little-endian.
fn ptr_words_bytes(v: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 8);
    for &w in v {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}
