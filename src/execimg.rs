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
    dup_strings, peek_word, poke_word, read_cstr, read_mem, read_ptr_array, write_mem, zero_range,
    MAX_ARGV, MAX_ENVV, MAX_HIDDEN, MAX_STRLEN,
};
use crate::tracer::{State, Tracer};
#[allow(deprecated)]
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::time::Instant;
use zeroize::{Zeroize, Zeroizing};

/// Reusable page-aligned, `mlock`ed, `MADV_DONTDUMP`, wipe-on-drop scratch
/// mapping for `--encrypt-memory` seal/open operations.
///
/// Keeps the per-session [`crate::crypto::SessionKey`] in `memfd_secret` while
/// avoiding a per-exec `memfd_secret` / `ftruncate` / `mmap` / `munmap` cycle
/// (and its cross-CPU direct-map TLB shootdowns) on every exec.
pub(crate) struct LockedScratch {
    ptr: *mut u8,
    cap: usize,
    locked: bool,
}

impl Default for LockedScratch {
    fn default() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            cap: 0,
            locked: false,
        }
    }
}

impl LockedScratch {
    fn ensure(&mut self, want: usize) -> io::Result<&mut [u8]> {
        if want == 0 {
            return Ok(&mut []);
        }
        if self.cap < want {
            let new_cap = (want.max(4096) + 4095) & !4095usize;
            // SAFETY: anonymous private mapping owned exclusively by `self`.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    new_cap,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `p` is a valid page-aligned mapping of `new_cap` bytes.
            let locked = unsafe {
                let _ = libc::madvise(p, new_cap, libc::MADV_DONTDUMP);
                libc::mlock(p, new_cap) == 0
            };
            self.release();
            self.ptr = p as *mut u8;
            self.cap = new_cap;
            self.locked = locked;
        }
        // SAFETY: `self.ptr` is non-null and holds at least `want` writable bytes.
        Ok(unsafe { std::slice::from_raw_parts_mut(self.ptr, want) })
    }

    fn release(&mut self) {
        if !self.ptr.is_null() && self.cap > 0 {
            // SAFETY: `self.ptr` points to our owned anonymous mapping of `self.cap` bytes.
            unsafe {
                std::slice::from_raw_parts_mut(self.ptr, self.cap).zeroize();
                if self.locked {
                    libc::munlock(self.ptr as *const libc::c_void, self.cap);
                }
                libc::munmap(self.ptr as *mut libc::c_void, self.cap);
            }
            self.ptr = std::ptr::null_mut();
            self.cap = 0;
            self.locked = false;
        }
    }
}

impl Drop for LockedScratch {
    fn drop(&mut self) {
        self.release();
    }
}

/// A sealed argv/envp vector decrypted in place inside [`LockedScratch`].
pub(crate) struct FastSealedStrings {
    nonce: [u8; 24],
    tag: [u8; 16],
    ct: Vec<u8>,
}

impl FastSealedStrings {
    const AAD: &'static [u8] = b"pmask strings v1";

    #[allow(deprecated)]
    pub(crate) fn seal(
        key: &crate::crypto::SessionKey,
        strings: &[Vec<u8>],
        scratch: &mut LockedScratch,
    ) -> io::Result<Self> {
        let mut total = 4usize;
        for s in strings {
            total = total
                .checked_add(4)
                .and_then(|n| n.checked_add(s.len()))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "sealed size overflow")
                })?;
        }
        let buf = scratch.ensure(total)?;
        let mut off = 0usize;
        buf[off..off + 4].copy_from_slice(&(strings.len() as u32).to_le_bytes());
        off += 4;
        for s in strings {
            buf[off..off + 4].copy_from_slice(&(s.len() as u32).to_le_bytes());
            off += 4;
            buf[off..off + s.len()].copy_from_slice(s);
            off += s.len();
        }
        let mut nonce = [0u8; 24];
        if let Err(e) = fill_random(&mut nonce) {
            buf.zeroize();
            return Err(e);
        }
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let tag = match cipher.encrypt_in_place_detached(XNonce::from_slice(&nonce), Self::AAD, buf)
        {
            Ok(t) => t,
            Err(_) => {
                buf.zeroize();
                return Err(io::Error::other("XChaCha20-Poly1305 seal failed"));
            }
        };
        let ct = buf.to_vec();
        buf.zeroize();
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(tag.as_slice());
        Ok(Self {
            nonce,
            tag: tag_bytes,
            ct,
        })
    }

    #[allow(deprecated)]
    pub(crate) fn open(
        &self,
        key: &crate::crypto::SessionKey,
        scratch: &mut LockedScratch,
    ) -> io::Result<Vec<Vec<u8>>> {
        let buf = scratch.ensure(self.ct.len())?;
        buf.copy_from_slice(&self.ct);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        if cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&self.nonce),
                Self::AAD,
                buf,
                Tag::from_slice(&self.tag),
            )
            .is_err()
        {
            buf.zeroize();
            return Err(io::Error::other("XChaCha20-Poly1305 open failed"));
        }
        let parsed = parse_string_vec(buf);
        buf.zeroize();
        parsed
    }
}

fn parse_string_vec(bytes: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut out: Zeroizing<Vec<Vec<u8>>> = Zeroizing::new(Vec::new());
    let mut off = 0usize;
    let count = read_le_u32(bytes, &mut off)? as usize;
    if count > 1_000_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sealed string count is implausible",
        ));
    }
    out.reserve(count);
    for _ in 0..count {
        let len = read_le_u32(bytes, &mut off)? as usize;
        if off + len > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sealed string length runs past the buffer",
            ));
        }
        out.push(bytes[off..off + len].to_vec());
        off += len;
    }
    if off != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing bytes after the sealed string vector",
        ));
    }
    Ok(std::mem::take(&mut *out))
}

fn read_le_u32(buf: &[u8], off: &mut usize) -> io::Result<u32> {
    if *off + 4 > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sealed string header is truncated",
        ));
    }
    let v = u32::from_le_bytes([buf[*off], buf[*off + 1], buf[*off + 2], buf[*off + 3]]);
    *off += 4;
    Ok(v)
}

fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    let mut off = 0usize;
    while off < buf.len() {
        // SAFETY: writing into our own buffer via getrandom(2).
        let n = unsafe {
            libc::getrandom(
                buf[off..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - off,
                0,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        off += n as usize;
    }
    Ok(())
}

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
    /// Syscall instruction site in the tracee found during block setup, reused
    /// for subsequent remote injections in the same exec stop.
    site: u64,
    /// The anonymous mapping the block lives in, and the size the kernel
    /// actually mapped.
    base: u64,
    mapped: u64,
    /// First byte after the real strings: scratch for the
    /// `PR_SET_MM_MAP` struct and the auxiliary vector copy, so writing
    /// them can never land on the strings the payload reads.
    scratch: u64,
    /// The bytes served as the presentation: label, NUL, environment,
    /// label copy.  They are written into the original argv/environment
    /// region of the stack when it is large enough, so `start_stack`, the
    /// `[stack]` VMA and its `gd` flag stay ordinary.
    pres_bytes: Vec<u8>,
}

/// ELF classification from a single 5-byte header read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ElfKind {
    NotElf,
    Elf64,
    Elf32,
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
    /// `--audit`: the per-exec audit row was already emitted right before
    /// `PR_SET_DUMPABLE=0` (while `/proc/<pid>/exe` and `fd` were still
    /// readable to the non-root supervisor).
    audited: bool,
}

impl Tracer {
    /// execve/execveat entry stop: save the real strings, swap the inline
    /// arrays for ELF targets, defer to post-exec hiding otherwise.
    pub(crate) fn on_exec_entry(&mut self, pid: libc::pid_t, nr: u64, regs: &Regs) {
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
        // Release any stale pending-plaintext marker before starting this exec.
        self.set_pending(pid, false);

        // A vfork child shares its parent's address space until the exec.
        // Writing the entry swap there would change the parent's memory;
        // gcc's clone3(CLONE_VM|CLONE_VFORK) run of cc1 is the measured
        // case, and it corrupted the parent's heap.  The child takes the
        // post-exec path instead: the exec runs unswapped and the
        // completion redacts the new image.
        if self.table.get(&pid).map(|t| t.vfork_child).unwrap_or(false) {
            if self.cfg.strict_exec {
                self.refuse(format_args!(
                    "pid {}: --strict-exec refuses a vfork child, which can only be redacted \
                     after its exec; the child is killed and the run stops",
                    pid
                ));
                // SAFETY: plain kill(2) of a stopped tracee.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                self.set_state(pid, State::Script);
                self.resume(pid, 0, false);
                return;
            }
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

        let image = self.exec_path(pid, flavor, regs);
        let elf_kind = image
            .as_ref()
            .map(|p| self.classify_image_elf(pid, p))
            .unwrap_or(ElfKind::NotElf);
        // A 64-bit supervisor cannot read or write the registers of a
        // 32-bit image, so it cannot redact it.  Refuse loudly instead
        // of swapping argv and then failing: the program keeps its real
        // arguments and the session summary names the exec.
        if elf_kind == ElfKind::Elf32 {
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
            self.refuse(format_args!(
                "pid {}: 32-bit (foreign ABI) program refused; a 32-bit image cannot \
                 be redacted, so it is not run unless --allow-foreign is set; the payload \
                 is killed and the run stops",
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

        if elf_kind == ElfKind::NotElf {
            if self.cfg.strict_exec {
                self.refuse(format_args!(
                    "pid {}: --strict-exec refuses a non-ELF image, which can only be redacted \
                     after its exec; the payload is killed and the run stops",
                    pid
                ));
                // SAFETY: plain kill(2) of a stopped tracee.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                self.set_state(pid, State::Script);
                self.resume(pid, 0, false);
                return;
            }
            // script / unknown: the kernel needs the real argv to build
            // the interpreter line; redact after completion instead.
            vlog!(self, "pid {}: script/unknown exec, post-exec mode", pid);
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        // `--exec-once`: point a settled tracee's exec at a cached image
        // the tracer holds.  The image path is written at the top of the
        // scratch window below the stack so the label and environment filler
        // written from `base` upward can never overwrite it.
        let mut rexec_redirect: Option<(std::sync::Arc<crate::rexec::Image>, Vec<u8>)> = None;
        if self.cfg.rexec_per_exec && redirect_ok {
            if let Some(path) = &image {
                match self.rexec_redirect_for(pid, path) {
                    Ok(Some((img, text))) => {
                        if let Some(note) = &img.note {
                            if !self.rexec_seal_warned {
                                self.rexec_seal_warned = true;
                                self.warn(format_args!("--exec-once: {}", note));
                            }
                        }
                        let mut bytes = text.into_bytes();
                        bytes.push(0);
                        rexec_redirect = Some((img, bytes));
                    }
                    Ok(None) => {}
                    Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                        // The carrier the session promised was replaced or
                        // edited.  Running the on-disk program instead
                        // would be a silent posture change and could run
                        // the attacker's bytes under the label; refuse
                        // the exec.
                        self.refuse(format_args!(
                            "pid {}: --exec-once carrier refused: {}; the exec is killed",
                            pid, e
                        ));
                        // SAFETY: plain kill(2) of a stopped tracee.
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                        self.set_state(pid, State::Script);
                        self.resume(pid, 0, false);
                        return;
                    }
                    Err(e) => self.warn(format_args!(
                        "pid {}: --exec-once image unavailable: {}",
                        pid, e
                    )),
                }
            }
        }

        let sp = regs.sp();
        let redirect_len = rexec_redirect.as_ref().map(|(_, b)| b.len());
        let scratch_plan = plan_entry_scratch(sp, redirect_len);
        match (rexec_redirect, scratch_plan) {
            (Some((image, bytes)), Some((_, Some(redirect_addr), _))) => {
                if write_mem(pid, redirect_addr, &bytes) != bytes.len() as isize {
                    self.warn(format_args!(
                        "pid {}: --exec-once redirect path could not be written",
                        pid
                    ));
                } else {
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
            }
            (Some((_, bytes)), _) => {
                vlog!(
                    self,
                    "pid {}: --exec-once redirect path ({} bytes) does not fit below sp {:#x}; not applied",
                    pid,
                    bytes.len(),
                    sp
                );
            }
            (None, _) => {}
        }

        // `--no-exact` keeps the kernel's windows where they are, so the
        // kernel must copy the real argv and environment and the
        // completion stop overwrites that original extent in place.
        // Swapping the inline arrays here would make the kernel build a
        // shortened window (`label` plus one NUL per slot), which is a
        // label-independent fingerprint and not the documented shape.
        // Stopping before `dup_strings`/sealing also avoids copying strings
        // that the post-exec reread path will never consume.
        if !self.cfg.exact {
            if self.cfg.strict_exec {
                self.refuse(format_args!(
                    "pid {}: --strict-exec refuses --no-exact, which can only redact after \
                     exec; the payload is killed and the run stops",
                    pid
                ));
                // SAFETY: plain kill(2) of a stopped tracee.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                self.set_state(pid, State::Script);
                self.resume(pid, 0, false);
                return;
            }
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            vlog!(
                self,
                "pid {}: --no-exact entry keeps the real extent; presentation at completion",
                pid
            );
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

        if overflow || avarr.is_none() {
            if self.cfg.strict_exec {
                self.refuse(format_args!(
                    "pid {}: --strict-exec refuses entry-redaction fallback \
                     (argv/envp unreadable or exceeds cap); the payload is killed and the run stops",
                    pid
                ));
                // SAFETY: plain kill(2) of a stopped tracee.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                self.set_state(pid, State::Script);
                self.resume(pid, 0, false);
                return;
            }
            vlog!(self, "pid {}: argv unreadable/huge, post-exec mode", pid);
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        let Some((base, _, filler_limit)) = scratch_plan else {
            if self.cfg.strict_exec {
                self.refuse(format_args!(
                    "pid {}: --strict-exec refuses entry-redaction fallback \
                     (no scratch space below stack pointer); the payload is killed and the run stops",
                    pid
                ));
                // SAFETY: plain kill(2) of a stopped tracee.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                self.set_state(pid, State::Script);
                self.resume(pid, 0, false);
                return;
            }
            vlog!(
                self,
                "pid {}: no entry scratch below sp, post-exec mode",
                pid
            );
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        };

        // Keep the supervisor non-dumpable while copying the real strings.
        self.set_pending(pid, true);
        let mut av_strings = avarr
            .as_ref()
            .and_then(|arr| dup_strings(pid, arr, &mut overflow))
            .map(ScrubStrings);
        let mut ev_strings = evarr
            .as_ref()
            .and_then(|arr| dup_strings(pid, arr, &mut overflow))
            .map(ScrubStrings);
        if overflow {
            drop(av_strings);
            drop(ev_strings);
            self.set_pending(pid, false);
            if self.cfg.strict_exec {
                self.refuse(format_args!(
                    "pid {}: --strict-exec refuses entry-redaction fallback \
                     (argv/envp strings exceed cap); the payload is killed and the run stops",
                    pid
                ));
                // SAFETY: plain kill(2) of a stopped tracee.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                self.set_state(pid, State::Script);
                self.resume(pid, 0, false);
                return;
            }
            vlog!(self, "pid {}: argv strings huge, post-exec mode", pid);
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        let avn = avarr.as_ref().map(|v| v.len()).unwrap_or(0);
        let evn = evarr.as_ref().map(|v| v.len()).unwrap_or(0);

        // scratch below the old SP: [label][NUL][empty NUL][optional env filler]
        let label = self.cfg.label.clone();
        // `fl` is capped at 255 so `empty_str` (base+fl) always lands on a
        // byte inside the zeroed scratch; a longer label would otherwise
        // point at uninitialised stack memory.
        let fl = (label.len() + 1).clamp(1, 255);
        let fake_str = base;
        let empty_str = base + fl as u64;

        // Build the entry scratch (and optional sized environment filler) in
        // one buffer so we issue a single `write_mem` instead of writing a
        // 256-byte scratch block and immediately overwriting it.
        let mut env_ptrs = vec![empty_str; evn + 1];
        let mut wrote_scratch = false;
        if self.cfg.redact_environ && evn > 0 {
            let pres_env = self.presentation_env_len(pid, evarr.as_deref().unwrap_or(&[]));
            let region_min = (label.len() + 1) + pres_env + (label.len() + 1);
            let arg_block = fl + avn;
            let env_block_min = region_min.saturating_sub(arg_block);
            let synth_total = env_block_min.saturating_sub(evn);
            let total = fl + 1 + synth_total + evn;
            if total <= filler_limit {
                let mut buf = vec![0u8; total];
                if fl > 1 {
                    buf[..fl - 1].copy_from_slice(&label[..fl - 1]);
                }
                let mut off = fl + 1;
                let mut used = 0usize;
                for (i, ptr) in env_ptrs.iter_mut().enumerate().take(evn) {
                    *ptr = base + off as u64;
                    let len = if i + 1 == evn {
                        synth_total.saturating_sub(used)
                    } else {
                        synth_total / evn
                    };
                    for b in buf.iter_mut().skip(off).take(len) {
                        *b = b'A';
                    }
                    off += len;
                    used += len;
                    off += 1; // NUL
                }
                if write_mem(pid, base, &buf) == buf.len() as isize {
                    wrote_scratch = true;
                } else {
                    env_ptrs = vec![empty_str; evn + 1];
                }
            }
        }
        if !wrote_scratch {
            let mut scratch = [0u8; 256];
            scratch[..fl - 1].copy_from_slice(&label[..fl - 1]);
            if write_mem(pid, base, &scratch) != scratch.len() as isize {
                drop(av_strings);
                drop(ev_strings);
                self.set_pending(pid, false);
                if self.cfg.strict_exec {
                    self.refuse(format_args!(
                        "pid {}: --strict-exec refuses entry-redaction fallback \
                         (scratch write failed); the payload is killed and the run stops",
                        pid
                    ));
                    // SAFETY: plain kill(2) of a stopped tracee.
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    self.set_state(pid, State::Script);
                    self.resume(pid, 0, false);
                    return;
                }
                vlog!(self, "pid {}: scratch write failed, post-exec mode", pid);
                self.set_state(pid, State::Script);
                self.resume_exec_entry(pid);
                return;
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
            if let Some(save) = &avarr {
                let _ = write_mem(pid, av, &ptr_words_bytes(save));
            }
            drop(av_strings);
            drop(ev_strings);
            self.set_pending(pid, false);
            if self.cfg.strict_exec {
                self.refuse(format_args!(
                    "pid {}: --strict-exec refuses entry-redaction fallback \
                     (argv array write failed); the payload is killed and the run stops",
                    pid
                ));
                // SAFETY: plain kill(2) of a stopped tracee.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                self.set_state(pid, State::Script);
                self.resume(pid, 0, false);
                return;
            }
            self.set_state(pid, State::Script);
            self.resume_exec_entry(pid);
            return;
        }

        let mut env_swapped = false;
        if self.cfg.redact_environ && evarr.is_some() {
            let mut ne = env_ptrs;
            ne[evn] = 0;
            let ne_bytes = ptr_words_bytes(&ne);
            if write_mem(pid, ev, &ne_bytes) == ne_bytes.len() as isize {
                env_swapped = true;
            } else if let Some(save) = &evarr {
                let _ = write_mem(pid, ev, &ptr_words_bytes(save));
            }
        }

        // The entry swap succeeded: commit the saved (or sealed) strings to
        // the tracee entry and update `stats.sealed` only on this path.
        let mut seal_errors: Vec<String> = Vec::new();
        {
            let key = self.cfg.session_key.clone();
            let scratch = &mut self.crypto_scratch;
            let Some(t) = self.table.get_mut(&pid) else {
                drop(av_strings);
                drop(ev_strings);
                self.set_pending(pid, false);
                return;
            };
            t.av_save = avarr;
            t.ev_save = evarr;
            t.env_swapped = env_swapped;
            if let Some(mut v) = av_strings.take() {
                if let Some(key) = &key {
                    match FastSealedStrings::seal(key, &v.0, scratch) {
                        Ok(sealed) => {
                            t.sealed_argv = Some(sealed);
                            drop(v);
                        }
                        Err(e) => {
                            seal_errors.push(format!("pid {}: argv seal failed: {}", pid, e));
                            t.argv = Some(std::mem::take(&mut v.0));
                        }
                    }
                } else {
                    t.argv = Some(std::mem::take(&mut v.0));
                }
            }
            if let Some(mut v) = ev_strings.take() {
                if let Some(key) = &key {
                    match FastSealedStrings::seal(key, &v.0, scratch) {
                        Ok(sealed) => {
                            t.sealed_envp = Some(sealed);
                            drop(v);
                        }
                        Err(e) => {
                            seal_errors.push(format!("pid {}: env seal failed: {}", pid, e));
                            t.envp = Some(std::mem::take(&mut v.0));
                        }
                    }
                } else {
                    t.envp = Some(std::mem::take(&mut v.0));
                }
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
        let sealed_now = self
            .table
            .get(&pid)
            .map(|t| t.sealed_argv.is_some() as u32 + t.sealed_envp.is_some() as u32)
            .unwrap_or(0);
        self.stats.sealed += sealed_now;
        let has_plain = self
            .table
            .get(&pid)
            .map(|t| t.argv.is_some() || t.envp.is_some())
            .unwrap_or(false);
        self.set_pending(pid, has_plain);

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
        &mut self,
        pid: libc::pid_t,
        sealed: Option<FastSealedStrings>,
        plain: Option<Vec<Vec<u8>>>,
    ) -> Option<Vec<Vec<u8>>> {
        match (sealed, self.cfg.session_key.clone()) {
            (Some(s), Some(key)) => match s.open(&key, &mut self.crypto_scratch) {
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
    pub(crate) fn restore_orig_arrays(&mut self, pid: libc::pid_t) {
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
            self.refuse(format_args!(
                "pid {}: a later exec of a tracee that already ran a 32-bit image is refused; the 64-bit tracer cannot redact it; the exec is killed",
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
            self.refuse(format_args!(
                "pid {}: 32-bit (foreign ABI) program refused at completion; a 32-bit \
                 image cannot be redacted, so it is not run unless --allow-foreign is set; \
                 the payload is killed and the run stops",
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
        if self.cfg.audit && !flags.audited {
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

        let (state, env_swapped) = match self.table.get_mut(&pid) {
            Some(t) => {
                // The address space was just replaced by exec; drop the old
                // image's cached syscall site before finding the new one.
                t.syscall_site = None;
                (t.state, t.env_swapped)
            }
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

        // 1. Read `/proc/<pid>/stat` ONCE for both the visible string bounds
        //    and the `MmFields` needed by `PR_SET_MM_MAP` (eliminates a second
        //    `/proc/<pid>/stat` open/read/parse and lets `relocate_windows`
        //    use `start_brk` directly without injecting `SYS_BRK(0)`).
        let (stat_bounds, cached_mm) = read_proc_stat(pid, sp);
        let (arg_lo, arg_hi, env_lo, env_hi) = match stat_bounds {
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
        //    injected anonymous mapping.  The syscall site found here is
        //    reused for all subsequent injections in this exec stop.
        let auxv_at = kenvp + (kev.len() as u64 + 1) * 8;
        let block = match self.build_redaction_block(
            pid,
            &orig_regs,
            auxv_at,
            &argv,
            &envp[..envc],
            pending_stop,
        ) {
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
        // The block now holds the real strings in the tracee.  Zero the
        // supervisor's copies when this function returns, on every path.
        let _argv = ScrubStrings(argv);
        let envp = ScrubStrings(envp);

        // Cache the syscall site and comm label address while the tracee is
        // still dumpable (before PR_SET_DUMPABLE=0 below).
        let site = block.site;
        if let Some(t) = self.table.get_mut(&pid) {
            t.rename_addr = block.comm_addr;
            t.syscall_site = Some(site);
        }

        // 4. repoint the inline arrays at the hidden strings.
        //    In production (`fault_poke_at == 0`), batch the contiguous
        //    `[argv[0..argc], 0, envp[0..envc]]` pointer block into one
        //    `write_mem` syscall instead of `argc + envc` separate syscalls.
        let mut repoint_ok = true;
        if self.fault_poke_at == 0 {
            let total_words = if envc > 0 { argc + 1 + envc } else { argc };
            if total_words > 0 {
                let mut ptrs = Vec::with_capacity(total_words * 8);
                for &addr in &block.str_addrs[..argc] {
                    ptrs.extend_from_slice(&addr.to_ne_bytes());
                }
                if envc > 0 {
                    ptrs.extend_from_slice(&0u64.to_ne_bytes());
                    for &addr in &block.str_addrs[argc..argc + envc] {
                        ptrs.extend_from_slice(&addr.to_ne_bytes());
                    }
                }
                self.poke_count += (argc + envc) as u32;
                if write_mem(pid, kargv, &ptrs) != ptrs.len() as isize {
                    repoint_ok = false;
                }
            }
        } else {
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

        // 5. present the visible spans.  On the swapped ELF exact path, the
        //    kernel-copied spans already contain only the swapped label and
        //    `'A'` filler (zero secrets) and `relocate_windows` immediately
        //    overwrites/repoints them; only pre-fill here when we took the
        //    reread/unswapped path or exact relocation will not run.
        let label = self.cfg.label.clone();
        let kept: Vec<&[u8]> = if self.cfg.redact_environ && !self.cfg.keep_env.is_empty() {
            envp.iter()
                .filter(|s| self.is_kept_env(Some(s)))
                .map(|s| s.as_slice())
                .collect()
        } else {
            Vec::new()
        };
        let will_relocate = self.cfg.exact && !self.fault_refuse_map;
        if (!will_relocate || reread) && arg_lo < arg_hi {
            fill_arg_window(pid, arg_lo, arg_hi, &label);
        }
        if self.cfg.redact_environ && (!will_relocate || reread || !env_swapped) && env_lo < env_hi
        {
            fill_env_window(pid, env_lo, env_hi, &kept);
        }

        // 6. inject `PR_SET_MM_MAP`, `PR_SET_NAME`, optional seccomp filter,
        //    and `PR_SET_DUMPABLE=0` via the cached syscall site and `orig_regs`.
        // 6a. give the kernel the compact presentation block as the argv
        //     and environment window.
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
                match self.relocate_windows(
                    pid,
                    &orig_regs,
                    &block,
                    auxv_at,
                    cached_mm,
                    pending_stop,
                ) {
                    WindowOutcome::Moved => flags.sized = true,
                    WindowOutcome::Refused(errno) => {
                        flags.sized_skipped = true;
                        // `relocate_windows` may have written the compact
                        // presentation (`label\0env\0label\0`) into
                        // `[arg_lo..env_hi]` before `PR_SET_MM_MAP` was
                        // refused.  Restore the full-extent presentation so
                        // `cmdline` stays space-padded with one final NUL
                        // and `environ` stays a complete decoy/kept window.
                        if arg_lo < arg_hi {
                            fill_arg_window(pid, arg_lo, arg_hi, &label);
                        }
                        if self.cfg.redact_environ && env_lo < env_hi {
                            fill_env_window(pid, env_lo, env_hi, &kept);
                        }
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
            &orig_regs,
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
        if !tracee_gone && self.cfg.fast_exec {
            let installed = self
                .table
                .get(&pid)
                .map(|t| t.exec_filter_installed)
                .unwrap_or(false);
            if !installed {
                match self.install_exec_filter(pid, &orig_regs, site, &block, pending_stop) {
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
        if !tracee_gone && self.cfg.audit && self.cfg.no_dumpable {
            // Emit the per-exec `--audit` row right before `PR_SET_DUMPABLE=0`
            // so a non-root supervisor can still inspect `/proc/<pid>/exe` and
            // `/proc/<pid>/fd` for its own audit report.
            self.audit_row(pid);
            flags.audited = true;
        }
        if !tracee_gone && self.cfg.no_dumpable {
            // Ensure `RLIMIT_CORE = 0` alongside `PR_SET_DUMPABLE = 0` so core
            // dumps stay disabled and `/proc/<pid>/limits` reports zero.
            let zero_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `prlimit` updates the stopped tracee's RLIMIT_CORE before
            // `PR_SET_DUMPABLE = 0` is applied.
            unsafe {
                libc::prlimit(pid, libc::RLIMIT_CORE, &zero_core, std::ptr::null_mut());
            }
            flags.dumpable_done = true;
            let r2 = crate::inject::run_remote_syscall(
                pid,
                &orig_regs,
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
        block: &RedactionBlock,
        auxv_at: u64,
        cached_mm: Option<crate::presetmm::MmFields>,
        pending_stop: &mut Option<i32>,
    ) -> WindowOutcome {
        if crate::presetmm::map_size_fast() != Some(crate::presetmm::MM_MAP_LEN as u32) {
            return WindowOutcome::Refused(libc::EINVAL);
        }
        // At `PTRACE_EVENT_EXEC`, userspace has not executed yet so
        // `mm->brk == mm->start_brk` (field 47 of `/proc/<pid>/stat`).
        // Pass `start_brk` directly to `PR_SET_MM_MAP` and only inject
        // `SYS_BRK(0)` as a fallback if the kernel returns `EINVAL`.
        let Some(mut fields) = cached_mm.or_else(|| {
            let mut f = crate::presetmm::read_fields(pid, 1)?;
            f.brk = f.start_brk;
            Some(f)
        }) else {
            return WindowOutcome::Refused(0);
        };

        // The presentation is `label`, one NUL, the exposed environment,
        // and the label copy `AT_EXECFN` points at.  It is written into
        // the kernel-copied argv+environment region of the stack when that
        // region is large enough, so `arg_start` stays inside the VMA the
        // kernel labels `[stack]`, `start_stack` is untouched, and
        // `arg_end == env_start` holds as it does for an ordinary exec.
        //
        // Three shapes need care.  `--keep-env` keeps the kernel's
        // environment window, so the compact argv window is anchored just
        // below `env_start` instead of moving both windows onto the block.
        // A region too small for the full presentation is shortened to the
        // decoy entries that fit (a kept variable must appear whole, so
        // that case falls back).  Only when nothing plausible fits does
        // the presentation move to the block, which is the extent shape
        // `--no-exact` also has.
        let label = self.cfg.label.clone();
        let fl = label.len() as u64;
        let Some(p) = plan_presentation(
            &label,
            self.cfg.redact_environ,
            self.cfg.keep_env.is_empty(),
            &fields,
            block.base,
            &block.pres_bytes,
        ) else {
            return WindowOutcome::Refused(0);
        };
        if write_mem(pid, p.base, &p.bytes) != p.bytes.len() as isize {
            return WindowOutcome::Refused(0);
        }
        let arg_end = p.base + fl + 1;
        let env_end = arg_end + p.env_len;
        if !p.env_visible {
            // The real strings above the presentation are unreachable
            // through /proc, but they are still readable through
            // `/proc/<pid>/mem`; removing them costs one write.  A block
            // presentation leaves nothing to zero here: the visible spans
            // were already overwritten by the label and decoy writes.
            if p.label_copy && p.base == fields.arg_start {
                let pres_end = env_end + fl + 1;
                if pres_end < fields.env_end {
                    zero_range(pid, pres_end, fields.env_end);
                }
            }
            fields.env_start = arg_end;
            fields.env_end = env_end;
        }
        fields.arg_start = p.base;
        fields.arg_end = arg_end;
        // `start_stack` keeps the value the kernel set at exec.  Pointing
        // it at the block made `/proc/<pid>/stat` report
        // `start_stack == arg_start` and moved the `[stack]` label onto a
        // 16 kB anonymous mapping; the real stack is still mapped, so
        // leaving the field alone restores both invariants.

        // `PR_SET_MM_MAP` rewrites `mm->saved_auxv`, which is what
        // `/proc/<pid>/auxv` serves.  The payload's own `getauxval` reads
        // the copy on its initial stack, which the kernel built from the
        // real exec.  Rewrite that stack copy only after `PR_SET_MM_MAP`
        // accepts the new windows, so a refusal does not leave `AT_EXECFN`
        // pointing into the restored decoy environment.
        let execfn = if p.label_copy { env_end } else { p.base };
        let auxv = crate::presetmm::read_auxv(pid).map(|a| (a, execfn));

        let site = block.site;
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
            crate::presetmm::Relocated::Yes => {
                patch_stack_execfn(pid, auxv_at, execfn);
                WindowOutcome::Moved
            }
            crate::presetmm::Relocated::Refused(libc::EINVAL) => {
                // Fallback when `mm->brk != mm->start_brk`: query the live
                // `brk(0)` via remote syscall and retry `PR_SET_MM_MAP` once.
                let real_brk = match crate::inject::run_remote_syscall(
                    pid,
                    regs,
                    arch::SYS_BRK,
                    [0, 0, 0, 0, 0, 0],
                    site,
                    pending_stop,
                ) {
                    Ok(b) if b > 0 => b as u64,
                    Ok(_) => return WindowOutcome::Refused(libc::EINVAL),
                    Err(_) => return WindowOutcome::Gone,
                };
                if real_brk != fields.brk {
                    fields.brk = real_brk;
                    match crate::presetmm::relocate(
                        pid,
                        regs,
                        scratch,
                        &fields,
                        auxv.as_ref().map(|(a, f)| (a.as_slice(), *f)),
                        pending_stop,
                    ) {
                        crate::presetmm::Relocated::Yes => {
                            patch_stack_execfn(pid, auxv_at, execfn);
                            return WindowOutcome::Moved;
                        }
                        crate::presetmm::Relocated::Refused(e2) => {
                            return WindowOutcome::Refused(e2);
                        }
                        crate::presetmm::Relocated::NoFields => return WindowOutcome::Refused(0),
                    }
                }
                WindowOutcome::Refused(libc::EINVAL)
            }
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
            self.resume_state(pid, 0);
        } else {
            self.resume(pid, 0, true);
        }
    }

    pub(crate) fn set_state(&mut self, pid: libc::pid_t, s: State) {
        if let Some(t) = self.table.get_mut(&pid) {
            t.state = s;
        }
    }

    /// Single-process exec completion (`--profile single`): runs the full
    /// post-exec redaction sequence (`build_redaction_block`, batched inline
    /// repoint, `PR_SET_MM_MAP`, `PR_SET_NAME`, `RLIMIT_CORE=0`,
    /// `PR_SET_DUMPABLE=0`) without resuming or emitting `--detach` warnings.
    ///
    /// Returns `(killed_foreign, pending_stop)` so the single-process helper
    /// can unlink any staged private path, `PTRACE_DETACH`, re-raise any
    /// `pending_stop`, and exit cleanly.
    pub(crate) fn on_exec_complete_single(&mut self, pid: libc::pid_t) -> (bool, Option<i32>) {
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
        if self.cfg.no_dumpable && !flags.dumpable_done {
            flags.dumpable_failed = true;
        }
        if flags.foreign && !self.cfg.allow_foreign {
            self.stats.foreign_refused += 1;
            self.refuse(format_args!(
                "pid {}: 32-bit (foreign ABI) program refused at completion; a 32-bit \
                 image cannot be redacted, so it is not run unless --allow-foreign is set; \
                 the payload is killed and the run stops",
                pid
            ));
            // SAFETY: plain kill(2) of a stopped tracee.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            self.set_pending(pid, false);
            return (true, None);
        }
        self.account(&flags);
        self.set_pending(pid, false);
        if let Some(t) = self.table.get_mut(&pid) {
            t.state = State::Run;
            t.clear_exec_state();
        }
        (false, pending_stop)
    }

    /// Map the redaction block inside the tracee.  The block is always
    /// anonymous; with `--encrypt-memory` or `--no-dumpable` it is also marked
    /// `MADV_DONTDUMP`.  A `memfd_secret` block would leave a
    /// `/secretmem` VMA in the payload, which is a tool fingerprint.
    fn map_block(
        &mut self,
        pid: libc::pid_t,
        orig_regs: &Regs,
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
        let addr = crate::inject::run_remote_syscall(
            pid,
            orig_regs,
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
        if self.cfg.encrypt_memory || self.cfg.no_dumpable {
            match crate::inject::run_remote_syscall(
                pid,
                orig_regs,
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
        orig_regs: &Regs,
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

        let r = crate::inject::run_remote_syscall(
            pid,
            orig_regs,
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
            orig_regs,
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
    /// Returns absolute tracee addresses and the cached syscall site.
    fn build_redaction_block(
        &mut self,
        pid: libc::pid_t,
        orig_regs: &Regs,
        auxv_at: u64,
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

        let label = self.cfg.label.clone();
        let env_pres = self.presentation_env(envp);
        let (pres_bytes, pres) = build_presentation_layout(&label, &env_pres);
        let strings = pres as usize + total;
        let map_len = (strings + SCRATCH_ROOM + 15) & !15usize;
        let site = crate::inject::find_syscall_site(pid, Some(auxv_at), self.fault_no_vdso)
            .ok_or_else(|| io::Error::other("no syscall instruction for mmap"))?;
        let (base, _secretmem) = self.map_block(pid, orig_regs, map_len, site, pending_stop)?;
        write_block(pid, base + pres, &buf)?;
        // The tracee has its copy; the supervisor's staging buffer must
        // not keep the real strings.
        buf.zeroize();
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
            site,
            base,
            mapped: map_len as u64,
            scratch: base + pres + total as u64,
            pres_bytes,
        })
    }

    /// The bytes `/proc/<pid>/environ` will serve: the `--keep-env`
    /// entries when they were named, otherwise the fixed decoy.  Each
    /// name appears once and every entry is complete.
    fn presentation_env(&self, envp: &[Vec<u8>]) -> Vec<u8> {
        if self.cfg.keep_env.is_empty() {
            return decoy_env().to_vec();
        }
        let mut v = Vec::new();
        for s in envp {
            if self.is_kept_env(Some(s)) && v.len() + s.len() < MAX_PRES_ENV {
                v.extend_from_slice(s);
                v.push(0);
            }
        }
        if v.is_empty() {
            decoy_env().to_vec()
        } else {
            v
        }
    }

    /// Length of [`Self::presentation_env`] for an exec whose environment
    /// pointers are still in the tracee: read only the kept names, or
    /// return the constant decoy length.
    fn presentation_env_len(&self, pid: libc::pid_t, ptrs: &[u64]) -> usize {
        if self.cfg.keep_env.is_empty() {
            return decoy_env().len();
        }
        let mut n = 0usize;
        for &p in ptrs {
            let Some(s) = read_cstr(pid, p, MAX_STRLEN) else {
                continue;
            };
            if self.is_kept_env(Some(&s)) && n + s.len() < MAX_PRES_ENV {
                n += s.len() + 1;
            }
        }
        if n == 0 {
            decoy_env().len()
        } else {
            n
        }
    }

    /// Classify `path` in a single open+5-byte read: non-ELF, 64-bit ELF, or
    /// 32-bit ELF (`EI_CLASS == ELFCLASS32`).
    ///
    /// The path is resolved relative to the tracee (`/proc/<pid>/root` for
    /// absolute paths, `/proc/<pid>/cwd` for relative paths, and
    /// `/proc/self/` rewritten to `/proc/<pid>/`).  Unreadable paths are
    /// treated as `NotElf` (conservative post-exec redaction).
    fn classify_image_elf(&self, pid: libc::pid_t, path: &[u8]) -> ElfKind {
        let inspect = |p: &std::path::Path| -> Option<ElfKind> {
            use std::io::Read;
            let mut f = std::fs::File::open(p).ok()?;
            let mut hdr = [0u8; 5];
            if f.read_exact(&mut hdr).is_ok() && hdr[..4] == [0x7f, b'E', b'L', b'F'] {
                Some(if hdr[4] == 1 {
                    ElfKind::Elf32
                } else {
                    ElfKind::Elf64
                })
            } else {
                Some(ElfKind::NotElf)
            }
        };
        if let Some(p) = rewrite_proc_self(pid, path) {
            // Never fall back to opening `/proc/self/...` in the tracer:
            // that would inspect the supervisor's own binary/fd table.
            return inspect(&p).unwrap_or(ElfKind::NotElf);
        }
        let os = std::ffi::OsStr::from_bytes(path);
        if path.first() == Some(&b'/') {
            let rel: Vec<u8> = path.iter().skip_while(|&&b| b == b'/').copied().collect();
            let mut p = std::path::PathBuf::from(format!("/proc/{}/root", pid));
            p.push(std::ffi::OsStr::from_bytes(&rel));
            if let Some(kind) = inspect(&p) {
                return kind;
            }
            // The root link is hidden (non-dumpable tracee): fall back to the
            // absolute path as the supervisor sees it.
            return inspect(std::path::Path::new(os)).unwrap_or(ElfKind::NotElf);
        }
        let mut p = std::path::PathBuf::from(format!("/proc/{}/cwd", pid));
        p.push(os);
        inspect(&p).unwrap_or(ElfKind::NotElf)
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
            avoid_tmp: false,
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
}

/// Rewrite a tracee's `/proc/self/...` or `/proc/thread-self/...` path
/// (including repeated leading slashes) to `/proc/<pid>/...`.
///
/// `/proc/self` and `/proc/thread-self` resolve relative to the process that
/// opens them, so opening them under `/proc/<pid>/root` (or directly) in the
/// tracer names the *tracer* instead of the tracee (Invariant 9, issue 006).
fn rewrite_proc_self(pid: libc::pid_t, path: &[u8]) -> Option<std::path::PathBuf> {
    if path.first() != Some(&b'/') {
        return None;
    }
    let i = path.iter().position(|&b| b != b'/')?;
    let trimmed = &path[i..];
    for magic in [b"proc/self/".as_slice(), b"proc/thread-self/".as_slice()] {
        if let Some(rest) = trimmed.strip_prefix(magic) {
            let mut p = std::path::PathBuf::from(format!("/proc/{}/", pid));
            p.push(std::ffi::OsStr::from_bytes(rest));
            return Some(p);
        }
    }
    None
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
    if let Some(p) = rewrite_proc_self(pid, path) {
        return Ok(p);
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

/// Plan the 4096-byte scratch window below `sp` used at exec entry.
///
/// Returns `(base, redirect_addr, filler_limit)`:
/// - `[base, base + 256)` holds `[label][NUL][0..]` for the swapped argv/empty
///   pointers.
/// - When `redirect_len` is `Some(n)` and fits above `[base, base + 256)`,
///   `redirect_addr` is placed at the top of `[base, sp)` (16-byte aligned),
///   and `filler_limit` is capped at `redirect_addr - base` so the env filler
///   buffer written at `base` can never overwrite the `--exec-once` redirect
///   path.
/// - Returns `None` when `sp < 4096`.
fn plan_entry_scratch(sp: u64, redirect_len: Option<usize>) -> Option<(u64, Option<u64>, usize)> {
    const WINDOW: u64 = 4096;
    const LABEL_RESERVE: u64 = 256;
    let base = sp.checked_sub(WINDOW)?;
    let Some(rlen) = redirect_len else {
        return Some((base, None, WINDOW as usize));
    };
    if rlen == 0 {
        return Some((base, None, WINDOW as usize));
    }
    let raw_addr = sp.checked_sub(rlen as u64)?;
    let redirect_addr = raw_addr & !15u64;
    if redirect_addr < base + LABEL_RESERVE || redirect_addr + rlen as u64 > sp {
        return Some((base, None, WINDOW as usize));
    }
    let filler_limit = (redirect_addr - base) as usize;
    Some((base, Some(redirect_addr), filler_limit))
}

/// Build the presentation byte vector and its 16-byte aligned size for the
/// redaction block: `[label][NUL][env_pres][label][NUL]`.
///
/// Reserving the trailing NUL for the `AT_EXECFN` label copy guarantees that
/// even when `(fl + 1 + env_pres.len() + fl) % 16 == 0`, the real `argv[0]`
/// written at `base + pres` never abuts `AT_EXECFN` without a terminator.
fn build_presentation_layout(label: &[u8], env_pres: &[u8]) -> (Vec<u8>, u64) {
    let fl = label.len();
    let env_off = fl + 1;
    let execfn = env_off + env_pres.len();
    let pres_len = execfn + fl + 1;
    let mut pres_bytes = vec![0u8; pres_len];
    pres_bytes[..fl].copy_from_slice(label);
    pres_bytes[env_off..env_off + env_pres.len()].copy_from_slice(env_pres);
    pres_bytes[execfn..execfn + fl].copy_from_slice(label);
    let pres = ((pres_len + 15) & !15) as u64;
    (pres_bytes, pres)
}

/// Read `/proc/<pid>/stat` once to extract both:
/// - `(arg_start, arg_end, env_start, env_end)` above `sp` for visible span
///   handling, and
/// - the `MmFields` needed by `PR_SET_MM_MAP` (with `brk` initialized to
///   `start_brk`, which equals `mm->brk` at `PTRACE_EVENT_EXEC`).
#[allow(clippy::type_complexity)]
fn read_proc_stat(
    pid: libc::pid_t,
    sp: u64,
) -> (
    Option<(u64, u64, u64, u64)>,
    Option<crate::presetmm::MmFields>,
) {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) else {
        return (None, None);
    };
    let Some(rparen) = stat.rfind(')') else {
        return (None, None);
    };
    let after = &stat[rparen + 1..];
    let mut start_code = 0u64;
    let mut end_code = 0u64;
    let mut start_stack = 0u64;
    let mut start_data = 0u64;
    let mut end_data = 0u64;
    let mut start_brk = 0u64;
    let mut arg_start = 0u64;
    let mut arg_end = 0u64;
    let mut env_start = 0u64;
    let mut env_end = 0u64;
    for (idx, tok) in after.split_whitespace().enumerate() {
        let field = idx + 3;
        match field {
            26 => start_code = tok.parse().unwrap_or(0),
            27 => end_code = tok.parse().unwrap_or(0),
            28 => start_stack = tok.parse().unwrap_or(0),
            45 => start_data = tok.parse().unwrap_or(0),
            46 => end_data = tok.parse().unwrap_or(0),
            47 => start_brk = tok.parse().unwrap_or(0),
            48 => arg_start = tok.parse().unwrap_or(0),
            49 => arg_end = tok.parse().unwrap_or(0),
            50 => env_start = tok.parse().unwrap_or(0),
            51 => {
                env_end = tok.parse().unwrap_or(0);
                break;
            }
            _ => {}
        }
    }
    let bounds = if arg_start != 0 && arg_end > arg_start && env_end >= env_start && arg_start >= sp
    {
        Some((arg_start, arg_end, env_start, env_end))
    } else {
        None
    };
    let mm = if start_code != 0
        && end_code != 0
        && start_data != 0
        && end_data != 0
        && start_brk != 0
        && start_stack != 0
        && arg_start != 0
        && arg_end != 0
        && env_start != 0
        && env_end != 0
    {
        Some(crate::presetmm::MmFields {
            start_code,
            end_code,
            start_data,
            end_data,
            start_brk,
            brk: start_brk,
            start_stack,
            arg_start,
            arg_end,
            env_start,
            env_end,
        })
    } else {
        None
    };
    (bounds, mm)
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

/// Rewrite `AT_EXECFN` in the tracee's own stack auxiliary vector.
///
/// The kernel copies the auxiliary vector from the old stack to the new
/// one at exec, and the payload's `getauxval` reads that copy.  A tracer
/// stopped at `PTRACE_EVENT_EXEC` runs before the dynamic loader, so the
/// rewrite is what the payload sees.  A missing entry or an unreadable
/// stack is not an error: `/proc/<pid>/auxv` is still consistent.
fn patch_stack_execfn(pid: libc::pid_t, auxv_at: u64, value: u64) {
    const AT_EXECFN: u64 = 31;
    // Read 512 bytes (32 auxv pairs) per syscall instead of 16 bytes at a
    // time; a typical Linux auxv (~20 pairs) completes in one read_mem call.
    const CHUNK_PAIRS: u64 = 32;
    let mut buf = [0u8; (CHUNK_PAIRS as usize) * 16];
    let mut off = 0u64;
    while off < 256 * 16 {
        let got = read_mem(pid, auxv_at + off, &mut buf);
        if got < 16 {
            return;
        }
        let usable = (got as usize) & !15usize;
        for (idx, pair) in buf[..usable].chunks_exact(16).enumerate() {
            let key = u64::from_le_bytes(match pair[..8].try_into() {
                Ok(k) => k,
                Err(_) => return,
            });
            if key == 0 {
                return;
            }
            if key == AT_EXECFN {
                let addr = auxv_at + off + (idx as u64) * 16;
                let _ = write_mem(pid, addr + 8, &value.to_le_bytes());
                return;
            }
        }
        off += usable as u64;
    }
}

/// Where the presentation goes, and what it says.
struct Presentation {
    /// Address the bytes are written to.
    base: u64,
    /// `label`, one NUL, the environment window, the `AT_EXECFN` copy.
    bytes: Vec<u8>,
    /// Bytes of environment window after the label (`0` when the kernel's
    /// environment window is left alone).
    env_len: u64,
    /// The kernel's environment window stays visible (`--keep-env`).
    env_visible: bool,
    /// `bytes` ends with the `AT_EXECFN` label copy.
    label_copy: bool,
}

/// Decide where the presentation goes and what it contains.  `None` when
/// the kernel reports no argv+environment region to write into.
fn plan_presentation(
    label: &[u8],
    redact_environ: bool,
    keep_env_empty: bool,
    fields: &crate::presetmm::MmFields,
    block_base: u64,
    pres_bytes: &[u8],
) -> Option<Presentation> {
    let fl = label.len() as u64;
    let full = pres_bytes.len() as u64;
    let overhead = 2 * (fl + 1);
    if full < overhead {
        return None;
    }
    let full_env = full - overhead;
    let region = if fields.arg_start != 0 && fields.env_end > fields.arg_start {
        fields.env_end - fields.arg_start
    } else {
        0
    };
    let block = |env_visible: bool| Presentation {
        base: block_base,
        bytes: pres_bytes.to_vec(),
        env_len: full_env,
        env_visible,
        label_copy: true,
    };
    if region == 0 {
        return None;
    }
    if !redact_environ {
        // The environment stays the kernel's.  Anchor the compact argv
        // window just below it, so `arg_end == env_start` holds and both
        // fields stay inside `[stack]`.
        if region > fl && fields.env_start > fields.arg_start + fl {
            let mut bytes = Vec::with_capacity((fl + 1) as usize);
            bytes.extend_from_slice(label);
            bytes.push(0);
            return Some(Presentation {
                base: fields.env_start - (fl + 1),
                bytes,
                env_len: 0,
                env_visible: true,
                label_copy: false,
            });
        }
        return Some(block(true));
    }
    if region >= full {
        return Some(Presentation {
            base: fields.arg_start,
            bytes: pres_bytes.to_vec(),
            env_len: full_env,
            env_visible: false,
            label_copy: true,
        });
    }
    if !keep_env_empty {
        // A `--keep-env=NAME` value must appear complete, so only the
        // fixed decoy may be shortened.
        return Some(block(false));
    }
    let env = shrink_env(region.saturating_sub(overhead));
    if env.is_empty() {
        return Some(block(false));
    }
    let mut bytes = Vec::with_capacity((overhead + env.len() as u64) as usize);
    bytes.extend_from_slice(label);
    bytes.push(0);
    bytes.extend_from_slice(&env);
    bytes.extend_from_slice(label);
    bytes.push(0);
    Some(Presentation {
        base: fields.arg_start,
        bytes,
        env_len: env.len() as u64,
        env_visible: false,
        label_copy: true,
    })
}

/// The decoy entries that fit `room` bytes, each complete and
/// NUL-terminated, in the order they appear in [`decoy_env`].  An entry
/// too large for the remaining space is skipped, so a smaller one still
/// fills the window.  An empty result means no complete entry fits and
/// the caller falls back to the block.
fn shrink_env(room: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if room == 0 {
        return out;
    }
    for entry in decoy_env().split(|b| *b == 0).filter(|e| !e.is_empty()) {
        if out.len() as u64 + entry.len() as u64 + 1 > room {
            continue;
        }
        out.extend_from_slice(entry);
        out.push(0);
    }
    out
}

/// The bytes written into an environment window of `span` bytes: each kept
/// variable once, then decoy entries from the same table the compact block
/// uses, then NUL padding to the end of the window.  An entry that does not
/// fit is skipped so a smaller one still fills the window: breaking at the
/// first oversized entry left the whole window NUL, and no real environment
/// is a run of NUL bytes.
fn env_window_bytes(span: usize, kept: &[&[u8]]) -> Vec<u8> {
    let mut buf = vec![0u8; span];
    if span == 0 {
        return buf;
    }
    let mut off = 0usize;
    for s in kept {
        if off + s.len() + 1 > span - 1 {
            break;
        }
        buf[off..off + s.len()].copy_from_slice(s);
        off += s.len() + 1;
    }
    if off < span {
        // Every entry carries its own NUL, so an entry that ends on the last
        // byte of the window still leaves the window NUL-terminated.
        let rest = shrink_env((span - off) as u64);
        buf[off..off + rest.len()].copy_from_slice(&rest);
    }
    buf
}

/// Write the presentation of the environment window when the kernel
/// keeps the original extent.  Each kept variable appears once, then
/// each decoy entry once; the rest of the original extent is NUL.  A
/// repeated `PATH=` run has no ordinary analogue, so the window never
/// repeats an entry.
fn fill_env_window(pid: libc::pid_t, lo: u64, hi: u64, kept: &[&[u8]]) {
    let span = (hi - lo) as usize;
    if span == 0 {
        return;
    }
    let buf = env_window_bytes(span, kept);
    let _ = write_mem(pid, lo, &buf);
}

/// Bytes reserved for the `PR_SET_MM_MAP` struct, which is 104, and for
/// the auxiliary vector copy, which is at most `AT_VECTOR_SIZE` entries
/// of 16 bytes.
const SCRATCH_ROOM: usize = 2048;

/// The fixed environment exposed in exact mode for root (`euid == 0`) when the
/// caller did not name variables to keep.
const DECOY_ENV_ROOT: &[u8] =
    b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0\
HOME=/root\0LANG=C.UTF-8\0TERM=xterm-256color\0";

/// The fixed environment exposed in exact mode for non-root accounts
/// (`euid != 0`) when the caller did not name variables to keep.  Uses
/// `HOME=/tmp` instead of `HOME=/root` so non-root processes never present a
/// mismatched root home directory.
const DECOY_ENV_NONROOT: &[u8] =
    b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0\
HOME=/tmp\0LANG=C.UTF-8\0TERM=xterm-256color\0";

fn decoy_env_for_uid(euid: libc::uid_t) -> &'static [u8] {
    if euid == 0 {
        DECOY_ENV_ROOT
    } else {
        DECOY_ENV_NONROOT
    }
}

/// The fixed decoy environment matching the current effective uid.
fn decoy_env() -> &'static [u8] {
    // SAFETY: geteuid(2) is always safe and cannot fail.
    let euid = unsafe { libc::geteuid() };
    decoy_env_for_uid(euid)
}

/// Upper bound on the exposed `--keep-env` span.  A caller can name many
/// variables; the presentation area is bounded so the block stays small.
const MAX_PRES_ENV: usize = 4096;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(
        arg_start: u64,
        arg_end: u64,
        env_start: u64,
        env_end: u64,
    ) -> crate::presetmm::MmFields {
        crate::presetmm::MmFields {
            start_code: 0x1000,
            end_code: 0x2000,
            start_data: 0x3000,
            end_data: 0x4000,
            start_brk: 0x5000,
            brk: 0x6000,
            start_stack: 0x7fff_0000,
            arg_start,
            arg_end,
            env_start,
            env_end,
        }
    }

    fn pres_bytes(label: &[u8]) -> Vec<u8> {
        build_presentation_layout(label, decoy_env()).0
    }

    fn entries(buf: &[u8]) -> Vec<&[u8]> {
        assert_eq!(
            *buf.last().expect("non-empty window"),
            0,
            "window ends with NUL"
        );
        buf.split(|b| *b == 0).filter(|e| !e.is_empty()).collect()
    }

    #[test]
    fn fitting_presentation_stays_in_the_stack() {
        let label = b"pmask";
        let pres = pres_bytes(label);
        let region = pres.len() as u64 + 40;
        let f = fields(0x7ffd_0000, 0x7ffd_0010, 0x7ffd_0010, 0x7ffd_0000 + region);
        let p = plan_presentation(label, true, true, &f, 0x1000_0000, &pres).expect("plan");
        assert_eq!(p.base, f.arg_start, "the presentation stays in the stack");
        assert!(!p.env_visible);
        assert!(p.label_copy, "AT_EXECFN points at the trailing copy");
        assert_eq!(p.env_len, decoy_env().len() as u64);
        assert_eq!(
            p.bytes.len() as u64,
            (label.len() as u64 + 1) + p.env_len + (label.len() as u64 + 1),
            "label, NUL, environment window, label copy, NUL"
        );
        let execfn_off = label.len() + 1 + p.env_len as usize;
        assert_eq!(&p.bytes[execfn_off..execfn_off + label.len()], label);
        assert_eq!(p.bytes[execfn_off + label.len()], 0);
        assert!(p.bytes.len() as u64 <= region, "fits the kernel's region");
    }

    /// `--keep-env`: the kernel's environment window is left alone, so the
    /// compact argv window is anchored directly below `env_start`.  The
    /// caller then sets `arg_end == env_start`, which is the relation an
    /// ordinary exec has.
    #[test]
    fn keep_env_anchors_argv_at_env_start() {
        let label = b"pmask";
        let pres = pres_bytes(label);
        let f = fields(0x7ffd_0000, 0x7ffd_0100, 0x7ffd_0100, 0x7ffd_0800);
        let p = plan_presentation(label, false, true, &f, 0x1000_0000, &pres).expect("plan");
        assert_eq!(p.base + label.len() as u64 + 1, f.env_start);
        assert_eq!(p.base, f.env_start - (label.len() as u64 + 1));
        assert!(p.base >= f.arg_start, "stays inside the region");
        let mut want = label.to_vec();
        want.push(0);
        assert_eq!(p.bytes, want);
        assert!(p.env_visible);
        assert!(!p.label_copy, "AT_EXECFN points at the argv window itself");
        assert_eq!(p.env_len, 0);
    }

    /// A region too small for the full presentation keeps the label and the
    /// decoy entries that fit whole.  `arg_end == env_start` still holds and
    /// the window never repeats an entry.
    #[test]
    fn small_region_shrinks_to_complete_decoy_entries() {
        let label = b"pmask";
        let pres = pres_bytes(label);
        let region = 40u64;
        let f = fields(0x7ffd_0000, 0x7ffd_0010, 0x7ffd_0010, 0x7ffd_0000 + region);
        let p = plan_presentation(label, true, true, &f, 0x1000_0000, &pres).expect("plan");
        assert_eq!(p.base, f.arg_start);
        assert!(p.bytes.len() as u64 <= region);
        assert!(!p.env_visible);
        assert!(p.label_copy);
        assert!(p.env_len > 0, "the environment window is not empty");
        assert_eq!(
            p.bytes.len() as u64,
            (label.len() as u64 + 1) + p.env_len + (label.len() as u64 + 1)
        );
        assert_eq!(*p.bytes.last().expect("trailing NUL"), 0);
        let start = label.len() + 1;
        let end = start + p.env_len as usize;
        let env = entries(&p.bytes[start..end]);
        assert!(!env.is_empty());
        let mut seen: Vec<&[u8]> = Vec::new();
        for e in &env {
            assert!(!seen.contains(e), "no repeated entry");
            seen.push(e);
        }
    }

    /// Nothing plausible fits: the presentation moves to the block, which
    /// is the extent shape `--no-exact` also has.
    #[test]
    fn tiny_region_falls_back_to_the_block() {
        let label = b"pmask";
        let pres = pres_bytes(label);
        let f = fields(0x7ffd_0000, 0x7ffd_0004, 0x7ffd_0004, 0x7ffd_0008);
        let p = plan_presentation(label, true, true, &f, 0x1000_0000, &pres).expect("plan");
        assert_eq!(p.base, 0x1000_0000);
        assert_eq!(p.bytes, pres);
        assert!(!p.env_visible);
    }

    /// A kept variable must appear whole, so `--keep-env=NAME` never
    /// shortens the window.
    #[test]
    fn kept_variable_is_never_shortened() {
        let label = b"pmask";
        let pres = pres_bytes(label);
        let f = fields(0x7ffd_0000, 0x7ffd_0010, 0x7ffd_0010, 0x7ffd_0028);
        let p = plan_presentation(label, true, false, &f, 0x1000_0000, &pres).expect("plan");
        assert_eq!(p.base, 0x1000_0000);
        assert_eq!(p.bytes, pres);
    }

    /// `--keep-env` with a region too small for the label also falls back,
    /// so the environment stays the kernel's either way.
    #[test]
    fn keep_env_tiny_region_falls_back_but_keeps_environ() {
        let label = b"pmask";
        let pres = pres_bytes(label);
        let f = fields(0x7ffd_0000, 0x7ffd_0002, 0x7ffd_0002, 0x7ffd_0004);
        let p = plan_presentation(label, false, true, &f, 0x1000_0000, &pres).expect("plan");
        assert_eq!(p.base, 0x1000_0000);
        assert!(p.env_visible);
    }

    #[test]
    fn hidden_fields_have_no_plan() {
        let label = b"pmask";
        let pres = pres_bytes(label);
        let f = fields(0, 0, 0, 0);
        assert!(plan_presentation(label, true, true, &f, 0x1000_0000, &pres).is_none());
    }

    #[test]
    fn shrink_env_keeps_entries_whole() {
        assert!(shrink_env(0).is_empty());
        let out = shrink_env(24);
        assert!(!out.is_empty());
        assert!(out.len() as u64 <= 24);
        for e in entries(&out) {
            assert!(out.windows(e.len()).any(|w| w == e));
        }
        // Every entry came from the decoy list.
        for e in entries(&out) {
            assert!(decoy_env().split(|b| *b == 0).any(|d| d == e));
        }
    }

    #[test]
    fn decoy_env_uses_home_root_only_for_uid_zero() {
        assert!(decoy_env_for_uid(0)
            .split(|b| *b == 0)
            .any(|e| e == b"HOME=/root"));
        assert!(decoy_env_for_uid(1000)
            .split(|b| *b == 0)
            .any(|e| e == b"HOME=/tmp"));
        assert!(!decoy_env_for_uid(1000)
            .split(|b| *b == 0)
            .any(|e| e == b"HOME=/root"));
    }

    /// The environment window a `--no-exact` run leaves behind must look
    /// like an environment.  A window too small for `PATH=` used to be
    /// written as NUL bytes only, because the decoy loop stopped at the
    /// first entry that did not fit.
    #[test]
    fn a_small_env_window_still_holds_a_plausible_entry() {
        // `env -i PATH=/usr/bin:/bin` is 19 bytes, the shape qa.d/40.sh
        // measures; the first decoy entry is 62 bytes and does not fit.
        let b = env_window_bytes(19, &[]);
        assert_eq!(b.len(), 19);
        assert!(
            b.iter().any(|c| *c != 0),
            "the window is a run of NUL bytes: {:?}",
            b
        );
        let first = b.split(|c| *c == 0).next().unwrap_or(&[]);
        assert!(
            first.contains(&b'='),
            "the first entry is not KEY=VALUE: {:?}",
            String::from_utf8_lossy(first)
        );
        // The window ends with a NUL and never overruns.
        assert_eq!(b[18], 0);
    }

    /// A window large enough for the whole decoy holds every entry once.
    #[test]
    fn a_full_env_window_holds_the_decoy_once() {
        let decoy = decoy_env();
        let b = env_window_bytes(decoy.len(), &[]);
        assert_eq!(b.len(), decoy.len());
        assert_eq!(b.as_slice(), decoy);
    }

    /// A kept variable comes first, then decoy entries fill the rest.
    #[test]
    fn a_kept_variable_comes_before_the_decoy() {
        let b = env_window_bytes(64, &[b"PMASK_KEPT=1"]);
        assert_eq!(b.len(), 64);
        assert_eq!(&b[..12], b"PMASK_KEPT=1");
        assert_eq!(b[12], 0);
        assert!(
            b[13..].iter().any(|c| *c != 0),
            "no decoy after the kept entry"
        );
    }

    /// A window too small for even one entry is NUL padding, and that is
    /// the one shape the function cannot make plausible; it must not panic
    /// or write past the window.
    #[test]
    fn a_window_shorter_than_any_entry_is_padding() {
        for span in 0..6 {
            let b = env_window_bytes(span, &[]);
            assert_eq!(b.len(), span);
            assert!(b.iter().all(|c| *c == 0), "span {span} is not padding");
        }
    }

    #[test]
    fn presentation_layout_nul_terminates_execfn_on_16_byte_boundary() {
        // Choose label + env_pres so `execfn + fl` is an exact multiple of 16:
        // fl=4, env_off=5, env_pres=7 -> execfn=12, execfn+fl=16 (16 % 16 == 0).
        let label = b"abcd";
        let env_pres = b"FOO=12\0";
        let execfn = label.len() + 1 + env_pres.len();
        assert_eq!((execfn + label.len()) % 16, 0);

        let (pres_bytes, pres) = build_presentation_layout(label, env_pres);
        assert_eq!(pres_bytes.len(), execfn + label.len() + 1);
        assert_eq!(&pres_bytes[execfn..execfn + label.len()], label);
        assert_eq!(
            pres_bytes[execfn + label.len()],
            0,
            "AT_EXECFN copy must carry its own NUL terminator"
        );
        assert!(
            pres > (execfn + label.len()) as u64,
            "real argv[0] at base+pres ({}) must never abut AT_EXECFN ({}) without a NUL",
            pres,
            execfn + label.len()
        );
        assert_eq!(pres % 16, 0);

        // Even when the stack region matches `pres_bytes.len()` exactly, the
        // planned stack presentation includes the trailing NUL so AT_EXECFN
        // cannot bleed into the kernel's original AT_EXECFN above `env_end`.
        let f = fields(
            0x7ffd_0000,
            0x7ffd_0008,
            0x7ffd_0008,
            0x7ffd_0000 + pres_bytes.len() as u64,
        );
        let p = plan_presentation(label, true, false, &f, 0x1000_0000, &pres_bytes).expect("plan");
        assert_eq!(p.base, f.arg_start);
        assert_eq!(p.bytes.len(), pres_bytes.len());
        assert_eq!(p.bytes[execfn + label.len()], 0);
    }

    #[test]
    fn entry_scratch_keeps_redirect_disjoint_from_env_filler() {
        let sp = 0x7fff_0000u64;
        // A 96-byte redirect path lands at the top of the 4096-byte scratch
        // window; filler up to `filler_limit` can never overwrite it, even
        // when `total > 512` (which collided with the old `base + 512` slot).
        let (base, redirect_addr, filler_limit) =
            plan_entry_scratch(sp, Some(96)).expect("scratch plan");
        let redirect_addr = redirect_addr.expect("redirect fits");
        assert_eq!(base, sp - 4096);
        assert!(redirect_addr >= base + 256);
        assert!(redirect_addr + 96 <= sp);
        assert_eq!(base + filler_limit as u64, redirect_addr);
        assert!(
            filler_limit > 1024,
            "large env fillers still fit without colliding with redirect_addr"
        );

        // An oversized redirect path that would encroach on the 256-byte
        // label scratch is rejected cleanly.
        let (_, too_big, limit) = plan_entry_scratch(sp, Some(3900)).expect("scratch plan");
        assert_eq!(too_big, None);
        assert_eq!(limit, 4096);

        // A stack pointer below 4096 returns None instead of underflowing.
        assert!(plan_entry_scratch(2048, Some(32)).is_none());
    }

    #[test]
    fn rewrite_proc_self_targets_tracee_not_tracer() {
        assert_eq!(
            rewrite_proc_self(4242, b"/proc/self/exe"),
            Some(std::path::PathBuf::from("/proc/4242/exe"))
        );
        assert_eq!(
            rewrite_proc_self(4242, b"/proc/thread-self/fd/3"),
            Some(std::path::PathBuf::from("/proc/4242/fd/3"))
        );
        assert_eq!(
            rewrite_proc_self(4242, b"///proc/self/exe"),
            Some(std::path::PathBuf::from("/proc/4242/exe"))
        );
        assert_eq!(rewrite_proc_self(4242, b"/usr/bin/true"), None);
        assert_eq!(rewrite_proc_self(4242, b"proc/self/exe"), None);
    }

    #[test]
    fn fast_sealed_strings_roundtrip_and_reject_wrong_key() {
        let key = crate::crypto::SessionKey::generate().expect("session key");
        let other = crate::crypto::SessionKey::generate().expect("other key");
        let mut scratch = LockedScratch::default();
        let input = vec![b"prog".to_vec(), b"--secret=xyz".to_vec(), Vec::new()];
        let sealed = FastSealedStrings::seal(&key, &input, &mut scratch).expect("seal");
        let opened = sealed.open(&key, &mut scratch).expect("open");
        assert_eq!(opened, input);
        assert!(sealed.open(&other, &mut scratch).is_err());
    }
}
