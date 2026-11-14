//! Redact this process's own published metadata.
//!
//! The tracer process lives as long as the supervised tree, so it
//! applies the same treatment to itself: its argv strings (and by
//! default its environment strings) are zeroed in place, the label is
//! written into the zeroed argv block, and its `comm` is set to the
//! session label.
//!
//! The caller snapshots the child's argv and environment first, then
//! calls this module, then forks.  The child's exec therefore still
//! sees the real values.

use std::io;

/// Locate `[arg_start, arg_end, env_start, env_end]` of this process via
/// `/proc/self/stat` (fields 48-51; comm may contain spaces/parens, so
/// parse after the last ')').
fn self_arg_env_range() -> io::Result<(u64, u64, u64, u64)> {
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    let after_comm = match stat.rfind(')') {
        Some(i) => &stat[i + 1..],
        None => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad stat")),
    };
    // remainder[0] is field 3 (state)
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let get = |field: usize| -> io::Result<u64> {
        fields
            .get(field - 3)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short stat"))
    };
    Ok((get(48)?, get(49)?, get(50)?, get(51)?))
}

/// Zero the argv string block of this process (the memory
/// `/proc/self/cmdline` is served from).
///
/// # Safety
/// Writes zeros over the process's initial argv string area.  Nothing may
/// read the original argv afterwards.  `std` saves `argc` and the `argv`
/// pointer at startup, not the strings, and every `std::env::args()` /
/// `args_os()` call dereferences those saved pointers.  After this call
/// they yield `argc` empty strings; after `mask_self` writes the label at
/// `arg_start`, element 0 is the label and later elements are label
/// suffixes or empty.  Collect `args_os()` (or call `snapshot_argv`)
/// before this call.
pub unsafe fn zero_own_argv() -> io::Result<()> {
    let (arg_start, arg_end, _, _) = self_arg_env_range()?;
    if arg_start < arg_end {
        std::ptr::write_bytes(arg_start as *mut u8, 0, (arg_end - arg_start) as usize);
    }
    Ok(())
}

/// Zero the environment string block of this process (the memory
/// `/proc/self/environ` is served from).
///
/// # Safety
/// See `zero_own_argv`; additionally `std::env::var*` will observe empty
/// values afterwards.
pub unsafe fn zero_own_environ() -> io::Result<()> {
    let (_, _, env_start, env_end) = self_arg_env_range()?;
    if env_start < env_end {
        std::ptr::write_bytes(env_start as *mut u8, 0, (env_end - env_start) as usize);
    }
    Ok(())
}

/// Write `label` at `arg_start`, clipped to the argv region and padded
/// with NUL bytes.  The last byte of the region stays NUL, so the kernel
/// serves exactly the label and does not run on into the environment.
///
/// # Safety
/// Same as `zero_own_argv`: the argv region must be zeroed or otherwise
/// unused.
unsafe fn write_own_label(label: &[u8]) -> io::Result<()> {
    let (arg_start, arg_end, _, _) = self_arg_env_range()?;
    if arg_start >= arg_end {
        return Ok(());
    }
    let room = (arg_end - arg_start) as usize;
    let n = label.len().min(room.saturating_sub(1));
    if n > 0 {
        std::ptr::copy_nonoverlapping(label.as_ptr(), arg_start as *mut u8, n);
    }
    Ok(())
}

/// The outcome of the self-treatment.  The argv/environ/comm work and
/// the window relocation are independent: the relocation needs
/// `CAP_SYS_RESOURCE`, and its refusal leaves the label in place.
pub struct SelfMask {
    /// The first error from zeroing argv, writing the label, zeroing the
    /// environment, or setting `comm`.
    pub error: Option<io::Error>,
    /// The error from `PR_SET_MM_MAP`, when the kernel refused it.  The
    /// supervisor's window keeps its original extent; the label is still
    /// what `/proc` serves.
    pub window: Option<io::Error>,
    /// The error from `PR_SET_DUMPABLE(0)`, when the supervisor could not
    /// be made non-dumpable.  A same-uid peer could then read its maps,
    /// auxv and memory for the life of the session.
    pub dumpable: Option<io::Error>,
}

/// Apply the full self-treatment with an explicit command-line label:
/// zero argv, write `label` into the zeroed block (NUL padded), zero the
/// environment strings when `redact_environ` is set, move the kernel's
/// argv and environment windows onto the label, and set `comm`.
///
/// Every step runs even when an earlier step failed.  The two failures
/// are returned separately so a caller can report a refused window
/// relocation without claiming the redaction itself failed.
pub fn mask_self_label_with_window(
    label: &[u8],
    label_comm: &[u8],
    redact_environ: bool,
) -> SelfMask {
    mask_self_label_with_window_opts(label, label_comm, redact_environ, true)
}

/// [`mask_self_label_with_window`] with an explicit choice for the
/// supervisor's dumpable flag.
///
/// `non_dumpable` is the safe default for a supervisor that holds
/// plaintext at rest.  A supervisor that has scrubbed every at-rest copy
/// can stay dumpable: on a host whose `/proc` uses `hidepid=invisible`,
/// a non-dumpable process is hidden from same-uid observers, and the
/// hidden-pid sweepers name it.  A dumpable supervisor with no secrets
/// is an ordinary process of the caller's uid.
pub fn mask_self_label_with_window_opts(
    label: &[u8],
    label_comm: &[u8],
    redact_environ: bool,
    non_dumpable: bool,
) -> SelfMask {
    // SAFETY: the callers snapshot everything they need from argv and
    // environ before this call (see the module docs).
    let mut first_error: Option<io::Error> = unsafe {
        zero_own_argv()
            .err()
            .or_else(|| write_own_label(label).err())
    };
    if redact_environ {
        // SAFETY: as above; the snapshot is already taken.
        if let Err(e) = unsafe { zero_own_environ() } {
            if first_error.is_none() {
                first_error = Some(e);
            }
        }
    }
    // The supervisor's own command line is otherwise label + as many NUL
    // bytes as its arguments took, which is the same length fingerprint
    // the payload's relocation removes.  Moving its own window is the
    // same one-shot prctl, applied to this process.
    let window = relocate_own_window(label.len() as u64, redact_environ).err();
    let mut buf = [0u8; 16];
    let n = label_comm.len().min(15);
    buf[..n].copy_from_slice(&label_comm[..n]);
    // SAFETY: buf is NUL terminated and lives for the call.
    let rc = unsafe { libc::prctl(libc::PR_SET_NAME, buf.as_ptr(), 0, 0, 0) };
    if rc == -1 && first_error.is_none() {
        first_error = Some(io::Error::last_os_error());
    }
    // A supervisor that still holds plaintext at rest must not be
    // readable by a same-uid peer.  A supervisor that has scrubbed every
    // at-rest copy can be dumpable; that is what keeps it out of the
    // hidden-pid family on a `hidepid=invisible` host.  The forked child
    // restores its own dumpable flag before the readiness byte, so the
    // payload keeps the default.
    // SAFETY: our own dumpable flag.
    let flag = if non_dumpable { 0 } else { 1 };
    let dumpable = if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, flag, 0, 0, 0) } == -1 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    SelfMask {
        error: first_error,
        window,
        dumpable,
    }
}

/// Apply the full self-treatment, returning the first failure of any
/// step.  Callers that want to distinguish a refused window relocation
/// from a failed redaction use [`mask_self_label_with_window`].
pub fn mask_self_label(label: &[u8], label_comm: &[u8], redact_environ: bool) -> io::Result<()> {
    let r = mask_self_label_with_window(label, label_comm, redact_environ);
    match (r.error, r.window, r.dumpable) {
        (Some(e), _, _) => Err(e),
        (None, Some(e), _) => Err(e),
        (None, None, Some(e)) => Err(e),
        (None, None, None) => Ok(()),
    }
}

/// Move this process's own `arg_start..arg_end` window onto the label that
/// now sits at `arg_start`, and collapse the environment window when the
/// environment strings were zeroed.
///
/// Every field of `struct prctl_mm_map` has to be a live address, so the
/// values for the segments come from `/proc/self/stat` and `sbrk(0)`.
fn relocate_own_window(label_len: u64, collapse_env: bool) -> io::Result<()> {
    let brk = unsafe { libc::sbrk(0) } as u64;
    let mut m = crate::presetmm::read_fields(0, brk)
        .ok_or_else(|| io::Error::other("mm fields unreadable"))?;
    m.arg_end = m.arg_start + label_len + 1;
    if m.arg_end > m.env_start {
        return Err(io::Error::other("label does not fit the argv window"));
    }
    if collapse_env {
        m.env_start = m.arg_end;
        m.env_end = m.arg_end;
    }
    // The supervisor's own `saved_auxv` still names the pmask binary in
    // `AT_EXECFN`, which a same-uid reader can resolve.  Rewrite it to
    // point at the label in the argv window, so auxv agrees with cmdline.
    // The kernel copies this buffer into `mm->saved_auxv`, so it only has
    // to live for the prctl call below.
    let mut auxv =
        crate::presetmm::read_auxv(std::process::id() as libc::pid_t).unwrap_or_default();
    let (auxv_addr, auxv_size) = if auxv.is_empty() {
        (0, 0)
    } else {
        crate::presetmm::patch_execfn(&mut auxv, m.arg_start);
        (auxv.as_ptr() as u64, auxv.len() as u32)
    };
    let buf = crate::presetmm::encode(&m, auxv_addr, auxv_size);
    let rc = unsafe {
        libc::syscall(
            libc::SYS_prctl,
            crate::presetmm::PR_SET_MM as libc::c_long,
            crate::presetmm::PR_SET_MM_MAP as libc::c_long,
            buf.as_ptr(),
            crate::presetmm::MM_MAP_LEN as libc::c_long,
            0 as libc::c_long,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Apply the full self-treatment with `label_comm` as both the
/// command-line label and the `comm` name.
pub fn mask_self(label_comm: &[u8], redact_environ: bool) -> io::Result<()> {
    mask_self_label(label_comm, label_comm, redact_environ)
}

/// [`mask_self`] with the window relocation reported separately.
pub fn mask_self_with_window(label_comm: &[u8], redact_environ: bool) -> SelfMask {
    mask_self_label_with_window(label_comm, label_comm, redact_environ)
}

/// [`mask_self_with_window`] with an explicit dumpable choice; see
/// [`mask_self_label_with_window_opts`].
pub fn mask_self_with_window_opts(
    label_comm: &[u8],
    redact_environ: bool,
    non_dumpable: bool,
) -> SelfMask {
    mask_self_label_with_window_opts(label_comm, label_comm, redact_environ, non_dumpable)
}
