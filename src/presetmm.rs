//! The kernel's own argv and environment windows: `/proc/<pid>/stat`
//! fields 48 to 51, and the one-shot `prctl(PR_SET_MM, PR_SET_MM_MAP)`
//! that moves them.
//!
//! `get_mm_cmdline()` reads exactly `[arg_start, arg_end)`, so
//! `arg_end - arg_start` is the byte length of `/proc/<pid>/cmdline` by
//! construction.  A redaction that rewrites strings in place leaves the
//! original span, which is a fingerprint an observer can read from
//! `/proc/<pid>/stat` without any privilege.  Relocating the span to an
//! anonymous mapping this crate owns removes it, and at the same time
//! sets the environment window and the `AT_EXECFN` entry of
//! `saved_auxv`.
//!
//! The bare operations (`PR_SET_MM_ARG_START`, `_ARG_END`, `_ENV_*`,
//! `_EXE_FILE`) check `CAP_SYS_RESOURCE`; the one-shot map does not,
//! because the check sits after the map dispatch in `prctl_set_mm()`.
//! The map is all or nothing: `validate_prctl_map_addr()` refuses a zero
//! address for any of the eleven fields, refuses `start_code ==
//! end_code`, and refuses `env_start == env_end == 0`, so every field
//! must be a real address inside the tracee.

use crate::arch::{self, Regs};
use crate::remote::write_mem;

/// `prctl(2)` options used here.  `libc` is missing the `PR_SET_MM`
/// family on some targets, and these numbers are in the uapi headers.
pub const PR_SET_MM: libc::c_int = 35;
pub const PR_SET_MM_MAP: libc::c_int = 14;
pub const PR_SET_MM_MAP_SIZE: libc::c_int = 15;

/// `struct prctl_mm_map` from `include/uapi/linux/prctl.h`, in bytes.
pub const MM_MAP_LEN: usize = 104;

/// `mm_struct` fields the map replaces, plus the argv/environment
/// windows it moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmFields {
    pub start_code: u64,
    pub end_code: u64,
    pub start_data: u64,
    pub end_data: u64,
    pub start_brk: u64,
    pub brk: u64,
    pub start_stack: u64,
    pub arg_start: u64,
    pub arg_end: u64,
    pub env_start: u64,
    pub env_end: u64,
}

/// The `(index, name)` of every `/proc/<pid>/stat` field this module
/// reads, 1-based as the man page numbers them.
const STAT_ARG_START: usize = 48;
const STAT_ARG_END: usize = 49;
const STAT_ENV_START: usize = 50;
const STAT_ENV_END: usize = 51;

/// Split `/proc/<pid>/stat` into fields after the command name.  The
/// command name can contain spaces and parentheses, so the split starts
/// after the *last* `)`.  `pid` 0 means this process.
fn stat_after_comm(pid: libc::pid_t) -> Option<Vec<u64>> {
    let which = if pid == 0 {
        "self".to_string()
    } else {
        pid.to_string()
    };
    let s = std::fs::read_to_string(format!("/proc/{}/stat", which)).ok()?;
    let rest = &s[s.rfind(')')? + 1..];
    let mut out = Vec::with_capacity(52);
    for tok in rest.split_whitespace() {
        // field 3 is the single-letter state; every later field is an
        // integer, and a `-` appears only as a negative value
        out.push(tok.parse::<u64>().unwrap_or(0));
    }
    Some(out)
}

/// Read the eleven addresses the map needs.
///
/// `brk` is not in `/proc/<pid>/stat`, so the caller supplies it (the
/// tracee's own `brk(0)` answer).  `None` when the kernel hides the mm
/// fields, which it does for a non-dumpable task.
pub fn read_fields(pid: libc::pid_t, brk: u64) -> Option<MmFields> {
    let f = stat_after_comm(pid)?;
    if f.len() < STAT_ENV_END - 3 {
        return None;
    }
    let get = |n: usize| -> u64 { *f.get(n - 3).unwrap_or(&0) };
    let m = MmFields {
        start_code: get(26),
        end_code: get(27),
        start_stack: get(28),
        start_data: get(45),
        end_data: get(46),
        start_brk: get(47),
        brk,
        arg_start: get(STAT_ARG_START),
        arg_end: get(STAT_ARG_END),
        env_start: get(STAT_ENV_START),
        env_end: get(STAT_ENV_END),
    };
    if m.start_code == 0 || m.end_code == 0 || m.start_data == 0 || m.end_data == 0 {
        return None;
    }
    if m.start_brk == 0 || m.brk == 0 || m.start_stack == 0 {
        return None;
    }
    if m.arg_start == 0 || m.arg_end == 0 || m.env_start == 0 || m.env_end == 0 {
        return None;
    }
    Some(m)
}

/// Serialize the map.  `auxv` is a tracee address holding `auxv_size`
/// bytes of auxiliary vector, or `(0, 0)` to leave `saved_auxv` alone.
/// `exe_fd` is always `-1`, which is what refuses the `PR_SET_MM_EXE_FILE`
/// path that needs checkpoint/restore capability.
pub fn encode(m: &MmFields, auxv: u64, auxv_size: u32) -> [u8; MM_MAP_LEN] {
    let mut b = [0u8; MM_MAP_LEN];
    let mut put = |off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    put(0, m.start_code);
    put(8, m.end_code);
    put(16, m.start_data);
    put(24, m.end_data);
    put(32, m.start_brk);
    put(40, m.brk);
    put(48, m.start_stack);
    put(56, m.arg_start);
    put(64, m.arg_end);
    put(72, m.env_start);
    put(80, m.env_end);
    put(88, auxv);
    b[96..100].copy_from_slice(&auxv_size.to_le_bytes());
    b[100..104].copy_from_slice(&u32::MAX.to_le_bytes());
    b
}

/// Ask the kernel for the size of its `struct prctl_mm_map`, in a child
/// so a refused call cannot disturb the caller.  `None` when the kernel
/// has no `PR_SET_MM_MAP` (no `CONFIG_CHECKPOINT_RESTORE`) or the call
/// is filtered.
///
/// The value matters: `encode` writes a hand-written 104-byte struct, and
/// a kernel that reports a different size would reinterpret every field.
/// The caller compares this against `MM_MAP_LEN` for that reason.
pub fn map_size() -> Option<u32> {
    let mut fds = [0i32; 2];
    // SAFETY: pipe2 writes two descriptors into a two-element array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return None;
    }
    let (rd, wr) = (fds[0], fds[1]);
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return None;
    }
    if pid == 0 {
        unsafe { libc::close(rd) };
        let mut out: u32 = 0;
        let rc = unsafe {
            libc::prctl(
                PR_SET_MM,
                PR_SET_MM_MAP_SIZE as libc::c_ulong,
                &mut out as *mut u32,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if rc == 0 {
            let bytes = out.to_ne_bytes();
            // SAFETY: `wr` is open in this child and `bytes` is 4 bytes.
            unsafe { libc::write(wr, bytes.as_ptr().cast(), bytes.len()) };
        }
        unsafe { libc::_exit(if rc == 0 { 0 } else { 1 }) };
    }
    unsafe { libc::close(wr) };
    let mut got = [0u8; 4];
    let mut have = 0usize;
    while have < got.len() {
        let n = unsafe { libc::read(rd, got[have..].as_mut_ptr().cast(), got.len() - have) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            break;
        }
        have += n as usize;
    }
    unsafe { libc::close(rd) };
    let mut status = 0i32;
    loop {
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        if w == -1 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
        break;
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 && have == got.len() {
        Some(u32::from_ne_bytes(got))
    } else {
        None
    }
}

/// What a relocation did, for the session summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relocated {
    /// The kernel's windows now describe the presentation string.
    Yes,
    /// The kernel refused the map (no `CONFIG_CHECKPOINT_RESTORE`, a
    /// seccomp filter, or a validation failure): the caller keeps the
    /// in-place redaction.
    Refused(libc::c_int),
    /// The mm fields were not readable.
    NoFields,
}

/// Where the injected syscall runs, and the writable tracee memory it
/// may use for its arguments.
#[derive(Debug, Clone, Copy)]
pub struct Scratch {
    /// A syscall instruction inside the tracee (see
    /// `inject::find_syscall_site`).
    pub site: u64,
    /// At least [`MM_MAP_LEN`] plus 1024 bytes of writable tracee memory.
    pub addr: u64,
}

/// Move the kernel's argv window to `arg_start..arg_end`, and the
/// environment window to `env_start..env_end`, in the tracee `pid`.
///
/// `auxv`, when given, is a vector to install together with the `AT_EXECFN`
/// entry rewritten to the second element (the presentation string).
pub fn relocate(
    pid: libc::pid_t,
    orig: &Regs,
    scratch: Scratch,
    m: &MmFields,
    auxv: Option<(&[u8], u64)>,
    pending_stop: &mut Option<i32>,
) -> Relocated {
    let (auxv_addr, auxv_size) = match auxv {
        Some((bytes, execfn_addr)) if !bytes.is_empty() && bytes.len() <= 1024 => {
            let mut patched = bytes.to_vec();
            patch_execfn(&mut patched, execfn_addr);
            if write_mem(pid, scratch.addr, &patched) != patched.len() as isize {
                return Relocated::NoFields;
            }
            (scratch.addr, patched.len() as u32)
        }
        _ => (0, 0),
    };
    let map_addr = scratch.addr + 1024;
    let buf = encode(m, auxv_addr, auxv_size);
    if write_mem(pid, map_addr, &buf) != buf.len() as isize {
        return Relocated::NoFields;
    }
    let r = crate::inject::run_remote_syscall(
        pid,
        orig,
        arch::SYS_PRCTL,
        [
            PR_SET_MM as u64,
            PR_SET_MM_MAP as u64,
            map_addr,
            MM_MAP_LEN as u64,
            0,
            0,
        ],
        scratch.site,
        pending_stop,
    );
    match r {
        Ok(0) => Relocated::Yes,
        Ok(rv) => Relocated::Refused(-(rv as i32)),
        Err(_) => Relocated::NoFields,
    }
}

/// `AT_EXECFN` in the auxiliary vector: the address the kernel reports
/// as the executed file name.  Rewriting it to the presentation string
/// keeps `/proc/<pid>/auxv` consistent with `/proc/<pid>/cmdline`.
const AT_EXECFN: u64 = 31;

/// Replace the `AT_EXECFN` value in an auxiliary vector image read from
/// `/proc/<pid>/auxv`.  Leaves an image without that entry untouched.
fn patch_execfn(auxv: &mut [u8], addr: u64) {
    let mut off = 0;
    while off + 16 <= auxv.len() {
        let key = u64::from_le_bytes(match auxv[off..off + 8].try_into() {
            Ok(a) => a,
            Err(_) => return,
        });
        if key == 0 {
            return;
        }
        if key == AT_EXECFN {
            auxv[off + 8..off + 16].copy_from_slice(&addr.to_le_bytes());
            return;
        }
        off += 16;
    }
}

/// Read `/proc/<pid>/auxv` as bytes, for the rewrite above.
///
/// The file is published from `mm->saved_auxv`, so it is both the source
/// of the vector to patch and the thing an observer reads afterwards.
pub fn read_auxv(pid: libc::pid_t) -> Option<Vec<u8>> {
    let bytes = std::fs::read(format!("/proc/{}/auxv", pid)).ok()?;
    if bytes.is_empty() || bytes.len() % 16 != 0 {
        return None;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_is_104_bytes() {
        assert_eq!(MM_MAP_LEN, 11 * 8 + 8 + 4 + 4);
    }

    #[test]
    fn encode_places_every_field() {
        let m = MmFields {
            start_code: 1,
            end_code: 2,
            start_data: 3,
            end_data: 4,
            start_brk: 5,
            brk: 6,
            start_stack: 7,
            arg_start: 8,
            arg_end: 9,
            env_start: 10,
            env_end: 11,
        };
        let b = encode(&m, 0, 0);
        assert_eq!(&b[56..64], &8u64.to_le_bytes());
        assert_eq!(&b[64..72], &9u64.to_le_bytes());
        assert_eq!(&b[88..96], &0u64.to_le_bytes());
        assert_eq!(&b[96..100], &0u32.to_le_bytes());
        assert_eq!(&b[100..104], &u32::MAX.to_le_bytes());
    }

    #[test]
    fn patched_execfn() {
        let mut v = vec![0u8; 48];
        v[0..8].copy_from_slice(&13u64.to_le_bytes()); // AT_ENTRY
        v[8..16].copy_from_slice(&0xdeadu64.to_le_bytes());
        v[16..24].copy_from_slice(&AT_EXECFN.to_le_bytes());
        v[24..32].copy_from_slice(&0xbeefu64.to_le_bytes());
        patch_execfn(&mut v, 0x1234);
        assert_eq!(&v[24..32], &0x1234u64.to_le_bytes());
        assert_eq!(&v[8..16], &0xdeadu64.to_le_bytes());
    }

    #[test]
    fn patched_execfn_absent() {
        let mut v = vec![0u8; 32];
        v[0..8].copy_from_slice(&13u64.to_le_bytes());
        v[16..24].copy_from_slice(&0u64.to_le_bytes());
        let before = v.clone();
        patch_execfn(&mut v, 0x1234);
        assert_eq!(v, before);
    }

    #[test]
    fn our_own_fields_are_readable() {
        let brk = unsafe { libc::sbrk(0) } as u64;
        let m = read_fields(0, brk).expect("own mm fields");
        assert!(m.arg_start < m.arg_end);
        assert!(m.env_start <= m.env_end);
        assert!(m.start_code < m.end_code);
    }
}
