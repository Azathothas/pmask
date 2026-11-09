//! Extra test-case subcommands for the option suites (`tests/options.sh`).
//!
//!   label-nul                    Mask::run and spawn must reject a NUL label
//!   debug-mask KEY VALUE         print `{:?}` of a Mask that holds KEY=VALUE
//!   as-uid UID CMD [ARGS...]     drop to UID (and gid UID), then exec CMD
//!   show-nnp                     print the NoNewPrivs line of /proc/self/status
//!   renamer                      rename itself with PR_SET_NAME, report comm
//!   evilrename [SECONDS]         rename itself with PR_SET_NAME to the
//!                                fixed name `evil-name`, print the
//!                                result and `comm`, then park
//!   count-proc                   count the numeric entries of /proc
//!   exe-id                       print the /proc/self/exe target and inode
//!   procviews PID                print the existence views of PID: raw
//!                                getdents64, libc readdir, stat and kill(0)
//!   getenv NAME                  print the value of NAME
//!   secretfd NAME [SECONDS]      print the inherited secret descriptor's
//!                                fd number, byte length, backing path and
//!                                a write attempt, then park SECONDS
//!   forkexec DIR PROG [ARGS...]  fork, chdir DIR in the child, exec PROG
//!                                (a real fork, so the first exec takes the
//!                                entry-swap path)

use std::ffi::CString;
use std::io::Write;

/// Run subcommand `cmd`; `None` when it is not one of ours.
pub fn dispatch(cmd: &str, rest: &[String]) -> Option<i32> {
    match cmd {
        "label-nul" => Some(label_nul()),
        "debug-mask" => Some(debug_mask(rest)),
        "as-uid" => Some(as_uid(rest)),
        "show-nnp" => Some(show_nnp()),
        "renamer" => Some(renamer()),
        "evilrename" => Some(evilrename(rest)),
        "count-proc" => Some(count_proc()),
        "exe-id" => Some(exe_id()),
        "procviews" => Some(procviews(rest)),
        "getenv" => Some(getenv(rest)),
        "secretfd" => Some(secretfd(rest)),
        "holdptrs" => Some(holdptrs(rest)),
        "holdscan" => Some(holdscan(rest)),
        "forkexec" => Some(forkexec(rest)),
        _ => None,
    }
}

/// A label with a NUL byte must fail at run and at spawn with
/// InvalidInput, before anything is forked.
fn label_nul() -> i32 {
    let no_args: [&str; 0] = [];
    let mut bad = 0;

    match pmask::Mask::new()
        .quiet()
        .label("a\0b")
        .run("true", &no_args)
    {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            println!("label-nul run: rejected ({})", e);
        }
        Err(e) => {
            println!("label-nul run: wrong error kind {:?} ({})", e.kind(), e);
            bad += 1;
        }
        Ok(_) => {
            println!("label-nul run: accepted");
            bad += 1;
        }
    }

    match pmask::Mask::new()
        .quiet()
        .label("a\0b")
        .spawn("true", &no_args)
    {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            println!("label-nul spawn: rejected ({})", e);
        }
        Err(e) => {
            println!("label-nul spawn: wrong error kind {:?} ({})", e.kind(), e);
            bad += 1;
        }
        Ok(child) => {
            drop(child);
            println!("label-nul spawn: accepted");
            bad += 1;
        }
    }
    bad
}

fn debug_mask(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: debug-mask KEY VALUE");
        return 2;
    }
    let mask = pmask::Mask::new()
        .label("dbg")
        .envs([(args[0].as_str(), args[1].as_str())])
        .env(format!("EXTRA_{}", args[0]), args[1].as_str());
    println!("{:?}", mask);
    0
}

fn as_uid(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: as-uid UID CMD [ARGS...]");
        return 2;
    }
    let uid: u32 = match args[0].parse() {
        Ok(u) => u,
        Err(_) => {
            eprintln!("as-uid: bad uid {}", args[0]);
            return 2;
        }
    };
    let cargs: Vec<CString> = match args[1..].iter().map(|a| CString::new(a.as_str())).collect() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("as-uid: NUL in argument");
            return 2;
        }
    };
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: plain credential syscalls, then exec with valid C strings.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) == -1
            || libc::setgid(uid as libc::gid_t) == -1
            || libc::setuid(uid as libc::uid_t) == -1
        {
            eprintln!(
                "as-uid: cannot drop privileges: {}",
                std::io::Error::last_os_error()
            );
            return 126;
        }
        libc::execvp(ptrs[0], ptrs.as_ptr());
    }
    eprintln!("as-uid: exec failed: {}", std::io::Error::last_os_error());
    127
}

fn show_nnp() -> i32 {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("show-nnp: {}", e);
            return 1;
        }
    };
    for line in status.lines() {
        if line.starts_with("NoNewPrivs:") {
            println!("{}", line);
            return 0;
        }
    }
    eprintln!("show-nnp: no NoNewPrivs line");
    1
}

fn own_comm() -> String {
    std::fs::read_to_string("/proc/self/comm")
        .map(|s| s.trim_end_matches('\n').to_string())
        .unwrap_or_default()
}

/// Settle, rename with PR_SET_NAME, wait, report comm, then park.
fn renamer() -> i32 {
    std::thread::sleep(std::time::Duration::from_millis(500));
    let name = b"other\0";
    // SAFETY: name is NUL terminated.
    unsafe {
        libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0);
    }
    std::thread::sleep(std::time::Duration::from_millis(700));
    println!("renamer-comm={}", own_comm());
    let _ = std::io::stdout().flush();
    loop {
        // SAFETY: pause(2) has no preconditions.
        unsafe {
            libc::pause();
        }
    }
}

/// Settle, rename itself to the fixed name `evil-name` with
/// `prctl(PR_SET_NAME)`, then report the syscall result, `comm` and the
/// `cmdline` it can read itself, and park for SECONDS (default 5).
///
/// The name is fixed and hostile on purpose: a suite reads the `comm` of
/// this pid from outside and asserts it is the label, so the case says
/// something about `/proc`, not about a string the payload printed.
fn evilrename(args: &[String]) -> i32 {
    let secs = args
        .first()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5);
    std::thread::sleep(std::time::Duration::from_millis(300));
    let name = b"evil-name\0";
    // SAFETY: name is NUL terminated.
    let rc = unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0) };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    println!("rename-rc={} errno={}", rc, if rc == 0 { 0 } else { errno });
    println!("comm={}", own_comm());
    let _ = std::io::stdout().flush();
    std::thread::sleep(std::time::Duration::from_secs(secs));
    0
}

fn count_proc() -> i32 {
    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(e) => {
            eprintln!("count-proc: {}", e);
            return 1;
        }
    };
    let mut n = 0;
    for ent in entries.flatten() {
        let name = ent.file_name();
        let s = name.to_string_lossy();
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            n += 1;
        }
    }
    println!("proc-count={}", n);
    0
}

/// Print the target of `/proc/self/exe` and the inode it resolves to, so
/// a suite can tell whether two execs ran from the same image.
fn exe_id() -> i32 {
    use std::os::unix::fs::MetadataExt;
    let target = std::fs::read_link("/proc/self/exe")
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "<unreadable>".to_string());
    let ino = std::fs::metadata("/proc/self/exe")
        .map(|m| m.ino())
        .unwrap_or(0);
    println!("exe={} ino={}", target, ino);
    0
}

/// procviews PID: the existence views a cross-view detector compares.
///
/// A detector of the SPiCa class compares TGID existence across channels:
/// the scheduler ledger (eBPF), the raw getdents64 listing of /proc, and
/// libc readdir.  The ledger needs eBPF; the other two, a direct stat of
/// /proc/PID and kill(pid, 0), are what a userspace observer can check.
/// One line, so a caller compares the views without walking a tree.
fn procviews(args: &[String]) -> i32 {
    let pid = match args.first().and_then(|s| s.parse::<i32>().ok()) {
        Some(p) if p > 0 => p,
        _ => {
            eprintln!("usage: procviews PID");
            return 2;
        }
    };
    let name = pid.to_string();
    let raw = getdents_has(&name);
    let cooked = std::fs::read_dir("/proc")
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy() == name.as_str())
        })
        .unwrap_or(false);
    let path = CString::new(format!("/proc/{}", pid)).expect("no NUL in a pid path");
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let stat_ok = unsafe { libc::stat(path.as_ptr(), &mut st) } == 0;
    let kill0 = unsafe { libc::kill(pid, 0) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    println!(
        "pid={} getdents64={} readdir={} stat={} kill0={}",
        pid,
        present(raw),
        present(cooked),
        present(stat_ok),
        present(kill0)
    );
    0
}

fn present(v: bool) -> &'static str {
    if v {
        "present"
    } else {
        "absent"
    }
}

/// Raw getdents64 over /proc: the channel an LD_PRELOAD hook cannot see.
fn getdents_has(name: &str) -> bool {
    let dir = CString::new("/proc").expect("no NUL in /proc");
    let fd = unsafe {
        libc::open(
            dir.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return false;
    }
    let mut buf = [0u8; 4096];
    let mut found = false;
    'outer: loop {
        let n = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        let mut off = 0usize;
        while off + 19 <= n as usize {
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen < 19 || off + reclen > n as usize {
                break;
            }
            let raw = &buf[off + 19..off + reclen];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            if &raw[..end] == name.as_bytes() {
                found = true;
                break 'outer;
            }
            off += reclen;
        }
    }
    unsafe { libc::close(fd) };
    found
}

fn getenv(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: getenv NAME");
        return 2;
    }
    match std::env::var_os(&args[0]) {
        Some(v) => {
            println!("{}={}", args[0], v.to_string_lossy());
            0
        }
        None => {
            println!("{} unset", args[0]);
            1
        }
    }
}

/// Report the secret descriptor that `--secret` delivered, as the exec'd
/// program sees it.  Prints one fact per line and never the value:
///
///   fd=N         the descriptor number carried by PMASK_SECRET_<NAME>
///   bytes=N      everything readable from it (run after the exec)
///   path=TGT     the /proc/self/<fd> link target, another process's view
///   write=...    result of one write attempt (sealing evidence)
///
/// Then parks SECONDS, so the suite can sweep /proc while the job runs.
fn secretfd(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: secretfd NAME [SECONDS]");
        return 2;
    }
    let name_upper: String = args[0]
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    let raw = match std::env::var(format!("PMASK_SECRET_{}", name_upper)) {
        Ok(v) => v,
        Err(_) => {
            println!("fd=none");
            return 1;
        }
    };
    let fd: libc::c_int = match raw.parse() {
        Ok(n) if n >= 0 => n,
        _ => {
            println!("fd-bad={}", raw);
            return 1;
        }
    };
    println!("fd={}", fd);

    // The read happens after the payload's own exec: this is how the
    // "descriptor survives exec" claim is checked.
    let mut buf = [0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            println!(
                "read-errno={}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            );
            break;
        }
        if n == 0 {
            break;
        }
        total += n as usize;
    }
    println!("bytes={}", total);

    match std::fs::read_link(format!("/proc/self/fd/{}", fd)) {
        Ok(p) => println!("path={}", p.to_string_lossy()),
        Err(e) => println!("path-errno={}", e.raw_os_error().unwrap_or(0)),
    }

    // F_SEAL_WRITE is set on every delivery memfd: the write must fail.
    let w = unsafe { libc::write(fd, b"x".as_ptr() as *const libc::c_void, 1) };
    if w < 0 {
        println!(
            "write-errno={}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        );
    } else {
        println!("write-ok={}", w);
    }

    if let Some(s) = args.get(1) {
        if let Ok(n) = s.parse::<u32>() {
            unsafe {
                libc::sleep(n);
            }
        }
    }
    0
}

fn holdptrs(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: holdptrs OUT");
        return 2;
    }
    let argsv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    use std::os::unix::ffi::OsStrExt;
    let mut text = String::new();
    text.push_str(&format!("argc={}\n", argsv.len()));
    for (i, a) in argsv.iter().enumerate() {
        let b = a.as_bytes();
        let p = b.as_ptr() as usize;
        text.push_str(&format!("arg{} addr={:#x} len={}\n", i, p, b.len()));
    }
    // /proc/self/stat fields 42..52, the arg/env span candidates live in
    // 46..49 (arg_start, arg_end, env_start, env_end); print them all so
    // the field indices are settled from inside.
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        if let Some(paren) = stat.rfind(')') {
            let after = &stat[paren + 1..];
            let fields: Vec<&str> = after.split_whitespace().collect();
            for n in 40..53.min(fields.len() + 3) {
                text.push_str(&format!(
                    "field{}={}\n",
                    n,
                    fields.get(n - 3).unwrap_or(&"?")
                ));
            }
        }
    }
    // For the last argument (the long one): print the offset of the first
    // NUL at or after byte 2048, and the byte at that offset's neighbours.
    if let Some(a) = argsv.last() {
        let b = a.as_bytes();
        let zero = b.iter().position(|&x| x == 0);
        text.push_str(&format!("lastlen={} lastzero={:?}\n", b.len(), zero));
    }
    let _ = std::fs::write(&args[0], text.as_bytes());
    loop {
        unsafe {
            libc::pause();
        }
    }
}

/// Diagnose a truncated-argv case: walk the raw memory below and above
/// the stat arg/env span, print the argv pointer words it finds and the
/// byte content around each of them.
fn holdscan(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: holdscan OUT");
        return 2;
    }
    use std::os::unix::ffi::OsStrExt;
    let argsv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let mut text = String::new();
    text.push_str(&format!("argc={}\n", argsv.len()));
    for (i, a) in argsv.iter().enumerate() {
        let b = a.as_bytes();
        text.push_str(&format!(
            "arg{} len={} first={:02x} last={:02x}\n",
            i,
            b.len(),
            b.first().copied().unwrap_or(0),
            b.last().copied().unwrap_or(0)
        ));
    }

    // stat span
    let (mut lo, mut hi) = (0u64, 0u64);
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        if let Some(paren) = stat.rfind(')') {
            let fields: Vec<&str> = stat[paren + 1..].split_whitespace().collect();
            for n in 42..52 {
                text.push_str(&format!(
                    "field{}={}\n",
                    n,
                    fields.get(n - 3).unwrap_or(&"?")
                ));
            }
            if let (Some(a0), Some(a1)) = (
                fields.get(45).and_then(|s| s.parse::<u64>().ok()),
                fields.get(46).and_then(|s| s.parse::<u64>().ok()),
            ) {
                lo = a0;
                hi = a1;
            }
        }
    }
    text.push_str(&format!("span={:#x}-{:#x}\n", lo, hi));

    // map rows around the span
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            let r = line.split_whitespace().next().unwrap_or("");
            let mut it = r.split('-');
            let l = it
                .next()
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .unwrap_or(0);
            let h = it
                .next()
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .unwrap_or(0);
            if l <= hi + 0x200000 && h >= lo.saturating_sub(0x200000) {
                text.push_str(&format!("map {}\n", line));
            }
        }
    }

    // raw reads via /proc/self/mem: walk the WHOLE [stack] mapping and
    // print every nonzero word found in the top 32 KiB, with targets for
    // pointer-shaped words.
    let mut text2 = String::new();
    let mut top = 0u64;
    let mut stack_lo = 0u64;
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            if !line.ends_with("[stack]") {
                continue;
            }
            if let Some(r) = line.split_whitespace().next() {
                let mut it = r.split('-');
                stack_lo = it
                    .next()
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .unwrap_or(0);
                top = it
                    .next()
                    .and_then(|s| u64::from_str_radix(&s[..s.len()], 16).ok())
                    .unwrap_or(0);
            }
        }
    }
    if top != 0 {
        if let Ok(mut f) = std::fs::File::open("/proc/self/mem") {
            use std::io::{Read, Seek, SeekFrom};
            let start = top.saturating_sub(0x8000);
            let len = (top - start) as usize;
            let mut buf = vec![0u8; len];
            let n = f
                .seek(SeekFrom::Start(start))
                .and_then(|_| f.read(&mut buf))
                .unwrap_or(usize::MAX);
            if n != usize::MAX && n >= 8 {
                let mut last = 0u8;
                for (w, _chunk) in buf
                    .chunks_exact(8)
                    .take(n / 8)
                    .enumerate()
                    .filter(|(_, c)| {
                        let v = u64::from_le_bytes((*c).try_into().unwrap());
                        v != 0
                    })
                {
                    let v = u64::from_le_bytes(buf[w * 8..w * 8 + 8].try_into().unwrap());
                    let tag = match v {
                        _ if v < 0x10000 => "num",
                        _ if v >= stack_lo && v < top => "ptr",
                        _ => "val",
                    };
                    if last == 0 {
                        text2.push('\n');
                    }
                    text2.push_str(&format!(
                        "  {}@{:#x} = {:#x}\n",
                        tag,
                        start + (w as u64) * 8,
                        v
                    ));
                    if tag == "ptr" {
                        let mut at = [0u8; 24];
                        if f.seek(SeekFrom::Start(v)).is_ok() && f.read(&mut at).is_ok() {
                            let s: String = at
                                .iter()
                                .take_while(|b| **b != 0)
                                .map(|b| {
                                    if b.is_ascii_graphic() || *b == b' ' {
                                        char::from(*b)
                                    } else {
                                        '.'
                                    }
                                })
                                .collect();
                            text2.push_str(&format!("    -> {:#x} {:?}\n", v, s));
                        }
                    }
                    let _ = &mut last;
                    last = 1;
                }
                if last == 0 {
                    text2.push_str("  (none nonzero)\n");
                }
            } else {
                text2.push_str("  mem read failed\n");
            }
        }
    } else {
        text2.push_str("  top=0\n");
    }
    text.push_str(&text2);
    let _ = std::fs::write(&args[0], text.as_bytes());
    loop {
        unsafe {
            libc::pause();
        }
    }
}

/// Fork, change the child's working directory, then exec PROG.  The
/// child is a real fork, not a vfork, so its first exec takes the
/// entry-swap path; the suite uses it to prove the ELF path is resolved
/// against the tracee's cwd.
fn forkexec(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: forkexec DIR PROG [ARGS...]");
        return 2;
    }
    let dir = match CString::new(args[0].as_str()) {
        Ok(c) => c,
        Err(_) => return 2,
    };
    let mut argv: Vec<CString> = Vec::new();
    for a in &args[1..] {
        match CString::new(a.as_str()) {
            Ok(c) => argv.push(c),
            Err(_) => return 2,
        }
    }
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: fork, chdir and execv in the child; the parent waits.
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            if libc::chdir(dir.as_ptr()) != 0 {
                libc::_exit(127);
            }
            libc::execv(argv[0].as_ptr(), ptrs.as_ptr());
            libc::_exit(127);
        }
        if pid < 0 {
            return 1;
        }
        let mut st = 0;
        if libc::waitpid(pid, &mut st, 0) != pid {
            return 1;
        }
        if libc::WIFEXITED(st) {
            libc::WEXITSTATUS(st)
        } else if libc::WIFSIGNALED(st) {
            128 + libc::WTERMSIG(st)
        } else {
            1
        }
    }
}
