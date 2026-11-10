//! Demonstrate that redacted processes still see their real environment.
//!
//! Needs ptrace: `/proc/<pid>/environ` can only be redacted by a ptrace
//! supervisor.  On a host that refuses ptrace this example dies with
//! `PermissionDenied`; `pmask probe` says so, and `vm/run.sh` gives a host
//! that allows it.
//!
//! The child prints an environment value that is invisible in
//! /proc/<pid>/environ while it runs (check with:
//! `tr '\0' '\n' < /proc/<pid>/environ` while the example sleeps).
//!
//! This example needs a host where ptrace is permitted: `kernel.yama.ptrace_scope`
//! is 0 and no seccomp filter bans ptrace. On a host that bans it the example
//! fails with `PermissionDenied`. Use the micro-VM gate (`sh vm/run.sh`) there;
//! it boots a kernel where ptrace works.
//!
//! ```sh
//! cargo run --example env_redaction
//! ```

use std::io::Write;

fn main() -> std::io::Result<()> {
    let script = r#"
echo "child sees SECRET=$SECRET"
sleep 0.4
"#;

    let mask = pmask::Mask::new()
        .label("example-worker")
        .envs([("SECRET", "hushhush"), ("PATH", "/usr/bin:/bin")]);

    let child = mask.spawn("/bin/sh", &["-c", script])?;

    // While the child sleeps, its /proc environ carries no trace of the
    // secret.  Observe it yourself:
    //   tr '\0' '\n' < /proc/$(pgrep -f example-worker)/environ
    std::thread::sleep(std::time::Duration::from_millis(200));
    let mut out = std::io::stdout().lock();
    writeln!(out, "supervisor: child pid {}", child.id())?;
    writeln!(
        out,
        "supervisor: scan /proc/{}/environ for 'hushhush'",
        child.id()
    )?;

    let st = child.wait()?;
    writeln!(out, "supervisor: child exit code {}", st.code)?;
    Ok(())
}
