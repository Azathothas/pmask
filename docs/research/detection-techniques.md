reproducible: no (source: the public pages and kernel sources named in the text, read 2026-11-03)

# Detection techniques for rewritten process arguments

What the public detection literature and the kernel say about a process whose
`argv` has been rewritten, and what a `/proc` consistency check can prove about
one. Host for every measurement here: Linux 6.12.113+deb13-amd64, Debian 13,
x86_64, uid 1000, gcc 14.2.0, procps-ng 4.0.4. Measurements live in
`detection-measured.md`; this file quotes and reasons.

Every claim is tagged `[observed]` or `[inferred]`. `[observed]` means the
primary page, source file or command output was read in this session and is
quoted or numbered from that output. `[inferred]` means the conclusion follows
from observed material but was not itself executed or measured here.

---

## 1. MITRE ATT&CK T1036.011

Read from `https://attack.mitre.org/techniques/T1036/011/` on 2026-11-03
through the fetch service. Page metadata: version 2.0, created 27 March 2025,
last modified 12 May 2026, tactic listed as TA0005, platform Linux.
`[observed]`

The technique description, quoted:

> Adversaries may modify a process's in-memory arguments to change its name in
> order to appear as a legitimate or benign process. On Linux, the operating
> system stores command-line arguments in the process's stack and passes them
> to the `main()` function as the `argv` array.

> During runtime, adversaries can erase the memory used by all command-line
> arguments for a process, overwriting each argument string with null bytes.
> This removes evidence of how the process was originally launched. They can
> then write a spoofed string into the memory region previously occupied by
> `argv[0]` to mimic a benign command, such as `cat resolv.conf`. The new
> command-line string is reflected in `/proc/<PID>/cmdline` and displayed by
> tools like `ps`.

`[observed]`

Three things the page states that matter to a tool claiming to prevent this:

1. No privilege is needed: "Since arguments are stored in user-space memory at
   launch, this modification can be performed without elevated privileges."
   `[observed]`
2. The observed effect is on `/proc/<PID>/cmdline` and on what `ps` prints. The
   page names no other observable. `[observed]`
3. The one software entry is BPFDoor (S1161), which "overwrites the `argv[0]`
   value used by the Linux `/proc` filesystem", choosing from "10 hardcoded
   names that resemble Linux system daemons, such as `/sbin/udevd -d`,
   `dbus-daemon --system`, `avahi-daemon: chroot helper`, `/sbin/auditd -n`,
   and `/usr/lib/systemd/systemd-journald`." `[observed]`

Point 3 is the part a label-based tool has to answer for. T1036.011 as written
is about a process choosing a name to look like a daemon. A tool that reduces
`argv` to a fixed operator-chosen label performs the same operation with a
different intent and a different name. The technique text does not distinguish
the two, because it describes the mechanism and not the motive. `[inferred]`

The page's reference list cites the Sandfly BPFDoor analysis and Microsoft's
XorDDoS writeup. Both were referenced but not read here; no claim in this file
depends on their content. `[observed]` that they are cited, nothing more.

## 2. MITRE DET0164

Read from `https://attack.mitre.org/detectionstrategies/DET0164` on the same
date. The page carries one analytic, AN0466, and no other content. `[observed]`

The analytic description, quoted in full:

> Detects adversary behavior where the command-line arguments of a running
> process are overwritten in memory to spoof the process name, typically
> replacing it with a benign or misleading string. The detection correlates
> unexpected null byte sequences, discrepancies between `/proc/<pid>/cmdline`
> and process ancestry, and suspicious memory writes shortly after process
> start.

`[observed]`

The page names two log sources, quoted:

| Data Component | Name | Channel |
| --- | --- | --- |
| Process Metadata (DC0034) | auditd:SYSCALL | execve, prctl, or ptrace activity affecting process memory or command-line arguments |
| Process Modification (DC0020) | ebpf:tracepoints | Runtime memory overwrite of argv[] memory region |

`[observed]`

And three mutable elements:

| Field | Description (quoted) |
| --- | --- |
| TimeWindow | Time threshold after process creation during which argv memory manipulation is expected to be rare; anomalies occurring outside this window may be more suspicious. |
| AllowedArgvMismatchPatterns | List of known legitimate processes where argv[0] mismatch is expected due to application logic or packaging quirks. |
| ParentExecutableTrustList | Trusted parent binaries allowed to spawn processes with altered command-line names. |

`[observed]`

### 2.1 What DET0164 actually detects, and what it misses for this class

The analytic is built from three signals. Test each against the technique the
kernel actually implements.

Signal 1, "unexpected null byte sequences". A zero-filled `argv` region is
exactly this: the measured naive rewrite produces a `cmdline` of 58 bytes with
49 NUL bytes and a longest NUL run of 49 (`detection-measured.md`, mode 1).
The same signal therefore fires on a naive implementation and does not fire on
one that truncates instead of zero-filling. Measured: when the label is placed
at `arg_start` and the byte at `arg_end - 1` is set to a non-zero byte,
`cmdline` is 10 bytes with one NUL and `ps` shows only `ci-runner` (mode 4 in
the measured file). One byte at the end of the span removes the entire first signal.
`[observed]` for the measurement, `[inferred]` for the generalisation that any
implementation can do this.

Signal 2, "discrepancies between `/proc/<pid>/cmdline` and process ancestry".
For a process launched through a wrapper this is real and cheap: the parent's
`exe` and the child's `exe` disagree with the child's `argv`. For a process
that is itself the labelled program, the discrepancy is between `argv` and
`exe`, which is the same observable as `comm` versus `exe`. Both survive any
userland rewrite, because `exe` is a kernel `dentry` and not process memory.
`[inferred]` from the kernel source read in section 4.3.

Signal 3, "suspicious memory writes shortly after process start". This needs
one of the two listed channels: auditd `SYSCALL` records or an eBPF tracepoint.
Both are kernel-side observations of the `write` itself. A rewrite performed by
the process on its own memory is a plain store instruction and emits no
`SYSCALL` record for audit to see, unless the rewrite goes through a syscall.
`[inferred]` from the auditd `SYSCALL` record shape: the record is generated at
syscall entry and exit, and a `memcpy` to the process's own stack is not a
syscall. The channel that does catch it is "suspicious memory writes", which is
where eBPF sits: an uprobe on `memcpy`, a kprobe on `access_remote_vm`, or a
raw tracepoint on page faults, all of which are kernel-side and unbypassable
from userland. `[inferred]`

The `MutableElements` field `AllowedArgvMismatchPatterns` is the honest part of
the analytic. It concedes that `argv[0]` mismatching `exe` has legitimate
causes. Chromium is the canonical one and is covered next.

The `ParentExecutableTrustList` element is worth one more sentence. A design
where every process in a tree is spawned by one long-lived parent makes that
parent the single entry that has to be trusted, and it makes the parent the
single point that has to be found. `[inferred]`

## 3. Chromium's process title code and the last-byte rule

Source read:
`https://raw.githubusercontent.com/chromium/chromium/main/base/process/set_process_title_linux.cc`,
fetched 2026-11-03. All quotes in this section are from that file, with the
line-leading `//` comment markers removed and `[...]` marking an elision;
nothing else is changed. `[observed]`

### 3.1 The layout assumption

The file's header comment states the memory model the kernel relies on:

> The Linux kernel sets up two locations in memory to pass arguments and
> environment variables to processes. First, there are two char* arrays stored
> one after another: argv and environ. [...] These arrays contain pointers to a
> second location in memory, where the strings themselves are stored one after
> another: first all the arguments, then the environment variables.

`[observed]`

and the kernel behaviour on read:

> When the kernel reads the command line arguments for a process, it looks at
> the range of memory that it initially used for the argument list. If the
> terminating '\0' character is still where it expects, nothing further is
> done. If it has been overwritten, the kernel will scan up to the size of a
> page looking for another.

`[observed]`

Measured here the layout holds: `env_start == arg_end` in every non-rewritten
process, and `[stack]` contains both (mode 0 in the measured file). The comment's
claim that the kernel "will scan up to the size of a page" is looser than
current source, which limits the scan to the environment region when it is
contiguous and to `arg_end` otherwise. Section 4.3 quotes the source.
`[observed]`

### 3.2 The trick itself

The operative code, quoted:

```c
const size_t argv_size =
    base::checked_cast<size_t>(g_argv_end - g_argv_start - 1);
if (!buggy_kernel && size < argv_size) {
  UNSAFE_TODO(g_argv_end[-1]) = '.';
}
```

with the comment above it:

> If the length of the new title is shorter than the original argv space, set
> the last byte of the space to an arbitrary non-null character to tell the
> kernel that setproctitle was called.

`[observed]`

The kernel side of that contract is commit
`d26d0cd97c88eb1a5704b42e41ab443406807810`, "/proc/<pid>/cmdline: add back the
setproctitle() special case", by Linus Torvalds, dated 13 July 2019. Its message
says the change "re-instates the original semantics of simply stopping at the
first NUL character when the original last NUL character is no longer there"
and that the overflow into the environment is allowed "only when it overflows
into the environment region if it is immediately adjacent." `[observed]`

The commit introduces `get_mm_proctitle`, which reads from `arg_start` for up to
one page (`if (pos >= PAGE_SIZE) return 0;`) and then takes `strnlen(page, got)`.
`[observed]` from the patch.

So the rule is: if the byte at `arg_end - 1` is non-zero, the kernel ignores
`arg_end` and serves a NUL-terminated string starting at `arg_start`, capped at
one page. If that byte is zero, the kernel serves exactly `[arg_start,
arg_end)`. Measured both ways on this host: mode 4 sets that byte to `.` and
`cmdline` collapses from 58 bytes to 10, mode 1 leaves it zero and `cmdline`
stays 58 bytes with a 49-byte NUL run. `[observed]`

Two consequences:

* The length of `cmdline` is not evidence about the length of `argv`. It is
  evidence about one byte at `arg_end - 1` and about `arg_end - arg_start`.
  `[inferred]`
* A `cmdline` shorter than the argv span with a clean single NUL is the
  signature of a deliberate setproctitle-style rewrite, the opposite of the
  DET0164 "null byte sequence" signal. `[inferred]`

### 3.3 The environment copy, and why it matters here

`setproctitle_init` moves the environment before rewriting, quoted:

> Move the environment out of the way. Note that we are moving the values, not
> the environment array itself.

and it verifies the layout first, returning early if any `argv[i]` is not
exactly contiguous with the previous string:

```c
for (size_t i = 0; UNSAFE_TODO(argv[i]); ++i) {
  if (p != UNSAFE_TODO(argv[i])) {
    return;
  }
  UNSAFE_TODO(p += strlen(p) + 1);
}
```

`[observed]`

That check is itself a detection surface: a process whose `arg_start`/`arg_end`
no longer describe a contiguous run of its own strings cannot use this path at
all, which is exactly the state a `PR_SET_MM_MAP` relocation produces. Measured:
after relocation `arg_start` points at an anonymous mapping and the original
strings are still in `[stack]`
(mode 2, and the same-process stack scan in `detection-residue.md`). `[observed]`

Chromium also carries the kernel bug window in code, quoted: "Linux 4.18--5.2
have a bug where we can never set a process title shorter than the initial
argv." `[observed]` The commit `2954152298c37804dab49d630aa959625b50cf64`, same
date, "[PATCH 1/2] /proc/<pid>/cmdline: remove all the special cases", is the
first half of that fix. `[observed]`

## 4. What a /proc consistency check can and cannot prove

This section is the part that decides whether a checker is worth running. It
separates the claims by whether a userland reader can settle them.

### 4.1 What it can prove

A userland reader with the same uid can prove, from files alone:

* **`cmdline` and `stat` disagree about the span.** `stat` fields 48 and 49
  give `arg_start`/`arg_end`. `cmdline` is served from that span. If `arg_end -
  arg_start` is larger than the bytes `cmdline` returns, the process is in the
  setproctitle path and the byte at `arg_end - 1` is non-zero. Measured: mode 2
  gives a span of 10 and a `cmdline` of 10, consistent; mode 4 gives a span of
  58 and a `cmdline` of 10, inconsistent. `[observed]`
  This rule does not fire on pmask's relocation mode: `PR_SET_MM_MAP` moves
  `arg_start` and `arg_end` onto the label block, so the span equals the
  `cmdline` length (see the table in section 5). A checker written on the
  rule alone therefore clears a masked process; it is useful only against
  the in-place modes. `[observed]`
* **The span is not in `[stack]`.** `[stack]` is where the kernel puts `argv`
  at exec. A span in an anonymous mapping, or in a mapping with no name, was
  placed there after exec. Measured: mode 2 reports `vma_after=[anonymous]`
  where mode 0 and mode 1 report `[stack]`. `[observed]`
* **`comm` and `exe` name different things.** `comm` is process memory,
  writable with `PR_SET_NAME`. `exe` is a kernel `dentry` from
  `mm->exe_file`. A process whose `comm` is `ci-runner` and whose `exe` is
  `/usr/bin/sleep` is reporting a name that is not its binary. Measured under
  pmask: `comm=ci-runner`, `exe=/usr/bin/sleep`. `[observed]`
* **`AT_EXECFN` names a different path from `argv[0]`.** `AT_EXECFN` comes
  from the auxiliary vector the kernel built at exec. It is not derived from
  `argv`. Measured: after both rewrites `AT_EXECFN` is still
  `/tmp/detharness`. `[observed]`
* **The env span is empty but the process is running normally.** `env_start ==
  env_end` means `environ` reads zero bytes. A process that behaves normally
  with no environment at all is unusual. Measured: mode 2 gives
  `environ.len=0`, and the process still runs and exits 0. `[observed]`

Each of those is a comparison between two kernel-supplied views, and none of
them requires privilege beyond the same uid. Together they are enough to say
"this process's published name is not its own and was set after exec".

### 4.2 What it cannot prove

* **It cannot recover the original `argv` from `/proc`.** After a
  `PR_SET_MM_MAP` relocation, `stat`, `cmdline`, `environ` and `auxv` agree
  with each other and all describe the label. No file still holds the original
  string. `[observed]`
* **It cannot tell a rewrite from a legitimate setproctitle caller.** The
  measured mode 4 result is indistinguishable, by `cmdline` shape, from
  Chromium, PostgreSQL, nginx and any other program calling `setproctitle`.
  `[inferred]`
* **It cannot see into another uid's memory.** The same-uid read that recovers
  the residue (row 9 of `detection-residue.md`) fails for a different uid: the
  `PTRACE_MODE_READ_FSCREDS` check on `/proc/<pid>/mem` refuses, and
  `PR_SET_DUMPABLE=0` refuses it for the same uid too. `[inferred]` from
  `proc(5)`; the cross-uid case was not exercised because only uid 1000 exists
  here.
* **It cannot prove the absence of a rewrite it did not model.** A checker built
  on the three DET0164 signals misses a rewrite that keeps the span on
  `[stack]`, keeps one NUL at the end, and leaves no null run, which is what a
  careful setproctitle caller produces. `[inferred]`

### 4.3 The kernel code that makes the distinction possible

Read from `https://raw.githubusercontent.com/torvalds/linux/master/fs/proc/base.c`
(fetched 2026-11-03, 4009 lines). The `cmdline` reader, quoted:

```c
	if (arg_start >= arg_end)
		return 0;

	/*
	 * We allow setproctitle() to overwrite the argument
	 * strings, and overflow past the original end. But
	 * only when it overflows into the environment area.
	 */
	if (env_start != arg_end || env_end < env_start)
		env_start = env_end = arg_end;
	len = env_end - arg_start;
```

then:

```c
	if (access_remote_vm(mm, arg_end-1, &c, 1, FOLL_ANON) == 1 && c)
		return get_mm_proctitle(mm, buf, count, pos, arg_start);
```

`[observed]`

`FOLL_ANON` is load-bearing twice, and both are measurable from outside. In the
last-byte probe it means the kernel reads `arg_end - 1` only if that resolves to
anonymous memory; a span in a file-backed mapping fails the probe and the kernel
falls through to the strict `[arg_start, arg_end)` path. In the copy loop it
means a non-anonymous span yields nothing. Measured: `prctl` accepts a
file-backed span and `stat` 48/49 report it, but `cmdline` reads zero bytes; an
anonymous `MAP_PRIVATE` block is readable, a `MAP_SHARED` anonymous block and a
memfd-backed block are not. `[observed]`

That gives a checker a third test that does not depend on the label: relocate
onto a non-anonymous mapping and the kernel reports nothing, a stronger
inconsistency than a wrong name.

## 5. Summary of what the signals buy

Numbers below are from `detection-measured.md`: `cmdline` 58 bytes and a
49-byte NUL run for mode 1, a 58-byte span against a 10-byte `cmdline` for
mode 4, a 10-byte span and an anonymous VMA for mode 2.

| signal | naive zero-fill | label at `arg_start` | PR_SET_MM relocation | pmask |
| --- | --- | --- | --- | --- |
| NUL run in `cmdline` (DET0164) | yes, 49 bytes | no, 1 | no, 1 | no |
| `cmdline` shorter than the `stat` span | no, 58 vs 58 | yes, 58 vs 10 | no, 10 vs 10 | no, 10 vs 10 |
| span not in `[stack]` | no | no | yes, `[anonymous]` | no |
| `environ` empty | no | no | yes, 0 bytes | yes, 0 bytes |
| `comm` versus `exe` | no | no | no | yes |
| `AT_EXECFN` versus `env_end` | no | no | not measured | yes, see below |

`[observed]` where a number or a VMA name is given.

The `comm` versus `exe` column is "no" for the three hand-written modes only
because the test harness never calls `PR_SET_NAME`; pmask does, and that is
why its column differs.

The `AT_EXECFN` row is a finding from `detection-residue.md` row 10 and has
moved since that row was written: on this release the presentation block
places a second label copy at `env_end` and points `AT_EXECFN` at it, so
`/proc/<pid>/auxv` serves the label and keeps `AT_EXECFN == env_end`, the
relation a plain exec has. The earlier `AT_EXECFN == arg_start` observation is
stale. A `--keep-env` run moves `AT_EXECFN` off `env_end`; the offset
`1 + label.len() + argc` still locates the second copy.

The honest reading: no single signal covers every variant. The signals that
cover pmask are an empty `environ`, `comm` disagreeing with `exe`, and a
nonzero `TracerPid` whose tracer is a thread of the parent. The first also
fires on a legitimate process started with an empty environment; the third
fires on every debugger unless the tracer's identity is checked. The
`cmdline`-shorter-than-the-span signal does not fire on pmask at all: the
`PR_SET_MM_MAP` relocation moves `arg_start` and `arg_end` onto the label, so
the span equals the `cmdline` length. `[observed]` for the span, `[inferred]`
for the generalisation.
