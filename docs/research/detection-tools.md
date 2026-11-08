reproducible: no (source: the project sources named in the text, read 2026-11-03; none was built or run)

# What the rootkit and integrity checkers actually compare

Sources read in this session, each fetched through the read service on
2026-11-03. Every claim is tagged `[observed]` when the source is quoted or a
number copied from the tool's own text, and `[inferred]` when it follows from
that source without being run here.

None of these tools was built or run on this host. What follows is what their
source and documentation say they compare, not a measurement of their output.
That distinction matters for every row and is restated where it does.

---

## 1. The shape of the problem

Every tool in this list answers one of two questions:

* **Is there a pid the kernel will serve that this tool cannot see in some other
  view?** That is a consistency check between two kernel-supplied interfaces.
  It finds a kernel that hides an entry, not a process that renamed itself.
* **Does a file on disk differ from a recorded baseline?** That is an integrity
  check. It says nothing about a running process at all.

A process that rewrote its own `argv` in place, or relocated its arg span with
`PR_SET_MM_MAP`, does not hide its `/proc` entry. It changes the contents of
one file inside an entry that is still listed. So none of the `ps`-versus-`/proc`
comparisons in the first group fire on it, and none of the file baselines in the
second group has anything to compare. `[inferred]` from the measured behaviour
in `detection-measured.md`: the entry stays listed, `readdir("/proc")` returns
the pid, and `ps` prints a line.

The one signal in this whole family that does survive a rewrite is unchanged
`/proc/<pid>/exe` next to a changed `comm`. `[inferred]` from the measurements.

## 2. sandfly-processdecloak

Source: `sandfly-processdecloak.go` and `processutils/processutils.go` from
`github.com/sandflysecurity/sandfly-processdecloak`, master, version string
`1.0.6`, dated 2022-11-15 in the file header. `[observed]`

What it compares, from `IsPidHidden`:

1. It reads `/proc/<pid>/maps`. Maps that come back empty are threads, and are
   skipped.
2. For a pid whose `status` reports `PID == Tgid` and `PID > 0`, it calls
   `os.Lstat("/proc/<pid>")`. A failure there is reported as hidden, on the
   source comment: "An error means lstat failed and something is hidden. We
   already know the PID is there above because we could read the maps file. So
   why can't we stat it?"
3. If that passed, it reads the whole of `/proc` with `ioutil.ReadDir` and
   checks that the pid appears in the listing. A pid absent from the listing is
   reported as hidden. The source comment names the target: "Secondary check to
   find other LKM rootkit hiding like Reptile. This rootkit will obscure
   directory reads at the top level."
4. A pid flagged hidden is re-checked after a one second sleep
   (`ConstHiddenVerifyDelay = 1`) to rule out a pid that exited mid-check.

`[observed]`

The constants: `ConstMinPID = 1`, `ConstMaxPID = 4194304`, with the comment
"64bit linux is 2^22. This value is a limiter." `[observed]`

What it therefore proves: the `/proc` directory entry is invisible to
`readdir` or to `lstat` while the same pid is still reachable by direct path.
That is a kernel-side fault. What it cannot prove: anything about the contents
of `cmdline`. A rewrite leaves all four of those checks passing. `[inferred]`

The README states the tool "leverages a Process ID (PID) bruteforce tactic to
find processes that are not showing themselves in the standard */proc* directory
listing". `[observed]`

## 3. unhide

Source: `unhide-linux.c` from `github.com/YJesus/Unhide`, master, header string
`Unhide 20240509`, copyright 2010-2024. `[observed]`

The test names it accepts, printed by its own `usage()`: `brute`,
`checkbrute`, `checkkill`, `checknoprocps`, `checkopendir`, `checkproc`,
`checkquick`, `checkreaddir`, `checkreverse`, `checksysinfo`,
`checksysinfo2`, `checksysinfo3`, plus `checkgetprio`, `checkgetpgid`,
`checkgetsid`, `checkgetaffinity`, `checkgetparam`, `checkgetsched`,
`checkRRgetinterval`. `[observed]`

The mechanism behind the variants is the same in each: call some syscall that
requires the pid to exist, and see whether the pid appears in a listing.
`checkkill` calls `kill(pid, 0)`; `checkgetprio` calls `getpriority`;
`checkgetaffinity` calls `sched_getaffinity`. The source declares
`int brutesimplecheck` and a table of functions filled in at startup:

```c
tab_test[TST_KILL].func = checkkill;
tab_test[TST_NOPROCPS].func = checkallnoprocps;
tab_test[TST_BRUTE].func = brute;
```

`[observed]`

When it does report a hidden pid, `printbadpid` reads and prints
`/proc/<pid>/cmdline`, `/proc/<pid>/exe`, `/proc/<pid>/comm` and two fields
from `/proc/<pid>/environ` (`USER` and `PWD`). Those reads are for reporting,
not for the decision. `[observed]`

What it therefore proves: the same class as processdecloak, a pid reachable by
syscall but absent from a listing. A rewrite passes every mode. Note that the
`cmdline` it prints on a rewritten process would be the label, so the tool
would report the label as the name of a genuinely hidden process. `[inferred]`

## 4. lsrootkit

Source: `lsrootkit.c` from `github.com/therealdreg/lsrootkit`, master. The file
opens with its author's own warning, quoted: "the code is bullshit (is only a
beta prototype)". `[observed]`

Different mechanism from the other two. From the README, quoted: "a lot of
rootkits uses a MAGIC GID (a random GID generated) to hide processes and files.
This tool find rootkits bruteforcing all GIDs possible in the system." `[observed]`

The source implements this by forking a child that calls `setgid` for each
candidate gid in a loop, and a parent that watches whether the child disappears
at some gid. It does the same for signals: `kill(child_pid, actual_signal)` for
each signal number, with the parent checking whether the child is still
reachable. The detection strings in the source name what it reports: `type:
%s`, `chown hooked`, and `process hidding via: kill signal: %u`. `[observed]`

Its own README states the cost: root or `stat`, `chown`, `setgid` and `/proc`
access, and "each analysis-feature can take: <60 hours in a QUADCORE CPU
3100.000 MHz (NO SSD)". `[observed]`

What it therefore proves: that a hook intercepts a specific gid or signal
number. It is a targeted test of a specific rootkit trick, not a general
consistency check. Nothing about it applies to an unprivileged process that
rewrote its own memory. `[inferred]`

## 5. chkrootkit

Source: `chkproc.c` from chkrootkit 0.58b-5 as packaged by Debian,
`sources.debian.org/data/main/c/chkrootkit/0.58b-5/chkproc.c`. `[observed]`

Four comparisons, from the source:

* `/proc` reachable by direct path but the pid missing from `readdir("/proc")`:
  `printf("PID %d: hidden from readdir(3) but %s exists\n", i, buf);`
* `/proc` reachable but the pid missing from `ps` output:
  `printf("PID %d: hidden from ps(1) output but %s exists\n", i, buf);`
* `getpriority` answers for a pid that has no `/proc/<pid>`:
  `printf("PID %d: is hidden: it has getpriority(2) information but no %s entry\n", ...)`
* the reverse direction, a pid in `ps` output with no `/proc` entry.

`[observed]`

The `ps` command it parses on Linux is hardcoded:

```c
const char *ps_cmds[] = {
 "ps -edf",       // SUN
 "ps auxw",       // fallback
 "ps mauxw 2>&1 ",// "COM" - FreeBSD, etc
 "ps -eTo pid= -o spid=", // linux
 "ps -axo pid="   // NetBSD
};
```

`[observed]`

`MAX_PROCESSES` is 4194304 on x86_64 and 9999999 elsewhere. The file's own
changelog records that `getpriority` was added in 2006/01/05, credited to
"Yjesus(unhide) and Slider/Flimbo(skdet)". `[observed]`

What it therefore proves: a discrepancy between the `ps` table, the
`readdir("/proc")` listing and direct path access. All three read the same
kernel state by different routes. A rewrite is invisible to it. Its `ps` parse
would also happily read the label as the process name. `[inferred]`

## 6. rkhunter

Source: `files/rkhunter` from the `crunchsec/rkhunter` mirror, master, 20342
lines. `[observed]`

Two relevant tests.

`running_procs` runs `lsof` and greps its output against a list of known
suspicious filenames:

```sh
${LSOF_CMD} -wnlP +c 0 2>&1 | egrep -v ' (FIFO|V?DIR|IPv[46]) ' | sort | uniq >"${RKHLSOF_FILE}"
...
FOUNDFILES=`grep "/${FNAMEGREP}$" "${RKHLSOF_FILE}"`
```

and if `lsof` is absent it prints `SKIPPED` with `NOT_FOUND_CMD 'lsof'`.
`[observed]`

`hidden_procs` does not implement a check of its own. It finds an `unhide`
binary and runs each configured test name from the `UNHIDE_TESTS` option,
defaulting to `sys`:

```sh
UNHIDE_TESTS=`get_option space-list UNHIDE_TESTS` || exit 1
...
if [ -z "${UNHIDE_TESTS}" ]; then
        UNHIDE_TESTS="sys"
```

`[observed]`

So on a host without `unhide` installed, rkhunter's `hidden_procs` test prints
`NOT_FOUND_CMD 'unhide'` and skips. `[observed]` That is worth stating because
it means rkhunter's process-hiding coverage is unhide's coverage, through a
shell wrapper.

What `running_procs` proves: a file open by a running process matches a known
bad path. It is a signature check against `lsof`, not a consistency check. A
`/proc` rewrite has no bearing on it. `[inferred]`

## 7. AIDE

Source: the AIDE manual at `aide.github.io/doc/`, version 0.16.2. `[observed]`

What it stores, quoted: "The AIDE database stores various file attributes
including: file type, permissions, inode number, user, group, file size, mtime
and ctime, atime, growing size, number of links and link name. AIDE also
creates a cryptographic checksum or hash of each file." `[observed]`

And what it is for, quoted: "This first AIDE database is a snapshot of the
system in it's normal state and the yardstick by which all subsequent updates
and changes will be measured. [...] The database probably should not contain
information about files which change frequently like log files, mail spools,
proc filesystems, user's home directories, or temporary directories."
`[observed]`

The `proc` filesystem is named in that list as a thing not to snapshot. AIDE
therefore has no record of `/proc/<pid>/cmdline` by design. `[inferred]`

The manual is also honest about its own limit, quoted: "Unfortunately, AIDE can
not provide absolute sureness about change in files. Like any other system
file, AIDE's binary and/or database can also be altered." `[observed]`

What it therefore proves: a file on disk differs from a baseline taken before
an event, or a new file exists that was not in the baseline. It cannot say
anything about a running process, because it never looks at one. `[inferred]`

## 8. The Stühn, Hilgert and Lambertz DTRAP 2024 numbers

Paper: "The Hidden Threat: Analysis of Linux Rootkit Techniques and Limitations
of Current Detection Tools", Jakob Stühn, Jan-Niclas Hilgert, Martin Lambertz,
Digital Threats: Research and Practice, Volume 5, Issue 3, Article 28, pages
1-24, published 26 October 2024, DOI `10.1145/3688808`. `[observed]`
Bibliographic data also confirmed through `researchr.org/publication/StuhnHL24`,
which records `DTRAP, 5(3), 2024`. `[observed]`

The body text was readable at `dl.acm.org/doi/full/10.1145/3688808` through the
read service, which recorded an upstream status of 403 and served a stored
snapshot. So the prose and tables below were read, but not from a live origin
response. That is a real caveat and it is why every number here is marked as
read-from-snapshot rather than as fetched from ACM. `[observed]`

Table 3, "Detection Rates for the Different Scenarios", copied verbatim:

| Tool | S1 just installed, no prior data | S2 just installed, with prior data | S3 all features, no prior data | S4 all features, with prior data |
| --- | --- | --- | --- | --- |
| rkhunter | 0% | 33.3% | 4.8% | 38.1% |
| chkrootkit | 23.8% | 33.3% | 95.2% | 95.2% |
| Unhide | 4.8% | 4.8% | 71.4% | 71.4% |
| AIDE | 0% | 42.9% | 4.8% | 47.6% |
| OSSEC | 14.3% | 33.3% | 85.7% | 90.4% |
| ClamAV | 0% | 0% | 4.8% | 4.8% |
| LKRG | 28.6% | 57.1% | 52.8% | 57.1% |

`[observed]` read from the snapshot, not reproduced.

The four scenarios, quoted from section 5.2:

> S1: The rootkit has been installed, and no additional features have been
> enabled. The detector does not have access to previously collected data or
> knowledge.
>
> S2: The rootkit has been installed, and no additional features have been
> enabled. The detector does have access to previously collected data or
> knowledge.
>
> S3: All additional features available to the rootkit have been enabled. The
> detector does not have access to previously collected data or knowledge.
>
> S4: All additional features available to the rootkit have been enabled. The
> detector does have access to previously collected data or knowledge.

`[observed]`

The scale: 21 rootkits, of which 5 (Jynx2, adore-ng, Knark, SuckIT, Drovorub)
carry the footnote marker `b`, "Not tested. Results are based on theoretical
considerations". Evaluation on Ubuntu 22.04.2 LTS or 14.04.6 LTS in a VM, one
fresh VM per rootkit. `[observed]`

The paper's own conclusion, quoted: "Based on our evaluation, we conclude that
the current means to detect rootkits on Linux are insufficient. We evaluated
seven common tools to detect rootkits and found that none could detect all
rootkits we tested. Moreover, the detection rate was notably worse when there
was no knowledge of the system under investigation and the rootkits to detect."
`[observed]`

What the numbers mean for a `/proc` rewrite: nothing directly. The paper's
subject is rootkits that hide processes, files and modules from a kernel hook.
It measures whether a detector notices a hidden object. A process that renamed
itself is not hidden, and none of the four scenarios describes it. The
transferable result is the negative one: the two tools whose mechanism is a
consistency check between kernel views (chkrootkit at 95.2%, Unhide at 71.4%
with all features active) are the two that do best, and the two whose mechanism
is a static baseline (rkhunter, AIDE) are near zero without prior data. `[inferred]`

## 9. Summary

| tool | what it compares | fires on a /proc rewrite |
| --- | --- | --- |
| sandfly-processdecloak | `/proc` listing and `lstat` against direct path access | no |
| unhide | a syscall that needs the pid against a listing | no |
| lsrootkit | whether a gid or signal number makes a child vanish | no |
| chkrootkit | `ps` table, `readdir`, direct path, `getpriority` | no |
| rkhunter | `lsof` filenames, plus unhide's tests | no |
| AIDE | file attributes and hashes against a snapshot | no |

`[inferred]` throughout, from the mechanisms quoted above. The column means
"this tool's decision procedure has no input that a rewrite changes". It does
not mean the tool is useless; it means these tools answer a different question.

The one thing this table does not say, and should not be read as saying, is
that a rewrite is undetectable. Two of the interfaces it cannot touch are
measured in `detection-measured.md` (`exe` and `AT_EXECFN`) and the rest are in
`detection-residue.md`.
