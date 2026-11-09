reproducible: yes (the harness in the rerun section of this file)

# Measured /proc observables across three rewrite strategies

Every number here was produced on this host in this session; nothing is quoted
from a paper or a blog. Host: Linux 6.12.113+deb13-amd64, Debian 13, x86_64,
gcc 14.2.0, procps-ng 4.0.4, uid 1000 gid 1000, CapEff `0000000000000000`,
`kernel.yama.ptrace_scope = 0`, `/proc` with no `hidepid`, in an LXC container
(`/proc/self/cgroup` is `0::/.lxc`), page size 4096. `/usr/bin/db-w` does not
exist here, so `ps -o args=` from procps-ng 4.0.4 is the outside observer
throughout. `[observed]`

---

## 1. The harness

Source in section 6. One process reporting on itself: `stat` fields 48 to 51,
the length and NUL statistics of `/proc/self/cmdline`, whether the canary
`CANARY-7f3c9a1e` is still in `/proc/self/environ`, `TracerPid` from
`/proc/self/status`, `AT_EXECFN` from `getauxval`, and the VMA holding
`arg_start`. It then sleeps so an outside reader can open the same files.

| mode | rewrite |
| --- | --- |
| 0 | none |
| 1 | zero-fill `[arg_start, arg_end)`, label at `arg_start`, last byte of the span left at zero |
| 2 | `prctl(PR_SET_MM, PR_SET_MM_MAP)` moving the arg and env spans to an anonymous `mmap` block |
| 4 | same as 1 plus a non-zero byte (`.`) at `arg_end - 1`, the Chromium rule |

## 2. The measured table

Every row from `DETHARNESS_CANARY=CANARY-7f3c9a1e /tmp/deth MODE 3 --env prod
--token ghp_SECRETVALUE_notreal`, with the observer reading `/proc/<pid>/*` and
`ps -o args=` one second in.

| observable | mode 0 plain | mode 1 zero-fill + label | mode 2 PR_SET_MM_MAP | mode 4 last byte `.` |
| --- | --- | --- | --- | --- |
| `stat` 48 `arg_start` | stack addr | same address | anon mmap addr | same address |
| `stat` 49 `arg_end` | +58 | +58 | +10 | +58 |
| `stat` 50 `env_start` | == arg_end | == arg_end | == arg_end | == arg_end |
| `stat` 51 `env_end` | arg_end + 2269 | arg_end + 2269 | == arg_end | arg_end + 2269 |
| `cmdline` bytes | 58 | 58 | 10 | 10 |
| `cmdline` NUL count | 7 | 49 | 1 | 1 |
| `cmdline` longest NUL run | 1 | 49 | 1 | 1 |
| `cmdline` text | full real argv | `ci-runner` + 49 NULs | `ci-runner` | `ci-runner` |
| `environ` bytes | 2269 | 2269 | 0 | 2269 |
| canary in `environ` | yes | yes | **no** | yes |
| VMA of `arg_start` | `[stack]` | `[stack]` | `[anonymous]` | `[stack]` |
| `TracerPid` | 0 | 0 | 0 | 0 |
| `AT_EXECFN` | `/tmp/deth3` | `/tmp/deth3` | `/tmp/deth3` | `/tmp/deth3` |
| `comm` | `deth3` | `deth3` | `deth3` | `deth3` |
| `exe` | `/tmp/deth3` | `/tmp/deth3` | `/tmp/deth3` | `/tmp/deth3` |
| `ps -o args=` | full real argv | `ci-runner` | `ci-runner` | `ci-runner` |
| exit code | 0 | 0 | 0 | 0 |

`[observed]` for every cell. Raw output for mode 2, the one that differs most:

```
after  stat48=0x7f384a7ce000 stat49=0x7f384a7ce00a span=10 stat50=0x7f384a7ce00a stat51=0x7f384a7ce00a
cmdline len=10 nul_count=1 longest_run=1 text=ci-runner.
environ len=0 nul_count=0 longest_run=0 canary_before=1 canary_after=0
TracerPid=0 AT_EXECFN=/tmp/deth3
vma_before=[stack] vma_after=[anonymous]
comm_before=deth3 comm_after=deth3 exe=/tmp/deth3
```

Three facts carry the argument: `arg_start` moved to an address with no name in
`maps`; `environ` went from 2269 bytes to 0, so the canary is gone from the
published view; and `AT_EXECFN`, `exe` and `comm` are unchanged.

### 2.1 The last-byte effect, isolated

Modes 1 and 4 differ by exactly one byte, at `arg_end - 1`.

| | mode 1, byte `0x00` | mode 4, byte `.` |
| --- | --- | --- |
| `stat` 48/49 span | 58 | 58 |
| `cmdline` bytes | 58 | 10 |
| `cmdline` NUL count | 49 | 1 |
| `ps -o args=` | `ci-runner` | `ci-runner` |

`[observed]` One byte decides whether the kernel serves `[arg_start, arg_end)`
or a NUL-terminated string from `arg_start`. Both render identically in `ps`,
but `cmdline` length versus `stat` span separates them exactly.

### 2.2 What `ps` shows

`ps` prints `cmdline` with NULs as spaces and trims. On a mode 2 process:

```
ps -o args=  |  -o pid,cmd  |  ps -ww -o args=  |  top COMMAND  ->  ci-runner
ps -o comm=,args=  |  ps -o pid,comm,args -L    ->  deth3  ci-runner
ps -o pid,ppid,user,args                        ->  71204 71122 agent  ci-runner
```

`[observed]`. Every format asking for `comm` keeps the real name, because the
harness never calls `PR_SET_NAME`.

### 2.3 What pmask produces

`target/release/pmask` as uid 1000:

```
pmask --label ci-runner /bin/sleep 8
```

Measured on the `sleep` child:

| observable | value |
| --- | --- |
| `ps -o comm,args` | `ci-runner       ci-runner` |
| `stat` 48/49 span | 10 |
| `cmdline` bytes | 10 (`ci-runner` then NUL) |
| `environ` bytes | 0 |
| byte at `arg_end - 1` | `0x00` |
| `comm` | `ci-runner` |
| `exe` | `/usr/bin/sleep` |
| `AT_EXECFN` | in `auxv`, at the second label copy, equal to `env_end` |
| VMA of `arg_start` | `[stack]` |
| `/bin/sleep` string still in `[stack]` | yes |

`[observed]`

That is the relocation shape plus `comm` set. `PR_SET_MM_MAP` moved
`arg_start`/`arg_end` onto a 10-byte block and collapsed the environment
window, so the span equals the `cmdline` length and `environ` reads 0 bytes.
The block's page still reads `[stack]` because the relocation moves
`start_stack` with it, and the original `/bin/sleep` string is still in the
payload's stack memory. `comm` versus `exe` is the observable that survives.

Re-measured for this document on Debian 13, kernel `6.12.113+deb13-amd64`,
uid 1000, `CapEff 0000000000000000`, with
`./target/release/pmask -q -l ci-runner -- /bin/sleep 8` and the child read
0.5 s in:

```
cmdline_bytes=10 environ_bytes=0 stat_span=10 comm=ci-runner
auxv AT_EXECFN=env_end (delta 0), execfn-arg_start=12 for argc=2
maps: arg_start and AT_EXECFN in a [stack] mapping
/proc/<pid>/mem: b"/bin/sleep\0" found in [stack] and in an anon mapping
```

The earlier table recorded `environ` as 37 bytes, all zero. That was a build
that zeroed the environment in place instead of collapsing the window; the
current build reads 0 bytes, and the row above is the current measurement.
The span and `cmdline` values are 10, not 11: the label is 9 bytes, so
`arg_end = base + 9 + 1` and `cmdline` is the label plus one NUL. The
measurement commands are in `evidence/docs2/measured-shape.log`,
`measured-auxv.log` and `measured-stack-string.log`.

## 3. The relocation recipe and where it fails

The recipe that works here, verified `rc=0`:

```c
struct prctl_mm_map m;
memset(&m, 0, sizeof m);
m.start_code = f[26]; m.end_code = f[27];        /* stat 26, 27 */
m.start_data = f[45]; m.end_data = f[46];        /* stat 45, 46 */
m.start_brk  = f[47]; m.brk = (unsigned long)sbrk(0);
m.start_stack = f[28];
m.arg_start = blk; m.arg_end = blk + strlen(label) + 1;
m.env_start = m.arg_end; m.env_end = m.arg_end;
m.auxv = NULL; m.auxv_size = 0; m.exe_fd = -1;
prctl(PR_SET_MM, PR_SET_MM_MAP, &m, sizeof m, 0);
```

Negative results, one field changed per call, each in a fresh process
(`/tmp/negprobe.c`, uid 1000, CapEff 0):

| change | rc | errno |
| --- | --- | --- |
| `start_code = 0` | -1 | 22 EINVAL |
| `start_data = 0` | -1 | 22 EINVAL |
| `env_start = env_end = 0` | -1 | 22 EINVAL |
| `arg_start = arg_end = 0` | -1 | 22 EINVAL |
| `auxv = NULL, auxv_size = 16` | -1 | 22 EINVAL |
| `start_stack = 0` | -1 | 22 EINVAL |
| `exe_fd` = fd from `open("/proc/self/exe", O_RDONLY)` | -1 | 22 EINVAL |
| `arg_start == arg_end` at the block | 0 | 0 |
| `env_start = blk, env_end = blk + 8` (env span inside arg block) | 0 | 0 |
| recipe as given | 0 | 0 |

`[observed]`

`exe_fd` needs a file opened with `FMODE_EXEC`; an `O_RDONLY` open of the
`/proc/self/exe` symlink fails that check and returns EINVAL, not EPERM.
`start_stack = 0` fails because the kernel rejects an empty stack range. One
self-inflicted error, recorded because it misleads: leaving `m.exe_fd` at zero
gives `EPERM`, errno 1, because zero is a valid fd (stdin) and the kernel tried
to use stdin as the executable. `EPERM` here does not always mean permissions.

### 3.1 Which mappings can host the relocated span

`/tmp/fol3.c`, uid 1000. Each row calls `prctl`, then reads `cmdline`.

| mapping kind | `prctl` rc | `cmdline` bytes |
| --- | --- | --- |
| `MAP_PRIVATE \| MAP_ANONYMOUS` | 0 | 13, `anonA-runner` |
| `MAP_PRIVATE \| MAP_ANONYMOUS`, `mprotect` to `PROT_READ` | 0 | 10, `ro-runner` |
| `MAP_SHARED \| MAP_ANONYMOUS` | 0 | 0 |
| `MAP_SHARED`, memfd-backed | 0 | 0 |
| `MAP_SHARED`, file-backed | 0 | 0 |
| `MAP_PRIVATE`, file-backed | 0 | 0 |

`[observed]`

The split is the `FOLL_ANON` flag in `get_mm_cmdline`: the kernel accepts any
span and refuses to read a non-anonymous one. A process whose `stat` 48/49 point
outside anonymous memory, or whose `cmdline` is empty while `arg_start <
arg_end`, is in a state ordinary programs do not reach.

### 3.2 Unmapping the block afterwards

Relocate to an anonymous block, confirm `cmdline` reads `gone-runne`, `munmap`
it, read again: 0 bytes. `[observed]` The `prctl` record outlives the mapping,
leaving `arg_start` pointing at an address with no VMA.

## 4. The environ canary

| mode | `environ` bytes | canary present |
| --- | --- | --- |
| 0 | 2269 | yes |
| 1 | 2269 | yes |
| 2 | 0 | no |
| 4 | 2269 | yes |

`[observed]`

Mode 1 zero-fills only `[arg_start, arg_end)`, which ends exactly where
`env_start` begins, so the environment is untouched. The harness confirms
`arg_env_contiguous=1` and `env0_in_argv_span=0`: the first environment string
does not start inside the argv span. That is the general case, not an artefact.
Truncating `argv` and leaving `environ` alone is the cheaper implementation and
leaves the whole environment readable.

## 5. What the measurements do not establish

* One kernel, uid, libc, page size and architecture. Numbers differ on a kernel
  before 5.3, where the setproctitle special case is absent, and on any host
  with `hidepid` set. `[inferred]`
* `TracerPid` was 0 in every run; nothing here measures a traced process.
* The same-uid memory read that recovers the original strings is in
  `detection-residue.md`, not here.
* `environ` readability depends on `PTRACE_MODE_READ_FSCREDS`. Only uid 1000 was
  available, so the cross-uid refusal is inferred from `proc(5)`, not measured.
* The 49-NUL `cmdline` was rendered by procps-ng 4.0.4; other `ps` builds may
  differ.

## 6. Rerun

```sh
gcc -O0 -o /tmp/deth /tmp/deth.c && gcc -O0 -o /tmp/negprobe /tmp/negprobe.c
export DETHARNESS_CANARY=CANARY-7f3c9a1e
for m in 0 1 2 4; do
  rm -f /tmp/detharness.*.out
  /tmp/deth $m 3 --env prod --token ghp_SECRETVALUE_notreal &
  p=$!; sleep 1
  printf 'mode %s ps=[%s] cmdline=%s environ=%s\n' "$m" \
    "$(ps -o args= -p $p)" "$(wc -c </proc/$p/cmdline)" "$(wc -c </proc/$p/environ)"
  cat /tmp/detharness.$p.out
  wait $p
done
```

The harness, complete and self-contained. It writes only
`/tmp/detharness.<pid>.out` and reads only its own procfs entries.

```c
/* detharness.c: the harness that produced the table above.
 * gcc -O0 -o /tmp/deth /tmp/deth.c ; /tmp/deth MODE HOLD [ARGS...]
 * 0 plain | 1 zero-fill+label, last byte zero | 2 PR_SET_MM_MAP | 4 '.' at end
 * Writes /tmp/detharness.<pid>.out. uid 1000, no privileges. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <linux/prctl.h>

static unsigned long F[64];
static const char CANARY[] = "CANARY-7f3c9a1e", LABEL[] = "ci-runner";

/* Field 2 (comm) is parenthesised; parse after the last ')'. */
static void statf(void)
{
    char b[4096]; memset(F, 0, sizeof F);
    int fd = open("/proc/self/stat", O_RDONLY);
    if (fd < 0) return;
    ssize_t n = read(fd, b, sizeof b - 1); close(fd);
    if (n <= 0) return;
    b[n] = 0;
    char *p = strrchr(b, ')'); if (!p) return;
    unsigned long k = 3; char *t = strtok(p + 1, " \n");
    while (t && k < 64) { F[k++] = strtoul(t, NULL, 10); t = strtok(NULL, " \n"); }
}
static size_t rd(const char *p, unsigned char *d, size_t c)
{
    int fd = open(p, O_RDONLY); ssize_t r = -1;
    if (fd >= 0) { r = read(fd, d, c); close(fd); }
    return r > 0 ? (size_t)r : 0;
}
static void nuls(const unsigned char *b, size_t n, size_t *cnt, size_t *run)
{
    size_t c = 0; *cnt = *run = 0;
    for (size_t i = 0; i < n; i++)
        if (b[i]) c = 0; else { (*cnt)++; if (++c > *run) *run = c; }
}
static void vma(unsigned long a, char *o, size_t cap)
{
    snprintf(o, cap, "none");
    FILE *f = fopen("/proc/self/maps", "r"); if (!f) return;
    char l[2048];
    while (fgets(l, sizeof l, f)) {
        unsigned long lo, hi; char pm[8] = {0};
        if (sscanf(l, "%lx-%lx %7s", &lo, &hi, pm) != 3) continue;
        if (a < lo || a >= hi) continue;
        char *q = l; int c = 0;
        while (*q && c < 5) { while (*q == ' ') q++; while (*q && *q != ' ') q++; c++; }
        while (*q == ' ') q++;
        char *nl = strchr(q, '\n'); if (nl) *nl = 0;
        snprintf(o, cap, "%s", *q ? q : "[anonymous]");
        break;
    }
    fclose(f);
}
static unsigned long statusf(const char *k)
{
    FILE *f = fopen("/proc/self/status", "r"); if (!f) return 0;
    char l[512]; size_t kl = strlen(k); unsigned long v = 0;
    while (fgets(l, sizeof l, f))
        if (!strncmp(l, k, kl) && l[kl] == ':') v = strtoul(l + kl + 1, NULL, 10);
    fclose(f); return v;
}
static int relocate(char *err, size_t cap)
{
    size_t ll = sizeof LABEL;                     /* includes the NUL */
    unsigned long blk = (unsigned long)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (blk == (unsigned long)MAP_FAILED) { snprintf(err, cap, "mmap %s", strerror(errno)); return -1; }
    memcpy((void *)blk, LABEL, ll);
    struct prctl_mm_map m; memset(&m, 0, sizeof m);
    m.start_code = F[26]; m.end_code = F[27];     /* stat 26, 27 */
    m.start_data = F[45]; m.end_data = F[46];     /* stat 45, 46 */
    m.start_brk = F[47];  m.brk = (unsigned long)sbrk(0);
    m.start_stack = F[28];
    m.arg_start = blk; m.arg_end = blk + ll;
    m.env_start = m.arg_end; m.env_end = m.arg_end;
    m.auxv = NULL; m.auxv_size = 0; m.exe_fd = -1;   /* -1, never 0 */
    if (prctl(PR_SET_MM, PR_SET_MM_MAP, &m, sizeof m, 0)) {
        snprintf(err, cap, "prctl errno=%d %s", errno, strerror(errno)); return -1;
    }
    return 0;
}
int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s MODE HOLD [ARGS]\n", argv[0]); return 2; }
    int mode = atoi(argv[1]), hold = atoi(argv[2]), ok = 1;
    char err[512] = "", vb[512], va[512], xf[512], lk[512];
    char cbn[64] = {0}, ca[64] = {0};
    unsigned char eb[131072], cmd[16384], e2[131072];
    char *e0 = environ ? environ[0] : NULL;

    statf();
    unsigned long a0 = F[48], a1 = F[49], s0 = F[50], s1 = F[51];
    vma(a0, vb, sizeof vb);
    const char *ef = (const char *)getauxval(AT_EXECFN);
    snprintf(xf, sizeof xf, "%s", ef ? ef : "(null)");
    size_t ncb = rd("/proc/self/comm", (unsigned char *)cbn, 63);
    if (ncb && cbn[ncb - 1] == '\n') cbn[ncb - 1] = 0;
    unsigned long tracer = statusf("TracerPid");
    size_t el = rd("/proc/self/environ", eb, sizeof eb);
    int canary1 = el && memmem(eb, el, CANARY, sizeof CANARY - 1);

    if (mode == 1 || mode == 4) {
        if (a0 < a1) {
            unsigned long sp = a1 - a0; memset((void *)a0, 0, sp);
            size_t n = sizeof LABEL - 1; if (n > sp - 1) n = sp - 1;
            memcpy((void *)a0, LABEL, n);
            if (mode == 4) ((unsigned char *)a0)[sp - 1] = '.';
        }
    } else if (mode == 2 && relocate(err, sizeof err)) ok = 0;

    statf();
    size_t cl = rd("/proc/self/cmdline", cmd, sizeof cmd), cn, cr;
    size_t e2l = rd("/proc/self/environ", e2, sizeof e2), en, er;
    nuls(cmd, cl, &cn, &cr); nuls(e2, e2l, &en, &er);
    int canary2 = e2l && memmem(e2, e2l, CANARY, sizeof CANARY - 1);
    size_t k = rd("/proc/self/comm", (unsigned char *)ca, 63);
    if (k && ca[k - 1] == '\n') ca[k - 1] = 0;
    ssize_t lr = readlink("/proc/self/exe", lk, sizeof lk - 1);
    lk[lr > 0 ? (size_t)lr : 0] = 0;
    vma(F[48], va, sizeof va);

    char out[128]; snprintf(out, sizeof out, "/tmp/detharness.%d.out", (int)getpid());
    FILE *o = fopen(out, "w"); if (!o) { perror("fopen"); return 1; }
    fprintf(o, "mode=%d pid=%d uid=%d mode_ok=%d err=%s\n",
            mode, (int)getpid(), (int)getuid(), ok, err);
    fprintf(o, "before stat48=%#lx stat49=%#lx span=%lu stat50=%#lx stat51=%#lx env=%lu\n",
            a0, a1, a1 - a0, s0, s1, s1 - s0);
    fprintf(o, "before arg_env_contiguous=%d env0_in_argv_span=%d\n",
            (s0 == a1 && s1 > s0) ? 1 : 0,
            (e0 && (unsigned long)e0 >= a0 && (unsigned long)e0 < a1) ? 1 : 0);
    fprintf(o, "after  stat48=%#lx stat49=%#lx span=%lu stat50=%#lx stat51=%#lx\n",
            F[48], F[49], F[49] > F[48] ? F[49] - F[48] : 0, F[50], F[51]);
    fprintf(o, "cmdline len=%zu nul_count=%zu longest_run=%zu text=", cl, cn, cr);
    for (size_t i = 0; i < (cl < 96 ? cl : 96); i++)
        fputc((cmd[i] >= 32 && cmd[i] < 127) ? cmd[i] : '.', o);
    fprintf(o, "\nenviron len=%zu nul_count=%zu longest_run=%zu canary_before=%d canary_after=%d\n",
            e2l, en, er, canary1, canary2);
    fprintf(o, "TracerPid=%lu AT_EXECFN=%s\n", tracer, xf);
    fprintf(o, "vma_before=%s vma_after=%s\n", vb, va);
    fprintf(o, "comm_before=%s comm_after=%s exe=%s\n", cbn, ca, lk);
    fclose(o);
    printf("%s\n", out);
    for (int i = 0; i < hold; i++) sleep(1);
    return 0;
}
```

## Self-mask window (C-024)

Measured 2026-11-07 with `sh docs/research/selfmask-window/run.sh` on
Linux 6.12.113+deb13-amd64, x86_64, uid 1000. The harness runs a C payload
and a Python payload that call `prctl(PR_SET_NAME, "smask")` at their first
user instruction; the observer samples `/proc/<pid>/comm` until it reads
the mask. The window is the time from the shell's fork to the first sample
that saw the mask, so it includes the exec and the observer's sampling
resolution.

| payload | outer window | payload's own time to the mask |
|---|---|---|
| C (`selfmask.c`) | 2.7 ms | 4 us |
| Python (`selfmask.py`) | 18.3 ms | 46 us |

The C payload masks itself 4 us after `main`; the outer 2.7 ms is the
shell's fork, the exec and the first sample, and it is not a clean
exec-to-mask measure. The Python window is the interpreter startup, 18.3
ms, which the self-mask cannot avoid because the first Python statement
runs only after the interpreter has started. The survey's figures, about
0.2 ms for C and 27 ms for Python, are the same shape; this harness
measures 4 us and 18.3 ms on this host. `[observed]`
