#!/bin/sh
# ============================================================================
# The launch window and the statistical side channels of supervision
# (issue 48), measured on the host that runs this script.
#
#   sh measurements/launch-window.sh
#
# Three measurements, each with its own control:
#
#   1. spawn latency
#        N sequential launches of /bin/true, plain, under `env -i`, and
#        under pmask.  Mean, median and p95 of the whole invocation, the
#        masked/plain ratio, and the per-round spread so a noisy host is
#        visible as UNSTABLE rather than reported as a point estimate.
#
#   2. launch window
#        A C sampler reads /proc/<pid>/comm in a tight loop (no fork, no
#        sleep) from the moment the payload pid appears, and records every
#        distinct comm with the nanosecond it was first seen.  Measured for
#        a script payload (the kernel execs the interpreter, so the comm
#        changes twice faster than a shell can observe) and for an ELF
#        payload, each with a plain launch of the same payload as the
#        control: a plain process never carries the label at all.
#
#        The sampler is C on purpose.  A shell loop costs about 2 ms per
#        iteration on this host, which is longer than the window being
#        measured: a shell sampler reports its own startup cost, not the
#        window.  Without a C compiler the row is SKIPPED.
#
#   3. syscall signature
#        (a) the launcher's own startup sequence, from
#            `strace -qq -o ...` on the launcher.  This works: without
#            `-f` strace never seizes the payload, so pmask's own
#            PTRACE_SEIZE of its child succeeds.
#        (b) the sustained traffic, from `strace -p <tracer-tid>`.  The
#            tracer thread made the supervisor non-dumpable, so attaching
#            needs CAP_SYS_PTRACE; the row is attempted through `sudo -n`
#            when that is available and SKIPPED with the refusal quoted
#            otherwise.
#
#            `strace -f` on the launcher CANNOT be used, and that is a
#            finding rather than a limitation of this script: with `-f`
#            strace seizes the forked payload, pmask's PTRACE_SEIZE of that
#            child is then refused with EPERM, and the session dies.  The
#            exact trace is printed by the failcheck in `verify-empty`.
#
# Every number carries its conditions, printed in HOST and repeated in each
# result line.  `date +%s%N` is GNU date, not POSIX; the rows that need it
# are SKIPPED when it is absent.
#
# Exit status: 0 when the measurement was produced (SKIP rows included),
# 2 when nothing could be produced at all.
# ============================================================================
set -u

SELF_DIR=$(cd "$(dirname "$0")" && pwd) || exit 2
ROOT=$(cd "$SELF_DIR/.." && pwd) || exit 2
cd "$SELF_DIR" || exit 2

TOOL="${PMASK_BIN:-$ROOT/target/release/pmask}"
if [ ! -x "$TOOL" ]; then
    echo "missing built binary: $TOOL (cargo build --release --bin pmask)" >&2
    exit 2
fi

T="${TMPDIR:-/tmp}/pmask-window.$$"
mkdir -p "$T" || exit 2
chmod 700 "$T"
KEEP="${WINDOW_KEEP:-0}"
cleanup() { [ "$KEEP" = 0 ] && rm -rf "$T"; return 0; }
trap cleanup EXIT INT TERM

ROUNDS="${WINDOW_ROUNDS:-3}"
N="${WINDOW_N:-60}"

CC=""
for c in cc gcc clang; do
    command -v "$c" >/dev/null 2>&1 && { CC="$c"; break; }
done

CAPEFF=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status 2>/dev/null)
echo "HOST uname=$(uname -srm) kernel=$(uname -r) uid=$(id -u) nproc=$( (nproc 2>/dev/null) || echo '?') capeff=$CAPEFF"
echo "HOST rounds=$ROUNDS n=$N pmask=$TOOL cc=${CC:-none}"
[ "$KEEP" = 0 ] || echo "HOST keep=$T"

# `date +%s%N` really gives nanoseconds.
have_date_ns() {
    d1=$(date +%s%N 2>/dev/null) || return 1
    case "$d1" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#d1}" -ge 16 ] || return 1
    d2=$(date +%s%N 2>/dev/null) || return 1
    [ "$d2" -gt "$d1" ] || return 1
    return 0
}

# ------------------------------------------------------- 1. spawn latency
median_of() {
    sort -n "$1" | awk '{a[NR]=$1} END{
        if (NR==0) { print ""; exit }
        if (NR%2) print a[(NR+1)/2];
        else printf "%.0f\n", (a[NR/2]+a[NR/2+1])/2
    }'
}

# p95_of FILE: the nearest-rank 95th percentile of the sorted file.
p95_of() {
    sort -n "$1" | awk '{a[NR]=$1} END{
        if (NR==0) { print ""; exit }
        i=int((NR*95+99)/100); if (i<1) i=1; if (i>NR) i=NR; print a[i]
    }'
}

mean_of() {
    awk '{s+=$1} END{ if (NR==0) {print ""; exit} printf "%.0f\n", s/NR }' "$1"
}

ms4() { awk -v x="$1" 'BEGIN{ if (x=="") { print "n/a"; exit } printf "%.4f", x/1000000 }'; }

# bench VARIANT N OUTFILE: one launch per iteration, whole invocation.
bench() {
    b_variant="$1"; b_n="$2"; b_out="$3"
    : >"$b_out"
    b_i=0
    while [ "$b_i" -lt "$b_n" ]; do
        b_t0=$(date +%s%N)
        case "$b_variant" in
            plain)  /bin/true ;;
            env-i)  env -i PATH=/usr/bin:/bin /bin/true ;;
            masked) env -i PATH=/usr/bin:/bin "$TOOL" -q -l bench -- /bin/true ;;
        esac
        b_t1=$(date +%s%N)
        echo $((b_t1 - b_t0)) >>"$b_out"
        b_i=$((b_i + 1))
    done
}

if have_date_ns; then
    for v in plain env-i masked; do
        : >"$T/all.$v"
        : >"$T/rm.$v"
        r=0
        while [ "$r" -lt "$ROUNDS" ]; do
            bench "$v" "$N" "$T/round.$v.$r"
            cat "$T/round.$v.$r" >>"$T/all.$v"
            median_of "$T/round.$v.$r" >>"$T/rm.$v"
            r=$((r + 1))
        done
        printf 'SPAWN variant=%s mean_ms=%s median_ms=%s p95_ms=%s n=%s rounds=%s\n' \
            "$v" "$(ms4 "$(mean_of "$T/all.$v")")" "$(ms4 "$(median_of "$T/all.$v")")" \
            "$(ms4 "$(p95_of "$T/all.$v")")" "$N" "$ROUNDS"
        lo=$(sort -n "$T/rm.$v" | head -1)
        hi=$(sort -n "$T/rm.$v" | tail -1)
        spread=$(awk -v a="$lo" -v b="$hi" 'BEGIN{ if (a+0<=0) { print "n/a"; exit } printf "%.1f", (b-a)*100.0/a }')
        printf 'SPAWN-SPREAD variant=%s round_median_min_ms=%s max_ms=%s spread_pct=%s %s\n' \
            "$v" "$(ms4 "$lo")" "$(ms4 "$hi")" "$spread" \
            "$(awk -v s="$spread" 'BEGIN{ if (s+0 > 30) print "UNSTABLE"; else print "STABLE" }')"
    done
    PM=$(median_of "$T/all.masked")
    PL=$(median_of "$T/all.plain")
    EN=$(median_of "$T/all.env-i")
    printf 'SPAWN-RATIO masked_over_plain=%s masked_over_env_i=%s\n' \
        "$(awk -v a="$PM" -v b="$PL" 'BEGIN{ if (b+0<=0) {print "n/a"; exit} printf "%.2f", a/b }')" \
        "$(awk -v a="$PM" -v b="$EN" 'BEGIN{ if (b+0<=0) {print "n/a"; exit} printf "%.2f", a/b }')"
else
    echo "SKIP spawn-latency (date +%s%N gives no nanoseconds here)"
fi

# ------------------------------------------------------- 2. launch window
# The sampler.  Shell is far too slow for this: one `cat /proc/PID/comm`
# costs about 2 ms on this host, which is longer than the window.  The
# sampler is C and does two things:
#
#   * watches `/proc` for the first child of the launcher (the payload),
#     so the observation starts before the payload's first exec;
#   * then reads `/proc/<pid>/comm` in a tight loop and prints a line per
#     change, with the nanosecond it happened.
#
# Args: SUP_PID SECONDS LABEL [direct]
#        `direct` samples SUP_PID itself instead of waiting for its first
#        child: a plain launch has no wrapper, so the launcher *is* the
#        payload and there is no child to find.
cat >"$T/sample.c" <<'EOF'
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static long long ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

/* Read the PPid field of /proc/PID/status.  Returns -1 when unreadable. */
static long ppid_of(long pid) {
    char path[64], buf[1024];
    snprintf(path, sizeof path, "/proc/%ld/status", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t k = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (k <= 0) return -1;
    buf[k] = 0;
    char *p = strstr(buf, "\nPPid:");
    if (!p) return -1;
    return atol(p + 6);
}

/* Find the first child of SUP.  Returns 0 when none is visible yet. */
static long child_of(long sup) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *e;
    long found = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        long pid = atol(e->d_name);
        if (pid == sup) continue;
        if (ppid_of(pid) == sup) { found = pid; break; }
    }
    closedir(d);
    return found;
}

/* Read the comm of PID.  Returns 0 on success. */
static int comm_of(long pid, char *out, size_t n) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%ld/comm", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t k = read(fd, out, n - 1);
    close(fd);
    if (k <= 0) return -1;
    while (k > 0 && (out[k-1] == '\n' || out[k-1] == 0)) k--;
    out[k] = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: sample SUP SECONDS LABEL\n"); return 2; }
    long sup = atol(argv[1]);
    double secs = atof(argv[2]);
    const char *label = argv[3];
    int direct = argc > 4 && strcmp(argv[4], "direct") == 0;
    long long t0 = ns(), end = t0 + (long long)(secs * 1e9);
    long long found_at = -1;
    long pid = 0;
    if (direct) {
        /* The launcher is the payload; sample it from the first moment
         * its comm is readable, not from a scan that would miss the very
         * interval under measurement. */
        pid = sup;
        found_at = t0;
    } else {
        while (ns() < end) {
            pid = child_of(sup);
            if (pid) { found_at = ns(); break; }
        }
    }
    if (!pid) { printf("NOCHILD\n"); return 0; }
    printf("FOUND pid=%ld ns=%lld\n", pid, found_at - t0);
    char last[128] = "", buf[128];
    long n = 0;
    long long first = 0, last_change = -1;
    int printed_first = 0;
    while (ns() < end) {
        if (comm_of(pid, buf, sizeof buf) != 0) break;
        if (n == 0) { first = ns(); strcpy(last, buf); }
        n++;
        if (!printed_first || strcmp(buf, last) != 0) {
            long long t = ns();
            printf("COMM %lld %s\n", t - t0, buf);
            printed_first = 1;
            last_change = t;
            strcpy(last, buf);
        }
    }
    printf("END samples=%ld first_ns=%lld last_change_ns=%lld interval_us=%.3f label=%s\n",
           n, first - t0, last_change < 0 ? -1 : last_change - t0,
           n ? (double)(ns() - first) / 1000.0 / (double)n : 0.0, label);
    return 0;
}
EOF

SAMPLER=""
if [ -n "$CC" ]; then
    "$CC" -O2 -o "$T/sample" "$T/sample.c" 2>"$T/cc.err" && SAMPLER="$T/sample"
fi

LABEL="win-$$"

# run_window VARIANT DESC CMD...
# Launch CMD, then have the sampler watch for the payload and report every
# distinct comm it sees.  The payload itself decides when to exit.
run_window() {
    rw_variant="$1"; rw_desc="$2"; shift 2
    rw_direct=child
    rw_err="$T/rw.$rw_variant.$rw_desc.err"
    rw_out="$T/win.$rw_variant.$rw_desc"
    case "$rw_variant" in
        masked)
            env -i PATH=/usr/bin:/bin "$TOOL" -q -l "$LABEL" -- "$@" \
                >/dev/null 2>"$rw_err" &
            ;;
        plain)
            # No wrapper: the launcher's own pid is the payload.
            rw_direct=direct
            env -i PATH=/usr/bin:/bin "$@" >/dev/null 2>"$rw_err" &
            ;;
        *) return 3 ;;
    esac
    rw_sup=$!
    "$SAMPLER" "$rw_sup" 1.5 "$LABEL" "${rw_direct:-child}" >"$rw_out" 2>"$T/win.err"
    kill -9 "$rw_sup" 2>/dev/null
    wait "$rw_sup" 2>/dev/null
    awk -v variant="$rw_variant" -v desc="$rw_desc" -v label="$LABEL" '
        /^COMM / {
            t = $2
            $1 = ""; $2 = ""
            sub(/^ +/, "")
            comm = $0
            if (n == 0) { start_t = t; prev_t = t; prev_c = comm }
            n++
            # Every change is a transition; the previous comm held from
            # prev_t to t.  Accumulate the time spent off the label.
            if (prev_c != label) off_ns += (t - prev_t)
            if (prev_c != "" && t - prev_t > longest_off && prev_c != label) {
                longest_off = t - prev_t
            }
            # A run-length encoded sequence is the readable form.
            if (n == 1) { seq = comm "@" t }
            else        { seq = seq ">" comm "@" t }
            if (comm == label && label_at == "") label_at = t
            prev_t = t; prev_c = comm
        }
        /^FOUND / {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^pid=/) { split($i, kv, "="); cpid = kv[2] }
                if ($i ~ /^ns=/) { split($i, kv, "="); found_at = kv[2] }
            }
        }
        /^END / {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^samples=/) { split($i, kv, "="); samples = kv[2] }
                if ($i ~ /^interval_us=/) { split($i, kv, "="); interval = kv[2] }
                if ($i ~ /^first_ns=/) { split($i, kv, "="); first_ns = kv[2] }
            }
        }
        END {
            if (samples == "" || samples == 0) {
                printf "WINDOW variant=%s payload=%s SKIP (no sample)\n", variant, desc
                exit
            }
            printf "WINDOW variant=%s payload=%s pid=%s found_ns=%s samples=%s interval_us=%s off_label_total_us=%.3f longest_off_label_us=%.3f", \
                variant, desc, (cpid == "" ? "?" : cpid), found_at, samples, interval,
                off_ns / 1000.0, longest_off / 1000.0
            if (label_at != "") printf " label_seen_at_ns=%s", label_at
            else                 printf " label_never_seen=1"
            printf " sequence=%s\n", (seq == "" ? "(none)" : seq)
        }
    ' "$rw_out"
}

# The launch-window calls.  The script payload makes the kernel exec the
# interpreter, so the process name changes under the sampler; the ELF
# payload is the single-exec case.  The plain runs are the controls: with
# no launcher, the process is its own payload and the masked run's label
# can never appear.
# The sampler finds the payload by scanning /proc, and on a loaded host a
# scan can take longer than the window itself.  A single sample therefore
# sometimes starts after the exec has settled and reports no window, which
# is a property of the instrument and not of the mask.  Repeat the masked
# rows and report the median of the windows that were actually seen, plus
# the number of attempts that missed; a row that missed every attempt says
# so and is a SKIP rather than a zero.  The plain controls are run once,
# because their expected result ("the label never appears") does not depend
# on catching a short interval.
WINDOW_ATTEMPTS="${WINDOW_ATTEMPTS:-3}"

# window_repeat VARIANT DESC CMD...
# Runs the attempt loop and reports the *median* off-label time of the
# attempts that saw a window, not the largest.  Taking the largest would be
# a biased estimator: a retry that happens to catch part of the next exec or
# a scheduling hiccup reports a longer window than the steady-state one, and
# repeating until the number looks big is how a measurement stops meaning
# anything.  A row that missed every attempt reports the misses and prints
# the SKIP form, never a zero.
#
# The per-attempt lines are printed so the spread is visible.
window_repeat() {
    wr_variant="$1"; wr_desc="$2"; shift 2
    wr_hit=0
    wr_attempt=0
    wr_vals="$T/wr.vals"
    : >"$wr_vals"
    wr_lines="$T/wr.lines"
    : >"$wr_lines"
    while [ "$wr_attempt" -lt "$WINDOW_ATTEMPTS" ]; do
        wr_attempt=$((wr_attempt + 1))
        wr_row=$(run_window "$wr_variant" "$wr_desc" "$@")
        case "$wr_row" in
            *" off_label_total_us=0.000"*|*"SKIP "*)
                printf 'WINDOW-ATTEMPT variant=%s payload=%s attempt=%s missed=1\n' \
                    "$wr_variant" "$wr_desc" "$wr_attempt"
                ;;
            *)
                wr_us=$(printf '%s' "$wr_row" | sed -n 's/.*off_label_total_us=\([0-9.]*\).*/\1/p')
                printf 'WINDOW-ATTEMPT variant=%s payload=%s attempt=%s off_label_us=%s\n' \
                    "$wr_variant" "$wr_desc" "$wr_attempt" "${wr_us:-?}"
                [ -n "$wr_us" ] && echo "$wr_us" >>"$wr_vals"
                wr_hit=$((wr_hit + 1))
                echo "$wr_row" >>"$wr_lines"
                ;;
        esac
    done
    if [ "$wr_hit" = 0 ]; then
        printf 'WINDOW variant=%s payload=%s SKIP (no attempt caught the window in %s tries; the sampler found the payload after its exec had settled)\n' \
            "$wr_variant" "$wr_desc" "$wr_attempt"
        return 0
    fi
    wr_stats=$(sort -n "$wr_vals" | awk '{a[NR]=$1} END{
        if (NR%2) med=a[(NR+1)/2];
        else med=(a[NR/2]+a[NR/2+1])/2;
        printf "%.3f %.3f %.3f", a[1], med, a[NR]
    }')
    wr_min=$(printf '%s' "$wr_stats" | cut -d' ' -f1)
    wr_median=$(printf '%s' "$wr_stats" | cut -d' ' -f2)
    wr_max=$(printf '%s' "$wr_stats" | cut -d' ' -f3)
    # The quoted sequences are the attempts that saw a transition, which is
    # the observable the channel is about.  They are printed as a block
    # rather than beside the median figure: with an even number of attempts
    # the median need not be any observed value, and putting one attempt's
    # sequence next to it would read as though the two came from one run.
    wr_transitions=$(awk '/ sequence=[^ ]*>/' "$wr_lines")
    if [ -n "$wr_transitions" ]; then
        printf 'WINDOW-SEEN the attempts that saw a comm change:\n'
        printf '%s\n' "$wr_transitions"
    else
        printf 'WINDOW-SEEN none: every attempt was late, so the window is shorter than the sampler can catch on this run\n'
    fi
    printf 'WINDOW variant=%s payload=%s attempts=%s caught=%s off_label_us_median=%s min=%s max=%s\n' \
        "$wr_variant" "$wr_desc" "$wr_attempt" "$wr_hit" "$wr_median" "$wr_min" "$wr_max"
}

if [ -n "$SAMPLER" ] && have_date_ns; then
    printf '#!/bin/sh\nsleep 0.35\n' >"$T/payload.sh"
    chmod 755 "$T/payload.sh"
    cp /bin/sleep "$T/payload.elf" 2>/dev/null || true
    window_repeat masked script "$T/payload.sh"
    window_repeat masked elf "$T/payload.elf" 0.35
    run_window plain script "$T/payload.sh"
    run_window plain elf "$T/payload.elf" 0.35
else
    if [ -z "$SAMPLER" ]; then
        echo "SKIP launch-window (no C compiler for the sampler: $(head -1 "$T/cc.err" 2>/dev/null))"
    else
        echo "SKIP launch-window (date +%s%N gives no nanoseconds here)"
    fi
fi

# --------------------------------------------------- 3. syscall signature
# (a) The startup sequence.  `strace -qq -o FILE` with no `-f` traces only
#     the launcher, so pmask's own seize of the child is not competing
#     with strace for the same tracee.
startup_trace() {
    st_out="$1"
    : >"$st_out"
    if ! command -v strace >/dev/null 2>&1; then
        return 1
    fi
    strace -qq -o "$st_out" -e trace=prctl,ptrace,clone,clone3 \
        env -i PATH=/usr/bin:/bin "$TOOL" -q -l bench -- /bin/true \
        >/dev/null 2>/dev/null
    [ -s "$st_out" ]
}

if startup_trace "$T/startup.trace"; then
    grep -E 'prctl\(PR_SET_(MM|NAME|DUMPABLE)|clone[3]?\(|PTRACE_SEIZE' "$T/startup.trace" \
        | sed 's/^[0-9]* //' | sed 's/^/SYSCALL-STARTUP /'
    grep -q 'PTRACE_SEIZE' "$T/startup.trace" \
        && echo "SYSCALL-STARTUP note=PTRACE_SEIZE is issued by the tracer thread, not the leader; it appears here because the trace covers the process" \
        || echo "SYSCALL-STARTUP note=no PTRACE_SEIZE line (the tracer thread was not traced; see the sustained section)"
else
    echo "SKIP syscall-startup (no strace, or the trace is empty)"
fi

# (b) The sustained traffic.  The tracer thread is the second task of the
#     supervisor, and the supervisor is non-dumpable, so the attach needs
#     CAP_SYS_PTRACE.  `sudo -n` supplies it when the host allows it; the
#     refusal is quoted when it does not.
sustained_trace() {
    su_out="$1"
    su_log="$T/su.err"
    : >"$su_out"
    # A payload that execs in a loop: an idle tracer performs nothing to
    # count, and a one-shot payload is gone before the sampler starts.
    env -i PATH=/usr/bin:/bin "$TOOL" -q -l busyloop -- \
        /bin/sh -c 'i=0; while [ $i -lt 300 ]; do /bin/true; i=$((i+1)); done' \
        >/dev/null 2>&1 &
    su_sup=$!
    su_tid=""
    su_i=0
    while [ "$su_i" -lt 200 ]; do
        for t in "/proc/$su_sup"/task/*; do
            [ -d "$t" ] || continue
            su_b=$(basename "$t")
            [ "$su_b" = "$su_sup" ] && continue
            su_tid=$su_b
        done
        [ -n "$su_tid" ] && break
        su_i=$((su_i + 1))
    done
    if [ -z "$su_tid" ]; then
        kill -9 "$su_sup" 2>/dev/null
        wait "$su_sup" 2>/dev/null
        echo "SKIP syscall-sustained (no second task in the supervisor)"
        return 1
    fi
    # Attach for as long as the payload loop runs, then stop the sampler.
    strace -qq -p "$su_tid" -e trace=ptrace,process_vm_readv,process_vm_writev,prctl \
        -o "$su_out" 2>"$su_log" &
    su_st=$!
    su_i=0
    while [ "$su_i" -lt 120 ]; do
        kill -0 "$su_sup" 2>/dev/null || break
        sleep 0.1 2>/dev/null || sleep 1
        su_i=$((su_i + 1))
    done
    kill -TERM "$su_st" 2>/dev/null
    wait "$su_st" 2>/dev/null
    kill -9 "$su_sup" 2>/dev/null
    wait "$su_sup" 2>/dev/null
    if [ -s "$su_out" ]; then
        TRACED_TID=$su_tid
        return 0
    fi
    echo "SKIP syscall-sustained (attach refused: $(head -1 "$su_log" 2>/dev/null))"
    return 1
}

# Find the tracer thread: the supervisor's second task.  Nothing in /proc
# marks it by name after the issue-38 fix, so the tid is the task that is
# not the leader.
find_tracer_tid() {
    ft_sup="$1"
    ft_tid=""
    ft_i=0
    while [ "$ft_i" -lt 200 ]; do
        for t in "/proc/$ft_sup"/task/*; do
            [ -d "$t" ] || continue
            ft_b=$(basename "$t")
            [ "$ft_b" = "$ft_sup" ] && continue
            ft_tid=$ft_b
        done
        [ -n "$ft_tid" ] && break
        ft_i=$((ft_i + 1))
    done
    printf '%s' "$ft_tid"
}

count_sustained() {
    awk '
        /ptrace\(PTRACE_SEIZE/ { sz++ }
        /ptrace\(PTRACE_SYSCALL/ { sc++ }
        /ptrace\(PTRACE_GET_SYSCALL_INFO/ { gs++ }
        /ptrace\(PTRACE_GETREGSET/ { gr++ }
        /ptrace\(PTRACE_SETREGSET/ { sr++ }
        /ptrace\(PTRACE_CONT/ { co++ }
        /ptrace\(PTRACE_GETEVENTMSG/ { ge++ }
        /process_vm_readv/ { vr++ }
        /process_vm_writev/ { vw++ }
        /prctl\(PR_SET_NAME/ { pn++ }
        /prctl\(PR_SET_MM/ { pm++ }
        END {
            printf "lines=%d PTRACE_SEIZE=%d PTRACE_SYSCALL=%d PTRACE_GET_SYSCALL_INFO=%d PTRACE_GETREGSET=%d PTRACE_SETREGSET=%d PTRACE_CONT=%d PTRACE_GETEVENTMSG=%d process_vm_readv=%d process_vm_writev=%d PR_SET_NAME=%d PR_SET_MM=%d\n", \
                NR, sz, sc, gs, gr, sr, co, ge, vr, vw, pn, pm
        }
    ' "$1"
}

# (b) The sustained traffic.  The tracer thread is not dumpable, so the
#     attach needs CAP_SYS_PTRACE; `sudo -n` supplies it where the host
#     allows it, and the refusal is quoted where it does not.
SUSTAINED_SECS="${WINDOW_SUSTAINED_SECS:-6}"
if command -v strace >/dev/null 2>&1; then
    env -i PATH=/usr/bin:/bin "$TOOL" -q -l busyloop -- \
        /bin/sh -c 'i=0; while [ $i -lt 2000 ]; do /bin/true; i=$((i+1)); done' \
        >/dev/null 2>&1 &
    SUP=$!
    TID=$(find_tracer_tid "$SUP")
    if [ -z "$TID" ]; then
        echo "SKIP syscall-sustained (no second task appeared in the supervisor)"
        kill -9 "$SUP" 2>/dev/null
        wait "$SUP" 2>/dev/null
    else
        su_rc=0
        if [ "$(id -u)" = 0 ]; then
            timeout "$SUSTAINED_SECS" strace -qq -p "$TID" \
                -e trace=ptrace,process_vm_readv,process_vm_writev,prctl \
                -o "$T/sustained.trace" 2>"$T/su.err"
            su_rc=$?
        elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            sudo -n timeout "$SUSTAINED_SECS" strace -qq -p "$TID" \
                -e trace=ptrace,process_vm_readv,process_vm_writev,prctl \
                -o "$T/sustained.trace" 2>"$T/su.err"
            su_rc=$?
        else
            su_rc=99
            echo "the supervisor is non-dumpable: the attach needs CAP_SYS_PTRACE and this caller has no passwordless sudo" >"$T/su.err"
        fi
        kill -9 "$SUP" 2>/dev/null
        wait "$SUP" 2>/dev/null
        if [ -s "$T/sustained.trace" ]; then
            printf 'SYSCALL-SUSTAINED tracer_tid=%s attach_secs=%s %s\n' \
                "$TID" "$SUSTAINED_SECS" "$(count_sustained "$T/sustained.trace")"
            echo "SYSCALL-SUSTAINED-NOTE counts cover ${SUSTAINED_SECS}s of a payload that execs /bin/true in a loop; divide by ${SUSTAINED_SECS} for a per-second rate"
        elif [ "$su_rc" = 99 ]; then
            echo "SKIP syscall-sustained ($(cat "$T/su.err"))"
        else
            echo "SKIP syscall-sustained (attach gave no lines: strace rc=$su_rc $(head -1 "$T/su.err" 2>/dev/null))"
        fi
    fi
else
    echo "SKIP syscall-sustained (no strace)"
fi

# The `strace -f` failcheck.  This is the measurement showing why the
# sustained row needs a per-thread attach, not a whole-process one: with
# `-f`, strace seizes the forked payload itself, pmask's own PTRACE_SEIZE
# of that child is then refused with EPERM, and the session dies.  Printed
# as a finding rather than hidden, because a reader of the syscall table
# would otherwise assume `strace -f` was an option.
if command -v strace >/dev/null 2>&1; then
    strace -f -qq -o "$T/fcheck.trace" -e trace=ptrace \
        env -i PATH=/usr/bin:/bin "$TOOL" -q -l bench -- /bin/true \
        >/dev/null 2>"$T/fcheck.err"
    fc_rc=$?
    if grep -q 'PTRACE_SEIZE.*EPERM' "$T/fcheck.trace" 2>/dev/null; then
        echo "FAILCHECK strace_f_breaks_a_session rc=$fc_rc $(grep -m1 'PTRACE_SEIZE' "$T/fcheck.trace" | sed 's/^[0-9]* //; s/<unfinished \.\.\.//')"
        echo "FAILCHECK stderr=$(tr '\n' '|' < "$T/fcheck.err" | cut -c1-90)"
    elif [ "$fc_rc" = 0 ]; then
        echo "FAILCHECK strace_f_does_not_break_a_session rc=0 (this host lets a tracee be seized under -f)"
    else
        echo "FAILCHECK strace_f_inconclusive rc=$fc_rc"
    fi
fi


echo "DONE (issue 48 measurement)"
exit 0
