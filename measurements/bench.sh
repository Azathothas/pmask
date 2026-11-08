#!/bin/sh
# ============================================================================
# Speed comparison against zapper, measured on this host.
#
#   sh measurements/bench.sh
#
# Three measurements, each repeated ROUNDS times so the spread is visible:
#
#   1. startup-to-exit  launch a trivial program N times, time the whole
#                       invocation from before exec to after wait.  This is
#                       what a user pays per launch, launcher included.
#   2. exec throughput  one payload that forks and execs a child M times,
#                       timed by the payload itself with CLOCK_MONOTONIC, so
#                       the launcher's own startup is excluded and only the
#                       per-exec supervision cost is left.
#   3. syscall loop     100000 getpid calls in the payload.  If the supervisor
#                       stopped on every syscall this is where it would show.
#                       It is the regression that matters most, because a
#                       tracer that costs a stop per syscall is unusable for
#                       real work even when its exec cost looks fine.
#
# External wall clock uses `date +%s%N`, which is GNU date and not POSIX.
# The script checks for it and skips that measurement if absent; the other
# two are timed inside C and do not depend on it.
#
# Every number carries the host conditions printed at the top.  A number
# whose spread across rounds exceeds 30 percent is marked UNSTABLE rather
# than reported as a median.
#
# zapper is built from source under $TMPDIR.  With no network or no C
# compiler the zapper rows are SKIPPED, and the pmask rows still run.
#
# Exit status: 0 when the measurement was produced (SKIP rows included),
# 2 when it could not be produced at all.
# ============================================================================
set -u
cd "$(dirname "$0")" || exit 2

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="${PMASK_BIN:-$ROOT/target/release/pmask}"
[ -x "$TOOL" ] || { echo "missing built binary: $TOOL (cargo build --release --bin pmask)" >&2; exit 2; }

T="${TMPDIR:-/tmp}/pmask-bench.$$"
mkdir -p "$T" || exit 2
chmod 700 "$T"
cleanup() { rm -rf "$T"; }
trap cleanup EXIT INT TERM

ROUNDS="${BENCH_ROUNDS:-3}"
N_START="${BENCH_START_N:-200}"
N_EXEC="${BENCH_EXEC_N:-100}"
N_SYSCALL="${BENCH_SYSCALL_N:-100000}"

# ------------------------------------------------------------------ payloads
cat >"$T/execpay.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
static long long ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 100;
    int ok = 0, i;
    long long t0 = ns();
    for (i = 0; i < n; i++) {
        pid_t p = fork();
        int st;
        if (p == 0) {
            execl("/bin/true", "true", (char *)0);
            _exit(127);
        }
        if (p < 0) break;
        if (waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0) ok++;
    }
    fprintf(stderr, "PAYLOAD ns=%lld n=%d ok=%d\n", ns() - t0, n, ok);
    return 0;
}
EOF

cat >"$T/syspay.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
static long long ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}
int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 100000;
    volatile long sink = 0;
    long i;
    long long t0 = ns();
    for (i = 0; i < n; i++) sink += getpid();
    fprintf(stderr, "PAYLOAD ns=%lld n=%ld sink=%ld\n", ns() - t0, n, sink);
    return 0;
}
EOF

CC=""
for c in cc gcc clang; do
    command -v "$c" >/dev/null 2>&1 && { CC="$c"; break; }
done
if [ -n "$CC" ]; then
    "$CC" -O2 -o "$T/execpay" "$T/execpay.c" 2>/dev/null || rm -f "$T/execpay"
    # -O0 on purpose: with optimisation the getpid loop is folded away and
    # the measurement becomes a constant.
    "$CC" -O0 -o "$T/syspay" "$T/syspay.c" 2>/dev/null || rm -f "$T/syspay"
fi

# -------------------------------------------------------------------- zapper
ZAPPER=""
ZAPPER_VERSION="absent"
if [ -x "$T/execpay" ]; then
    if command -v git >/dev/null 2>&1 && [ -n "$CC" ]; then
        if git clone -q --depth 1 https://github.com/hackerschoice/zapper.git "$T/zapper" 2>/dev/null; then
            if (cd "$T/zapper" && make -s >/dev/null 2>&1) && [ -x "$T/zapper/zapper" ]; then
                ZAPPER="$T/zapper/zapper"
                ZAPPER_VERSION="$("$ZAPPER" -h 2>&1 | sed -n 's/^Version \([^ ]*\).*/\1/p' | head -1)"
                [ -n "$ZAPPER_VERSION" ] || ZAPPER_VERSION="unknown"
            else
                echo "SKIP zapper: the clone built no binary"
            fi
        else
            echo "SKIP zapper: cannot clone hackerschoice/zapper"
        fi
    else
        echo "SKIP zapper: no git, or no C compiler"
    fi
else
    echo "SKIP zapper: no C compiler for the payloads"
fi

# ------------------------------------------------------------------ host info
have_date_ns() {
    dn=$(date +%s%N 2>/dev/null) || return 1
    case "$dn" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "${#dn}" -ge 16 ] || return 1
    return 0
}
DATE_NS=no
have_date_ns && DATE_NS=yes

KVM=absent
if [ -e /dev/kvm ]; then
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then KVM=usable; else KVM=not-usable; fi
fi

printf 'FIELDS %s\n' "uname nproc uid capeff kernel kvm date_ns zapper rounds start_n exec_n syscall_n"
printf 'HOST  %s\n' \
    "uname=$(uname -srm)" \
    "nproc=$( (nproc 2>/dev/null) || echo '?')" \
    "uid=$(id -u)" \
    "capeff=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status 2>/dev/null)" \
    "kernel=$(uname -r)" \
    "kvm=$KVM" \
    "date_ns=$DATE_NS" \
    "zapper=$ZAPPER_VERSION" \
    "rounds=$ROUNDS" \
    "start_n=$N_START" \
    "exec_n=$N_EXEC" \
    "syscall_n=$N_SYSCALL"

# ------------------------------------------------------------------- helpers
now_ns() { date +%s%N; }

# variant_run VARIANT PAYLOAD [ARGS...]
# Runs the payload under the launcher the variant names.
variant_run() {
    vr_variant="$1"; shift
    case "$vr_variant" in
        baseline)   "$@" ;;
        zapper)     [ -n "$ZAPPER" ] || return 3; "$ZAPPER" "$@" ;;
        zapper-f)   [ -n "$ZAPPER" ] || return 3; "$ZAPPER" -f "$@" ;;
        pmask)   "$TOOL" -q -l bench -- "$@" ;;
        pmask-detach) "$TOOL" -q -l bench --detach -- "$@" ;;
        *) return 3 ;;
    esac
}

# median FILE  (FILE sorted numerically ascending, non-empty)
median_file() {
    mf_n=$(wc -l <"$1")
    [ "$mf_n" -gt 0 ] || { echo ""; return; }
    if [ $((mf_n % 2)) = 1 ]; then
        sed -n "$(( (mf_n + 1) / 2 ))p" "$1"
    else
        awk -v a=$((mf_n / 2)) -v b=$((mf_n / 2 + 1)) \
            'NR==a{lo=$1} NR==b{printf "%d\n", (lo+$1)/2}' "$1"
    fi
}

# pct FILE PCT  (FILE sorted numerically ascending)
pct_file() {
    pf_n=$(wc -l <"$1")
    [ "$pf_n" -gt 0 ] || { echo ""; return; }
    pf_r=$(( ($2 * pf_n + 99) / 100 ))
    [ "$pf_r" -lt 1 ] && pf_r=1
    [ "$pf_r" -gt "$pf_n" ] && pf_r="$pf_n"
    sed -n "${pf_r}p" "$1"
}

# spread OF ROUND VALUES...  -> percent between min and max, 0 when equal
spread_of() {
    so_min="$1"; so_max="$1"; shift
    for so_v in "$@"; do
        [ "$so_v" -lt "$so_min" ] && so_min="$so_v"
        [ "$so_v" -gt "$so_max" ] && so_max="$so_v"
    done
    if [ "$so_min" -le 0 ]; then echo 0; return; fi
    echo $(( (so_max - so_min) * 100 / so_min ))
}

VARIANTS="baseline zapper zapper-f pmask pmask-detach"

# --------------------------------------------- measurement 1: startup-to-exit
# Only meaningful with a nanosecond clock.
if [ "$DATE_NS" = yes ]; then
    for v in $VARIANTS; do
        round=0
        vals=""
        while [ "$round" -lt "$ROUNDS" ]; do
            round=$((round + 1))
            raw="$T/s$v.$round.raw"
            : >"$raw"
            i=0
            while [ "$i" -lt "$N_START" ]; do
                i=$((i + 1))
                t0=$(now_ns)
                variant_run "$v" /bin/true >/dev/null 2>&1 || true
                t1=$(now_ns)
                echo $(( (t1 - t0) / 1000 )) >>"$raw"
            done
            sort -n "$raw" >"$raw.s"
            med=$(median_file "$raw.s")
            p95=$(pct_file "$raw.s" 95)
            printf 'STARTUP variant=%s round=%s n=%s median_us=%s p95_us=%s\n' \
                "$v" "$round" "$N_START" "$med" "$p95"
            vals="$vals $med"
        done
        # shellcheck disable=SC2086
        set -- $vals
        med_of_meds=$(printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{ if(NR%2) print a[(NR+1)/2]; else print int((a[NR/2]+a[NR/2+1])/2) }')
        sp=$(spread_of "$@")
        flag=""
        [ "$sp" -gt 30 ] && flag=" UNSTABLE"
        printf 'STARTUP-MEDIAN variant=%s median_us=%s spread_pct=%s%s\n' "$v" "$med_of_meds" "$sp" "$flag"
    done
else
    echo "SKIP startup-to-exit: no nanosecond clock (date +%s%N)"
fi

# ---------------------------------------------- measurement 2: exec throughput
if [ -x "$T/execpay" ]; then
    for v in $VARIANTS; do
        if [ -z "$ZAPPER" ] && [ "$v" != baseline ] && [ "$v" != pmask ] && [ "$v" != pmask-detach ]; then
            echo "EXEC variant=$v SKIP no zapper"
            continue
        fi
        round=0
        vals=""
        while [ "$round" -lt "$ROUNDS" ]; do
            round=$((round + 1))
            out="$T/e$v.$round.out"
            variant_run "$v" "$T/execpay" "$N_EXEC" >"$out" 2>&1 || true
            ns=$(sed -n 's/^PAYLOAD ns=\([0-9]*\).*/\1/p' "$out" | head -1)
            ok=$(sed -n 's/.* ok=\([0-9]*\).*/\1/p' "$out" | head -1)
            if [ -z "$ns" ]; then
                echo "EXEC variant=$v round=$round FAILED no payload timing: $(tr '\n' '|' <"$out")"
                continue
            fi
            per=$(( ns / N_EXEC / 1000 ))
            printf 'EXEC variant=%s round=%s n=%s ok=%s total_us=%s per_exec_us=%s\n' \
                "$v" "$round" "$N_EXEC" "${ok:-?}" "$(( ns / 1000 ))" "$per"
            vals="$vals $per"
        done
        [ -n "$vals" ] || continue
        # shellcheck disable=SC2086
        set -- $vals
        med=$(printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{ if(NR%2) print a[(NR+1)/2]; else print int((a[NR/2]+a[NR/2+1])/2) }')
        sp=$(spread_of "$@")
        flag=""
        [ "$sp" -gt 30 ] && flag=" UNSTABLE"
        printf 'EXEC-MEDIAN variant=%s per_exec_us=%s spread_pct=%s%s\n' "$v" "$med" "$sp" "$flag"
    done
else
    echo "SKIP exec throughput: no C compiler for the payload"
fi

# --------------------------------------------------- measurement 3: syscall loop
if [ -x "$T/syspay" ]; then
    for v in $VARIANTS; do
        if [ -z "$ZAPPER" ] && [ "$v" != baseline ] && [ "$v" != pmask ] && [ "$v" != pmask-detach ]; then
            echo "SYSCALL variant=$v SKIP no zapper"
            continue
        fi
        round=0
        vals=""
        while [ "$round" -lt "$ROUNDS" ]; do
            round=$((round + 1))
            out="$T/y$v.$round.out"
            variant_run "$v" "$T/syspay" "$N_SYSCALL" >"$out" 2>&1 || true
            ns=$(sed -n 's/^PAYLOAD ns=\([0-9]*\).*/\1/p' "$out" | head -1)
            if [ -z "$ns" ]; then
                echo "SYSCALL variant=$v round=$round FAILED no payload timing: $(tr '\n' '|' <"$out")"
                continue
            fi
            printf 'SYSCALL variant=%s round=%s n=%s total_us=%s per_call_ns=%s\n' \
                "$v" "$round" "$N_SYSCALL" "$(( ns / 1000 ))" "$(( ns / N_SYSCALL ))"
            vals="$vals $(( ns / 1000 ))"
        done
        [ -n "$vals" ] || continue
        # shellcheck disable=SC2086
        set -- $vals
        med=$(printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{ if(NR%2) print a[(NR+1)/2]; else print int((a[NR/2]+a[NR/2+1])/2) }')
        sp=$(spread_of "$@")
        flag=""
        [ "$sp" -gt 30 ] && flag=" UNSTABLE"
        printf 'SYSCALL-MEDIAN variant=%s total_us=%s spread_pct=%s%s\n' "$v" "$med" "$sp" "$flag"
    done
else
    echo "SKIP syscall loop: no C compiler for the payload"
fi

# ------------------------------------------------ measurement 4: build job
# A real workload: compile and link a small C file three times inside the
# supervised tree.  The three rows above use a trivial payload; this is
# the second payload class the goal asks for.
if [ "$DATE_NS" = yes ] && [ -n "$CC" ]; then
    printf 'int main(void) { return 0; }\n' >"$T/build.c"
    cat >"$T/buildpay.sh" <<'EOF'
#!/bin/sh
cc=$1; out=$2; src=$3; i=0
while [ "$i" -lt 3 ]; do
    "$cc" -O0 -o "$out" "$src" || exit 1
    i=$((i + 1))
done
EOF
    chmod +x "$T/buildpay.sh"
    for v in $VARIANTS; do
        if [ -z "$ZAPPER" ] && [ "$v" != baseline ] && [ "$v" != pmask ] && [ "$v" != pmask-detach ]; then
            echo "BUILD variant=$v SKIP no zapper"
            continue
        fi
        round=0
        vals=""
        while [ "$round" -lt "$ROUNDS" ]; do
            round=$((round + 1))
            t0=$(now_ns)
            variant_run "$v" /bin/sh "$T/buildpay.sh" "$CC" "$T/build.out" "$T/build.c" >/dev/null 2>&1
            rc=$?
            t1=$(now_ns)
            if [ "$rc" != 0 ]; then
                echo "BUILD variant=$v round=$round FAILED rc=$rc"
                continue
            fi
            ms=$(( (t1 - t0) / 1000000 ))
            printf 'BUILD variant=%s round=%s n=3 total_ms=%s\n' "$v" "$round" "$ms"
            vals="$vals $ms"
        done
        [ -n "$vals" ] || continue
        # shellcheck disable=SC2086
        set -- $vals
        med=$(printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{ if(NR%2) print a[(NR+1)/2]; else print int((a[NR/2]+a[NR/2+1])/2) }')
        sp=$(spread_of "$@")
        flag=""
        [ "$sp" -gt 30 ] && flag=" UNSTABLE"
        printf 'BUILD-MEDIAN variant=%s total_ms=%s spread_pct=%s%s\n' "$v" "$med" "$sp" "$flag"
    done
else
    echo "SKIP build job: no C compiler or no nanosecond clock"
fi

echo
echo "BENCH: OK"
exit 0
