#!/bin/sh
# Shared helpers for the pmask test suites.
#
# Observers are /proc-first (that IS the ground truth `ps` reads) and the
# helpers only need busybox-grade tools, so the suites run identically on
# a full host and inside a minimal initramfs VM.

# The QEMU guest under TCG is much slower than the host.  A suite that
# waits for a process to appear reads this to scale its deadline.
VM_TCG=0
case "$(cat /proc/cmdline 2>/dev/null)" in
    *pmask.accel=tcg*) VM_TCG=1 ;;
esac

# suites `cd` to their own directory before sourcing this file
BIN_DIR="$(pwd)"
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"

# ---------------------------------------------------------------- scanning

# sightings MARKER
# Count processes whose /proc cmdline, environ or comm contain MARKER.
# Excludes our own shell and the observer itself.  The match is a shell
# `case` over `tr` output, so no child of this function carries MARKER in
# its argv: a `grep -F -- "$MARKER"` process used to count itself through
# its own /proc/<pid>/cmdline.
sightings() {
    m="$1"
    n=0
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        [ "$pid" = "$$" ] && continue
        for f in cmdline environ comm; do
            # The subshell carries the redirect, so an unreadable file
            # (/proc/<pid>/environ of another uid) does not print a shell
            # diagnostic that a reader could mistake for a finding.
            if ( tr '\0' '\n' < "$d/$f" ) 2>/dev/null | {
                found=0
                while IFS= read -r line || [ -n "$line" ]; do
                    case "$line" in
                        *"$m"*) found=1; break ;;
                    esac
                done
                [ "$found" = 1 ]
            }; then
                n=$((n + 1))
                break
            fi
        done
    done
    # ps reads the same /proc data, so adding its count to a non-zero
    # /proc count counts one process twice.  It is a fallback for a host
    # whose /proc scan found nothing, not a second observer.
    if [ "$n" = 0 ] && command -v ps >/dev/null 2>&1; then
        pn=$(ps -e -o args= 2>/dev/null | {
            c=0
            while IFS= read -r line || [ -n "$line" ]; do
                case "$line" in
                    *"$m"*) c=$((c + 1)) ;;
                esac
            done
            echo "$c"
        })
        n=$((n + ${pn:-0}))
    fi
    echo "$n"
}

# watch MARKER SECONDS
# Sample repeatedly; sets SEE to the max sighting count, stops early on
# the first sighting.
watch() {
    m="$1"; secs="$2"
    SEE=0
    end=$(( $(date +%s 2>/dev/null || echo 0) + secs ))
    while :; do
        s=$(sightings "$m")
        [ "$s" -gt "$SEE" ] && SEE=$s
        [ "$SEE" -gt 0 ] && break
        now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$now" -ge "$end" ] && break
        sleep 0.05 2>/dev/null || sleep 1
    done
}

# comm_count PREFIX
# Number of processes whose comm starts with PREFIX.  The prefix is
# matched literally (`${c#"$p"}`), not as a glob: labels such as
# `[kworker/1:2-rcu_gp]` carry `[`, which a `case` pattern would read as
# a bracket expression.
comm_count() {
    p="$1"
    n=0
    for c in /proc/[0-9]*/comm; do
        cc=$(cat "$c" 2>/dev/null)
        [ "${cc#"$p"}" != "$cc" ] && n=$((n + 1))
    done
    # Same reason as sightings: ps reports the same comm, so adding it to a
    # non-zero /proc count counts one process twice.
    if [ "$n" = 0 ] && command -v ps >/dev/null 2>&1; then
        pn=$(ps -e -o comm= 2>/dev/null | awk -v p="$p" 'index($0, p) == 1' | wc -l | tr -d ' ')
        n=$((n + pn))
    fi
    echo "$n"
}

# ------------------------------------------------------- scoped cleanup
# kill_comm only touches processes that belong to this suite run.
# PMASK_TEST_GLOBAL_KILL=1 restores the machine-wide comm-prefix kill
# (disposable VMs and containers only).

MY_UID=$(id -u 2>/dev/null || echo 0)

proc_ppid() {  # pid -> parent pid (empty when the process is gone)
    sed -n 's/^PPid:[[:space:]]*\([0-9]*\).*/\1/p' "/proc/$1/status" 2>/dev/null
}

proc_uid() {  # pid -> real uid
    sed -n 's/^Uid:[[:space:]]*\([0-9]*\).*/\1/p' "/proc/$1/status" 2>/dev/null
}

proc_start() {  # pid -> start time in clock ticks (stat field 22)
    # strip "pid (comm) " up to the last ") "; the state is then field 1
    sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f20
}

# start time of this shell: no process of this run started earlier
SUITE_START=$(proc_start $$)
[ -n "$SUITE_START" ] || SUITE_START=0

# in_suite_scope PID
# True when PID descends from this shell (PPid walk, at most 16 hops).
# A double-forked daemon is reparented to init, so a chain that ends at
# pid 1 is attributed by its topmost process: same uid and started after
# this shell.  Two suites of one uid running at the same time can see
# each other's orphans; that is the documented limit of the scoped mode.
in_suite_scope() {
    sc_p="$1"; sc_d=0
    while [ "$sc_d" -lt 16 ]; do
        sc_pp=$(proc_ppid "$sc_p")
        [ -n "$sc_pp" ] || return 1
        [ "$sc_pp" = "$$" ] && return 0
        if [ "$sc_pp" -le 1 ]; then
            [ "$(proc_uid "$sc_p")" = "$MY_UID" ] || return 1
            sc_st=$(proc_start "$sc_p")
            [ -n "$sc_st" ] || return 1
            [ "$sc_st" -ge "$SUITE_START" ]
            return
        fi
        sc_p="$sc_pp"
        sc_d=$((sc_d + 1))
    done
    return 1
}

# kill_comm PREFIX [SIGNAL]
kill_comm() {
    p="$1"; sig="${2:-KILL}"
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        [ "$pid" = "$$" ] && continue
        case "$(cat "$d/comm" 2>/dev/null)" in
            "$p"*)
                if [ "${PMASK_TEST_GLOBAL_KILL:-0}" = 1 ] || in_suite_scope "$pid"; then
                    kill -"$sig" "$pid" 2>/dev/null
                fi
                ;;
        esac
    done
}

# kill_label PREFIX
# SIGKILL every process whose comm starts with PREFIX, without the
# in_suite_scope check.  A masked payload keeps the label as its comm and
# is reparented away from this shell when its supervisor exits, so the
# scope walk cannot attribute it and kill_comm leaves it running.  The
# label is unique to the suite that chose it, which is what makes the
# unscoped kill safe.
kill_label() {
    p="$1"
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        [ "$pid" = "$$" ] && continue
        c=$(cat "$d/comm" 2>/dev/null)
        [ "${c#"$p"}" != "$c" ] || continue
        kill -9 "$pid" 2>/dev/null
    done
}

# comm_exe_count COMM-PREFIX EXE-BASENAME
# Processes whose comm starts with COMM-PREFIX and whose /proc/<pid>/exe
# names EXE-BASENAME.  Liveness that cannot be satisfied by the
# supervisor itself carrying the label.
comm_exe_count() {
    p="$1"; exe="$2"; n=0
    for d in /proc/[0-9]*; do
        case "$(cat "$d/comm" 2>/dev/null)" in
            "$p"*)
                case "$(readlink "$d/exe" 2>/dev/null)" in
                    */"$exe") n=$((n + 1)) ;;
                esac
                ;;
        esac
    done
    echo "$n"
}

# wait_comm_exe COMM-PREFIX EXE-BASENAME WANT SECONDS
# Poll until comm_exe_count reaches WANT; prints the last count.
wait_comm_exe() {
    end=$(( $(date +%s 2>/dev/null || echo 0) + $4 ))
    while :; do
        n=$(comm_exe_count "$1" "$2")
        [ "$n" -ge "$3" ] && break
        now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$now" -ge "$end" ] && break
        sleep 0.1 2>/dev/null || sleep 1
    done
    echo "$n"
}

# environ_hits MARKER
# Count processes whose /proc environ contains MARKER (own shell excluded).
environ_hits() {
    m="$1"; n=0
    for d in /proc/[0-9]*; do
        [ "${d#/proc/}" = "$$" ] && continue
        if cat "$d/environ" 2>/dev/null | tr '\0' ' ' | grep -qF -- "$m"; then
            n=$((n + 1))
        fi
    done
    echo "$n"
}

# unique marker for this run
fresh_marker() {
    dd if=/dev/urandom bs=6 count=1 2>/dev/null | base64 2>/dev/null | tr -dc 'a-zA-Z0-9'
    echo -n ""
}

# ---------------------------------------------------------------- binaries
# refresh_bins: make tests/{pmask,pmaskd,testcases,protocases} current.
#   1. TESTBIN_DIR set: copy the prebuilt binaries from there.
#   2. cargo present: always run `cargo build --release --bins --features testbins` (a no-op
#      when fresh) and copy; cargo decides what is stale.
#   3. otherwise (the VM): use the binaries already in this directory.
# Returns 1 with a FATAL line when a required binary is missing.
# Each copy lands by rename, so a running tracee keeps the old inode and
# the copy does not fail with ETXTBSY.
BIN_PAIRS="pmask:pmask pmaskd:pmaskd pmask-testcases:testcases pmask-protocases:protocases"

# Install SRC at DST by renaming over it.  A running tracee keeps the old
# inode open, so writing DST in place fails with ETXTBSY; rename replaces
# the directory entry and leaves the running process on the old inode.
install_bin() {
    ib_tmp="$BIN_DIR/.$2.$$"
    cp -p "$1" "$ib_tmp" || { rm -f "$ib_tmp"; return 1; }
    mv -f "$ib_tmp" "$BIN_DIR/$2" || { rm -f "$ib_tmp"; return 1; }
}

refresh_bins() {
    root="$BIN_DIR/.."
    if [ -n "${TESTBIN_DIR:-}" ]; then
        for pair in $BIN_PAIRS; do
            # TESTBIN_DIR may use the cargo names or the tests/ names
            cargo_name=${pair%%:*}; dst=${pair##*:}
            src=""
            [ -x "$TESTBIN_DIR/$dst" ] && src="$TESTBIN_DIR/$dst"
            [ -z "$src" ] && [ -x "$TESTBIN_DIR/$cargo_name" ] && src="$TESTBIN_DIR/$cargo_name"
            [ -n "$src" ] || continue
            [ "$src" -ef "$BIN_DIR/$dst" ] && continue
            install_bin "$src" "$dst" || return 1
        done
        [ -x "$TESTBIN_DIR/testcases32" ] && install_bin "$TESTBIN_DIR/testcases32" testcases32
    elif command -v cargo >/dev/null 2>&1 && [ -f "$root/Cargo.toml" ]; then
        (cd "$root" && cargo build --release --bins --features testbins) \
            || { echo "FATAL: cargo build failed" >&2; return 1; }
        for pair in $BIN_PAIRS; do
            src=${pair%%:*}; dst=${pair##*:}
            [ -x "$root/target/release/$src" ] || continue
            install_bin "$root/target/release/$src" "$dst" || return 1
        done
        # Cargo decides what is stale.  A per-binary mtime comparison
        # against every src/*.rs file is wrong: pmaskd does not depend
        # on src/main.rs, so editing the CLI made the daemon look stale
        # and the gate refused to run.
    fi
    for b in pmask pmaskd testcases; do
        if [ ! -x "$BIN_DIR/$b" ]; then
            echo "FATAL: $BIN_DIR/$b missing (no cargo, no TESTBIN_DIR)" >&2
            return 1
        fi
    done
    return 0
}

# require_bins: suites call this first.  run.sh has already refreshed the
# binaries and sets PMASK_BINS_READY=1 so each suite does not rebuild.
require_bins() {
    [ "${PMASK_BINS_READY:-0}" = 1 ] && return 0
    refresh_bins
}
