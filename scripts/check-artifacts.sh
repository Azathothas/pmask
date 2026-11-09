#!/bin/sh
# Report the on-disk footprint pmask leaves, and say what each artefact
# means.  Exit 0 whenever the report could be produced; a finding is in the
# report, not in the exit status.
#
# This exists because a triage that only lists processes misses everything
# here: the store and its lock and its directory, the daemon socket, the
# agent socket, the exec-once carrier under /dev/shm, the live memfd names
# and the release binary's own ELF metadata.  Issue #54 filed the footprint
# and the release binary's `.comment` fingerprint; this script is the
# working instrument for both, so a later change can be measured instead of
# argued about.
#
# Usage:
#   sh scripts/check-artifacts.sh                 # this host, this tree
#   sh scripts/check-artifacts.sh BINARY...       # also fingerprint binaries
#
# Environment honoured, same as pmask itself:
#   PMASK_STORE                store path
#   XDG_DATA_HOME              default store directory's parent
#   XDG_RUNTIME_DIR            default socket directory
#
# Exit: 0 on a produced report; 2 on a setup error.
set -u
cd "$(dirname "$0")/.." || exit 2

uid=$(id -u 2>/dev/null || echo unknown)

say() { printf '%s\n' "$*"; }
row() { printf '  %-26s %s\n' "$1" "$2"; }

# mode_and_size PATH -> prints "MODE SIZE" or "absent".
# A named variable rather than positional parameters: `set --` inside a
# report loop would clobber the caller's own arguments and `$1`.
MS_RESULT=""
mode_and_size() {
    if [ -e "$1" ]; then
        ms_mode=$(stat -c '%a' "$1" 2>/dev/null || echo '?')
        ms_size=$(stat -c '%s' "$1" 2>/dev/null || echo '?')
        MS_RESULT="$ms_mode $ms_size"
    else
        MS_RESULT="absent"
    fi
}
mode_of() {
    mode_and_size "$1"
    printf '%s' "${MS_RESULT%% *}"
}
size_of() {
    mode_and_size "$1"
    printf '%s' "${MS_RESULT##* }"
}

# file_magic PATH -> the first 16 bytes with non-printables escaped.
# The store's magic is `PMASKSTORE1` plus five NULs, so an all-printable
# rendering would hide the interesting part.
file_magic() {
    if [ ! -f "$1" ]; then
        return 0
    fi
    od -A n -t x1 -N 16 "$1" 2>/dev/null | tr -s ' \n' '  ' | sed 's/^ *//; s/ *$//'
}

# magic_is_store PATH -> 0 when the first 12 bytes are PMASKSTORE1
magic_is_store() {
    [ -f "$1" ] || return 1
    fm_head=$(head -c 12 "$1" 2>/dev/null)
    [ "$fm_head" = "PMASKSTORE1" ]
}

say "pmask on-disk footprint"
say "  uid=$uid host=$(uname -sr) date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
say ""

# ------------------------------------------------------------------ store
# `pmask store path` is the binary's own answer, which is the only one
# that cannot drift from the code.  It needs a binary; fall back to the
# documented default when one is not built.
say "store"
store_path=""
if [ -x target/release/pmask ]; then
    store_path=$(target/release/pmask store path 2>/dev/null | head -1)
elif [ -x tests/pmask ]; then
    store_path=$(tests/pmask store path 2>/dev/null | head -1)
fi
if [ -z "$store_path" ]; then
    store_path="${PMASK_STORE:-${XDG_DATA_HOME:-$HOME/.local/share}/pmask/store.enc}"
    row "source" "default path (no pmask binary to ask)"
else
    row "source" "pmask store path"
fi
row "path" "$store_path"
row "mode size" "$(mode_of "$store_path") $(size_of "$store_path")"
if [ -f "$store_path" ]; then
    row "magic hex" "$(file_magic "$store_path")"
    if magic_is_store "$store_path"; then
        row "magic" "PMASKSTORE1 (an encrypted store)"
    else
        row "magic" "NOT a store: no PMASKSTORE1 prefix"
        if [ "$(size_of "$store_path")" = 0 ]; then
            row "verdict" "a zero-byte file: this is the #23 tmpfiles defect; pmask store init refuses it"
        fi
    fi
else
    row "magic" "no file, so nothing to read"
fi
store_dir=$(dirname "$store_path")
row "directory mode" "$(mode_of "$store_dir")"
lock="$store_path.lock"
row "lock mode size" "$(mode_of "$lock") $(size_of "$lock")"
if [ -e "$lock" ]; then
    row "lock meaning" "a writer holds it or left it behind; flock, not a pid file"
fi
say ""

# ----------------------------------------------------------------- sockets
say "sockets"
runtime="${XDG_RUNTIME_DIR:-/run/user/$uid}"
row "daemon default" "$runtime/pmask.sock"
row "daemon as root" "/run/pmask.sock"
row "agent" "--socket PATH, default $runtime/pmask.sock"
if [ -d "$runtime" ]; then
    found=""
    for s in "$runtime"/*.sock /run/pmask.sock /run/pmask/*.sock; do
        [ -e "$s" ] || continue
        # -S on a live socket, -e for a stale name whose inode holder is
        # gone; the distinction is the finding, so it is printed.
        if [ -S "$s" ]; then
            found="$found
  $(mode_of "$s") $(size_of "$s")  live-socket  $s"
        else
            found="$found
  stale-name  $s"
        fi
    done
    if [ -n "$found" ]; then
        say "  present:"
        printf '%s\n' "$found" | sed '/^$/d'
    else
        row "present" "none"
    fi
else
    row "present" "$runtime does not exist"
fi
unix_rows=""
if [ -r /proc/net/unix ]; then
    unix_rows=$(awk 'NR > 1 { print $NF }' /proc/net/unix 2>/dev/null | grep -i pmask | sort -u)
fi
if [ -n "$unix_rows" ]; then
    row "/proc/net/unix" "$(printf '%s' "$unix_rows" | tr '\n' ' ')"
else
    row "/proc/net/unix" "no pmask entry"
fi
say ""

# ------------------------------------------------------------- live memfds
# The image and secret descriptors exist only while a session runs.  They
# are read from /proc/<pid>/exe and /proc/<pid>/fd, which is the only
# place they are visible at all.
#
# Only processes of this uid are listed: /proc/<pid>/fd of another uid is
# unreadable anyway, and a host-wide sweep of every pid's fd table is both
# slow and noise.  A root run sees everything, which is the point of
# running it as root once.
say "live memfd names"
memfd_rows=""
for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    [ "$pid" = "$$" ] && continue
    [ "$(sed -n 's/^Uid:[[:space:]]*\([0-9]*\).*/\1/p' "$d/status" 2>/dev/null)" = "$uid" ] || continue
    exe=$(readlink "$d/exe" 2>/dev/null)
    case "$exe" in
        /memfd:*) memfd_rows="$memfd_rows
  pid=$pid exe=$exe" ;;
    esac
    for f in "$d"/fd/*; do
        tgt=$(readlink "$f" 2>/dev/null)
        case "$tgt" in
            /memfd:pmask-secret*|/secretmem*)
                memfd_rows="$memfd_rows
  pid=$pid fd=${f##*/} -> $tgt" ;;
        esac
    done
done
if [ -n "$memfd_rows" ]; then
    printf '%s\n' "$memfd_rows" | sed '/^$/d'
else
    row "present" "none (no live pmask session of uid $uid)"
fi
say ""

# ---------------------------------------------------------- exec-once files
say "exec-once carrier"
carrier=""
for d in /dev/shm/.pmask-rexec-* /tmp/.pmask-rexec-*; do
    [ -e "$d" ] || continue
    carrier="$carrier
  $(mode_of "$d") $(size_of "$d") $d"
done
if [ -n "$carrier" ]; then
    printf '%s\n' "$carrier" | sed '/^$/d'
    row "meaning" "a live session; the file is removed at session end"
else
    row "present" "none (transient: only a live session has one)"
fi
say ""

# ------------------------------------------------------------- tmpfiles/sysusers
say "packaging"
row "tmpfiles" "contrib/tmpfiles.d/pmask.conf"
if [ -f contrib/tmpfiles.d/pmask.conf ]; then
    for line in d f w; do
        # grep -c prints 0 and exits 1 when nothing matches; `|| true` keeps
        # the command substitution from printing a second line.
        hits=$(grep -cE "^[[:space:]]*$line[+!]?[[:space:]]+/var/lib/pmask" contrib/tmpfiles.d/pmask.conf 2>/dev/null || true)
        row "  '$line' lines" "${hits:-0}"
    done
    if grep -Eq '^[[:space:]]*f[+!]?[[:space:]]+/var/lib/pmask/store\.enc' contrib/tmpfiles.d/pmask.conf; then
        row "  verdict" "an f line pre-creates store.enc: issue #23 is back"
    else
        row "  verdict" "no f line; store init creates the file itself"
    fi
fi
row "sysusers" "contrib/sysusers.d/pmask.conf"
if [ -f contrib/sysusers.d/pmask.conf ]; then
    row "  creates" "$(grep -E '^[[:space:]]*u[[:space:]]' contrib/sysusers.d/pmask.conf 2>/dev/null | tr '\n' ' ')"
fi
say ""

# --------------------------------------------------------------- binaries
# The ELF fingerprint from issue #54.  Two facts are reported, not judged:
# whether a `.comment` names the toolchain, and which pmask strings a YARA
# rule would key on.  No build has to exist for the report to be useful.
say "release binary fingerprint"
if [ "$#" -eq 0 ]; then
    bin_list=""
    for b in target/x86_64-unknown-linux-musl/release/pmask \
        target/x86_64-unknown-linux-musl/release/pmaskd \
        target/release/pmask target/release/pmaskd; do
        [ -f "$b" ] && bin_list="$bin_list $b"
    done
else
    bin_list="$*"
fi
if [ -z "$bin_list" ]; then
    row "binaries" "none built (cargo build --release --bins)"
else
    for b in $bin_list; do
        say "  $b"
        if [ ! -f "$b" ]; then
            row "  state" "missing"
            continue
        fi
        row "  mode size" "$(mode_of "$b") $(size_of "$b")"
        if command -v readelf >/dev/null 2>&1; then
            elf_class=$(readelf -h "$b" 2>/dev/null | sed -n 's/^ *Type: *//p' | head -1)
            row "  elf type" "${elf_class:-unknown}"
            if readelf -d "$b" 2>/dev/null | grep -q NEEDED; then
                row "  linkage" "dynamic"
            else
                row "  linkage" "static"
            fi
            if readelf -S "$b" 2>/dev/null | grep -q '\.comment'; then
                row "  .comment" "present"
                cmt=$(readelf -p .comment "$b" 2>/dev/null | sed -n 's/^ *\[[^]]*\] *//p' | tr '\n' ';' | sed 's/;$//')
                row "    contents" "$cmt"
            else
                row "  .comment" "absent (no toolchain string to key on)"
            fi
            if readelf -n "$b" 2>/dev/null | grep -q 'Build ID'; then
                row "  build id" "present"
            else
                row "  build id" "absent"
            fi
        else
            row "  readelf" "not installed, ELF metadata not read"
        fi
        if command -v strings >/dev/null 2>&1; then
            hits=0
            for s in "pmask capability report" PMASKSTORE1 "pmask audit: residue: " \
                PMASK_NO_SELFMASK pmask-secret "pmaskd: job refused: "; do
                strings "$b" 2>/dev/null | grep -Fq -- "$s" && hits=$((hits + 1))
            done
            row "  pmask strings" "$hits of 6 (a YARA rule needs 3 plus the .comment)"
        fi
    done
fi
say ""

say "== ARTIFACTS: report complete =="
exit 0
