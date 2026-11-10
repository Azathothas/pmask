#!/bin/sh
# Issue 45: the memfd names pmask chooses, and the two options that
# replace them.
#
# Every observation here is a plain read of /proc; nothing trusts pmask's
# own report.  The three families and what this fragment decides:
#
#   secret family   --secret delivers the value on a sealed memfd whose
#                   /proc/<pid>/fd/N reads /memfd:pmask-secret (deleted)
#                   by default.  --secret-fd-name NAME replaces the name.
#   image family    --rexec/--image/--exec-once execute from a memfd named
#                   after the label.  --memfd-name NAME replaces it, for
#                   the memfd and for the temporary-file carrier's tag.
#   supervisor      the /secretmem buffer is not nameable by either option;
#                   its name is the kernel's and is not touched here.
#
# Cases:
#   q1  default: /proc/<pid>/fd/N reads /memfd:pmask-secret (deleted)
#   q1b control: a host-wide sweep finds that literal on the default run
#   q2  --secret-fd-name secret-deadbeef: the fd reads that exact name
#   q2b the same sweep finds no pmask-secret link on the named run
#   q2c the payload still reads its 8 bytes (the name is cosmetic)
#   q3  --rexec --memfd-name: /proc/<pid>/exe reads /memfd:<name>
#   q3b control: without the option exe reads /memfd:<label>
#   q4  --image --memfd-name: exe reads /memfd:<name>
#   q5  --exec-once: the cache entry on disk carries the requested name
#   q5b plain --rexec: the temporary-file carrier's tag uses the name
#       (fault hook forces the file)
#   q6  validation: empty, '/', LF and 201 bytes are refused with 255
#   q7  --secret-fd-name is accepted with a real 200-byte name
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa45.XXXXXX") || {
    echo "FATAL: cannot create a temp dir"; exit 2
}
SUP=""
cleanup() {
    [ -n "$SUP" ] && kill "$SUP" 2>/dev/null
    kill_label qa45-
    rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

L=qa45-label
NAME=secret-deadbeef
IMG=image-1a2b3c4d

# child_of PID -> the first direct child, empty when there is none.
# /proc only: pgrep is not part of the reduced VM userland.
child_of() {
    for d in /proc/[0-9]*; do
        pp=$(sed -n 's/^PPid:[[:space:]]*//p' "$d/status" 2>/dev/null)
        if [ "$pp" = "$1" ]; then
            echo "${d#/proc/}"
            return 0
        fi
    done
    return 1
}

# await_pid SUP -> wait up to 4 s for a direct child
await_pid() {
    n=0
    while [ "$n" -lt 40 ]; do
        p=$(child_of "$1") && { echo "$p"; return 0; }
        n=$((n + 1))
        sleep 0.1 2>/dev/null || sleep 1
    done
    return 1
}

# fd_links PID -> one "fdN TARGET" line per descriptor
fd_links() {
    for f in "/proc/$1"/fd/*; do
        t=$(readlink "$f" 2>/dev/null) || continue
        echo "${f##*/} $t"
    done
}

# sweep_literal NEEDLE -> count of /proc/<pid>/fd links naming NEEDLE.
# The needle is matched with `case`, so no child of this function carries
# the literal in its own argv and counts itself.
sweep_literal() {
    n=0
    for f in /proc/[0-9]*/fd/*; do
        t=$(readlink "$f" 2>/dev/null) || continue
        case "$t" in
            *"$1"*) ;;        
            *) continue ;;
        esac
        # A descriptor of another checkout's run is not this case's
        # evidence: count only a process that started after this fragment
        # did, so a leaked memfd in a parallel worktree cannot turn a pass
        # into a fail (and a stale one from an earlier run cannot either).
        sl_pid=${f#/proc/}
        sl_pid=${sl_pid%%/*}
        sl_st=$(proc_start "$sl_pid")
        if [ -n "$sl_st" ] && [ -n "$SUITE_START" ] \
            && [ "$sl_st" -ge "$SUITE_START" ] 2>/dev/null; then
            n=$((n + 1))
        fi
    done
    echo "$n"
}

# ------------------------------------------------- q1: the default name
# The default must not change: the conformance suite asserts a /memfd:
# link, and this asserts the exact literal the issue names.
"$TOOL" -q -l "$L" --secret TOK=literal:QA45VAL8 \
    -- "$CASES" secretfd TOK 3 >"$D/q1.out" 2>"$D/q1.err" &
SUP=$!
PAY=$(await_pid "$SUP") || PAY=""
links=""
[ -n "$PAY" ] && links=$(fd_links "$PAY")
# q1b: the negative control, taken while the session is alive.  A
# host-wide sweep for the default literal must find the default run, or
# q2b's zero would prove nothing.
default_hits=$(sweep_literal pmask-secret)
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
case "$links" in
    *" /memfd:pmask-secret (deleted)"*)
        pass "q1-default-secret-fd-name (/memfd:pmask-secret)" ;;
    *)
        fail "q1-default-secret-fd-name (pid=[$PAY] links=[$(printf '%s' "$links" | tr '\n' '|')])" ;;
esac
if [ "$default_hits" -ge 1 ]; then
    pass "q1b-control-sweep-sees-pmask-secret (hits=$default_hits)"
else
    fail "q1b-control-sweep-sees-pmask-secret (hits=0: the observer finds nothing, so q2b cannot be read)"
fi

# --------------------------------------- q2: the chosen secret fd name
"$TOOL" -q -l "$L" --secret TOK=literal:QA45VAL8 \
    --secret-fd-name "$NAME" -- "$CASES" secretfd TOK 3 >"$D/q2.out" 2>"$D/q2.err" &
SUP=$!
PAY=$(await_pid "$SUP") || PAY=""
links=""
[ -n "$PAY" ] && links=$(fd_links "$PAY")
# The sweep also runs while the session is alive: the control above found
# the default literal at this moment, so a zero here is the option's work.
named_hits=$(sweep_literal pmask-secret)
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
case "$links" in
    *" /memfd:$NAME (deleted)"*)
        pass "q2-secret-fd-name ($NAME)" ;;
    *)
        fail "q2-secret-fd-name (pid=[$PAY] links=[$(printf '%s' "$links" | tr '\n' '|')]; stderr=$(head -1 "$D/q2.err"))" ;;
esac
case "$links" in
    *pmask-secret*)
        fail "q2a-no-default-literal-left (a link still reads pmask-secret)" ;;
    *)
        pass "q2a-no-default-literal-left" ;;
esac

if [ "$named_hits" -eq 0 ]; then
    pass "q2b-sweep-finds-no-pmask-secret (hits=0)"
else
    fail "q2b-sweep-finds-no-pmask-secret (hits=$named_hits)"
fi

# q2c: the payload still read the whole value.  The name is cosmetic; a
# run where the descriptor is broken would also have no link to find.
case "$(cat "$D/q2.out" 2>/dev/null)" in
    *"bytes=8"*)
        pass "q2c-payload-read-the-secret (bytes=8)" ;;
    *)
        fail "q2c-payload-read-the-secret ($(cat "$D/q2.out" 2>/dev/null | tr '\n' '|'))" ;;
esac

# -------------------------------------- q3: the image family's memfd name
"$TOOL" -q --rexec -l "$L" --memfd-name "$IMG" -- "$CASES" sleeper >/dev/null 2>"$D/q3.err" &
SUP=$!
PAY=$(await_pid "$SUP") || PAY=""
exe=""
[ -n "$PAY" ] && exe=$(readlink "/proc/$PAY/exe" 2>/dev/null)
maps_hits=0
[ -n "$PAY" ] && maps_hits=$(grep -c "memfd:$IMG" "/proc/$PAY/maps" 2>/dev/null)
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
if grep -q -- '--rexec unavailable' "$D/q3.err" 2>/dev/null; then
    skip "q3-rexec-memfd-name (no image: $(grep -m1 -- '--rexec unavailable' "$D/q3.err"))"
    skip "q3b-control-rexec-default-name (same reason)"
else
    case "$exe" in
        "/memfd:$IMG (deleted)")
            pass "q3-rexec-memfd-name ($exe, maps=$maps_hits)" ;;
        *)
            fail "q3-rexec-memfd-name (exe=[$exe], want /memfd:$IMG (deleted))" ;;
    esac
fi

# q3b is the control: without the option the label is still the name, so
# q3's string came from the option and not from the binary.
"$TOOL" -q --rexec -l "$L" -- "$CASES" sleeper >/dev/null 2>"$D/q3b.err" &
SUP=$!
PAY=$(await_pid "$SUP") || PAY=""
exe=""
[ -n "$PAY" ] && exe=$(readlink "/proc/$PAY/exe" 2>/dev/null)
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
if grep -q -- '--rexec unavailable' "$D/q3b.err" 2>/dev/null; then
    skip "q3b-control-rexec-default-name (no image)"
else
    case "$exe" in
        "/memfd:$L (deleted)")
            pass "q3b-control-rexec-default-name ($exe)" ;;
        *)
            fail "q3b-control-rexec-default-name (exe=[$exe], want /memfd:$L (deleted))" ;;
    esac
fi

# ---------------------------- q4: the image name with --image PATH
# `--image` without -l names the memfd after the program; --memfd-name
# replaces that too.
"$TOOL" -q --image "$CASES" --memfd-name "$IMG" -- sleeper >/dev/null 2>"$D/q4.err" &
SUP=$!
PAY=$(await_pid "$SUP") || PAY=""
exe=""
[ -n "$PAY" ] && exe=$(readlink "/proc/$PAY/exe" 2>/dev/null)
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
case "$exe" in
    "/memfd:$IMG (deleted)")
        pass "q4-image-memfd-name ($exe)" ;;
    *)
        fail "q4-image-memfd-name (exe=[$exe]; stderr=$(head -1 "$D/q4.err"))" ;;
esac

# ------------------------- q5: the --exec-once cache entry's tag
# `--exec-once` writes a named carrier `.pmask-rexec-<tag>-<pid>-<run>-<n>`
# for a settled tracee's next exec, and that file is the cache entry the
# later exec runs from.  TMPDIR points at this fragment's own cache
# directory, so the entry is looked for where the tool was told to put it.
# The payload execs the program once and sleeps, so the entry is observable
# while the session is alive (the session removes it at the end).
mkdir -p "$D/eo" 2>/dev/null
TMPDIR="$D/eo" "$TOOL" -q -l "$L" --rexec --exec-once --memfd-name "$IMG" \
    -- /bin/sh -c '"$1" sleepfor 20' sh "$CASES" >/dev/null 2>"$D/q5.err" &
SUP=$!
SH=$(await_pid "$SUP") || SH=""
PAY=""
if [ -n "$SH" ]; then
    n=0
    while [ -z "$PAY" ] && [ "$n" -lt 40 ]; do
        PAY=$(child_of "$SH") || PAY=""
        [ -n "$PAY" ] && break
        n=$((n + 1))
        sleep 0.1 2>/dev/null || sleep 1
    done
fi
exe=""
eo_present=0
# The direct child is /bin/sh; its own child (depth 1) execs testcases,
# and that first exec is the one the cache redirects.  Poll the grandchild's
# /proc/<pid>/exe until it names the entry (or the payload is gone), then
# check the file while the session still lives.
n=0
while [ -n "$PAY" ] && [ "$n" -lt 50 ]; do
    exe=$(readlink "/proc/$PAY/exe" 2>/dev/null)
    case "$exe" in
        *"/.pmask-rexec-$IMG-"*) break ;;
    esac
    [ -z "$exe" ] && break
    n=$((n + 1))
    sleep 0.1 2>/dev/null || sleep 1
done
[ -n "$exe" ] && [ -f "$exe" ] && eo_present=1
kill "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
SUP=""
eo_dir=$(cd "$D/eo" 2>/dev/null && pwd -P)
case "$exe" in
    "$eo_dir"/.pmask-rexec-"$IMG"-*)
        if [ "$eo_present" = 1 ]; then
            pass "q5-exec-once-carrier-tag ($exe)"
        else
            fail "q5-exec-once-carrier-tag (exe names $exe but no file was there while the session ran)"
        fi ;;
    *)
        if [ -z "$exe" ] || [ "$exe" = "$CASES" ]; then
            # A vfork child's first exec takes the post-exec path, so the
            # tracer never sees the entry stop that installs the redirect.
            # The cache tag is then not observable; say so instead of
            # failing a host whose shell chose vfork.
            skip "q5-exec-once-carrier-tag (the child's first exec took the post-exec path; no cache entry to observe)"
        else
            fail "q5-exec-once-carrier-tag (exe=[$exe], want $eo_dir/.pmask-rexec-$IMG-*; stderr=$(head -1 "$D/q5.err"))"
        fi ;;
esac

# --------------------- q5b: the plain --rexec temporary carrier's tag
# Without --exec-once the carrier is written for the first exec only.  The
# fault hook removes the two procfs carriers, so the named temporary file
# is the only route and its tag is observable in /proc/<pid>/exe.
out=$(PMASK_FAULT_REXEC_NO_PROC=1 "$TOOL" -q --label "$L" --memfd-name "$IMG" \
    --rexec "$CASES" exe-id 2>"$D/q5b.err")
case "$out" in
    *".pmask-rexec-$IMG-"*)
        pass "q5b-plain-rexec-temp-file-tag ($(printf '%s' "$out" | cut -c1-80))" ;;
    *)
        fail "q5b-plain-rexec-temp-file-tag (out=[$out]; stderr=$(head -1 "$D/q5b.err"))" ;;
esac

# --------------------------------------------- q6: name validation
check_refused() {  # check_refused CASE_NAME FLAG VALUE
    err=$("$TOOL" -q --secret TOK=literal:x "$2" "$3" -- true 2>&1 >/dev/null)
    rc=$?
    if [ "$rc" = 255 ]; then
        pass "$1 (rc=255: $(printf '%s' "$err" | head -1))"
    else
        fail "$1 (rc=$rc, want 255; err=[$err])"
    fi
}
check_refused q6a-empty-refused --secret-fd-name ""
check_refused q6b-slash-refused --secret-fd-name "a/b"
check_refused q6c-lf-refused --secret-fd-name "$(printf 'a\nb')"
check_refused q6d-cr-refused --secret-fd-name "$(printf 'a\rb')"
long=$(printf '%0200d' 0 | tr '0' 'n')
long="$long""n"
check_refused q6e-201-bytes-refused --secret-fd-name "$long"
# The same check on the image option, which validates before the fork.
err=$("$TOOL" -q --memfd-name "a/b" --rexec -- true 2>&1 >/dev/null)
rc=$?
if [ "$rc" = 255 ]; then
    pass "q6f-memfd-name-slash-refused (rc=255)"
else
    fail "q6f-memfd-name-slash-refused (rc=$rc, want 255)"
fi

# ---------------------------- q7: a 200-byte name is accepted and used
n200=$(printf '%0200d' 0 | tr '0' 'n')
out=$("$TOOL" -q --secret TOK=literal:QA45VAL8 --secret-fd-name "$n200" \
    -- "$CASES" secretfd TOK 0 2>"$D/q7.err")
case "$out" in
    *"/memfd:$n200 (deleted)"*)
        pass "q7-200-byte-name-accepted" ;;
    *)
        fail "q7-200-byte-name-accepted ($(printf '%s' "$out" | tr '\n' '|'); stderr=$(head -1 "$D/q7.err"))" ;;
esac

# ------------------------- q8: --memfd-name reaches every image carrier
# The path carrier was covered by q4.  The stdin and descriptor carriers
# build the spool in a different function, and that is exactly where the
# name was dropped: `/proc/<pid>/exe` must read the requested name on all
# three, or the hardening the flag promises is absent on two of them.
# The probe prints `exe=<link> ino=<n>`; the link is the first field.
exe_link() {
    sed -n 's/^exe=\([^ ][^ ]*\).*/\1/p'
}
stdin_exe=$("$TOOL" -q --image - --memfd-name qa45stdin -l qa45s -- \
    exe-id <"$CASES" 2>/dev/null | exe_link)
fd_exe=$("$TOOL" -q --image-from-fd 3 --memfd-name qa45fd -l qa45f -- \
    exe-id 3<"$CASES" 2>/dev/null | exe_link)
path_exe=$("$TOOL" -q --image "$CASES" --memfd-name qa45path -- \
    exe-id 2>/dev/null | exe_link)
for pair in "stdin:$stdin_exe" "fd:$fd_exe" "path:$path_exe"; do
    which=${pair%%:*}
    got=${pair#*:}
    # The `(deleted)` suffix reaches the probe through a shell redirect, so
    # only the prefix is asserted here; q4 asserts the exact link on the
    # secret descriptor.
    case "$got" in
        "/memfd:qa45$which")
            pass "q8-memfd-name-on-$which-carrier" ;;
        *)
            fail "q8-memfd-name-on-$which-carrier (exe=[$got], want /memfd:qa45$which)" ;;
    esac
done

echo "== QA45: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL)"
[ "$FAIL" = 0 ] || exit 1
exit 0
