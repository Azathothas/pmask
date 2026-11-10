#!/bin/sh
# ============================================================================
# pmask conformance suite: one case per row of the honesty table.
#
# The table lives in README.md, section "What it is not", and in
# docs/DESIGN.md, section "Trust boundary".  Each row says what a given
# observer sees.  A case asserts that row, and a row this process cannot
# observe prints SKIP with the reason.  SKIP is never a pass.
#
#   args-hidden              /proc/<pid>/cmdline does not hold the canary
#   args-visible-control     the same canary IS visible without supervision
#   environ-hidden           /proc/<pid>/environ is empty
#   environ-keep-control     --keep-env=NAME keeps that name visible
#   comm-is-label            comm is the label cut to 15 bytes
#   comm-control             an unsupervised comm is the program name
#   ps-args-is-label         `ps -o pid,args=` prints the label
#   ps-args-control          `ps -o pid,args=` prints the real command
#   supervisor-selfmask      the holder's own cmdline is the label too
#   same-uid-exe-maps        a same-uid peer still reads exe, maps, fd, cwd
#   same-uid-environ-read    a same-uid peer reads environ without a secret
#   holder-environ-refused   a same-uid peer is refused the holder environ
#   payload-session          a secret session produced a payload at all
#   secret-absent            the value is in no /proc entry of the session
#   core-limit-zero          RLIMIT_CORE is 0 in the holder and the payload
#   core-limit-control       without a secret the inherited hard limit stays
#   secret-fd-is-memfd       the delivered descriptor is a sealed memfd
#   secret-fd-control        a plain file on the same fd has no seals
#   dumpable-default         PR_GET_DUMPABLE is 1 in the payload
#   dumpable-nodumpable      PR_GET_DUMPABLE is 0 with --no-dumpable
#   nodumpable-refuses       --no-dumpable refuses that peer the payload too
#   observer-other-uid       another uid sees the label (SKIP, needs root)
#   observer-root            root sees exe, maps and memory (SKIP, needs root)
#   observer-kernel          a kernel attacker sees everything (SKIP, by design)
#
# Every process the suite starts is killed on exit.  The exit status is
# non-zero only when a case fails.
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

# The suite needs an executable pmask.  When it is absent, build it the
# way refresh_bins does.  It does not re-copy an existing binary: a leftover
# process from an earlier run holds tests/pmask and the copy would fail
# with ETXTBSY, which says nothing about the code under test.
ensure_tool() {
    et_root="$BIN_DIR/.."
    if [ -x "$TOOL" ]; then
        return 0
    fi
    command -v cargo >/dev/null 2>&1 || return 1
    [ -f "$et_root/Cargo.toml" ] || return 1
    ( cd "$et_root" && cargo build --release --bins ) || return 1
    cp -p "$et_root/target/release/pmask" "$TOOL"
}

ensure_tool || {
    echo "CONFORMANCE: FAIL pass=0 fail=1 skip=0"
    echo "pmask: cannot build $TOOL" >&2
    exit 2
}
if [ ! -x "$TOOL" ]; then
    echo "CONFORMANCE: FAIL pass=0 fail=1 skip=0"
    exit 2
fi

T=/tmp/pmask-conformance.$$
mkdir -p "$T" || { echo "CONFORMANCE: FAIL pass=0 fail=1 skip=0"; exit 2; }

TPASS=0
TFAIL=0
TSKIP=0
TRACK=""
LABEL='cfm-conf'
CAN="CFMCONF-$(fresh_marker)-ARG"
[ -n "$CAN" ] || CAN="CFMCONF-fallback-$$"
SEC="CFMCONF-SECRET-$(fresh_marker)"
[ -n "$SEC" ] || SEC="CFMCONF-SECRET-fallback-$$"
HOLD=4

pass() { TPASS=$((TPASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { TFAIL=$((TFAIL + 1)); printf 'FAIL %s: %s\n' "$1" "$2"; }
skip() { TSKIP=$((TSKIP + 1)); printf 'SKIP %s: %s\n' "$1" "$2"; }

track() { TRACK="$TRACK $1"; }

cleanup() {
    for cp in $TRACK; do
        kill -9 "$cp" 2>/dev/null
    done
    kill_comm "$LABEL" KILL 2>/dev/null
    kill_comm cfm-conf KILL 2>/dev/null
    rm -rf "$T"
    :
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- helpers

# await_child SUPERVISOR LABEL -> pid of the direct child carrying LABEL.
#
# When no child carries the label but a child exists, a note naming the
# wrong child goes to $T/childnote, so the caller's failure text can say
# "a label is missing" instead of "a process is missing".  Those are
# different defects, and the message must not confuse them.  A file is used
# because the caller captures the pid with command substitution, which runs
# in a subshell where a variable assignment would not survive.
NOTE_FILE="$T/childnote"
: > "$NOTE_FILE"
noted() { printf '%s' "$1" > "$NOTE_FILE"; }
note_text() {
    if [ -s "$NOTE_FILE" ]; then
        cat "$NOTE_FILE"
    else
        printf 'no diagnostic'
    fi
}
await_child() {
    nc_label=""
    nc_any=""
    nc_n=0
    while [ "$nc_n" -lt 40 ]; do
        for nc_d in /proc/[0-9]*; do
            nc_p=${nc_d#/proc/}
            [ "$nc_p" = "$$" ] && continue
            nc_pp=$(sed -n 's/^PPid:[[:space:]]*//p' "$nc_d/status" 2>/dev/null)
            [ "$nc_pp" = "$1" ] || continue
            [ -z "$nc_any" ] && nc_any=$nc_p
            if [ -z "$nc_label" ] &&
                [ "$(cat "$nc_d/comm" 2>/dev/null)" = "$2" ]; then
                nc_label=$nc_p
            fi
        done
        if [ -n "$nc_label" ]; then
            : > "$NOTE_FILE"
            printf '%s' "$nc_label"
            return 0
        fi
        nc_n=$((nc_n + 1))
        sleep 0.05 2>/dev/null || sleep 1
    done
    if [ -n "$nc_any" ] && [ -d "/proc/$nc_any" ]; then
        noted "a direct child exists but does not carry the label: pid $nc_any, comm=[$(cat "/proc/$nc_any/comm" 2>/dev/null)] cmdline=[$(tr '\0' '|' < "/proc/$nc_any/cmdline" 2>/dev/null | cut -c1-60)]"
    else
        noted "the holder produced no child at all"
    fi
    return 1
}

# has PATH NEEDLE -> 0 when PATH holds NEEDLE, 1 when it does not, and 1
# when PATH cannot be opened at all.  Both callers only need "not present",
# and an unreadable file answers that.
has() {
    if ! ( : < "$1" ) 2>/dev/null; then
        return 1
    fi
    ( tr '\0\n' '\n\n' < "$1" | grep -q -- "$2" ) 2>/dev/null
}

# peer_read PID FILE -> exit status of a same-uid reader that is not an
# ancestor of PID.  setsid gives it a session of its own.  Without setsid
# this shell reads the file, which is only the grandparent, and the kernel
# applies the same PR_SET_DUMPABLE check to both.
peer_read() {
    if command -v setsid >/dev/null 2>&1; then
        setsid sh -c "cat /proc/$1/$2 >/dev/null 2>&1; exit \$?" 2>/dev/null
    else
        cat "/proc/$1/$2" >/dev/null 2>&1
    fi
}

# core_limits PID -> "soft hard" of RLIMIT_CORE in /proc/PID/limits, or
# "SKIP SKIP" when the file cannot be read
core_limits() {
    awk '/Max core file size/ { print $5, $6 }' "/proc/$1/limits" 2>/dev/null |
        sed 's/^$/SKIP SKIP/'
}

# ps_args PID -> the command line `ps` prints for PID.  busybox ps has no -p,
# so the portable form is `ps -o pid,args=` filtered on the pid.  That form
# prints a header first and pads the pid column, and both are handled.  A
# non-zero return means ps could not answer for this pid.
ps_args() {
    pa_out=$(ps -o pid,args= 2>/dev/null | awk -v p="$1" '
        $1 == p {
            $1 = ""
            sub(/^ +/, "")
            print
            exit
        }')
    [ -n "$pa_out" ] || return 1
    printf '%s' "$pa_out"
}

# ------------------------------------------- build the C probe
# F_GET_SEALS and PR_GET_DUMPABLE have no shell equivalent, so one tiny C
# program answers both.  Without a compiler those two cases print SKIP.
PROBE=""
CC=""
for cand in cc gcc clang; do
    if command -v "$cand" >/dev/null 2>&1; then
        CC=$cand
        break
    fi
done
if [ -n "$CC" ] && [ -r helpers/compare-probe.c ]; then
    if "$CC" -O0 -o "$T/cfprobe" helpers/compare-probe.c 2>"$T/cc.err"; then
        [ -x "$T/cfprobe" ] && PROBE="$T/cfprobe"
    fi
fi

OUT="$T/args.err"
RAW="$T/raw.err"

# ======================================================== redacted session
# One session serves the cmdline, environ, comm, ps and holder cases.
"$TOOL" run -q --label "$LABEL" -- /bin/sh -c "sleep $HOLD" "$CAN" \
    >/dev/null 2>"$OUT" &
SUP=$!
track "$SUP"
PAY=$(await_child "$SUP" "$LABEL") || PAY=""
[ -n "$PAY" ] && track "$PAY"

# ------------------------------------------------------- args hidden
if [ -z "$PAY" ]; then
    fail args-hidden "no payload carrying [$LABEL] under holder pid $SUP ($(note_text); stderr: $(head -1 "$OUT"))"
elif has "/proc/$PAY/cmdline" "$CAN"; then
    fail args-hidden "canary is in /proc/$PAY/cmdline: $(tr '\0' '|' < "/proc/$PAY/cmdline" | cut -c1-120)"
else
    pass "args-hidden cmdline=[$(tr '\0' '|' < "/proc/$PAY/cmdline" | cut -c1-40)]"
fi

# Negative control: the same canary in an unsupervised argv.  The shell
# must stay alive: `sh -c "sleep 4" CAN` execs sleep, and the canary is
# then in no argv at all.  A `while` loop keeps the shell, and the `$0`
# that carries the canary, in /proc for the sample.
/bin/sh -c 'while :; do sleep 1; done' "$CAN" >/dev/null 2>&1 &
CTL=$!
track "$CTL"
sleep 0.3
if has "/proc/$CTL/cmdline" "$CAN"; then
    pass "args-visible-control canary visible in pid $CTL without supervision"
else
    fail args-visible-control "the observer cannot see the canary in a plain /bin/sh argv, so args-hidden proves nothing"
fi

# ---------------------------------------------------- environ hidden
# The environmental value is checked twice: no canary anywhere in the file,
# and no non-zero length at all, because a redacted environ is empty by
# construction.  A non-zero length with no canary would mean the redaction
# kept something it should have dropped, which is a defect, not a pass.
if [ -n "$PAY" ] && [ -d "/proc/$PAY" ]; then
    eb=$( ( wc -c < "/proc/$PAY/environ" ) 2>/dev/null | tr -d ' ')
    if [ -z "$eb" ]; then
        fail environ-hidden "environ could not be read for pid $PAY"
    elif has "/proc/$PAY/environ" "$CAN"; then
        fail environ-hidden "canary is in /proc/$PAY/environ"
    elif [ "$eb" != 0 ]; then
        fail environ-hidden "environ is [$eb] bytes, want 0: $(tr '\0' '|' < "/proc/$PAY/environ" | cut -c1-100)"
    else
        pass environ-hidden
    fi
else
    skip environ-hidden "the payload of the redacted session is gone"
fi

# Control: --keep-env=NAME keeps the named variable, which shows that the
# environ reader works and the policy, not the kernel, removed the rest.
"$TOOL" run -q --label "$LABEL" --keep-env=PMK_CONF_KEEP \
    --env "PMK_CONF_KEEP=$CAN" -- /bin/sh -c "sleep $HOLD" >/dev/null 2>&1 &
KSUP=$!
track "$KSUP"
KEEP=$(await_child "$KSUP" "$LABEL") || KEEP=""
[ -n "$KEEP" ] && track "$KEEP"
if [ -z "$KEEP" ]; then
    fail environ-keep-control "no payload carrying [$LABEL] under holder pid $KSUP ($(note_text))"
elif has "/proc/$KEEP/environ" "$CAN"; then
    pass "environ-keep-control environ=[$(tr '\0' '|' < "/proc/$KEEP/environ" | cut -c1-60)]"
else
    fail environ-keep-control "environ is [$(tr '\0' '|' < "/proc/$KEEP/environ" | cut -c1-120)] without the kept value"
fi

# ------------------------------------------------------ comm is label
if [ -n "$PAY" ] && [ -d "/proc/$PAY" ]; then
    c=$(cat "/proc/$PAY/comm" 2>/dev/null)
    if [ "$c" = "$LABEL" ]; then
        pass comm-is-label
    else
        fail comm-is-label "comm is [$c], want [$LABEL]"
    fi
else
    skip comm-is-label "the payload of the redacted session is gone"
fi

/bin/sh -c 'while :; do sleep 1; done' >/dev/null 2>&1 &
CTL2=$!
track "$CTL2"
sleep 0.3
c=$(cat "/proc/$CTL2/comm" 2>/dev/null)
# The row is "an unsupervised comm is the program name".  Which name the
# shell reports depends on the host (dash, busybox ash, or busybox
# itself); what matters is that it is not the label.
case "$c" in
    sh|dash|ash|busybox) pass "comm-control unsupervised comm is [$c]" ;;
    *) fail comm-control "an unsupervised /bin/sh has comm [$c], want the program name (sh, dash, ash or busybox)" ;;
esac

# ------------------------------------------------------- ps shows label
# A fresh, longer-lived control sits beside the ps case: the earlier control
# may already have exited by the time ps runs, and a gone process would read
# as a blind ps rather than as a missing process.  The shell stays alive for
# the same reason as args-visible-control: an exec'd `sleep` has no canary
# in its argv.
/bin/sh -c 'while :; do sleep 1; done' "$CAN" >/dev/null 2>&1 &
CTL3=$!
track "$CTL3"
sleep 0.3
if ! command -v ps >/dev/null 2>&1; then
    skip ps-args-is-label "ps is not installed"
    skip ps-args-control "ps is not installed"
else
    if [ -n "$PAY" ] && [ -d "/proc/$PAY" ]; then
        if s=$(ps_args "$PAY"); then
            if [ "$s" = "$LABEL" ]; then
                pass ps-args-is-label
            else
                fail ps-args-is-label "ps printed [$s], want [$LABEL]"
            fi
        else
            fail ps-args-is-label "ps answered nothing for pid $PAY"
        fi
    else
        skip ps-args-is-label "the payload of the redacted session is gone"
    fi
    if s=$(ps_args "$CTL3"); then
        case "$s" in
            *"$CAN"*) pass ps-args-control ;;
            *) fail ps-args-control "ps printed [$s] for the control, without the canary" ;;
        esac
    else
        fail ps-args-control "ps answered nothing for the control pid $CTL3"
    fi
fi

# -------------------------------------------------- holder self mask
# The presented command line covers the whole session, the holder included.
if [ -d "/proc/$SUP" ]; then
    hc=$(cat "/proc/$SUP/comm" 2>/dev/null)
    if [ "$hc" = "$LABEL" ] && ! has "/proc/$SUP/cmdline" "$CAN"; then
        pass "supervisor-selfmask comm=[$hc] cmdline=[$(tr '\0' '|' < "/proc/$SUP/cmdline" | cut -c1-40)]"
    else
        fail supervisor-selfmask "holder comm [$hc] cmdline [$(tr '\0' '|' < "/proc/$SUP/cmdline" | cut -c1-100)]"
    fi
else
    skip supervisor-selfmask "the holder has exited"
fi

# ------------------------------------------- same-uid documented disclosure
# Row: a monitoring agent of the same uid sees the label, and also exe,
# maps, fd/* and cwd, which name the real binary.  The case asserts the
# disclosure is still there.  Expecting it gone would contradict the README.
if [ -n "$KEEP" ] && [ -d "/proc/$KEEP" ]; then
    exe=$(readlink "/proc/$KEEP/exe" 2>/dev/null)
    maps_ok=1
    cwd_ok=1
    fd_ok=1
    peer_read "$KEEP" maps || maps_ok=0
    readlink "/proc/$KEEP/cwd" >/dev/null 2>&1 || cwd_ok=0
    ls "/proc/$KEEP/fd" >/dev/null 2>&1 || fd_ok=0
    if [ -n "$exe" ] && [ "$maps_ok" = 1 ] && [ "$cwd_ok" = 1 ] && [ "$fd_ok" = 1 ]; then
        pass "same-uid-exe-maps exe=[$exe]"
    else
        fail same-uid-exe-maps "exe=[$exe] maps=$maps_ok cwd=$cwd_ok fd=$fd_ok, want the documented disclosure"
    fi
    # Row: environ is readable by the same uid unless --no-dumpable.
    if peer_read "$KEEP" environ; then
        pass same-uid-environ-read
    else
        fail same-uid-environ-read "a same-uid peer was refused environ without --no-dumpable"
    fi
else
    fail same-uid-exe-maps "there is no payload to observe ($(note_text)), so the disclosure was not seen"
    fail same-uid-environ-read "there is no payload to observe ($(note_text)), so the disclosure was not seen"
fi

# ======================================================== secret session
# One session serves the descriptor, secrecy, limit and dumpable cases.
"$TOOL" run -q --label "$LABEL" --secret "TOK=literal:$SEC" \
    -- /bin/sh -c "sleep $HOLD" >/dev/null 2>"$RAW" &
SSUP=$!
track "$SSUP"
SPAY=$(await_child "$SSUP" "$LABEL") || SPAY=""
[ -n "$SPAY" ] && track "$SPAY"

# Row: a same-uid peer is refused the holder's environ.  The holder holds
# the plaintext, so it calls harden_self before the session starts.  The
# holder must be alive for the observation; a gone holder would look refised
# for the wrong reason and is reported as a failure of the session instead.
if root_peer_observer; then
    # Root with CAP_SYS_PTRACE is not the same-uid peer this row is about:
    # the capability check succeeds before the dumpable check, so the read
    # is allowed by design and the refusal is not observable (issue #35).
    skip holder-environ-refused "$ROOT_PEER_REASON"
elif [ ! -d "/proc/$SSUP" ]; then
    fail holder-environ-refused "the holder pid $SSUP is gone, so nothing was observed"
elif peer_read "$SSUP" environ; then
    fail holder-environ-refused "a same-uid peer read the holder's environ while it held a secret"
else
    pass holder-environ-refused
fi

# Row: the session produced a payload that carries the label.
if [ -z "$SPAY" ] || [ ! -d "/proc/$SPAY" ]; then
    fail payload-session "no payload carrying [$LABEL] under secret holder pid $SSUP ($(note_text); stderr: $(head -1 "$RAW"))"
else
    pass "payload-session pid=$SPAY"
fi

# Row: the secret value is in no /proc entry of the session.
if [ -n "$SPAY" ] && [ -d "/proc/$SPAY" ] && [ -d "/proc/$SSUP" ]; then
    leak=""
    has "/proc/$SPAY/cmdline" "$SEC" && leak="payload cmdline"
    has "/proc/$SPAY/environ" "$SEC" && leak="$leak payload environ"
    has "/proc/$SSUP/cmdline" "$SEC" && leak="$leak holder cmdline"
    has "/proc/$SSUP/environ" "$SEC" && leak="$leak holder environ"
    if [ -z "$leak" ]; then
        pass secret-absent
    else
        fail secret-absent "the value appears in:$leak"
    fi
else
    skip secret-absent "the secret session is gone"
fi

# Row: RLIMIT_CORE is 0 in the holder and in every process of the tree.
if [ -n "$SPAY" ] && [ -d "/proc/$SPAY" ] && [ -d "/proc/$SSUP" ]; then
    h=$(core_limits "$SSUP")
    c=$(core_limits "$SPAY")
    if [ "$h" = "0 0" ] && [ "$c" = "0 0" ]; then
        pass "core-limit-zero holder=[$h] payload=[$c]"
    else
        fail core-limit-zero "holder=[$h] payload=[$c], want soft and hard both 0"
    fi
else
    skip core-limit-zero "the secret session is gone"
fi

# Control: without a secret the inherited hard limit survives.  This shell
# starts with hard 0 only when the host already forbids cores, in which case
# the 0 above proves nothing and the case is a SKIP.
if [ -z "$PROBE" ]; then
    skip core-limit-control "no C compiler, so the payload cannot report its own limits"
elif [ "$(ulimit -c -H 2>/dev/null)" = "0" ]; then
    skip core-limit-control "this shell's hard RLIMIT_CORE is already 0, so a zero in the session proves nothing"
else
    c=$("$TOOL" run -q --label "$LABEL" -- "$PROBE" corelim 2>/dev/null)
    hard=$(printf '%s\n' "$c" | sed -n 's/^core_hard=//p')
    soft=$(printf '%s\n' "$c" | sed -n 's/^core_soft=//p')
    if [ -n "$hard" ] && [ "$hard" != 0 ]; then
        pass "core-limit-control payload soft=[$soft] hard=[$hard] without a secret"
    else
        fail core-limit-control "payload reported soft=[$soft] hard=[$hard] without a secret, want the inherited hard limit"
    fi
fi

# Row: the descriptor is a sealed memfd, and a plain file is not.  The
# payload link is read while the secret session is alive; a missing link is
# reported as a failure rather than as a skip, because the session above has
# already proved that a payload exists.
if [ -z "$PROBE" ]; then
    skip secret-fd-is-memfd "no C compiler, so F_GET_SEALS cannot be read"
    skip secret-fd-control "no C compiler, so F_GET_SEALS cannot be read"
else
    link=""
    [ -n "$SPAY" ] && [ -d "/proc/$SPAY" ] && link=$(readlink "/proc/$SPAY/fd/3" 2>/dev/null)
    out=$("$TOOL" run -q --label "$LABEL" --secret "TOK=literal:$SEC" \
        -- "$PROBE" seals TOK 2>"$T/seal.err")
    sfd=$(printf '%s\n' "$out" | sed -n 's/^fd=//p')
    sseal=$(printf '%s\n' "$out" | sed -n 's/^seals=//p')
    swerr=$(printf '%s\n' "$out" | sed -n 's/^write_errno=//p')
    case "$link" in
        /memfd:*) link_ok=1 ;;
        *) link_ok=0 ;;
    esac
    if [ -z "$sfd" ]; then
        fail secret-fd-is-memfd "the payload never reported a descriptor for TOK (stderr: $(head -1 "$T/seal.err"))"
    elif [ "$link_ok" = 1 ] && [ "${sseal:-0}" = 15 ] && [ "${swerr:-0}" = 1 ]; then
        # F_SEAL_SEAL 1, SHRINK 2, GROW 4, WRITE 8: all four, so 15, and the
        # one-byte write fails with EPERM, which is 1 on Linux.
        pass "secret-fd-is-memfd fd=$sfd seals=$sseal write_errno=$swerr link=$link"
    else
        fail secret-fd-is-memfd "fd=[$sfd] seals=[$sseal] write_errno=[$swerr] link=[$link], want seals=15, write_errno=1 and a /memfd: link"
    fi
    printf '%s' "$SEC" > "$T/plain"
    out=$("$PROBE" sealsfd 3 3<"$T/plain" 2>/dev/null)
    pseal=$(printf '%s\n' "$out" | sed -n 's/^seals=//p')
    # A regular file is not a memfd.  What F_GET_SEALS reports for one is
    # the kernel's business: -1 (EINVAL) on most filesystems, 0 or even
    # F_SEAL_SEAL (1) on a tmpfs file.  The case distinguishes the plain
    # file from the delivered descriptor by the seal *set*: the memfd
    # carries all four seals (15), and a plain file does not.
    case "$pseal" in
        15) fail secret-fd-control "a plain file on fd 3 reported the full memfd seal set (15), so the memfd assertion proves nothing" ;;
        ''|*[!0-9-]*) fail secret-fd-control "a plain file on fd 3 reported seals=[$pseal], want a number" ;;
        *) pass "secret-fd-control seals=[$pseal] for a plain file (the memfd set is 15)" ;;
    esac
fi

# Row: PR_GET_DUMPABLE reflects the mode.
if [ -z "$PROBE" ]; then
    skip dumpable-default "no C compiler, so PR_GET_DUMPABLE cannot be read"
    skip dumpable-nodumpable "no C compiler, so PR_GET_DUMPABLE cannot be read"
else
    d=$("$TOOL" run -q --label "$LABEL" -- "$PROBE" dumpable 2>/dev/null)
    if [ "$d" = "dumpable=1" ]; then
        pass dumpable-default
    elif [ -z "$d" ]; then
        fail dumpable-default "the payload never reported its dumpable flag, so nothing was observed"
    else
        fail dumpable-default "the payload reported [$d] without --no-dumpable, want dumpable=1"
    fi
    d=$("$TOOL" run -q --label "$LABEL" --no-dumpable -- "$PROBE" dumpable 2>/dev/null)
    if [ "$d" = "dumpable=0" ]; then
        pass dumpable-nodumpable
    elif [ -z "$d" ]; then
        fail dumpable-nodumpable "the payload never reported its dumpable flag, so nothing was observed"
    else
        fail dumpable-nodumpable "the payload reported [$d] with --no-dumpable, want dumpable=0"
    fi
    # Row: --no-dumpable refuses the peer the payload's environ too.
    "$TOOL" run -q --label "$LABEL" --no-dumpable \
        -- /bin/sh -c "sleep $HOLD" >/dev/null 2>&1 &
    NSUP=$!
    track "$NSUP"
    NPAY=$(await_child "$NSUP" "$LABEL") || NPAY=""
    [ -n "$NPAY" ] && track "$NPAY"
    if [ -z "$NPAY" ]; then
        fail nodumpable-refuses "no payload carrying [$LABEL] under holder pid $NSUP ($(note_text))"
    elif root_peer_observer; then
        # Same reason as holder-environ-refused: root with CAP_SYS_PTRACE
        # reads the payload's environ by design, so the refusal this row
        # asserts cannot be observed from root (issue #35).
        skip nodumpable-refuses "$ROOT_PEER_REASON"
    elif peer_read "$NPAY" environ; then
        fail nodumpable-refuses "a same-uid peer read /proc/$NPAY/environ with --no-dumpable set"
    else
        pass nodumpable-refuses
    fi
fi

# ============================================================ observer rows
# Row: another uid sees the label and nothing else.  Creating a second uid
# needs root.  The cmdline and comm halves are readable by every uid and are
# covered by args-hidden and comm-is-label, which follow the label only.
skip observer-other-uid "needs root to create a second uid; its cmdline and comm half is what args-hidden and comm-is-label measure"

# Row: root sees the pid, exe, maps, open files and memory.
skip observer-root "this suite runs as uid $(id -u), so root's view cannot be observed from here"

# Row: a kernel-level attacker sees everything.  That is a statement about
# the mechanism and no case inside the process can observe it.
skip observer-kernel "a kernel-level attacker is outside the process's view, so no case can measure it"

# ================================================================ verdict
if [ "$TFAIL" != 0 ]; then
    vt=FAIL
elif [ "$TPASS" = 0 ]; then
    vt=SKIP
else
    vt=PASS
fi
printf 'CONFORMANCE: %s pass=%s fail=%s skip=%s\n' "$vt" "$TPASS" "$TFAIL" "$TSKIP"
[ "$TFAIL" = 0 ]
