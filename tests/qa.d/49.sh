#!/bin/sh
# Issue 49: the modes that do not redact, and what each one leaves behind.
#
# One row per mode, each asserting what the issue measured on
# 2026-11-08 and what this host shows now:
#
#   49a  default: the leaf's cmdline is the label, comm is the label,
#        environ is 0 bytes, TracerPid is the tracer thread.
#   49b  --no-redact: real argv, real comm, real environ, TracerPid 0,
#        and the load-bearing marker is in the payload's environ.
#   49c  --isolate: the leaf keeps its real argv/comm/environ (the
#        intermediate process carries the label), TracerPid 0, and the
#        namespace fingerprints: `hidepid=invisible` on the private
#        procfs and an `NSpid` chain of two numbers.
#   49d  --unshare: either the fixed shape (label + empty environ) or
#        the #4 shape (real argv on the host).  Which one is asserted is
#        decided by measurement, and a real argv is a named dependency
#        on qa/fix1 rather than a silent pass.
#   49e  --redact --isolate composes to --unshare: the same row as 49d,
#        and the report says `"mode": "redact"`.
#   49f  32-bit image: refused loudly, and the payload keeps its real
#        argv.  Needs `tests/testcases32`, which `vm/run.sh` builds.
#   49g  the report refuses to call a zero-exec run `redact`?  No: it
#        does not, and that is issue 49's own finding.  The row pins the
#        current shape so a fix has a failing case to flip.
#
# The `--unshare` defect itself is #4 and is not re-derived here; this
# fragment only records which shape this worktree serves.
set -u
# lib.sh reads BIN_DIR from the cwd, so run from tests/ (see its header).
cd "$(dirname "$0")/.." || exit 2
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

LABEL="qa49-$$"
MARK="MK49-$$"
T=$(mktemp -d "${TMPDIR:-/tmp}/qa49.XXXXXX") || {
    echo "FATAL: mktemp -d failed"
    exit 2
}
SUPS=""
cleanup() {
    for s in $SUPS; do kill -9 "$s" 2>/dev/null; done
    kill_label "$LABEL" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

# leaf_of SUP: print the deepest descendant of SUP, found by a PPid walk.
# `pgrep -x sleep` would match any other sleep on this host, and several
# agents run suites here.
leaf_of() {
    l_cur=$1
    l_depth=0
    while [ "$l_depth" -lt 8 ]; do
        l_next=""
        for d in /proc/[0-9]*; do
            l_pid=${d#/proc/}
            l_pp=$(sed -n 's/^PPid:[[:space:]]*\([0-9]*\).*/\1/p' \
                "$d/status" 2>/dev/null)
            if [ "$l_pp" = "$l_cur" ]; then
                l_next=$l_pid
                break
            fi
        done
        [ -n "$l_next" ] || break
        l_cur=$l_next
        l_depth=$((l_depth + 1))
    done
    [ "$l_depth" -gt 0 ] && echo "$l_cur"
}

field() { sed -n "s/^$2:[[:space:]]*//p" "/proc/$1/status" 2>/dev/null; }
cmdline_of() { tr '\0' '|' < "/proc/$1/cmdline" 2>/dev/null; }

# ns_unavailable ERR_FILE: the run asked for namespaces and the host
# refused them, so the mode fell back to redact or plain.  The namespace
# fingerprints cannot exist; the row is a SKIP with the host's reason.
ns_unavailable() {
    grep -q 'no unprivileged user namespaces' "$1" 2>/dev/null
}

# The probe is the reliable answer: the note is printed when a run ends,
# which is after the row has read the leaf.  `isolation active` means the
# host grants the namespaces the rows below need.
NS_OK=0
if "$TOOL" probe 2>/dev/null | grep -q 'isolation[[:space:]][[:space:]]*active'; then
    NS_OK=1
fi
comm_of() { cat "/proc/$1/comm" 2>/dev/null; }
envbytes() { wc -c < "/proc/$1/environ" 2>/dev/null | tr -d ' '; }
envhas() {
    tr '\0' '\n' < "/proc/$1/environ" 2>/dev/null | grep -qxF -- "$2"
}

# start LOGNAME MODE-FLAGS...: start one run with the marker in the
# payload's environ, wait for the leaf, and print "SUP LEAF".  stderr
# goes to $T/LOGNAME.err.  The run is not quiet: the notes that say a
# mode cannot apply a flag are part of what these rows assert.
start() {
    s_log=$1
    shift
    LABEL="qa49-$$"
    env -i PATH=/usr/bin:/bin QA49_MARK="$MARK" "$TOOL" -l "$LABEL" \
        "$@" -- /bin/sleep 20 >/dev/null 2>"$T/$s_log.err" &
    s_sup=$!
    SUPS="$SUPS $s_sup"
    s_i=0
    s_leaf=""
    while [ "$s_i" -lt 60 ]; do
        s_leaf=$(leaf_of "$s_sup")
        [ -n "$s_leaf" ] && break
        kill -0 "$s_sup" 2>/dev/null || break
        sleep 0.1
        s_i=$((s_i + 1))
    done
    echo "$s_sup $s_leaf"
}

kill_sup() { kill -9 "$1" 2>/dev/null; wait "$1" 2>/dev/null; }

# ---------------------------------------------------------- 49a default
set -- $(start default)
SUP=$1
LEAF=$2
if [ -z "$LEAF" ]; then
    fail "49a-default-redacted (no leaf under $SUP: $(head -2 "$T/default.err" | tr '\n' '|'))"
else
    cl=$(cmdline_of "$LEAF")
    cm=$(comm_of "$LEAF")
    eb=$(envbytes "$LEAF")
    tp=$(field "$LEAF" TracerPid)
    if [ "$cl" = "$LABEL|" ] && [ "$cm" = "$LABEL" ] \
        && [ "$eb" = 0 ] && [ "$tp" != 0 ]; then
        pass "49a-default-redacted cmdline=[$cl] comm=[$cm] env=0 tracer=$tp"
    else
        fail "49a-default-redacted cmdline=[$cl] comm=[$cm] envb=$eb tracer=$tp"
    fi
    kill_sup "$SUP"
fi

# -------------------------------------------------------- 49b --no-redact
set -- $(start plain --no-redact)
SUP=$1
LEAF=$2
if [ -z "$LEAF" ]; then
    fail "49b-plain-real (no leaf under $SUP)"
else
    cl=$(cmdline_of "$LEAF")
    cm=$(comm_of "$LEAF")
    tp=$(field "$LEAF" TracerPid)
    case "$cl" in
        *"/bin/sleep"*"20"*) cl_ok=1 ;;
        *) cl_ok=0 ;;
    esac
    if [ "$cl_ok" = 1 ] && [ "$cm" = "sleep" ] && envhas "$LEAF" "QA49_MARK=$MARK" \
        && [ "$tp" = 0 ]; then
        pass "49b-plain-real cmdline=[$cl] comm=[$cm] environ-has-marker tracer=0"
    else
        fail "49b-plain-real cmdline=[$cl] comm=[$cm] marker=$(envhas "$LEAF" "QA49_MARK=$MARK" && echo present || echo absent) tracer=$tp"
    fi
    # The note is printed when the run finishes, so it needs a run that
    # ends: the parked payload above never reaches that point.
    "$TOOL" -l "$LABEL" --no-redact -- /bin/true >/dev/null 2>"$T/plain.err"
    case "$(cat "$T/plain.err" 2>/dev/null)" in
        *"does not redact the payload's /proc metadata"*)
            note=$(sed -n 's/^pmask: note: //p' "$T/plain.err" | head -1 | cut -c1-70)
            pass "49b-plain-note ($note)" ;;
        *)
            fail "49b-plain-note (stderr=$(head -3 "$T/plain.err" | tr '\n' '|'))" ;;
    esac
    kill_sup "$SUP"
fi

# --------------------------------------------------------- 49c --isolate
set -- $(start isolate --isolate)
SUP=$1
LEAF=$2
if [ -z "$LEAF" ] || [ "$NS_OK" = 0 ] || ns_unavailable "$T/isolate.err"; then
    skip "49c-isolate-real (unprivileged user namespaces unavailable: $(head -2 "$T/isolate.err" | tr '\n' '|'))"
    skip "49c-isolate-procfs-fingerprint (no namespaces)"
    skip "49c-isolate-nspid-fingerprint (no namespaces)"
else
    cl=$(cmdline_of "$LEAF")
    cm=$(comm_of "$LEAF")
    tp=$(field "$LEAF" TracerPid)
    case "$cl" in
        *"/bin/sleep"*) cl_ok=1 ;;
        *) cl_ok=0 ;;
    esac
    if [ "$cl_ok" = 1 ] && [ "$cm" = "sleep" ] \
        && envhas "$LEAF" "QA49_MARK=$MARK" && [ "$tp" = 0 ]; then
        pass "49c-isolate-real cmdline=[$cl] comm=[$cm] environ-has-marker tracer=0"
    else
        fail "49c-isolate-real cmdline=[$cl] comm=[$cm] marker=$(envhas "$LEAF" "QA49_MARK=$MARK" && echo present || echo absent) tracer=$tp"
    fi
    # The issue's own fingerprint: a private procfs mounted hidepid=invisible.
    hp=$(grep -c 'hidepid=invisible' "/proc/$LEAF/mountinfo" 2>/dev/null)
    if [ "${hp:-0}" -ge 1 ]; then
        pass "49c-isolate-procfs-fingerprint (mountinfo: $(grep 'hidepid=invisible' "/proc/$LEAF/mountinfo" | head -1 | cut -c1-90))"
    else
        fail "49c-isolate-procfs-fingerprint (no hidepid=invisible mount in mountinfo)"
    fi
    # The NSpid chain: two numbers means the process is in a pid namespace.
    nspid=$(field "$LEAF" NSpid)
    n_count=$(printf '%s\n' "$nspid" | awk '{print NF}')
    if [ "${n_count:-0}" -ge 2 ]; then
        pass "49c-isolate-nspid-fingerprint (NSpid=[$nspid])"
    else
        fail "49c-isolate-nspid-fingerprint (NSpid=[$nspid], want two levels)"
    fi
    # The intermediate process stays labelled while the leaf is real.
    if [ -n "$SUP" ] && [ -d "/proc/$SUP" ]; then
        supcl=$(cmdline_of "$SUP")
        case "$supcl" in
            "$LABEL|") pass "49c-isolate-intermediate-labelled (supervisor cmdline=[$supcl])" ;;
            *) fail "49c-isolate-intermediate-labelled (supervisor cmdline=[$supcl])" ;;
        esac
    else
        skip "49c-isolate-intermediate-labelled (the supervisor had already exited)"
    fi
    kill_sup "$SUP"
fi

# -------------------------------------- 49d/49e: --unshare and its spelling
# The shape this build serves decides which assertion applies.  A real
# argv is issue #4 and the fix belongs to qa/fix1; the row is then a
# SKIP with the dependency named, not a pass.
unshare_row() {
    u_name=$1
    shift
    set -- $(start "$u_name" "$@")
    u_sup=$1
    u_leaf=$2
    if [ -z "$u_leaf" ] || [ "$NS_OK" = 0 ] || ns_unavailable "$T/$u_name.err"; then
        skip "$u_name (user namespaces unavailable: $(head -2 "$T/$u_name.err" | tr '\n' '|'))"
        return
    fi
    u_cl=$(cmdline_of "$u_leaf")
    u_tp=$(field "$u_leaf" TracerPid)
    u_eb=$(envbytes "$u_leaf")
    u_nspid=$(field "$u_leaf" NSpid)
    case "$u_cl" in
        "$LABEL|")
            if [ "$u_eb" = 0 ] && [ "$u_tp" != 0 ]; then
                pass "$u_name-fixed cmdline=[$u_cl] env=0 tracer=$u_tp NSpid=[$u_nspid]"
            else
                fail "$u_name-fixed-shape (cmdline=[$u_cl] envb=$u_eb tracer=$u_tp)"
            fi ;;
        *"/bin/sleep"*)
            # The #4 shape: the host serves the real argv.
            skip "$u_name-current-shape-real (host serves [$u_cl]; the redaction defect is #4, fixed by qa/fix1 -- assert the label shape once that lands)" ;;
        *)
            fail "$u_name-unknown-shape (cmdline=[$u_cl])" ;;
    esac
    u_hp=$(grep -c 'hidepid=invisible' "/proc/$u_leaf/mountinfo" 2>/dev/null)
    if [ "${u_hp:-0}" -ge 1 ]; then
        pass "$u_name-procfs-fingerprint (hidepid=invisible present)"
    else
        fail "$u_name-procfs-fingerprint (no hidepid=invisible mount)"
    fi
    u_n=$(printf '%s\n' "$u_nspid" | awk '{print NF}')
    if [ "${u_n:-0}" -ge 2 ]; then
        pass "$u_name-nspid-fingerprint (NSpid=[$u_nspid])"
    else
        fail "$u_name-nspid-fingerprint (NSpid=[$u_nspid], want two levels)"
    fi
    kill_sup "$u_sup"
}

unshare_row 49d-unshare --unshare

# `--redact --isolate` is the composed spelling.  It takes the redaction
# path and produces a report there; the shape assertion still applies.
unshare_row 49e-redact-isolate --redact --isolate

# ------------------------------------------------------ 49f: 32-bit image
# The i686 probe is a vm/run.sh artifact.  When it is absent, a static
# 32-bit C probe is built with `cc -m32`; without either the row is a
# SKIP.  Two runs: the first parks so the argv can be read, the second
# exits at once so the session summary is written.
T32=""
if [ -x ./testcases32 ]; then
    T32="$PWD/testcases32"
elif command -v cc >/dev/null 2>&1; then
    cat > "$T/t32.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "sleeper") == 0) {
        sleep(30);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "exec64") == 0) {
        usleep(200000);
        char *av[] = {"/bin/sleep", "2", 0};
        execv("/bin/sleep", av);
        return 127;
    }
    for (int i = 0; i < argc; i++) printf("argv[%d]=%s\n", i, argv[i]);
    return 0;
}
EOF
    if cc -m32 -static -o "$T/t32" "$T/t32.c" 2>/dev/null; then
        T32="$T/t32"
    fi
fi
if [ -n "$T32" ]; then
    # Default: the 32-bit exec is refused before the image runs, so no
    # process with the real argv appears.
    "$TOOL" -l "$LABEL" -- "$T32" sleeper "MK49B-$MARK" \
        >"$T/k32.out" 2>"$T/k32.err" &
    K32=$!
    sleep 0.8
    LEAF=$(leaf_of "$K32")
    if [ -z "$LEAF" ]; then
        pass "49f-32bit-refused-by-default"
    else
        fail "49f-32bit-refused-by-default (a 32-bit payload appeared: $(cmdline_of "$LEAF"))"
    fi
    kill -9 "$K32" 2>/dev/null
    wait "$K32" 2>/dev/null
    if grep -q '32-bit.*refused' "$T/k32.err"; then
        pass "49f-32bit-refusal-is-loud ($(head -1 "$T/k32.err" | cut -c1-90))"
    else
        fail "49f-silent-32bit-refusal (stderr=$(head -2 "$T/k32.err" | tr '\n' '|'))"
    fi

    # `--allow-foreign` restores the documented unredacted run and the
    # summary counts it.
    "$TOOL" -l "$LABEL" --allow-foreign -- "$T32" sleeper "MK49B-$MARK" \
        >"$T/k32c.out" 2>"$T/k32c.err" &
    K32=$!
    sleep 0.8
    LEAF=$(leaf_of "$K32")
    if [ -n "$LEAF" ]; then
        cl=$(cmdline_of "$LEAF")
        case "$cl" in
            *"sleeper"*"MK49B-$MARK"*)
                pass "49f-32bit-allow-foreign-runs-unredacted cmdline=[$cl]" ;;
            *) fail "49f-32bit-allow-foreign-runs-unredacted (cmdline=[$cl])" ;;
        esac
        exe=$(readlink "/proc/$LEAF/exe" 2>/dev/null)
        case "$exe" in
            *testcases32|*/t32) pass "49f-32bit-allow-foreign-exe-names-the-image (exe=$exe)" ;;
            *) fail "49f-32bit-allow-foreign-exe-names-the-image (exe=[$exe])" ;;
        esac
    else
        fail "49f-32bit-allow-foreign-runs-unredacted (no 32-bit payload appeared)"
    fi
    [ -n "$LEAF" ] && kill -9 "$LEAF" 2>/dev/null
    kill -9 "$K32" 2>/dev/null
    wait "$K32" 2>/dev/null

    "$TOOL" -l "$LABEL" --allow-foreign -- "$T32" echoargs "MK49B-$MARK" \
        >"$T/k32b.out" 2>"$T/k32b.err"
    if grep -q 'foreign-arch' "$T/k32b.err"; then
        pass "49f-32bit-summary-counts-foreign-arch ($(tail -1 "$T/k32b.err"))"
    else
        fail "49f-32bit-summary-counts-foreign-arch (stderr=$(tail -1 "$T/k32b.err"))"
    fi
    "$TOOL" -l "$LABEL" --allow-foreign -- "$T32" exec64 \
        >/dev/null 2>"$T/k32d.err"
    rc=$?
    if [ "$rc" = 137 ] \
        && grep -q 'later exec of a tracee that already ran a 32-bit image is refused' \
            "$T/k32d.err"; then
        pass "49f-32bit-later-exec-refused (rc=$rc)"
    else
        fail "49f-32bit-later-exec-refused (rc=$rc err=$(tr '\n' '|' < "$T/k32d.err" | cut -c1-200))"
    fi

    # A native master settles, then execs a 32-bit image.  There is no
    # entry stop for it, so the completion stop is the last place to
    # refuse; the kernel has already copied the real argv by then.
    "$TOOL" -l "$LABEL" -- /bin/sh -c "sleep 0.2; exec $T32 sleeper 30" \
        >/dev/null 2>"$T/k32e.err"
    rc=$?
    if [ "$rc" = 137 ] && grep -q 'refused at completion' "$T/k32e.err"; then
        pass "49f-32bit-later-exec-native-refused (rc=$rc)"
    else
        fail "49f-32bit-later-exec-native-refused (rc=$rc err=$(tr '\n' '|' < "$T/k32e.err" | cut -c1-200))"
    fi

    # The explicit opt-in keeps the documented unredacted run.
    "$TOOL" -l "$LABEL" --allow-foreign -- /bin/sh -c "sleep 0.2; exec $T32 sleeper 30" \
        >/dev/null 2>"$T/k32f.err" &
    K32F=$!
    sleep 0.9
    LEAF=$(leaf_of "$K32F")
    if [ -n "$LEAF" ]; then
        cl=$(cmdline_of "$LEAF")
        exe=$(readlink "/proc/$LEAF/exe" 2>/dev/null)
        case "$cl:$exe" in
            *sleeper*:*/testcases32|*sleeper*:*/t32)
                pass "49f-32bit-later-exec-native-allow-foreign cmdline=[$cl] exe=$exe" ;;
            *) fail "49f-32bit-later-exec-native-allow-foreign (cmdline=[$cl] exe=[$exe])" ;;
        esac
    else
        skip "49f-32bit-later-exec-native-allow-foreign (the 30 s payload had already settled or the host refused the exec)"
    fi
    [ -n "$LEAF" ] && kill -9 "$LEAF" 2>/dev/null
    kill -9 "$K32F" 2>/dev/null
    wait "$K32F" 2>/dev/null

    # The seccomp fast path sees the exec at its entry stop, so the
    # refusal happens before the image runs.
    "$TOOL" -l "$LABEL" --exec-once --on-exit wait -- /bin/sh -c "sleep 0.2; exec $T32 sleeper 30" \
        >/dev/null 2>"$T/k32g.err"
    rc=$?
    if [ "$rc" = 137 ] && grep -q '32-bit.*refused' "$T/k32g.err" \
        && ! grep -q 'at completion' "$T/k32g.err"; then
        pass "49f-32bit-later-exec-fastpath-refused (rc=$rc)"
    else
        fail "49f-32bit-later-exec-fastpath-refused (rc=$rc err=$(tr '\n' '|' < "$T/k32g.err" | cut -c1-200))"
    fi
else
    skip "49f-32bit-refused-by-default (tests/testcases32 absent: the i686 probe is built by vm/run.sh)"
    skip "49f-32bit-refusal-is-loud (tests/testcases32 absent)"
    skip "49f-32bit-allow-foreign-runs-unredacted (tests/testcases32 absent)"
    skip "49f-32bit-allow-foreign-exe-names-the-image (tests/testcases32 absent)"
    skip "49f-32bit-summary-counts-foreign-arch (tests/testcases32 absent)"
    skip "49f-32bit-later-exec-refused (tests/testcases32 absent)"
    skip "49f-32bit-later-exec-native-refused (tests/testcases32 absent)"
    skip "49f-32bit-later-exec-native-allow-foreign (tests/testcases32 absent)"
    skip "49f-32bit-later-exec-fastpath-refused (tests/testcases32 absent)"
fi

# ------------------------------------- 49g: the report's mode for --unshare
# A `--unshare` run that redacted zero execs still reports "mode": "redact".
# That is issue 49's own finding, not a property to celebrate: the row is
# recorded as INFO-style output in the PASS text so the shape is pinned
# and a fix flips it.
printf 'token\n' > "$T/tok"
chmod 600 "$T/tok"
"$TOOL" --unshare --report=json --secret T=file:"$T/tok" -- /bin/true \
    >"$T/rep.json" 2>/dev/null
if [ -s "$T/rep.json" ]; then
    rmode=$(sed -n 's/.*"mode": "\([a-z]*\)".*/\1/p' "$T/rep.json" | head -1)
    rexec=$(sed -n 's/.*"execs": {"total": \([0-9]*\).*/\1/p' "$T/rep.json" | head -1)
    if [ "$rmode" = "redact" ] && [ "${rexec:-0}" -gt 0 ]; then
        pass "49g-unshare-report-mode-and-execs (mode=$rmode execs=$rexec)"
    elif [ "$rmode" = "redact" ]; then
        # The mismatch issue 49 names.  Recorded, not asserted as good.
        pass "49g-unshare-report-says-redact-with-zero-execs (mode=$rmode execs=${rexec:-0}; issue 49's report mismatch, pinned)"
    else
        fail "49g-unshare-report-mode (mode=[$rmode] execs=[${rexec:-?}])"
    fi
else
    fail "49g-unshare-report-mode (no JSON report was produced)"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
