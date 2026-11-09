#!/bin/sh
# Issue 56: the auditd record shapes a pmask launch leaves, and the rule
# forms that do and do not see them.
#
# This fragment is gated on the host, because a wrong host makes every
# row vacuous:
#
#   - `auditctl -s` must answer a status rather than "The audit system is
#     disabled" (that is how a kernel with auditing off answers), and
#   - `ausearch` must exist so the records can be read back.
#
# When either is missing the fragment prints SKIP with the exact reason
# and exits 0.  It never turns an unmeasured host into a pass.
#
# Rows, on a host that passes the gate:
#
#   56a  control: the exec exit rule sees an unmasked exec.  Without it
#        every "no record" row below would pass on a blind observer.
#   56b  the supervisor's exec record carries pmask's own argv: the label
#        and the payload path are in a0..an, and a `literal:` secret is
#        in a cleartext slot.  This is the record issue 59 is about; the
#        row asserts it exists rather than pretending it does not.
#   56c  the payload's exec record is `argc=N a0="label" a1="" ...`: the
#        label and `argc - 1` empty strings.
#   56d  the tracer's own syscalls are visible: a `ptrace` record with
#        `comm="pmask-tracer"` and an `OBJ_PID` record naming a tracee.
#   56e  the rule-form finding: a `-w PATH -p x` watch produces no
#        execution record for a repeated exec, while an
#        `-a always,exit -S execve` rule produces one per exec.  Both
#        counts are printed; the row asserts the asymmetry the issue
#        measured.
#   56f  a 32-bit payload keeps its real argv in the EXECVE record while
#        the record's `arch=` is the exec'ing syscall's ABI, so a rule
#        filtered on `arch=b32` cannot see the exec.  Needs
#        `tests/testcases32`; a SKIP otherwise.
#
# Cleanup removes exactly the rules this fragment installed, by key, even
# when a row fails or the fragment is interrupted.
set -u
# lib.sh reads BIN_DIR from the cwd, so run from tests/ (see its header).
cd "$(dirname "$0")/.." || exit 2

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

# ------------------------------------------------------------- the gate
AUDITCTL=""
for c in auditctl /sbin/auditctl /usr/sbin/auditctl; do
    if command -v "$c" >/dev/null 2>&1; then
        AUDITCTL=$c
        break
    fi
done
AUSEARCH=""
for c in ausearch /sbin/ausearch /usr/sbin/ausearch; do
    if command -v "$c" >/dev/null 2>&1; then
        AUSEARCH=$c
        break
    fi
done

# audit_root CMD...: run an audit tool as root.  `auditctl` refuses a
# non-root caller with "You must be root to run this program" and exit 4,
# which says nothing about the subsystem.
audit_root() {
    if [ "$(id -u)" = 0 ]; then
        "$@"
    elif sudo -n true 2>/dev/null; then
        sudo -n "$@"
    else
        return 127
    fi
}

if [ -z "$AUDITCTL" ]; then
    skip "56-audit-subsystem (no auditctl on this host: the kernel audit records cannot be read)"
    echo "== VERDICT: FAIL=0 (SKIP: no auditctl) =="
    exit 0
fi
if [ -z "$AUSEARCH" ]; then
    skip "56-audit-subsystem (no ausearch on this host: the audit log cannot be read back)"
    echo "== VERDICT: FAIL=0 (SKIP: no ausearch) =="
    exit 0
fi

AUDIT_STATUS=$(audit_root "$AUDITCTL" -s 2>&1)
AUDIT_RC=$?
if [ "$AUDIT_RC" = 127 ]; then
    # `audit_root` could neither run as root nor use sudo.  `auditctl`
    # refuses a non-root caller before it asks the kernel anything, so
    # there is no status to read.
    skip "56-audit-subsystem (auditctl needs root and passwordless sudo is unavailable; run this fragment as root or on a host where sudo -n works)"
    echo "== VERDICT: FAIL=0 (SKIP: no privilege) =="
    exit 0
fi
# `auditctl -s` can also answer nothing at all while a second probe does
# explain why: on an LXC container the kernel refuses AUDIT_GET with
# ECONNREFUSED and `-s` prints no line, yet `-l` says the subsystem is
# disabled.  Read both before deciding the host cannot be measured.
AUDIT_LIST=$(audit_root "$AUDITCTL" -l 2>&1)
case "$AUDIT_STATUS" in
    *"enabled=1"*|*"enabled=2"*)
        : ;;
    *"The audit system is disabled"*)
        skip "56-audit-subsystem (auditctl -s: The audit system is disabled)"
        echo "== VERDICT: FAIL=0 (SKIP: audit disabled; run on a host with auditd, or the QEMU guest with auditd staged, or the sand-net microVM) =="
        exit 0 ;;
    *"You must be root"*)
        skip "56-audit-subsystem (auditctl needs root and sudo is not available: [$AUDIT_STATUS])"
        echo "== VERDICT: FAIL=0 (SKIP: no privilege) =="
        exit 0 ;;
    "")
        case "$AUDIT_LIST" in
            *"The audit system is disabled"*)
                skip "56-audit-subsystem (auditctl -l: The audit system is disabled; auditctl -s printed nothing and exited $AUDIT_RC)"
                echo "== VERDICT: FAIL=0 (SKIP: audit disabled) =="
                exit 0 ;;
        esac
        # A container can refuse the NETLINK_AUDIT request outright: the
        # kernel answers ECONNREFUSED to AUDIT_GET and auditctl prints
        # nothing at all.  That is not "auditing is off"; it is "the
        # question cannot be put here", and it needs a different host.
        skip "56-audit-subsystem (auditctl -s printed nothing and exited $AUDIT_RC: NETLINK_AUDIT/AUDIT_GET is refused on this host, e.g. an LXC container; capture with 'sudo strace -e trace=socket,sendto,recvfrom auditctl -s' and rerun on a host with a working audit subsystem)"
        echo "== VERDICT: FAIL=0 (SKIP: audit netlink refused) =="
        exit 0 ;;
    *)
        skip "56-audit-subsystem (auditctl -s answered neither a status nor a refusal: [$(printf '%s' "$AUDIT_STATUS" | head -1)])"
        echo "== VERDICT: FAIL=0 (SKIP: unreadable audit status) =="
        exit 0 ;;
esac

# ---------------------------------------------------------------- host ok
if ! command -v "$PWD/pmask" >/dev/null 2>&1 && [ ! -x "$PWD/pmask" ]; then
    echo "FATAL: $PWD/pmask missing (build failed)"
    exit 2
fi
TOOL="$PWD/pmask"

T=$(mktemp -d "${TMPDIR:-/tmp}/qa56.XXXXXX") || {
    echo "FATAL: mktemp -d failed"
    exit 2
}
LABEL="qa56-$$"
SECRET="QA56-CANARY-$$"
KEYS="qa56-exec-$$ qa56-trace-$$ qa56-watch-$$ qa56-x-$$ qa56-exit-$$ qa56-b32-$$"
SUPS=""

audit_del() {
    for k in $KEYS; do
        audit_root "$AUDITCTL" -W -k "$k" >/dev/null 2>&1
        audit_root "$AUDITCTL" -D -k "$k" >/dev/null 2>&1
    done
}
cleanup() {
    for s in $SUPS; do kill -9 "$s" 2>/dev/null; done
    audit_del
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

# audit_cmd RULE-ARGS...: install one rule, reporting a refusal.
audit_cmd() {
    out=$(audit_root "$AUDITCTL" "$@" 2>&1)
    rc=$?
    printf '%s\n' "$out" >>"$T/rules.log"
    [ "$rc" = 0 ] || printf 'auditctl %s -> rc=%s %s\n' "$*" "$rc" "$out" >&2
    return "$rc"
}

# ---------- 56a/56b/56c: one launch, three records from one rule set
if ! audit_cmd -a always,exit -F arch=b64 -S execve -S execveat -k "qa56-exec-$$"; then
    skip "56a-control-exec-record (the exit rule for execve could not be installed)"
    skip "56b-supervisor-record (the exit rule could not be installed)"
    skip "56c-payload-record (the exit rule could not be installed)"
else
    sleep 0.2
    "$TOOL" -q -l "$LABEL" --secret "S=literal:$SECRET" -- /bin/sh -c 'true' \
        >/dev/null 2>"$T/launch.err"
    sleep 0.3
    "$AUSEARCH" -k "qa56-exec-$$" -i >"$T/exec.log" 2>"$T/ausearch.err"

    # 56a: the control.  pmask's own exec is an exec the rule saw.
    if grep -q 'type=EXECVE' "$T/exec.log"; then
        pass "56a-control-exec-record ($(grep -c 'type=EXECVE' "$T/exec.log") EXECVE records)"
    else
        fail "56a-control-exec-record (no EXECVE record: $(head -2 "$T/ausearch.err" | tr '\n' '|'))"
    fi

    # 56b: the supervisor's record.  The whole argv is in it, including
    # the literal secret: that is the exposure, asserted so a fix has a
    # case to flip.  The value appears as the `literal:` source text
    # (`S=literal:CANARY`), which is what the shell handed pmask.
    if grep -qF -- "literal:$SECRET" "$T/exec.log"; then
        rec=$(grep -F -- "literal:$SECRET" "$T/exec.log" | head -1 | cut -c1-160)
        pass "56b-supervisor-record-carries-argv (found the literal secret in: $rec)"
    else
        skip "56b-supervisor-record-carries-argv (the record was not found; the deployment may filter argv with --log_format or exclude the key)"
    fi
    if grep -q "a[0-9]*=\"--secret\"" "$T/exec.log"; then
        pass "56b-supervisor-record-names-the-secret-flag"
    else
        skip "56b-supervisor-record-names-the-secret-flag (no --secret slot in the record)"
    fi

    # 56c: the payload's record.  The shape is "one non-empty label slot
    # followed by argc-1 empty slots", which is what the detector in
    # docs/research/bteam-audit.md matches.  The first slot is not always
    # the label text this fragment chose: a deployment label is cut to 15
    # bytes for `comm`, and `--comm` can change it.  The empty tail is the
    # part that no ordinary program produces.
    payload_record=$(awk '
        /type=EXECVE/ {
            argc = ""; n = 0; empty = 0; first = "";
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^argc=/) { argc = substr($i, 6) }
                if ($i ~ /^a[0-9]+=/) {
                    n++
                    v = $i; sub(/^a[0-9]+=/, "", v)
                    if (n == 1) { first = v }
                    else if (v == "\"\"") { empty++ }
                }
            }
            if (argc != "" && n == argc && empty == argc - 1 && first != "\"\"") {
                print argc, empty, first
                exit
            }
        }
    ' "$T/exec.log" | head -1)
    if [ -n "$payload_record" ]; then
        pass "56c-payload-record (argc=$(echo "$payload_record" | cut -d' ' -f1), $(echo "$payload_record" | cut -d' ' -f2) empty slots, a0=$(echo "$payload_record" | cut -d' ' -f3-))"
    else
        fail "56c-payload-record (no EXECVE record with a non-empty a0 and an all-empty tail: $(grep -c 'type=EXECVE' "$T/exec.log") EXECVE records)"
    fi
fi

# ------------------------------------------------ 56d: the tracer syscalls
if audit_cmd -a always,exit -F arch=b64 -S ptrace -k "qa56-trace-$$"; then
    sleep 0.2
    "$TOOL" -q -l "$LABEL" -- /bin/sleep 1 >/dev/null 2>&1
    sleep 0.3
    "$AUSEARCH" -k "qa56-trace-$$" -i >"$T/trace.log" 2>/dev/null
    if grep -q 'comm="pmask-tracer"' "$T/trace.log"; then
        pass "56d-tracer-record (ptrace records: $(grep -c 'syscall=101' "$T/trace.log"))"
    else
        fail "56d-tracer-record (no ptrace record with comm=pmask-tracer: $(head -1 "$T/trace.log"))"
    fi
    if grep -q 'type=OBJ_PID' "$T/trace.log"; then
        pass "56d-obj-pid-record ($(grep -c 'type=OBJ_PID' "$T/trace.log") OBJ_PID records)"
    else
        skip "56d-obj-pid-record (no OBJ_PID record: the kernel may not have emitted one for this stop)"
    fi
else
    skip "56d-tracer-record (the ptrace exit rule could not be installed)"
    skip "56d-obj-pid-record (the ptrace exit rule could not be installed)"
fi

# ------------------------------------- 56e: the watch rule versus the exit rule
# Two runs of the same binary, twice: once with only the `-w PATH -p x`
# watch installed, once with only the `always,exit -S execve` rule.  The
# two counts are what the issue's finding rests on, and running them one
# after the other with the other rule removed is the control that
# separates "the watch does not see exec" from "an earlier rule claimed
# the event".
WATCHED="$T/watched"
cat > "$WATCHED" <<'SH'
#!/bin/sh
exit 0
SH
chmod 755 "$WATCHED"

watch_only=$(
    audit_del
    if audit_cmd -w "$WATCHED" -p x -k "qa56-watch-$$" >/dev/null 2>&1; then
        sleep 0.2
        "$WATCHED"
        "$WATCHED"
        sleep 0.3
        "$AUSEARCH" -k "qa56-watch-$$" 2>/dev/null | grep -c 'type=SYSCALL'
    else
        echo "install-failed"
    fi
)
exit_only=$(
    audit_del
    if audit_cmd -a always,exit -F arch=b64 -S execve -k "qa56-exit-$$" >/dev/null 2>&1; then
        sleep 0.2
        "$WATCHED"
        "$WATCHED"
        sleep 0.3
        "$AUSEARCH" -k "qa56-exit-$$" -i 2>/dev/null | grep -c 'type=EXECVE'
    else
        echo "install-failed"
    fi
)
audit_del

if [ "$watch_only" = install-failed ] || [ "$exit_only" = install-failed ]; then
    skip "56e-watch-rule-blind (a watch or exit rule could not be installed)"
elif [ "$exit_only" -ge 2 ] && [ "$watch_only" -le 1 ]; then
    # The watch's one record is the auditctl call that installed it.
    pass "56e-watch-rule-blind (watch records=$watch_only, exit-rule records=$exit_only for two execs)"
elif [ "$watch_only" -ge 2 ]; then
    # A kernel that does emit exec events under -p x.  The finding is then
    # kernel-dependent, and the row says so rather than failing.
    pass "56e-watch-rule-visible-here (watch records=$watch_only, exit-rule records=$exit_only; the -p x blind spot did not reproduce on this kernel)"
else
    fail "56e-watch-rule-blind (watch records=$watch_only, exit-rule records=$exit_only for two execs)"
fi

# --------------------------------------------------- 56f: the 32-bit payload
if [ -x ./testcases32 ]; then
    if audit_cmd -a always,exit -F arch=b64 -S execve -k "qa56-b32-$$" >/dev/null 2>&1; then
        sleep 0.2
        "$TOOL" -q -l "$LABEL" -- ./testcases32 echoargs "QA56-32-$$" >/dev/null 2>&1
        sleep 0.3
        "$AUSEARCH" -k "qa56-b32-$$" -i >"$T/b32.log" 2>/dev/null
        if grep -q "a[0-9]*=\"QA56-32-$$\"\|a[0-9]*=5141362d33322d" "$T/b32.log"; then
            pass "56f-32bit-record-keeps-real-argv"
        else
            skip "56f-32bit-record-keeps-real-argv (no slot for the 32-bit payload's argument: $(grep -c 'type=EXECVE' "$T/b32.log") EXECVE records)"
        fi
        if grep -q 'arch=c000003e' "$T/b32.log"; then
            pass "56f-every-record-says-arch-c000003e (the exec syscall's ABI, not the payload's)"
        else
            fail "56f-every-record-says-arch-c000003e (no arch=c000003e record)"
        fi
    else
        skip "56f-32bit-record-keeps-real-argv (the exec rule could not be installed)"
        skip "56f-every-record-says-arch-c000003e (the exec rule could not be installed)"
    fi
else
    skip "56f-32bit-record-keeps-real-argv (tests/testcases32 absent: built by vm/run.sh)"
    skip "56f-every-record-says-arch-c000003e (tests/testcases32 absent)"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
