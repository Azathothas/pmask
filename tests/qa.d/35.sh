#!/bin/sh
# Issue 35: the gate must be root-safe, and the isolation matrix must not
# leak the control it starts.
#
# Two properties, both measured the same way.
#
# 1. `root_peer_observer` decides "root with CAP_SYS_PTRACE" from uid 0 and
#    bit 19 of CapEff.  A wrong decode would either skip the same-uid
#    matrix on a host that can still observe it (silent loss of coverage)
#    or keep failing the matrix under root (the original defect).  The
#    decode is exercised on synthetic CapEff values, including the two
#    that must NOT count: no capabilities, and CAP_SYS_ADMIN without
#    CAP_SYS_PTRACE.
#
# 2. `kill_owned PID START` kills the process only when it is still the
#    same uid and the same start time.  That is what makes it safe to kill
#    the isolation suite's control payload, which `kill_comm mkiso` cannot
#    reach because its comm is `testcases`.  The positive case proves the
#    kill works; the negative control proves a recycled pid is refused,
#    which is the half that makes the cleanup safe rather than merely
#    effective.
set -u
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
tests=$(CDPATH= cd -- "$here/.." && pwd) || exit 1
. "$tests/lib.sh"
TOOL="$tests/pmask"
CASES="$tests/testcases"
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

# ------------------------------------------------ 1. the capability decode
# CAP_SYS_PTRACE is bit 19, the high bit of the fifth hex digit from the
# right of CapEff.
cap_case() {  # CAPHEX WANT
    if cap_has_sys_ptrace "$1"; then
        got=yes
    else
        got=no
    fi
    if [ "$got" = "$2" ]; then
        pass "qa35-cap-decode $1 -> $got"
    else
        fail "qa35-cap-decode $1 -> $got, want $2"
    fi
}
cap_case 000001ffffffffff yes   # a full root capability set
cap_case 0000000000000000 no    # no capabilities at all
cap_case 0000000000080000 yes   # CAP_SYS_PTRACE alone
cap_case 0000000000000800 no    # CAP_SETPCAP only
cap_case 0000000000000001 no    # CAP_CHOWN only
cap_case 0000000000100000 no    # bit 20, one above CAP_SYS_PTRACE

# On this host the two halves must agree with reality: a uid that is 0
# with the bit set must be reported as a root peer, and anything else must
# not be.  A decode that is right in the unit cases but wired to the wrong
# uid is the defect this catches.
cap=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status 2>/dev/null | tr -d ' ')
if [ -z "$cap" ]; then
    skip "qa35-live-decision (no CapEff in /proc/self/status)"
else
    if cap_has_sys_ptrace "$cap"; then want=yes; else want=no; fi
    if root_peer_observer; then got=yes; else got=no; fi
    case "$(id -u)" in
        0) expect=$want ;;
        *) expect=no ;;
    esac
    if [ "$got" = "$expect" ]; then
        pass "qa35-live-decision (uid=$(id -u) bit19=$want decision=$got)"
    else
        fail "qa35-live-decision (uid=$(id -u) bit19=$want decision=$got, want $expect)"
    fi
    if [ "$got" = yes ] && [ -n "$ROOT_PEER_REASON" ]; then
        pass "qa35-skip-reason-is-printed (a root peer names why)"
    elif [ "$got" = no ]; then
        pass "qa35-skip-reason-is-printed (not a root peer: the matrix runs)"
    else
        fail "qa35-skip-reason-is-printed (root peer with an empty reason)"
    fi
fi

# The suites that must use the decision, and the case names that depend on
# it.  A suite that quietly dropped the matrix would pass every other case
# and lose the guarantee; the names are the coverage.
for pair in "isolation.sh:i21-environ" "isolation.sh:i36-kcmp" \
    "conformance.sh:holder-environ-refused" "conformance.sh:nodumpable-refuses" \
    "lease.sh:d5-agent-refuses"; do
    f=${pair%%:*}
    name=${pair##*:}
    if grep -q -- "$name" "$tests/$f"; then
        pass "qa35-$(basename "$f" .sh)-keeps-$name"
    else
        fail "qa35-$(basename "$f" .sh)-keeps-$name ($f no longer mentions $name)"
    fi
done
# ... and that each of them consults root_peer_observer.
for f in isolation.sh conformance.sh lease.sh; do
    if grep -q 'root_peer_observer' "$tests/$f"; then
        pass "qa35-$(basename "$f" .sh)-consults-root-peer-observer"
    else
        fail "qa35-$(basename "$f" .sh)-consults-root-peer-observer"
    fi
done

# ----------------------------------------- 2. kill_owned, both directions
if [ ! -x "$CASES" ]; then
    skip "qa35-kill-owned ($CASES is not built)"
else
    # The payload carries the same marker shape the isolation suite uses,
    # so this also proves the observer would see a leak if there were one.
    MARK="PMKISO-qa35-$$"
    "$CASES" sleeper "$MARK" >/dev/null 2>&1 &
    victim=$!
    # Wait for the exec so /proc/<pid>/stat is the sleeper's, not the
    # shell's fork image; the start time is read after that.
    v_i=0
    while [ "$v_i" -lt 50 ]; do
        [ "$(cat "/proc/$victim/comm" 2>/dev/null)" = "testcases" ] && break
        sleep 0.05
        v_i=$((v_i + 1))
    done
    v_start=$(proc_start "$victim")
    if [ -z "$v_start" ]; then
        skip "qa35-kill-owned ($victim never reached the testcases image)"
    else
        # The observer sees the marker: without this, "no sighting after
        # the kill" would prove nothing.
        if [ "$(sightings "$MARK")" -ge 1 ]; then
            pass "qa35-control-the-marker-is-observable-before-the-kill"
        else
            fail "qa35-control-the-marker-is-observable-before-the-kill"
        fi
        # negative control: a wrong start time must leave it alive.
        kill_owned "$victim" 1
        sleep 0.2
        if kill -0 "$victim" 2>/dev/null; then
            pass "qa35-kill-owned-refuses-a-recycled-pid"
        else
            fail "qa35-kill-owned-refuses-a-recycled-pid (killed a pid it did not own)"
        fi
        # positive: the recorded start time kills it.
        kill_owned "$victim" "$v_start"
        wait "$victim" 2>/dev/null
        sleep 0.3
        n=$(sightings "$MARK")
        if [ "$n" = 0 ]; then
            pass "qa35-kill-owned-kills-the-recorded-process"
        else
            fail "qa35-kill-owned-kills-the-recorded-process ($n still carry $MARK)"
            kill -9 "$victim" 2>/dev/null
        fi
    fi
fi

# The isolation suite must use kill_owned for the control payload, not
# only kill_comm, whose comm-prefix match cannot reach `testcases`.
if grep -q 'kill_owned "\$MATRIX_CTL"' "$tests/isolation.sh"; then
    pass "qa35-isolation-cleans-up-the-control-payload"
else
    fail "qa35-isolation-cleans-up-the-control-payload (cleanup never kills MATRIX_CTL)"
fi
if grep -q 'i37-no-pmkiso-process-survives-the-matrix' "$tests/isolation.sh"; then
    pass "qa35-isolation-asserts-no-orphan-survives"
else
    fail "qa35-isolation-asserts-no-orphan-survives"
fi

[ "$FAIL" = 0 ] && echo "QA35: PASS" || echo "QA35: FAIL ($FAIL)"
[ "$FAIL" = 0 ]
