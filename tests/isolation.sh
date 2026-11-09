#!/bin/sh
# ============================================================================
# pmask isolation suite -- one group per mechanism in src/isolate.rs.
#
# Every group has a control that must behave differently from the tested
# run, so a group cannot pass because the observer saw nothing.  The defect
# each group catches is named in its header comment.
#
# Cases that need something this machine may lack print SKIP with the
# reason.  A SKIP is never a PASS and is not counted as one.
#
#   I1  the requested set and the effective set are both named, in full
#   I2  PR_SET_NO_NEW_PRIVS is set in the payload
#   I3  the PID namespace shows only the payload
#   I4  the UTS namespace carries a neutral hostname
#   I5  the IPC namespace is not the host's
#   I6  the cgroup namespace is not the host's
#   I7  the private /tmp is empty and the host's is not claimed
#   I8  /dev holds only the bound device nodes and the members issue 25
#       added, and they work
#   I9  a refused mount is named and does not abort the run
#   I10 Landlock denies a path outside its allowlist (with a positive control)
#   I11 the payload's exit status and stdout pass through unchanged
#   I12 --env and --env-file reach the isolated payload; PATH survives
#   I13 a label that isolate mode cannot apply is reported, not dropped;
#       without --label the supervisor's own entry gets the program name
#   I14 --secret-close-on-exec is refused in isolate mode (no tracer)
#   I15 an env: or literal: secret is refused, and the supervisor's own
#       environ is masked without --label
#   I16 --secret-close-on-exec with no secret says it has nothing to close
#   I17 the host-profile matrix: each override it uses is asserted in
#       the probe report, and the selected mode and mode_reason are
#       asserted in the run report
#   I18 --redact --isolate is the composed spelling of --unshare, and
#       --redact with --no-redact is refused
#
# Three groups run before the availability gate:
#   I0a --isolate=fs is refused, and --help does not advertise it
#   I0b the shipped payload unit's allow-list names ptrace
#   I17 the host-profile matrix, which uses the probe overrides and skips
#       a row whose real mechanism the host lacks
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
T="/tmp/mkiso.$$"
mkdir -p "$T" || { echo "FATAL: cannot create $T"; exit 2; }

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    # The control payload is started directly, so its comm is the test
    # binary's name and `kill_comm mkiso` never matches it: kill the pid
    # and the label as well.  A leak here poisons the /proc sweep in
    # tests/edge.sh, which runs after this suite.
    [ -n "${MATRIX_CTL:-}" ] && kill -9 "$MATRIX_CTL" 2>/dev/null
    [ -n "${MATRIX_PID:-}" ] && kill -9 "$MATRIX_PID" 2>/dev/null
    [ -n "${MATRIX_SUP:-}" ] && kill -9 "$MATRIX_SUP" 2>/dev/null
    kill_comm mkiso KILL 2>/dev/null
    [ -n "${MATRIX_LABEL:-}" ] && kill_label "$MATRIX_LABEL" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT

# report_of ERR_FILE -> the effective isolation line, or empty
report_of() {
    sed -n 's/^pmask: isolation: //p' "$1" 2>/dev/null | head -1
}

# has SEGMENTS NAME -> 0 when the report names NAME exactly
has() {
    case ",$1," in
        *",$2,"*|*",$2:"*|*",$2="*) return 0 ;;
    esac
    return 1
}

# iso_run OUT ERR ARGS... -> exit status of pmask --isolate ARGS...
iso_run() {
    ir_out=$1
    ir_err=$2
    shift 2
    "$TOOL" --isolate "$@" >"$ir_out" 2>"$ir_err" </dev/null
}

# ---------------------------------------- I0a: --isolate=fs is not an option
# Catches: a help text or a design note advertising a namespace-free
# filesystem mode that the parser does not accept.
"$TOOL" -q --isolate=fs "$CASES" true >"$T/fs.out" 2>"$T/fs.err" </dev/null
fs_rc=$?
if [ "$fs_rc" = 255 ] && grep -q -- "--isolate takes pid,net,tmp,all or none" "$T/fs.err"; then
    pass "i0a-isolate-fs-refused-by-the-parser"
else
    fail "i0a-isolate-fs-refused-by-the-parser (rc=$fs_rc err=[$(cat "$T/fs.err")])"
fi
if "$TOOL" --help 2>&1 | grep -q -- "--isolate=fs"; then
    fail "i0a-help-does-not-advertise-isolate-fs (--isolate=fs is in --help)"
else
    pass "i0a-help-does-not-advertise-isolate-fs"
fi

# ------------------------------ I0b: the shipped payload unit permits ptrace
# Catches: SystemCallFilter=@system-service without ptrace, which makes the
# pmask inside the unit fall back to plain mode.  The semantic proof is
# `systemd-analyze verify` on a systemd host (C-027); this is the cheap
# guard against a revert.
UNIT="$(pwd)/../contrib/systemd/pmask-run@.service"
if [ ! -f "$UNIT" ]; then
    skip "i0b-payload-unit-permits-ptrace ($UNIT is not staged)"
elif grep -Eq '^SystemCallFilter=(.*[[:space:]])?ptrace([[:space:]]|$)' "$UNIT"; then
    pass "i0b-payload-unit-permits-ptrace"
else
    fail "i0b-payload-unit-permits-ptrace (no allow-list line names ptrace)"
fi

# ------------------------------- I17: the host-profile matrix
# Catches: a probe that is read but never consumed, and a mode selection
# that ignores an axis.  Each row sets one PMASK_PROBE_<NAME> override,
# asserts the probe report shows that answer (so the override ran and the
# real syscall was skipped), then asserts the run report's mode and
# mode_reason.  The controls at the end prove that a wrong mode and a
# wrong probe value are both refused.
#
# The rows run before the availability gate: the overrides let the matrix
# run on a host that does not offer every profile.  A row that needs the
# real mechanism (ptrace for the redaction path, userns for the isolate
# path) is skipped when the host lacks it, never passed.
json_string() {
    sed -n 's/^[[:space:]]*"'"$2"'": "\([^"]*\)".*/\1/p' "$1" | head -1
}

json_scalar() {
    sed -n 's/^[[:space:]]*"'"$2"'": \([^,}]*\).*/\1/p' "$1" | head -1
}

json_has() {
    grep -q '"'"$2"'":' "$1"
}

# profile_row NAME OVERRIDES PROBE_KEY PROBE_WANT MODE_WANT REASON_WANT [ARGS...]
profile_row() {
    pr_name=$1
    pr_env=$2
    pr_key=$3
    pr_probe=$4
    pr_mode=$5
    pr_reason=$6
    shift 6
    # shellcheck disable=SC2086
    env $pr_env "$TOOL" probe --json >"$T/$pr_name.probe" 2>"$T/$pr_name.probe.err"
    pr_rc=$?
    pr_got=$(json_scalar "$T/$pr_name.probe" "$pr_key")
    if [ "$pr_rc" != 0 ] || [ "$pr_got" != "$pr_probe" ]; then
        fail "$pr_name-probe ($pr_key=[$pr_got], want [$pr_probe], rc=$pr_rc)"
        return 0
    fi
    # shellcheck disable=SC2086
    env $pr_env "$TOOL" --report=json --secret T=file:"$T/matrix.tok" "$@" \
        -- /bin/true >"$T/$pr_name.json" 2>"$T/$pr_name.err"
    pr_rc=$?
    if [ "$pr_rc" != 0 ]; then
        fail "$pr_name-run (rc=$pr_rc: $(tr '\n' '|' < "$T/$pr_name.err"))"
        return 0
    fi
    if ! json_has "$T/$pr_name.json" mode_reason; then
        fail "$pr_name-report (no mode_reason field)"
        return 0
    fi
    pr_got_mode=$(json_string "$T/$pr_name.json" mode)
    pr_got_reason=$(json_string "$T/$pr_name.json" mode_reason)
    if [ "$pr_got_mode" = "$pr_mode" ] && [ "$pr_got_reason" = "$pr_reason" ]; then
        pass "$pr_name (mode=$pr_got_mode reason=[$pr_got_reason] $pr_key=$pr_got)"
    else
        fail "$pr_name (mode=[$pr_got_mode] want [$pr_mode], reason=[$pr_got_reason] want [$pr_reason], $pr_key=[$pr_got])"
    fi
}

printf 'matrix-token\n' > "$T/matrix.tok"
chmod 600 "$T/matrix.tok"

"$TOOL" probe --json >"$T/matrix-host.json" 2>/dev/null
host_ptrace=$(json_scalar "$T/matrix-host.json" metadata_redaction)
host_memfd=$(json_scalar "$T/matrix-host.json" memfd_secret)
host_userns=$(json_scalar "$T/matrix-host.json" isolation)
host_landlock=$(json_scalar "$T/matrix-host.json" landlock_abi)
host_seccomp=$(json_scalar "$T/matrix-host.json" seccomp_filter)
host_scope=$(sed -n 's/.*"ptrace_scope": \([0-9][0-9]*\).*/\1/p' "$T/matrix-host.json" | head -1)
if [ "$host_seccomp" = true ]; then
    ptrace_reason=seccomp
elif [ -n "$host_scope" ] && [ "$host_scope" -ge 3 ] 2>/dev/null; then
    ptrace_reason=yama_ptrace_scope
else
    ptrace_reason=no_capability
fi
if [ "$host_ptrace" = true ]; then
    default_mode=redact
    default_reason=""
else
    default_mode=plain
    default_reason=$ptrace_reason
fi

# ptrace: the allowed row needs the real syscall; the banned row does not.
if [ "$host_ptrace" = true ]; then
    profile_row i17a-profile-ptrace-allowed PMASK_PROBE_PTRACE=1 \
        metadata_redaction true redact ""
else
    skip "i17a-profile-ptrace-allowed: the host refuses ptrace, so the allowed row cannot run"
fi
profile_row i17b-profile-ptrace-banned PMASK_PROBE_PTRACE=0 \
    metadata_redaction false plain "$ptrace_reason"

# memfd_secret: the mode does not change, so the probe report is the
# assertion that the override ran.
profile_row i17c-profile-memfd-present PMASK_PROBE_MEMFD_SECRET=1 \
    memfd_secret true "$default_mode" "$default_reason"
profile_row i17d-profile-memfd-absent PMASK_PROBE_MEMFD_SECRET=0 \
    memfd_secret false "$default_mode" "$default_reason"

# userns: present selects isolate; absent degrades to redact and names the
# axis.  A host without ptrace runs plain before either branch.
if [ "$host_userns" = true ]; then
    if [ "$host_ptrace" = true ]; then
        profile_row i17e-profile-userns-present PMASK_PROBE_USERNS=1 \
            isolation true isolate "" --isolate
    else
        profile_row i17e-profile-userns-present PMASK_PROBE_USERNS=1 \
            isolation true plain "$ptrace_reason" --isolate
    fi
else
    skip "i17e-profile-userns-present: the host has no user namespaces, so the isolate row cannot run"
fi
if [ "$host_ptrace" = true ]; then
    profile_row i17f-profile-userns-absent PMASK_PROBE_USERNS=0 \
        isolation false redact isolate_unavailable --isolate
else
    profile_row i17f-profile-userns-absent PMASK_PROBE_USERNS=0 \
        isolation false plain "$ptrace_reason" --isolate
fi

# Landlock: the ABI does not change the mode; the probe report carries it.
profile_row i17g-profile-landlock-abi-0 PMASK_PROBE_LANDLOCK_ABI=0 \
    landlock_abi 0 "$default_mode" "$default_reason"
profile_row i17h-profile-landlock-abi-1 PMASK_PROBE_LANDLOCK_ABI=1 \
    landlock_abi 1 "$default_mode" "$default_reason"
profile_row i17i-profile-landlock-abi-3 PMASK_PROBE_LANDLOCK_ABI=3 \
    landlock_abi 3 "$default_mode" "$default_reason"
profile_row i17j-profile-landlock-abi-6 PMASK_PROBE_LANDLOCK_ABI=6 \
    landlock_abi 6 "$default_mode" "$default_reason"

# Controls: the host value is one of the two row values, and a wrong mode
# and a wrong probe value are each refused.  The subshell keeps the
# injected failures out of this suite's count.
case "$host_ptrace" in
    true|false) pass "i17-control-ptrace-host-value-is-a-row-value ($host_ptrace)" ;;
    *) fail "i17-control-ptrace-host-value-is-a-row-value ([$host_ptrace])" ;;
esac
case "$host_memfd" in
    true|false) pass "i17-control-memfd-host-value-is-a-row-value ($host_memfd)" ;;
    *) fail "i17-control-memfd-host-value-is-a-row-value ([$host_memfd])" ;;
esac
case "$host_userns" in
    true|false) pass "i17-control-userns-host-value-is-a-row-value ($host_userns)" ;;
    *) fail "i17-control-userns-host-value-is-a-row-value ([$host_userns])" ;;
esac
case "$host_landlock" in
    ''|*[!0-9]*) fail "i17-control-landlock-host-value-is-a-number ([$host_landlock])" ;;
    *) pass "i17-control-landlock-host-value-is-a-number ($host_landlock)" ;;
esac
ctl=$( ( profile_row i17-control-wrong-mode PMASK_PROBE_PTRACE=1 \
    metadata_redaction true plain "" ) 2>&1 )
case "$ctl" in
    *"FAIL i17-control-wrong-mode"*) pass "i17-control-a-wrong-mode-is-refused" ;;
    *) fail "i17-control-a-wrong-mode-is-refused (got: $(printf '%s' "$ctl" | tr '\n' '|'))" ;;
esac
ctl=$( ( profile_row i17-control-wrong-probe PMASK_PROBE_PTRACE=1 \
    metadata_redaction false redact "" ) 2>&1 )
case "$ctl" in
    *"FAIL i17-control-wrong-probe-probe"*) pass "i17-control-a-wrong-probe-is-refused" ;;
    *) fail "i17-control-a-wrong-probe-is-refused (got: $(printf '%s' "$ctl" | tr '\n' '|'))" ;;
esac

# ------------------------------------------------------ availability gate
# One probe decides the whole suite: without a user namespace there is no
# isolation to test, and every case below would report a false failure.
"$TOOL" --isolate "$CASES" count-proc >"$T/probe.out" 2>"$T/probe.err" </dev/null
probe_rc=$?
probe_rep=$(report_of "$T/probe.err")
if [ "$probe_rc" != 0 ] || [ -z "$probe_rep" ]; then
    reason=$(sed -n 's/^pmask: note: //p' "$T/probe.err" | head -1)
    [ -n "$reason" ] || reason="no 'pmask: isolation:' report (rc=$probe_rc)"
    skip "i0-isolation-available: $reason"
    # Every case below needs the namespace set, so a host without it would
    # report failures that are not the tree's.  A SKIP is not a pass and is
    # not a failure: print the verdict and stop here.
    echo "== VERDICT: FAIL=$FAIL SKIP =="
    [ "$FAIL" = 0 ] || exit 1
    exit 0
fi

host_pids=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l | tr -d ' ')
host_tmp=$(ls -a /tmp 2>/dev/null | wc -l | tr -d ' ')

# ------------------------------------------------ I1: the reported set
# Catches: a mechanism reporting itself by omission, and the effective set
# drifting from the requested one.
want="user mount pid net uts ipc cgroup tmp landlock no_new_privs dev proc"
missing=""
for m in $want; do
    has "$probe_rep" "$m" || missing="$missing $m"
done
if [ -z "$missing" ]; then
    pass "i1-effective-set-names-every-mechanism: $probe_rep"
else
    fail "i1-effective-set-names-every-mechanism (missing:$missing in [$probe_rep])"
fi

case "$probe_rep" in
    user,mount,*) pass "i1-set-starts-with-the-unconditional-namespaces" ;;
    *) fail "i1-set-starts-with-the-unconditional-namespaces (got [$probe_rep])" ;;
esac

iso_run "$T/none.out" "$T/none.err" --isolate=none "$CASES" true
none_rep=$(report_of "$T/none.err")
if has "$none_rep" "pid=off" && has "$none_rep" "net=off" && has "$none_rep" "tmp=off"; then
    pass "i1-off-switches-are-named-not-omitted"
else
    fail "i1-off-switches-are-named-not-omitted (got [$none_rep])"
fi

# --------------------------------------------------- I2: no_new_privs
# Catches: the prctl missing in the payload, or set after the exec.
iso_run "$T/nnp.out" "$T/nnp.err" "$CASES" show-nnp
nnp=$(tr -d '[:space:]' <"$T/nnp.out")
case "$nnp" in
    *NoNewPrivs:1*) pass "i2-no-new-privs-set-in-the-payload" ;;
    *) fail "i2-no-new-privs-set-in-the-payload (status said: [$nnp] [$T/nnp.err])" ;;
esac

# control: the same binary without isolation must show the flag clear, or
# the check above proves nothing about isolate.rs
"$TOOL" -q "$CASES" show-nnp >"$T/nnp0.out" 2>/dev/null
nnp0=$(tr -d '[:space:]' <"$T/nnp0.out")
case "$nnp0" in
    *NoNewPrivs:0*) pass "i2-control-flag-clear-without-isolation" ;;
    *) skip "i2-control-flag-clear-without-isolation: this host already sets NoNewPrivs ([$nnp0])" ;;
esac

# ------------------------------------------------- I3: PID namespace
# Catches: a private procfs over the host's PID namespace, which would list
# every host process while claiming to isolate.
iso_run "$T/pid.out" "$T/pid.err" "$CASES" count-proc
inside_pids=$(sed -n 's/^proc-count=//p' "$T/pid.out")
if [ -n "$inside_pids" ] && [ "$inside_pids" -ge 1 ] && [ "$inside_pids" -le 5 ] \
    && [ "$host_pids" -gt "$inside_pids" ]; then
    pass "i3-payload-sees-only-itself (inside=$inside_pids host=$host_pids)"
else
    fail "i3-payload-sees-only-itself (inside=[$inside_pids] host=$host_pids [$T/pid.err])"
fi

# The payload is pid 1 of the new namespace when CLONE_NEWPID is in effect.
# A private procfs without it would list the host's processes.
if has "$probe_rep" "pid"; then
    pid_ns=1
else
    pid_ns=0
fi

# control: with the pid namespace off the payload must see many host
# processes, not the handful a private namespace holds.  The host count
# moves while the suite runs, so the assertion is the order of magnitude,
# not an exact equality.
iso_run "$T/nopid.out" "$T/nopid.err" --isolate=net,tmp "$CASES" count-proc
nopid_pids=$(sed -n 's/^proc-count=//p' "$T/nopid.out")
wrap_lo=$((inside_pids + 5))
if [ -n "$nopid_pids" ] && [ "$nopid_pids" -gt "$wrap_lo" ] && [ "$nopid_pids" -gt 5 ]; then
    pass "i3-control-pid-off-sees-the-host (off=$nopid_pids host~$host_pids isolated=$inside_pids)"
else
    fail "i3-control-pid-off-sees-the-host (off=[$nopid_pids] host~$host_pids isolated=$inside_pids, want off > $wrap_lo)"
fi

# ------------------------------------------------- I4: UTS namespace
# Catches: CLONE_NEWUTS missing, or the hostname left naming the host.
host_name=$(uname -n 2>/dev/null)
iso_run "$T/uts.out" "$T/uts.err" /bin/sh -c 'uname -n'
in_name=$(sed -n '1p' "$T/uts.out")
if [ "$in_name" = "pmask" ] && [ "$in_name" != "$host_name" ]; then
    pass "i4-neutral-hostname-inside (host=$host_name inside=$in_name)"
elif [ "$in_name" = "pmask" ]; then
    skip "i4-neutral-hostname-inside: the host is already named $in_name"
else
    fail "i4-neutral-hostname-inside (host=$host_name inside=[$in_name] [$T/uts.err])"
fi

# control: with the UTS namespace off the payload must NOT be renamed.
# `--isolate=none` still creates a UTS namespace (it costs nothing to
# refuse and cannot weaken the view), so the control is the unisolated run.
# Catches: a hostname that was already neutral, which would make the case
# above pass for the wrong reason.
"$TOOL" -q /bin/sh -c 'uname -n' >"$T/nouts.out" 2>/dev/null
nout_name=$(sed -n '1p' "$T/nouts.out")
if [ "$nout_name" = "$host_name" ]; then
    pass "i4-control-without-isolation-sees-the-host-name"
elif [ "$host_name" = "pmask" ]; then
    skip "i4-control-without-isolation-sees-the-host-name: the host itself is named pmask, so the neutral name proves nothing"
else
    fail "i4-control-without-isolation-sees-the-host-name (host=$host_name plain=[$nout_name])"
fi

# ------------------------------------------------- I5: IPC namespace
# Catches: CLONE_NEWIPC claimed but not created.
host_ipc=$(readlink /proc/self/ns/ipc 2>/dev/null)
iso_run "$T/ipc.out" "$T/ipc.err" /bin/sh -c 'readlink /proc/self/ns/ipc'
in_ipc=$(sed -n '1p' "$T/ipc.out")
if has "$probe_rep" "ipc" && [ -n "$in_ipc" ] && [ "$in_ipc" != "$host_ipc" ]; then
    pass "i5-ipc-namespace-is-not-the-host's ($in_ipc)"
elif has "$probe_rep" "ipc=refused(EPERM)" || has "$probe_rep" "ipc=refused(EINVAL)"; then
    skip "i5-ipc-namespace-is-not-the-host's: this kernel refuses CLONE_NEWIPC"
else
    fail "i5-ipc-namespace-is-not-the-host's (host=[$host_ipc] inside=[$in_ipc])"
fi

# ------------------------------------------------- I6: cgroup namespace
# Catches: CLONE_NEWCGROUP claimed but not created; the payload then reads
# the host's cgroup path out of /proc/<pid>/cgroup.
host_cg=$(readlink /proc/self/ns/cgroup 2>/dev/null)
iso_run "$T/cg.out" "$T/cg.err" /bin/sh -c 'readlink /proc/self/ns/cgroup; cat /proc/self/cgroup'
in_cg=$(sed -n '1p' "$T/cg.out")
in_cgpath=$(sed -n '2p' "$T/cg.out")
if has "$probe_rep" "cgroup" && [ -n "$in_cg" ] && [ "$in_cg" != "$host_cg" ]; then
    pass "i6-cgroup-namespace-is-not-the-host's ($in_cg)"
elif has "$probe_rep" "cgroup=refused(EPERM)" || has "$probe_rep" "cgroup=refused(EINVAL)"; then
    skip "i6-cgroup-namespace-is-not-the-host's: this kernel refuses CLONE_NEWCGROUP"
else
    fail "i6-cgroup-namespace-is-not-the-host's (host=[$host_cg] inside=[$in_cg])"
fi
if [ "$in_cgpath" = "0::/" ]; then
    pass "i6-cgroup-path-is-the-namespace-root"
else
    fail "i6-cgroup-path-is-the-namespace-root (got [$in_cgpath], want 0::/)"
fi

# ------------------------------------------------- I7: private /tmp
# Catches: the private tmpfs mount failing silently, which leaves the host's
# /tmp readable while the run claims a private one.
canary="mkiso-canary.$$"
: > "/tmp/$canary" || skip "i7-private-tmp-empty: cannot write a canary into /tmp"
wrote_canary=0
[ -f "/tmp/$canary" ] && wrote_canary=1

iso_run "$T/tmp.out" "$T/tmp.err" /bin/sh -c "ls -a /tmp | grep -c '^$canary\$' || true"
tmp_hits=$(sed -n '1p' "$T/tmp.out" | tr -d ' ')
if [ "$wrote_canary" != 1 ]; then
    skip "i7-private-tmp-empty: no canary in /tmp to look for"
elif has "$probe_rep" "tmp"; then
    if [ "$tmp_hits" = "0" ]; then
        pass "i7-private-tmp-hides-the-host's-files"
    else
        fail "i7-private-tmp-hides-the-host's-files (canary visible $tmp_hits time(s) while the report claims tmp)"
    fi
elif has "$probe_rep" "tmp=refused" || has "$probe_rep" "tmp=blocked" || has "$probe_rep" "tmp=skipped"; then
    # The honest degraded form: the report must not claim tmp, and the
    # host's /tmp is then expected to be visible.
    if [ "$tmp_hits" != "0" ]; then
        pass "i7-refused-tmp-is-reported-and-the-host's-/tmp-is-visible (as the report says)"
    else
        skip "i7-refused-tmp-is-reported: /tmp was empty anyway, so the negative control is silent"
    fi
else
    skip "i7-private-tmp: the report names neither tmp nor a refusal ($probe_rep)"
fi

# control: with the private tmpfs off the same canary IS visible
iso_run "$T/tmpoff.out" "$T/tmpoff.err" --isolate=pid,net /bin/sh -c "ls -a /tmp | grep -c '^$canary\$' || true"
tmpoff_hits=$(sed -n '1p' "$T/tmpoff.out" | tr -d ' ')
if [ "$wrote_canary" = 1 ] && [ "$tmpoff_hits" != "0" ]; then
    pass "i7-control-tmp-off-sees-the-host's-files"
else
    fail "i7-control-tmp-off-sees-the-host's-files (canary sightings=$tmpoff_hits, want >=1)"
fi

# ------------------------------ I7b: a payload that lives under /tmp
# Catches: the private tmpfs mounted over the directory holding the
# payload's own binary, which makes the binary unreachable and the run fail
# with execve ENOENT while the description still claims a private /tmp.
if [ -x "$CASES" ]; then
    cp "$CASES" "$T/under-tmp" 2>/dev/null
    if [ ! -x "$T/under-tmp" ]; then
        skip "i7b-payload-under-tmp: cannot stage a copy of the test binary in $T"
    else
        "$TOOL" --isolate "$T/under-tmp" count-proc >"$T/utmp.out" 2>"$T/utmp.err" </dev/null
        utmp_rc=$?
        utmp_rep=$(report_of "$T/utmp.err")
        utmp_n=$(sed -n 's/^proc-count=//p' "$T/utmp.out")
        if [ "$utmp_rc" = 0 ] && [ -n "$utmp_n" ]; then
            pass "i7b-payload-under-tmp-still-runs (rc=$utmp_rc inside=$utmp_n)"
        else
            fail "i7b-payload-under-tmp-still-runs (rc=$utmp_rc [$T/utmp.err])"
        fi
        # Either the tmpfs was skipped and says so, or the payload ran with a
        # private tmp.  What may never happen is a claim of a private /tmp
        # together with a failure to exec.
        if [ "$utmp_rc" != 0 ]; then
            fail "i7b-payload-under-tmp-is-not-a-false-tmp-claim ($utmp_rep)"
        else
            case "$utmp_rep" in
                *tmp=refused*|*tmp=blocked*|*tmp=skipped*)
                    pass "i7b-payload-under-tmp-reports-the-tmp-degradation" ;;
                *)
                    pass "i7b-payload-under-tmp-kept-a-private-tmp" ;;
            esac
        fi
    fi
fi

# ------------------------------------------------------- I8: fresh /dev
# Catches: the host's /dev left in place, or a tmpfs mounted over it with no
# usable device nodes.  `/dev/pts`, `/dev/ptmx` and `/dev/shm` are part of
# the fresh /dev since issue 25 (a pty-using payload needs them), so they
# are expected rather than leaks; each is checked for usability below.
iso_run "$T/dev.out" "$T/dev.err" /bin/sh -c 'ls /dev'
dev_list=$(tr '\n' ' ' <"$T/dev.out")
if has "$probe_rep" "dev"; then
    unexpected=""
    for n in $dev_list; do
        case "$n" in
            null|zero|full|random|urandom|tty|fd|stdin|stdout|stderr|pts|ptmx|shm) ;;
            *) unexpected="$unexpected $n" ;;
        esac
    done
    if [ -z "$unexpected" ]; then
        pass "i8-dev-holds-only-the-expected-nodes ($dev_list)"
    else
        fail "i8-dev-holds-only-the-expected-nodes (unexpected:$unexpected)"
    fi
    for n in null zero urandom; do
        case " $dev_list " in
            *" $n "*) ;;
            *) unexpected="$unexpected $n" ;;
        esac
    done
    if [ -z "$unexpected" ]; then
        pass "i8-dev-has-the-basic-nodes"
    else
        fail "i8-dev-has-the-basic-nodes (absent:$unexpected)"
    fi
    # A host node that exists outside the bound set must be gone.  Any one
    # of these proves the host's /dev is not visible.
    leak=""
    # `pts`, `ptmx` and `shm` are deliberately present inside (bound or
    # created by the private /dev), so they cannot serve as leak probes.
    for n in kvm mqueue fuse net console log core initctl; do
        if [ -e "/dev/$n" ]; then
            leak=$n
            break
        fi
    done
    if [ -z "$leak" ]; then
        skip "i8-control-host-dev-node-absent: this host's /dev has none of kvm mqueue fuse net console log core initctl"
    else
        case " $dev_list " in
            *" $leak "*)
                fail "i8-host-dev-node-is-gone (/dev/$leak is still visible inside)" ;;
            *)
                pass "i8-host-dev-node-is-gone (/dev/$leak exists on the host, absent inside)" ;;
        esac
    fi
    iso_run "$T/devw.out" "$T/devw.err" /bin/sh -c 'echo written > /dev/null && echo DEVNULL-OK'
    case "$(sed -n '1p' "$T/devw.out")" in
        DEVNULL-OK) pass "i8-bound-node-is-usable" ;;
        *) fail "i8-bound-node-is-usable (writing /dev/null failed)" ;;
    esac
elif has "$probe_rep" "dev=refused" || has "$probe_rep" "dev=blocked"; then
    skip "i8-fresh-dev: the kernel refused the fresh /dev ($probe_rep)"
else
    skip "i8-fresh-dev: the report names neither dev nor a refusal ($probe_rep)"
fi

# ------------------------------------------- I9: refused mounts reported
# Catches: a mount failure aborting the run, or staying silent.  A private
# procfs needs a PID namespace, so `--isolate=net,tmp` refuses it and the
# run must still finish.
iso_run "$T/refuse.out" "$T/refuse.err" --isolate=net,tmp /bin/sh -c 'echo STILL-RAN'
refuse_rc=$?
refuse_rep=$(report_of "$T/refuse.err")
if [ "$refuse_rc" = 0 ] && [ "$(sed -n '1p' "$T/refuse.out")" = "STILL-RAN" ]; then
    pass "i9-refused-mount-does-not-abort-the-run"
else
    fail "i9-refused-mount-does-not-abort-the-run (rc=$refuse_rc out=[$(cat "$T/refuse.out")])"
fi
case "$refuse_rep" in
    *proc=refused*|*proc=blocked*)
        pass "i9-refused-mount-is-named-in-the-description" ;;
    *)
        fail "i9-refused-mount-is-named-in-the-description (got [$refuse_rep])" ;;
esac
if grep -q "^pmask: isolation degraded:" "$T/refuse.err"; then
    pass "i9-refused-mount-carries-a-degraded-line"
else
    fail "i9-refused-mount-carries-a-degraded-line (no 'isolation degraded:' line)"
fi

# ------------------------------------------------------- I10: Landlock
# Catches: a ruleset that claims a filesystem restriction and then allows
# everything, and an ABI claimed without querying the kernel.
# The canary is a file outside the allowlist that the payload's own account
# can read: the repository root, which is never one of FS_POLICY_PATHS.
canary_path="$(pwd)/../Cargo.toml"
case "$probe_rep" in
    *landlock:abi=*)
        abi=$(printf '%s' "$probe_rep" | sed -n 's/.*landlock:abi=\([0-9]*\).*/\1/p')
        if [ -n "$abi" ] && [ "$abi" -ge 1 ]; then
            pass "i10-landlock-abi-is-reported (abi=$abi)"
        else
            fail "i10-landlock-abi-is-reported (abi=[$abi])"
        fi
        # positive control: a path inside the allowlist stays readable
        iso_run "$T/ll-pos.out" "$T/ll-pos.err" /bin/sh -c "cat /etc/passwd >/dev/null 2>&1 && echo ALLOWED || echo DENIED"
        if [ "$(sed -n '1p' "$T/ll-pos.out")" = "ALLOWED" ]; then
            pass "i10-landlock-still-allows-the-system-directories"
        else
            fail "i10-landlock-still-allows-the-system-directories (a policy that allows nothing is not a policy)"
        fi
        # negative control: the canary must be denied
        if [ -r "$canary_path" ]; then
            iso_run "$T/ll-neg.out" "$T/ll-neg.err" /bin/sh -c "cat '$canary_path' >/dev/null 2>&1 && echo READ || echo DENIED"
            if [ "$(sed -n '1p' "$T/ll-neg.out")" = "DENIED" ]; then
                pass "i10-landlock-denies-a-path-outside-the-allowlist ($canary_path)"
            else
                fail "i10-landlock-denies-a-path-outside-the-allowlist ($canary_path was readable)"
            fi
            # control: the same read succeeds without isolation
            if cat "$canary_path" >/dev/null 2>&1; then
                pass "i10-control-canary-is-readable-without-isolation"
            else
                fail "i10-control-canary-is-readable-without-isolation ($canary_path unreadable here)"
            fi
        else
            skip "i10-landlock-denies-a-path-outside-the-allowlist: $canary_path is not readable by this account, so there is nothing to deny"
        fi
        ;;
    *landlock=refused*)
        skip "i10-landlock: this kernel refused Landlock ($probe_rep)"
        ;;
    *)
        skip "i10-landlock: the report names neither landlock nor a refusal ($probe_rep)"
        ;;
esac

# ------------------------------------ I11: stdout and exit status pass through
# Catches: the extra fork swallowing the payload's status, or its output.
iso_run "$T/out.out" "$T/out.err" /bin/sh -c 'echo PAYLOAD-STDOUT; exit 7'
out_rc=$?
if [ "$out_rc" = 7 ] && [ "$(sed -n '1p' "$T/out.out")" = "PAYLOAD-STDOUT" ]; then
    pass "i11-stdout-and-exit-status-pass-through (rc=$out_rc)"
else
    fail "i11-stdout-and-exit-status-pass-through (rc=$out_rc out=[$(cat "$T/out.out")])"
fi

# A signal the payload handles must reach it, and its own exit code must
# come back.  A pid-namespace init ignores unhandled default-action signals
# (see i11), so the delivery is proved with a handler.
iso_run "$T/sig.out" "$T/sig.err" /bin/sh -c 'trap "exit 42" TERM; kill -TERM $$; sleep 0.2'
sig_rc=$?
if [ "$sig_rc" = 42 ]; then
    pass "i11-handled-signal-reaches-the-payload (rc=$sig_rc)"
else
    fail "i11-handled-signal-reaches-the-payload (rc=$sig_rc, want 42)"
fi

# The payload is pid 1 of its PID namespace, and the kernel drops a signal
# whose action would be the default for that pid.  This is kernel semantics,
# not a passthrough the supervisor lost, so the case asserts the semantics
# and the control shows the same command dying 143 without isolation.
iso_run "$T/dead.out" "$T/dead.err" /bin/sh -c 'kill -TERM $$'
dead_rc=$?
"$TOOL" -q /bin/sh -c 'kill -TERM $$' >/dev/null 2>&1
plain_rc=$?
if [ "$pid_ns" = 1 ] && [ "$dead_rc" = 0 ] && [ "$plain_rc" = 143 ]; then
    pass "i11-pid-namespace-init-drops-a-default-action-signal (isolated rc=$dead_rc, unisolated rc=$plain_rc)"
elif [ "$pid_ns" != 1 ] && [ "$dead_rc" = 143 ]; then
    pass "i11-signal-death-is-128-plus-signal without a pid namespace (rc=$dead_rc)"
else
    fail "i11-default-action-signal (isolated rc=$dead_rc, unisolated rc=$plain_rc, pid_ns=$pid_ns)"
fi

# ------------------------------------- I12: --env in isolate mode
# Catches: the isolate path building the environment from vars_os() alone,
# which drops --env and --env-file.
iso_run "$T/env.out" "$T/env.err" --env MK_ISO_E=isoval "$CASES" getenv MK_ISO_E
env_out=$(sed -n '1p' "$T/env.out")
[ "$env_out" = "MK_ISO_E=isoval" ] && pass "i12-env-reaches-the-isolated-payload" \
    || fail "i12-env-reaches-the-isolated-payload (got [$env_out] [$T/env.err])"

printf 'MK_ISO_F=fileval\n' > "$T/iso.env"
iso_run "$T/envf.out" "$T/envf.err" --env-file "$T/iso.env" "$CASES" getenv MK_ISO_F
envf_out=$(sed -n '1p' "$T/envf.out")
[ "$envf_out" = "MK_ISO_F=fileval" ] && pass "i12-env-file-reaches-the-isolated-payload" \
    || fail "i12-env-file-reaches-the-isolated-payload (got [$envf_out])"

# control: without --env the same name is not there
iso_run "$T/envc.out" "$T/envc.err" "$CASES" getenv MK_ISO_E
envc_out=$(sed -n '1p' "$T/envc.out")
[ "$envc_out" = "MK_ISO_E unset" ] && pass "i12-control-env-not-set-without-the-flag" \
    || fail "i12-control-env-not-set-without-the-flag (got [$envc_out])"

# the inherited environment still reaches the payload
iso_run "$T/path.out" "$T/path.err" "$CASES" getenv PATH
path_out=$(sed -n '1p' "$T/path.out")
case "$path_out" in
    PATH=*) pass "i12-inherited-path-survives" ;;
    *) fail "i12-inherited-path-survives (got [$path_out])" ;;
esac

# ---------------------------------- I13: a label is not silently dropped
# Catches: --label accepted in isolate mode and never applied, with no
# note.  Isolate mode does not redact the payload's /proc, so the payload
# cannot be labelled; the run must say so.  The supervisor's own entry is
# labelled, which I13b asserts.
iso_run "$T/label.out" "$T/label.err" --label mkiso-label "$CASES" true
if grep -q "^pmask: note: the payload's label was not applied: isolate mode" "$T/label.err"; then
    pass "i13-label-not-applied-is-visible"
else
    fail "i13-label-not-applied-is-visible (stderr: $(tr '\n' '|' < "$T/label.err"))"
fi

# I13b: the supervisor's own cmdline carries the label in isolate mode.
"$TOOL" --isolate --label mkiso-sup /bin/sh -c 'sleep 2' >/dev/null 2>"$T/sup.err" &
SUP=$!
sup_text=""
i13_i=0
while [ "$i13_i" -lt 40 ]; do
    sup_text=$(tr -d '\000' < "/proc/$SUP/cmdline" 2>/dev/null)
    [ "$sup_text" = "mkiso-sup" ] && break
    kill -0 "$SUP" 2>/dev/null || break
    sleep 0.1
    i13_i=$((i13_i + 1))
done
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null
[ "$sup_text" = "mkiso-sup" ] && pass "i13b-supervisor-cmdline-is-the-label" \
    || fail "i13b-supervisor-cmdline-is-the-label (cmdline=[$sup_text])"

# I13c: without --label the supervisor's own entry gets the program
# basename.  Catches: isolate mode leaving the supervisor's full command
# line (and any literal: secret in it) in /proc until it exits.
"$TOOL" --isolate /bin/sh -c 'sleep 1' >/dev/null 2>"$T/sup2.err" &
SUP=$!
sup_text=""
i13_i=0
while [ "$i13_i" -lt 40 ]; do
    sup_text=$(tr -d '\000' < "/proc/$SUP/cmdline" 2>/dev/null)
    [ "$sup_text" = "sh" ] && break
    kill -0 "$SUP" 2>/dev/null || break
    sleep 0.1
    i13_i=$((i13_i + 1))
done
wait "$SUP" 2>/dev/null
[ "$sup_text" = "sh" ] && pass "i13c-supervisor-cmdline-is-the-program-basename" \
    || fail "i13c-supervisor-cmdline-is-the-program-basename (cmdline=[$sup_text])"

# --------------------- I14: close-on-exec needs the tracer
# Isolate mode has no tracer, so the flag cannot be enforced: FD_CLOEXEC
# would close the payload's own copy at its exec, and without it every
# descendant would inherit the descriptor.  The combination is refused,
# naming both flags.
printf 'iso-token\n' > "$T/i14.tok"
chmod 600 "$T/i14.tok"
out=$("$TOOL" --isolate --secret-close-on-exec --secret T=file:"$T/i14.tok" \
    -- /bin/true 2>&1)
rc=$?
if [ "$rc" = 255 ] && printf '%s' "$out" | grep -q -- '--isolate' \
    && printf '%s' "$out" | grep -q -- '--secret-close-on-exec'; then
    pass "i14-isolate-refuses-close-on-exec"
else
    fail "i14-isolate-refuses-close-on-exec (rc=$rc out=$(printf '%s' "$out" | tr '\n' '|'))"
fi
# The advice must name the flag that makes the refusal unavoidable;
# "run where ptrace is available" cannot help an explicit --isolate.
if printf '%s' "$out" | grep -q -- "drop --isolate" \
    && ! printf '%s' "$out" | grep -q "run where ptrace is available"; then
    pass "i14-refusal-advice-names-isolate"
else
    fail "i14-refusal-advice-names-isolate (out=$(printf '%s' "$out" | tr '\n' '|'))"
fi

# ---------------------------------- I15: an env: secret in isolate mode
# Catches: isolate mode accepting an env: source while it cannot redact
# the payload's environ, which leaves the value readable for the whole
# run; and a supervisor that does not mask its own entry without --label.
out=$(MK_ISO_ENV=MK-ISO-ENVSECRET "$TOOL" --isolate --secret T=env:MK_ISO_ENV \
    -- "$CASES" sleeper 2>&1)
rc=$?
if [ "$rc" = 255 ] && printf '%s' "$out" | grep -q "env:MK_ISO_ENV" \
    && printf '%s' "$out" | grep -q -- "--allow-argv-secret"; then
    pass "i15-isolate-refuses-an-env-secret"
else
    fail "i15-isolate-refuses-an-env-secret (rc=$rc out=$(printf '%s' "$out" | tr '\n' '|'))"
fi
[ "$(sightings MK-ISO-ENVSECRET)" = 0 ] \
    && pass "i15-refused-env-secret-leaves-no-process" \
    || fail "i15-refused-env-secret-leaves-no-process ($(sightings MK-ISO-ENVSECRET) sightings)"

out=$("$TOOL" --isolate --secret T=literal:MK-ISO-LITSECRET -- "$CASES" sleeper 2>&1)
rc=$?
if [ "$rc" = 255 ] && printf '%s' "$out" | grep -q "literal:"; then
    pass "i15-isolate-refuses-a-literal-secret"
else
    fail "i15-isolate-refuses-a-literal-secret (rc=$rc out=$(printf '%s' "$out" | tr '\n' '|'))"
fi

# The positive half: a file: source is allowed, and the child reads it
# from the delivered descriptor.  This is the regression case for the
# isolate child restoring dumpability before it signals ready: the parent
# writes the child's id maps through /proc/<pid>/uid_map, which a
# non-dumpable process does not let it open.
printf 'iso-secret-value' > "$T/i15b.tok"
chmod 600 "$T/i15b.tok"
out=$("$TOOL" --isolate --secret T=file:"$T/i15b.tok" -- "$CASES" secretfd T 16 2>&1)
rc=$?
if [ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'fd=3' \
    && printf '%s' "$out" | grep -q 'bytes=16'; then
    pass "i15b-isolate-delivers-a-file-secret"
else
    fail "i15b-isolate-delivers-a-file-secret (rc=$rc out=$(printf '%s' "$out" | tr '\n' '|'))"
fi

# control: the supervisor masks its own environ in isolate mode even
# without a secret.  The payload's inherited environ keeps the value,
# which is the documented limit that makes the env: source above a
# refusal.
MK_ISO_ENV=MK-ISO-ENVSECRET "$TOOL" --isolate /bin/sh -c 'sleep 1' \
    >/dev/null 2>"$T/i15.err" &
SUP=$!
sleep 0.5
sup_env=$(tr '\0' '\n' < "/proc/$SUP/environ" 2>/dev/null)
payload_hits=$(environ_hits MK-ISO-ENVSECRET)
wait "$SUP" 2>/dev/null
case "$sup_env" in
    *MK-ISO-ENVSECRET*)
        fail "i15-supervisor-environ-is-masked (the value is still in /proc/$SUP/environ)" ;;
    *) pass "i15-supervisor-environ-is-masked" ;;
esac
[ "$payload_hits" -ge 1 ] \
    && pass "i15-control-payload-environ-keeps-the-value ($payload_hits)" \
    || fail "i15-control-payload-environ-keeps-the-value (observer saw $payload_hits)"
[ "$(sightings MK-ISO-ENVSECRET)" = 0 ] \
    && pass "i15-value-is-gone-after-the-run" \
    || fail "i15-value-is-gone-after-the-run ($(sightings MK-ISO-ENVSECRET) sightings)"

# --------------------------- I16: close-on-exec with no secret
# Catches: --isolate --secret-close-on-exec with no secret silently
# dropping the flag.  The help says the refusal is for a delivered
# secret; with nothing to close the run says so.
err=$("$TOOL" --isolate --secret-close-on-exec -- /bin/true 2>&1 >/dev/null); rc=$?
if [ "$rc" = 0 ] && printf '%s' "$err" | grep -q "has nothing to close"; then
    pass "i16-no-secret-close-on-exec-is-named"
else
    fail "i16-no-secret-close-on-exec-is-named (rc=$rc err=[$err])"
fi

# --------------------------- I17: --redact --isolate composes
# Catches: the two-flag spelling being refused, or composing without the
# label.  The pair is the composed spelling of --unshare: the label
# applies and the payload gets a private pid namespace and procfs.
ctl_n=$("$TOOL" -q "$CASES" count-proc 2>/dev/null | sed -n 's/^proc-count=//p')
out=$("$TOOL" --redact --isolate -l mk-i18 /bin/sh -c "cat /proc/self/comm; $CASES count-proc" 2>"$T/i18.err")
comm=$(printf '%s\n' "$out" | sed -n '1p')
n=$(printf '%s\n' "$out" | sed -n 's/^proc-count=//p')
if grep -q "^pmask: --unshare unavailable:" "$T/i18.err"; then
    skip "i18-redact-isolate ($(grep -m1 '^pmask: --unshare unavailable:' "$T/i18.err"))"
elif [ "$comm" = "mk-i18" ] && [ -n "$n" ] && [ "$n" -le 3 ] \
    && [ -n "$ctl_n" ] && [ "$ctl_n" -gt "$n" ]; then
    pass "i18-redact-isolate-composes-label-and-private-view (inside=$n outside=$ctl_n)"
else
    fail "i18-redact-isolate-composes-label-and-private-view (comm=[$comm] inside=[$n] outside=[$ctl_n])"
fi
err=$("$TOOL" --redact --no-redact -- /bin/true 2>&1 >/dev/null); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q "contradict"; then
    pass "i18-redact-and-no-redact-contradict"
else
    fail "i18-redact-and-no-redact-contradict (rc=$rc err=[$err])"
fi

# ============================================================================
# I19 to I36: the per-interface matrix
#
# docs/research/MICROVM-GAP.md has one row per interface with its state in
# this tree.  A closed row is redacted by default; a partial row is closed
# only with --no-dumpable.  Each case below reads one interface from a live
# masked payload and from a live unmasked control, so a refusal proves the
# flag and not a missing file.  The open rows are limits in
# docs/THREAT-MODEL.md, not cases.
#
# One masked session and one control session serve the whole group.  The
# label is short enough for comm (15 bytes); the canary is in argv and in
# the environment of both.
# ============================================================================

MATRIX_LABEL=mkisomatrix
MATRIX_CAN=PMKISO-$$
MATRIX_PY=""
command -v python3 >/dev/null 2>&1 && [ -r helpers/procprobe.py ] && MATRIX_PY=helpers/procprobe.py

# matrix_child SUPERVISOR -> the direct child pid, or empty
matrix_child() {
    mc_sup=$1
    mc_pid=""
    mc_i=0
    while [ "$mc_i" -lt 50 ]; do
        for mc_d in /proc/[0-9]*; do
            mc_p=${mc_d#/proc/}
            [ "$mc_p" = "$$" ] && continue
            mc_pp=$(sed -n 's/^PPid:[[:space:]]*//p' "$mc_d/status" 2>/dev/null)
            [ "$mc_pp" = "$mc_sup" ] || continue
            mc_pid=$mc_p
        done
        [ -n "$mc_pid" ] && break
        kill -0 "$mc_sup" 2>/dev/null || break
        sleep 0.05 2>/dev/null || sleep 1
        mc_i=$((mc_i + 1))
    done
    printf '%s' "$mc_pid"
}

# matrix_read PID FILE -> 0 when the file can be read
matrix_read() {
    ( cat "/proc/$1/$2" ) >/dev/null 2>&1
}

# matrix_open PID FILE -> 0 when the file can be opened
matrix_open() {
    ( : < "/proc/$1/$2" ) >/dev/null 2>&1
}

# matrix_dir PID DIR -> 0 when the directory can be listed
matrix_dir() {
    ( ls "/proc/$1/$2" ) >/dev/null 2>&1
}

# matrix_link PID PATH -> 0 when readlink resolves
matrix_link() {
    ( readlink "/proc/$1/$2" ) >/dev/null 2>&1
}

# matrix_bytes PID FILE -> byte count, or empty when the read is refused
matrix_bytes() {
    ( wc -c < "/proc/$1/$2" ) 2>/dev/null | tr -d ' '
}

# matrix_probe OP PID -> the helper's one-line answer
matrix_probe() {
    if [ -z "$MATRIX_PY" ]; then
        printf 'no-python'
        return 0
    fi
    python3 "$MATRIX_PY" "$1" "$2" 2>/dev/null
}

# matrix_has TEXT NEEDLE -> 0 when TEXT contains NEEDLE
matrix_has() {
    case "$1" in
        *"$2"*) return 0 ;;
    esac
    return 1
}

MATRIX_SUP=""
MATRIX_PID=""
MATRIX_CTL=""
MK_ISO_ENV="$MATRIX_CAN" "$TOOL" run --label "$MATRIX_LABEL" --no-dumpable \
    -- "$CASES" sleeper "$MATRIX_CAN" >/dev/null 2>"$T/matrix.err" &
MATRIX_SUP=$!
MATRIX_PID=$(matrix_child "$MATRIX_SUP")
MK_ISO_ENV="$MATRIX_CAN" "$CASES" sleeper "$MATRIX_CAN" >/dev/null 2>&1 &
MATRIX_CTL=$!
sleep 0.2

if [ -z "$MATRIX_PID" ] || [ ! -d "/proc/$MATRIX_PID" ] || [ ! -d "/proc/$MATRIX_CTL" ]; then
    fail "i19-matrix-sessions-are-live (masked=[$MATRIX_PID] control=[$MATRIX_CTL])"
else
    pass "i19-matrix-sessions-are-live (masked=$MATRIX_PID control=$MATRIX_CTL)"

    # i17: cmdline is the label, not the arguments.
    m_len=$(matrix_bytes "$MATRIX_PID" cmdline)
    m_cmd=$(tr '\0' '\n' < "/proc/$MATRIX_PID/cmdline" 2>/dev/null)
    c_cmd=$(tr '\0' '\n' < "/proc/$MATRIX_CTL/cmdline" 2>/dev/null)
    want_len=$(( $(printf '%s' "$MATRIX_LABEL" | wc -c | tr -d ' ') + 1 ))
    if [ "$m_cmd" = "$MATRIX_LABEL" ] && [ "$m_len" = "$want_len" ] \
        && matrix_has "$c_cmd" "$MATRIX_CAN"; then
        pass "i19-cmdline-is-the-label (bytes=$m_len)"
    else
        fail "i19-cmdline-is-the-label (masked=[$m_cmd] bytes=[$m_len] want=$want_len control=[$c_cmd])"
    fi

    # i18: comm is the label.
    m_comm=$(cat "/proc/$MATRIX_PID/comm" 2>/dev/null)
    c_comm=$(cat "/proc/$MATRIX_CTL/comm" 2>/dev/null)
    if [ "$m_comm" = "$MATRIX_LABEL" ] && [ "$c_comm" != "$MATRIX_LABEL" ]; then
        pass "i20-comm-is-the-label (masked=$m_comm control=$c_comm)"
    else
        fail "i20-comm-is-the-label (masked=[$m_comm] control=[$c_comm])"
    fi

    # i19: environ is refused with --no-dumpable; the control's is readable
    # and carries the canary.
    if matrix_read "$MATRIX_PID" environ; then
        fail "i21-environ-refused-with-no-dumpable (readable)"
    elif matrix_read "$MATRIX_CTL" environ \
        && ( tr '\0' '\n' < "/proc/$MATRIX_CTL/environ" | grep -qF -- "$MATRIX_CAN" ); then
        pass "i21-environ-refused-with-no-dumpable"
    else
        fail "i21-environ-refused-with-no-dumpable (the control is not readable or does not carry the canary, so the refusal proves nothing)"
    fi

    # i20: maps is refused with --no-dumpable.
    m_b=$(matrix_bytes "$MATRIX_PID" maps)
    c_b=$(matrix_bytes "$MATRIX_CTL" maps)
    if [ -z "$m_b" ] && [ -n "$c_b" ] && [ "$c_b" -gt 0 ]; then
        pass "i22-maps-refused-with-no-dumpable (control bytes=$c_b)"
    else
        fail "i22-maps-refused-with-no-dumpable (masked=[$m_b] control=[$c_b])"
    fi

    # i21: smaps is refused with --no-dumpable.
    m_b=$(matrix_bytes "$MATRIX_PID" smaps)
    c_b=$(matrix_bytes "$MATRIX_CTL" smaps)
    if [ -z "$m_b" ] && [ -n "$c_b" ] && [ "$c_b" -gt 0 ]; then
        pass "i23-smaps-refused-with-no-dumpable (control bytes=$c_b)"
    else
        fail "i23-smaps-refused-with-no-dumpable (masked=[$m_b] control=[$c_b])"
    fi

    # i22: fd and fdinfo are refused with --no-dumpable.
    c_fd=$( ( ls "/proc/$MATRIX_CTL/fd" ) 2>/dev/null | wc -l | tr -d ' ' )
    c_fdi=$( ( ls "/proc/$MATRIX_CTL/fdinfo" ) 2>/dev/null | wc -l | tr -d ' ' )
    if ! matrix_dir "$MATRIX_PID" fd && ! matrix_dir "$MATRIX_PID" fdinfo \
        && [ -n "$c_fd" ] && [ "$c_fd" -gt 0 ] && [ -n "$c_fdi" ] && [ "$c_fdi" -gt 0 ]; then
        pass "i24-fd-and-fdinfo-refused-with-no-dumpable (control fd=$c_fd fdinfo=$c_fdi)"
    else
        fail "i24-fd-and-fdinfo-refused-with-no-dumpable (control fd=[$c_fd] fdinfo=[$c_fdi])"
    fi

    # i23: exe is refused with --no-dumpable.
    c_exe=$(readlink "/proc/$MATRIX_CTL/exe" 2>/dev/null)
    if ! matrix_link "$MATRIX_PID" exe && [ -n "$c_exe" ]; then
        pass "i25-exe-refused-with-no-dumpable (control=$c_exe)"
    else
        fail "i25-exe-refused-with-no-dumpable (control=[$c_exe])"
    fi

    # i24: cwd and root are refused with --no-dumpable.
    c_cwd=$(readlink "/proc/$MATRIX_CTL/cwd" 2>/dev/null)
    c_root=$(readlink "/proc/$MATRIX_CTL/root" 2>/dev/null)
    if ! matrix_link "$MATRIX_PID" cwd && ! matrix_link "$MATRIX_PID" root \
        && [ -n "$c_cwd" ] && [ -n "$c_root" ]; then
        pass "i26-cwd-and-root-refused-with-no-dumpable (control cwd=$c_cwd root=$c_root)"
    else
        fail "i26-cwd-and-root-refused-with-no-dumpable (control cwd=[$c_cwd] root=[$c_root])"
    fi

    # i25: the namespace links are refused with --no-dumpable.
    c_ns=$(readlink "/proc/$MATRIX_CTL/ns/pid" 2>/dev/null)
    if ! matrix_link "$MATRIX_PID" ns/pid && [ -n "$c_ns" ]; then
        pass "i27-ns-refused-with-no-dumpable (control=$c_ns)"
    else
        fail "i27-ns-refused-with-no-dumpable (control=[$c_ns])"
    fi

    # i26: auxv is refused with --no-dumpable.
    m_b=$(matrix_bytes "$MATRIX_PID" auxv)
    c_b=$(matrix_bytes "$MATRIX_CTL" auxv)
    if [ -z "$m_b" ] && [ -n "$c_b" ] && [ "$c_b" -gt 0 ]; then
        pass "i28-auxv-refused-with-no-dumpable (control bytes=$c_b)"
    else
        fail "i28-auxv-refused-with-no-dumpable (masked=[$m_b] control=[$c_b])"
    fi

    # i27: syscall is refused with --no-dumpable.
    m_b=$(matrix_bytes "$MATRIX_PID" syscall)
    c_b=$(matrix_bytes "$MATRIX_CTL" syscall)
    if [ -z "$m_b" ] && [ -n "$c_b" ] && [ "$c_b" -gt 0 ]; then
        pass "i29-syscall-refused-with-no-dumpable (control bytes=$c_b)"
    else
        fail "i29-syscall-refused-with-no-dumpable (masked=[$m_b] control=[$c_b])"
    fi

    # i28: io is refused with --no-dumpable.
    m_b=$(matrix_bytes "$MATRIX_PID" io)
    c_b=$(matrix_bytes "$MATRIX_CTL" io)
    if [ -z "$m_b" ] && [ -n "$c_b" ] && [ "$c_b" -gt 0 ]; then
        pass "i30-io-refused-with-no-dumpable (control bytes=$c_b)"
    else
        fail "i30-io-refused-with-no-dumpable (masked=[$m_b] control=[$c_b])"
    fi

    # i29: mem cannot be opened with --no-dumpable.
    if matrix_open "$MATRIX_PID" mem; then
        fail "i31-mem-refused-with-no-dumpable (opened)"
    elif matrix_open "$MATRIX_CTL" mem; then
        pass "i31-mem-refused-with-no-dumpable"
    else
        fail "i31-mem-refused-with-no-dumpable (the control cannot open its own mem, so the refusal proves nothing)"
    fi

    # i30 to i34 need the syscall helper.  Without python3 or the helper
    # every one of them is a SKIP with the reason, never a pass.
    if [ -z "$MATRIX_PY" ]; then
        skip "i32-pidfd-getfd-refused-with-no-dumpable: no python3 or helpers/procprobe.py"
        skip "i33-process-vm-readv-refused-with-no-dumpable: no python3 or helpers/procprobe.py"
        skip "i34-process-vm-writev-refused-with-no-dumpable: no python3 or helpers/procprobe.py"
        skip "i35-ptrace-attach-and-seize-refused-with-no-dumpable: no python3 or helpers/procprobe.py"
        skip "i36-kcmp-refused-with-no-dumpable: no python3 or helpers/procprobe.py"
    else
        # i30: pidfd_getfd is refused with --no-dumpable.
        m_out=$(matrix_probe pidfd_getfd "$MATRIX_PID")
        c_out=$(matrix_probe pidfd_getfd "$MATRIX_CTL")
        if matrix_has "$m_out" "EPERM" && matrix_has "$c_out" "ok"; then
            pass "i32-pidfd-getfd-refused-with-no-dumpable (masked=$m_out control=$c_out)"
        else
            fail "i32-pidfd-getfd-refused-with-no-dumpable (masked=[$m_out] control=[$c_out])"
        fi

        # i31: process_vm_readv is refused with --no-dumpable.
        m_out=$(matrix_probe process_vm_readv "$MATRIX_PID")
        c_out=$(matrix_probe process_vm_readv "$MATRIX_CTL")
        if matrix_has "$m_out" "EPERM" && matrix_has "$c_out" "ok"; then
            pass "i33-process-vm-readv-refused-with-no-dumpable (masked=$m_out control=$c_out)"
        else
            fail "i33-process-vm-readv-refused-with-no-dumpable (masked=[$m_out] control=[$c_out])"
        fi

        # i32: process_vm_writev is refused with --no-dumpable.
        m_out=$(matrix_probe process_vm_writev "$MATRIX_PID")
        c_out=$(matrix_probe process_vm_writev "$MATRIX_CTL")
        if matrix_has "$m_out" "EPERM" && matrix_has "$c_out" "ok"; then
            pass "i34-process-vm-writev-refused-with-no-dumpable (masked=$m_out control=$c_out)"
        else
            fail "i34-process-vm-writev-refused-with-no-dumpable (masked=[$m_out] control=[$c_out])"
        fi

        # i33: PTRACE_ATTACH and PTRACE_SEIZE are refused with --no-dumpable.
        m_a=$(matrix_probe ptrace_attach "$MATRIX_PID")
        c_a=$(matrix_probe ptrace_attach "$MATRIX_CTL")
        m_s=$(matrix_probe ptrace_seize "$MATRIX_PID")
        c_s=$(matrix_probe ptrace_seize "$MATRIX_CTL")
        if matrix_has "$m_a" "EPERM" && matrix_has "$c_a" "ok" \
            && matrix_has "$m_s" "EPERM" && matrix_has "$c_s" "ok"; then
            pass "i35-ptrace-attach-and-seize-refused-with-no-dumpable (attach masked=$m_a control=$c_a; seize masked=$m_s control=$c_s)"
        else
            fail "i35-ptrace-attach-and-seize-refused-with-no-dumpable (attach masked=[$m_a] control=[$c_a]; seize masked=[$m_s] control=[$c_s])"
        fi

        # i34: kcmp is refused with --no-dumpable.
        m_out=$(matrix_probe kcmp "$MATRIX_PID")
        c_out=$(matrix_probe kcmp "$MATRIX_CTL")
        if matrix_has "$m_out" "EPERM" && matrix_has "$c_out" "ok"; then
            pass "i36-kcmp-refused-with-no-dumpable (masked=$m_out control=$c_out)"
        else
            fail "i36-kcmp-refused-with-no-dumpable (masked=[$m_out] control=[$c_out])"
        fi
    fi
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ]
