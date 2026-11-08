#!/bin/sh
# The secret side: naming, `read`, descriptor delivery and the run report.
#
# Every case names the defect it catches, so a green run of this file is a
# statement about behaviour rather than about the script.  Cases that need
# a mechanism this host lacks print SKIP with the reason.
#
# POSIX sh only: dash and busybox ash must both run it.
set -u
cd "$(dirname "$0")" || exit 2
TOOL="$(pwd)/pmask"
[ -x "$TOOL" ] || { echo "FATAL: $TOOL is missing"; exit 2; }
CASES="$(pwd)/testcases"

T=$(mktemp -d "${TMPDIR:-/tmp}/pmask-secrets.XXXXXX") || exit 2
chmod 700 "$T"
trap 'rm -rf "$T"' EXIT INT TERM
PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "PASS $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL $*"; }
skip() { SKIP=$((SKIP + 1)); echo "SKIP $*"; }

# A secret file at 0600, so no permission warning competes with the output.
mksecret() {  # FILE VALUE
    printf '%s' "$2" > "$1"
    chmod 600 "$1"
}

# ---------------------------------------------------------- A: name mapping
# Catches: two secrets that collapse to one environment variable, which
# leaves the first unreachable and delivers the second twice.

S="$T/name"
mkdir -p "$S"
mksecret "$S/a" alpha
mksecret "$S/b" beta

out=$("$TOOL" run --no-redact --secret a=file:"$S/a" --secret A=file:"$S/b" \
    -- /bin/true 2>&1)
rc=$?
if [ "$rc" = 0 ]; then
    fail "a1-colliding-names-refused (rc=0)"
elif ! printf '%s' "$out" | grep -q "both map to"; then
    fail "a1-colliding-names-refused (message: $(printf '%s' "$out" | tr '\n' '|'))"
elif ! printf '%s' "$out" | grep -q "'a'" || ! printf '%s' "$out" | grep -q "'A'"; then
    fail "a1-colliding-names-refused (does not name both originals: $(printf '%s' "$out" | tr '\n' '|'))"
else
    pass "a1-colliding-names-refused"
fi

out=$("$TOOL" run --no-redact --secret deploy-token=file:"$S/a" \
    --secret deploy_token=file:"$S/b" -- /bin/true 2>&1)
[ "$?" != 0 ] && printf '%s' "$out" | grep -q "both map to" \
    && pass "a2-punctuation-collision-refused" \
    || fail "a2-punctuation-collision-refused ($(printf '%s' "$out" | tr '\n' '|'))"

out=$("$TOOL" run --no-redact --secret ""=file:"$S/a" -- /bin/true 2>&1)
[ "$?" != 0 ] && pass "a3-empty-name-refused" \
    || fail "a3-empty-name-refused (rc=0)"

LONGNAME=$(printf 'x%.0s' $(seq 1 65))
out=$("$TOOL" run --no-redact --secret "$LONGNAME"=file:"$S/a" -- /bin/true 2>&1)
[ "$?" != 0 ] && pass "a4-over-long-name-refused" \
    || fail "a4-over-long-name-refused (rc=0)"

out=$("$TOOL" run --no-redact --secret TOKEN=file:"$S/a" \
    --secret OTHER=file:"$S/b" -- /bin/true 2>&1)
[ "$?" = 0 ] && pass "a5-distinct-names-accepted" \
    || fail "a5-distinct-names-accepted ($(printf '%s' "$out" | tr '\n' '|'))"

# -------------------------------------------------------------- B: `read`
# Catches: a read that shares the descriptor offset, so the second read in
# one tree returns nothing; a newline appended to a value that has one; a
# newline missing where the value has none.

R="$T/read"
mkdir -p "$R"
printf 'tok-123\n' > "$R/nl"
printf 'no-newline' > "$R/plain"
chmod 600 "$R/nl" "$R/plain"

# A descriptor the caller opened is the same open file description the
# child inherits, so its offset persists across both reads.
(
    exec 3< "$R/nl"
    PMASK_SECRET_T=3 "$TOOL" read T
    PMASK_SECRET_T=3 "$TOOL" read T
) > "$T/b1.out"
printf 'tok-123\ntok-123\n' > "$T/b1.want"
if cmp -s "$T/b1.out" "$T/b1.want"; then
    pass "b1-read-is-repeatable"
else
    fail "b1-read-is-repeatable (od: $(od -c "$T/b1.out" | head -2 | tr '\n' '|'))"
fi

# The value already ends with a newline, so the output must not add one.
# Written straight to a file: a command substitution would strip the
# trailing newline and hide the very thing this case measures.
PMASK_SECRET_T=3 "$TOOL" read T 3< "$R/nl" > "$T/b2.out"
printf 'tok-123\n' > "$T/b2.want"
cmp -s "$T/b2.out" "$T/b2.want" && pass "b2-newline-not-doubled" \
    || fail "b2-newline-not-doubled (od: $(od -c "$T/b2.out" | head -1))"

# A value without a trailing newline gains one by default, so the shell
# sees a complete line.
PMASK_SECRET_N=3 "$TOOL" read N 3< "$R/plain" > "$T/b3.out"
printf 'no-newline\n' > "$T/b3.want"
cmp -s "$T/b3.out" "$T/b3.want" && pass "b3-newline-added-for-a-bare-value" \
    || fail "b3-newline-added-for-a-bare-value (od: $(od -c "$T/b3.out" | head -1))"

# With --no-newline the bytes are exactly the value, so a pipe receives
# what was written rather than what a terminal would find convenient.
PMASK_SECRET_N=3 "$TOOL" read --no-newline N 3< "$R/plain" > "$T/b4.out"
printf 'no-newline' > "$T/b4.want"
cmp -s "$T/b4.out" "$T/b4.want" && pass "b4-no-newline-is-byte-exact" \
    || fail "b4-no-newline-is-byte-exact (od: $(od -c "$T/b4.out" | head -1))"

# --fd names a descriptor without the environment lookup.
PMASK_SECRET_N=3 "$TOOL" read --fd 3 --no-newline 3< "$R/plain" > "$T/b5.out"
cmp -s "$T/b5.out" "$T/b4.want" && pass "b5-read-by-descriptor" \
    || fail "b5-read-by-descriptor (od: $(od -c "$T/b5.out" | head -1))"

# ------------------------------------------------- C: descriptor behaviour
# Catches: a descriptor that survives an exec when it should not, and a
# burn set that cannot be truncated.

D="$T/deliv"
mkdir -p "$D"
mksecret "$D/tok" 'burn-me'
mksecret "$D/tok2" 'second-value'

# --secret-close-on-exec: the supervised program reads the value, and a
# program it starts finds the descriptor closed.
# The master reads the value; the shell it starts must not inherit the
# descriptor.  This is the only shape the flag promises: the payload keeps
# the secret, its children do not, and the decision is made by the tracer
# at the child's fork rather than by FD_CLOEXEC on the payload's own exec.
# /dev/fd/3 rather than `3<&0` shell redirection: a shell would open the
# file itself when the descriptor is missing, which would pass for the
# wrong reason.
"$TOOL" run --secret-close-on-exec --secret T=file:"$D/tok" \
    -- /bin/sh -c 'if [ -r /proc/self/fd/3 ]; then echo master-has-fd; fi; /bin/sh -c "dd if=/dev/fd/3 bs=64 count=1 2>/dev/null || echo grandchild-refused"' \
    > "$T/c1.out" 2>"$T/c1.err"
rc=$?
if [ "$rc" = 0 ] && grep -q 'master-has-fd' "$T/c1.out" \
    && grep -q 'grandchild-refused' "$T/c1.out" \
    && ! grep -q 'burn-me' "$T/c1.out"; then
    pass "c1-close-on-exec-withholds-it-from-a-grandchild"
else
    fail "c1-close-on-exec-withholds-it-from-a-grandchild (rc=$rc out=$(tr '\n' '|' < "$T/c1.out"))"
fi

# The control: without the flag the same grandchild does inherit it, so
# the case above is measuring the flag and not something else.
"$TOOL" run --secret T=file:"$D/tok" \
    -- /bin/sh -c '/bin/sh -c "dd if=/dev/fd/3 bs=64 count=1 2>/dev/null || echo grandchild-refused"' \
    > "$T/c1b.out" 2>/dev/null
grep -q 'burn-me' "$T/c1b.out" \
    && pass "c1b-control-inherit-lets-the-grandchild-read" \
    || fail "c1b-control-inherit-lets-the-grandchild-read ($(tr '\n' '|' < "$T/c1b.out"))"

# The fork window, not the exec: a child that has forked from the payload
# and has not exec'd yet must not hold the descriptor.  A subshell is a
# fork without an exec and `[ -r ]` is a shell builtin, so the check runs
# in the forked child itself.  The payload keeps the descriptor.
"$TOOL" run --secret-close-on-exec --secret T=file:"$D/tok" \
    -- /bin/sh -c 'if [ -r /proc/self/fd/3 ]; then echo master-has-fd; fi
                   ( if [ -r /proc/self/fd/3 ]; then echo child-has-fd; else echo child-no-fd; fi )' \
    > "$T/c1c.out" 2>"$T/c1c.err"
if grep -q 'master-has-fd' "$T/c1c.out" && grep -q 'child-no-fd' "$T/c1c.out"; then
    pass "c1c-close-on-exec-withholds-it-at-the-fork"
else
    fail "c1c-close-on-exec-withholds-it-at-the-fork (out=$(tr '\n' '|' < "$T/c1c.out"))"
fi

# The close targets are the numbers the install writes to (3, 4, ...), not
# the numbers the supervisor happened to get.  Two secrets make the two
# target numbers distinct: the payload holds both, and the child that has
# forked and not exec'd holds neither.
"$TOOL" run --secret-close-on-exec --secret A=file:"$D/tok" --secret B=file:"$D/tok2" \
    -- /bin/sh -c 'if [ -r /proc/self/fd/3 ] && [ -r /proc/self/fd/4 ]; then echo master-has-both; fi
                   ( if [ -r /proc/self/fd/3 ] || [ -r /proc/self/fd/4 ]; then echo child-has-fd; else echo child-no-fd; fi )' \
    > "$T/c1d.out" 2>"$T/c1d.err"
if grep -q 'master-has-both' "$T/c1d.out" && grep -q 'child-no-fd' "$T/c1d.out"; then
    pass "c1d-close-targets-are-the-installed-numbers"
else
    fail "c1d-close-targets-are-the-installed-numbers (out=$(tr '\n' '|' < "$T/c1d.out"))"
fi

# A thread is not a fork: it shares the payload's descriptor table and must
# not be treated as a descendant.  A child the thread spawns is a real fork
# and loses the descriptor.  The check script reports its own descriptor and
# the payload's, so the case measures both halves.  `system()` runs the
# check under an intermediate shell, whose PPID is not the payload; that
# path prints parent-no-fd and is not the assertion.
FDCHECK="$T/fdcheck"
cat > "$FDCHECK" <<'EOF'
#!/bin/sh
if [ -r /proc/self/fd/3 ]; then echo "child-has-fd"; else echo "child-no-fd"; fi
if [ -r "/proc/$PPID/fd/3" ]; then echo "parent-has-fd"; else echo "parent-no-fd"; fi
EOF
chmod 700 "$FDCHECK"

if [ -x "$CASES" ] && command -v timeout >/dev/null 2>&1; then
    timeout 4 "$TOOL" run --secret-close-on-exec --secret T=file:"$D/tok" \
        -- "$CASES" threadspawn "$FDCHECK" MARK1 MARK2 \
        > "$T/c1g.out" 2>"$T/c1g.err"
    if grep -q 'parent-has-fd' "$T/c1g.out" \
        && ! grep -q 'child-has-fd' "$T/c1g.out" \
        && grep -q 'child-no-fd' "$T/c1g.out"; then
        pass "c1g-close-on-exec-withholds-it-from-a-thread-spawn"
    else
        fail "c1g-close-on-exec-withholds-it-from-a-thread-spawn (out=$(tr '\n' '|' < "$T/c1g.out"))"
    fi

    # vfork: the child is a real fork of the payload, so the close runs
    # before the child execs the check.
    timeout 4 "$TOOL" run --secret-close-on-exec --secret T=file:"$D/tok" \
        -- "$CASES" vforkspawn "$FDCHECK" MARK \
        > "$T/c1h.out" 2>"$T/c1h.err"
    if grep -q 'parent-has-fd' "$T/c1h.out" \
        && ! grep -q 'child-has-fd' "$T/c1h.out" \
        && grep -q 'child-no-fd' "$T/c1h.out"; then
        pass "c1h-close-on-exec-withholds-it-from-a-vfork-spawn"
    else
        fail "c1h-close-on-exec-withholds-it-from-a-vfork-spawn (out=$(tr '\n' '|' < "$T/c1h.out"))"
    fi
else
    skip "c1g-close-on-exec-withholds-it-from-a-thread-spawn (testcases or timeout unavailable)"
    skip "c1h-close-on-exec-withholds-it-from-a-vfork-spawn (testcases or timeout unavailable)"
fi

# clone(CLONE_FILES) without CLONE_THREAD shares the payload's descriptor
# table.  Closing there would close the payload's own copy, so the tracer
# leaves it open, warns, and counts the degradation.  The child and the
# payload both see fd 3; the warning and the session count are the proof
# that this is a reported limit and not a silent one.
if command -v python3 >/dev/null 2>&1; then
    cat > "$T/clonefiles.py" <<'PY'
import ctypes, os, platform, time
libc = ctypes.CDLL(None, use_errno=True)
syscalls = {"x86_64": (56, 312), "aarch64": (220, 272)}.get(platform.machine())
if syscalls is None:
    print("unsupported-arch")
    raise SystemExit(0)
sys_clone, sys_kcmp = syscalls
CLONE_FILES = 0x400
SIGCHLD = 17
KCMP_FILES = 2


def has_fd(n):
    try:
        os.fstat(n)
        return True
    except OSError:
        return False


# kcmp must answer for the tracer as well; a kernel without it keeps the
# old close and the documented limit, so the case skips instead of lying.
# The probe child sleeps so it is still alive when the parent asks.
pid = os.fork()
if pid == 0:
    time.sleep(0.5)
    os._exit(0)
kc = libc.syscall(sys_kcmp, os.getpid(), pid, KCMP_FILES, 0, 0)
os.waitpid(pid, 0)
# 0 is equal; 1, 2 and 3 are the "different" orderings.
if kc not in (0, 1, 2, 3):
    print("kcmp-unavailable")
    raise SystemExit(0)
rc = libc.syscall(sys_clone, CLONE_FILES | SIGCHLD, 0, 0, 0, 0)
if rc == 0:
    print("clone-child-has-fd" if has_fd(3) else "clone-child-no-fd", flush=True)
    os._exit(0)
print("payload-has-fd" if has_fd(3) else "payload-no-fd", flush=True)
os.waitpid(rc, 0)
PY
    "$TOOL" run --secret-close-on-exec --secret T=file:"$D/tok" \
        -- python3 "$T/clonefiles.py" > "$T/c1i.out" 2>"$T/c1i.err"
    if grep -q 'kcmp-unavailable' "$T/c1i.out"; then
        skip "c1i-clone-files-keeps-the-shared-descriptor (kcmp unavailable)"
    elif grep -q 'unsupported-arch' "$T/c1i.out"; then
        skip "c1i-clone-files-keeps-the-shared-descriptor (arch not covered by the probe)"
    elif grep -q 'clone-child-has-fd' "$T/c1i.out" \
        && grep -q 'payload-has-fd' "$T/c1i.out" \
        && grep -q "shares its parent's descriptor table" "$T/c1i.err" \
        && grep -q 'secret descriptor(s) could not be closed in a descendant' "$T/c1i.err"; then
        pass "c1i-clone-files-keeps-the-shared-descriptor"
    else
        fail "c1i-clone-files-keeps-the-shared-descriptor (out=$(tr '\n' '|' < "$T/c1i.out") err=$(tr '\n' '|' < "$T/c1i.err"))"
    fi
else
    skip "c1i-clone-files-keeps-the-shared-descriptor (python3 unavailable)"
fi

# A fork from a thread after the main thread has exited.  The kernel keeps
# a zombie group leader in the tracer's table until the whole group exits
# (measured on 7.2.0), so this exercises the thread-fork path rather than
# the leader-gone depth; the depth function itself is unit-tested in
# `src/tracer.rs`.  The worker thread keeps the payload's descriptor; the
# fork child must lose it.
if command -v python3 >/dev/null 2>&1; then
    cat > "$T/leadergone.py" <<'PY'
import ctypes, os, threading, time
libc = ctypes.CDLL(None)


def has_fd(n):
    try:
        os.fstat(n)
        return True
    except OSError:
        return False


def worker2():
    pid = os.fork()
    if pid == 0:
        print("fork-child-has-fd" if has_fd(3) else "fork-child-no-fd", flush=True)
        os._exit(0)
    os.waitpid(pid, 0)
    print("worker-has-fd" if has_fd(3) else "worker-no-fd", flush=True)
    os._exit(0)


def worker1():
    time.sleep(0.3)
    t = threading.Thread(target=worker2)
    t.start()
    t.join()


t = threading.Thread(target=worker1)
t.start()
time.sleep(0.1)
# The group leader (the main thread) exits while the worker lives.
libc.pthread_exit(None)
PY
    timeout 5 "$TOOL" run --on-exit wait --secret-close-on-exec \
        --secret T=file:"$D/tok" -- python3 "$T/leadergone.py" \
        > "$T/c1j.out" 2>"$T/c1j.err"
    if grep -q 'fork-child-no-fd' "$T/c1j.out" \
        && grep -q 'worker-has-fd' "$T/c1j.out"; then
        pass "c1j-a-thread-fork-after-the-main-thread-exits-loses-the-descriptor"
    else
        fail "c1j-a-thread-fork-after-the-main-thread-exits-loses-the-descriptor (out=$(tr '\n' '|' < "$T/c1j.out") err=$(tr '\n' '|' < "$T/c1j.err"))"
    fi
else
    skip "c1j-a-thread-fork-after-the-main-thread-exits-loses-the-descriptor (python3 unavailable)"
fi

# A close that failed is re-attempted in the next descendant, and the
# warning names what the failed child starts.  The test hook makes every
# close report a failure, so the payload's child and its grandchild both
# fail; the session count includes the inherited copy.
out=$(PMASK_FAULT_CLOSE=1 "$TOOL" run --secret-close-on-exec \
    --secret T=file:"$D/tok" -- /bin/sh -c '( sleep 0.05 & wait )' 2>&1)
rc=$?
if [ "$rc" = 0 ] \
    && printf '%s' "$out" | grep -q 'stay open in it and in what it starts' \
    && printf '%s' "$out" | grep -q '2 secret descriptor(s) could not be closed in a descendant'; then
    pass "c1k-a-failed-close-is-re-attempted-in-the-child"
else
    fail "c1k-a-failed-close-is-re-attempted-in-the-child (rc=$rc out=$(printf '%s' "$out" | tr '\n' '|'))"
fi

# The relocation above fd 200 is what keeps the image out of the secret
# install's target range; a normal run still executes the sealed image.
"$TOOL" run --rexec --secret T=file:"$D/tok" -- /bin/true >/dev/null 2>"$T/c1l.err" \
    && pass "c1l-rexec-with-a-secret-still-runs" \
    || fail "c1l-rexec-with-a-secret-still-runs ($(tr '\n' '|' < "$T/c1l.err"))"

# A failed relocation warns and drops --rexec for that run instead of
# leaving the image at a descriptor number `install_fds` may clobber
# (R1-12).  A descriptor limit of 200 makes `F_DUPFD 200` fail, the
# warning names the failure, and the on-disk program still runs (rc 0).
# `--image` has no on-disk program, so there the same failure is fatal.
if ( ulimit -n 200 ) 2>/dev/null; then
    out=$( ( ulimit -n 200; "$TOOL" --rexec -- /bin/true ) 2>&1 )
    rc=$?
    if [ "$rc" = 0 ] \
        && printf '%s' "$out" | grep -q 'cannot move the image above the secret descriptors'; then
        pass "c1m-a-failed-image-relocation-refuses-rexec"
    else
        fail "c1m-a-failed-image-relocation-refuses-rexec (rc=$rc out=$(printf '%s' "$out" | tr '\n' '|'))"
    fi
else
    skip "c1m-a-failed-image-relocation-refuses-rexec (cannot lower the descriptor limit)"
fi

# The default `--on-exit detach` policy has the same consequence for a
# descriptor whose close failed: a descendant still running when the
# program exits is detached untraced.  The policy note must be visible,
# and an explicit wait policy must not print it.
out=$("$TOOL" run --secret-close-on-exec --secret T=file:"$D/tok" -- /bin/true 2>&1)
if printf '%s' "$out" | grep -q 'default --on-exit detach'; then
    pass "c1n-the-default-detach-policy-is-named"
else
    fail "c1n-the-default-detach-policy-is-named ($(printf '%s' "$out" | tr '\n' '|'))"
fi
out=$("$TOOL" run --on-exit wait --secret-close-on-exec --secret T=file:"$D/tok" \
    -- /bin/true 2>&1)
if printf '%s' "$out" | grep -q 'default --on-exit detach'; then
    fail "c1n-control-wait-policy-has-no-note ($(printf '%s' "$out" | tr '\n' '|'))"
else
    pass "c1n-control-wait-policy-has-no-note"
fi


out=$("$TOOL" run --detach --secret-close-on-exec --secret T=file:"$D/tok" \
    -- /bin/true 2>&1)
printf '%s' "$out" | grep -q 'detach with --secret-close-on-exec' \
    && pass "c1e-detach-conflict-is-reported" \
    || fail "c1e-detach-conflict-is-reported ($(printf '%s' "$out" | tr '\n' '|'))"

# Plain mode has no tracer, so the flag cannot be enforced: FD_CLOEXEC
# would close the payload's own copy at its exec, and without it every
# descendant would inherit the descriptor.  The combination is refused,
# naming both flags, instead of silently breaking either half.
out=$("$TOOL" run --no-redact --secret-close-on-exec --secret T=file:"$D/tok" \
    -- /bin/true 2>&1)
rc=$?
if [ "$rc" = 255 ] && printf '%s' "$out" | grep -q -- '--secret-close-on-exec' \
    && printf '%s' "$out" | grep -q -- '--no-redact'; then
    pass "c1f-plain-mode-refuses-close-on-exec"
else
    fail "c1f-plain-mode-refuses-close-on-exec (rc=$rc out=$(printf '%s' "$out" | tr '\n' '|'))"
fi
# The control: plain mode itself is fine; the refusal is the combination.
"$TOOL" run --no-redact --secret T=file:"$D/tok" -- /bin/true >/dev/null 2>&1 \
    && pass "c1f-control-plain-mode-runs-without-the-flag" \
    || fail "c1f-control-plain-mode-runs-without-the-flag"

# Burn mode: the reader can truncate the value to zero, and the seal set
# permits it.  The mode exists because F_SEAL_SEAL forecloses re-sealing,
# so a burn has to be chosen when the descriptor is created.
if "$TOOL" run --no-redact --secret-burn --secret T=file:"$D/tok" \
    -- /bin/sh -c 'python3 -c "
import fcntl, os
seals = fcntl.fcntl(3, 1034)
print(\"seals=%d\" % seals)
os.ftruncate(3, 0)
print(\"after=%d\" % os.fstat(3).st_size)
"' > "$T/c2.out" 2>"$T/c2.err"; then
    if grep -q 'after=0' "$T/c2.out"; then
        pass "c2-burn-mode-can-truncate ($(grep -o 'seals=[0-9]*' "$T/c2.out"))"
    else
        fail "c2-burn-mode-can-truncate ($(tr '\n' '|' < "$T/c2.out"))"
    fi
else
    skip "c2-burn-mode-can-truncate (python3 unavailable: $(head -1 "$T/c2.err"))"
fi

# The default seal set is the other half: it must refuse the truncate, or
# the payload can destroy its own secret.
if "$TOOL" run --no-redact --secret T=file:"$D/tok" \
    -- /bin/sh -c 'python3 -c "
import os
try:
    os.ftruncate(3, 0)
    print(\"truncate-allowed\")
except OSError as e:
    print(\"truncate-refused\")
"' > "$T/c3.out" 2>"$T/c3.err"; then
    if grep -q 'truncate-refused' "$T/c3.out"; then
        pass "c3-default-seals-refuse-a-truncate"
    else
        fail "c3-default-seals-refuse-a-truncate ($(tr '\n' '|' < "$T/c3.out"))"
    fi
else
    skip "c3-default-seals-refuse-a-truncate (python3 unavailable)"
fi

# ------------------------------------------------------ D: argv-source rule
# Catches: a literal secret left in pmask's own argv for the whole run
# on a host that cannot redact /proc.

out=$("$TOOL" run --no-redact --secret T=literal:swordfish -- /bin/true 2>&1)
rc=$?
if [ "$rc" = 0 ]; then
    fail "d1-plain-mode-refuses-a-literal"
elif ! printf '%s' "$out" | grep -q "literal:"; then
    fail "d1-plain-mode-refuses-a-literal (message: $(printf '%s' "$out" | tr '\n' '|'))"
else
    pass "d1-plain-mode-refuses-a-literal"
fi

out=$("$TOOL" run --no-redact --allow-argv-secret --secret T=literal:swordfish \
    -- /bin/true 2>&1)
rc=$?
printf '%s' "$out" | grep -q "another local account can read it" && [ "$rc" = 0 ] \
    && pass "d2-allow-argv-secret-warns-and-runs" \
    || fail "d2-allow-argv-secret-warns-and-runs (rc=$rc: $(printf '%s' "$out" | tr '\n' '|'))"

# A file source is never in argv, so it must work in the same mode.
"$TOOL" run --no-redact --secret T=file:"$D/tok" -- /bin/true >/dev/null 2>&1 \
    && pass "d3-file-source-works-without-redaction" \
    || fail "d3-file-source-works-without-redaction"

# ------------------------------------------------------------- E: the report
# Catches: a report that cannot be parsed, or one that omits the fields a
# CI job needs to decide on.

"$TOOL" run --report=json --secret T=file:"$D/tok" -- /bin/true \
    > "$T/e1.json" 2>/dev/null
if command -v python3 >/dev/null 2>&1; then
    if python3 - "$T/e1.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
need = {"mode", "mode_reason", "ptrace", "payload_dumpable", "hardening", "exit", "execs", "secrets", "notes"}
missing = need - set(d)
assert not missing, "missing keys: %s" % missing
assert isinstance(d["mode_reason"], str), d["mode_reason"]
assert d["secrets"][0]["name"] == "T", d["secrets"]
assert d["secrets"][0]["fd"] == 3, d["secrets"]
assert isinstance(d["secrets"][0]["locked"], bool)
PY
    then
        pass "e1-report-json-has-the-documented-keys"
    else
        fail "e1-report-json-has-the-documented-keys ($(head -c 200 "$T/e1.json"))"
    fi
else
    skip "e1-report-json-has-the-documented-keys (python3 unavailable)"
fi

# The report must name the hardening tier, and a squeezed memlock limit
# must show up as a weaker tier rather than being assumed.
(
    ulimit -l 0 2>/dev/null || exit 0
    "$TOOL" run --report=json --secret T=file:"$D/tok" -- /bin/true
) > "$T/e2.json" 2>/dev/null
if [ -s "$T/e2.json" ] && command -v python3 >/dev/null 2>&1; then
    if python3 - "$T/e2.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["hardening"] in ("heap", "secret_mem"), d["hardening"]
assert d["secrets"][0]["locked"] is (False if d["hardening"] == "heap" else True), d
PY
    then
        pass "e2-squeezed-memlock-is-reported ($(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["hardening"])' "$T/e2.json"))"
    else
        fail "e2-squeezed-memlock-is-reported ($(head -c 200 "$T/e2.json"))"
    fi
else
    skip "e2-squeezed-memlock-is-reported (ulimit -l unsupported here or python3 unavailable)"
fi

echo "== VERDICT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP =="
[ "$FAIL" = 0 ]
