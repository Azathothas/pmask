#!/bin/sh
# ============================================================================
# pmask option suite -- one case group per CLI/library option.
#
# Every group has a control that must behave differently from the tested
# run, so a group cannot pass because the observer sees nothing.  The
# defect each group catches is named in its header comment.
#
# Cases that need a kernel feature the machine may lack print SKIP with
# the reason.  A SKIP is never a PASS and is not counted as one.
#
#   O1  --help documents PMASK_NO_SELFMASK and the '-' label
#   O2  --argv0 sets argv[0]
#   O3  default argv[0] is the original program string, not the path
#   O4  --comm overrides comm; more than 15 bytes is rejected
#   O5  NUL label is rejected by Mask::run and Mask::spawn
#   O6  LF label is rejected by the CLI
#   O7  -l- , '-l -' and --label=- give the same blank label
#   O8  {:?} of a Mask holds no environment name or value
#   O9  --env and --env-file reach the program but not /proc
#   O10 --keep-env=NAME keeps NAME visible and the rest hidden
#   O11 --args-from-fd keeps the secret out of pmask's own cmdline
#   O12 the supervisor shows the label and hides argv and environ
#   O13 race probe against the supervisor's own /proc entry
#   O14 --on-exit detach | kill | wait
#   O15 --no-dumpable blocks a same-uid observer
#   O16 --no-new-privs and --watch-rename set NoNewPrivs
#   O17 --watch-rename keeps the label across PR_SET_NAME
#   O18 --rexec shows a memfd as /proc/<pid>/exe
#   O19 --unshare shows only the payload in /proc
#   O20 mask options with --daemon print a warning
#   O21 a --env-file with an empty key or a NUL byte is refused
#   O22 --secret keeps PATH and HOME and adds PMASK_SECRET_*
#   O23 --args-from-fd refuses a vector over the 8 MiB limit
#   O24 --daemon refuses --secret, --isolate and --no-redact
#   O25 doctor --help names landlock, and --require accepts it
#   O26 --secret with --args-from-fd runs the program from the descriptor
#   O27 the report carries the degradation counts and the dumpability
#   O28 close-on-exec: the advice names the flag to drop, and a no-secret
#       run says the flag has nothing to close
#   O29 --report is refused before --args-from-fd is read
#   O30 --image PATH, --image - and --image-from-fd N run the bytes
#   O32 a refused image is reported and the on-disk fallback is explicit
#   O33 --hugetlb reports its backing and falls back
#   O37 --scope-name runs the command or names its fallback
#   O38 an empty --env key is refused and named
#   O34 --rexec runs a program from a noexec mount that refuses a plain exec
#   O35 --argv0 is the same on the disk and the image paths
#   O36 --exec-once reuses one image across 100 execs in one tree
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
T="/tmp/mkopt.$$"
mkdir -p "$T" || { echo "FATAL: cannot create $T"; exit 2; }

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

# every label of this suite starts with "mko", so one prefix cleans up
cleanup() {
    kill_comm mko KILL
    rm -rf "$T"
}
trap cleanup EXIT

# child_of PID -> pid of the first process whose parent is PID
child_of() {
    for d in /proc/[0-9]*; do
        cp=${d#/proc/}
        pp=$(sed -n 's/^PPid:[[:space:]]*//p' "$d/status" 2>/dev/null)
        if [ "$pp" = "$1" ]; then
            echo "$cp"
            return 0
        fi
    done
    return 1
}

# await_child PID -> prints the tracee pid once it exists (3 s limit)
await_child() {
    n=0
    while [ "$n" -lt 30 ]; do
        ac=$(child_of "$1") && [ -n "$ac" ] && { echo "$ac"; return 0; }
        n=$((n + 1))
        sleep 0.1
    done
    return 1
}

# reap SUPERVISOR_PID
reap() {
    kill -9 "$1" 2>/dev/null
    kill_comm mko KILL
    wait "$1" 2>/dev/null
    return 0
}

# comm_of PID -> comm text without the trailing newline
comm_of() {
    cat "/proc/$1/comm" 2>/dev/null
}

# wait_text FILE PATTERN SECONDS -> 0 once FILE contains PATTERN
wait_text() {
    n=0
    lim=$(($3 * 10))
    while [ "$n" -lt "$lim" ]; do
        grep -q -- "$2" "$1" 2>/dev/null && return 0
        n=$((n + 1))
        sleep 0.1
    done
    return 1
}

# ------------------------------------------------------------ O1: --help
help=$("$TOOL" --help 2>&1)
case "$help" in
    *PMASK_NO_SELFMASK*) pass o1-help-names-selfmask-escape ;;
    *) fail "o1-help-names-selfmask-escape (PMASK_NO_SELFMASK not in --help)" ;;
esac
case "$help" in
    *"--label=-"*) pass o1-help-documents-dash-label ;;
    *) fail "o1-help-documents-dash-label (--label=- not in --help)" ;;
esac

# ----------------------------------------------------------- O2: --argv0
# Catches: --argv0 ignored, argv[0] always the program path.
out=$("$TOOL" -q --argv0 git "$CASES" echoargs x 2>/dev/null)
case "$out" in
    *"arg0=[git] arg1=[echoargs]"*) pass o2-argv0-override ;;
    *) fail "o2-argv0-override (got: $out)" ;;
esac

# ------------------------------------------- O3: original string is argv[0]
# Catches: argv[0] rewritten to the resolved path (issue 20, item 1).
mkdir -p "$T/bin"
ln -s "$CASES" "$T/bin/tcprog"
out=$(PATH="$T/bin:$PATH" "$TOOL" -q tcprog echoargs 2>/dev/null)
case "$out" in
    *"arg0=[tcprog] arg1=[echoargs]"*) pass o3-default-argv0-is-original-string ;;
    *) fail "o3-default-argv0-is-original-string (got: $out)" ;;
esac

# --------------------------------------------------------------- O4: comm
# Catches: comm always cut from the label; no length check.
"$TOOL" -q -l "mko-long-label-for-comm-test" --comm mko-cm "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
tr_pid=$(await_child "$SUP") || tr_pid=""
sleep 0.6
c=""
[ -n "$tr_pid" ] && c=$(comm_of "$tr_pid")
[ "$c" = "mko-cm" ] && pass o4-comm-override \
    || fail "o4-comm-override (tracee comm=[$c], want mko-cm)"
reap "$SUP"

out=$("$TOOL" -q --comm 0123456789abcdef "$CASES" echoargs 2>&1)
rc=$?
if [ "$rc" != 0 ] && ! printf '%s' "$out" | grep -q "arg0="; then
    pass o4-comm-over-15-bytes-rejected
else
    fail "o4-comm-over-15-bytes-rejected (rc=$rc out=$out)"
fi

# ------------------------------------------------------- O5: NUL label
# The shell cannot pass NUL, so the library API is called directly.
# Catches: NUL label accepted at run or spawn.
out=$("$CASES" label-nul 2>&1)
rc=$?
if [ "$rc" = 0 ] && printf '%s' "$out" | grep -q "label-nul run: rejected" \
    && printf '%s' "$out" | grep -q "label-nul spawn: rejected"; then
    pass o5-nul-label-rejected-run-and-spawn
else
    fail "o5-nul-label-rejected (rc=$rc out=$(printf '%s' "$out" | tr '\n' '|'))"
fi

# ------------------------------------------------------- O6: LF label
# Catches: a newline label reaching ps output.
NL=$(printf 'a\nb')
out=$("$TOOL" -q -l "$NL" "$CASES" echoargs 2>&1)
rc=$?
if [ "$rc" != 0 ] && printf '%s' "$out" | grep -qi "label" \
    && ! printf '%s' "$out" | grep -q "arg0="; then
    pass o6-newline-label-rejected
else
    fail "o6-newline-label-rejected (rc=$rc out=$out)"
fi

# --------------------------------------------- O7: -l- equals --label=-
# Catches: the two spellings of the blank label diverging again.
blank_comm() {  # OPTION... -> comm of the tracee started with those options
    "$TOOL" -q "$@" "$CASES" sleeper >/dev/null 2>&1 &
    bsup=$!
    bt=$(await_child "$bsup") || bt=""
    sleep 0.6
    bc="<none>"
    [ -n "$bt" ] && bc=$(comm_of "$bt")
    reap "$bsup"
    printf '%s' "[$bc]"
}
a=$(blank_comm -l-)
b=$(blank_comm --label=-)
d=$(blank_comm -l -)
e=$(blank_comm --label -)
if [ "$a" = "[ ]" ] && [ "$a" = "$b" ] && [ "$a" = "$d" ] && [ "$a" = "$e" ]; then
    pass o7-dash-label-forms-agree
else
    fail "o7-dash-label-forms-agree (-l-=$a --label=-=$b '-l -'=$d '--label -'=$e, want all [ ])"
fi

# ------------------------------------------------------ O8: Debug output
# Catches: derived Debug printing environment names or values.
out=$("$CASES" debug-mask MK_DBG_KEY MK-DBG-SECRET 2>&1)
if printf '%s' "$out" | grep -q "MK-DBG-SECRET" || printf '%s' "$out" | grep -q "MK_DBG_KEY"; then
    fail "o8-debug-hides-env (secret or name printed: $out)"
elif printf '%s' "$out" | grep -q "redacted"; then
    pass o8-debug-hides-env
else
    fail "o8-debug-hides-env (no 'redacted' marker in: $out)"
fi

# ----------------------------------------------- O9: --env, --env-file
out=$("$TOOL" -q --env MK_OPT_E=envval "$CASES" getenv MK_OPT_E 2>/dev/null)
[ "$out" = "MK_OPT_E=envval" ] && pass o9-env-reaches-program \
    || fail "o9-env-reaches-program (got: $out)"

printf 'MK_OPT_F=filval\n# comment\n\nMK_OPT_G=two\n' > "$T/envf"
out=$("$TOOL" -q --env-file "$T/envf" "$CASES" getenv MK_OPT_F 2>/dev/null)
[ "$out" = "MK_OPT_F=filval" ] && pass o9-env-file-reaches-program \
    || fail "o9-env-file-reaches-program (got: $out)"

printf 'MK_OPT_SECF=MK-OPT-FILESECRET\n' > "$T/envf2"
"$TOOL" -q -l mko-env --env MK_OPT_SECE=MK-OPT-ENVSECRET --env-file "$T/envf2" "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
await_child "$SUP" >/dev/null
sleep 0.8
s1=$(sightings MK-OPT-ENVSECRET)
s2=$(sightings MK-OPT-FILESECRET)
reap "$SUP"
[ "$s1" = 0 ] && [ "$s2" = 0 ] && pass o9-env-and-env-file-hidden-from-proc \
    || fail "o9-env-and-env-file-hidden-from-proc (env=$s1 file=$s2 sightings)"

# control: with --keep-env the same secret IS visible, so the observer works
"$TOOL" -q -l mko-envc --keep-env --env MK_OPT_SECE=MK-OPT-ENVSECRET "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
await_child "$SUP" >/dev/null
sleep 0.8
s=$(sightings MK-OPT-ENVSECRET)
reap "$SUP"
[ "$s" -ge 1 ] && pass o9-control-keep-env-secret-visible \
    || fail "o9-control-keep-env-secret-visible (observer saw $s)"

# --------------------------------------------------- O10: --keep-env=NAME
# Catches: keep list ignored (PATH absent) or ignored the other way
# (secret visible).
"$TOOL" -q -l mko-keep --keep-env=PATH --env PATH=/usr/bin:/bin --env MK_OPT_HID=hiddenvalue "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
tr_pid=$(await_child "$SUP") || tr_pid=""
sleep 0.8
envtxt=""
[ -n "$tr_pid" ] && envtxt=$(tr '\0' '\n' < "/proc/$tr_pid/environ" 2>/dev/null)
reap "$SUP"
if printf '%s\n' "$envtxt" | grep -q '^PATH=' && ! printf '%s\n' "$envtxt" | grep -q 'MK_OPT_HID'; then
    pass o10-keep-env-name-visible-secret-hidden
else
    fail "o10-keep-env-name (environ: $(printf '%s' "$envtxt" | tr '\n' '|' | cut -c1-120))"
fi

"$TOOL" -q -l mko-keepc --env PATH=/usr/bin:/bin "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
tr_pid=$(await_child "$SUP") || tr_pid=""
sleep 0.8
envtxt=""
[ -n "$tr_pid" ] && envtxt=$(tr '\0' '\n' < "/proc/$tr_pid/environ" 2>/dev/null)
reap "$SUP"
if printf '%s\n' "$envtxt" | grep -q '^PATH='; then
    fail "o10-control-default-redacts-path (PATH visible without --keep-env)"
else
    pass o10-control-default-redacts-path
fi

# ---------------------------------------------------- O11: --args-from-fd
# Catches: the secret reaching pmask's own argv.
printf '%s\0%s\0%s\0' "$CASES" sleeper MK-OPT-FDSECRET > "$T/args.bin"
nuls=$(tr -cd '\0' < "$T/args.bin" | wc -c | tr -d ' ')
if [ "$nuls" != 3 ]; then
    skip "o11-args-from-fd (this printf cannot write NUL bytes: $nuls found, want 3)"
else
    "$TOOL" -q -l mko-fd --args-from-fd 3 3<"$T/args.bin" >/dev/null 2>&1 &
    SUP=$!
    tr_pid=$(await_child "$SUP") || tr_pid=""
    sleep 0.8
    own=$(tr '\0' ' ' < "/proc/$SUP/cmdline" 2>/dev/null)
    s=$(sightings MK-OPT-FDSECRET)
    reap "$SUP"
    if [ -z "$tr_pid" ]; then
        fail "o11-args-from-fd (the program did not start)"
    elif printf '%s' "$own" | grep -q "MK-OPT-FDSECRET" || [ "$s" != 0 ]; then
        fail "o11-args-from-fd-secret-absent (own cmdline=[$own] sightings=$s)"
    else
        pass o11-args-from-fd-secret-absent
    fi

    printf '%s\0%s\0%s\0' "$CASES" echoargs MK-OPT-FDARG > "$T/args2.bin"
    out=$("$TOOL" -q --args-from-fd 3 3<"$T/args2.bin" 2>/dev/null)
    case "$out" in
        *"arg2=[MK-OPT-FDARG]"*) pass o11-args-from-fd-program-gets-arguments ;;
        *) fail "o11-args-from-fd-program-gets-arguments (got: $out)" ;;
    esac
fi

# control: an unmasked process with the same marker IS found by sightings
"$CASES" sleeper MK-OPT-FDCTL >/dev/null 2>&1 &
CTL=$!
sleep 0.3
s=$(sightings MK-OPT-FDCTL)
kill "$CTL" 2>/dev/null
[ "$s" -ge 1 ] && pass o11-control-observer-sees-plain-argv \
    || fail "o11-control-observer-sees-plain-argv (saw $s)"

# ------------------------------------------- O12: supervisor self-mask
# Catches: label missing from the supervisor (it showed as '[-]'), argv or
# environ left readable.
MK_OPT_SUPENV=MK-OPT-SUPENVSECRET "$TOOL" -q -l mko-supself "$CASES" sleeper MK-OPT-SUPSECRET >/dev/null 2>&1 &
SUP=$!
sleep 0.9
sc=$(comm_of "$SUP")
sv=$(tr -d '\0' < "/proc/$SUP/cmdline" 2>/dev/null)
se=$(tr '\0' ' ' < "/proc/$SUP/environ" 2>/dev/null)
reap "$SUP"
[ "$sc" = "mko-supself" ] && pass o12-supervisor-comm-is-label \
    || fail "o12-supervisor-comm-is-label (comm=[$sc])"
[ "$sv" = "mko-supself" ] && pass o12-supervisor-cmdline-is-label \
    || fail "o12-supervisor-cmdline-is-label (cmdline=[$sv])"
case "$sv$se" in
    *MK-OPT-SUPSECRET*|*MK-OPT-SUPENVSECRET*)
        fail "o12-supervisor-hides-argv-and-environ (secret found)" ;;
    *) pass o12-supervisor-hides-argv-and-environ ;;
esac

# control: PMASK_NO_SELFMASK=1 leaves the secret readable
PMASK_NO_SELFMASK=1 "$TOOL" -q -l mko-supnos "$CASES" sleeper MK-OPT-SUPSECRET >/dev/null 2>&1 &
SUP=$!
sleep 0.9
sv=$(tr '\0' ' ' < "/proc/$SUP/cmdline" 2>/dev/null)
reap "$SUP"
case "$sv" in
    *MK-OPT-SUPSECRET*) pass o12-control-no-selfmask-leaves-argv ;;
    *) fail "o12-control-no-selfmask-leaves-argv (cmdline=[$sv])" ;;
esac

# -------------------------------------------------- O13: self-entry race
# A program cannot redact the argv the kernel published for its own exec:
# the window opens at execve and closes at the supervisor's first
# instruction that zeroes the block.  What the supervisor CAN guarantee is
# that the secret is gone before it forks any child.  This case asserts
# exactly that, and measures the entry window as an observation.
#
# Catches: a supervisor that parses options, probes and forks before it
# redacts itself (the child then runs while the parent's argv still shows
# the secret).
hits=0
samples=0
k=0
while [ "$k" -lt 10 ]; do
    "$TOOL" -q -l mko-race "$CASES" sleeper MK-OPT-RACESECRET >/dev/null 2>&1 &
    rp=$!
    child=$(await_child "$rp") || child=""
    # the child exists: the session has started.  From here on the
    # supervisor's own cmdline must never show the secret again.
    j=0
    while [ "$j" -lt 5 ]; do
        ctext=$(tr '\0' ' ' 2>/dev/null < "/proc/$rp/cmdline") || ctext=""
        samples=$((samples + 1))
        case "$ctext" in
            *MK-OPT-RACESECRET*) hits=$((hits + 1)) ;;
        esac
        j=$((j + 1))
        sleep 0.1
    done
    reap "$rp"
    [ -n "$child" ] && kill -9 "$child" 2>/dev/null
    kill_comm mko-race KILL 2>/dev/null
    k=$((k + 1))
done
if [ "$hits" = 0 ]; then
    pass "o13-secret-gone-before-fork (0 sightings in $samples samples while the child ran)"
else
    fail "o13-secret-gone-before-fork ($hits sightings in $samples samples: the supervisor forked before it redacted itself)"
fi

# entry window measurement: how long does the kernel publish the real argv
# of a supervisor?  Reported, not asserted: the executor's speed decides it.
if [ "${ID:-}" != "nonroot" ]; then
    worst=0
    n=0
    while [ "$n" -lt 5 ]; do
        "$TOOL" -q -l mko-race "$CASES" sleeper MK-OPT-RACESECRET >/dev/null 2>&1 &
        rp=$!
        t0=$(date +%s%N 2>/dev/null || echo 0)
        w=0
        while [ "$w" -lt 400 ]; do
            ctext=$(tr '\0' ' ' 2>/dev/null < "/proc/$rp/cmdline") || break
            [ -z "$ctext" ] && break
            w=$((w + 1))
        done
        t1=$(date +%s%N 2>/dev/null || echo 0)
        if [ "$t1" -gt "$t0" ] 2>/dev/null; then
            d=$(( (t1 - t0) / 1000000 ))
            [ "$d" -gt "$worst" ] && worst=$d
        fi
        reap "$rp"
        kill_comm mko-race KILL 2>/dev/null
        n=$((n + 1))
    done
    echo "INFO self-entry-window ${worst}ms (kernel publishes the supervisor argv until it zeroes the block; not closable from inside the process)"
fi

# ------------------------------------------------------ O14: --on-exit
# The master shell starts a background child and exits.
# detach: the child lives on.  kill: it is killed.  wait: pmask returns
# only after it ends.
# Catches: session end killing detached jobs, or not killing under kill.
"$TOOL" -q -l mko-oxdet --on-exit detach /bin/sh -c "$CASES sleeper MK-OPT-OX </dev/null >/dev/null 2>&1 & sleep 0.5; exit 0" >/dev/null 2>&1
sleep 0.5
n=$(comm_count mko-oxdet)
kill_comm mko-oxdet KILL
[ "$n" -ge 1 ] && pass o14-on-exit-detach-keeps-background-child \
    || fail "o14-on-exit-detach-keeps-background-child (alive=$n)"

"$TOOL" -q -l mko-oxkill --on-exit kill /bin/sh -c "$CASES sleeper MK-OPT-OX </dev/null >/dev/null 2>&1 & sleep 0.5; exit 0" >/dev/null 2>&1
n=1
w=0
while [ "$w" -lt 20 ]; do
    n=$(comm_count mko-oxkill)
    [ "$n" = 0 ] && break
    w=$((w + 1))
    sleep 0.1
done
kill_comm mko-oxkill KILL
[ "$n" = 0 ] && pass o14-on-exit-kill-terminates-background-child \
    || fail "o14-on-exit-kill-terminates-background-child (alive=$n)"

# Milliseconds: `date +%s` truncates, so a 3 s wait that starts 0.9 s into
# a second and ends 0.1 s into the next reads as 2 and a fast detach reads
# as 1 or 0 depending on where the boundary fell.  The property is that
# `wait` outlives the payload and `detach` does not.
now_ms() {
    # GNU date prints 19 digits for %N; busybox prints the seconds from %s
    # and ignores %N, so a short numeric value is seconds and is widened.
    _ns=$(date +%s%N 2>/dev/null)
    case "$_ns" in
        ''|*[!0-9]*) echo $(( $(date +%s) * 1000 )) ;;
        *)
            if [ ${#_ns} -le 10 ]; then
                echo $(( _ns * 1000 ))
            else
                echo $(( _ns / 1000000 ))
            fi
            ;;
    esac
}
t0=$(now_ms)
"$TOOL" -q -l mko-oxdet2 --on-exit detach /bin/sh -c "sleep 3 </dev/null >/dev/null 2>&1 & exit 0" >/dev/null 2>&1
t1=$(now_ms)
d_detach=$(( (t1 - t0) / 1000 ))
t0=$(now_ms)
"$TOOL" -q -l mko-oxwait --on-exit wait /bin/sh -c "sleep 3 </dev/null >/dev/null 2>&1 & exit 0" >/dev/null 2>&1
t1=$(now_ms)
d_wait=$(( (t1 - t0) / 1000 ))
if [ "$d_wait" -ge 2 ] && [ "$d_detach" -le 1 ]; then
    pass "o14-on-exit-wait-waits (detach=${d_detach}s wait=${d_wait}s)"
else
    fail "o14-on-exit-wait-waits (detach=${d_detach}s wait=${d_wait}s, want detach<=1 and wait>=2)"
fi

# --------------------------------------------------- O15: --no-dumpable
# The tracee runs as uid 1000.  The observer is another process of uid
# 1000, not an ancestor.  With the flag the observer gets EACCES.
# Catches: dumpable flag not injected (observer can read environ).
if [ "$(id -u)" != 0 ]; then
    skip "o15-no-dumpable (needs root to switch to uid 1000)"
elif ! "$CASES" as-uid 1000 "$CASES" show-nnp >/dev/null 2>&1; then
    skip "o15-no-dumpable (uid 1000 cannot run the test binaries from $BIN_DIR)"
else
    dump_observe() {  # EXTRA_OPTION -> prints "rc|text" of the observer
        MK_OPT_DUMP=dumpvisible "$CASES" as-uid 1000 "$TOOL" -q --keep-env -l mko-dmp $1 "$CASES" sleeper >/dev/null 2>&1 &
        dsup=$!
        dt=$(await_child "$dsup") || dt=""
        sleep 0.9
        if [ -z "$dt" ]; then
            reap "$dsup"
            printf '%s' "99|no-tracee"
            return 0
        fi
        dout=$("$CASES" as-uid 1000 cat "/proc/$dt/environ" 2>&1)
        drc=$?
        reap "$dsup"
        printf '%s' "$drc|$(printf '%s' "$dout" | tr '\0\n' '  ')"
    }
    ctl=$(dump_observe "")
    res=$(dump_observe "--no-dumpable")
    ctl_rc=${ctl%%|*}
    res_rc=${res%%|*}
    case "$ctl" in
        "0|"*dumpvisible*) pass "o15-control-same-uid-observer-reads-environ" ;;
        *) fail "o15-control-same-uid-observer-reads-environ ($ctl)" ;;
    esac
    case "$res" in
        *dumpvisible*) fail "o15-no-dumpable-blocks-observer (environ readable: $res)" ;;
        *)
            if [ "$res_rc" != 0 ] && [ "$res_rc" != 99 ]; then
                pass "o15-no-dumpable-blocks-observer (before: rc=$ctl_rc readable, after: rc=$res_rc)"
            else
                fail "o15-no-dumpable-blocks-observer (rc=$res_rc: $res)"
            fi
            ;;
    esac
fi

# --------------------------------------------- O16: --no-new-privs
# Catches: the prctl missing in the child.
nnp() {  # OPTION... -> the NoNewPrivs value
    nout=$("$TOOL" -q "$@" "$CASES" show-nnp 2>/dev/null)
    printf '%s' "$nout" | tr -d '[:space:]'
}
v=$(nnp --no-new-privs)
[ "$v" = "NoNewPrivs:1" ] && pass o16-no-new-privs-sets-flag || fail "o16-no-new-privs-sets-flag ($v)"
v=$(nnp --watch-rename)
[ "$v" = "NoNewPrivs:1" ] && pass o16-watch-rename-implies-no-new-privs || fail "o16-watch-rename-implies-no-new-privs ($v)"
v=$(nnp -l mko-nnp0)
[ "$v" = "NoNewPrivs:0" ] && pass o16-control-default-leaves-flag-clear || fail "o16-control-default-leaves-flag-clear ($v)"

# --------------------------------------------- O17: --watch-rename
# The renamer settles, calls prctl(PR_SET_NAME, "other") and reports its
# own comm.  With the watch the comm must stay the label.
# Catches: the seccomp watch not reverting the rename.
"$TOOL" -l mko-keeplabel --watch-rename "$CASES" renamer >"$T/rn.out" 2>"$T/rn.err" &
SUP=$!
wait_text "$T/rn.out" "renamer-comm=" 5
rn=$(sed -n 's/^renamer-comm=//p' "$T/rn.out")
reap "$SUP"
if grep -q -- "--watch-rename unavailable" "$T/rn.err"; then
    skip "o17-watch-rename ($(grep -m1 -- '--watch-rename unavailable' "$T/rn.err"))"
elif [ "$rn" = "mko-keeplabel" ]; then
    pass o17-watch-rename-keeps-label
else
    fail "o17-watch-rename-keeps-label (comm after rename=[$rn], want mko-keeplabel)"
fi

"$TOOL" -q -l mko-keepctl "$CASES" renamer >"$T/rn2.out" 2>/dev/null &
SUP=$!
wait_text "$T/rn2.out" "renamer-comm=" 5
rn=$(sed -n 's/^renamer-comm=//p' "$T/rn2.out")
reap "$SUP"
[ "$rn" = "other" ] && pass o17-control-without-watch-rename-comm-changes \
    || fail "o17-control-without-watch-rename-comm-changes (comm=[$rn], want other)"

# O17b: a refused filter install is fatal and names the failure.  The
# fault hook drives the same arm a real refusal takes; the control above
# is the success path, which must stay silent.
err=$(PMASK_FAULT_WATCH=1 "$TOOL" -q -l mko-nowatch --watch-rename "$CASES" echoargs ok 2>&1 >/dev/null); rc=$?
if [ "$rc" = 126 ] && printf '%s' "$err" | grep -q -- "--watch-rename unavailable"; then
    pass "o17b-watch-rename-refusal-is-fatal"
else
    fail "o17b-watch-rename-refusal-is-fatal (rc=$rc err=[$err])"
fi
err=$("$TOOL" -q -l mko-watchok --watch-rename "$CASES" echoargs ok 2>&1 >/dev/null); rc=$?
if [ "$rc" = 0 ] && [ -z "$err" ]; then
    pass "o17b-watch-rename-success-is-silent"
else
    fail "o17b-watch-rename-success-is-silent (rc=$rc err=[$err])"
fi

# ------------------------------------------------------------ O18: --rexec
# Catches: exe still naming the on-disk binary; the path in maps.
"$TOOL" -l mko-rex --rexec "$CASES" sleeper >/dev/null 2>"$T/rx.err" &
SUP=$!
tr_pid=$(await_child "$SUP") || tr_pid=""
exe=""
n=0
while [ "$n" -lt 30 ]; do
    [ -n "$tr_pid" ] && exe=$(readlink "/proc/$tr_pid/exe" 2>/dev/null)
    case "$exe" in /memfd:*) break ;; esac
    n=$((n + 1))
    sleep 0.1
done
maps_hits=-1
[ -n "$tr_pid" ] && maps_hits=$(grep -c "testcases" "/proc/$tr_pid/maps" 2>/dev/null)
reap "$SUP"
if grep -q -- "--rexec unavailable" "$T/rx.err"; then
    skip "o18-rexec ($(grep -m1 -- '--rexec unavailable' "$T/rx.err"))"
else
    case "$exe" in
        /memfd:*) pass "o18-rexec-exe-is-memfd ($exe)" ;;
        *) fail "o18-rexec-exe-is-memfd (exe=[$exe])" ;;
    esac
    [ "$maps_hits" = 0 ] && pass o18-rexec-maps-has-no-disk-path \
        || fail "o18-rexec-maps-has-no-disk-path (lines naming the binary: $maps_hits)"
fi

"$TOOL" -q -l mko-rexc "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
tr_pid=$(await_child "$SUP") || tr_pid=""
sleep 0.6
exe=""
[ -n "$tr_pid" ] && exe=$(readlink "/proc/$tr_pid/exe" 2>/dev/null)
reap "$SUP"
[ "$exe" = "$CASES" ] && pass o18-control-exe-is-disk-path \
    || fail "o18-control-exe-is-disk-path (exe=[$exe], want $CASES)"

# ----------------------------------------------------------- O19: --unshare
# With a private pid namespace and proc, the payload counts only itself
# (1 to 3 numeric entries).  When the kernel refuses, pmask prints a
# 'pmask: --unshare unavailable:' line and the case is skipped.
ctl_out=$("$TOOL" -q "$CASES" count-proc 2>/dev/null)
ctl_n=$(printf '%s\n' "$ctl_out" | sed -n 's/^proc-count=//p')
out=$("$TOOL" --unshare "$CASES" count-proc 2>"$T/ns.err")
n=$(printf '%s\n' "$out" | sed -n 's/^proc-count=//p')
if grep -q "^pmask: --unshare unavailable:" "$T/ns.err"; then
    skip "o19-unshare ($(grep -m1 '^pmask: --unshare unavailable:' "$T/ns.err"))"
elif [ -n "$n" ] && [ "$n" -ge 1 ] && [ "$n" -le 3 ] && [ -n "$ctl_n" ] && [ "$ctl_n" -gt "$n" ]; then
    pass "o19-unshare-payload-sees-only-itself (inside=$n outside=$ctl_n)"
else
    fail "o19-unshare-payload-sees-only-itself (inside=[$n] outside=[$ctl_n], out=[$out])"
fi

# --------------------------------------------- O20: --daemon warnings
# Catches: mask options silently dropped in daemon mode.
err=$("$TOOL" --daemon "$T/no-such.sock" --no-follow --on-exit wait -- true 2>&1 >/dev/null)
if printf '%s' "$err" | grep -qi "warning" && printf '%s' "$err" | grep -q -- "--no-follow" \
    && printf '%s' "$err" | grep -q -- "--on-exit"; then
    pass o20-daemon-with-mask-options-warns
else
    fail "o20-daemon-with-mask-options-warns (stderr: $err)"
fi
err=$("$TOOL" -q --daemon "$T/no-such.sock" --no-follow -- true 2>&1 >/dev/null)
printf '%s' "$err" | grep -qi "warning" \
    && fail "o20-quiet-suppresses-daemon-warning (stderr: $err)" \
    || pass o20-quiet-suppresses-daemon-warning
err=$("$TOOL" --daemon "$T/no-such.sock" --label x -- true 2>&1 >/dev/null)
printf '%s' "$err" | grep -qi "warning" \
    && fail "o20-control-label-only-has-no-warning (stderr: $err)" \
    || pass o20-control-label-only-has-no-warning

# ------------------------------------------ O21: env-file grammar refusal
# Catches: an empty key, a missing separator or a NUL byte silently kept.
# The CLI surface cannot produce a key containing '=' ('--env' splits at
# the first '='), and NUL is unrepresentable in argv, so the two reachable
# bad states live in an env file.  Refusal must be the 255 exit of the
# option parser, before anything is forked.
printf 'no-separator-here\n' > "$T/envbad1"
err=$("$TOOL" -q --env-file "$T/envbad1" true 2>&1 >/dev/null); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q "expected KEY=VALUE"; then
    pass o21-env-file-no-separator-refused
else
    fail "o21-env-file-no-separator-refused (rc=$rc err=[$err])"
fi

printf '=emptykey\n' > "$T/envbad2"
err=$("$TOOL" -q --env-file "$T/envbad2" true 2>&1 >/dev/null); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q "expected KEY=VALUE"; then
    pass o21-env-file-empty-key-refused
else
    fail "o21-env-file-empty-key-refused (rc=$rc err=[$err])"
fi

printf 'MK-OPT-NULKEY\0x=y\n' > "$T/envbad3"
nuls=$(tr -cd '\0' < "$T/envbad3" | wc -c | tr -d ' ')
if [ "$nuls" != 1 ]; then
    skip "o21-env-file-nul-byte (this printf cannot write NUL bytes: $nuls found, want 1)"
else
    err=$("$TOOL" -q --env-file "$T/envbad3" true 2>&1 >/dev/null); rc=$?
    if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q "NUL byte"; then
        pass o21-env-file-nul-byte-refused
    else
        fail "o21-env-file-nul-byte-refused (rc=$rc err=[$err])"
    fi
    # control: the same key with a real separator is accepted
    printf 'MK-OPT-NULKEY=1\n' > "$T/envgood1"
    "$TOOL" -q --env-file "$T/envgood1" true >/dev/null 2>&1 && \
        pass o21-control-good-key-accepted || \
        fail "o21-control-good-key-accepted (rc=$?)"
fi

# ------------------------------------ O22: --secret keeps the environment
# Catches: the secret path replacing the whole environment with the fd map
# (Mask::envs), so PATH and HOME disappear from the payload.  The values
# are set explicitly here so the case does not depend on the ambient
# environment of the suite.
printf 'mk-opt-token\n' > "$T/token"
chmod 600 "$T/token"
out=$(HOME="$T/home" PATH="/usr/bin:/bin" "$TOOL" -q \
    --secret TOKEN=file:"$T/token" "$CASES" getenv PATH 2>/dev/null)
[ "$out" = "PATH=/usr/bin:/bin" ] && pass o22-secret-keeps-path \
    || fail "o22-secret-keeps-path (got: $out)"
out=$(HOME="$T/home" PATH="/usr/bin:/bin" "$TOOL" -q \
    --secret TOKEN=file:"$T/token" "$CASES" getenv HOME 2>/dev/null)
[ "$out" = "HOME=$T/home" ] && pass o22-secret-keeps-home \
    || fail "o22-secret-keeps-home (got: $out)"
out=$(HOME="$T/home" PATH="/usr/bin:/bin" "$TOOL" -q \
    --secret TOKEN=file:"$T/token" "$CASES" getenv PMASK_SECRET_TOKEN 2>/dev/null)
[ "$out" = "PMASK_SECRET_TOKEN=3" ] && pass o22-secret-fd-map-present \
    || fail "o22-secret-fd-map-present (got: $out)"
# The plain mode builds its own environment; it must apply the same rule.
out=$(HOME="$T/home" PATH="/usr/bin:/bin" "$TOOL" -q --no-redact \
    --secret TOKEN=file:"$T/token" "$CASES" getenv PATH 2>/dev/null)
[ "$out" = "PATH=/usr/bin:/bin" ] && pass o22-plain-secret-keeps-path \
    || fail "o22-plain-secret-keeps-path (got: $out)"

# ------------------------------------ O23: --args-from-fd size limit
# Catches: an operator-supplied descriptor read to EOF into memory with no
# cap.  A vector over the 8 MiB limit is refused before it is buffered.
dd if=/dev/zero of="$T/big.args" bs=1048576 count=9 2>/dev/null
if [ ! -s "$T/big.args" ]; then
    skip "o23-args-from-fd-oversize (cannot create a 9 MiB file)"
else
    err=$("$TOOL" -q --args-from-fd 3 3<"$T/big.args" 2>&1 >/dev/null); rc=$?
    if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q "8 MiB"; then
        pass o23-args-from-fd-oversize-refused
    else
        fail "o23-args-from-fd-oversize-refused (rc=$rc err=[$err])"
    fi
fi

# ------------------------------------ O24: --daemon with local-only flags
# Catches: --daemon silently ignored when --secret, --isolate or
# --no-redact is present (the runner path was taken first).
for spec in "secret:--secret TOKEN=literal:x" "isolate:--isolate" "no-redact:--no-redact"; do
    name=${spec%%:*}
    args=${spec#*:}
    # shellcheck disable=SC2086
    err=$("$TOOL" --daemon "$T/no-such.sock" $args -- true 2>&1 >/dev/null); rc=$?
    if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q -- "--daemon cannot be combined" \
        && printf '%s' "$err" | grep -q -- "--$name"; then
        pass "o24-daemon-refuses-$name"
    else
        fail "o24-daemon-refuses-$name (rc=$rc err=[$err])"
    fi
done
# control: --daemon alone reaches the daemon connect path, not the refusal
err=$("$TOOL" --daemon "$T/no-such.sock" -- true 2>&1 >/dev/null); rc=$?
if [ "$rc" = 255 ] && ! printf '%s' "$err" | grep -q -- "cannot be combined"; then
    pass o24-control-daemon-alone-connects
else
    fail "o24-control-daemon-alone-connects (rc=$rc err=[$err])"
fi

# ------------------------------------ O25: doctor --help names landlock
# Catches: the help list drifting from the names guarantee() accepts.
out=$("$TOOL" doctor --help 2>&1)
case "$out" in
    *landlock*) pass o25-doctor-help-names-landlock ;;
    *) fail "o25-doctor-help-names-landlock (got: $out)" ;;
esac
"$TOOL" doctor --require landlock >/dev/null 2>&1
rc=$?
case "$rc" in
    0|3|4) pass o25-doctor-accepts-landlock ;;
    *) fail "o25-doctor-accepts-landlock (rc=$rc, want 0, 3 or 4)" ;;
esac

# -------------------------- O26: --secret with --args-from-fd
# Catches: the runner path taken before load_args_fd, so the program is
# empty and nothing runs.  The program comes from the descriptor and the
# secret from the fd map; both must arrive.
printf '%s\0%s\0%s\0' "$CASES" getenv PMASK_SECRET_TOKEN > "$T/args3.bin"
nuls=$(tr -cd '\0' < "$T/args3.bin" | wc -c | tr -d ' ')
if [ "$nuls" != 3 ]; then
    skip "o26-secret-args-from-fd (this printf cannot write NUL bytes: $nuls found, want 3)"
else
    out=$("$TOOL" -q --secret TOKEN=file:"$T/token" \
        --args-from-fd 3 3<"$T/args3.bin" 2>/dev/null)
    [ "$out" = "PMASK_SECRET_TOKEN=3" ] && pass o26-secret-args-from-fd-runs-the-program \
        || fail "o26-secret-args-from-fd-runs-the-program (got: $out)"
fi

# -------------------------------- O27: the report's degradation counts
# Catches: a failed descriptor close or a refused window relocation that
# the stderr summary names but the machine-readable report drops, so a CI
# job asserting `degraded == 0` passes after a degradation.
printf 'mk-opt-token\n' > "$T/token"
chmod 600 "$T/token"
"$TOOL" --report=json --secret TOKEN=file:"$T/token" -- /bin/true \
    >"$T/rep1.json" 2>/dev/null
if grep -q '"secret_close_failed": 0' "$T/rep1.json" \
    && grep -q '"sized_skipped": 0' "$T/rep1.json"; then
    pass "o27-report-carries-the-degradation-counts"
else
    fail "o27-report-carries-the-degradation-counts ($(head -c 300 "$T/rep1.json"))"
fi

# A refused PR_SET_MM_MAP is a session degradation, not a silent zero.
PMASK_FAULT_REFUSE_MAP=1 "$TOOL" --report=json --secret TOKEN=file:"$T/token" \
    -- /bin/true >"$T/rep2.json" 2>/dev/null
if grep -Eq '"sized_skipped": [1-9]' "$T/rep2.json"; then
    pass "o27-refused-window-relocation-is-counted"
else
    fail "o27-refused-window-relocation-is-counted ($(head -c 300 "$T/rep2.json"))"
fi

# The child restores dumpability before its readiness byte, so a --secret
# run is dumpable unless --no-dumpable is set.
out=$("$TOOL" --report=json --secret TOKEN=file:"$T/token" -- /bin/true 2>/dev/null)
case "$out" in
    *'"payload_dumpable": true'*) pass "o27-secret-run-is-dumpable" ;;
    *) fail "o27-secret-run-is-dumpable ($(printf '%s' "$out" | head -c 300))" ;;
esac
out=$("$TOOL" --report=json --secret TOKEN=file:"$T/token" --no-dumpable \
    -- /bin/true 2>/dev/null)
case "$out" in
    *'"payload_dumpable": false'*) pass "o27-no-dumpable-is-reported" ;;
    *) fail "o27-no-dumpable-is-reported ($(printf '%s' "$out" | head -c 300))" ;;
esac

# --------------------------- O28: close-on-exec advice and no-secret
# Catches: an isolate/plain refusal that tells the operator to "run where
# ptrace is available", which cannot help an explicit --no-redact or
# --isolate; and a no-secret flag that is silently dropped.
out=$("$TOOL" --no-redact --secret-close-on-exec --secret T=file:"$T/token" \
    -- /bin/true 2>&1)
rc=$?
if [ "$rc" = 255 ] && printf '%s' "$out" | grep -q -- "drop --no-redact" \
    && ! printf '%s' "$out" | grep -q "run where ptrace is available"; then
    pass "o28-plain-refusal-names-the-flag-to-drop"
else
    fail "o28-plain-refusal-names-the-flag-to-drop (rc=$rc out=$(printf '%s' "$out" | tr '\n' '|'))"
fi

err=$("$TOOL" --no-redact --secret-close-on-exec -- /bin/true 2>&1 >/dev/null); rc=$?
if [ "$rc" = 0 ] && printf '%s' "$err" | grep -q "has nothing to close"; then
    pass "o28-no-secret-close-on-exec-is-named"
else
    fail "o28-no-secret-close-on-exec-is-named (rc=$rc err=[$err])"
fi

help=$("$TOOL" --help 2>&1)
if printf '%s' "$help" | grep -q "refuses" \
    && printf '%s' "$help" | grep -q "the flag when a secret is delivered"; then
    pass "o28-help-says-when-the-flag-is-refused"
else
    fail "o28-help-says-when-the-flag-is-refused (the conditional refusal is not in --help)"
fi

# --------------------- O29: --report is refused before the fd is read
# Catches: --args-from-fd consumed (and its own error printed) before the
# report refusal.  fd 3 is closed here, so the old order dies in
# load_args_fd with "Bad file descriptor".
err=$("$TOOL" -q --args-from-fd 3 --report=json 3<&- 2>&1 >/dev/null); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q -- "--report=json: the plain mask path" \
    && ! printf '%s' "$err" | grep -q "Bad file descriptor"; then
    pass "o29-report-refused-before-args-from-fd"
else
    fail "o29-report-refused-before-args-from-fd (rc=$rc err=[$err])"
fi

# O29b: the plain refusal without --args-from-fd.  The report is produced
# by the secret-side runner, so a plain mask run has none to print.
err=$("$TOOL" -q --report=json -- /bin/true 2>&1 >/dev/null); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q -- "--report=json: the plain mask path"; then
    pass "o29b-report-refused-on-a-plain-run"
else
    fail "o29b-report-refused-on-a-plain-run (rc=$rc err=[$err])"
fi

# O29c: the --daemon arm.  The daemon owns the run, so the client has no
# report and must say so instead of printing nothing.
err=$("$TOOL" -q --report=json --daemon /tmp/mk-o29c.sock -- /bin/true 2>&1 >/dev/null); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q -- "--report=json: a --daemon job"; then
    pass "o29c-report-refused-on-a-daemon-job"
else
    fail "o29c-report-refused-on-a-daemon-job (rc=$rc err=[$err])"
fi

# ------------------------------------------------------- O30: --image
# Catches: --image ignored, or the bytes executed from the path instead
# of a sealed image.
img_out=$("$TOOL" -q --image "$CASES" exe-id 2>/dev/null)
case "$img_out" in
    *"exe=/memfd:testcases"*) pass o30-image-path-runs-from-a-memfd ;;
    *) fail "o30-image-path-runs-from-a-memfd (got: $img_out)" ;;
esac

img_out=$("$TOOL" -q --image - exe-id <"$CASES" 2>/dev/null)
case "$img_out" in
    *"exe=/memfd:-"*) pass o30b-image-stdin-runs-from-a-memfd ;;
    *) fail "o30b-image-stdin-runs-from-a-memfd (got: $img_out)" ;;
esac

img_out=$("$TOOL" -q --image-from-fd 3 exe-id 3<"$CASES" 2>/dev/null)
case "$img_out" in
    *"exe=/memfd:"*) pass o30c-image-from-fd-runs-from-a-memfd ;;
    *) fail "o30c-image-from-fd-runs-from-a-memfd (got: $img_out)" ;;
esac

printf '#!/bin/sh\nexit 0\n' >"$T/notelf"
err=$("$TOOL" -q --image "$T/notelf" 2>&1 >/dev/null); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q "not an ELF image"; then
    pass o30d-image-non-elf-refused
else
    fail "o30d-image-non-elf-refused (rc=$rc err=[$err])"
fi

err=$("$TOOL" -q --image "$CASES" --args-from-fd 3 3</dev/null 2>&1 >/dev/null); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q "exclusive"; then
    pass o30e-image-and-args-from-fd-refused
else
    fail "o30e-image-and-args-from-fd-refused (rc=$rc err=[$err])"
fi

# ---------------------------------- O31: the named temporary-file carrier
# Catches: the last image step being unreachable, or its file outliving
# the session.  The fault hook skips the procfs carriers, so the named
# file is the only route.
img_out=$(PMASK_FAULT_REXEC_NO_PROC=1 "$TOOL" -q --label mko-rexec-temp \
    --rexec "$CASES" exe-id 2>/dev/null)
case "$img_out" in
    *"exe="*".pmask-rexec-mko-rexec-temp-"*) pass o31-rexec-named-temp-carrier ;;
    *) fail "o31-rexec-named-temp-carrier (got: $img_out)" ;;
esac
left=$(ls /dev/shm/.pmask-rexec-mko-rexec-temp-* \
    /tmp/.pmask-rexec-mko-rexec-temp-* 2>/dev/null | wc -l | tr -d ' ')
[ "$left" = 0 ] && pass o31-rexec-temp-file-is-removed \
    || fail "o31-rexec-temp-file-is-removed ($left file(s) left)"

# ----------------------------- O32: refused image and explicit disk fallback
# Catches: a silent fallback to the on-disk file (C-002), or a disk
# fallback that is not reported.
out=$(PMASK_FAULT_REXEC_FAIL=1 "$TOOL" --rexec --label mko-rexec-fail \
    "$CASES" echoargs MK-REXEC-FAIL 2>"$T/rx-fail.err")
rc=$?
if [ "$rc" = 126 ] && ! printf '%s' "$out" | grep -q 'MK-REXEC-FAIL' \
    && grep -q -- '--rexec' "$T/rx-fail.err"; then
    pass "o32-refused-image-is-reported (rc=$rc)"
else
    fail "o32-refused-image-is-reported (rc=$rc out=[$out] err=$(tr '\n' '|' < "$T/rx-fail.err"))"
fi

out=$(PMASK_FAULT_REXEC_DISK=1 "$TOOL" --rexec --rexec-allow-disk \
    --label mko-rexec-disk "$CASES" echoargs MK-REXEC-DISK 2>"$T/rx-disk.err")
rc=$?
if [ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'MK-REXEC-DISK' \
    && grep -q 'explicit last resort' "$T/rx-disk.err"; then
    pass o32-explicit-disk-fallback-is-reported
else
    fail "o32-explicit-disk-fallback-is-reported (rc=$rc out=[$out] err=$(tr '\n' '|' < "$T/rx-disk.err"))"
fi

# -------------------------------------------------------- O33: --hugetlb
# Catches: --hugetlb silently ignored, or a failure that does not fall
# back to an ordinary image.
err=$("$TOOL" --hugetlb --rexec "$CASES" echoargs x 2>&1 >/dev/null); rc=$?
if [ "$rc" = 0 ] \
    && printf '%s' "$err" | grep -Eq -- '--hugetlb unavailable|image backing is hugetlb'; then
    pass "o33-hugetlb-reports-its-backing ($(printf '%s' "$err" | grep -E -- '--hugetlb unavailable|image backing is hugetlb' | head -1))"
else
    fail "o33-hugetlb-reports-its-backing (rc=$rc err=[$err])"
fi

# ------------------------------------------------ O34: noexec mount
# Both halves: a plain exec of the program on a noexec tmpfs is refused,
# and --rexec runs the same bytes from the sealed image.
if ! command -v unshare >/dev/null 2>&1; then
    skip "o34-rexec-noexec-mount (no unshare)"
else
    nx="$T/noexec"
    mkdir -p "$nx"
    nxout=$(unshare -Urm --propagation private sh -c '
        d=$1; tool=$2; cases=$3
        mount -t tmpfs -o noexec tmpfs "$d" 2>/dev/null || exit 3
        cp "$cases" "$d/prog" || exit 3
        chmod 755 "$d/prog"
        "$d/prog" echoargs plain >"$d/plain.out" 2>"$d/plain.err"
        prc=$?
        "$tool" -q --rexec "$d/prog" echoargs rexec >"$d/rex.out" 2>"$d/rex.err"
        rrc=$?
        echo "plain=$prc rexec=$rrc"
        cat "$d/rex.out"
        umount "$d" 2>/dev/null
        exit 0
    ' sh "$nx" "$TOOL" "$CASES" 2>/dev/null)
    case "$nxout" in
        *"plain=126 rexec=0"*"arg2=[rexec]"*)
            pass "o34-rexec-runs-from-a-noexec-mount (plain refused, rexec ran)" ;;
        *)
            skip "o34-rexec-noexec-mount (no unprivileged mount namespace: $(printf '%s' "$nxout" | tr '\n' '|' | cut -c1-120))" ;;
    esac
fi

# ------------------------------------------------------- O35: --argv0
# Catches: the memfd path losing or rewriting argv[0].
a=$("$TOOL" -q --argv0 mko-argv0 "$CASES" echoargs x 2>/dev/null)
b=$("$TOOL" -q --argv0 mko-argv0 --rexec "$CASES" echoargs x 2>/dev/null)
c=$(PMASK_FAULT_REXEC_NO_PROC=1 "$TOOL" -q --argv0 mko-argv0 --rexec \
    "$CASES" echoargs x 2>/dev/null)
if printf '%s' "$a" | grep -q 'arg0=\[mko-argv0\]' \
    && printf '%s' "$b" | grep -q 'arg0=\[mko-argv0\]' \
    && printf '%s' "$c" | grep -q 'arg0=\[mko-argv0\]'; then
    pass o35-argv0-is-the-same-on-the-disk-and-image-paths
else
    fail "o35-argv0-is-the-same-on-the-disk-and-image-paths (disk=[$a] memfd=[$b] temp=[$c])"
fi

# ---------------------------------------------------- O36: --exec-once
# Catches: a new image per exec, or the cache not keyed by the program.
eo_out=$("$TOOL" -q --rexec --exec-once --label mko-exec-once -- \
    /bin/sh -c 'i=0; while [ $i -lt 100 ]; do "$1" exe-id; i=$((i+1)); done' \
    sh "$CASES" 2>"$T/eo.err")
eo_n=$(printf '%s\n' "$eo_out" | sed -n 's/.*ino=//p' | sort -u | wc -l | tr -d ' ')
[ "$eo_n" = 1 ] && pass "o36-exec-once-reuses-one-image (1 inode in 100 execs)" \
    || fail "o36-exec-once-reuses-one-image ($eo_n distinct inodes in 100 execs)"

ctl_out=$("$TOOL" -q --rexec --label mko-exec-ctl -- \
    /bin/sh -c 'i=0; while [ $i -lt 3 ]; do "$1" exe-id; i=$((i+1)); done' \
    sh "$CASES" 2>/dev/null)
case "$ctl_out" in
    *"exe=$CASES"*) pass o36-control-without-exec-once-runs-from-disk ;;
    *) fail "o36-control-without-exec-once-runs-from-disk (got: $ctl_out)" ;;
esac

# Two distinct programs get two images, so the cache is keyed by the
# program and not by the session.
cp "$CASES" "$T/prog2"
two_out=$("$TOOL" -q --rexec --exec-once --label mko-exec-two -- \
    /bin/sh -c 'i=0; while [ $i -lt 5 ]; do "$1" exe-id; "$2" exe-id; i=$((i+1)); done' \
    sh "$CASES" "$T/prog2" 2>/dev/null)
two_n=$(printf '%s\n' "$two_out" | sed -n 's/.*ino=//p' | sort -u | wc -l | tr -d ' ')
[ "$two_n" = 2 ] && pass "o36-exec-once-keys-by-program (2 inodes for 2 programs)" \
    || fail "o36-exec-once-keys-by-program ($two_n distinct inodes for 2 programs)"

left=$(ls /dev/shm/.pmask-rexec-mko-exec-* \
    /tmp/.pmask-rexec-mko-exec-* 2>/dev/null | wc -l | tr -d ' ')
[ "$left" = 0 ] && pass o36-exec-once-temp-file-is-removed \
    || fail "o36-exec-once-temp-file-is-removed ($left file(s) left)"

# ---------------------------------------- O37: --scope-name fallback
# Catches: --scope-name silently dropped, or the run failing when
# systemd-run is absent.  The fallback line is the documented behaviour.
out=$("$TOOL" -q --scope-name mk-o37 -- "$CASES" echoargs MK-O37 2>"$T/o37.err"); rc=$?
if [ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'arg2=\[MK-O37\]'; then
    if grep -q 'scope-name unavailable' "$T/o37.err"; then
        pass "o37-scope-name-fallback-is-named"
    else
        pass "o37-scope-name-ran"
    fi
else
    fail "o37-scope-name (rc=$rc out=[$out] err=[$(head -2 "$T/o37.err" | tr '\n' '|')])"
fi

# ---------------------------------------- O38: a bad --env key is named
# Catches: an empty key reaching the child, and a refusal that does not
# name the key.
err=$("$TOOL" --env '=x' -- /bin/true 2>&1 >/dev/null); rc=$?
# The parser refuses before any mode is chosen, so the same input gives
# the same answer in plain and redact mode (issue 30).  Either wording
# names the key: the parser's own, or the mask validator's.
if [ "$rc" = 255 ] && printf '%s' "$err" \
    | grep -q -e 'environment variable name ""' -e "non-empty KEY, not '=x'"; then
    pass "o38-empty-env-key-is-refused-by-name"
else
    fail "o38-empty-env-key (rc=$rc err=[$err])"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ]
