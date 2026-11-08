#!/bin/sh
# ============================================================================
# pmask edge cases -- behaviours the main battery does not reach.
#
# Each case here pins a specific defect that was found and fixed, so a
# regression fails loudly instead of silently degrading redaction:
#
#   E1  exec failure exits 127/126, does not hang
#   E2  a non-UTF-8 argument reaches the program byte for byte
#   E3  ELF detection resolves a relative path against the TRACEE's cwd
#       (after a chdir inside the tree), so the entry swap still happens
#   E4  a label longer than the 255-byte scratch still runs; E4b pins the
#       settled length and the warning wording at 254, 255 and 300 bytes
#   E5  a large argv is forwarded intact and still redacted
#   E6  the supervisor masks its own /proc entry
#   E7  -l- / -a- mean a blank label; --label=- is the literal '-'
#   E8  a missing option value names the flag that was used
#   E9  an executable #! script: zero sightings, liveness, argv fidelity,
#       post-exec fallback log line
#   E10 --keep-env visible vs default redacted environ
#   E11 --no-follow: direct child redacted, grandchild visible and working
#   E12 --no-exit-kill: tree survives the supervisor (default: it dies)
#   E13 --label-empty: blank comm, empty cmdline
#   E14 no label given: cmdline is the program name, arguments stripped
#   E15 execveat and fexecve (skipped while testcases lacks the subcommands)
#   E16 two chained execs keep arguments and exit code
#   E17 an empty command line is refused, not run
#   E18 Exhume's TracerPid scoring: untraced none, traced high, detach none,
#       a credential-holder label critical
#   E20 a vfork child takes the post-exec path (gcc's cc1 run)
#   E21 kdetect's cross-view score: the external channels agree on the
#       label and the payload's own AT_EXECFN is the named dissent
#   E22 Mao's lesson: a PATH-resolved check is not evidence
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAKE='[kworker/1:2-rcu_gp]'
FAKE15=$(printf '%s' "$FAKE" | cut -c1-15)   # kernel comm is 15 bytes
ROOT=$(cd .. && pwd)
FAIL=0
T="${TMPDIR:-/tmp}/mk-edge.$$"
mkdir -p "$T" || exit 2
trap 'rm -rf "$T"' 0 2 15

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

# ---------------------------------------------------------------- E1: exec
"$TOOL" -q -l "$FAKE" /nonexistent/pmask-probe >/dev/null 2>&1
rc=$?
[ "$rc" = 127 ] && pass e1-missing-binary-exits-127 \
    || fail "e1-missing-binary (rc=$rc, want 127)"

printf '#!/bin/sh\nexit 0\n' > /tmp/notexec.$$
chmod 644 /tmp/notexec.$$
"$TOOL" -q -l "$FAKE" /tmp/notexec.$$ >/dev/null 2>&1
rc=$?
rm -f /tmp/notexec.$$
[ "$rc" = 126 ] && pass e1-not-executable-exits-126 \
    || fail "e1-not-executable (rc=$rc, want 126)"

# ---------------------------------------------- E2: non-UTF-8 argument
BAD=$(printf 'a\377b')
out=$("$TOOL" -q -l "$FAKE" "$CASES" echoargsraw "$BAD" 2>/dev/null)
case "$out" in
    *arg2=61ff62*) pass e2-non-utf8-argv-forwarded ;;
    *) fail "e2-non-utf8-argv (want arg2=61ff62, got: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160))" ;;
esac

# ---------------------------------------- E3: tracee-relative ELF path
# A real fork changes the child's cwd to ROOT and then execs
# ./tests/testcases as its FIRST exec, while the tracer is still in the
# tests directory.  A plain shell `exec` would be a re-exec of an
# already-settled process, which is post-exec by design and would prove
# nothing.  A shell command is not used either: dash may spawn it with
# vfork, which now takes the post-exec path.  Resolving the path against
# the tracer's cwd would miss the binary and silently fall back to
# post-exec redaction.
log=$("$TOOL" -v -l "$FAKE" "$CASES" forkexec "$ROOT" ./tests/testcases echoargs X 2>&1)
nswap=$(printf '%s\n' "$log" | grep -c 'entry pointer-swap (ELF)')
nscript=$(printf '%s\n' "$log" | grep -c 'script/unknown exec')
if [ "$nswap" -ge 2 ] && [ "$nscript" = 0 ]; then
    pass "e3-tracee-cwd-elf (entry-swaps=$nswap)"
else
    fail "e3-tracee-cwd-elf (entry-swaps=$nswap script-fallbacks=$nscript, want >=2 and 0): $(printf '%s' "$log" | grep -E 'entry pointer-swap|script/unknown|exec-done' | head -4 | tr '\n' '|')"
fi

# ------------------------------------------------- E4: oversized label
LONG=$(head -c 300 /dev/zero 2>/dev/null | tr '\0' 'x')
[ -n "$LONG" ] || LONG="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"$TOOL" -q -l "$LONG" "$CASES" echoargs ok >/dev/null 2>&1
rc=$?
[ "$rc" = 0 ] && pass e4-long-label-runs \
    || fail "e4-long-label (rc=$rc, want 0)"

# ------------------------------------------------ E4b: label cut boundary
# The entry scratch keeps 254 bytes, and the completion block carries the
# whole label.  The warning must name the entry scratch rather than claim
# the process presents only 254 bytes, and the settled cmdline must be the
# whole label at 254, 255 and 300 bytes.
e4b_len() {  # LABEL -> settled cmdline byte count of the payload
    e4b_want="$1"
    e4b_found_pid=""
    e4b_i=0
    while [ "$e4b_i" -lt 100 ]; do
        for d in /proc/[0-9]*; do
            case "$(readlink "$d/exe" 2>/dev/null)" in
                */testcases)
                    e4b_text=$(tr -d '\0' < "$d/cmdline" 2>/dev/null)
                    if [ "$e4b_text" = "$e4b_want" ]; then
                        e4b_found_pid=${d#/proc/}
                        printf '%s' "$e4b_found_pid" > "$T/e4b.pid"
                        wc -c < "$d/cmdline" | tr -d ' '
                        return 0
                    fi
                    ;;
            esac
        done
        sleep 0.05
        e4b_i=$((e4b_i + 1))
    done
    return 1
}
for e4b_n in 254 255 300; do
    e4b_label=$(head -c "$e4b_n" /dev/zero | tr '\0' 'x')
    "$TOOL" -l "$e4b_label" "$CASES" sleeper >/dev/null 2>"/tmp/mk-e4b.$$" &
    e4b_pid=$!
    e4b_bytes=$(e4b_len "$e4b_label" || true)
    e4b_found_pid=$(cat "$T/e4b.pid" 2>/dev/null)
    e4b_err=$(cat "/tmp/mk-e4b.$$" 2>/dev/null)
    rm -f "/tmp/mk-e4b.$$" "$T/e4b.pid"
    [ -n "${e4b_found_pid:-}" ] && kill -9 "$e4b_found_pid" 2>/dev/null
    kill -9 "$e4b_pid" 2>/dev/null
    wait "$e4b_pid" 2>/dev/null
    if [ "$e4b_bytes" = "$((e4b_n + 1))" ]; then
        pass "e4b-label-$e4b_n-settles-whole"
    else
        fail "e4b-label-$e4b_n-settles-whole (cmdline bytes=${e4b_bytes:-none}, want $((e4b_n + 1)))"
    fi
    case "$e4b_n" in
        254)
            case "$e4b_err" in
                "") pass e4b-254-no-warning ;;
                *) fail "e4b-254-no-warning ($e4b_err)" ;;
            esac
            ;;
        *)
            case "$e4b_err" in
                *"entry scratch"*)
                    case "$e4b_err" in
                        *"only the first 254 bytes are presented"*)
                            fail "e4b-$e4b_n-warning-names-scratch (old wording)" ;;
                        *) pass "e4b-$e4b_n-warning-names-scratch" ;;
                    esac
                    ;;
                *) fail "e4b-$e4b_n-warning-names-scratch ($e4b_err)" ;;
            esac
            ;;
    esac
done

# ------------------------------------------------ E5: large argv
set -- 
i=0
while [ "$i" -lt 500 ]; do
    set -- "$@" "MK-E5-${i}-XXXXXXXX"
    i=$((i + 1))
done
out=$("$TOOL" -q -l "$FAKE" "$CASES" echoargs "$@" 2>/dev/null)
case "$out" in
    *arg501=*) pass e5-large-argv-forwarded ;;
    *) fail "e5-large-argv (last argument missing from the program's own view)" ;;
esac

# ------------------------------------------------ E6: supervisor self-mask
# Zeroing does not shrink the arg region, so a size test would be
# vacuous: assert on content.  The supervisor writes the label into the
# zeroed argv block, so its cmdline reads back as exactly the label and
# never as the program path or an argument.
visible_cmdline() {  # pid -> non-NUL text of its cmdline
    cat "/proc/$1/cmdline" 2>/dev/null | tr -d '\000'
}
proc_state() {  # pid -> one-letter process state (Z = zombie)
    sed -n 's/.*) \([A-Za-z]\).*/\1/p' "/proc/$1/stat" 2>/dev/null
}
# The shapes a REAL argv takes: the probe binary by name, and the
# supervisor as this suite invokes it.  Both are matched at the start of
# the text, which is argv[0].  A foreign process whose command line merely
# mentions a path under the tree, such as a shell running
# "cd .../pmask && ...", is not a leak.  A masked label that happens to
# contain the word pmask, such as the daemon default label
# "pmask-job", is not a leak either.
real_argv_shapes() {  # text -> 0 when the text is a real argv of this tree
    case "$1" in
        "$CASES"*) return 0 ;;
        "$TOOL"*) return 0 ;;
    esac
    return 1
}

# control: without pmask the probe's own name IS in a cmdline
"$CASES" sleeper >/dev/null 2>&1 &
CTL_PID=$!
sleep 0.3
ctl=0
for d in /proc/[0-9]*; do
    case "$(visible_cmdline "${d#/proc/}")" in
        *testcases*) ctl=1; break ;;
    esac
done
kill "$CTL_PID" 2>/dev/null
# reap the control before the masked run scans: a SIGTERM in flight is
# not a dead process, and its argv names the probe
wait "$CTL_PID" 2>/dev/null
[ "$ctl" = 1 ] && pass e6-control-cmdline-detectable \
    || fail "e6-control (the observer cannot see an unmasked cmdline)"

"$TOOL" -q -l "$FAKE" "$CASES" sleeper >/dev/null 2>&1 &
SELF_PID=$!
# Wait for the observable condition, not a fixed sleep: the kernel
# publishes the supervisor's real argv until the supervisor zeroes the
# block, and that window is not closable from inside the process.
e6_i=0
while [ "$e6_i" -lt 60 ]; do
    [ "$(visible_cmdline "$SELF_PID")" = "$FAKE" ] && break
    kill -0 "$SELF_PID" 2>/dev/null || break
    sleep 0.1
    e6_i=$((e6_i + 1))
done
leak=0
selfmasked=0
leakers=""
for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    txt=$(visible_cmdline "$pid")
    if real_argv_shapes "$txt"; then
        leak=1
        leakers="$leakers $pid:[$(cat "$d/comm" 2>/dev/null)][$txt]"
    fi
    c=$(cat "$d/comm" 2>/dev/null) || continue
    [ "$c" = "$FAKE15" ] || continue
    # a zombie has no mm and therefore an empty cmdline: not evidence
    [ "$(proc_state "$pid")" = "Z" ] && continue
    # the label is what the supervisor publishes in place of its argv
    if [ "$txt" = "$FAKE" ]; then
        selfmasked=1
    fi
done
if [ "$leak" = 0 ] && [ "$selfmasked" = 1 ]; then
    pass e6-supervisor-selfmask
else
    fail "e6-supervisor-selfmask (leak=$leak selfmasked=$selfmasked leakers:$leakers)"
fi
kill "$SELF_PID" 2>/dev/null

# ------------------------------------------------------ E7: label forms
# Every spelling of the blank label must produce a blank comm for the
# supervisor and for the tracee: the supervisor masks its own comm, and
# the tracee's comm is set at the exec completion stop.
# Catches: '-l-' and '--label=-' diverging, or a blank label rendering
# as something else.
blank_tracees() {  # pid-of-supervisor -> live tracees with a one-space comm
    bt=0
    for d in /proc/[0-9]*; do
        [ "${d#/proc/}" = "$1" ] && continue
        [ "$(cat "$d/comm" 2>/dev/null)" = " " ] || continue
        # a zombie has no mm: its comm survives but it is not a running
        # masked process
        [ "$(proc_state "${d#/proc/}")" = "Z" ] && continue
        bt=$((bt + 1))
    done
    echo "$bt"
}
await_blank() {  # pid-of-supervisor -> count, waiting up to 4s for one
    ab=0
    abi=0
    while [ "$abi" -lt 40 ]; do
        ab=$(blank_tracees "$1")
        [ "$ab" -ge 1 ] && break
        sleep 0.1
        abi=$((abi + 1))
    done
    echo "$ab"
}
for form in "-l-" "--label=-" "-l -" "--label -"; do
    # shellcheck disable=SC2086
    "$TOOL" -q $form "$CASES" sleeper >/dev/null 2>&1 &
    P=$!
    n=$(await_blank "$P")
    sc=$(cat "/proc/$P/comm" 2>/dev/null)
    kill "$P" 2>/dev/null
    if [ "$sc" = " " ] && [ "$n" -ge 1 ]; then
        pass "e7-blank-label [$form] (supervisor comm blank, $n tracee(s) blank)"
    else
        fail "e7-blank-label [$form] (supervisor comm=[$sc] tracees=$n, want ' ' and >= 1)"
    fi
    sleep 0.2
done

# ------------------------------------------- E8: missing value names flag
msg=$("$TOOL" -a 2>&1)
rc=$?
case "$msg" in
    *"-a needs a value"*) pass e8-missing-value-names-flag ;;
    *) fail "e8-missing-value (rc=$rc, msg did not name -a)" ;;
esac

# ======================================================================
# Cases E9 to E17.  Shared helpers first.
# ======================================================================

# labelled_tracees COMM-PREFIX: labelled processes that are not the
# supervisor (exe names pmask) and not zombies (exe unreadable).
labelled_tracees() {
    p="$1"; n=0
    for d in /proc/[0-9]*; do
        case "$(cat "$d/comm" 2>/dev/null)" in
            "$p"*)
                exe=$(readlink "$d/exe" 2>/dev/null)
                case "$exe" in
                    "") ;;
                    */pmask) ;;
                    *) n=$((n + 1)) ;;
                esac
                ;;
        esac
    done
    echo "$n"
}

# wait_labelled COMM-PREFIX WANT SECONDS: poll labelled_tracees.
wait_labelled() {
    end=$(( $(date +%s 2>/dev/null || echo 0) + $3 ))
    while :; do
        n=$(labelled_tracees "$1")
        [ "$n" -ge "$2" ] && break
        now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$now" -ge "$end" ] && break
        sleep 0.1 2>/dev/null || sleep 1
    done
    echo "$n"
}

# wait_file FILE SECONDS: poll until FILE exists and is not empty.
wait_file() {
    end=$(( $(date +%s 2>/dev/null || echo 0) + $2 ))
    while :; do
        [ -s "$1" ] && return 0
        now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$now" -ge "$end" ] && return 1
        sleep 0.1 2>/dev/null || sleep 1
    done
}

# stop_tree SUPERVISOR-PID COMM-PREFIX...: SIGKILL the supervisor (the
# default EXITKILL takes the tree) and sweep the labelled leftovers.
stop_tree() {
    sp="$1"; shift
    kill -9 "$sp" 2>/dev/null
    wait "$sp" 2>/dev/null
    for cp in "$@"; do kill_comm "$cp" KILL 2>/dev/null; done
    sleep 0.2
}

# ------------------------------------------- E9: executable #! script
# The whole State::Script path: the kernel copies the real interpreter
# line, the post-exec completion stop zeroes it.
# Defects caught: script argv left visible (sightings > 0); the script not
# running (no output file, no liveness); argv changed on the way through
# the interpreter (argv fidelity); the script exec taking the ELF swap or
# losing the fallback log line.
E9_SCRIPT=/tmp/mk-e9-script.$$
E9_OUT=/tmp/mk-e9-out.$$
E9_LOG=/tmp/mk-e9-log.$$
cat > "$E9_SCRIPT" <<EOS
#!/bin/sh
printf '0=%s\nn=%s\n' "\$0" "\$#" > "$E9_OUT"
for a in "\$@"; do printf 'arg=%s\n' "\$a" >> "$E9_OUT"; done
while :; do sleep 1; done
EOS
chmod 755 "$E9_SCRIPT"
rm -f "$E9_OUT" "$E9_LOG"

"$E9_SCRIPT" MK-E9-ARG "two words" >/dev/null 2>&1 &
CTL=$!
wait_file "$E9_OUT" 15
sleep 0.3
n=$(sightings MK-E9-ARG)
kill -9 "$CTL" 2>/dev/null; wait "$CTL" 2>/dev/null
kill_comm sleep KILL 2>/dev/null
[ "$n" -ge 1 ] && pass "e9-control-script-argv-detectable ($n sightings)" \
    || fail "e9-control (script argument not visible without pmask)"
rm -f "$E9_OUT"

"$TOOL" -v -l mk-e9-label "$E9_SCRIPT" MK-E9-ARG "two words" >/dev/null 2>"$E9_LOG" &
E9_PID=$!
if wait_file "$E9_OUT" 20; then
    n=$(wait_labelled mk-e9-label 1 10)
    sleep 0.5
    s=$(sightings MK-E9-ARG)
    [ "$s" = 0 ] && pass e9-script-zero-sightings \
        || fail "e9-script-zero-sightings ($s sighting(s) of the script argument)"
    [ "$n" -ge 1 ] && pass "e9-script-liveness ($n labelled process(es))" \
        || fail "e9-script-liveness (no labelled process; the script is not running under the label)"
    want="0=$E9_SCRIPT
n=2
arg=MK-E9-ARG
arg=two words"
    got=$(cat "$E9_OUT")
    [ "$got" = "$want" ] && pass e9-script-argv-fidelity \
        || fail "e9-script-argv-fidelity (got: $(printf '%s' "$got" | tr '\n' '|'))"
else
    fail "e9-script-ran (the script wrote no output within 20 s)"
fi
stop_tree "$E9_PID" mk-e9-label sleep
nfall=$(grep -c 'script/unknown exec, post-exec mode' "$E9_LOG")
[ "$nfall" -ge 1 ] && pass "e9-script-fallback-log (lines=$nfall)" \
    || fail "e9-script-fallback-log (no 'script/unknown exec, post-exec mode' line): $(head -c 300 "$E9_LOG" | tr '\n' '|')"
rm -f "$E9_SCRIPT" "$E9_OUT" "$E9_LOG"

# ------------------------------------- shared control for E10 to E16
"$CASES" sleeper MK-E-CTRL >/dev/null 2>&1 &
CTL=$!
sleep 0.5
n=$(sightings MK-E-CTRL)
kill -9 "$CTL" 2>/dev/null; wait "$CTL" 2>/dev/null
[ "$n" -ge 1 ] && pass "e-control-argv-detectable ($n sightings)" \
    || fail "e-control (the observer cannot see an unmasked sleeper argument)"

# ------------------------------------------------------ E10: --keep-env
# Defects caught: --keep-env ignored (the visible run finds nothing);
# redaction of environ broken in the default mode (the hidden run finds
# the value).  The --keep-env run is also the detector control for the
# default run.
"$TOOL" -q --keep-env -l mk-e10-keep env MK_E10_VAR=MK-E10-VISIBLE "$CASES" sleeper >/dev/null 2>&1 &
P=$!
n=$(wait_comm_exe mk-e10-keep testcases 1 15)
hits=$(environ_hits MK-E10-VISIBLE)
stop_tree "$P" mk-e10-keep
[ "$n" -ge 1 ] && [ "$hits" -ge 1 ] && pass "e10-keep-env-visible (hits=$hits)" \
    || fail "e10-keep-env-visible (alive=$n hits=$hits, want >=1 and >=1)"

"$TOOL" -q -l mk-e10-hide env MK_E10_VAR=MK-E10-HIDDEN "$CASES" sleeper >/dev/null 2>&1 &
P=$!
n=$(wait_comm_exe mk-e10-hide testcases 1 15)
sleep 0.3
hits=$(environ_hits MK-E10-HIDDEN)
stop_tree "$P" mk-e10-hide
[ "$n" -ge 1 ] && [ "$hits" = 0 ] && pass "e10-default-environ-redacted (alive=$n)" \
    || fail "e10-default-environ-redacted (alive=$n hits=$hits, want >=1 and 0)"

# ----------------------------------------------------- E11: --no-follow
# Defects caught: --no-follow ignored (the grandchild is redacted, so its
# marker is not visible); the direct child left unredacted (the parent
# marker is visible); a grandchild that stopped working.
E11_OUT=/tmp/mk-e11-out.$$
rm -f "$E11_OUT"
"$TOOL" -q --no-follow -l mk-e11-only /bin/sh -c ": MK-E11-PARENT; $CASES echoargs G1 G2 > $E11_OUT; $CASES sleeper MK-E11-GC & wait" >/dev/null 2>&1 &
P=$!
if wait_file "$E11_OUT" 20; then
    watch MK-E11-GC 8
    gc=$SEE
    parent=$(sightings MK-E11-PARENT)
    n=$(wait_labelled mk-e11-only 1 5)
    [ "$gc" -ge 1 ] && pass "e11-no-follow-grandchild-visible (sightings=$gc)" \
        || fail "e11-no-follow-grandchild-visible (grandchild was redacted)"
    [ "$parent" = 0 ] && [ "$n" -ge 1 ] && pass "e11-no-follow-direct-child-redacted (labelled=$n)" \
        || fail "e11-no-follow-direct-child-redacted (parent sightings=$parent labelled=$n)"
    case "$(cat "$E11_OUT")" in
        *G1*G2*) pass e11-no-follow-grandchild-functional ;;
        *) fail "e11-no-follow-grandchild-functional ($(cat "$E11_OUT"))" ;;
    esac
else
    fail "e11-no-follow (the command produced no output within 20 s)"
fi
stop_tree "$P" mk-e11-only testcases
rm -f "$E11_OUT"

# ------------------------------------------------- E12: --no-exit-kill
# Defects caught: --no-exit-kill ignored (the tree dies with the
# supervisor); EXITKILL missing in the default mode (the control run
# leaves survivors).  The supervisor exe is pmask, so only tracees
# (exe testcases) are counted.
"$TOOL" -q --no-exit-kill -l mk-e12-keep /bin/sh -c "$CASES sleeper MK-E12 & wait" >/dev/null 2>&1 &
P=$!
before=$(wait_comm_exe mk-e12-keep testcases 1 15)
kill -9 "$P" 2>/dev/null; wait "$P" 2>/dev/null
sleep 1.5
after=$(comm_exe_count mk-e12-keep testcases)
kill_comm mk-e12-keep KILL 2>/dev/null; sleep 0.2
[ "$before" -ge 1 ] && [ "$after" -ge 1 ] && pass "e12-no-exit-kill-tree-survives (before=$before after=$after)" \
    || fail "e12-no-exit-kill-tree-survives (before=$before after=$after, want >=1 and >=1)"

"$TOOL" -q -l mk-e12-kill /bin/sh -c "$CASES sleeper MK-E12 & wait" >/dev/null 2>&1 &
P=$!
before=$(wait_comm_exe mk-e12-kill testcases 1 15)
kill -9 "$P" 2>/dev/null; wait "$P" 2>/dev/null
sleep 1.5
after=$(comm_exe_count mk-e12-kill testcases)
kill_comm mk-e12-kill KILL 2>/dev/null; sleep 0.2
[ "$before" -ge 1 ] && [ "$after" = 0 ] && pass "e12-default-exit-kill-control (before=$before after=$after)" \
    || fail "e12-default-exit-kill-control (before=$before after=$after, want >=1 and 0)"

# ---------------------------------------------------- E13: --label-empty
# Defects caught: --label-empty ignored (the cmdline shows the program
# name, so no labelled process has an empty cmdline); the marker visible.
"$TOOL" -q --label-empty "$CASES" sleeper MK-E13 >/dev/null 2>&1 &
P=$!
n=$(wait_comm_exe ' ' testcases 1 15)
sleep 0.3
empty=0
for d in /proc/[0-9]*; do
    [ "$(cat "$d/comm" 2>/dev/null)" = " " ] || continue
    case "$(readlink "$d/exe" 2>/dev/null)" in
        */testcases) [ -z "$(visible_cmdline "${d#/proc/}")" ] && empty=$((empty + 1)) ;;
    esac
done
s=$(sightings MK-E13)
stop_tree "$P" ' '
[ "$n" -ge 1 ] && [ "$empty" -ge 1 ] && [ "$s" = 0 ] \
    && pass "e13-label-empty (blank comm, empty cmdline: $empty process(es))" \
    || fail "e13-label-empty (alive=$n empty-cmdline=$empty sightings=$s)"

# ------------------------------------------ E14: default, no label given
# Defects caught: no-label mode leaves the arguments visible; no-label
# mode produces an empty or foreign cmdline instead of the program name.
kill_comm testcases KILL 2>/dev/null; sleep 0.2
"$TOOL" -q "$CASES" sleeper MK-E14 >/dev/null 2>&1 &
P=$!
n=$(wait_comm_exe testcases testcases 1 15)
sleep 0.3
named=0
for d in /proc/[0-9]*; do
    case "$(readlink "$d/exe" 2>/dev/null)" in
        */testcases) [ "$(visible_cmdline "${d#/proc/}")" = "testcases" ] && named=$((named + 1)) ;;
    esac
done
s=$(sightings MK-E14)
stop_tree "$P" testcases
[ "$n" -ge 1 ] && [ "$named" -ge 1 ] && [ "$s" = 0 ] \
    && pass "e14-default-no-label (cmdline is the program name, args stripped)" \
    || fail "e14-default-no-label (alive=$n named=$named sightings=$s)"

# --------------------------------------------- E15: execveat and fexecve
# Defects caught: execveat/fexecve not recognised as exec (marker visible
# or program broken).  Skipped, visibly, while the testcases binary has
# no such subcommand.
for sub in execveat fexecve; do
    if "$CASES" "$sub" 2>&1 | grep -q 'unknown testcase'; then
        echo "SKIP e15-$sub (testcases has no '$sub' subcommand)"
        continue
    fi
    out=$("$TOOL" -q -l "$FAKE" "$CASES" "$sub" "$CASES" echoargs E15A E15B 2>/dev/null)
    case "$out" in
        *E15A*E15B*) pass "e15-$sub-argv-fidelity" ;;
        *) fail "e15-$sub-argv-fidelity (got: $out)" ;;
    esac
    "$TOOL" -q -l mk-e15-label "$CASES" "$sub" "$CASES" sleeper MK-E15-$sub >/dev/null 2>&1 &
    P=$!
    n=$(wait_comm_exe mk-e15-label testcases 1 15)
    sleep 0.3
    s=$(sightings MK-E15-$sub)
    stop_tree "$P" mk-e15-label
    [ "$n" -ge 1 ] && [ "$s" = 0 ] && pass "e15-$sub-redacted (alive=$n)" \
        || fail "e15-$sub-redacted (alive=$n sightings=$s)"
done

# ------------------------------------------------ E16: two chained execs
# env execs a shell that runs a script: two execs in one tree.
# Defects caught: the second exec loses its arguments or exit code; the
# verbose log shows fewer than two completed execs.
E16_SCRIPT=/tmp/mk-e16-inner.$$
E16_LOG=/tmp/mk-e16-log.$$
printf 'echo "inner-ok $1"\n' > "$E16_SCRIPT"
out=$("$TOOL" -v -l testlabel env /bin/sh "$E16_SCRIPT" MK-E16 2>"$E16_LOG")
rc=$?
ndone=$(grep -c 'exec-done' "$E16_LOG")
[ "$rc" = 0 ] && [ "$out" = "inner-ok MK-E16" ] && pass "e16-two-exec-output (rc=$rc)" \
    || fail "e16-two-exec-output (rc=$rc out=[$out])"
[ "$ndone" -ge 2 ] && pass "e16-two-exec-completions (exec-done lines=$ndone)" \
    || fail "e16-two-exec-completions (exec-done lines=$ndone, want >=2)"
rm -f "$E16_SCRIPT" "$E16_LOG"

# ------------------------------------------------ E17: empty command line
# Defect caught: an empty argv either panics or runs something unintended.
# Each shape must be refused with a message and the documented status.
err=$("$TOOL" 2>&1 >/dev/null); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q 'Usage: pmask'; then
    pass "e17-no-arguments-prints-usage-and-exits-255"
else
    fail "e17-no-arguments (rc=$rc err=$(printf '%s' "$err" | head -1))"
fi

E17_EMPTY=/tmp/mk-e17-empty.$$
: > "$E17_EMPTY"
err=$("$TOOL" -q --args-from-fd 3 3<"$E17_EMPTY" 2>&1 >/dev/null); rc=$?
if [ "$rc" = 255 ] && printf '%s' "$err" | grep -q 'no program given'; then
    pass "e17-empty-args-from-fd-is-refused"
else
    fail "e17-empty-args-from-fd (rc=$rc err=[$err])"
fi
rm -f "$E17_EMPTY"

err=$("$TOOL" -q "" 2>&1 >/dev/null); rc=$?
if [ "$rc" = 127 ] && printf '%s' "$err" | grep -q 'cannot exec'; then
    pass "e17-empty-program-name-is-refused (rc=$rc)"
else
    fail "e17-empty-program-name (rc=$rc err=[$err])"
fi

# ---------------------------------------- E18: Exhume TracerPid scoring
# Exhume's injectrules.rs scores any non-debugger TracerPid as High and a
# traced process whose comm is one of its SECRET_HOLDERS (the survey
# records sshd, sudo and ssh-agent) as Critical.  The rule reads
# /proc/<pid>/status and /proc/<pid>/comm only, so no label can change the
# first clause and a credential-holder label raises the second.
#
# Control: an untraced payload scores none.  Masked default: the tracee
# carries its tracer's pid and scores high.  Masked --detach: the tracee
# is released, scores none.  Masked with the ssh-agent label: the same
# traced process scores critical.  The last two are the operator-facing
# trade: --detach clears the score and costs tree coverage; a label naming
# a credential holder makes an ordinary trace look worse.
tracerpid() {  # pid -> TracerPid value, empty when the process is gone
    sed -n 's/^TracerPid:[[:space:]]*\([0-9]*\).*/\1/p' "/proc/$1/status" 2>/dev/null
}

exhume_score() {  # pid -> none | high | critical | absent
    es_tp=$(tracerpid "$1")
    [ -n "$es_tp" ] || { echo absent; return; }
    [ "$es_tp" = 0 ] && { echo none; return; }
    case "$(cat "/proc/$1/comm" 2>/dev/null)" in
        sshd|sudo|ssh-agent|gpg-agent|passwd|su) echo critical ;;
        *) echo high ;;
    esac
}

pid_comm_exe() {  # COMM EXE -> pid, empty when none
    for d in /proc/[0-9]*; do
        [ "$(cat "$d/comm" 2>/dev/null)" = "$1" ] || continue
        case "$(readlink "$d/exe" 2>/dev/null)" in
            */"$2") echo "${d#/proc/}"; return 0 ;;
        esac
    done
    return 1
}

find_pid_comm_exe() {  # COMM EXE SECONDS -> pid, empty on timeout
    fpe_end=$(( $(date +%s 2>/dev/null || echo 0) + $3 ))
    while :; do
        fpe_pid=$(pid_comm_exe "$1" "$2")
        if [ -n "$fpe_pid" ]; then
            echo "$fpe_pid"
            return 0
        fi
        fpe_now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$fpe_now" -ge "$fpe_end" ] && break
        sleep 0.1 2>/dev/null || sleep 1
    done
    echo ""
    return 1
}

"$CASES" sleeper MK-E18-CTRL >/dev/null 2>&1 &
E18_CTL=$!
E18_PID=$E18_CTL
E18_SCORE=$(exhume_score "$E18_PID")
kill -9 "$E18_CTL" 2>/dev/null; wait "$E18_CTL" 2>/dev/null
[ "$E18_SCORE" = none ] && pass "e18-control-untraced-scores-none (TracerPid=0)" \
    || fail "e18-control-untraced (pid=$E18_PID score=$E18_SCORE, want none)"

"$TOOL" -q -l mk-e18-trace "$CASES" sleeper >/dev/null 2>&1 &
E18_P=$!
E18_PID=$(find_pid_comm_exe mk-e18-trace testcases 15)
E18_TP=$(tracerpid "$E18_PID")
E18_SCORE=$(exhume_score "$E18_PID")
kill -9 "$E18_P" 2>/dev/null; wait "$E18_P" 2>/dev/null
kill_label mk-e18-trace
if [ "$E18_SCORE" = high ] && [ -n "$E18_TP" ] && [ "$E18_TP" != 0 ]; then
    pass "e18-default-traced-scores-high (TracerPid=$E18_TP)"
else
    fail "e18-default-traced (pid=${E18_PID:-none} TracerPid=${E18_TP:-none} score=$E18_SCORE, want high)"
fi

"$TOOL" -q --detach -l mk-e18-detach "$CASES" sleeper >/dev/null 2>&1 &
E18_P=$!
E18_PID=$(find_pid_comm_exe mk-e18-detach testcases 15)
E18_TP=$(tracerpid "$E18_PID")
E18_SCORE=$(exhume_score "$E18_PID")
kill -9 "$E18_P" 2>/dev/null; wait "$E18_P" 2>/dev/null
kill_label mk-e18-detach
if [ "$E18_SCORE" = none ] && [ "$E18_TP" = 0 ]; then
    pass "e18-detach-untraced-scores-none (TracerPid=0)"
else
    fail "e18-detach (pid=${E18_PID:-none} TracerPid=${E18_TP:-none} score=$E18_SCORE, want none)"
fi

"$TOOL" -q -l ssh-agent "$CASES" sleeper >/dev/null 2>&1 &
E18_P=$!
E18_PID=$(find_pid_comm_exe ssh-agent testcases 15)
E18_SCORE=$(exhume_score "$E18_PID")
kill -9 "$E18_P" 2>/dev/null; wait "$E18_P" 2>/dev/null
# Kill the tracee by its pid, never by the label: a real ssh-agent may be
# running on the host, and kill_label would take it with ours.
[ -n "$E18_PID" ] && kill -9 "$E18_PID" 2>/dev/null
[ "$E18_SCORE" = critical ] && pass "e18-secret-holder-label-scores-critical" \
    || fail "e18-secret-holder (pid=${E18_PID:-none} score=$E18_SCORE, want critical)"

# ------------------------------------ E19: SPiCa cross-view existence
# SPiCa's engine compares TGID existence across a scheduler ledger, the raw
# getdents64 listing of /proc and libc readdir, records the kernel start
# time for its impersonation check, and never reads cmdline, environ,
# arg_start or auxv.  The ledger needs eBPF, which this host refuses;
# `testcases procviews` prints the other channels plus a direct stat and
# kill(0), and the case compares them.
#
# Control: a live pid is present in every view, and a reaped pid is absent
# in every view, so neither verdict is constant.  Masked: every view agrees
# on the tracee, its start time does not move, and its comm and cmdline are
# the label, so the rewrite is invisible to this detector.
E19_VIEWS=$("$CASES" procviews $$)
case "$E19_VIEWS" in
    *"getdents64=present readdir=present stat=present kill0=present"*)
        pass "e19-control-live-pid-present-in-every-view" ;;
    *) fail "e19-control-live (procviews $$: $E19_VIEWS)" ;;
esac

"$CASES" sleeper MK-E19-DEAD >/dev/null 2>&1 &
E19_DEAD=$!
kill -9 "$E19_DEAD" 2>/dev/null
wait "$E19_DEAD" 2>/dev/null
E19_VIEWS=$("$CASES" procviews "$E19_DEAD")
case "$E19_VIEWS" in
    *"getdents64=absent readdir=absent stat=absent kill0=absent"*)
        pass "e19-control-dead-pid-absent-in-every-view" ;;
    *) fail "e19-control-dead (procviews $E19_DEAD: $E19_VIEWS)" ;;
esac

"$TOOL" -q -l mk-e19-view "$CASES" sleeper MK-E19-ARG >/dev/null 2>&1 &
E19_P=$!
E19_PID=$(find_pid_comm_exe mk-e19-view testcases 15)
if [ -n "$E19_PID" ]; then
    E19_VIEWS=$("$CASES" procviews "$E19_PID")
    E19_START1=$(proc_start "$E19_PID")
    sleep 0.3
    E19_START2=$(proc_start "$E19_PID")
    E19_OTHER=$(proc_start $$)
    E19_COMM=$(cat "/proc/$E19_PID/comm" 2>/dev/null)
    E19_CMD=$(visible_cmdline "$E19_PID")
    case "$E19_VIEWS" in
        *"getdents64=present readdir=present stat=present kill0=present"*)
            pass "e19-masked-present-in-every-view" ;;
        *) fail "e19-masked-present (procviews $E19_PID: $E19_VIEWS)" ;;
    esac
    if [ -n "$E19_START1" ] && [ "$E19_START1" = "$E19_START2" ]; then
        pass "e19-masked-start-time-stable (starttime=$E19_START1)"
    else
        fail "e19-masked-start-time (first=${E19_START1:-none} second=${E19_START2:-none})"
    fi
    # The impersonation check compares start times, so two live processes
    # must be distinguishable by that field; the suite shell started long
    # before the tracee.
    if [ -n "$E19_START1" ] && [ -n "$E19_OTHER" ] && [ "$E19_START1" != "$E19_OTHER" ]; then
        pass "e19-control-start-times-differ (tracee=$E19_START1 shell=$E19_OTHER)"
    else
        fail "e19-control-start-times (tracee=${E19_START1:-none} shell=${E19_OTHER:-none}, want different)"
    fi
    [ "$E19_COMM" = mk-e19-view ] && pass "e19-masked-comm-is-label" \
        || fail "e19-masked-comm-is-label (comm=[$E19_COMM])"
    case "$E19_CMD" in
        *MK-E19-ARG*)
            fail "e19-masked-cmdline-hides-argument (cmdline=[$E19_CMD])" ;;
        *)
            pass "e19-masked-cmdline-hides-argument" ;;
    esac
else
    fail "e19-masked (no labelled tracee appeared within 15 s)"
fi
kill -9 "$E19_P" 2>/dev/null; wait "$E19_P" 2>/dev/null
kill_label mk-e19-view

# ------------------------------------------------ E20: vfork child exec
# Defect caught: the entry swap ran in a vfork child, which shares the
# parent's address space (gcc's clone3(CLONE_VM|CLONE_VFORK) run of cc1).
# The write changed the parent's memory and gcc crashed in free() after
# the child exited.  A vfork child takes the post-exec path instead.
if command -v gcc >/dev/null 2>&1; then
    E20_DIR=/tmp/mk-e20.$$
    mkdir -p "$E20_DIR"
    printf 'int main(void) { return 0; }\n' > "$E20_DIR/e20.c"
    "$TOOL" -q -l mk-e20 -- gcc -c -o "$E20_DIR/e20.o" "$E20_DIR/e20.c" >/dev/null 2>&1
    rc=$?
    if [ "$rc" = 0 ] && [ -s "$E20_DIR/e20.o" ]; then
        pass "e20-vfork-child-does-not-corrupt-the-parent"
    else
        fail "e20-vfork-child (rc=$rc, object missing or empty)"
    fi
    rm -rf "$E20_DIR"
    kill_label mk-e20
else
    skip "e20-vfork-child (no gcc)"
fi

# ------------------------------------------------ E21: kdetect cross-view score
# kdetect's method: score independent channels, require corroboration, and
# name the dissenting channel.  The channels a detector can read are the
# cmdline, the stat arg span, /proc/<pid>/auxv AT_EXECFN, and the payload's
# own getauxval(AT_EXECFN).  Control: all four name the real argv.  Masked:
# cmdline, span and auxv name the label; the payload's own getauxval still
# names the real path (C-030 pins that divergence), so the dissent is
# exactly that channel and the case names it.  The span assertion needs the
# window relocation (`PR_SET_MM_MAP`); on a kernel that refuses it the span
# is a real dissent and the case reports it.
e21_span() {  # pid -> arg_end - arg_start, the bytes between the two pointers
    e21_s=$(sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f46,47)
    # shellcheck disable=SC2086
    set -- $e21_s
    [ $# = 2 ] || return 1
    echo $(( $2 - $1 ))
}
e21_auxv_str() {  # pid -> AT_EXECFN string
    e21_ptr=$(od -An -v -tx8 "/proc/$1/auxv" 2>/dev/null | tr -s ' ' '\n' |
        awk 'NF { if (++n % 2 == 1) t = $1; else if (t ~ /^0*1f$/) print $1 }')
    [ -n "$e21_ptr" ] || return 1
    dd if="/proc/$1/mem" bs=1 skip=$((0x$e21_ptr)) count=512 2>/dev/null |
        tr '\0' '\n' | head -1
}
e21_pid_by_marker() {  # MARKER -> pid of the testcases process carrying it
    for d in /proc/[0-9]*; do
        [ "$(cat "$d/comm" 2>/dev/null)" = "testcases" ] || continue
        case "$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)" in
            *"$1"*) echo "${d#/proc/}"; return 0 ;;
        esac
    done
    return 1
}
e21_wait_pid_by_marker() {  # MARKER SECONDS -> pid, empty on timeout
    e21w_end=$(( $(date +%s 2>/dev/null || echo 0) + $2 ))
    while :; do
        e21w_pid=$(e21_pid_by_marker "$1")
        if [ -n "$e21w_pid" ]; then
            echo "$e21w_pid"
            return 0
        fi
        e21w_now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$e21w_now" -ge "$e21w_end" ] && break
        sleep 0.1 2>/dev/null || sleep 1
    done
    echo ""
    return 1
}

E21_LBL="mk-e21"
E21_MARK="MK-E21-ARG"
"$CASES" execfn 3 "$E21_MARK" >"$T/e21ctl.out" 2>/dev/null &
E21_CTL=$!
E21_CTL_PID=$(e21_wait_pid_by_marker "$E21_MARK" 10)
E21_CTL_CMD=$(visible_cmdline "$E21_CTL_PID")
E21_CTL_AUX=$(e21_auxv_str "$E21_CTL_PID")
e21c_end=$(( $(date +%s 2>/dev/null || echo 0) + 10 ))
while ! grep -q '^execfn=' "$T/e21ctl.out" 2>/dev/null; do
    e21c_now=$(date +%s 2>/dev/null || echo 99999999999)
    [ "$e21c_now" -ge "$e21c_end" ] && break
    sleep 0.1 2>/dev/null || sleep 1
done
E21_CTL_OWN=$(sed -n 's/^execfn=//p' "$T/e21ctl.out" 2>/dev/null | head -1)
kill -9 "$E21_CTL" 2>/dev/null; wait "$E21_CTL" 2>/dev/null
case "$E21_CTL_CMD" in
    *"$E21_MARK"*) E21_CTL_CMD_S=real ;;
    *) E21_CTL_CMD_S=dissent ;;
esac
case "$E21_CTL_AUX" in
    *testcases*) E21_CTL_AUX_S=real ;;
    *) E21_CTL_AUX_S=dissent ;;
esac
case "$E21_CTL_OWN" in
    *testcases*) E21_CTL_OWN_S=real ;;
    *) E21_CTL_OWN_S=dissent ;;
esac
if [ "$E21_CTL_CMD_S" = real ] && [ "$E21_CTL_AUX_S" = real ] \
    && [ "$E21_CTL_OWN_S" = real ]; then
    pass "e21-control-all-channels-name-the-real-argv"
else
    fail "e21-control (cmd=[$E21_CTL_CMD_S] auxv=[$E21_CTL_AUX_S] own=[$E21_CTL_OWN_S])"
fi

"$TOOL" -q -l "$E21_LBL" "$CASES" execfn 3 "$E21_MARK" >"$T/e21.out" 2>/dev/null &
E21_SUP=$!
E21_PID=$(find_pid_comm_exe "$E21_LBL" testcases 15)
if [ -n "$E21_PID" ]; then
    E21_CMD=$(visible_cmdline "$E21_PID")
    E21_SPAN=$(e21_span "$E21_PID")
    E21_AUX=$(e21_auxv_str "$E21_PID")
else
    E21_CMD=""
    E21_SPAN=""
    E21_AUX=""
fi
e21_end=$(( $(date +%s 2>/dev/null || echo 0) + 10 ))
while ! grep -q '^execfn=' "$T/e21.out" 2>/dev/null; do
    e21_now=$(date +%s 2>/dev/null || echo 99999999999)
    [ "$e21_now" -ge "$e21_end" ] && break
    sleep 0.1 2>/dev/null || sleep 1
done
E21_OWN=$(sed -n 's/^execfn=//p' "$T/e21.out" 2>/dev/null | head -1)
[ -n "$E21_PID" ] && kill -9 "$E21_PID" 2>/dev/null
kill -9 "$E21_SUP" 2>/dev/null; wait "$E21_SUP" 2>/dev/null
E21_LEN=$(( $(printf '%s' "$E21_LBL" | wc -c | tr -d ' ') + 1 ))
E21_DISSENT=""
[ "$E21_CMD" = "$E21_LBL" ] || E21_DISSENT="$E21_DISSENT cmdline"
[ "$E21_SPAN" = "$E21_LEN" ] || E21_DISSENT="$E21_DISSENT span"
[ "$E21_AUX" = "$E21_LBL" ] || E21_DISSENT="$E21_DISSENT auxv"
case "$E21_OWN" in
    *testcases*) E21_DISSENT="$E21_DISSENT execfn" ;;
esac
if [ -z "$E21_DISSENT" ]; then
    fail "e21-masked-dissent (no channel dissented; auxv/own both named the label)"
elif [ "$E21_DISSENT" = " execfn" ]; then
    pass "e21-masked-dissent-is-the-in-process-execfn (cmd=[$E21_CMD] span=[$E21_SPAN] auxv=[$E21_AUX] own=[$E21_OWN])"
else
    fail "e21-masked-dissent (dissent=[$E21_DISSENT] cmd=[$E21_CMD] span=[$E21_SPAN] auxv=[$E21_AUX] own=[$E21_OWN])"
fi

# ------------------------------------------------ E22: Mao PATH-resolved check
# Mao's lesson: a detector resolved through PATH is not evidence, because
# the binary it runs can be replaced.  The case plants a `ps` earlier in
# PATH that prints a chosen answer, shows the PATH-resolved check returns
# it, and shows that the direct /proc read does not.
E22_DIR=/tmp/mk-e22.$$
mkdir -p "$E22_DIR"
printf '#!/bin/sh\necho MK-E22-FAKE\n' >"$E22_DIR/ps"
chmod 755 "$E22_DIR/ps"
e22_path=$(PATH="$E22_DIR:$PATH" ps -o args= -p $$ 2>/dev/null | tr -d ' ')
e22_direct=$(tr '\0' ' ' < "/proc/$$/cmdline" 2>/dev/null)
rm -rf "$E22_DIR"
case "$e22_path" in
    *MK-E22-FAKE*) pass "e22-path-resolved-check-returns-the-planted-answer" ;;
    *) fail "e22-path-resolved-check (got [$e22_path])" ;;
esac
case "$e22_direct" in
    *MK-E22-FAKE*) fail "e22-direct-proc-read-is-not-the-planted-answer" ;;
    *) pass "e22-direct-proc-read-is-not-the-planted-answer" ;;
esac

rm -rf "$T"
echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ]
