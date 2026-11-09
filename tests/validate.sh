#!/bin/sh
# ============================================================================
# pmask validation -- run a battery of marker-carrying commands under a
# mask and verify with /proc (cmdline, environ, comm) + ps that nothing
# real is observable, while the programs themselves keep working.
#
# Self-contained.  Verification method (no trust in the tool required):
#   1. NEGATIVE CONTROL: the same battery runs WITHOUT the mask; the
#      observer MUST find the markers (proves the detector can detect).
#   2. The battery runs under pmask while an observer samples:
#        /proc/<pid>/cmdline   (what every /proc reader gets)
#        /proc/<pid>/environ   (environment disclosure)
#        /proc/<pid>/comm      (the Name top/htop display)
#        ps -e -o args         (when a ps is present)
#   3. A case passes only with ZERO sightings of its marker.
#   4. LIVENESS: processes must be alive under the label (not silently
#      dead -- that would make "zero sightings" vacuous).
#   5. ISOLATION: each phase carries its own markers, and the control's
#      payload is reaped before phase 2 samples.  A `cmd &` payload is a
#      grandchild of the background job, so killing `$!` alone leaves it
#      running and it would be counted as a phase-2 sighting.
#   6. PHASE 5: six real argv-secret shapes (an HTTP bearer header, a
#      password flag, a URL password, an API-key header, an environment
#      key and a -p flag), each with the control and the wrapped half.
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAKE='[kworker/1:2-rcu_gp]'
# The label as the kernel cuts it into comm (15 bytes).  comm_count matches
# the prefix literally, so the `[` needs no escaping.
FAKE15=$(printf '%s' "$FAKE" | cut -c1-15)
R=$(fresh_marker); [ -n "$R" ] || R="x$$$(date +%s 2>/dev/null || echo 1)"

OVERALL=0
PIDS=""

# reap_marker MARKER SECONDS
# SIGKILL every process of this uid that carries MARKER in its cmdline or
# environ, then wait until none is left.  The control's payload is a
# grandchild of the background job: `$!` is the subshell dash forks for
# `cmd &`, so killing `$!` alone leaves the payload running, and a
# leftover from phase 1 is then counted as a sighting in phase 2.  The
# match is a shell `case` over `tr` output, so no child of this function
# carries MARKER in its own argv.
reap_marker() {
    rm_m="$1"; rm_secs="$2"
    rm_end=$(( $(date +%s 2>/dev/null || echo 0) + rm_secs ))
    while :; do
        rm_left=0
        for rm_d in /proc/[0-9]*; do
            rm_p=${rm_d#/proc/}
            [ "$rm_p" = "$$" ] && continue
            [ "$(proc_uid "$rm_p")" = "$MY_UID" ] || continue
            rm_hit=0
            for rm_f in cmdline environ; do
                if ( tr '\0' '\n' < "$rm_d/$rm_f" ) 2>/dev/null | {
                    rm_found=0
                    while IFS= read -r rm_line || [ -n "$rm_line" ]; do
                        case "$rm_line" in
                            *"$rm_m"*) rm_found=1; break ;;
                        esac
                    done
                    [ "$rm_found" = 1 ]
                }; then
                    rm_hit=1
                    break
                fi
            done
            [ "$rm_hit" = 1 ] || continue
            rm_left=$((rm_left + 1))
            kill -9 "$rm_p" 2>/dev/null
        done
        [ "$rm_left" = 0 ] && return 0
        rm_now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$rm_now" -ge "$rm_end" ] && return 1
        sleep 0.05 2>/dev/null || sleep 1
    done
}

# labelled_under PARENT PREFIX: labelled processes that descend from PARENT
# (at most 8 hops).  Counting the whole machine would let a leftover from
# the previous case satisfy the wait, so the ancestry is the check.
labelled_under() {
    lu_p="$1"; lu_l="$2"; lu_n=0
    for lu_d in /proc/[0-9]*; do
        lu_c=$(cat "$lu_d/comm" 2>/dev/null)
        [ "${lu_c#"$lu_l"}" != "$lu_c" ] || continue
        lu_q=${lu_d#/proc/}
        # `cmd &` may run the job in the forked child itself or in a
        # grandchild, depending on the shell; count both shapes.
        if [ "$lu_q" = "$lu_p" ]; then lu_n=$((lu_n + 1)); continue; fi
        lu_h=0
        while [ "$lu_h" -lt 8 ]; do
            lu_pp=$(proc_ppid "$lu_q")
            [ -n "$lu_pp" ] || break
            if [ "$lu_pp" = "$lu_p" ]; then lu_n=$((lu_n + 1)); break; fi
            lu_q="$lu_pp"
            lu_h=$((lu_h + 1))
        done
    done
    echo "$lu_n"
}

# kill_label (lib.sh) removes the masked payloads: they keep the label as
# their comm, so neither kill_comm "yes" nor a marker search can see them
# once their supervisor is gone.

run_case() {  # $1 marker, $2 payload, $3 mode(mask|control), $4 expect(see|blind)
    if [ "$3" = mask ]; then
        PAYLOAD="$2" "$TOOL" -q -l "$FAKE" /bin/sh -c 'eval "$PAYLOAD"' >/dev/null 2>&1 &
    else
        PAYLOAD="$2" /bin/sh -c 'eval "$PAYLOAD"' >/dev/null 2>&1 &
    fi
    pid=$!
    [ -n "$pid" ] && PIDS="$PIDS $pid"
    if [ "$3" = mask ]; then
        # Wait for the label before sampling.  A masked case that has not
        # started yet has no sightings either, and "zero sightings" would
        # then be a statement about the clock rather than about the
        # redaction.  Two labelled descendants are the supervisor and the
        # payload.
        lw=0
        lw_end=$(( $(date +%s 2>/dev/null || echo 0) + 5 + VM_TCG * 25 ))
        while :; do
            lw=$(labelled_under "$pid" "$FAKE15")
            [ "$lw" -ge 2 ] && break
            lw_now=$(date +%s 2>/dev/null || echo 99999999999)
            [ "$lw_now" -ge "$lw_end" ] && break
            sleep 0.05 2>/dev/null || sleep 1
        done
        if [ "$lw" -lt 2 ]; then
            echo "FAIL $1: the mask never started ($lw labelled process(es) under the job)"
            OVERALL=1
            return 0
        fi
    else
        sleep 0.3
    fi
    watch "$1" 1
    if [ "$4" = see ]; then
        if [ "$SEE" -gt 0 ]; then echo "PASS control-$1 (detector works, $SEE sightings)"
        else echo "FAIL control-$1: marker not even visible WITHOUT pmask (detector broken)"; OVERALL=1; fi
    else
        if [ "$SEE" -eq 0 ]; then echo "PASS $1: no sightings"
        else echo "FAIL $1: LEAKED $SEE sighting(s) via /proc or ps"; OVERALL=1; fi
    fi
}

cleanup() {
    for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
    PIDS=""
    kill_label "$FAKE15"
    kill_label mask-liveness
}
trap 'cleanup' EXIT INT TERM

echo "== pmask validation run (suffix $R, label $FAKE) =="

A="MK${R}A"; B="MK${R}B"; C="MK${R}C"; D="MK${R}D"
E="MK${R}E"; F="MK${R}F"; G="MK${R}G"; H="MK${R}H"
# Phase 1 carries its own markers.  A control payload that outlives its
# job is then not a sighting of a phase-2 marker, whatever happens to the
# cleanup below; the two phases cannot contaminate each other.
A1="MK${R}1A"; D1="MK${R}1D"

echo "-- phase 1: negative control (no pmask; markers MUST be observable)"
run_case "$A1" "yes $A1 >/dev/null"                          control see
run_case "$D1" "env $D1=leaky-env-value yes $D1 >/dev/null"   control see
cleanup; kill_comm "yes" KILL 2>/dev/null
# Killing `$!` is not enough: the payload is a grandchild of the
# background job.  Reap what still carries a phase-1 marker, then wait for
# the machine to hold no `yes` at all, so phase 2 samples a clean host.
reap_marker "$A1" 3
reap_marker "$D1" 3
yn=0
yi=0
while [ "$yi" -lt 40 ]; do
    yn=$(comm_count yes)
    [ "$yn" = 0 ] && break
    yi=$((yi + 1))
    sleep 0.05 2>/dev/null || sleep 1
done
[ "$yn" = 0 ] || echo "INFO phase 1: $yn yes process(es) still on the machine (another run may own them)"

echo "-- phase 2: battery under pmask (expect zero sightings)"
run_case "$A" "yes $A >/dev/null"                                mask blind
run_case "$B" "exec yes $B >/dev/null"                           mask blind
run_case "$C" "yes $C >/dev/null & wait"                         mask blind
run_case "$D" "env $D=leaky-env-value yes $D >/dev/null"         mask blind
run_case "$E" "sh -c 'sh -c \"exec yes $E >/dev/null\"'"         mask blind
run_case "$F" "( ( exec yes $F >/dev/null ) & ) ; while :; do sleep 5; done" mask blind
run_case "$G" "for i in 1 2 3 4 5 6 7 8; do yes $G >/dev/null & done; wait"  mask blind
run_case "$H" "i=0; while [ \$i -lt 30 ]; do sh -c true v\$i; i=\$((i+1)); done; exec yes $H >/dev/null" mask blind
cleanup; kill_comm "yes" KILL 2>/dev/null
# The masked payloads keep the label, not `yes`, as their comm, so
# kill_comm cannot see them once their supervisor is gone.  Kill by the
# label this suite used, then confirm nothing is left.
kill_label "$FAKE15"
i=0
while [ "$i" -lt 40 ] && [ "$(comm_count "$FAKE15")" != 0 ]; do
    i=$((i + 1))
    sleep 0.05 2>/dev/null || sleep 1
done
sleep 0.3

echo "-- phase 2b: liveness proof (processes really run under the mask)"
L="MK${R}L"
PAYLOAD="yes $L >/dev/null" "$TOOL" -q -l mask-liveness /bin/sh -c 'eval "$PAYLOAD"' >/dev/null 2>&1 &
LP=$!
PIDS="$PIDS $LP"
alive=0
li=0
while [ "$li" -lt 100 ]; do
    alive=$(labelled_under "$LP" mask-liveness)
    [ "$alive" -ge 2 ] && break
    li=$((li + 1))
    sleep 0.05 2>/dev/null || sleep 1
done
leakL=$(sightings "$L")
kill -9 $LP 2>/dev/null
kill_comm "yes" KILL 2>/dev/null
kill_label mask-liveness
if [ "$alive" -ge 1 ] && [ "$leakL" = "0" ]; then
    echo "PASS liveness: $alive process(es) running with the label, marker unseen"
elif [ "$alive" -ge 1 ]; then
    echo "FAIL liveness: running but marker leaked ($leakL)"; OVERALL=1
else
    echo "FAIL liveness: nothing ran under pmask (vacuous pass risk)"; OVERALL=1
fi
sleep 0.3

echo "-- phase 3: functional sanity under pmask"
out=$(echo mask-io-test | "$TOOL" -q -l "$FAKE" /bin/cat 2>/dev/null); rc=$?
if [ "$out" = "mask-io-test" ] && [ "$rc" = "0" ]; then
    echo "PASS functional: stdin/stdout/exit-code intact"
else
    echo "FAIL functional: got [$out] rc=$rc"; OVERALL=1
fi
"$TOOL" -q -l "$FAKE" /bin/sh -c 'exit 42' 2>/dev/null; rc=$?
if [ "$rc" = "42" ]; then echo "PASS functional: exit codes propagate"
else echo "FAIL functional: rc=$rc (want 42)"; OVERALL=1; fi

echo "-- phase 4: the program still sees its own argv/env"
o=$("$TOOL" -q -l "$FAKE" "$CASES" echoargs X1 X2 2>/dev/null)
case "$o" in
    *X1*X2*env=\[ok\]*) echo "PASS argv-fidelity: [$o]" ;;
    *) echo "FAIL argv-fidelity: [$o]"; OVERALL=1 ;;
esac

echo "-- phase 5: real argv-secret shapes (cli-spy-style negative control)"
# Six shapes from the survey's fixture corpus.  The payload is the tree's
# own sleeper with the shape and a fresh marker as one argument; the
# observer is `sightings`, the same /proc reader the other phases use.
# Each shape has both halves: the control is visible without pmask,
# and the wrapped run is not.  A zero without the control is not a pass.
i=0
for shape in \
    "Authorization: Bearer " \
    "--password=" \
    "postgres://user:pass@" \
    "--header=x-api-key:" \
    "AWS_SECRET_ACCESS_KEY=" \
    "-p"
do
    i=$((i + 1))
    marker="PMK-CLI-$i-$R"
    arg="$shape$marker"
    "$CASES" sleeper "$arg" >/dev/null 2>&1 &
    cp=$!
    # Wait for the control to be observable instead of sampling once: on a
    # loaded host the fork/exec window outlives a fixed sleep, and a zero
    # control makes the "wrapped=0" half vacuous.
    ctl=0
    ctl_i=0
    while [ "$ctl_i" -lt 40 ]; do
        ctl=$(sightings "$marker")
        [ "$ctl" -ge 1 ] && break
        sleep 0.05 2>/dev/null || sleep 1
        ctl_i=$((ctl_i + 1))
    done
    kill -9 "$cp" 2>/dev/null
    wait "$cp" 2>/dev/null
    "$TOOL" -q -l "$FAKE" "$CASES" sleeper "$arg" >/dev/null 2>&1 &
    wp=$!
    # The masked run needs the same settle time before the sweep; sample
    # until the label is visible, then take one more reading.
    wp_i=0
    while [ "$wp_i" -lt 40 ]; do
        comm_count "$FAKE15" >/dev/null 2>&1 && break
        sleep 0.05 2>/dev/null || sleep 1
        wp_i=$((wp_i + 1))
    done
    wrapped=$(sightings "$marker")
    kill -9 "$wp" 2>/dev/null
    kill_label "$FAKE15" 2>/dev/null
    wait "$wp" 2>/dev/null
    if [ "$ctl" -ge 1 ] && [ "$wrapped" = 0 ]; then
        echo "PASS cli-spy-$i: control=$ctl wrapped=$wrapped"
    else
        echo "FAIL cli-spy-$i: control=$ctl wrapped=$wrapped"; OVERALL=1
    fi
done

echo "== VERDICT: $([ $OVERALL = 0 ] && echo ALL-PASS || echo FAILURES) =="
exit $OVERALL
