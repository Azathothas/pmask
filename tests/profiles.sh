#!/bin/sh
# ============================================================================
# pmask v0.3.0 profiles, audit, explain, profile-json, secret-fd, and UX suite.
#
# Tests all v0.3.0 profile and verification capabilities end-to-end:
#   P1  --profile single, tree, compat, tee, and auto (ELF -> single, sh -> tree)
#   P2  single profile live invariants (TracerPid: 0, Threads: 1, no supervisor,
#       NoNewPrivs/Seccomp unchanged, PR_SET_DUMPABLE=0, RLIMIT_CORE=0,
#       MADV_DONTDUMP, cmdline/comm = label, zero token leak)
#   P3  --audit --json self-audit (exit 0, passed: true on single and tree)
#   P4  --audit --pid planted defects (argv token, environ token, real exe,
#       real cwd, missing label, visible TracerPid on single -> ALL exit 1)
#   P5  --explain and --explain --json (same-uid observer & root out-of-scope)
#   P6  --profile-json and --profile-json --pid (native psgen schema: 2, zero secret)
#   P7  --secret-fd N and --secret-fd API_KEY=N (plus invalid fd exits 2)
#   P8  --rexec-mode=path (no /memfd: in exe/maps, staged file cleaned up)
#   P9  --cwd /tmp (payload sees /tmp even with relative binary path)
#   P10 --allow-impersonation (refuses [kworker/0:0] and sshd with exit 2;
#       succeeds with --allow-impersonation)
#   P11 --keep-env FOO /bin/true exits 2 with --keep-env=FOO hint
#   P12 recommended paths emit ZERO stderr warnings
#   P13 one-screen --help (<= 45 lines), full --help=all, help redact
#   P14 SIGKILL crash cleanup leaves 0 .rt-* dirs on single and tree
#   P15 --rexec-mode=tmpfile works cleanly with zero /memfd: and zero .rt-* dirs
#   P16 --stealth uses private path (Auto), zero unsolicited stderr on hidepid=off,
#       and pins /proc/<pid>/comm across rename with rc=0
#   P17 --profile tee forwards SECRET_TOKEN when userns+/proc succeeds, or fails
#       closed with exit 255 (never silent exit 0)
#   P18 AT_EXECFN direct read without EIO (--allow-dumpable or root)
#
# POSIX sh only: dash and busybox ash must both run it.
# ============================================================================
set -u
cd "$(dirname "$0")" || exit 2
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
PASS=0
SKIP=0
T="${TMPDIR:-/tmp}/pmask-profiles.$$"
mkdir -p "$T" || { echo "FATAL: cannot create $T"; exit 2; }
chmod 700 "$T"

pass() { PASS=$((PASS + 1)); echo "PASS $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL $*"; }
skip() { SKIP=$((SKIP + 1)); echo "SKIP $*"; }

PIDS=""
track_pid() {
    PIDS="$PIDS $1"
}

cleanup() {
    for p in $PIDS; do
        kill -9 "$p" 2>/dev/null || true
    done
    kill_comm prof- KILL 2>/dev/null || true
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

status_field() {  # PID FIELD -> value
    sed -n "s/^$2:[[:space:]]*//p" "/proc/$1/status" 2>/dev/null | head -1
}

wait_pid_file() {  # FILE -> prints pid
    wp_i=0
    wp_lim=60
    [ "$VM_TCG" = 1 ] && wp_lim=200
    while [ "$wp_i" -lt "$wp_lim" ]; do
        if [ -s "$1" ]; then
            wp_v=$(cat "$1" 2>/dev/null | tr -d '[:space:]')
            if [ -n "$wp_v" ] && [ -d "/proc/$wp_v" ]; then
                printf '%s' "$wp_v"
                return 0
            fi
        fi
        sleep 0.05 2>/dev/null || sleep 1
        wp_i=$((wp_i + 1))
    done
    return 1
}

wait_for_comm() {  # PID WANT
    wc_i=0
    wc_lim=60
    [ "$VM_TCG" = 1 ] && wc_lim=200
    while [ "$wc_i" -lt "$wc_lim" ]; do
        wc_got=$(cat "/proc/$1/comm" 2>/dev/null)
        [ "$wc_got" = "$2" ] && return 0
        sleep 0.05 2>/dev/null || sleep 1
        wc_i=$((wc_i + 1))
    done
    return 1
}

# Build a tiny helper ELF or use $CASES for direct ELF live targets.
# $CASES sleeper sleeps until killed, keeping its own PID alive.
# $CASES echoargs / getenv inspect real argv/env.

# ---------------------------------------------------------- P1: Profiles
# single, tree, compat, auto (ELF -> single, /bin/sh -> tree), tee

# P1a: --profile single runs ELF cleanly
"$TOOL" --profile single --label prof-single -- /bin/true >"$T/p1s.out" 2>"$T/p1s.err"
rc=$?
if [ "$rc" = 0 ] && [ ! -s "$T/p1s.err" ]; then
    pass "p1a-profile-single-runs-cleanly"
else
    fail "p1a-profile-single-runs-cleanly (rc=$rc err=$(cat "$T/p1s.err"))"
fi

# P1b: --profile tree runs cleanly with zero stderr warnings
"$TOOL" --profile tree --label prof-tree -- /bin/true >"$T/p1t.out" 2>"$T/p1t.err"
rc=$?
if [ "$rc" = 0 ] && [ ! -s "$T/p1t.err" ]; then
    pass "p1b-profile-tree-runs-cleanly"
else
    fail "p1b-profile-tree-runs-cleanly (rc=$rc err=$(cat "$T/p1t.err"))"
fi

# P1c: --profile compat runs cleanly with legacy dumpable default
"$TOOL" --profile compat --label prof-compat -- "$CASES" sleeper >/dev/null 2>"$T/p1c.err" &
p1c_sup=$!
track_pid "$p1c_sup"
p1c_child=""
p1c_i=0
while [ "$p1c_i" -lt 60 ]; do
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        if [ "$(proc_ppid "$p")" = "$p1c_sup" ]; then
            p1c_child="$p"
            break
        fi
    done
    [ -n "$p1c_child" ] && break
    sleep 0.05 2>/dev/null || sleep 1
    p1c_i=$((p1c_i + 1))
done
if [ -n "$p1c_child" ] && wait_for_comm "$p1c_child" "prof-compat"; then
    p1c_tr=$(status_field "$p1c_child" TracerPid)
    if [ -n "$p1c_tr" ] && [ "$p1c_tr" != "0" ]; then
        pass "p1c-profile-compat-traced-tree (TracerPid=$p1c_tr)"
    else
        fail "p1c-profile-compat-traced-tree (TracerPid=${p1c_tr:-empty})"
    fi
else
    fail "p1c-profile-compat-traced-tree (child not found)"
fi
kill -9 "$p1c_sup" 2>/dev/null || true
[ -n "$p1c_child" ] && kill -9 "$p1c_child" 2>/dev/null || true
wait "$p1c_sup" 2>/dev/null || true

# P1d: --profile auto selects single for direct ELF (TracerPid: 0, in-place PID!)
"$TOOL" --profile auto --label prof-auto-elf -- "$CASES" sleeper >/dev/null 2>"$T/p1ae.err" &
p1ae_pid=$!
track_pid "$p1ae_pid"
if wait_for_comm "$p1ae_pid" "prof-auto-elf"; then
    p1ae_tr=$(status_field "$p1ae_pid" TracerPid)
    p1ae_th=$(status_field "$p1ae_pid" Threads)
    if [ "$p1ae_tr" = "0" ] && [ "$p1ae_th" = "1" ]; then
        pass "p1d-auto-elf-selects-single (pid=$p1ae_pid TracerPid=0 Threads=1)"
    else
        fail "p1d-auto-elf-selects-single (TracerPid=$p1ae_tr Threads=$p1ae_th)"
    fi
else
    fail "p1d-auto-elf-selects-single (comm=$(cat "/proc/$p1ae_pid/comm" 2>/dev/null))"
fi
kill -9 "$p1ae_pid" 2>/dev/null || true
wait "$p1ae_pid" 2>/dev/null || true

# P1e: --profile auto selects tree for /bin/sh (supervisor traces shell, TracerPid != 0)
"$TOOL" --profile auto --label prof-auto-sh -- /bin/sh -c 'echo $$ > "'"$T/p1as.pid"'"; sleep 10' >/dev/null 2>"$T/p1as.err" &
p1as_sup=$!
track_pid "$p1as_sup"
p1as_pid=$(wait_pid_file "$T/p1as.pid" || true)
if [ -n "$p1as_pid" ]; then
    p1as_tr=$(status_field "$p1as_pid" TracerPid)
    if [ "$p1as_pid" != "$p1as_sup" ] && [ -n "$p1as_tr" ] && [ "$p1as_tr" != "0" ]; then
        pass "p1e-auto-sh-selects-tree (sup=$p1as_sup child=$p1as_pid TracerPid=$p1as_tr)"
    else
        fail "p1e-auto-sh-selects-tree (sup=$p1as_sup child=$p1as_pid TracerPid=${p1as_tr:-empty})"
    fi
else
    fail "p1e-auto-sh-selects-tree (shell pid file missing)"
fi
kill -9 "$p1as_sup" 2>/dev/null || true
[ -n "$p1as_pid" ] && kill -9 "$p1as_pid" 2>/dev/null || true
wait "$p1as_sup" 2>/dev/null || true

# P1f: --profile tee (skip cleanly if userns unavailable)
if "$TOOL" probe 2>/dev/null | grep -q 'isolation[[:space:]][[:space:]]*active'; then
    "$TOOL" --profile tee --label prof-tee -- /bin/true >"$T/p1tee.out" 2>"$T/p1tee.err"
    rc=$?
    if [ "$rc" = 0 ]; then
        pass "p1f-profile-tee-runs"
    else
        fail "p1f-profile-tee-runs (rc=$rc err=$(tr '\n' '|' < "$T/p1tee.err"))"
    fi
else
    skip "p1f-profile-tee-runs (user namespaces unavailable on this host)"
fi

# ---------------------------------------- P2: Single profile live invariants
# Check TracerPid: 0, Threads: 1, no supervisor process, NoNewPrivs unchanged,
# Seccomp_filters unchanged, PR_SET_DUMPABLE=0, RLIMIT_CORE=0, MADV_DONTDUMP,
# cmdline/comm = label, zero token leak!

BASE_NNP=$(status_field "$$" NoNewPrivs)
BASE_SEC=$(status_field "$$" Seccomp_filters)
[ -n "$BASE_NNP" ] || BASE_NNP=0
[ -n "$BASE_SEC" ] || BASE_SEC=0
TOK_SINGLE="PROF-SINGLE-TOK-$$-987654"

"$TOOL" --profile single --label prof-inv --env "PROF_SECRET=$TOK_SINGLE" \
    -- "$CASES" sleeper "$TOK_SINGLE" >/dev/null 2>"$T/p2.err" &
p2_pid=$!
track_pid "$p2_pid"

if wait_for_comm "$p2_pid" "prof-inv"; then
    p2_tr=$(status_field "$p2_pid" TracerPid)
    p2_th=$(status_field "$p2_pid" Threads)
    p2_nnp=$(status_field "$p2_pid" NoNewPrivs)
    p2_sec=$(status_field "$p2_pid" Seccomp_filters)
    p2_ppid=$(status_field "$p2_pid" PPid)
    p2_comm=$(cat "/proc/$p2_pid/comm" 2>/dev/null)
    p2_cmd=$(tr '\0' '|' < "/proc/$p2_pid/cmdline" 2>/dev/null)
    p2_core=$(awk '/^Max core file size/{print $5 ":" $6}' "/proc/$p2_pid/limits" 2>/dev/null)

    [ "$p2_tr" = "0" ] && pass "p2a-single-tracerpid-zero" \
        || fail "p2a-single-tracerpid-zero (got=$p2_tr)"
    [ "$p2_th" = "1" ] && pass "p2b-single-threads-one" \
        || fail "p2b-single-threads-one (got=$p2_th)"
    [ "$p2_ppid" = "$$" ] && pass "p2c-single-no-supervisor-in-place" \
        || fail "p2c-single-no-supervisor-in-place (ppid=$p2_ppid want=$$)"
    [ "${p2_nnp:-0}" = "$BASE_NNP" ] && pass "p2d-single-nonewprivs-unchanged" \
        || fail "p2d-single-nonewprivs-unchanged (got=${p2_nnp:-empty} base=$BASE_NNP)"
    [ "${p2_sec:-0}" = "$BASE_SEC" ] && pass "p2e-single-seccomp-filters-unchanged" \
        || fail "p2e-single-seccomp-filters-unchanged (got=${p2_sec:-empty} base=$BASE_SEC)"
    if [ "$p2_comm" = "prof-inv" ] && [ "$p2_cmd" = "prof-inv|" ]; then
        pass "p2f-single-cmdline-and-comm-match-label"
    else
        fail "p2f-single-cmdline-and-comm-match-label (comm=$p2_comm cmd=$p2_cmd)"
    fi
    [ "$p2_core" = "0:0" ] && pass "p2g-single-rlimit-core-zero" \
        || fail "p2g-single-rlimit-core-zero (got=$p2_core)"

    p2_sights=$(sightings "$TOK_SINGLE")
    [ "$p2_sights" = "0" ] && pass "p2h-single-zero-token-leak" \
        || fail "p2h-single-zero-token-leak (sightings=$p2_sights)"

    if [ "$MY_UID" = "0" ]; then
        # Root bypasses PR_SET_DUMPABLE=0 on /proc/<pid>/mem, so verify
        # MADV_DONTDUMP (`dd` in smaps VmFlags) directly instead.
        if grep -q 'VmFlags:.* dd' "/proc/$p2_pid/smaps" 2>/dev/null; then
            pass "p2i-single-madv-dontdump-present"
        else
            fail "p2i-single-madv-dontdump-present (no VmFlags dd in smaps)"
        fi
        skip "p2j-single-nodumpable-eacces (running as uid 0 bypasses PR_SET_DUMPABLE=0)"
    else
        if ( : < "/proc/$p2_pid/mem" ) 2>/dev/null; then
            fail "p2j-single-nodumpable-eacces (/proc/$p2_pid/mem opened by same uid!)"
        else
            pass "p2j-single-nodumpable-eacces"
        fi
        if ( : < "/proc/$p2_pid/environ" ) 2>/dev/null; then
            fail "p2k-single-environ-eacces (/proc/$p2_pid/environ opened by same uid!)"
        else
            pass "p2k-single-environ-eacces"
        fi
    fi
else
    fail "p2-single-live-target-did-not-start (err=$(cat "$T/p2.err"))"
fi
kill -9 "$p2_pid" 2>/dev/null || true
wait "$p2_pid" 2>/dev/null || true

# ---------------------------------------- P3: --audit --json self-audit
# Verify self-audit exits 0 and reports `"passed": true` on single & tree.
# Note: running as uid 0 (root) bypasses PR_SET_DUMPABLE=0 so root's own
# /proc/<pid>/mem scan sees the synthetic heap token (expected: root is
# out of scope!).  Run full self-audit pass assertion for non-root, and
# verify --audit --json schema & non-mem invariants even for root.
if [ "$MY_UID" = "0" ]; then
    skip "p3a-self-audit-single-json (uid 0 bypasses PR_SET_DUMPABLE=0; tested in non-root pass)"
    skip "p3b-self-audit-tree-json (uid 0 bypasses PR_SET_DUMPABLE=0; tested in non-root pass)"
else
    "$TOOL" --audit --json --profile single --rexec-mode=path --label prof-aud-s \
        >"$T/p3s.json" 2>"$T/p3s.err"
    rc=$?
    if [ "$rc" = 0 ] && grep -q '"schema": "pmask-audit/1"' "$T/p3s.json" \
        && grep -q '"passed": true' "$T/p3s.json"; then
        pass "p3a-self-audit-single-json"
    else
        fail "p3a-self-audit-single-json (rc=$rc err=$(tr '\n' '|' < "$T/p3s.err") json=$(grep -E '"(passed|id|detail)"' "$T/p3s.json" | tr '\n' '|'))"
    fi

    "$TOOL" --audit --json --profile tree --label prof-aud-t \
        >"$T/p3t.json" 2>"$T/p3t.err"
    rc=$?
    if [ "$rc" = 0 ] && grep -q '"schema": "pmask-audit/1"' "$T/p3t.json" \
        && grep -q '"passed": true' "$T/p3t.json"; then
        pass "p3b-self-audit-tree-json"
    else
        fail "p3b-self-audit-tree-json (rc=$rc err=$(tr '\n' '|' < "$T/p3t.err") json=$(grep -E '"(passed|id|detail)"' "$T/p3t.json" | tr '\n' '|'))"
    fi
fi

# ---------------------------------------- P4: Planted defects (ALL must exit 1)
PLANT_TOK="PLANTED-SECRET-TOK-$$-XYZ"

# P4a: token in argv
"$CASES" sleeper "$PLANT_TOK" >/dev/null 2>&1 &
d_pid=$!
track_pid "$d_pid"
sleep 0.1
PMASK_TEST_TOK="$PLANT_TOK" "$TOOL" --audit --json --profile single --pid "$d_pid" \
    --token-env PMASK_TEST_TOK >"$T/p4a.json" 2>"$T/p4a.err"
rc=$?
kill -9 "$d_pid" 2>/dev/null || true
wait "$d_pid" 2>/dev/null || true
if [ "$rc" = 1 ] && grep -q '"passed": false' "$T/p4a.json" \
    && ! grep -q "$PLANT_TOK" "$T/p4a.json"; then
    pass "p4a-planted-argv-token-exits-1-and-no-secret-echo"
else
    fail "p4a-planted-argv-token-exits-1 (rc=$rc)"
fi

# P4b: token in environ
PLANT_ENV_TOK="$PLANT_TOK" "$CASES" sleeper >/dev/null 2>&1 &
d_pid=$!
track_pid "$d_pid"
sleep 0.1
PMASK_TEST_TOK="$PLANT_TOK" "$TOOL" --audit --json --profile single --pid "$d_pid" \
    --token-env PMASK_TEST_TOK >"$T/p4b.json" 2>"$T/p4b.err"
rc=$?
kill -9 "$d_pid" 2>/dev/null || true
wait "$d_pid" 2>/dev/null || true
if [ "$rc" = 1 ] && grep -q '"passed": false' "$T/p4b.json" \
    && ! grep -q "$PLANT_TOK" "$T/p4b.json"; then
    pass "p4b-planted-environ-token-exits-1"
else
    fail "p4b-planted-environ-token-exits-1 (rc=$rc)"
fi

# P4c: real exe visible (no --rexec + --allow-dumpable)
"$TOOL" --profile single --no-rexec --allow-dumpable --label prof-noexe -- "$CASES" sleeper >/dev/null 2>&1 &
d_pid=$!
track_pid "$d_pid"
wait_for_comm "$d_pid" "prof-noexe" || true
"$TOOL" --audit --json --profile single --pid "$d_pid" --label prof-noexe \
    --real-exe "$CASES" >"$T/p4c.json" 2>"$T/p4c.err"
rc=$?
kill -9 "$d_pid" 2>/dev/null || true
wait "$d_pid" 2>/dev/null || true
if [ "$rc" = 1 ] && grep -q '"passed": false' "$T/p4c.json"; then
    pass "p4c-planted-real-exe-exits-1"
else
    fail "p4c-planted-real-exe-exits-1 (rc=$rc)"
fi

# P4d: real cwd visible (--allow-dumpable without --cwd)
REAL_CWD=$(pwd)
"$TOOL" --profile single --allow-dumpable --label prof-nocwd -- "$CASES" sleeper >/dev/null 2>&1 &
d_pid=$!
track_pid "$d_pid"
wait_for_comm "$d_pid" "prof-nocwd" || true
"$TOOL" --audit --json --profile single --pid "$d_pid" --label prof-nocwd \
    --real-cwd "$REAL_CWD" >"$T/p4d.json" 2>"$T/p4d.err"
rc=$?
kill -9 "$d_pid" 2>/dev/null || true
wait "$d_pid" 2>/dev/null || true
if [ "$rc" = 1 ] && grep -q '"passed": false' "$T/p4d.json"; then
    pass "p4d-planted-real-cwd-exits-1"
else
    fail "p4d-planted-real-cwd-exits-1 (rc=$rc)"
fi

# P4e: missing / mismatched label
"$TOOL" --profile single --label prof-actual -- "$CASES" sleeper >/dev/null 2>&1 &
d_pid=$!
track_pid "$d_pid"
wait_for_comm "$d_pid" "prof-actual" || true
"$TOOL" --audit --json --profile single --pid "$d_pid" --label prof-expected \
    >"$T/p4e.json" 2>"$T/p4e.err"
rc=$?
kill -9 "$d_pid" 2>/dev/null || true
wait "$d_pid" 2>/dev/null || true
if [ "$rc" = 1 ] && grep -q '"passed": false' "$T/p4e.json"; then
    pass "p4e-planted-mismatched-label-exits-1"
else
    fail "p4e-planted-mismatched-label-exits-1 (rc=$rc)"
fi

# P4f: visible TracerPid on single (launch under tree, audit as single!)
"$TOOL" --profile tree --label prof-traced -- /bin/sh -c 'echo $$ > "'"$T/p4f.pid"'"; sleep 10' >/dev/null 2>&1 &
d_sup=$!
track_pid "$d_sup"
d_pid=$(wait_pid_file "$T/p4f.pid" || true)
if [ -n "$d_pid" ]; then
    "$TOOL" --audit --json --profile single --pid "$d_pid" --label prof-traced \
        >"$T/p4f.json" 2>"$T/p4f.err"
    rc=$?
    if [ "$rc" = 1 ] && grep -q '"passed": false' "$T/p4f.json" \
        && grep -q 'TracerPid' "$T/p4f.json"; then
        pass "p4f-planted-tracerpid-on-single-exits-1"
    else
        fail "p4f-planted-tracerpid-on-single-exits-1 (rc=$rc)"
    fi
else
    fail "p4f-planted-tracerpid-on-single-exits-1 (target pid not created)"
fi
kill -9 "$d_sup" 2>/dev/null || true
[ -n "$d_pid" ] && kill -9 "$d_pid" 2>/dev/null || true
wait "$d_sup" 2>/dev/null || true

# ---------------------------------------- P5: --explain and --explain --json
"$TOOL" --explain --profile single --label prof-exp >"$T/p5.txt" 2>"$T/p5.err"
rc=$?
if [ "$rc" = 0 ] && [ ! -s "$T/p5.err" ] \
    && grep -qi 'same-uid' "$T/p5.txt" \
    && grep -qi 'root' "$T/p5.txt"; then
    pass "p5a-explain-text"
else
    fail "p5a-explain-text (rc=$rc err=$(cat "$T/p5.err"))"
fi

"$TOOL" --explain --json --profile single --label prof-exp >"$T/p5.json" 2>"$T/p5j.err"
rc=$?
if [ "$rc" = 0 ] && [ ! -s "$T/p5j.err" ] \
    && grep -q '"profile": "single"' "$T/p5.json" \
    && grep -qi 'same-uid' "$T/p5.json" \
    && grep -qi 'root' "$T/p5.json"; then
    pass "p5b-explain-json"
else
    fail "p5b-explain-json (rc=$rc err=$(cat "$T/p5j.err"))"
fi

# ---------------------------------------- P6: --profile-json & --pid (psgen schema: 2)
"$TOOL" --profile-json --profile single --label prof-tmpl >"$T/p6a.json" 2>"$T/p6a.err"
rc=$?
p6a_ok=1
for p6_key in '"schema": 2' '"source":' '"identity":' '"status":' '"stat":' '"memory":' '"auxv":' '"fds":' '"task":' '"syscall":' '"timing":' '"children":'; do
    grep -q "$p6_key" "$T/p6a.json" || p6a_ok=0
done
if [ "$rc" = 0 ] && [ ! -s "$T/p6a.err" ] && [ "$p6a_ok" = 1 ]; then
    pass "p6a-profile-json-template-schema2"
else
    fail "p6a-profile-json-template-schema2 (rc=$rc err=$(cat "$T/p6a.err"))"
fi

P6_TOK="PROF-JSON-SECRET-$$-NEVER-LEAK"
"$TOOL" --profile single --label prof-p6 --env "S=$P6_TOK" \
    -- "$CASES" sleeper "$P6_TOK" >/dev/null 2>&1 &
p6_pid=$!
track_pid "$p6_pid"
if wait_for_comm "$p6_pid" "prof-p6"; then
    PMASK_P6_TOK="$P6_TOK" "$TOOL" --profile-json --profile single --pid "$p6_pid" \
        --label prof-p6 --token-env PMASK_P6_TOK >"$T/p6b.json" 2>"$T/p6b.err"
    rc=$?
    p6b_ok=1
    for p6_key in '"schema": 2' '"source":' '"identity":' '"status":' '"stat":' '"memory":' '"auxv":' '"fds":' '"task":' '"syscall":' '"timing":' '"children":'; do
        grep -q "$p6_key" "$T/p6b.json" || p6b_ok=0
    done
    if [ "$rc" = 0 ] && [ ! -s "$T/p6b.err" ] && [ "$p6b_ok" = 1 ] \
        && ! grep -q "$P6_TOK" "$T/p6b.json"; then
        pass "p6b-profile-json-live-pid-schema2-no-secret"
    else
        fail "p6b-profile-json-live-pid-schema2-no-secret (rc=$rc err=$(cat "$T/p6b.err"))"
    fi
else
    fail "p6b-profile-json-live-pid-schema2-no-secret (target did not start)"
fi
kill -9 "$p6_pid" 2>/dev/null || true
wait "$p6_pid" 2>/dev/null || true

# ---------------------------------------- P7: --secret-fd
printf 'UNAMED-SECRET-VAL\n' > "$T/sfd1"
printf 'NAMED-API-KEY-VAL\n' > "$T/sfd2"

out=$("$TOOL" --label prof-sfd --secret-fd 7 \
    -- /bin/sh -c 'IFS= read -r v <&7; printf "%s:%s\n" "$PMASK_SECRET_FD" "$v"' \
    7<"$T/sfd1" 2>"$T/p7a.err")
rc=$?
if [ "$rc" = 0 ] && [ "$out" = "7:UNAMED-SECRET-VAL" ] && [ ! -s "$T/p7a.err" ]; then
    pass "p7a-secret-fd-unnamed"
else
    fail "p7a-secret-fd-unnamed (rc=$rc out=$out err=$(cat "$T/p7a.err"))"
fi

out=$("$TOOL" --label prof-sfd --secret-fd API_KEY=8 \
    -- /bin/sh -c 'IFS= read -r v <&8; printf "%s:%s\n" "$PMASK_SECRET_API_KEY" "$v"' \
    8<"$T/sfd2" 2>"$T/p7b.err")
rc=$?
if [ "$rc" = 0 ] && [ "$out" = "8:NAMED-API-KEY-VAL" ] && [ ! -s "$T/p7b.err" ]; then
    pass "p7b-secret-fd-named"
else
    fail "p7b-secret-fd-named (rc=$rc out=$out err=$(cat "$T/p7b.err"))"
fi

"$TOOL" --label prof-sfd --secret-fd 99 -- /bin/true >"$T/p7c.out" 2>"$T/p7c.err"
rc=$?
if [ "$rc" = 2 ]; then
    pass "p7c-secret-fd-invalid-exits-2"
else
    fail "p7c-secret-fd-invalid-exits-2 (rc=$rc want=2)"
fi

# ---------------------------------------- P8: --rexec-mode=path
# Verify no /memfd: in exe/maps and staged carrier is unlinked immediately!
"$TOOL" --profile single --rexec-mode=path --allow-dumpable --label prof-rpath \
    -- "$CASES" sleeper >/dev/null 2>"$T/p8.err" &
p8_pid=$!
track_pid "$p8_pid"
if wait_for_comm "$p8_pid" "prof-rpath"; then
    # Under `--rexec-mode=path`, the kernel sets comm from the staged filename
    # basename during execve before the transient helper finishes unlinking the
    # staged file and detaching; wait for TracerPid: 0 so slow TCG VMs never
    # observe the pre-detach window.
    p8_i=0
    while [ "$p8_i" -lt 80 ]; do
        p8_tr=$(awk '/^TracerPid:/{print $2}' "/proc/$p8_pid/status" 2>/dev/null)
        [ "$p8_tr" = "0" ] && break
        sleep 0.05
        p8_i=$((p8_i + 1))
    done
    p8_exe=$(readlink "/proc/$p8_pid/exe" 2>/dev/null)
    p8_has_memfd=0
    case "$p8_exe" in /memfd:*) p8_has_memfd=1 ;; esac
    grep -q '/memfd:' "/proc/$p8_pid/maps" 2>/dev/null && p8_has_memfd=1
    p8_raw="${p8_exe% (deleted)}"
    if [ "$p8_has_memfd" = 0 ] && [ -n "$p8_exe" ] && [ ! -e "$p8_raw" ] && [ ! -s "$T/p8.err" ]; then
        pass "p8-rexec-mode-path-no-memfd-and-unlinked (exe=$p8_exe)"
    else
        fail "p8-rexec-mode-path-no-memfd-and-unlinked (exe=$p8_exe memfd=$p8_has_memfd err=$(cat "$T/p8.err"))"
    fi
else
    fail "p8-rexec-mode-path-no-memfd-and-unlinked (target did not start: $(cat "$T/p8.err"))"
fi
kill -9 "$p8_pid" 2>/dev/null || true
wait "$p8_pid" 2>/dev/null || true

# ---------------------------------------- P9: --cwd /tmp with relative binary
# Copy /bin/sh as "$T/sh" (keeping basename `sh` so BusyBox applet dispatch
# works in the micro-VM as well as dash/bash on glibc hosts) to prove relative
# binary resolution happens BEFORE chdir(/tmp).
cp /bin/sh "$T/sh"
chmod 700 "$T/sh"
out=$( ( cd "$T" && "$TOOL" --profile single --label prof-cwd --cwd /tmp -- ./sh -c pwd ) 2>"$T/p9.err" )
rc=$?
if [ "$rc" = 0 ] && [ "$out" = "/tmp" ] && [ ! -s "$T/p9.err" ]; then
    pass "p9-cwd-tmp-with-relative-binary"
else
    fail "p9-cwd-tmp-with-relative-binary (rc=$rc out=$out err=$(cat "$T/p9.err"))"
fi

# ---------------------------------------- P10: --allow-impersonation
"$TOOL" --label '[kworker/0:0]' -- /bin/true >"$T/p10a.out" 2>"$T/p10a.err"
rc=$?
if [ "$rc" = 2 ] && grep -q -- '--allow-impersonation' "$T/p10a.err"; then
    pass "p10a-refuses-kworker-label-exit-2"
else
    fail "p10a-refuses-kworker-label-exit-2 (rc=$rc err=$(cat "$T/p10a.err"))"
fi

"$TOOL" --label sshd -- /bin/true >"$T/p10b.out" 2>"$T/p10b.err"
rc=$?
if [ "$rc" = 2 ] && grep -q -- '--allow-impersonation' "$T/p10b.err"; then
    pass "p10b-refuses-sshd-label-exit-2"
else
    fail "p10b-refuses-sshd-label-exit-2 (rc=$rc err=$(cat "$T/p10b.err"))"
fi

"$TOOL" --allow-impersonation --label '[kworker/0:0]' -- /bin/true >"$T/p10c.out" 2>"$T/p10c.err"
rc=$?
if [ "$rc" = 0 ] && [ ! -s "$T/p10c.err" ]; then
    pass "p10c-allow-impersonation-permits-kworker"
else
    fail "p10c-allow-impersonation-permits-kworker (rc=$rc err=$(cat "$T/p10c.err"))"
fi

"$TOOL" --allow-impersonation --label sshd -- /bin/true >"$T/p10d.out" 2>"$T/p10d.err"
rc=$?
if [ "$rc" = 0 ] && [ ! -s "$T/p10d.err" ]; then
    pass "p10d-allow-impersonation-permits-sshd"
else
    fail "p10d-allow-impersonation-permits-sshd (rc=$rc err=$(cat "$T/p10d.err"))"
fi

# ---------------------------------------- P11: --keep-env FOO /bin/true
"$TOOL" --keep-env FOO /bin/true >"$T/p11.out" 2>"$T/p11.err"
rc=$?
if [ "$rc" = 2 ] && grep -q -- '--keep-env=FOO' "$T/p11.err"; then
    pass "p11-keep-env-space-form-exits-2-with-hint"
else
    fail "p11-keep-env-space-form-exits-2-with-hint (rc=$rc err=$(cat "$T/p11.err"))"
fi

# ---------------------------------------- P12: Zero stderr warnings on recommended paths
p12_err=""
for cmd_name in default single tree; do
    case "$cmd_name" in
        default) "$TOOL" --label prof-quiet -- /bin/true >/dev/null 2>"$T/p12-$cmd_name.err" ;;
        single)  "$TOOL" --profile single --label prof-quiet -- /bin/true >/dev/null 2>"$T/p12-$cmd_name.err" ;;
        tree)    "$TOOL" --profile tree --label prof-quiet -- /bin/true >/dev/null 2>"$T/p12-$cmd_name.err" ;;
    esac
    if [ -s "$T/p12-$cmd_name.err" ]; then
        p12_err="$p12_err $cmd_name($(tr '\n' '|' < "$T/p12-$cmd_name.err"))"
    fi
done
if [ -z "$p12_err" ]; then
    pass "p12-zero-stderr-warnings-on-recommended-paths"
else
    fail "p12-zero-stderr-warnings-on-recommended-paths ($p12_err)"
fi

# ---------------------------------------- P13: Concise --help, --help=all, help redact
h_lines=$("$TOOL" --help 2>&1 | wc -l | tr -d ' ')
h_all_lines=$("$TOOL" --help=all 2>&1 | wc -l | tr -d ' ')
if [ "$h_lines" -gt 5 ] && [ "$h_lines" -le 45 ]; then
    pass "p13a-help-fits-one-screen (lines=$h_lines)"
else
    fail "p13a-help-fits-one-screen (lines=$h_lines want <=45)"
fi
if [ "$h_all_lines" -gt "$h_lines" ] && "$TOOL" --help=all 2>&1 | grep -q 'PMASK_NO_SELFMASK'; then
    pass "p13b-help-all-is-full-reference (lines=$h_all_lines)"
else
    fail "p13b-help-all-is-full-reference (lines=$h_all_lines)"
fi
if "$TOOL" help redact 2>&1 | grep -q -- '--label'; then
    pass "p13c-help-redact-includes-label"
else
    fail "p13c-help-redact-includes-label"
fi

# ---------------------------------------- P14: SIGKILL cleanup leaves 0 .rt-* dirs
mkdir -p "$T/rt14s" "$T/rt14t"
chmod 700 "$T/rt14s" "$T/rt14t"

XDG_RUNTIME_DIR="$T/rt14s" "$TOOL" --profile single --rexec-mode=path --label prof-k14s \
    -- "$CASES" sleeper >/dev/null 2>"$T/p14s.err" &
p14s_pid=$!
track_pid "$p14s_pid"
wait_for_comm "$p14s_pid" "prof-k14s" || true
kill -9 "$p14s_pid" 2>/dev/null || true
wait "$p14s_pid" 2>/dev/null || true
sleep 0.2 2>/dev/null || sleep 1
p14s_left=$(find "$T/rt14s" -maxdepth 1 -name '.rt-*' 2>/dev/null | wc -l | tr -d ' ')
if [ "$p14s_left" = "0" ]; then
    pass "p14a-sigkill-single-leaves-zero-rt-dirs"
else
    fail "p14a-sigkill-single-leaves-zero-rt-dirs (left=$p14s_left)"
fi

XDG_RUNTIME_DIR="$T/rt14t" "$TOOL" --profile tree --rexec-mode=path --label prof-k14t \
    -- "$CASES" sleeper >/dev/null 2>"$T/p14t.err" &
p14t_sup=$!
track_pid "$p14t_sup"
sleep 0.3 2>/dev/null || sleep 1
kill -9 "$p14t_sup" 2>/dev/null || true
wait "$p14t_sup" 2>/dev/null || true
sleep 0.2 2>/dev/null || sleep 1
p14t_left=$(find "$T/rt14t" -maxdepth 1 -name '.rt-*' 2>/dev/null | wc -l | tr -d ' ')
if [ "$p14t_left" = "0" ]; then
    pass "p14b-sigkill-tree-leaves-zero-rt-dirs"
else
    fail "p14b-sigkill-tree-leaves-zero-rt-dirs (left=$p14t_left)"
fi

# ---------------------------------------- P15: --rexec-mode=tmpfile
mkdir -p "$T/rt15"
chmod 700 "$T/rt15"
XDG_RUNTIME_DIR="$T/rt15" "$TOOL" --profile single --rexec-mode=tmpfile --label prof-tmpf \
    -- /bin/true >"$T/p15chk.out" 2>"$T/p15chk.err"
p15_chk_rc=$?
if [ "$p15_chk_rc" = 126 ] && grep -qi 'O_TMPFILE' "$T/p15chk.err"; then
    skip "p15-rexec-mode-tmpfile (O_TMPFILE unsupported on writable exec mounts here)"
else
    XDG_RUNTIME_DIR="$T/rt15" "$TOOL" --profile single --rexec-mode=tmpfile --allow-dumpable \
        --label prof-tmpf -- "$CASES" sleeper >/dev/null 2>"$T/p15.err" &
    p15_pid=$!
    track_pid "$p15_pid"
    if wait_for_comm "$p15_pid" "prof-tmpf"; then
        p15_i=0
        while [ "$p15_i" -lt 80 ]; do
            p15_tr=$(status_field "$p15_pid" TracerPid)
            [ "$p15_tr" = "0" ] && break
            sleep 0.05 2>/dev/null || sleep 1
            p15_i=$((p15_i + 1))
        done
        p15_exe=$(readlink "/proc/$p15_pid/exe" 2>/dev/null)
        p15_memfd=0
        case "$p15_exe" in /memfd:*) p15_memfd=1 ;; esac
        grep -q '/memfd:' "/proc/$p15_pid/maps" 2>/dev/null && p15_memfd=1
        p15_rt=$(find "$T/rt15" -maxdepth 1 -name '.rt-*' 2>/dev/null | wc -l | tr -d ' ')
        if [ "$p15_memfd" = "0" ] && [ "$p15_rt" = "0" ] && [ ! -s "$T/p15.err" ]; then
            pass "p15-rexec-mode-tmpfile-clean (exe=$p15_exe)"
        else
            fail "p15-rexec-mode-tmpfile-clean (exe=$p15_exe memfd=$p15_memfd rt=$p15_rt err=$(cat "$T/p15.err"))"
        fi
    else
        fail "p15-rexec-mode-tmpfile-clean (did not start: $(cat "$T/p15.err"))"
    fi
    kill -9 "$p15_pid" 2>/dev/null || true
    wait "$p15_pid" 2>/dev/null || true
fi

# ---------------------------------------- P16: --stealth Auto path, quiet on hidepid=off, pinned comm
mkdir -p "$T/rt16"
chmod 700 "$T/rt16"
p16_hidepid=0
grep -E ' /proc .* - proc proc ' /proc/self/mountinfo 2>/dev/null \
    | grep -Eq 'hidepid=(2|4|invisible|ptraceable)' && p16_hidepid=1

XDG_RUNTIME_DIR="$T/rt16" "$TOOL" --stealth --label prof-st16 \
    -- "$CASES" evilrename 1 >"$T/p16.out" 2>"$T/p16.err"
p16_rc=$?
if [ "$p16_rc" = 0 ] && grep -q '^comm=prof-st16$' "$T/p16.out"; then
    pass "p16a-stealth-pins-comm-after-rename-rc0"
else
    fail "p16a-stealth-pins-comm-after-rename-rc0 (rc=$p16_rc out=$(tr '\n' '|' < "$T/p16.out") err=$(cat "$T/p16.err"))"
fi
if [ "$p16_hidepid" = 0 ]; then
    if [ ! -s "$T/p16.err" ]; then
        pass "p16b-stealth-zero-unsolicited-stderr-on-hidepid-off"
    else
        fail "p16b-stealth-zero-unsolicited-stderr-on-hidepid-off (err=$(tr '\n' '|' < "$T/p16.err"))"
    fi
else
    skip "p16b-stealth-zero-unsolicited-stderr-on-hidepid-off (host uses hidepid=invisible/ptraceable)"
fi

XDG_RUNTIME_DIR="$T/rt16" "$TOOL" --stealth --allow-dumpable --label prof-st16e \
    -- "$CASES" sleeper >/dev/null 2>"$T/p16e.err" &
p16_sup=$!
track_pid "$p16_sup"
p16_child=""
p16_i=0
while [ "$p16_i" -lt 60 ]; do
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        if [ "$(proc_ppid "$p")" = "$p16_sup" ]; then
            p16_child="$p"
            break
        fi
    done
    [ -n "$p16_child" ] && break
    sleep 0.05 2>/dev/null || sleep 1
    p16_i=$((p16_i + 1))
done
if [ -n "$p16_child" ] && wait_for_comm "$p16_child" "prof-st16e"; then
    p16_exe=$(readlink "/proc/$p16_child/exe" 2>/dev/null)
    if [ -n "$p16_exe" ]; then
        case "$p16_exe" in
            /memfd:*) fail "p16c-stealth-uses-auto-private-path (stuck on memfd: $p16_exe)" ;;
            "$CASES") fail "p16c-stealth-uses-auto-private-path (exposed real exe: $p16_exe)" ;;
            *) pass "p16c-stealth-uses-auto-private-path (exe=$p16_exe)" ;;
        esac
    else
        skip "p16c-stealth-uses-auto-private-path (exe unreadable under current uid)"
    fi
else
    fail "p16c-stealth-uses-auto-private-path (child not found)"
fi
kill -9 "$p16_sup" 2>/dev/null || true
[ -n "$p16_child" ] && kill -9 "$p16_child" 2>/dev/null || true
wait "$p16_sup" 2>/dev/null || true

# ---------------------------------------- P17: --profile tee forwards secret OR fails closed (255)
P17_SECRET="TEE-FWD-SECRET-$$-OK"
p17_out=$(SECRET_TOKEN="$P17_SECRET" "$TOOL" --profile tee --label prof-tee17 \
    -- "$CASES" getenv SECRET_TOKEN 2>"$T/p17.err")
p17_rc=$?
if [ "$p17_rc" = 0 ]; then
    if [ "$p17_out" = "SECRET_TOKEN=$P17_SECRET" ]; then
        pass "p17-profile-tee-forwards-secret-token"
    else
        fail "p17-profile-tee-forwards-secret-token (got=[$p17_out] want=[SECRET_TOKEN=$P17_SECRET])"
    fi
elif [ "$p17_rc" = 255 ] && [ -s "$T/p17.err" ]; then
    pass "p17-profile-tee-fails-closed-exit-255 ($(tr '\n' ' ' < "$T/p17.err" | cut -c1-120))"
else
    fail "p17-profile-tee-fail-closed-or-forward (rc=$p17_rc out=[$p17_out] err=$(tr '\n' '|' < "$T/p17.err"))"
fi

# ---------------------------------------- P18: AT_EXECFN direct read without EIO
p18_yama=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)
"$TOOL" --profile single --allow-dumpable --label prof-execfn \
    -- "$CASES" sleeper >/dev/null 2>"$T/p18.err" &
p18_pid=$!
track_pid "$p18_pid"
if wait_for_comm "$p18_pid" "prof-execfn"; then
    p18_i=0
    while [ "$p18_i" -lt 80 ]; do
        p18_tr=$(status_field "$p18_pid" TracerPid)
        [ "$p18_tr" = "0" ] && break
        sleep 0.05 2>/dev/null || sleep 1
        p18_i=$((p18_i + 1))
    done
    "$TOOL" --audit --json --profile single --pid "$p18_pid" --label prof-execfn \
        >"$T/p18.json" 2>"$T/p18a.err"
    if [ "$MY_UID" = "0" ] || [ "$p18_yama" = "0" ]; then
        if grep -q '"execfn_io_error": false' "$T/p18.json" \
            && grep -q '"auxv_execfn_readable": true' "$T/p18.json" \
            && ! grep -q '"at_execfn_str": null' "$T/p18.json"; then
            pass "p18-at-execfn-direct-read-no-eio"
        else
            fail "p18-at-execfn-direct-read-no-eio ($(grep -E 'execfn' "$T/p18.json" | tr '\n' '|'))"
        fi
    else
        if grep -q '"execfn_io_error": false' "$T/p18.json"; then
            skip "p18-at-execfn-direct-read-no-eio (yama.ptrace_scope=$p18_yama denies sibling /proc/<pid>/mem as non-root)"
        else
            fail "p18-at-execfn-direct-read-no-eio (unexpected execfn_io_error)"
        fi
    fi
else
    fail "p18-at-execfn-direct-read-no-eio (target did not start)"
fi
kill -9 "$p18_pid" 2>/dev/null || true
wait "$p18_pid" 2>/dev/null || true

echo "== PROFILES: PASS=$PASS FAIL=$FAIL SKIP=$SKIP =="
[ "$FAIL" = 0 ] || exit 1
exit 0
