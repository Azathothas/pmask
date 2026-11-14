#!/bin/sh
# QA fragment for the stealth and hidepid work.
#
# The audit found that the supervisor was non-dumpable for the whole
# session.  On a host whose /proc uses hidepid=invisible, a non-dumpable
# process is hidden from same-uid observers, so chkproc and a same-uid
# unhide named the supervisor as a hidden pid.  The supervisor now
# scrubs its at-rest copies and stays dumpable; --no-dumpable still pins
# it non-dumpable, and --stealth chooses the best trade for the host.
#
# Cases:
#   qa62-default-supervisor-visible   hidepid=invisible, default run:
#                                     the same uid sees the supervisor
#   qa62-nodumpable-supervisor-hidden hidepid=invisible, --no-dumpable:
#                                     the same uid does not (control)
#   qa62-stealth-closes-the-memory-read  hidepid=0: --stealth applies
#                                     --no-dumpable, so environ is EACCES
#   qa62-stealth-keeps-comm           a self-renaming payload keeps the
#                                     label under --stealth (--watch-rename)
#   qa62-stealth-uses-a-memfd         root sees /memfd: for exe
#   qa62-stealth-names-the-hidepid-trade  hidepid=invisible: --stealth
#                                     says it did not apply --no-dumpable
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa62.XXXXXX") || {
    echo "FATAL: cannot create a temp dir"; exit 2
}
PIDS=""
cleanup() {
    for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
    kill_label qa62 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT INT TERM HUP QUIT

have_root=no
sudo -n true 2>/dev/null && have_root=yes
have_setpriv=no
command -v setpriv >/dev/null 2>&1 && have_setpriv=yes
have_unshare=no
command -v unshare >/dev/null 2>&1 && have_unshare=yes

# ------------------------------------------------ hidepid visibility
# The script runs inside a private mount and pid namespace as root, then
# drops to uid 1000 to start pmask and to read /proc.  A dumpable
# process is visible in the readdir; a non-dumpable one is not.
vis_case() {
    vc_flags="$1"
    vc_name="$2"
    cat > "$D/vis.sh" <<EOF
#!/bin/sh
mount -o remount,hidepid=invisible /proc || exit 9
setpriv --reuid=1000 --regid=1000 --clear-groups -- "$TOOL" -q -l qa62vis $vc_flags -- /bin/sleep 5 &
SUP=\$!
sleep 0.7
if setpriv --reuid=1000 --regid=1000 --clear-groups -- sh -c "ls /proc | grep -qx \$SUP"; then
    echo VISIBLE
else
    echo HIDDEN
fi
kill -9 \$SUP 2>/dev/null
EOF
    chmod +x "$D/vis.sh"
    sudo -n unshare -m -p --fork --mount-proc sh "$D/vis.sh" 2>/dev/null
}

unshare_ok=no
if [ "$have_root" = yes ] && [ "$have_unshare" = yes ]; then
    if sudo -n unshare -m -p --fork --mount-proc sh -c true 2>"$D/unshare.err"; then
        unshare_ok=yes
    fi
fi
if [ "$have_root" = yes ] && [ "$have_setpriv" = yes ] && [ "$unshare_ok" = yes ]; then
    out=$(vis_case "" default)
    case "$out" in
        *VISIBLE*) pass "qa62-default-supervisor-visible (hidepid=invisible)" ;;
        *) fail "qa62-default-supervisor-visible (out=$(printf '%s' "$out" | tr '\n' '|'))" ;;
    esac
    out=$(vis_case "--no-dumpable" nodumpable)
    case "$out" in
        *HIDDEN*) pass "qa62-nodumpable-supervisor-hidden (control)" ;;
        *) fail "qa62-nodumpable-supervisor-hidden (out=$(printf '%s' "$out" | tr '\n' '|'))" ;;
    esac
else
    skip "qa62-default-supervisor-visible (needs root, setpriv and unshare)"
    skip "qa62-nodumpable-supervisor-hidden (needs root, setpriv and unshare)"
fi

# ------------------------------------------------ --stealth on hidepid=0
"$TOOL" -q -l qa62st --stealth -- "$CASES" sleeper QAMARK >/dev/null 2>"$D/st.err" &
ST=$!
PIDS="$PIDS $ST"
sleep 0.8
PAY=""
for d in /proc/[0-9]*; do
    [ "$(cat "$d/comm" 2>/dev/null)" = "qa62st" ] || continue
    q=${d#/proc/}
    [ "$q" = "$ST" ] && continue
    PAY=$q
done
if [ -n "$PAY" ]; then
    env_rc=0
    cat "/proc/$PAY/environ" >/dev/null 2>&1 || env_rc=$?
    if [ "$env_rc" != 0 ]; then
        pass "qa62-stealth-closes-the-memory-read (environ EACCES)"
    else
        fail "qa62-stealth-closes-the-memory-read (environ readable: $(wc -c < "/proc/$PAY/environ") bytes)"
    fi
    cl=$(tr '\0' '|' < "/proc/$PAY/cmdline" 2>/dev/null)
    [ "$cl" = "qa62st|" ] && pass "qa62-stealth-cmdline-is-the-label" \
        || fail "qa62-stealth-cmdline-is-the-label (cmdline=[$cl])"
    if [ "$have_root" = yes ]; then
        exe=$(sudo -n readlink "/proc/$PAY/exe" 2>/dev/null)
        case "$exe" in
            /memfd:*) pass "qa62-stealth-uses-a-memfd (exe=$exe)" ;;
            *) fail "qa62-stealth-uses-a-memfd (exe=[$exe])" ;;
        esac
    else
        skip "qa62-stealth-uses-a-memfd (needs root to read a non-dumpable exe)"
    fi
else
    fail "qa62-stealth-closes-the-memory-read (no payload)"
    fail "qa62-stealth-cmdline-is-the-label (no payload)"
    skip "qa62-stealth-uses-a-memfd (no payload)"
fi
kill -9 "$ST" 2>/dev/null
wait "$ST" 2>/dev/null
PIDS=""

# ------------------------------------------------ --stealth keeps comm
"$TOOL" -q -l qa62rn --stealth -- "$CASES" renamer >/dev/null 2>"$D/rn.err" &
RN=$!
PIDS="$PIDS $RN"
sleep 1.2
PAY=""
for d in /proc/[0-9]*; do
    [ "$(cat "$d/comm" 2>/dev/null)" = "qa62rn" ] || continue
    q=${d#/proc/}
    [ "$q" = "$RN" ] && continue
    PAY=$q
done
if [ -n "$PAY" ]; then
    pass "qa62-stealth-keeps-comm (comm=qa62rn after a self-rename)"
else
    fail "qa62-stealth-keeps-comm (no process kept the label after the rename)"
fi
kill -9 "$RN" 2>/dev/null
wait "$RN" 2>/dev/null
PIDS=""

# --------------------------- --stealth names the hidepid trade
if [ "$have_root" = yes ] && [ "$have_setpriv" = yes ] && [ "$unshare_ok" = yes ]; then
    cat > "$D/trade.sh" <<EOF
#!/bin/sh
mount -o remount,hidepid=invisible /proc || exit 9
setpriv --reuid=1000 --regid=1000 --clear-groups -- "$TOOL" --stealth -l qa62tr -- /bin/true 2>&1
EOF
    chmod +x "$D/trade.sh"
    out=$(sudo -n unshare -m -p --fork --mount-proc sh "$D/trade.sh" 2>&1)
    case "$out" in
        *"hidepid=invisible"*"not applied"*)
            pass "qa62-stealth-names-the-hidepid-trade" ;;
        *) fail "qa62-stealth-names-the-hidepid-trade (out=$(printf '%s' "$out" | tr '\n' '|' | cut -c1-200))" ;;
    esac
else
    skip "qa62-stealth-names-the-hidepid-trade (needs root, setpriv and unshare)"
fi

echo "== VERDICT: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL) failures=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
