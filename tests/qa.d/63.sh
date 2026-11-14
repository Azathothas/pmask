#!/bin/sh
# QA fragment for --hide-pid.
#
# The kernel mechanism is PR_SET_DUMPABLE=0 plus a /proc mount with
# hidepid=invisible or hidepid=ptraceable.  On a weaker mount the flag
# must refuse the run instead of claiming a hide the kernel does not
# provide.  A hidden pid is still present to kill(0), pidfd_open and root.
#
# Cases:
#   qa63-off-refused      hidepid=off: exit 255, names the mount
#   qa63-probe-row        pmask probe has the hide-pid row
#   qa63-hidden           hidepid=invisible: the supervisor and payload
#                         are absent from a same-uid readdir
#   qa63-kill0-present    the same pid answers kill(0)
#   qa63-payload-hidden   the payload pid is absent too
#   qa63-report           the JSON report says hide_pid=true
#   qa63-stealth-note     --stealth --hide-pid says which trade wins
#   qa63-daemon-refused   --daemon refuses the flag instead of running
#   qa63-noreadact        --hide-pid with --no-redact is refused
#   qa63-nofollow-refused --hide-pid with --no-follow is refused
#   qa63-detach-refused   --hide-pid with --detach is refused
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

D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa63.XXXXXX") || {
    echo "FATAL: cannot create a temp dir"; exit 2
}
PIDS=""
cleanup() {
    for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
    kill_label qa63 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT INT TERM HUP QUIT

have_root=no
sudo -n true 2>/dev/null && have_root=yes
have_setpriv=no
command -v setpriv >/dev/null 2>&1 && have_setpriv=yes
have_unshare=no
command -v unshare >/dev/null 2>&1 && have_unshare=yes

# ------------------------------------------------ refusal on a weaker mount
# The refusal is host policy: a host already mounted with
# hidepid=invisible or ptraceable accepts the flag, so the row is a
# skip there rather than a failure of the tree.
policy=off
if grep -q 'hidepid=invisible' /proc/mounts 2>/dev/null; then
    policy=invisible
elif grep -q 'hidepid=ptraceable' /proc/mounts 2>/dev/null; then
    policy=ptraceable
elif grep -q 'hidepid=restricted' /proc/mounts 2>/dev/null; then
    policy=restricted
fi
case "$policy" in
invisible|ptraceable)
    skip "qa63-off-refused (this host is hidepid=$policy, so the flag is accepted; the refusal row needs a weaker mount)" ;;
*)
    "$TOOL" --hide-pid -l qa63off -- /bin/true >/dev/null 2>"$D/off.err"
    rc=$?
    if [ "$rc" = 255 ] && grep -q -- '--hide-pid needs /proc' "$D/off.err"; then
        pass "qa63-off-refused ($(head -1 "$D/off.err" | cut -c1-100))"
    else
        fail "qa63-off-refused (rc=$rc err=$(tr '\n' '|' < "$D/off.err" | cut -c1-160))"
    fi ;;
esac

if "$TOOL" probe 2>/dev/null | grep -q 'hide-pid'; then
    pass "qa63-probe-row"
else
    fail "qa63-probe-row"
fi

# ------------------------------------------------ --no-redact refusal
"$TOOL" --hide-pid --no-redact -l qa63nr -- /bin/true >/dev/null 2>"$D/nr.err"
rc=$?
if [ "$rc" = 255 ] && grep -q -- 'needs the redaction mode' "$D/nr.err"; then
    pass "qa63-noreadact ($(head -1 "$D/nr.err" | cut -c1-100))"
else
    fail "qa63-noreadact (rc=$rc err=$(tr '\n' '|' < "$D/nr.err" | cut -c1-160))"
fi

# ------------------------------------------------ composition refusals
# An exec resets PR_SET_DUMPABLE to 1.  --no-follow and --detach both take
# a process off the completion path that re-applies it, so the tree-wide
# promise cannot hold.  The refusal is checked before the mount policy, so
# these rows decide on every host.
"$TOOL" --hide-pid --no-follow -l qa63nf -- /bin/true >/dev/null 2>"$D/nf.err"
rc=$?
if [ "$rc" = 255 ] && grep -q -- '--hide-pid and --no-follow' "$D/nf.err"; then
    pass "qa63-nofollow-refused ($(head -1 "$D/nf.err" | cut -c1-100))"
elif [ "$rc" = 255 ] && grep -q -- 'needs the redaction mode' "$D/nf.err"; then
    skip "qa63-nofollow-refused (this host selects mode=plain, so --hide-pid is refused before the composition check)"
else
    fail "qa63-nofollow-refused (rc=$rc err=$(tr '\n' '|' < "$D/nf.err" | cut -c1-160))"
fi

"$TOOL" --hide-pid --detach -l qa63det -- /bin/true >/dev/null 2>"$D/det.err"
rc=$?
if [ "$rc" = 255 ] && grep -q -- '--hide-pid and --detach' "$D/det.err"; then
    pass "qa63-detach-refused ($(head -1 "$D/det.err" | cut -c1-100))"
elif [ "$rc" = 255 ] && grep -q -- 'needs the redaction mode' "$D/det.err"; then
    skip "qa63-detach-refused (this host selects mode=plain, so --hide-pid is refused before the composition check)"
else
    fail "qa63-detach-refused (rc=$rc err=$(tr '\n' '|' < "$D/det.err" | cut -c1-160))"
fi

# ------------------------------------------------ hidden under hidepid=invisible
unshare_ok=no
if [ "$have_root" = yes ] && [ "$have_unshare" = yes ]; then
    if sudo -n unshare -m -p --fork --mount-proc sh -c true 2>"$D/unshare.err"; then
        unshare_ok=yes
    fi
fi
if [ "$have_root" = yes ] && [ "$have_setpriv" = yes ] && [ "$unshare_ok" = yes ]; then
    cat > "$D/hp.sh" <<EOF
#!/bin/sh
mount -o remount,hidepid=invisible /proc || exit 9
setpriv --reuid=1000 --regid=1000 --clear-groups -- "$TOOL" -q -l qa63hid --hide-pid -- /bin/sleep 5 &
SUP=\$!
sleep 0.8
echo "SUP=\$SUP"
if setpriv --reuid=1000 --regid=1000 --clear-groups -- sh -c "ls /proc | grep -qx \$SUP"; then
    echo SUP-VISIBLE
else
    echo SUP-HIDDEN
fi
if setpriv --reuid=1000 --regid=1000 --clear-groups -- sh -c "kill -0 \$SUP 2>/dev/null"; then
    echo KILL0-PRESENT
else
    echo KILL0-ABSENT
fi
PAY=\$(pgrep -P \$SUP 2>/dev/null | head -n 1)
echo "PAY=\$PAY"
if [ -n "\$PAY" ]; then
    if setpriv --reuid=1000 --regid=1000 --clear-groups -- sh -c "ls /proc | grep -qx \$PAY"; then
        echo PAY-VISIBLE
    else
        echo PAY-HIDDEN
    fi
fi
kill -9 \$SUP 2>/dev/null
EOF
    chmod +x "$D/hp.sh"
    out=$(sudo -n unshare -m -p --fork --mount-proc sh "$D/hp.sh" 2>&1)
    case "$out" in
        *SUP-HIDDEN*) pass "qa63-hidden (same-uid readdir omits the supervisor)" ;;
        *) fail "qa63-hidden (out=$(printf '%s' "$out" | tr '\n' '|' | cut -c1-200))" ;;
    esac
    case "$out" in
        *KILL0-PRESENT*) pass "qa63-kill0-present (the pid still exists)" ;;
        *) fail "qa63-kill0-present (out=$(printf '%s' "$out" | tr '\n' '|' | cut -c1-200))" ;;
    esac
    case "$out" in
        *PAY-HIDDEN*) pass "qa63-payload-hidden" ;;
        *PAY-VISIBLE*) fail "qa63-payload-hidden (the payload pid was visible)" ;;
        *) skip "qa63-payload-hidden (no payload pid found)" ;;
    esac

    # The JSON report, on a run that exits at once.
    cat > "$D/rep.sh" <<EOF
#!/bin/sh
mount -o remount,hidepid=invisible /proc || exit 9
setpriv --reuid=1000 --regid=1000 --clear-groups -- "$TOOL" --hide-pid --report=json -l qa63rep -- /bin/true
EOF
    chmod +x "$D/rep.sh"
    out=$(sudo -n unshare -m -p --fork --mount-proc sh "$D/rep.sh" 2>/dev/null)
    case "$out" in
        *'"hide_pid": true'*) pass "qa63-report" ;;
        *) fail "qa63-report (out=$(printf '%s' "$out" | tr '\n' '|' | cut -c1-200))" ;;
    esac

    cat > "$D/st.sh" <<EOF
#!/bin/sh
mount -o remount,hidepid=invisible /proc || exit 9
setpriv --reuid=1000 --regid=1000 --clear-groups -- "$TOOL" --stealth --hide-pid -l qa63st -- /bin/true 2>&1
EOF
    chmod +x "$D/st.sh"
    out=$(sudo -n unshare -m -p --fork --mount-proc sh "$D/st.sh" 2>&1)
    case "$out" in
        *'--hide-pid wins'*) pass "qa63-stealth-note" ;;
        *) fail "qa63-stealth-note (out=$(printf '%s' "$out" | tr '\n' '|' | cut -c1-200))" ;;
    esac
else
    skip "qa63-hidden (needs root, setpriv and unshare)"
    skip "qa63-kill0-present (needs root, setpriv and unshare)"
    skip "qa63-payload-hidden (needs root, setpriv and unshare)"
    skip "qa63-report (needs root, setpriv and unshare)"
    skip "qa63-stealth-note (needs root, setpriv and unshare)"
fi

# ------------------------------------------------ --daemon cannot honour it
# A job sent to pmaskd is masked by the daemon's policy, so --hide-pid
# would be silently dropped.  The refusal must happen before the local
# runner is selected, or the job runs here while the operator asked for
# the daemon.
"$TOOL" -q --daemon /nonexistent.sock --hide-pid -l qa63dm -- /bin/true \
    >/dev/null 2>"$D/dm.err"
rc=$?
if [ "$rc" = 255 ] && grep -q -- '--daemon cannot be combined with --hide-pid' "$D/dm.err"; then
    pass "qa63-daemon-refused"
else
    fail "qa63-daemon-refused (rc=$rc err=$(head -1 "$D/dm.err"))"
fi

echo "== VERDICT: $([ "$FAIL" = 0 ] && echo PASS || echo FAIL) failures=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
