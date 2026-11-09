#!/bin/sh
# QA fragment for issue 26: `--isolate=none` still created user, mount,
# UTS, IPC and cgroup namespaces, and set NoNewPrivs.
#
# The defect: `parse_isolate("none")` produced `Isolate { pid: false,
# net: false, private_tmp: false }`, which is the same value as
# "isolation with the three switchable namespaces off".  Every
# `isolate::run` also creates the unconditional user, mount, UTS, IPC and
# cgroup namespaces, a private /dev and /proc, Landlock and
# `no_new_privs`, so `--isolate=none` isolated the payload anyway.
#
# Cases:
#   qa26-no-new-privs          NoNewPrivs is 0
#   qa26-host-user-namespace   the payload is in the host's user namespace
#   qa26-host-mount-namespace  the payload is in the host's mount namespace
#   qa26-no-isolation-line     no `pmask: isolation:` report is printed
#   qa26-note-names-the-choice the run report says what `none` meant
#   qa26-control-isolate-all   `--isolate` DOES change all three, so each
#                              row above can fail
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D="${TMPDIR:-/tmp}/qa26.$$"
mkdir -p "$D" || { echo "FAIL qa26-cannot-create-tmp"; exit 1; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    kill_label qa26 KILL 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT

HOST_USER=$(readlink /proc/self/ns/user 2>/dev/null)
HOST_MNT=$(readlink /proc/self/ns/mnt 2>/dev/null)
if [ -z "$HOST_USER" ] || [ -z "$HOST_MNT" ]; then
    skip "qa26-host-namespaces (readlink /proc/self/ns/* failed)"
    exit 0
fi

"$TOOL" --isolate=none --report=json -- /bin/sh -c \
    'echo nnp=$(grep ^NoNewPrivs /proc/self/status | cut -f2); readlink /proc/self/ns/user; readlink /proc/self/ns/mnt' \
    >"$D/none.out" 2>"$D/none.err"
rc=$?
if [ "$rc" = 0 ]; then
    pass "qa26-run-exits-zero"
else
    fail "qa26-run-exits-zero (rc=$rc err=$(tr '\n' '|' <"$D/none.err"))"
fi

nnp=$(sed -n 's/^nnp=//p' "$D/none.out" | head -1)
user=$(sed -n '2p' "$D/none.out")
mnt=$(sed -n '3p' "$D/none.out")
if [ "$nnp" = "0" ]; then
    pass "qa26-no-new-privs (NoNewPrivs=0)"
else
    fail "qa26-no-new-privs (NoNewPrivs=[$nnp])"
fi
if [ -n "$user" ] && [ "$user" = "$HOST_USER" ]; then
    pass "qa26-host-user-namespace ($user)"
else
    fail "qa26-host-user-namespace (inside=[$user] host=[$HOST_USER])"
fi
if [ -n "$mnt" ] && [ "$mnt" = "$HOST_MNT" ]; then
    pass "qa26-host-mount-namespace ($mnt)"
else
    fail "qa26-host-mount-namespace (inside=[$mnt] host=[$HOST_MNT])"
fi
if grep -q "^pmask: isolation:" "$D/none.err"; then
    fail "qa26-no-isolation-line ($(grep -m1 '^pmask: isolation:' "$D/none.err"))"
else
    pass "qa26-no-isolation-line"
fi
if grep -q -- "--isolate=none: the payload runs with the host's namespaces" "$D/none.out"; then
    pass "qa26-note-names-the-choice"
else
    fail "qa26-note-names-the-choice (notes: $(tr '\n' '|' <"$D/none.out" | cut -c1-300))"
fi

# Control: `--isolate` (all) must change the user namespace, print the
# isolation line, and set NoNewPrivs.  If the host refuses user
# namespaces the control cannot run, and the rows above are still
# decidable because "none" is the weaker request.
if unshare -Ur true 2>/dev/null; then
    "$TOOL" -q --isolate --report=json -- /bin/sh -c \
        'echo nnp=$(grep ^NoNewPrivs /proc/self/status | cut -f2); readlink /proc/self/ns/user' \
        >"$D/all.out" 2>"$D/all.err"
    ctl_nnp=$(sed -n 's/^nnp=//p' "$D/all.out" | head -1)
    ctl_user=$(sed -n '2p' "$D/all.out")
    if [ "$ctl_nnp" = "1" ] && [ -n "$ctl_user" ] && [ "$ctl_user" != "$HOST_USER" ]; then
        pass "qa26-control-isolate-all-changes-both (nnp=$ctl_nnp user=$ctl_user)"
    else
        fail "qa26-control-isolate-all-changes-both (nnp=[$ctl_nnp] user=[$ctl_user] host=[$HOST_USER])"
    fi
else
    skip "qa26-control-isolate-all-changes-both (user namespaces refused here)"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ] || exit 1
exit 0
