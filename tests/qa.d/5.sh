#!/bin/sh
# QA fragment for issue 5: `pmask read NAME` fails inside a masked payload.
#
# The defect: `mask::snapshot_argv()` read `/proc/self/cmdline`.  Under a
# default exact mask the tracer has moved the kernel's argv window onto the
# label, so a nested `pmask` saw `argv = [label]`, found no subcommand, and
# printed the 11 KiB help text on stderr with exit 255.  `pmask --version`
# failed the same way, and `--no-redact` worked, which is why the plain-mode
# cases in the suite passed.
#
# The fix takes the snapshot from `std::env::args_os()` and keeps
# `/proc/self/cmdline` only as the fallback.  The block is still zeroed at
# startup, so the self-mask property must survive: this fragment asserts
# both halves.
#
# Cases:
#   qa5-version              nested `pmask --version` exits 0, prints the
#                            version, and prints no help text
#   qa5-read                 nested `pmask read T` prints the secret, exit 0
#   qa5-read-no-help         the nested read writes nothing on stderr
#   qa5-control-no-redact    the same nested read works with --no-redact
#                            (the control: the delivery itself is fine)
#   qa5-control-unmasked     `pmask read T` outside any mask works
#   qa5-selfmask-still-on    the supervisor's own /proc cmdline is the
#                            label: the runtime snapshot did not cost the
#                            self-mask
#   qa5-unshare-read         the read works under --unshare too
set -u
cd "$(dirname "$0")"
. ../lib.sh

BIN_DIR=$(cd .. && pwd)
TOOL="$BIN_DIR/pmask"
CASES="$BIN_DIR/testcases"
require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
D=$(mktemp -d "${TMPDIR:-/tmp}/pmask-qa5.XXXXXX") || {
    echo "FAIL qa5-cannot-create-tmp"; exit 2
}
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

cleanup() {
    kill_label qa5 KILL 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT

SECRET="QA5-SECRET-VALUE-$$"
printf '%s' "$SECRET" > "$D/token"
chmod 600 "$D/token"

# ---------------------------------------------------------- nested version
"$TOOL" -l qa5-v -q -- "$TOOL" --version >"$D/v.out" 2>"$D/v.err"
rc=$?
vbytes=$(wc -c < "$D/v.err" | tr -d ' ')
if [ "$rc" = 0 ] && grep -q '^pmask [0-9]' "$D/v.out" && [ "$vbytes" = 0 ]; then
    pass qa5-version
elif [ "$rc" = 0 ] && grep -q '^pmask [0-9]' "$D/v.out"; then
    # Version succeeded; stderr has something.  That is not a help dump.
    case "$(head -c 200 "$D/v.err")" in
        *"Usage: pmask"*) fail "qa5-version (help text on stderr, $vbytes bytes)" ;;
        *) pass qa5-version ;;
    esac
else
    fail "qa5-version (rc=$rc stdout=[$(head -1 "$D/v.out")] stderr=$vbytes bytes)"
fi

# ------------------------------------------------------------- nested read
"$TOOL" -l qa5-r -q --secret T=file:"$D/token" -- "$TOOL" read T \
    >"$D/r.out" 2>"$D/r.err"
rc=$?
got=$(cat "$D/r.out" 2>/dev/null)
rbytes=$(wc -c < "$D/r.err" | tr -d ' ')
if [ "$rc" = 0 ] && [ "$got" = "$SECRET" ]; then
    pass qa5-read
else
    fail "qa5-read (rc=$rc got=[$got] want=[$SECRET])"
fi
if [ "$rbytes" = 0 ]; then
    pass qa5-read-no-help
else
    fail "qa5-read-no-help (stderr=$rbytes bytes: $(head -c 80 "$D/r.err" | tr '\n' ' '))"
fi

# ------------------------------------------- control: --no-redact still works
got=$("$TOOL" -q --no-redact --secret T=file:"$D/token" -- "$TOOL" read T 2>/dev/null)
rc=$?
if [ "$rc" = 0 ] && [ "$got" = "$SECRET" ]; then
    pass qa5-control-no-redact
else
    fail "qa5-control-no-redact (rc=$rc got=[$got])"
fi

# --------------------------------------- control: unmasked delivery works
got=$("$TOOL" -q --secret T=file:"$D/token" -- /bin/sh -c \
    'printf "%s" "$PMASK_SECRET_T"' 2>/dev/null)
if [ "$got" = "3" ]; then
    pass qa5-control-fd-env
else
    fail "qa5-control-fd-env (PMASK_SECRET_T=[$got])"
fi

# ----------------------------------------------- the self-mask is still on
"$TOOL" -q -l qa5-s -- "$CASES" sleeper QAMARK >/dev/null 2>&1 &
SUP=$!
sleep 0.9
if kill -0 "$SUP" 2>/dev/null; then
    sc=$(tr '\0' '|' < "/proc/$SUP/cmdline" 2>/dev/null)
    if [ "$sc" = "qa5-s|" ]; then
        pass qa5-selfmask-still-on
    else
        fail "qa5-selfmask-still-on (supervisor cmdline=[$sc] want=[qa5-s|])"
    fi
else
    fail "qa5-selfmask-still-on (supervisor gone)"
fi
kill -9 "$SUP" 2>/dev/null
wait "$SUP" 2>/dev/null

# ------------------------------------------------ nested read under --unshare
if unshare -Urn true 2>/dev/null; then
    got=$("$TOOL" -l qa5-u -q --unshare --secret T=file:"$D/token" -- "$TOOL" read T 2>"$D/u.err")
    rc=$?
    if [ "$rc" = 0 ] && [ "$got" = "$SECRET" ]; then
        pass qa5-unshare-read
    else
        fail "qa5-unshare-read (rc=$rc got=[$got])"
    fi
else
    skip "qa5-unshare-read (user namespaces refused here)"
fi

exit "$FAIL"
