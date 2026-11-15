#!/bin/sh
# Issue 70: the report and audit are writable by the tree; the audit fd
# reason is name-keyed.
set -u
cd "$(dirname "$0")"
. ../lib.sh
BIN_DIR=$(cd .. && pwd); TOOL="$BIN_DIR/pmask"; CASES="$BIN_DIR/testcases"
require_bins || exit 2
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
T=$(mktemp -d "${TMPDIR:-/tmp}/qa70.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
"$TOOL" --report-file "$T/report.json" -q -l q70 -- /bin/sh -c '
  test -e '"$T"'/report.json && exit 9
  for f in /proc/$PPID/fd/*; do cat "$f" >/dev/null 2>&1 || continue; done
  exit 0' >/dev/null 2>&1; rc=$?
[ "$rc" = 0 ] && pass q70-report-absent-during-run || fail "q70-report-absent-during-run (rc=$rc)"
last=$(tr -d '\n' < "$T/report.json" 2>/dev/null | tail -c 1)
[ "$last" = "}" ] && pass q70-report-is-complete || fail "q70-report-is-complete"
# A report run waits for the tree unless the caller overrides the policy;
# an explicit override names what it costs instead of paying it silently.
out=$("$TOOL" --report-file "$T/detach.json" --on-exit detach -l q70 \
    -- "$CASES" sleeper 1 2>&1)
printf '%s' "$out" | grep -q 'on-exit detach lets a descendant outlive' \
    && pass q70-detach-warning \
    || fail "q70-detach-warning ($(printf '%s' "$out" | grep -i 'pmask:' | head -1))"

# The classifier must read what a descriptor *is*.  A delivered secret is
# a sealed memfd, and a name without "pmask" in it does not make it less
# of a live secret: the old rule matched that literal and missed this.
printf 'q70-secret\n' > "$T/secret"
out=$("$TOOL" -q --audit --secret TOK=file:"$T/secret" --secret-fd-name custom-name \
    -l q70 -- "$CASES" sleeper 1 2>&1)
row=$(printf '%s\n' "$out" | grep '^pmask audit: residue:' | head -n 1)
list=$(printf '%s' "$row" | sed -n 's/.*(\(.*\))$/\1/p')
case ",$list," in
    *,fd,*) pass q70-audit-fd-identity ;;
    *) fail "q70-audit-fd-identity (row: ${row:-none})" ;;
esac
printf '%s' "$row" | grep -q 'memfd:custom-name' \
    && pass q70-audit-fd-named-descriptor \
    || fail "q70-audit-fd-named-descriptor (row: ${row:-none})"

# The other direction: an inherited file whose path contains the program
# name is not residue.  The old rule called it one.
exec 9>"$T/pmask-looking-file"
out=$("$TOOL" -q --audit -l q70 -- "$CASES" sleeper 1 2>&1)
exec 9>&-
row=$(printf '%s\n' "$out" | grep '^pmask audit: residue:' | head -n 1)
list=$(printf '%s' "$row" | sed -n 's/.*(\(.*\))$/\1/p')
case ",$list," in
    *,fd,*) fail "q70-audit-plain-file-not-residue (row: ${row:-none})" ;;
    *) pass q70-audit-plain-file-not-residue ;;
esac
printf '%s' "$row" | grep -q 'pmask-looking-file' \
    && pass q70-audit-plain-file-visible \
    || fail "q70-audit-plain-file-visible (row: ${row:-none})"
echo "################ QA70: FAIL=$FAIL"
[ "$FAIL" = 0 ]
