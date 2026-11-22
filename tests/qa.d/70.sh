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
  # Check supervisor fd table isolation: a report run marks the supervisor
  # non-dumpable (PR_SET_DUMPABLE=0), so a non-root payload must see n=0
  # readable descriptors under /proc/$PPID/fd, while root bypasses the
  # dumpable check and sees n>0.
  n=0
  for f in /proc/$PPID/fd/*; do [ -r "$f" ] && n=$((n + 1)); done
  if [ "$(id -u)" = 0 ]; then
      [ "$n" -gt 0 ] || exit 8
  else
      [ "$n" = 0 ] || exit 7
  fi
  exit 0' >/dev/null 2>&1; rc=$?
case "$rc" in
    0) pass q70-report-absent-during-run ;;
    7) fail "q70-report-absent-during-run (non-root payload read supervisor /proc/\$PPID/fd despite non-dumpable supervisor)" ;;
    8) fail "q70-report-absent-during-run (no descriptor of the supervisor was readable as root)" ;;
    9) fail "q70-report-absent-during-run (the report existed during the run)" ;;
    *) fail "q70-report-absent-during-run (payload rc=$rc)" ;;
esac
last=$(tr -d '\n' < "$T/report.json" 2>/dev/null | tail -c 1)
[ "$last" = "}" ] && pass q70-report-is-complete || fail "q70-report-is-complete"
# A report run waits for the tree unless the caller overrides the policy;
# an explicit override names what it costs instead of paying it silently.
out=$("$TOOL" --report-file "$T/detach.json" --on-exit detach -l q70 \
    -- /bin/sh -c 'sleep 0.2' 2>&1)
printf '%s' "$out" | grep -q 'on-exit detach lets a descendant outlive' \
    && pass q70-detach-warning \
    || fail "q70-detach-warning ($(printf '%s' "$out" | grep -i 'pmask:' | head -1))"

# The classifier must read what a descriptor *is*, not what it is called.
# The detail row proves the descriptor was visible; the residue line proves
# how it was classified.  Both are needed, because a classifier that never
# sees a descriptor agrees with one that judges it correctly.
reasons() { printf '%s\n' "$1" | grep '^pmask audit: residue:' | head -n 1; }
fdlist() { printf '%s\n' "$1" | grep '^pmask audit: pid=' | head -n 1; }
list() { printf '%s' "$1" | sed -n 's/.*(\(.*\))$/\1/p' | tr -d ' '; }

# A descriptor to a deleted file is residue, whatever it is called.  The
# name here has nothing to do with the program, which is the case the old
# literal match on "pmask" missed.
exec 9>"$T/plain-name"
rm -f "$T/plain-name"
out=$("$TOOL" -q --audit -l q70 -- /bin/sh -c 'sleep 0.2' 2>&1)
exec 9>&-
det=$(fdlist "$out") ; row=$(reasons "$out") ; lst=$(list "$row")
printf '%s' "$det" | grep -q '9:.*(deleted)' \
    && pass q70-audit-deleted-fd-visible \
    || fail "q70-audit-deleted-fd-visible (detail: ${det:-none})"
case ",$lst," in
    *,fd,*) pass q70-audit-deleted-fd-is-residue ;;
    *) fail "q70-audit-deleted-fd-is-residue (row: ${row:-none})" ;;
esac

# The other direction: a live inherited file whose path contains the
# program name is not residue.  The old rule called it one.
exec 9>"$T/pmask-looking-file"
out=$("$TOOL" -q --audit -l q70 -- /bin/sh -c 'sleep 0.2' 2>&1)
exec 9>&-
det=$(fdlist "$out") ; row=$(reasons "$out") ; lst=$(list "$row")
printf '%s' "$det" | grep -q '9:.*pmask-looking-file' \
    && pass q70-audit-live-file-visible \
    || fail "q70-audit-live-file-visible (detail: ${det:-none})"
case ",$lst," in
    *,fd,*) fail "q70-audit-live-file-not-residue (row: ${row:-none})" ;;
    *) pass q70-audit-live-file-not-residue ;;
esac
echo "################ QA70: FAIL=$FAIL"
[ "$FAIL" = 0 ]
