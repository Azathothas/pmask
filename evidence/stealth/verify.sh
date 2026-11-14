#!/bin/sh
# Re-run the regression fragments that prove the stealth changes.
#
# The fragments are the project's own gate pieces.  They need a built
# pmask and testcases binary, so run scripts/verify.sh or `cargo build
# --release` first.  The hidden-pid rows need root, setpriv and unshare;
# they SKIP when those are absent.
set -u
cd "$(dirname "$0")/../.." || exit 2
ROOT=$(pwd)
[ -x "$ROOT/target/release/pmask" ] || {
    echo "FATAL: build first (cargo build --release)" >&2
    exit 2
}
fail=0
for frag in 39 40 41 45 49 50 62; do
    f="$ROOT/tests/qa.d/$frag.sh"
    [ -f "$f" ] || { echo "SKIP $frag (fragment absent)"; continue; }
    echo "== qa.d/$frag.sh =="
    if ! sh "$f"; then
        fail=1
    fi
done
if [ -f "$ROOT/evidence/stealth/matrix.tsv" ]; then
    echo "== evidence/stealth/matrix.tsv =="
    awk -F'\t' 'NR==1 || $1=="M1" || $1=="M2" || $1=="M11" || $1=="M18" || $1=="M40" || $1=="C1" || $1=="C6" || $1=="C9" || $1=="C10"' \
        "$ROOT/evidence/stealth/matrix.tsv"
fi
[ "$fail" = 0 ] || exit 1
echo "STEALTH: OK"
exit 0
