#!/bin/sh
# Verify a checkout of this work without an absolute path, a fixed home,
# or a fixed install prefix.  The script changes to the repository root,
# so it runs from any directory:
#
#   sh scripts/verify.sh          native gate
#   sh scripts/verify.sh --vm     native gate plus the pinned QEMU micro-VM gate
#
# Exit 0 only when every requested gate prints a pass.
set -eu
cd "$(dirname "$0")/.."

VM=0
case "${1:-}" in
    "") ;;
    --vm) VM=1 ;;
    -h|--help) sed -n '2,/^set -eu/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "usage: sh scripts/verify.sh [--vm]" >&2; exit 2 ;;
esac

if ! command -v cargo >/dev/null 2>&1; then
    if [ -x /usr/local/cargo/bin/cargo ]; then
        PATH="$PATH:/usr/local/cargo/bin"
        export PATH
    else
        echo "missing: cargo" >&2
        exit 2
    fi
fi

echo "== rustc"; rustc --version
echo "== build"
cargo build --locked --release --bins --features testbins

echo "== library tests"
cargo test --locked --lib

echo "== format"
if cargo fmt --version >/dev/null 2>&1; then
    cargo fmt --all -- --check
else
    echo "SKIP format (rustfmt not installed)"
fi

echo "== clippy"
if cargo clippy --version >/dev/null 2>&1; then
    cargo clippy --locked --all-targets --features testbins -- -D warnings
else
    echo "SKIP clippy (clippy not installed)"
fi

echo "== rename guard"
sh scripts/check-rename.sh

echo "== notices"
python3 scripts/notices.py --check

echo "== manifest and unit lint"
if command -v mandoc >/dev/null 2>&1; then
    mandoc -T lint -W error man/pmask.1 man/pmaskd.8
else
    echo "SKIP mandoc (not installed)"
fi

echo "== native gate"
sh tests/run.sh

if [ "$VM" = 1 ]; then
    echo "== micro-VM gate"
    sh vm/run.sh
fi

echo "VERIFY: PASS"
