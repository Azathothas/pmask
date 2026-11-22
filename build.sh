#!/bin/sh
# Build pmask binaries anywhere this tree can sit.
#
# Dependencies are pinned by Cargo.lock. The first build reads crates.io;
# a later build with the same lock and a warm cargo cache needs no network.
# This script never assumes an absolute checkout path, a fixed home
# directory, or a fixed install prefix. It builds in this tree's own
# target/ directory, then copies the binaries the test suites use.
#
#   ./build.sh [--static] [--test]
#
# --static  Build static musl binaries (x86_64-unknown-linux-musl).
#           The default glibc build is dynamic and needs the host libc.
# --test    Run cargo test --lib and the unwrap audit.
#
# Manual install, for example:
#
#   install -m0755 target/release/pmask /usr/local/bin/
#   install -m0755 target/release/pmaskd /usr/local/bin/
#   install -m0644 man/pmask.1 /usr/local/share/man/man1/
#   install -m0644 man/pmaskd.8 /usr/local/share/man/man8/
#
# The systemd units under contrib/systemd/ use ExecStart=/usr/bin/pmask;
# for a user-local install, edit ExecStart to the installed path.
#
# Requires: Rust 1.87+ (rust-version in Cargo.toml), and for --static
# the musl target. See README.md Build for details.
set -eu
cd "$(dirname "$0")"

STATIC=0
TEST=0
for arg in "$@"; do
    case "$arg" in
        --static) STATIC=1 ;;
        --test) TEST=1 ;;
        -h|--help)
            sed -n '2,/^set -eu/p' "$0" | sed '$d'
            exit 0
            ;;
        *) echo "usage: $0 [--static] [--test]" >&2; exit 2 ;;
    esac
done

if [ "$STATIC" = 1 ]; then
    echo "building static (musl)"
    rustup target list --installed | grep -q '^x86_64-unknown-linux-musl$' \
        || rustup target add x86_64-unknown-linux-musl
    CARGO_TARGET_DIR="$PWD/target" cargo build --locked --release \
        --target x86_64-unknown-linux-musl --bins --features testbins
    OUT_DIR="$PWD/target/x86_64-unknown-linux-musl/release"
else
    echo "building (glibc)"
    cargo build --locked --release --bins --features testbins
    OUT_DIR="$PWD/target/release"
fi

# Copy bins to the test directory (idempotent, like tests/run.sh).
for b in pmask pmaskd pmask-testcases pmask-protocases; do
    if [ -x "$OUT_DIR/$b" ]; then
        dst=$(echo "$b" | sed 's/^pmask-testcases$/testcases/; s/^pmask-protocases$/protocases/')
        cp -p "$OUT_DIR/$b" "tests/$dst"
    fi
done

echo "ok: $OUT_DIR/pmask"

if [ "$TEST" = 1 ]; then
    cargo test --locked --lib
    python3 scripts/unwrap_audit.py
    echo "tests ok"
fi
