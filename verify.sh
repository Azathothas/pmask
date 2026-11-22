#!/bin/sh
# Relocatable entry point for the project's own gate.
#
#   sh verify.sh          native gate
#   sh verify.sh --vm     native gate plus the pinned QEMU micro-VM gate
#
# The real script is scripts/verify.sh; this wrapper exists so an archive
# can be checked from its root without knowing the layout.
set -eu
cd "$(dirname "$0")"
exec sh scripts/verify.sh "$@"
