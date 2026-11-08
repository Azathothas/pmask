#!/bin/sh
# Fail if the old project name appears in the tree.
set -eu
cd "$(dirname "$0")/.."
if git grep -n -I -e confmask -e CONFMASK -e Confmask -- . ':!scripts/check-rename.sh'; then
    echo "the old project name is still in the tree" >&2
    exit 1
fi
