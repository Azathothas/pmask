#!/bin/sh
# Print the package version from Cargo.toml.
set -eu
cd "$(dirname "$0")/.."
python3 -I - <<'PY'
import tomllib
with open("Cargo.toml", "rb") as f:
    doc = tomllib.load(f)
print(doc["package"]["version"])
PY
