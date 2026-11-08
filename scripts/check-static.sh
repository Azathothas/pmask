#!/bin/sh
# Assert that each argument is a static Linux binary.
set -eu
[ "$#" -gt 0 ] || { echo "usage: $0 BINARY..." >&2; exit 2; }
for b in "$@"; do
    [ -f "$b" ] || { echo "missing: $b" >&2; exit 1; }
    if readelf -d "$b" | grep -q NEEDED; then
        echo "$b: dynamic dependencies" >&2
        readelf -d "$b" >&2
        exit 1
    fi
    if readelf -l "$b" | grep -q INTERP; then
        echo "$b: asks for a program interpreter" >&2
        exit 1
    fi
    file "$b"
done
