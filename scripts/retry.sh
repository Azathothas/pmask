#!/bin/sh
# Run a command, retrying a network failure three times.
set -eu
if [ "$#" -eq 0 ]; then
    echo "usage: $0 COMMAND..." >&2
    exit 2
fi
n=0
while :; do
    if "$@"; then
        exit 0
    fi
    n=$((n + 1))
    if [ "$n" -ge 3 ]; then
        exit 1
    fi
    sleep "$((n * 10))"
done
