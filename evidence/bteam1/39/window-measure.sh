#!/bin/sh
# The supervisor's own cmdline during a blocking `stdin:` secret.
# `load` for stdin: blocks until the writer closes, so every sample lands
# while the supervisor is still deciding, which is the widest window the
# two modes can be compared in.
#
# Run from the crate root: sh evidence/bteam1/39/window-measure.sh
set -u
PM=./target/release/pmask
TC=./target/release/pmask-testcases
D=$(mktemp -d); mkfifo "$D/fifo"
run() {
  tag=$1; shift
  ( exec 3>"$D/fifo"; sleep 2.0; printf 's3cr3t\n' >&3; exec 3>&- ) &
  w=$!
  env "$@" "$PM" -q -l wtest --secret T=stdin --secret U=literal:CANARY-LITERAL -- "$TC" sleeper M <"$D/fifo" &
  s=$!
  i=0; seen=0; tot=0
  while [ $i -lt 40 ]; do
    sleep 0.025
    line=$(tr '\0' '|' < /proc/$s/cmdline 2>/dev/null)
    tot=$((tot+1))
    case "$line" in *CANARY-LITERAL*) seen=$((seen+1));; esac
    i=$((i+1))
  done
  echo "$tag: samples=$tot with_canary=$seen last=[$(tr '\0' '|' < /proc/$s/cmdline 2>/dev/null)]"
  kill $s $w 2>/dev/null; wait $s 2>/dev/null; wait $w 2>/dev/null
}
run "selfmask-on"
run "NO_SELFMASK" PMASK_NO_SELFMASK=1
rm -rf "$D"
