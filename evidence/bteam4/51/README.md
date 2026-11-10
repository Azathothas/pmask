# Issue 51 evidence

Two logs, in the order they were taken.

- `qa51.log` is the fragment's first run, before the two rows it failed
  were fixed. `51-socket-name-in-ss-x` failed because plain `ss -x`
  prints connected sockets only, so the fragment now asks for the
  listening table (`ss -xl`, then `ss -x state listening`).
  `51-root-daemon-start` failed because the root daemon was started
  without the socket directory the fragment then looked in. Both are
  defects in the fragment, not in `pmaskd`; the fragment at this tag
  carries the fixes. The `VERDICT: FAIL=2` line is that first run.
- `ping-two-uids.log` is the measurement the issue is about: one PING
  from uid 1000, which is neither the daemon's uid nor root, and one
  from root. The first gets `detail=reduced` with the protocol facts
  only; the second gets `detail=full` with the policy fields. Neither
  body carries an environment value.

The fragment's own verdict at this tag is in the gate log under
`evidence/fix5/`, where `tests/qa.sh` reports `passed=` and `skipped=`
for the whole batch.
