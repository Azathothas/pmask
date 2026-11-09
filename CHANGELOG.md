# Changes

Every commit on `qa/final` on top of `fa46e62`.

## Features and hardening

- feat: name the memfds behind --secret and --rexec (`812b15d`)
- feat: warn when a documented escape publishes a secret (`fcec4b0`)

## Fixes

- fix: report a memfd name that names nothing (`e852567`)
- fix: interrupt the seized master for the handshake (`d0cadd7`)
- fix: redirect rename to the mapped label, no write (`cd389fd`)
- fix: ignore a failed stdout write in audit rows (`9e1de9d`)
- fix: create memfd_secret with MFD_CLOEXEC (`8797876`)
- fix: snapshot argv from the runtime's own copy (`0b01a4f`)
- fix: reject LF and CR in --comm like the label (`35080b0`)
- fix: keep-env list overrides an earlier --keep-env (`9b3fe5f`)
- fix: warn when --detach releases a tracee untraced (`1063b67`)
- fix: name the tracer thread after the session label (`69cc3f8`)
- fix: warn that argv secrets reach the kernel audit log (`34b20e3`)
- fix: warn about the escapes only for a run that happens (`c9ed635`)

## Tests and gates

- test: report the launch-window spread instead of one sample (`fbc4666`)
- test: assert the tracer relation, not its old name (`7d12efc`)
- test: make every QA fragment clean up its own processes (`f1a3a3d`)
- test: cover the tracer name, end states, launch window and memory (`f0bd7e0`)
- test: cover the watch-rename filter row (`af95ff7`)
- test: cover the memfd name options (`20716d0`)
- test: drop the exit-0 claim from the 44 liveness row (`74fbe52`)
- test: correct the liveness comment in the 44 fragment (`720873b`)
- test: gate the audit checks on a host that can answer (`8031b41`)
- test: cover the mode table that does not redact (`74b7b6a`)
- test: measure the no-dumpable EACCES set with open (`8d1c552`)
- test: cover the argv-secret audit warning (`6a1ba77`)
- test: cover the self-mask, windows, environ and auxv channels (`0e5b064`)

## Documentation

- docs: record the hidden-pid detector measurements (`5f996f6`)
- docs: record the eBPF and connector refusals (`ca32ce6`)
- docs: record the issue 45 memfd-name evidence (`0022762`)
- docs: refresh the final fragment run (`8fd8074`)
- docs: correct the library test count and its baseline (`d4e2e0e`)
- docs: correct which process is the isolate namespace init (`66937c9`)
- docs: record the verification transcript and the fragment run (`6e05fa6`)
- docs: drop the duplicate auditctl capture (`bc75077`)
- docs: add the bteam3 evidence bundles (`9ca47ad`)
- docs: record the audit records and the rule forms that see them (`07d7cc8`)
- docs: record the refusal-before-warning ordering in the evidence (`26aeb7a`)
- docs: point every claim in the residue note at its source (`149ee7c`)
- docs: refresh the evidence logs and add the verification transcript (`a5c7708`)
- docs: measure the zero-argv startup window (`bc2888f`)
- docs: record the b-team 39-43 residue measurements (`bd8b77a`)

## Merges

- merge: bteam5 refresh (`4265298`)
- merge: bteam2 refresh (`68fab27`)
- merge: fix1 (`cb56f9e`)
- merge: bteam5 (`e8a8454`)
- merge: bteam2 (`f55ecc3`)
- merge: bteam3 (`b1ce019`)
- merge: bteam1 (`ef260ca`)

