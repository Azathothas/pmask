# Documentation

| file | answers |
|---|---|
| [`../README.md`](../README.md) | what pmask is, how to install it, how to use it, and its honest limits |
| [`DESIGN.md`](DESIGN.md) | the mechanism: exec-entry swap, window relocation, daemon protocol, failure modes |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | one row per claim, the mechanism behind it, and the test that catches a regression |
| [`DEPLOY.md`](DEPLOY.md) | the three deployment shapes and the row each one closes |
| [`COMMENT-AUDIT.md`](COMMENT-AUDIT.md) | the source comments the fix branches corrected, and the replacement each got |
| [`ISSUE-CLOSURE.md`](ISSUE-CLOSURE.md) | one row per issue: its fix commit, the test that would fail if the behaviour changed, and the evidence directory |
| [`research/README.md`](research/README.md) | the measurements, the detection residue, the b-team channel studies, and the field survey |
| [`releases/`](releases/) | release notes, one file per tag |

The README is the contract. A claim in any other document that the code
does not support is a bug; report it against the mechanism and the test
that should have caught it.
