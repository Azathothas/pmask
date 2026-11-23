# Documentation

| file | contents |
|---|---|
| [`../README.md`](../README.md) | Overview, installation, usage, and security limits |
| [`PROFILES.md`](PROFILES.md) | Execution profiles (`auto`, `single`, `tree`, `tee`, `compat`), `EACCES` and `rexec` tradeoffs, `INV-1..INV-10` audit invariants, `pmask-profile/1` schema, and `psgen` integration |
| [`DESIGN.md`](DESIGN.md) | Architecture: exec-entry swap, window relocation, daemon protocol, failure modes |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | Per-claim security matrix, backing mechanisms, and regression tests |
| [`DEPLOY.md`](DEPLOY.md) | Three deployment shapes and the threats each shape closes |
| [`INTEGRATION.md`](INTEGRATION.md) | Binary and library contract, feature flags, and packaging |
| [`DETECTION-AUDIT.md`](DETECTION-AUDIT.md) | Detection-audit findings, fixes, tests, and evidence |
| [`REDTEAM-RESULTS.md`](REDTEAM-RESULTS.md) | Red-team campaign results across redaction, stealth, and secret delivery |
| [`COMPETITORS.md`](COMPETITORS.md) | Feature and boundary comparison against related tools |
| [`COMMENT-AUDIT.md`](COMMENT-AUDIT.md) | Source comments corrected during audit branches |
| [`ISSUE-CLOSURE.md`](ISSUE-CLOSURE.md) | Per-issue provenance ledger: fix commits, QA fragments, and evidence directories |
| [`research/README.md`](research/README.md) | Measurements, detection residue, b-team channel studies, and field survey |
| [`releases/v0.2.0.md`](releases/v0.2.0.md) | Release notes for `v0.2.0` |
| [`releases/v0.1.0.md`](releases/v0.1.0.md) | Release notes for `v0.1.0` |
| [`releases/`](releases/) | All release notes, one file per tag |

`README.md` is the user contract.
Any claim in another document that the code does not support is a bug.
Report mismatches against the mechanism and the test that should catch the regression.
