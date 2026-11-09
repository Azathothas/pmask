# Research

The measurement and comparison material behind the design. Every file
that quotes a number states the host, the kernel, the uid and the command
that produced it. A number without those conditions is not a claim.

| file | answers |
|---|---|
| [`detection-measured.md`](detection-measured.md) | the measurement harness and the table: plain, in-place fill, relocated window, proctitle byte |
| [`detection-residue.md`](detection-residue.md) | one row per interface that still tells the truth, with the condition that reveals it |
| [`detection-techniques.md`](detection-techniques.md) | MITRE T1036.011 and DET0164, Chromium's last-byte trick, what a consistency check can prove |
| [`detection-tools.md`](detection-tools.md) | what the sweep tools actually compare, and the published detection rates |
| [`MICROVM-GAP.md`](MICROVM-GAP.md) | the per-interface gap table, what a separate kernel would buy, and what it costs |
| [`MICROVM-probes/`](MICROVM-probes/) | reproduces every number in `MICROVM-GAP.md` |
| [`selfmask-window/`](selfmask-window/) | the self-mask window harness; its figures are in `detection-measured.md` |
| [`survey-2025/`](survey-2025/) | the 2025-2026 field survey: queries, replay script, triage ledger, review data |
| [`bteam-39-43.md`](bteam-39-43.md) | issues 39 to 43: the supervisor's own entry, the window arithmetic, `environ` shapes, the label and `exe` split, `AT_EXECFN` |
| [`bteam-38-50.md`](bteam-38-50.md) | issues 38, 47, 48 and 50: the tracer thread, end states, the launch window, payload memory |
| [`bteam-audit.md`](bteam-audit.md) | issues 44, 49, 56 and 59: `--no-dumpable`, the non-redacting modes, the audit record, the supervisor's literal secret |
| [`bteam-records.md`](bteam-records.md) | issues 51 to 55: daemon discovery, the daemon tree, refusals, the on-disk footprint, out-of-tree records |
| [`bteam-ebpf.md`](bteam-ebpf.md) | issues 45, 46 and 57: named kernel objects, the rename filter, eBPF and the process connector |
| [`bteam-detectors.md`](bteam-detectors.md) | issue 58: the rootkit, hidden-pid and sweeper family measured against the release |

The survey is a comparison of prior art, not a claim about this tree.
The measurement harnesses in `measurements/` are separate: they compare
`pmask` against zapper and measure its speed on the host that runs them.
