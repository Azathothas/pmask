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
| [`bteam-39-43.md`](bteam-39-43.md) | issues 39 to 43: the supervisor's own entry, the window arithmetic, environ shapes, the label/exe split and `AT_EXECFN`, measured against this release |
| [`bteam-38-50.md`](bteam-38-50.md) | issues 38, 47, 48 and 50: the tracer thread, the end states, the launch window and the payload-memory channel |
| [`bteam-audit.md`](bteam-audit.md) | issues 44, 49, 56 and 59: the kernel audit records a launch leaves, and the rule forms that do and do not see them |
| [`bteam-records.md`](bteam-records.md) | issues 51 to 55: the records outside the masked tree: report, audit, daemon log, `sudo`, shell history, systemd scope, `probe`/`doctor` |
| [`bteam-ebpf.md`](bteam-ebpf.md) | issues 45, 46 and 57: eBPF sensors and the process connector: what each sees of a masked exec |
| [`bteam-detectors.md`](bteam-detectors.md) | issue 58: the hidden-pid detector family, measured, and the content rules that do fire |

The survey is a comparison of prior art, not a claim about this tree.
The measurement harnesses in `measurements/` are separate: they compare
`pmask` against zapper and measure its speed on the host that runs them.
