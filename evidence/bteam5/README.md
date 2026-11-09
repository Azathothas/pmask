# bteam5 evidence: issues 45, 46, 57, 58

Worktree `/workspace/wt/bteam5`, branch `qa/bteam5`, based on `qa-base`
(`d2f331a`) plus the six commits listed in the final report.

Host for every measurement: Debian 13, kernel `6.12.113+deb13-amd64`,
x86_64, LXC container, uid 1000 with passwordless sudo.  ptrace and user
namespaces work; tracefs, eBPF and the process connector do not.

| directory | issue | research note | QA fragment |
| --- | --- | --- | --- |
| [`45/`](45/) | named kernel objects, `--secret-fd-name`, `--memfd-name` | none (code change) | `tests/qa.d/45.sh` |
| [`46/`](46/) | `--watch-rename`, `Seccomp_filters`, `NoNewPrivs` | none (measurement) | `tests/qa.d/46.sh` |
| [`57/`](57/) | eBPF sensors and the process connector | `docs/research/bteam-ebpf.md` | `tests/qa.d/57.sh` |
| [`58/`](58/) | the hidden-pid detector family | `docs/research/bteam-detectors.md` | `tests/qa.d/58.sh` |

`qa-final.log` is the last full `sh tests/qa.sh` run: four fragments,
`== QA: PASS`, no FAIL line.
