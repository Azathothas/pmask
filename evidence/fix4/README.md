# fix4 evidence — issues 25, 28, 31, 47

Host: LXC container, Debian, uid 1000. Native ptrace works; user
namespaces work. `HugePages_Total` is 0, so the hugetlb fallback is
reachable and its success arm is not.

| file | what it is |
|---|---|
| `gates.log` | `cargo fmt --check`, clippy `-D warnings`, `cargo test --lib` |
| `full-run.log` | `sh tests/run.sh`, `################ FINAL: ALL-PASS`, 533 PASS, 9 SKIP, 0 FAIL |
| `25/` | issue 25 raw commands, fragment log, negative control, README |
| `28/` | issue 28 raw commands, fragment log, negative control, README |
| `31/` | issue 31 raw command, fragment log, negative control, README |
| `47/` | issue 47 raw commands, fragment log, negative control, README |

Every negative control is the same fragment run against the pre-fix source
for that issue, rebuilt and installed at `tests/pmask`:
`git show <fix>^:src/<file>.rs`, `cargo build`, `sh tests/qa.d/<n>.sh`.
Each one fails exactly the cases the fix makes pass, and passes the
controls, so the assertions are not vacuous.
