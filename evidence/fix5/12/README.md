# Issue 12 evidence: isolation/compare/conformance never ran in CI

Date: 2026-11-09T10:18:35Z  host: Linux 6.12.113+deb13-amd64 x86_64  uid: 1000

## 1. The gap, from the workflow as committed at HEAD

```
$ grep -n "isolation\|compare\|conformance" .github/workflows/ci.yml
```
(no match: none of the three is named by any job)

vm/common.sh stages:
143:# SKIP with a reason for every suite that is not staged.  The native gate
144:# runs sixteen; the seven not staged here are store, isolation, lease,
149:# vm_stage STAGE-DIR
151:vm_stage() {
182:# vm_pack STAGE-DIR OUT.cpio.gz

## 2. The new CI job

`.github/workflows/ci.yml`, job `native-suites` (ubuntu-24.04, 30 min):

- installs `python3` and `build-essential` explicitly, so a future image
  change cannot silently turn `isolation.sh` i32-i36 or `conformance.sh`'s
  six compiler cases into SKIPs;
- sets `kernel.yama.ptrace_scope=0` and, where the sysctl exists,
  `kernel.apparmor_restrict_unprivileged_userns=0` /
  `kernel.unprivileged_userns_clone=0`;
- runs as the runner uid (no `sudo` for the suites themselves), because the
  same-uid refusal cases are what the suite is for and root with
  `CAP_SYS_PTRACE` defeats them by design (issue #35);
- runs `sh tests/native-suites.sh isolation compare conformance`, which
  turns an absent suite into a FAIL (see §3);
- fails the job when `isolation.sh` printed `SKIP i0-isolation-available`,
  so a runner without user namespaces cannot report zero coverage as a
  pass;
- runs `sh tests/qa.sh` so the per-issue fragments run in CI.

The VM job (`suites-in-vm`) is unchanged and still runs `vm/run.sh` with
its nine staged suites. The `all` aggregator now needs `native-suites`.

Environment this job needs, stated here because it is a CI contract:
ubuntu-24.04, a normal (non-root) runner uid, `ptrace` allowed for that
uid, unprivileged user namespaces allowed, `python3`, and a C compiler
(`cc`). `sudo` is used only for `apt-get` and `sysctl`.

## 3. Commands and verdicts (this host, uid 1000)

`sh tests/native-suites.sh isolation compare conformance` is the CI
command. Suites were run here in two pairs to keep the output readable:

| command | exit | verdict line |
| --- | --- | --- |
| `sh tests/native-suites.sh isolation` | 0 | `################ NATIVE: ALL-PASS ran=1 missing=0`; isolation itself `== VERDICT: FAIL=0 ==`, zero SKIPs |
| `sh tests/native-suites.sh compare conformance` | 0 | `COMPARE: OK`; `CONFORMANCE: PASS pass=21 fail=0 skip=3`; the 3 SKIPs are `observer-other-uid`, `observer-root`, `observer-kernel`, all root-or-kernel-only rows |
| `sh tests/native-suites.sh isolation no-such-suite` | 1 | `FAIL no-such-suite (tests/no-such-suite.sh is absent; a missing suite is a failure in this gate)` and `################ NATIVE: FAILURES ran=1 missing=1` |

The missing-suite run is the control: the named-but-absent suite is a
FAIL, not the `SKIP <suite> (absent)` that `tests/run.sh` prints for the
micro-VM. `isolation.sh` still ran and passed inside that run, so the
exit 1 comes from the absent suite alone.

The compiler cases are not vacuous on this host: `conformance.sh` printed
`PASS core-limit-control`, `PASS secret-fd-is-memfd fd=3 seals=15` and
`PASS secret-fd-control seals=[-1]`, which are the six cases that SKIP
without `cc`. `isolation.sh` printed no SKIP at all.

Raw logs: `isolation.log`, `compare-conformance.log`,
`missing-suite-control.log`.

## 4. Deferred

The VM job's staged set is unchanged (nine suites). Staging `isolation`,
`compare` and `conformance` into the initramfs would need a python3 and a
C compiler in the guest, which is a change to `vm/` and not to this
issue; the new native job covers them instead.
