reproducible: no (source: the review rows under docs/research/survey-2025/review/, written 2026-11-03; the repositories are external)

# Review ledger: 84 rows, 43 kept

Review date: 2026-11-03. Ten reviewers took 8 or 9 repositories each and
judged every row against one question: what can pmask learn from it?
Access was the pkgforge proxy only. Source was read where the mechanism
mattered; the `evidence` column says what was actually read.

A removal is not a claim that the tool does nothing. It is a claim that
this row adds no surface, mechanism, failure mode or test that the kept
rows and pmask's own comparison do not already carry. Every removal is
recorded here with its reason so it can be reversed with evidence.

Counts: 43 kept, 15 duplicate removals, 26 slop or stub removals.

The full per-row notes, including the files read and the delta against
pmask, are in [`review/`](review/). The assignment split is
[`review/assignments.json`](review/assignments.json).

## Kept (34)

| repository | created | evidence | reason |
|---|---|---|---|
| `0xKirisame/SPiCa` | 2026-01-06 | source | A real kernel-anchored cross-view engine, source-verified to compare existence rather than metadata, usable as the external test pmask's detection doc lacks. |
| `Acceis/eBPF-hide-PID` | 2024-02-08 | source | Minimal, source-verified getdents64 buffer-rewrite technique with the per-observer notification detail, and it marks exactly where enumeration hiding stops. |
| `DataDog/rshell` | 2026-03-08 | source | Source-confirmed removal of the argv surface by a DataDog agent shell, the usable precedent the lane report already flags. |
| `Haind03/Exhume` | 2026-10-11 | source | Source-verified cross-view detector that gives pmask a concrete external regression test and shows which of its surfaces still score. |
| `Junximo/Ginhook_kpm` | 2026-03-07 | source | Distinct, source-verified DKOM primitive (pid_links unlink with an attach_pid restore) that no other row in the slice shows. |
| `Misskss/LinyuKernel` | 2026-05-20 | source | Source-verified LKM with two distinct hook surfaces (proc_pid_readdir actor swap, do_filp_open kretprobe) and the module self-hide pattern, all absent from the compared rows. |
| `Mymaqn/proc_mimicry` | 2024-01-24 | source | Names two concrete kernel mechanisms for the exe and maps surfaces that pmask reaches only partially through --rexec. |
| `NuoNb/LDKit` | 2026-02-23 | source | The one source-verified row showing the getenv-versus-/proc/environ split, with a README that overclaims what the code hides. |
| `OWLZOPS/owlzops-mapper` | 2026-06-21 | source | A real, source-verified scanner that reads exactly the two files pmask rewrites and can serve as an external before/after test. |
| `activex37b/LOLsp00f` | 2025-08-07 | source | Shows the creation-record versus later-read split and its detection residue, the property pmask's kernel-consistency claim depends on. |
| `afek854/argv_hider` | 2024-01-23 | source | Kept as the single representative of the LD_PRELOAD class: 45 lines, source read, and its residue (a live-stack cmdline with an unchanged arg_start/arg_end span) is the lesson. cli-interposer was removed as the same mechanism with its novel path compiled out. |
| `ags-slc/s2` | 2026-04-03 | source | A source-verified environment-injection tool whose residue is the precise surface pmask's environ relocation removes. |
| `aliyun/credagent` | 2026-07-22 | source | A real cmdline-attestation deployment plus a shipped tamper test that directly exercises pmask's surface and the TracerPid check that catches it. |
| `b1ackow1/FakeProcessNameDemo` | 2026-01-04 | source | A 2025+ unprivileged direct tool with readable source that demonstrates the residue pmask's exact mode is built to remove. |
| `basil9099/kdetect` | 2026-08-16 | source | A concrete cross-view detector design whose scoring and evidence discipline pmask can reuse, with the caveat that its own channels cannot see a redacted command line. |
| `bryanbhd/check-argv-secrets` | 2026-10-16 | source | The fixture corpus is a concrete external test input, though the scanner itself only greps source text. |
| `dedene/claw-wrap` | 2026-02-01 | readme | A real credential-proxy deployment that shows a policy gate and a trust-domain split pmaskd does not implement. |
| `dvarrazzo/py-setproctitle` | 2012-02-06 | source | Kept as the canonical in-process setproctitle implementation: upstream of PostgreSQL's ps_status, with SPT_NOENV as the explicit trade. smaugx, gspt and ghidearg were removed as the same trade with less evidence. |
| `emptymonkey/mimic` | 2014-04-24 | source | The closest pre-2025 ptrace ancestor, and the only row that shows the inverse ordering plus the main()-entry hand-off whose heuristic can abort, which is the case pmask's post-exec fallback covers. |
| `gershnik/processtitle` | 2026-03-08 | source | Source-verified PR_SET_MM_MAP use in a library, and it shows exactly which parts of the window a library leaves behind. |
| `hackerschoice/zapper` | 2023-09-08 | source | The only direct competitor with a measured comparison, and the code corrects the CSV's 'exec entry' mechanism in a way that sharpens pmask's ordering argument. |
| `joydle/agentjail` | 2026-04-08 | source | It shows the ordering and credential-proxy patterns that answer two limits pmask documents. |
| `lei33440/xboard-node-hidden-process` | 2026-06-07 | source | A real 2026 deployment that demonstrates precisely which surfaces exec -a leaves exposed, and the demand pmask answers. |
| `lthoangg/secretsh` | 2026-04-15 | readme | It states the argv exposure precisely and quantifies the trust assumption pmask's daemon makes about the client's command. |
| `maxvarm/memfd-process-hide` | 2023-08-27 | source | It is the measured auditd record for the exact memfd-exe surface --rexec claims, and it shows which parts of the command line survive it. |
| `monocursive/ukai` | 2026-08-31 | source | A source-verified ptrace supervisor whose stopped-exec re-read, race model and gap accounting are directly reusable, even though it redacts no metadata. |
| `nfsec/unhider` | 2025-10-20 | source | Small but precise: it demonstrates getdents64-versus-stat on /proc/<pid> with no framework around it, and that distinction is what pmask's honest limit rests on. |
| `pathtofile/commandline_cloaking` | 2021-11-27 | readme | It is the only row here that pairs argv cloaking with a kernel-side observer that can validate or refute pmask's kernel-consistency claim. |
| `phonginreallife/kernelseal` | 2025-06-23 | source | Verified BPF-LSM mechanism with the protect-before-release ordering and fail-closed mode the pmask doc already names as the environ upper bound, plus a concrete path the implementation misses. |
| `sleepunit-agents/loom-secrets` | 2026-10-24 | source | It enforces a specific no-argv contract and deliberately declines env injection after a real leak, which is the case pmask exists to make unnecessary. |
| `sylirre/fake-chroot-ng` | 2026-07-24 | source | It independently verifies the PR_SET_MM_MAP mechanism and its unprivileged precondition, and supplies a fallback for the CONFIG_CHECKPOINT_RESTORE-refused host pmask documents but does not handle. |
| `tallhatdoug/cli-spy` | 2026-08-18 | source | A verified detector for /proc/<pid>/cmdline and environ secrets that pmask can use as the negative-control regression test its README calls for. |
| `vtsingaras/setproctitle` | 2015-03-12 | source | A pre-2025 external ptrace writer absent from pmask's comparison that demonstrates the arg/env window boundary pmask relies on. |
| `waldh4ri/zygarde` | 2025-11-15 | source | Source-level detector that names two concrete pmask configurations it would flag, and confirms the exact window is not flagged. |

## Kept with a caveat (9)

| repository | created | evidence | reason |
|---|---|---|---|
| `Arsylk/gozinject` | 2026-05-22 | source | The clearest 2026 example of per-UID maps filtering and CoW page-accounting residue on the same same-uid boundary pmask defines, with the filter implementation unverified. |
| `Elixion-ai/claudepass` | 2026-09-09 | source | Documented, source-confirmed instance of the 2026 env-injection trade with the same-uid gap named, which makes it evidence for pmask's threat model rather than a mechanism to copy. |
| `Ozhiaki/fenn` | 2026-07-21 | source | Source-verified threat evidence that a careful 2026 secret-avoidance tool protects argv and leaves environ exposed. |
| `aimardcr/akane-injector` | 2026-05-30 | source | Root-only Android injector kept as the concrete per-reader-filter anti-pattern and memory-surface checklist, not as a mechanism pmask can adopt. |
| `mephistolist/Mao` | 2025-08-30 | readme | Adversary context with a concrete technique, patched detector binaries, that bounds what any PATH-resolved check can prove. |
| `momenbasel/quiet-operator` | 2026-05-31 | readme | Docs-only field manual, useful only as threat evidence and as a source of external detection invariants for label validation. |
| `reecdeep/hollowise` | 2025-02-20 | source | Relevant only as the Windows analogue of the cross-view residue pmask must avoid, and the kernel-side claim is inference from a PEB-only edit. |
| `royashbrook/hush` | 2026-06-18 | source | Threat evidence only: a verified no-get store whose env-var injection leaves the secret in /proc/<pid>/environ for same-uid readers. |
| `vvswift/blackbox-ave` | 2025-06-18 | source | The canonical LKM-hiding row, already the duplicate target for two other parts, kept only as threat context: it shows root-level PID hiding plus the audit and accounting suppression that pmask's root limit implies, and teaches no redaction mechanism. |

## Removed as duplicate (15)

| repository | created | evidence | reason |
|---|---|---|---|
| `Kaidstor/sec` | 2026-07-08 | readme | A mature but ordinary argv-avoidance secret store; same mechanism and lesson as ags-slc/s2's subprocess environment injection. Duplicate of `ags-slc/s2`. |
| `MatheuZSecurity/Singularity` | 2025-09-23 | readme | Same mechanism and lesson as vvswift/blackbox-ave's ftrace LKM hiding; the extra anti-forensics is root-only context the threat model already scopes out. Duplicate of `vvswift/blackbox-ave`. |
| `S4L1Mabd/Process_ARG_Spoofing` | 2024-10-30 | source | A two-string demo of the same PEB write, with less detail than the row it duplicates. Duplicate of `activex37b/LOLsp00f`. |
| `Tumlinh/cli-interposer` | 2018-01-28 | source | Same LD_PRELOAD argv-erasure mechanism as afek854/argv_hider, and its one novel ordering is disabled in the source that ships. Duplicate of `afek854/argv_hider`. |
| `Wcccc06/adf` | 2026-09-21 | description | An unbuilt reimplementation of the LinyuKernel row with the same Android anti-cheat hiding lesson. Duplicate of `Misskss/LinyuKernel`. |
| `erikdubbelboer/gspt` | 2013-09-21 | source | Same in-process argv rewrite and same title-length-versus-environment tradeoff as dvarrazzo/py-setproctitle, with no mechanism a ptrace supervisor can use. Duplicate of `dvarrazzo/py-setproctitle`. |
| `flashnuke/mod-rootkit` | 2025-03-12 | source | Same ftrace/getdents64 LKM hiding class as vvswift/blackbox-ave, with a cmdline-keyword trigger that teaches no mechanism pmask can adopt. Duplicate of `vvswift/blackbox-ave`. |
| `haolipeng/ebpfRootkit` | 2025-03-13 | source | Duplicate of `Acceis/eBPF-hide-PID` with only implementation-level extra detail. |
| `lezer0/smitty` | 2025-11-01 | source | Same LD_PRELOAD readdir hook and same lesson as rtvkiz/process-hider, with nothing added on the metadata surface. Duplicate of `NuoNb/LDKit`. |
| `mephistolist/hoxha` | 2025-05-31 | source | README and source both place it as the earlier, superseded version of mephistolist/Mao with no mechanism Mao lacks. Duplicate of `mephistolist/Mao`. |
| `moussahl/process-hiding-rootkit` | 2026-02-12 | readme | Same ftrace getdents hiding and lesson as flashnuke/mod-rootkit, differing only in the activation trigger. Duplicate of `vvswift/blackbox-ave`. |
| `rtvkiz/process-hider` | 2025-09-24 | source | A blog-derived teaching snippet that duplicates the LDKit readdir row and adds no surface. Duplicate of `NuoNb/LDKit`. |
| `scriptzteam/Hidden` | 2023-12-09 | source | A zapper derivative with the same ptrace stack and auxv rewrite; its one difference, the post-exec window, is already documented by pmask. Duplicate of `hackerschoice/zapper`. |
| `sitano/ghidearg` | 2015-08-20 | source | A thin Go in-place argv-value overwrite with the same lesson as the gspt row and no environ, comm or tree surface. Duplicate of `dvarrazzo/py-setproctitle`. |
| `smaugx/setproctitle` | 2020-10-28 | source | Same nginx-style environ relocation and same residue as dvarrazzo/py-setproctitle, plus an unrelated PR_SET_NAME demo; it adds no surface or mechanism pmask does not already implement. Duplicate of `dvarrazzo/py-setproctitle`. |

## Removed as slop or stub (26)

| repository | created | evidence | reason |
|---|---|---|---|
| `0xlane/cmd-spoofing` | 2023-02-13 | source | A 2023 Windows PEB tool whose only nuance, ETW-versus-PEB divergence, is context with no transferable Linux mechanism. |
| `10N351R/Phantomizer` | 2024-03-08 | source | Pre-2025 Windows educational tool whose length-field trick is the mechanism pmask already has, without its guarantees. |
| `Freaky/rust-proctitle` | 2019-04-25 | source | A comm-only PR_SET_NAME binding, unchanged since 2019-04-28, whose claimed argv mechanism does not exist in the tree. |
| `Idov31/Silverseal` | 2026-03-20 | source | The claimed rootkit is a hello-world stub, and a bootkit adds no lesson for an unprivileged metadata redactor. |
| `JKornev/hidden` | 2016-06-16 | readme | A Windows driver misclassified as a Linux LKM; it teaches nothing about Linux process metadata. |
| `JodisKripe/MasqueradeProcessName` | 2025-06-05 | source | Two-line README and a self-PEB demo; an abandoned WIP stub. |
| `K0rnhulio/ksu_hideproc` | 2025-04-19 | description | Empty repository with no readable files, so it cannot teach a mechanism or serve as threat evidence. |
| `LeGambiArt/arapuca` | 2026-04-11 | readme | A cross-platform sandbox with no process-metadata surface; it adds nothing to the argv/environ/comm comparison. |
| `Pizz33/Go_Processhider` | 2026-01-22 | readme | A Windows GUI-hiding demo with no Linux process-metadata lesson. |
| `Swayampadhy/TLS-ProcArgs-Spoofing` | 2025-11-13 | source | A single-file Windows PoC whose late userland PEB write is the failure mode pmask's exec-entry ordering already avoids. |
| `Winkmoon/Linux_rootkit` | 2025-09-05 | readme | Tutorial/demo LKM rootkit with no distinguishing mechanism and no bearing on unprivileged metadata redaction. |
| `buter-chkalova/project-rvbbit` | 2026-04-11 | source | Educational single-file LKM whose techniques pmask cannot use and the survey already covers. |
| `cagansv/process-ghost` | 2026-04-04 | source | Forty lines around mount --bind with no namespace, root-only and globally destructive, and it teaches nothing pmask's existing --unshare does not already do better. |
| `cc-Infiltration/SysHideTools` | 2025-08-15 | source | A demo GUI that sets one file attribute; there is no process mechanism to learn from or verify. |
| `finogeeks/finsafe` | 2026-05-08 | readme | Installer, packaging, policy examples and docs only, with no mechanism to verify. |
| `greenlight908/argv-guard` | 2026-09-11 | source | Static shell-script lint with no process or /proc surface, and its only lesson is already in pmask's README. |
| `iret77/givepw` | 2026-10-14 | source | A shell password prompt/storer with no argv, environ or comm mechanism; the argv exposure it avoids is already covered by stronger rows such as secretsh and cli-spy. |
| `kurowashi/pi-placeholder` | 2026-10-18 | source | A transcript-only placeholder plugin with no process surface; it teaches nothing about /proc and re-exposes the value to tool arguments by design. |
| `lbw1320028474/ProcessHiderGui` | 2025-09-23 | readme | Windows-only EPROCESS demo with no Linux process-metadata lesson. |
| `manuelpenazuniga/ClawCrate` | 2026-04-09 | source | Kernel-sandbox primitives pmask already implements, with no process-metadata surface and no mechanism it lacks. |
| `oh-az/NoArgs` | 2024-03-15 | readme | A 2024 Windows PEB/CreateProcessW demo with no Linux surface and no mechanism pmask's entry swap does not already do better. |
| `safe1024/apollolnk` | 2026-01-11 | readme | README-only Windows shortcut generator; there is no code and no Linux process-metadata mechanism to learn from. |
| `sysprog21/kbox` | 2026-03-17 | readme | An isolation substrate with no host-visible argv, environ or comm surface; a guest-side /proc does not redact the host's /proc. |
| `thalium/rkchk` | 2025-03-11 | readme | Root-only LKM detector on a surface pmask does not occupy, with no check or test that can observe a masked process. |
| `threatexpert/atrk-linux` | 2025-01-21 | source | A detector for the PID-enumeration surface pmask explicitly does not defend, with no content-level check to reuse. |
| `varungor365/phantom-lkm` | 2026-01-06 | source | Educational stub whose README overclaims what the code does and whose mechanism adds nothing to the hide group. |

## Corrections found during the review

These contradict the CSV, the report or a README. All were read from source
or from the file named; none was executed.

- `hackerschoice/zapper` stops at the exec **syscall exit**, not at exec entry. It copies the new stack, adjusts the argv/env/auxv pointers and zeroes the strings in place; it never moves `mm->arg_start`/`arg_end`.
- `vtsingaras/setproctitle` is a root-only `PTRACE_ATTACH`/`POKEDATA` writer on an arbitrary PID, not an in-process unprivileged library. `--force` deliberately spills into `environ`.
- `b1ackow1/FakeProcessNameDemo` zeroes the argv **and environ** span, not just `argv[0]`, and leaves `arg_start`/`arg_end` at the original extent.
- `dvarrazzo/py-setproctitle` has no `PR_SET_MM` call in its tree. The PR #110 claim about `PR_SET_MM_MAP` cannot be checked from the repository; `tools/prctl_demo.c` is a `PR_SET_NAME` demo.
- `tallhatdoug/cli-spy`'s README says 26 rules; `g_rules[]` in `cli-spy.c` has 30.
- `phonginreallife/kernelseal` resolves the target PID from the immediate parent dentry, so `/proc/<pid>/task/<tid>/environ` is compared as a tid against a map keyed by the tgid. Non-leader threads are missed. Source read, not run.
- `DataDog/rshell`'s code confirms its `ps` builtin never reads `/proc/<pid>/cmdline`; PR #269 itself could not be fetched through the proxy.
- `Arsylk/gozinject`'s per-UID `vma_hide` kernel module is not in the tree; only the client writes were verified.
- `Junximo/Ginhook_kpm` is a single-commit KPM drop with a 189-byte README, no SDK headers and a committed `.kpm`. The primitive is readable; the module is not buildable from the tree.
- `NuoNb/LDKit`'s `getenv` hook hides `LD_PRELOAD` from `getenv` but not from `environ` or `/proc/<pid>/environ`.

## Not established by this review

- No kept or removed tool was built or run. Every mechanism is read from source or README.
- A README that overclaims is recorded as a correction only where the source was read.
- The pre-review rows are recorded here and in `review/part-*.json`; the kept
  43 are in the lane CSV. Nothing was committed, so there is no earlier CSV
  revision to diff against.
