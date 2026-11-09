# Issue 54 evidence: on-disk footprint and the release binary fingerprint

Date: 2026-11-09T11:03:18Z  host: Linux 6.12.113+deb13-amd64 x86_64  uid: 1000

## 1. `scripts/check-artifacts.sh`

```
pmask on-disk footprint
  uid=1000 host=Linux 6.12.113+deb13-amd64 date=2026-11-09T11:00:51Z

store
  source                     pmask store path
  path                       /state/kage/pmask/store.enc
  mode size                  absent absent
  magic                      no file, so nothing to read
  directory mode             absent
  lock mode size             absent absent

sockets
  daemon default             /run/user/1000/pmask.sock
  daemon as root             /run/pmask.sock
  agent                      --socket PATH, default /run/user/1000/pmask.sock
  present                    /run/user/1000 does not exist
  /proc/net/unix             no pmask entry

live memfd names
  present                    none (no live pmask session of uid 1000)

exec-once carrier
  present                    none (transient: only a live session has one)

packaging
  tmpfiles                   contrib/tmpfiles.d/pmask.conf
    'd' lines                1
    'f' lines                0
    'w' lines                0
    verdict                  no f line; store init creates the file itself
  sysusers                   contrib/sysusers.d/pmask.conf
    creates                  u pmask - "pmask secret holder" /var/lib/pmask 

release binary fingerprint
  target/x86_64-unknown-linux-musl/release/pmask
    mode size                755 1132808
    elf type                 DYN (Position-Independent Executable file)
    linkage                  static
    .comment                 present
      contents               rustc version 1.99.1 (58cf8f9c3 2026-10-13);Linker: LLD 23.1.1 (/checkout/src/llvm-project/llvm 1b9c0d5ff9bbe7634aead059efe6b11a7eeba145);GCC: (GNU) 9.4.0
    build id                 absent
    pmask strings            5 of 6 (a YARA rule needs 3 plus the .comment)
  target/x86_64-unknown-linux-musl/release/pmaskd
    mode size                755 749320
    elf type                 DYN (Position-Independent Executable file)
    linkage                  static
    .comment                 present
      contents               rustc version 1.99.1 (58cf8f9c3 2026-10-13);Linker: LLD 23.1.1 (/checkout/src/llvm-project/llvm 1b9c0d5ff9bbe7634aead059efe6b11a7eeba145);GCC: (GNU) 9.4.0
    build id                 absent
    pmask strings            2 of 6 (a YARA rule needs 3 plus the .comment)
  target/release/pmask
    mode size                755 1031648
    elf type                 DYN (Position-Independent Executable file)
    linkage                  dynamic
    .comment                 present
      contents               GCC: (Debian 14.2.0-19) 14.2.0;rustc version 1.99.1 (58cf8f9c3 2026-10-13);Linker: LLD 23.1.1 (/checkout/src/llvm-project/llvm 1b9c0d5ff9bbe7634aead059efe6b11a7eeba145)
    build id                 present
    pmask strings            5 of 6 (a YARA rule needs 3 plus the .comment)
  target/release/pmaskd
    mode size                755 648728
    elf type                 DYN (Position-Independent Executable file)
    linkage                  dynamic
    .comment                 present
      contents               GCC: (Debian 14.2.0-19) 14.2.0;rustc version 1.99.1 (58cf8f9c3 2026-10-13);Linker: LLD 23.1.1 (/checkout/src/llvm-project/llvm 1b9c0d5ff9bbe7634aead059efe6b11a7eeba145)
    build id                 present
    pmask strings            2 of 6 (a YARA rule needs 3 plus the .comment)

== ARTIFACTS: report complete ==
[exit 0]
```

## 2. The release binary fingerprint: is stripping `.comment` feasible?

The release build is `cargo build --release --target <musl>` with
`[profile.release] strip = true, lto = true, codegen-units = 1, panic = "abort"`.

### 2a. What the shipped build carries

```
$ readelf -p .comment target/x86_64-unknown-linux-musl/release/pmask

String dump of section '.comment':
  [     1]  rustc version 1.99.1 (58cf8f9c3 2026-10-13)
  [    2d]  Linker: LLD 23.1.1 (/checkout/src/llvm-project/llvm 1b9c0d5ff9bbe7634aead059efe6b11a7eeba145)
  [    8b]  GCC: (GNU) 9.4.0


$ readelf -n target/x86_64-unknown-linux-musl/release/pmask   # build id

$ readelf -d ... | grep NEEDED    # static?
0
(0 = static)

$ file ...
target/x86_64-unknown-linux-musl/release/pmask: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, stripped
```

### 2b. Attempted build settings (all rejected)

```
$ RUSTFLAGS="-C link-arg=-Wl,--discard-section=.comment" cargo build ...
rust-lld: error: unknown argument '-Wl,--discard-section=.comment'

$ RUSTFLAGS="-C link-arg=--discard-section=.comment" cargo build ...
rust-lld: error: unknown argument '--discard-section=.comment'

$ ld.lld --help | grep -i discard
  --discard-all           Delete all local symbols
  --discard-locals        Delete temporary local symbols
  --discard-none          Keep all symbols in the symbol table
(no --discard-section; LLD can drop symbols, not a named non-alloc section)

$ cargo + rustc: no [profile] key removes .comment
  strip = "symbols"  -> --strip-all at link; .comment survives (measured below)
  strip = "debuginfo" -> debug sections only
```

Proof that the already-configured `strip = true` does not remove it:

```
$ strip --strip-all /tmp/p2; readelf -S /tmp/p2 | grep -c comment
1
(1 = still present: GNU strip keeps .comment by default)
```

### 2c. What a post-link `objcopy` would do (measured, not shipped)

```
$ cp pmask /tmp/strip-pmask; objcopy --remove-section=.comment /tmp/strip-pmask
$ readelf -p .comment /tmp/strip-pmask
readelf: Warning: Section '.comment' was not dumped because it does not exist

$ sh scripts/check-static.sh /tmp/strip-pmask /tmp/strip-pmaskd
/tmp/strip-pmask: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, stripped
/tmp/strip-pmaskd: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, stripped
[exit 0]

$ /tmp/strip-pmask --version
pmask 0.1.0-beta.1 (unknown)
$ /tmp/strip-pmask probe | head -2
pmask capability report
  arch=x86_64 kernel=6.12.113+deb13-amd64 tier=redact+isolate+secret-mem

$ stat -c "%s %n" pmask strip-pmask
1132808 target/x86_64-unknown-linux-musl/release/pmask
1132568 /tmp/strip-pmask

$ strings /tmp/strip-pmask | grep -c "rustc version"
0
(0 = the toolchain strings are gone)

$ strings /tmp/strip-pmask | grep -cE "PMASKSTORE1|pmask capability report|pmask-secret"
3
(the pmask strings remain: a YARA rule keyed on them still matches)

$ sha256sum of two independent objcopy runs (reproducible?)
7d7b6f9f4ab205f1cbbaa1cd1d6b8679ffd3eb17cb8111c62cacb4f258a04694  /tmp/p1
7d7b6f9f4ab205f1cbbaa1cd1d6b8679ffd3eb17cb8111c62cacb4f258a04694  /tmp/p4
7d7b6f9f4ab205f1cbbaa1cd1d6b8679ffd3eb17cb8111c62cacb4f258a04694  /tmp/r1
7d7b6f9f4ab205f1cbbaa1cd1d6b8679ffd3eb17cb8111c62cacb4f258a04694  /tmp/r2
```

### 2d. Verdict: a packaging limit, not a build setting

No build setting removes `.comment` with this toolchain. rust-lld has no
`--discard-section` (both spellings are rejected, 2b), `[profile.release]`
has only `strip = "symbols"`/`"debuginfo"` and neither drops it (2b), and
GNU `strip --strip-all` keeps it (2b).

A **post-link** `objcopy --remove-section=.comment` does work and is
reproducible (identical sha256 across four runs, 2c), keeps the binary
static-pie and runnable, and takes 240 bytes off `pmask`. It is not a build
setting: it has to run after `cargo build`, on both the x86-64 and the
aarch64 runner, before `scripts/check-static.sh` and the version check, and
it changes the artefact the attestation covers. That is a release-workflow
change, which this issue did not ask for and which the task explicitly
limits. **The release workflow is therefore unchanged.** This is the
packaging limit:

- every release binary names `rustc 1.99.1` and `Linker: LLD 23.1.1` in
  `.comment`, so a YARA rule keyed on those two strings matches it;
- removing `.comment` removes those two strings but leaves the pmask
  strings (`PMASKSTORE1`, `pmask capability report`, `pmask-secret`, ...),
  so a rule that keys on three pmask strings still matches. The
  fingerprint gets more expensive, not impossible;
- the safe follow-up, if the maintainers want it, is one step in
  `release.yml` after the build and before `check-static.sh`:
  `objcopy --remove-section=.comment dist/pmask-$target dist/pmaskd-$target`.
  It must run on both matrix legs, and `check-static.sh` must run after it
  (it passes either way, measured in 2c).

The instrument for re-measuring this is `scripts/check-artifacts.sh BINARY`,
which prints the `.comment` contents, the build id, the linkage and the
pmask-string count for each binary it is given.
