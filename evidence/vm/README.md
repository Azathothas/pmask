# Pinned-kernel VM gate

Date: 2026-11-11, read from the evaluation host.
Guest kernel: `6.12.115-0-virt` (the project's pinned `linux-virt`).
Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86_64, QEMU/KVM.
Harness: `vm/run.sh`, the project's own micro-VM.
Result: `VM-HARNESS: ALL-PASS (root and non-root)`.

The log is `vm-gate.log`.  The rows that changed in beta.5:

- `k4-32bit-refused-by-default`: the 32-bit image is refused before it
  runs, with exit 137 and a warning.
- `k4-32bit-allow-foreign-runs`: `--allow-foreign` runs the 32-bit image
  unredacted and the summary names `foreign-arch`.
- `k15-window-kept`: the `--no-exact` window is the label padded with
  spaces and one NUL, and `environ` is a 13-byte decoy, not a NUL block.
- `k12-control-std-args-read-the-kernel-block`: the control for the
  `std::env::args()` contract.

The VM stages a subset of the shell suites; the native `verify.sh` runs
the full set.  The VM result is the kernel-side proof, not a replacement
for the native gate.
