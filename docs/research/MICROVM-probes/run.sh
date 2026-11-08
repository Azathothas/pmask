#!/bin/sh
# reproducible: yes (this script produces docs/research/MICROVM-probes/run.out)
# Reproduce every number in docs/research/MICROVM-GAP.md.
#
# It prints the host conditions, runs the interface probe twice (plain
# sibling, then a pmask masked sibling), and boots a micro-VM twice
# under KVM and once under TCG.  It touches nothing in the repository
# and needs no network.  Safe to run twice: every subject it starts is
# killed before the script exits, and the micro-VM it builds lives in a
# temporary directory.
#
# Exit status is 0 when the run completed, even where a probe was
# refused: a refusal is a result, not a failure.

set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "=== host conditions"
echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
uname -a
echo "uid=$(id -u) gid=$(id -g) caps=$(awk '/^CapEff/{print $2}' /proc/self/status)"
echo "seccomp=$(awk '/^Seccomp/{print $2}' /proc/self/status)"
echo "yama.ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo unreadable)"
echo "vm.memfd_noexec=$(cat /proc/sys/vm/memfd_noexec 2>/dev/null || echo unreadable)"
echo "qemu=$(command -v qemu-system-x86_64 || echo absent) $(qemu-system-x86_64 --version 2>/dev/null | head -1)"
echo "kvm=$(test -r /dev/kvm && echo usable || echo unusable)"

echo
echo "=== interface probe (uid $(id -u), no capabilities)"
PMASK_BIN="$repo/target/release/pmask" python3 "$here/probe.py"

echo
echo "=== micro-VM boot to a shell"
kernel="$repo/vm/cache/kernel-x86_64-linux-virt-6.12.115-r0/boot/vmlinuz-virt"
busybox="$repo/vm/cache/busybox-x86_64-busybox-static-1.37.0-r20/bin/busybox.static"
if [ ! -f "$kernel" ] || [ ! -f "$busybox" ]; then
    echo "SKIP: the pinned kernel or busybox is not in vm/cache"
    exit 0
fi

mkdir -p "$work/root/bin"
cp "$busybox" "$work/root/bin/busybox"
cat >"$work/root/init" <<'INIT'
#!/bin/busybox sh
/bin/busybox mkdir -p /proc /sys /dev
/bin/busybox mount -t proc proc /proc
/bin/busybox --install -s /bin 2>/dev/null
echo MICROVM-BOOT-OK kernel=$(uname -r) arch=$(uname -m)
poweroff -f
INIT
chmod +x "$work/root/init"
(cd "$work/root" && find . | cpio -o -H newc 2>/dev/null | gzip -9 >"$work/mini.cpio.gz")
echo "initramfs=$(wc -c <"$work/mini.cpio.gz") bytes, kernel=$(wc -c <"$kernel") bytes"

for accel in kvm tcg; do
    cpu=host
    [ "$accel" = tcg ] && cpu=max
    for run in 1 2; do
        start=$(date +%s%N)
        timeout 120 qemu-system-x86_64 -m 256 -smp 1 -accel "$accel" -cpu "$cpu" \
            -kernel "$kernel" -initrd "$work/mini.cpio.gz" \
            -append "console=ttyS0 rdinit=/init quiet" \
            -nographic -no-reboot -monitor none >"$work/boot-$accel-$run.log" 2>&1
        rc=$?
        end=$(date +%s%N)
        marker=$(grep -ac MICROVM-BOOT-OK "$work/boot-$accel-$run.log" || true)
        echo "boot accel=$accel run=$run rc=$rc ms=$(( (end - start) / 1000000 )) marker=$marker"
    done
done

echo
echo "=== done"
exit 0
