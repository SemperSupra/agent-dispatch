#!/usr/bin/env bash
# R52-C disposable real-Linux QEMU task; NOT real Wyse/KVM/Agent Dispatch.
set -Eeuo pipefail
umask 077

if [[ ${1:-} == --self-test ]]; then
 D=$(mktemp -d); trap 'rm -rf -- "$D"' EXIT
 expected=$(printf 'wyse-r51-canary-v1\n'|sha256sum|cut -d' ' -f1)
 [[ "$expected" == e990572be5fbb48fd706e5c3f612dd7c6e953c9b583919c3455f10c4f1845a8d ]] || exit 12
 printf 'wyse-r51-canary-v1 altered\n' | sha256sum | cut -d' ' -f1 | grep -Fxq "$expected" && { echo R53_C_MUTATED_PAYLOAD_HASH_ADMITTED=RED >&2; exit 13; }
 printf 'R52_C_GUEST_LINUX_STARTED=PASS\nR52_C_GUEST_RESULT_SHA256=%s\nR52_C_GUEST_CLEAN_EXIT=PASS\n' "$expected" > "$D/good"
 grep -Fxq 'R52_C_GUEST_LINUX_STARTED=PASS' "$D/good"
 grep -Fxq "R52_C_GUEST_RESULT_SHA256=$expected" "$D/good"
 grep -Fxq 'R52_C_GUEST_CLEAN_EXIT=PASS' "$D/good"
 sed 's/R52_C_GUEST_RESULT_SHA256=.*/R52_C_GUEST_RESULT_SHA256=WRONG/' "$D/good" > "$D/bad"
 if grep -Fxq "R52_C_GUEST_RESULT_SHA256=$expected" "$D/bad"; then
  echo R52_C_FALSE_RECEIPT_ADMITTED=RED >&2; exit 3
 fi
 echo R52_C_NEGATIVE_ORACLE_SELF_TEST=PASS
 exit 0
fi
if [[ ${1:-} != --public-disposable || ${GITHUB_ACTIONS:-} != true || -z ${RUNNER_TEMP:-} ||
      $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
 echo R52_C_NO_APPROVED_DISPOSABLE_X64_CI_INTENT=DENIED >&2; exit 10
fi

QEMU=$(command -v qemu-system-x86_64 || :)
BUSYBOX=$(command -v busybox || :)
KERNEL=$(find /boot -maxdepth 1 -name 'vmlinuz-*-generic' -print 2>/dev/null | sort -V | tail -n1 || :)
for bin in "$QEMU" "$BUSYBOX" "$KERNEL"; do
 if [[ -z $bin || ! -f $bin ]]; then
  echo R52_C_KERNEL_OR_QEMU_DEPENDENCY_ABSENT=ENVIRONMENT_FAILURE >&2; exit 21
 fi
done
if ! file "$BUSYBOX" | grep -qi 'statically linked'; then
 echo R52_C_BUSYBOX_NOT_STATIC=ENVIRONMENT_FAILURE >&2; exit 22
fi
if [[ -z $(command -v cpio || :) || -z $(command -v gzip || :) ]]; then
 echo R52_C_CPIO_DEPENDENCY_ABSENT=ENVIRONMENT_FAILURE >&2; exit 23
fi

W=$(mktemp -d "$RUNNER_TEMP/r52-linux-guest-XXXXXXXX")
trap 'sudo rm -rf -- "$W"' EXIT
# Public CI Ubuntu kernel package; copy only that package-installed test
# kernel into disposable temp so private runner boot assets are never used.
sudo cp -- "$KERNEL" "$W/test-linux-vmlinuz"
sudo chown "$(id -u):$(id -g)" "$W/test-linux-vmlinuz"
test -r "$W/test-linux-vmlinuz"
mkdir -p "$W/root"/{bin,sbin,dev,proc,sys}
cp "$BUSYBOX" "$W/root/bin/busybox"
ln -s busybox "$W/root/bin/sh"
ln -s busybox "$W/root/bin/sha256sum"
ln -s busybox "$W/root/bin/mount"
ln -s ../bin/busybox "$W/root/sbin/poweroff"
printf 'wyse-r51-canary-v1\n' > "$W/root/r52_payload"
# Independently pinned R51 owner-approved guest task, never a hash derived
# solely from mutable fixture bytes. Fail closed if payload is changed.
R51_CANONICAL_SHA=e990572be5fbb48fd706e5c3f612dd7c6e953c9b583919c3455f10c4f1845a8d
EXPECTED=$(sha256sum "$W/root/r52_payload" | cut -d' ' -f1)
if [[ $EXPECTED != "$R51_CANONICAL_SHA" ]]; then
 echo R53_C_CANONICAL_PAYLOAD_HASH_MISMATCH=RED >&2; exit 24
fi
echo R53_C_CANONICAL_GUEST_PAYLOAD_MATCHES_R51=PASS
cat > "$W/root/init" <<'GUEST'
#!/bin/sh
export PATH=/bin:/sbin
/bin/mount -t proc proc /proc || exit 41
/bin/mount -t sysfs sysfs /sys || exit 42
echo 'R52_C_GUEST_LINUX_STARTED=PASS' >/dev/console
set -- $(/bin/sha256sum /r52_payload)
echo "R52_C_GUEST_RESULT_SHA256=$1" >/dev/console
echo 'R52_C_GUEST_CLEAN_EXIT=PASS' >/dev/console
/bin/busybox sync
/sbin/poweroff -f
exit 43
GUEST
chmod 0755 "$W/root/init"
sudo mknod -m 600 "$W/root/dev/console" c 5 1
sudo mknod -m 666 "$W/root/dev/null" c 1 3
sudo mknod -m 666 "$W/root/dev/ttyS0" c 4 64
(
 cd "$W/root"
 find . -print0 | cpio --null -o -H newc --quiet | gzip -9 > "$W/guest-initramfs.cpio.gz"
)
test "$(stat -c %s "$W/guest-initramfs.cpio.gz")" -gt 10000
# No -drive, host volume, USB, host PCI, SSH keys, or network interfaces.
set +e
timeout -k 5s 110s "$QEMU" \
  -machine q35 -accel tcg -cpu max -smp 1 -m 192M \
  -nodefaults -nic none -display none -monitor none \
  -serial "file:$W/serial.log" -no-reboot \
  -kernel "$W/test-linux-vmlinuz" -initrd "$W/guest-initramfs.cpio.gz" \
  -append 'console=ttyS0 panic=1 rdinit=/init' \
  >"$W/qemu-stderr.log" 2>&1
CODE=$?
set -e
if [[ $CODE -ne 0 ]]; then
 echo "R52_C_LINUX_QEMU_EXIT=RED:$CODE" >&2
 tail -n 24 "$W/serial.log" >&2 || :
 tail -n 16 "$W/qemu-stderr.log" >&2 || :
 exit 42
fi
# The emulated ISA UART serial console can add CRLF transport endings.
# Normalize only CR bytes, without weakening full-line or hash equality.
tr -d '\r' < "$W/serial.log" > "$W/serial-normalized.log"
grep -Fxq 'R52_C_GUEST_LINUX_STARTED=PASS' "$W/serial-normalized.log" ||
 { echo R52_C_GUEST_LINUX_BOOT_ORACLE=RED >&2;
   echo R52_C_SYNTHETIC_GUEST_SERIAL_DIAGNOSTIC_BEGIN >&2;
   tail -n 50 "$W/serial.log" >&2 || :;
   tail -n 16 "$W/qemu-stderr.log" >&2 || :;
   echo R52_C_SYNTHETIC_GUEST_SERIAL_DIAGNOSTIC_END >&2; exit 43; }
grep -Fxq "R52_C_GUEST_RESULT_SHA256=$EXPECTED" "$W/serial-normalized.log" ||
 { echo R52_C_GUEST_TASK_DIGEST=RED >&2; exit 44; }
grep -Fxq 'R52_C_GUEST_CLEAN_EXIT=PASS' "$W/serial-normalized.log" ||
 { echo R52_C_GUEST_SHUTDOWN_ORACLE=RED >&2; exit 45; }
mkdir -p evidence/public
{
 echo R52_C_EVIDENCE_CLASS=PUBLIC_DISPOSABLE_REAL_LINUX_NOT_DELL_HIL
 echo R52_C_GUEST_BOOT=LINUX_KERNEL_QEMU_TCG_OBSERVED
 echo "R52_C_GUEST_TASK_SHA256=$EXPECTED"
 echo R52_C_HOST_VOLUME_AND_GUEST_NIC=NOT_ATTACHED
 echo R52_C_AGENT_DISPATCH_REAL_LEASE=NOT_TESTED
 echo R52_C_WYSE_REAL_KVM_AND_EMMC=NOT_TESTED
 echo R53_C_CANONICAL_R51_SHA256=$R51_CANONICAL_SHA
 echo R53_C_GUEST_PAYLOAD_CANONICAL_R51=PASS
 echo R52_C_GUEST_RESULT_AND_CLEAN_EXIT=PASS
} > evidence/public/r52-linux-guest.txt
echo R52_C_PUBLIC_REAL_LINUX_GUEST_TASK_AND_SHUTDOWN=PASS
