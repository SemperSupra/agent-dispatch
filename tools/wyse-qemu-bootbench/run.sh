#!/usr/bin/env bash
# Synthetic x86 boot-sector microbenchmark on disposable PUBLIC cloud CI.
# Does not boot a Linux guest and cannot predict physical Wyse throughput.
set -Eeuo pipefail
umask 077
if test "${GITHUB_ACTIONS:-}" != true || test -z "${RUNNER_TEMP:-}"; then
  echo R44_PUBLIC_CI_ADMISSION_ONLY=FAIL_CLOSED >&2
  exit 10
fi
W=$(mktemp -d "$RUNNER_TEMP/wyse-r44-qemu-XXXXXX")
trap 'rm -rf -- "$W"' EXIT
mkdir -p evidence/public
nasm -f bin tools/wyse-qemu-bootbench/bootsector.asm -o "$W/boot.img"
test "$(stat -c %s "$W/boot.img")" -eq 512
test "$(od -An -tx1 -j510 -N2 "$W/boot.img" | tr -d ' \n')" = 55aa
QEMU_VERSION=$(qemu-system-x86_64 --version | head -1)
printf '%s\n' "R44_SCOPE=PUBLIC_CLOUD_SYNTHETIC_NOT_DELL_HIL" > evidence/public/r44-qemu-bootbench.txt
printf 'R44_QEMU_VERSION=%s\n' "$QEMU_VERSION" >> evidence/public/r44-qemu-bootbench.txt
printf 'R44_BOOT_SOURCE_SHA256=%s\n' "$(sha256sum tools/wyse-qemu-bootbench/bootsector.asm|cut -d' ' -f1)" >> evidence/public/r44-qemu-bootbench.txt
printf 'R44_BOOTSECTOR_SHA256=%s\n' "$(sha256sum "$W/boot.img"|cut -d' ' -f1)" >> evidence/public/r44-qemu-bootbench.txt
printf 'R44_IGPU_GPU_PASSTHROUGH_HIL=NOT_TESTED\n' >> evidence/public/r44-qemu-bootbench.txt

run() {
  local mode=$1 machine=$2 accel=$3 cpu=$4 smp=$5
  local -a disk base
  base=(-machine "$machine" -accel "$accel" -cpu "$cpu" -smp "$smp" -m 128M
        -nodefaults -display none -serial none -monitor none -no-reboot
        -device isa-debug-exit,iobase=0xf4,iosize=0x04
        -debugcon "file:$W/debugcon.txt"
        -global isa-debugcon.iobase=0xe9 -boot order=c)
  if test "$machine" = pc; then
    disk=(-drive "if=ide,media=disk,format=raw,file=$W/boot.img")
  else
    disk=(-device ich9-ahci,id=ahci
          -drive "if=none,id=boot,media=disk,format=raw,file=$W/boot.img"
          -device ide-hd,bus=ahci.0,drive=boot,bootindex=1)
  fi
  for rep in 1 2 3; do
    : > "$W/debugcon.txt"
    local start end code=0
    start=$(date +%s%3N)
    timeout -k 3s 25s qemu-system-x86_64 "${base[@]}" "${disk[@]}" \
      > "$W/qemu-$mode-$rep.log" 2>&1 || code=$?
    end=$(date +%s%3N)
    if test "$code" -ne 33 || ! grep -Fxq 'R44_GUEST_BOOTSECTOR_EXECUTED=PASS' "$W/debugcon.txt"; then
      echo "R44_GUEST_BOOT_OR_EXIT_ORACLE=RED:$mode:$rep:exit=$code" >&2
      tail -n 15 "$W/qemu-$mode-$rep.log" >&2
      exit 41
    fi
    echo "R44_SAMPLE=$mode,$rep,$accel,$machine,$smp,$((end-start))ms" >> evidence/public/r44-qemu-bootbench.txt
  done
  echo "R44_MODE_$mode=PASS" >> evidence/public/r44-qemu-bootbench.txt
}
run TCG_PC_IDE pc tcg max 1
run TCG_Q35_AHCI q35 tcg max 1
run TCG_Q35_AHCI_2VCPU q35 tcg max 2
if test -c /dev/kvm && test -r /dev/kvm && test -w /dev/kvm; then
  run KVM_Q35_AHCI q35 kvm host 2
  echo 'R44_RUNNER_KVM_BOOT=OBSERVED_PASS' >> evidence/public/r44-qemu-bootbench.txt
else
  echo 'R44_RUNNER_KVM_BOOT=NOT_AVAILABLE_NOT_A_WYSE_VERDICT' >> evidence/public/r44-qemu-bootbench.txt
fi
if qemu-system-x86_64 -device help 2>/dev/null | grep -Fq virtio-gpu-pci; then
  echo 'R44_VIRTIO_GPU_DEVICE_ADVERTISED=YES_NOT_GUEST_OR_ACCEL_TESTED' >> evidence/public/r44-qemu-bootbench.txt
else
  echo 'R44_VIRTIO_GPU_DEVICE_ADVERTISED=NO_OR_UNKNOWN' >> evidence/public/r44-qemu-bootbench.txt
fi
echo 'R44_PUBLIC_CLOUD_RUNNER_PERFORMANCE_NOT_WYSE=TRUE' >> evidence/public/r44-qemu-bootbench.txt
echo R44_THREE_REP_GUEST_EXECUTION_ORACLES=PASS
