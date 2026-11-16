#!/bin/sh
set -eu
case "$R04_ARCH" in
  aarch64)
    echo 'R04_HYPERVISOR_TCG_ACCELERATOR=REQUESTED_ARM64'
    exec qemu-system-aarch64 -machine virt -cpu cortex-a57 -accel tcg \
      -m 512M -smp 1 -nographic -monitor none -net none -no-reboot \
      -kernel /guest/kernel -initrd /guest/initrd.gz \
      -append 'console=ttyAMA0 earlycon=pl011,0x09000000 rdinit=/init loglevel=6'
    ;;
  riscv64)
    echo 'R04_HYPERVISOR_TCG_ACCELERATOR=REQUESTED_RISCV64'
    exec qemu-system-riscv64 -machine virt -cpu rv64 -accel tcg \
      -m 512M -smp 1 -nographic -monitor none -net none -no-reboot \
      -kernel /guest/kernel -initrd /guest/initrd.gz \
      -append 'console=ttyS0 earlycon=sbi rdinit=/init loglevel=6'
    ;;
  *) echo 'R04_TARGET_NOT_SUPPORTED=RED' >&2; exit 77 ;;
esac
