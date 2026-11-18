#!/bin/sh
set -eu
echo USBFABRIC_R04_HOST_KERNEL_CONFIG_BEGIN
grep -E '^CONFIG_(USBIP|USB_GADGET|USB_CONFIGFS|USB_LIBCOMPOSITE|USB_DUMMY_HCD)' /guest/kernel-config || true
echo USBFABRIC_R04_HOST_KERNEL_CONFIG_END
echo USBFABRIC_R04_REAL_GUEST_BOOT_BEGIN
timeout 170s qemu-system-x86_64 -machine q35 -accel tcg -cpu qemu64 -m 512 -smp 1 \
 -kernel /guest/kernel -initrd /guest/initrd.gz \
 -append 'console=ttyS0 rdinit=/init panic=1' \
 -nographic -monitor none -net none -no-reboot
echo USBFABRIC_R04_REAL_GUEST_BOOT_END
echo USBFABRIC_R04_REAL_USBIP_URB=NOT_TESTED
