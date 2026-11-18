#!/bin/sh
# Runs ONLY inside disposable QEMU Linux guest.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc || :
mount -t sysfs sysfs /sys || :
mount -t devtmpfs devtmpfs /dev || :
echo USBFABRIC_R04_GUEST_BOOT=PASS >/dev/console
uname -r >/dev/console
for m in usbip_core usbip_host vhci_hcd usbip_vudc libcomposite dummy_hcd; do
 if modprobe "$m" >/dev/console 2>&1; then
   echo "USBFABRIC_R04_MODULE_${m}=LOADED" >/dev/console
 else
   echo "USBFABRIC_R04_MODULE_${m}=FAILED" >/dev/console
 fi
done
mkdir -p /sys/kernel/config
if mount -t configfs configfs /sys/kernel/config >/dev/console 2>&1; then
 echo USBFABRIC_R04_CONFIGFS_MOUNT=PASS >/dev/console
else
 echo USBFABRIC_R04_CONFIGFS_MOUNT=RED >/dev/console
fi
if [ -d /sys/class/udc ]; then
 echo USBFABRIC_R04_UDC_ENUM_BEGIN >/dev/console
 ls -1 /sys/class/udc >/dev/console
 echo USBFABRIC_R04_UDC_ENUM_END >/dev/console
else
 echo USBFABRIC_R04_UDC_ENUM=ABSENT >/dev/console
fi
echo USBFABRIC_R04_GUEST_PROBE_END=YES >/dev/console
sync
poweroff -f || reboot -f
