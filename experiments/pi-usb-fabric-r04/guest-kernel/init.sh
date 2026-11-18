#!/bin/sh
# Runs ONLY inside disposable QEMU Linux guest.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /proc /sys /dev
if mount -t proc proc /proc; then echo USBFABRIC_R04_PROC_MOUNT=PASS >/dev/console; else echo USBFABRIC_R04_PROC_MOUNT=RED >/dev/console; fi
if mount -t sysfs sysfs /sys; then echo USBFABRIC_R04_SYSFS_MOUNT=PASS >/dev/console; else echo USBFABRIC_R04_SYSFS_MOUNT=RED >/dev/console; fi
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
# Upstream USB/IP vUDC example explicitly requests num=1; otherwise no UDC may register.
modprobe -r usbip_vudc >/dev/console 2>&1 || :
if modprobe usbip_vudc num=1 >/dev/console 2>&1; then
 echo USBFABRIC_R04_VUDC_NUM1_LOAD=PASS >/dev/console
else
 echo USBFABRIC_R04_VUDC_NUM1_LOAD=RED >/dev/console
fi
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
