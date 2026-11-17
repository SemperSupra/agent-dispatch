#!/bin/sh
# Disposable Linux guest: real USB mass-storage block read (no host USB).
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
/bin/busybox mkdir -p /proc /sys /dev
/bin/busybox mount -t proc proc /proc || exit 20
/bin/busybox mount -t sysfs sysfs /sys || exit 21
/bin/busybox mount -t devtmpfs devtmpfs /dev || exit 22
echo R26_M2_REAL_LINUX_GUEST_BOOTED=PASS
for mod in xhci_pci xhci_hcd scsi_mod sd_mod usb_storage uas; do
 /sbin/modprobe "$mod" >/dev/null 2>&1 || true
done
expected=""
for arg in $(/bin/busybox cat /proc/cmdline); do
 case "$arg" in r26_sha=*) expected="${arg#r26_sha=}" ;; esac
done
if [ -z "$expected" ]; then echo R26_M2_MISSING_EXPECTED_SHA=RED; /bin/busybox poweroff -f; fi
tries=0
while [ "$tries" -lt 30 ]; do
 [ -b /dev/sda ] && [ -f /sys/class/block/sda/ro ] && break
 /bin/busybox sleep 1
 tries=$((tries+1))
done
echo "R26_M2_BLOCK_DISCOVERY_POLL=$tries"
if [ ! -b /dev/sda ]; then
 echo R26_M2_GUEST_SCSI_BLOCK_NODE=RED
 /bin/busybox ls /sys/class/block 2>/dev/null || true
 /bin/busybox poweroff -f
 /bin/busybox sleep 3
 exit 30
fi
echo R26_M2_GUEST_SCSI_BLOCK_NODE=PASS
ro="$(/bin/busybox cat /sys/class/block/sda/ro)"
if [ "$ro" = 1 ];then
 echo R26_M2_GUEST_BLOCK_READONLY=PASS
else
 echo "R26_M2_GUEST_BLOCK_READONLY=RED observed=$ro"
fi
actual="$(/bin/busybox dd if=/dev/sda bs=512 count=1 2>/dev/null | /bin/busybox sha256sum | /bin/busybox awk '{print $1}')"
echo "R26_M2_GUEST_SECTOR_SHA256=$actual"
if [ "$ro" = 1 ] && [ "$actual" = "$expected" ];then
 echo R26_M2_GUEST_READONLY_STORAGE_DATA_INTEGRITY=PASS
else
 echo R26_M2_GUEST_READONLY_STORAGE_DATA_INTEGRITY=RED
fi
/bin/busybox poweroff -f
/bin/busybox sleep 5
exit 0
