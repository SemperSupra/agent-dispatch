#!/bin/sh
# Disposable Linux initrd with pcscd/libccid, real QEMU USB CCID reader.
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
/bin/busybox mkdir -p /proc /sys /dev /run/pcscd /var/run /tmp
/bin/busybox mount -t proc proc /proc || exit 31
/bin/busybox mount -t sysfs sysfs /sys || exit 32
/bin/busybox mount -t devtmpfs devtmpfs /dev || exit 33
/bin/busybox mount -t tmpfs tmpfs /run || true
/bin/busybox mkdir -p /run/pcscd
for mod in xhci_pci xhci_hcd usbcore; do /sbin/modprobe "$mod" >/dev/null 2>&1 || true;done
tries=0;seen=0
while [ "$tries" -lt 20 ];do
 for f in /sys/bus/usb/devices/*/product;do
  [ -f "$f" ] || continue
  case "$(/bin/busybox cat "$f")" in *CCID*) seen=1 ;;esac
 done
 [ "$seen" = 1 ] && break
 tries=$((tries+1))
 /bin/busybox sleep 1
done
if [ "$seen" != 1 ];then echo R26_N5B_REAL_GUEST_USB_CCID_SYSFS=RED; /bin/busybox poweroff -f; exit 35;fi
echo R26_N5B_REAL_GUEST_USB_CCID_SYSFS=PASS
/usr/sbin/pcscd --foreground --debug >/tmp/pcscd.log 2>&1 &
pid=$!
/bin/busybox sleep 2
/r26-pcsc-probe
status=$?
if [ "$status" = 0 ];then echo R26_N5B_REAL_GUEST_USB_CCID_APDU_ORACLE=PASS;else echo "R26_N5B_REAL_GUEST_USB_CCID_APDU_ORACLE=RED exit=$status";fi
/bin/busybox kill "$pid" 2>/dev/null || true
/bin/busybox poweroff -f
/bin/busybox sleep 10
exit 0
