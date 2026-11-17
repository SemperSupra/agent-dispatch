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
# An initrd has no udev daemon. Enumerate the kernel-owned USB character
# devices explicitly so libusb/libccid can open a synthetic QEMU reader.
for u in /sys/bus/usb/devices/*;do
 [ -r "$u/dev" ] && [ -r "$u/busnum" ] && [ -r "$u/devnum" ] || continue
 pair="$(/bin/busybox cat "$u/dev")"
 bus="$(/bin/busybox cat "$u/busnum")"
 dev="$(/bin/busybox cat "$u/devnum")"
 path="$(/bin/busybox printf "/dev/bus/usb/%03d/%03d" "$bus" "$dev")"
 /bin/busybox mkdir -p "${path%/*}"
 [ -c "$path" ] || /bin/busybox mknod "$path" c "${pair%:*}" "${pair#*:}" || true
done
for u in /sys/bus/usb/devices/*;do
 [ -r "$u/idVendor" ] && [ -r "$u/idProduct" ] || continue
 echo "R26_N5B_SYNTHETIC_USB_VID_PID=$(/bin/busybox cat "$u/idVendor"):$(
   /bin/busybox cat "$u/idProduct")"
done
/bin/busybox ls /dev/bus/usb 2>/dev/null || true
# pcsc-lite on Debian trixie uses a udev-backed hotplug path. Replay
# *guest-local* USB add events using Debian's shipped libccid rule;
# never alter runner-host udev, kernel modules, or physical USB devices.
/usr/lib/systemd/systemd-udevd --daemon >/tmp/r26-udevd.log 2>&1 || true
/bin/busybox sleep 1
/usr/bin/udevadm trigger --action=add --subsystem-match=usb >/tmp/r26-udev-trigger.log 2>&1 || true
/usr/bin/udevadm settle --timeout=12 >/tmp/r26-udev-settle.log 2>&1 || true
echo R26_N5B_GUEST_UDEV_USB_EVENT_REPLAY_ATTEMPTED=PASS
/usr/sbin/pcscd --foreground --disable-polkit --debug >/tmp/pcscd.log 2>&1 &
pid=$!
/bin/busybox sleep 2
# Minimal-initrd kernels do not run the udev event dispatcher. Request
# a bounded new reader scan after synthetic USB character nodes exist.
/usr/sbin/pcscd --hotplug >/tmp/pcsc-hotplug.log 2>&1 || true
/bin/busybox sleep 1
/r26-pcsc-probe
status=$?
if [ "$status" = 0 ];then echo R26_N5B_REAL_GUEST_USB_CCID_APDU_ORACLE=PASS;else echo "R26_N5B_REAL_GUEST_USB_CCID_APDU_ORACLE=RED exit=$status";fi
# No PIN or APDU data is used in this synthetic run. Limit to loader/device
# startup errors rather than dumping arbitrary card responses.
if [ "$status" != 0 ];then
 echo R26_N5B_PCSC_DAEMON_DIAGNOSTIC_BEGIN
 echo "R26_N5B_PCSC_LOG_BYTES=$(/bin/busybox wc -c </tmp/pcscd.log)"
echo R26_N5B_PCSC_INITIAL_DRIVER_LOG
/bin/busybox head -n 55 /tmp/pcscd.log 2>/dev/null || true
echo R26_N5B_PCSC_LAST_CLIENT_LOG
/bin/busybox tail -n 15 /tmp/pcscd.log 2>/dev/null || true
echo R26_N5B_GUEST_UDEV_LOG
/bin/busybox head -n 12 /tmp/r26-udevd.log 2>/dev/null || true
/bin/busybox head -n 12 /tmp/r26-udev-trigger.log 2>/dev/null || true
/bin/busybox head -n 12 /tmp/r26-udev-settle.log 2>/dev/null || true
echo R26_N5B_PCSC_RESCAN_DIAGNOSTIC
/bin/busybox tail -n 20 /tmp/pcsc-hotplug.log 2>/dev/null || true
 echo R26_N5B_PCSC_DAEMON_DIAGNOSTIC_END
fi
/bin/busybox kill "$pid" 2>/dev/null || true
/bin/busybox poweroff -f
/bin/busybox sleep 10
exit 0
