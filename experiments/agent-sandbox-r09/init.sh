#!/bin/sh
# Public synthetic guest init. Must prove real Linux USB sysfs enumeration.
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
/bin/busybox mount -t proc proc /proc 2>/dev/null || true
/bin/busybox mount -t sysfs sysfs /sys 2>/dev/null || true
/bin/busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
echo R09_GUEST_PID1_STARTED=PASS
/bin/busybox uname -r
for mod in xhci_pci xhci_hcd usb_storage usbhid hid_generic; do
 if /sbin/modprobe "$mod" >/dev/null 2>&1 || /bin/busybox modprobe "$mod" >/dev/null 2>&1; then
  echo "R09_MODULE_LOAD_ATTEMPT=$mod PRESENT_OR_LOADED"
 else
  echo "R09_MODULE_LOAD_ATTEMPT=$mod FAILED_OR_BUILTIN"
 fi
done
/bin/busybox sleep 3
seen_kbd=0
seen_tab=0
seen_disk=0
for p in /sys/bus/usb/devices/*/product; do
 [ -f "$p" ] || continue
 text="$(/bin/busybox cat "$p" 2>/dev/null)"
 echo "R09_GUEST_USB_SYSFS_PRODUCT=$text"
 case "$text" in
  *Keyboard*|*keyboard*) seen_kbd=1 ;;
  *Tablet*|*tablet*) seen_tab=1 ;;
  *HARDDRIVE*|*Mass*Storage*|*Storage*|*USB*drive*) seen_disk=1 ;;
 esac
done
if [ "$seen_kbd" = 1 ];then echo R09_GUEST_USB_KEYBOARD_ENUMERATED=PASS;fi
if [ "$seen_tab" = 1 ];then echo R09_GUEST_USB_TABLET_ENUMERATED=PASS;fi
if [ "$seen_disk" = 1 ];then echo R09_GUEST_USB_MASS_STORAGE_ENUMERATED=PASS;fi
if [ "$seen_kbd" != 1 ] || [ "$seen_tab" != 1 ] || [ "$seen_disk" != 1 ];then
 echo R09_GUEST_USB_ALL_THREE_ENUMERATED=RED
 /bin/busybox poweroff -f
 /bin/busybox sleep 5
 exit 27
fi
echo R09_GUEST_USB_ALL_THREE_ENUMERATED=PASS
/bin/busybox poweroff -f
/bin/busybox sleep 10
exit 0
