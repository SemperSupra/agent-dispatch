#!/bin/sh
# Public synthetic guest init. Must prove real Linux USB sysfs enumeration.
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
/bin/busybox mkdir -p /proc /sys /dev
/bin/busybox mount -t proc proc /proc || { echo R15_GUEST_PROC_MOUNT=RED; /bin/busybox poweroff -f; }
if ! /bin/busybox mount -t sysfs sysfs /sys; then
 echo R15_GUEST_SYSFS_MOUNT=RED
 /bin/busybox poweroff -f
 /bin/busybox sleep 4
 exit 26
fi
echo R15_GUEST_SYSFS_MOUNT=PASS
/bin/busybox mount -t devtmpfs devtmpfs /dev || echo R15_GUEST_DEVTMPFS_MOUNT=RED
echo R15_GUEST_PID1_STARTED=PASS
/bin/busybox uname -r
for mod in evdev xhci_pci xhci_hcd usbhid hid_generic virtio virtio_ring virtio_pci virtio_console; do
 if /sbin/modprobe "$mod" >/dev/null 2>&1 || /bin/busybox modprobe "$mod" >/dev/null 2>&1; then
  echo "R15_MODULE_LOAD_ATTEMPT=$mod PRESENT_OR_LOADED"
 else
  echo "R15_MODULE_LOAD_ATTEMPT=$mod FAILED_OR_BUILTIN"
 fi
done
seen_kbd=0
seen_tab=0
seen_disk=0
tries=0
while [ "$tries" -lt 20 ]; do
 for p in /sys/bus/usb/devices/*/product; do
  [ -f "$p" ] || continue
  text="$(/bin/busybox cat "$p" 2>/dev/null)"
  case "$text" in
   *Keyboard*|*keyboard*) seen_kbd=1 ;;
   *Tablet*|*tablet*) seen_tab=1 ;;
   *HARDDRIVE*|*Mass*Storage*|*Storage*|*USB*drive*) seen_disk=1 ;;
  esac
 done
 if [ "$seen_kbd" = 1 ]; then
  break
 fi
 tries=$((tries+1))
 /bin/busybox sleep 1
done
echo "R15_SYSFS_POLL_ITERATIONS=$tries"
for p in /sys/bus/usb/devices/*/product; do
 [ -f "$p" ] || continue
 text="$(/bin/busybox cat "$p" 2>/dev/null)"
 echo "R15_GUEST_USB_SYSFS_PRODUCT=$text"
done
if [ "$seen_kbd" = 1 ];then echo R15_GUEST_USB_KEYBOARD_ENUMERATED=PASS;fi
if [ "$seen_tab" = 1 ];then echo R15_GUEST_USB_TABLET_ENUMERATED=PASS;fi
if [ "$seen_disk" = 1 ];then echo R15_GUEST_USB_MASS_STORAGE_ENUMERATED=PASS;fi
if [ "$seen_kbd" != 1 ];then
 echo R26_L8_REAL_GUEST_USB_KEYBOARD_ENUMERATION=RED
 /bin/busybox poweroff -f
 /bin/busybox sleep 5
 exit 27
fi
echo R26_L8_REAL_GUEST_USB_KEYBOARD_ENUMERATION=PASS
usb_event=""
for p in /sys/class/input/event*/device/name; do
 [ -f "$p" ] || continue
 name="$(/bin/busybox cat "$p" 2>/dev/null)"
 case "$name" in
  *QEMU*USB*Keyboard*)
   usb_event="${p%/device/name}"
   usb_event="/dev/input/${usb_event##*/}"
   break
   ;;
 esac
done
if [ -n "$usb_event" ] && [ ! -c "$usb_event" ]; then
 event_name="${usb_event##*/}"
 dev_file="/sys/class/input/$event_name/dev"
 if [ -r "$dev_file" ]; then
  devnum="$(/bin/busybox cat "$dev_file")"
  major="${devnum%:*}"
  minor="${devnum#*:}"
  /bin/busybox mkdir -p /dev/input
  /bin/busybox mknod "$usb_event" c "$major" "$minor" || true
 fi
fi
if [ -z "$usb_event" ] || [ ! -c "$usb_event" ]; then
 echo R15_GUEST_EVENT_CLASS_LIST_FOR_FAILURE_ONLY
 /bin/busybox ls -l /sys/class/input 2>/dev/null || true
 /bin/busybox ls -l /dev/input 2>/dev/null || true

 echo R15_USB_KEYBOARD_EVDEV_NODE=RED
 /bin/busybox ls -l /dev/input 2>/dev/null || true
 /bin/busybox poweroff -f
 /bin/busybox sleep 3
 exit 28
fi
echo R15_USB_KEYBOARD_EVDEV_NODE=PASS
wire_port="/dev/vport0p1"
n=0
while [ ! -c "$wire_port" ] && [ "$n" -lt 15 ];do
 if [ -r /sys/class/virtio-ports/vport0p1/dev ];then
  devnum="$(/bin/busybox cat /sys/class/virtio-ports/vport0p1/dev)"
  /bin/busybox mknod "$wire_port" c "${devnum%:*}" "${devnum#*:}" || true
 fi
 n=$((n+1))
 /bin/busybox sleep 1
done
if [ ! -c "$wire_port" ];then
 echo R26_L8_REAL_GUEST_VIRTIO_PORT_MISSING=RED
 /bin/busybox poweroff -f
 exit 41
fi
echo R26_L8_REAL_GUEST_VIRTIO_PORT_PRESENT=PASS
scoped=""
case " $(/bin/busybox cat /proc/cmdline) " in
 *" r26_scoped=1 "*) scoped="scoped";;
esac
case " $(/bin/busybox cat /proc/cmdline) " in
 *" r27_signed=1 "*)
  # The only accepted test identity is already in host-builder custody.
  # Private key is inside extractable synthetic initramfs: NOT production.
  echo R27C_GUEST_IMAGE_PROVISIONED_ED25519_MODE=PASS
  /r27-runtime-guest-observer "$usb_event" "$wire_port"
  ;;
 *)
  if [ -n "$scoped" ];then
   echo R26_L9C_GUEST_SCOPED_RECEIPTS_REQUESTED=PASS
   /guestwire-observer "$usb_event" "$wire_port" scoped
  else
   /guestwire-observer "$usb_event" "$wire_port"
  fi
  ;;
esac
if [ "$?" -ne 0 ]; then
 echo R26_L8_GUEST_EVDEV_RECEIPT=RED
 /bin/busybox poweroff -f
 /bin/busybox sleep 3
 exit 29
fi
echo R26_L8_GUEST_EVDEV_RECEIPT=PASS
/bin/busybox poweroff -f
/bin/busybox sleep 10
exit 0
