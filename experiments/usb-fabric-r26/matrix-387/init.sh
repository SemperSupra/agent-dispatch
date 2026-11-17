#!/bin/sh
# Guest real evdev observer for virtual USB mouse and absolute tablet.
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
/bin/busybox mkdir -p /proc /sys /dev
/bin/busybox mount -t proc proc /proc || exit 20
/bin/busybox mount -t sysfs sysfs /sys || exit 21
/bin/busybox mount -t devtmpfs devtmpfs /dev || exit 22
echo R26_M1_REAL_LINUX_GUEST_BOOTED=PASS
for mod in xhci_pci xhci_hcd usbhid hid_generic evdev;do
 /sbin/modprobe "$mod" >/dev/null 2>&1 || true
done
kind=""
for arg in $(/bin/busybox cat /proc/cmdline);do
 case "$arg" in r26_kind=*) kind="${arg#r26_kind=}" ;; esac
done
event=""
tries=0
while [ "$tries" -lt 25 ];do
 for p in /sys/class/input/event*/device/name;do
  [ -f "$p" ] || continue
  name="$(/bin/busybox cat "$p" 2>/dev/null)"
  case "$kind:$name" in
   mouse:*USB*Mouse*|tablet:*USB*Tablet*)
    event="${p%/device/name}"
    event="/dev/input/${event##*/}"
    ;;
  esac
 done
 [ -n "$event" ] && break
 tries=$((tries+1))
 /bin/busybox sleep 1
done
echo "R26_M1_GUEST_EVENT_DISCOVERY_POLL=$tries"
if [ -z "$event" ];then
 echo R26_M1_USB_POINTER_INPUT_NODE=RED
 /bin/busybox ls -l /sys/class/input 2>/dev/null || true
 /bin/busybox poweroff -f
 /bin/busybox sleep 3
 exit 30
fi
if [ ! -c "$event" ];then
 num="${event##*/}"
 desc="$(/bin/busybox cat /sys/class/input/$num/dev)"
 major="${desc%:*}";minor="${desc#*:}"
 /bin/busybox mkdir -p /dev/input
 /bin/busybox mknod "$event" c "$major" "$minor" || true
fi
if [ ! -c "$event" ];then
 echo R26_M1_USB_POINTER_INPUT_NODE=RED
 /bin/busybox poweroff -f
 exit 31
fi
echo R26_M1_USB_POINTER_INPUT_NODE=PASS
/pointer_observer "$event" "$kind"
result=$?
echo "R26_M1_POINTER_ORACLE_EXIT=$result"
/bin/busybox poweroff -f
/bin/busybox sleep 4
exit 0
