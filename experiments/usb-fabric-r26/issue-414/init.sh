#!/bin/sh
# Actual guest mixed xHCI devices: evdev HID, read-only USB disk, RNDIS TFTP,
# USB ALSA playback and CCID reader sysfs. No raw user data or real keys.
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
fatal(){ echo "R26_P5_GUEST_FAILURE=RED cause=$1"; /bin/busybox poweroff -f; /bin/busybox sleep 5; exit 80; }
/bin/busybox mkdir -p /proc /sys /dev /tmp /dev/input
/bin/busybox mount -t proc proc /proc || fatal proc
/bin/busybox mount -t sysfs sysfs /sys || fatal sysfs
/bin/busybox mount -t devtmpfs devtmpfs /dev || fatal devtmpfs
/bin/busybox mount -t tmpfs tmpfs /tmp || true
for mod in xhci_pci xhci_hcd usbhid hid_generic evdev usb_storage scsi_mod sd_mod usbnet rndis_host cdc_ether snd snd_pcm snd_usb_audio snd_usbmidi_lib; do
 /sbin/modprobe "$mod" >/dev/null 2>&1 || true
done
reps=""
variant=""
netsha=""
disksha=""
for a in $(/bin/busybox cat /proc/cmdline);do
 case "$a" in
  r26_reps=*)reps="${a#r26_reps=}" ;;
  r26_variant=*)variant="${a#r26_variant=}" ;;
  r26_netsha=*)netsha="${a#r26_netsha=}" ;;
  r26_disksha=*)disksha="${a#r26_disksha=}" ;;
 esac
done
[ "$reps" = 32 ] || fatal mismatched_network_count
case "$variant" in quiet|disk|audio|both);; *)fatal invalid_variant;;esac
[ -n "$netsha" ] && [ -n "$disksha" ] || fatal expected_hash_missing
iface=""
usbkey=""
tries=0
while [ "$tries" -lt 35 ];do
 for p in /sys/class/net/*;do
  n="${p##*/}"
  if [ "$n" != lo ] && [ -e "$p/device" ];then iface="$n";break;fi
 done
 for p in /sys/class/input/event*/device/name;do
  [ -f "$p" ] || continue
  case "$(/bin/busybox cat "$p")" in
   *QEMU*USB*Keyboard*)usbkey="${p%/device/name}";usbkey="/dev/input/${usbkey##*/}";break;;
  esac
 done
 [ -n "$iface" ] && [ -n "$usbkey" ] && [ -b /dev/sda ] && [ -e /dev/snd/pcmC0D0p ] && break
 /bin/busybox sleep 1
 tries=$((tries+1))
done
echo "R26_P5_DEVICE_DISCOVERY iface=${iface:-NONE} key=${usbkey:-NONE} storage=$([ -b /dev/sda ] && echo yes || echo no) audio=$([ -e /dev/snd/pcmC0D0p ] && echo yes || echo no)"
for p in /sys/bus/usb/devices/*/product;do
 [ -f "$p" ] || continue
 echo "R26_P5_GUEST_USB_SYSFS_PRODUCT=$(/bin/busybox cat "$p")"
done
[ -n "$iface" ] && [ -n "$usbkey" ] && [ -b /dev/sda ] && [ -e /dev/snd/pcmC0D0p ] || fatal required_usb_class_missing
if [ ! -c "$usbkey" ];then
 n="${usbkey##*/}"
 d="$(/bin/busybox cat /sys/class/input/$n/dev)"
 /bin/busybox mknod "$usbkey" c "${d%:*}" "${d#*:}" || fatal key_node
fi
ccid=0
for p in /sys/bus/usb/devices/*/product;do
 [ -f "$p" ] || continue
 case "$(/bin/busybox cat "$p")" in *CCID*)ccid=1;;esac
done
[ "$ccid" = 1 ] || fatal ccid_reader_missing
echo R26_P5_GUEST_USB_HID_STORAGE_RNDIS_AUDIO_CCID_ENUMERATED=PASS
[ "$(/bin/busybox cat /sys/class/block/sda/ro)" = 1 ] || fatal storage_readonly_missing
actual="$(/bin/busybox dd if=/dev/sda bs=512 count=1 2>/dev/null | /bin/busybox sha256sum | /bin/busybox awk '{print $1}')"
[ "$actual" = "$disksha" ] || fatal storage_first_sector_hash
echo R26_P5_GUEST_USB_STORAGE_READONLY_SHA=PASS
/bin/busybox ifconfig "$iface" 10.0.2.15 netmask 255.255.255.0 up || fatal usb_net_ip
/hid_observer "$usbkey" &
hidpid=$!
(
 n=0
 while [ "$n" -lt "$reps" ];do
  start="$(/bin/busybox cat /proc/uptime | /bin/busybox awk '{print $1}')"
  /bin/busybox tftp -g -l /tmp/payload.bin -r payload.bin 10.0.2.2 || exit 61
  got="$(/bin/busybox sha256sum /tmp/payload.bin | /bin/busybox awk '{print $1}')"
  [ "$got" = "$netsha" ] || exit 62
  end="$(/bin/busybox cat /proc/uptime | /bin/busybox awk '{print $1}')"
  ms="$(/bin/busybox awk -v b="$start" -v e="$end" 'BEGIN{printf "%.1f",(e-b)*1000}')"
  echo "R26_P8_TFTP_MS=$ms"
  n=$((n+1))
 done
 echo "R26_P5_NETWORK_SHA_TRANSFERS=PASS count=$reps"
) &
netpid=$!
if [ "$variant" = disk ] || [ "$variant" = both ];then
(
 n=0
 while [ "$n" -lt "$reps" ];do
  /bin/busybox dd if=/dev/sda of=/dev/null bs=1048576 count=4 2>/dev/null || exit 63
  n=$((n+1))
 done
 echo "R26_P5_USB_DISK_BULK_READS=PASS count=$reps"
) &
diskpid=$!
fi
if [ "$variant" = audio ] || [ "$variant" = both ];then
(
 n=0
 loops=2
 [ "$reps" = 32 ] && loops=6
 while [ "$n" -lt "$loops" ];do
  /usr/bin/aplay -q -D hw:0,0 /r26-tone.wav || exit 64
  n=$((n+1))
 done
 echo "R26_P5_USB_AUDIO_PCM_PLAYS=PASS count=$loops"
) &
audiopid=$!
fi
wait "$netpid" || fatal tftp_or_corrupt_payload
if [ "$variant" = disk ] || [ "$variant" = both ];then wait "$diskpid" || fatal disk_bulk_io;fi
if [ "$variant" = audio ] || [ "$variant" = both ];then wait "$audiopid" || fatal usb_alsa;fi
wait "$hidpid" || fatal missing_usb_evdev_key_up
echo "R26_P8_GUEST_NETWORK_SHA_AND_HID=PASS variant=$variant count=$reps"
echo "R26_P8_GUEST_VARIANT_COMPLETED=PASS variant=$variant count=$reps"
/bin/busybox poweroff -f
/bin/busybox sleep 6
exit 0
