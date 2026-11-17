#!/bin/sh
# Real Linux xHCI virtual USB network/audio data-path observer.
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
fatal(){ echo "R26_P2_GUEST_ORACLE=RED cause=$1"; /bin/busybox poweroff -f; /bin/busybox sleep 5; exit 80; }
/bin/busybox mkdir -p /proc /sys /dev /tmp
/bin/busybox mount -t proc proc /proc || fatal proc
/bin/busybox mount -t sysfs sysfs /sys || fatal sysfs
/bin/busybox mount -t devtmpfs devtmpfs /dev || fatal devtmpfs
/bin/busybox mount -t tmpfs tmpfs /tmp || true
for mod in xhci_pci xhci_hcd usbnet rndis_host cdc_ether snd snd_pcm snd_usb_audio snd_usbmidi_lib; do
 /sbin/modprobe "$mod" >/dev/null 2>&1 || true
done
mode=""
sha=""
for arg in $(/bin/busybox cat /proc/cmdline);do
 case "$arg" in r26_mode=*) mode="${arg#r26_mode=}" ;; r26_sha=*) sha="${arg#r26_sha=}" ;; esac
done
case "$mode" in
 network)
  iface=""
  tries=0
  while [ "$tries" -lt 30 ];do
   for p in /sys/class/net/*;do
    n="${p##*/}"
    if [ "$n" != lo ] && [ -e "$p/device" ];then iface="$n";break;fi
   done
   [ -n "$iface" ] && break
   tries=$((tries+1))
   /bin/busybox sleep 1
  done
  [ -n "$iface" ] || fatal no_usb_net_interface
  echo "R26_P2_REAL_GUEST_USB_NETWORK_IFACE=PASS iface=$iface"
  /bin/busybox ifconfig "$iface" 10.0.2.15 netmask 255.255.255.0 up || fatal ifconfig
  i=0
  while [ "$i" -lt 4 ];do
   /bin/busybox rm -f /tmp/r26.dat
   /bin/busybox tftp -g -l /tmp/r26.dat -r payload.bin 10.0.2.2 || fatal tftp_transfer
   got="$(/bin/busybox sha256sum /tmp/r26.dat|/bin/busybox awk '{print $1}')"
   [ "$got" = "$sha" ] || fatal packet_payload_hash
   i=$((i+1))
  done
  echo R26_P2_REAL_GUEST_USB_NET_UDP_TFTP_4X_SHA256=PASS
  ;;
 audio)
  tries=0
  while [ "$tries" -lt 30 ];do
   [ -e /dev/snd/pcmC0D0p ] && break
   /bin/busybox sleep 1
   tries=$((tries+1))
  done
  [ -e /dev/snd/pcmC0D0p ] || fatal no_alsa_usb_pcm
  echo R26_P2_REAL_GUEST_USB_AUDIO_ALSA_PCM_PRESENT=PASS
  /usr/bin/aplay -q -D hw:0,0 /r26-tone.wav || fatal alsa_playback
  echo R26_P2_REAL_GUEST_USB_AUDIO_PLAYBACK=PASS
  ;;
 *)fatal bad_mode;;
esac
/bin/busybox poweroff -f
/bin/busybox sleep 8
exit 0
