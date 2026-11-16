#!/usr/bin/env bash
# Public synthetic and read-only Linux sysfs bus-origin classifier.
# Not a physical disk identifier, firmware manager or authorization primitive.
set -Eeuo pipefail
if (( $# < 1 || $# > 2 )); then
  echo 'usage: classifier.sh /sys [--expect-no-sata|--expect-sata|--expect-usb]' >&2
  exit 2
fi
root=$1
mode=--observe
if (( $# == 2 )); then mode=$2; fi
case "$mode" in --observe|--expect-no-sata|--expect-sata|--expect-usb) ;; *) echo 'INVALID_MODE' >&2; exit 2 ;; esac
test -d "$root/devices" && test -d "$root/block" || { echo 'SYSFS_ROOT_MISSING=RED'; exit 3; }
root=$(cd "$root" && pwd -P)
sata=0
usb=0
unknown=0
shopt -s nullglob
for block in "$root"/block/sd*; do
  name=$(basename "$block")
  [[ $name =~ ^sd[a-z]+$ ]] || continue
  test -d "$block/device" || { echo "BLOCK_BUS_UNKNOWN=$name"; ((unknown+=1)); continue; }
  physical=$(cd "$block/device" && pwd -P) || { echo "BLOCK_BUS_UNKNOWN=$name"; ((unknown+=1)); continue; }
  case "$physical" in "$root"/devices/*) ;; *) echo "BLOCK_BUS_OUTSIDE_SYSFS=$name"; ((unknown+=1)); continue ;; esac
  # Do not infer bus type from /dev/sda, USB and SATA both use sd* names.
  # Kernel sysfs ancestry is the concrete read-only evidence.
  on_usb=0
  on_sata=0
  [[ "$physical" =~ /usb[0-9]+/ ]] && on_usb=1
  [[ "$physical" =~ /ata[0-9]+/ ]] && on_sata=1
  if (( on_usb == 1 && on_sata == 0 )); then
    echo "BLOCK_BUS_USB=$name"
    ((usb+=1))
  elif (( on_sata == 1 && on_usb == 0 )); then
    echo "BLOCK_BUS_SATA=$name"
    ((sata+=1))
  else
    echo "BLOCK_BUS_UNKNOWN=$name"
    ((unknown+=1))
  fi
done
echo "BUS_COUNTS_USB=$usb"
echo "BUS_COUNTS_SATA=$sata"
echo "BUS_COUNTS_UNKNOWN=$unknown"
if (( unknown > 0 )); then echo 'BUS_ATTRIBUTION=RED_UNKNOWN'; exit 4; fi
case "$mode" in
  --expect-no-sata)
    (( sata == 0 )) || { echo 'UNEXPECTED_SATA=FAIL_OPEN'; exit 5; }
    (( usb > 0 )) || { echo 'USB_BOOT_STORAGE_ABSENT=RED'; exit 6; }
    echo 'NO_SATA_WITH_USB_PRESENT=PASS'
    ;;
  --expect-sata)
    (( sata > 0 )) || { echo 'EXPECTED_SATA_ABSENT=RED'; exit 7; }
    echo 'SATA_BUS_PRESENT=PASS'
    ;;
  --expect-usb)
    (( usb > 0 )) || { echo 'EXPECTED_USB_ABSENT=RED'; exit 8; }
    echo 'USB_BUS_PRESENT=PASS'
    ;;
esac
