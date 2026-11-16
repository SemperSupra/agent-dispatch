#!/usr/bin/env bash
# Self-contained, synthetic sysfs tests. No physical devices, no write to /sys.
set -Eeuo pipefail
T=$(mktemp -d)
trap 'rm -rf -- "$T"' EXIT
root="$T/sys"
mkdir -p "$root/devices" "$root/block"
classifier="scripts/public_wyse_r31_disk_bus_classifier.sh"
test -s "$classifier"
bash -n "$classifier"
new_device() {
  local name=$1 segment=$2
  mkdir -p "$root/block/$name" "$root/devices/$segment"
  ln -s "$root/devices/$segment" "$root/block/$name/device"
}
must_pass() {
  local description=$1 mode=$2 required=$3
  if ! bash "$classifier" "$root" "$mode" > "$T/output.txt" 2>&1; then
    cat "$T/output.txt"
    echo "FAIL:$description" >&2
    exit 1
  fi
  grep -Fxq "$required" "$T/output.txt" || { cat "$T/output.txt"; echo "MISSING:$description" >&2; exit 1; }
  echo "PASS:$description"
}
must_fail() {
  local description=$1 mode=$2 required=$3
  if bash "$classifier" "$root" "$mode" > "$T/output.txt" 2>&1; then
    cat "$T/output.txt"
    echo "FAIL_OPEN:$description" >&2
    exit 1
  fi
  grep -Fq "$required" "$T/output.txt" || { cat "$T/output.txt"; echo "MISSING_NEGATIVE:$description" >&2; exit 1; }
  echo "PASS_NEGATIVE:$description"
}
# Empty host is NOT evidence for a USB-backed no-SATA recovery environment.
must_fail empty_no_usb --expect-no-sata USB_BOOT_STORAGE_ABSENT=RED
# The FIRST sdX block is the USB boot drive; it must NOT be mistaken for SATA.
new_device sda pci0000:00/0000:00:14.0/usb1/1-1/host0/target0:0:0/0:0:0:0
must_pass usb_sda_not_sata --expect-no-sata NO_SATA_WITH_USB_PRESENT=PASS
must_pass usb_path_readback --expect-usb USB_BUS_PRESENT=PASS
# The SECOND sdX block is the actual ATA-backed disk.
new_device sdb pci0000:00/0000:00:1f.2/ata1/host1/target1:0:0/1:0:0:0
must_pass sata_sdb_bus_attribution --expect-sata SATA_BUS_PRESENT=PASS
must_fail sata_present_refuses_no_sata --expect-no-sata UNEXPECTED_SATA=FAIL_OPEN
# Unknown virtual SCSI transport must fail closed rather than infer SATA.
new_device sdc pci0000:00/0000:00:04.0/virtio0/host2/target2:0:0/2:0:0:0
must_fail unknown_transport_refused --expect-sata BUS_ATTRIBUTION=RED_UNKNOWN
rm -rf -- "$root/block/sdc"
# Escape outside the permitted sysfs tree is a hard error.
mkdir -p "$root/block/sdd" "$T/outside/usb2/disk"
ln -s "$T/outside/usb2/disk" "$root/block/sdd/device"
must_fail escaped_sysfs_root_refused --expect-no-sata BLOCK_BUS_OUTSIDE_SYSFS=sdd
rm -rf -- "$root/block/sdd"
# Conflicting bus ancestry is ambiguous, never classify as USB or ATA.
new_device sde pci0000:00/usb3/ata2/host3/target3:0:0/3:0:0:0
must_fail conflicting_usb_ata_paths_refused --expect-no-sata BUS_ATTRIBUTION=RED_UNKNOWN
rm -rf -- "$root/block/sde"
mkdir -p "$root/block/sdf"
ln -s "$root/devices/not-existing" "$root/block/sdf/device"
must_fail missing_sysfs_link_refused --expect-no-sata BLOCK_BUS_UNKNOWN=sdf
echo R31_SYNTHETIC_DISK_BUS_CLASSIFIER=PASS
