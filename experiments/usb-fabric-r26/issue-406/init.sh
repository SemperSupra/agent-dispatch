#!/bin/sh
# Synthetic USB-UAS -> SCSI CD/DVD-like filesystem reader.
# Never formats, erases, opens or burns physical optical media.
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
fatal(){ echo "R26_P3_GUEST_ORACLE=RED reason=$1"; /bin/busybox poweroff -f; /bin/busybox sleep 4; exit 50; }
/bin/busybox mkdir -p /proc /sys /dev /mnt/disc /tmp
/bin/busybox mount -t proc proc /proc || fatal proc
/bin/busybox mount -t sysfs sysfs /sys || fatal sysfs
/bin/busybox mount -t devtmpfs devtmpfs /dev || fatal devtmpfs
for mod in xhci_pci xhci_hcd usb_storage uas scsi_mod sr_mod cdrom iso9660 udf;do
 /sbin/modprobe "$mod" >/dev/null 2>&1 || true
done
kind=""
for arg in $(/bin/busybox cat /proc/cmdline);do
 case "$arg" in r26_kind=*)kind="${arg#r26_kind=}" ;; esac
done
[ "$kind" = iso9660 ] || [ "$kind" = udf ] || fatal wrong_kind
tries=0
while [ "$tries" -lt 30 ];do
 [ -b /dev/sr0 ] && break
 /bin/busybox sleep 1
 tries=$((tries+1))
done
[ -b /dev/sr0 ] || fatal no_virtual_optical_media
echo "R26_P3_REAL_GUEST_USB_UAS_SCSI_CD_DEVICE=PASS kind=$kind"
ro="$(/bin/busybox cat /sys/class/block/sr0/ro)"
[ "$ro" = 1 ] || fatal optical_not_readonly
echo R26_P3_REAL_GUEST_OPTICAL_READONLY=PASS
/bin/busybox mount -t "$kind" /dev/sr0 /mnt/disc || fatal mount_failure
got="$(/bin/busybox cat /mnt/disc/manifest.txt)"
case "$kind:$got" in
 iso9660:R26_SYNTHETIC_OPTICAL_ISO_2026|udf:R26_SYNTHETIC_OPTICAL_UDF_2026) ;;
 *) fatal payload_data_integrity ;;
esac
echo "R26_P3_REAL_GUEST_OPTICAL_FILE_READ=PASS kind=$kind"
/bin/busybox dd if=/dev/sr0 bs=2048 count=64 of=/tmp/sector.bin 2>/dev/null || fatal raw_read
[ "$(/bin/busybox wc -c </tmp/sector.bin)" = 131072 ] || fatal sector_count
echo "R26_P3_REAL_GUEST_2048_BYTE_OPTICAL_SECTORS=PASS kind=$kind"
# Explicit negative control: optical backing must not permit generic block
# writes. This is not an MMC burn/provisioning protocol test.
if printf 'NO_WRITE' | /bin/busybox dd of=/dev/sr0 bs=8 count=1 >/tmp/write.log 2>&1;then
 fatal unsafe_optical_write_accepted
fi
echo "R26_P3_REAL_GUEST_OPTICAL_BLOCK_WRITE_DENIED=PASS kind=$kind"
/bin/busybox umount /mnt/disc || fatal unmount_failure
echo "R26_P3_REAL_GUEST_OPTICAL_UNMOUNT=PASS kind=$kind"
/bin/busybox poweroff -f
/bin/busybox sleep 6
exit 0
