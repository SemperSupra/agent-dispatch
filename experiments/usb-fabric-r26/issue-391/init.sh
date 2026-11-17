#!/bin/sh
# Actual kernel guest does all filesystem formatting and file I/O on
# synthetic USB storage. Never runs on the GitHub host or real media.
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
fail() {
 echo "R26_N2_GUEST_RESULT=RED reason=$1"
 /bin/busybox poweroff -f
 /bin/busybox sleep 5
 exit 90
}
/bin/busybox mkdir -p /proc /sys /dev /mnt/usb
/bin/busybox mount -t proc proc /proc || fail proc
/bin/busybox mount -t sysfs sysfs /sys || fail sysfs
/bin/busybox mount -t devtmpfs devtmpfs /dev || fail devtmpfs
for mod in xhci_pci xhci_hcd scsi_mod sd_mod usb_storage uas ext4 jbd2 mbcache;do
 /sbin/modprobe "$mod" >/dev/null 2>&1 || true
done
mode=""
for arg in $(/bin/busybox cat /proc/cmdline);do
 case "$arg" in r26_mode=*) mode="${arg#r26_mode=}" ;; esac
done
[ "$mode" = initial ] || [ "$mode" = second ] || [ "$mode" = verify ] || fail invalid_mode
tries=0
while [ "$tries" -lt 30 ];do
 [ -b /dev/sda ] && break
 tries=$((tries+1))
 /bin/busybox sleep 1
done
[ -b /dev/sda ] || fail no_usb_disk
echo "R26_N2_GUEST_USB_DISK_PRESENT=PASS mode=$mode"
[ "$(/bin/busybox cat /sys/class/block/sda/ro)" = 0 ] || fail disk_is_readonly
if ! /bin/busybox mount -t ext4 /dev/sda /mnt/usb 2>/dev/null;then
 [ "$mode" = initial ] || fail cannot_mount_existing_disk
 # No format of unknown or already-formatted media. Synthetic host starts
 # the backing file at all zeroes, so superblock magic must be all zeroes.
 magic="$(/bin/busybox dd if=/dev/sda bs=1 skip=1080 count=2 2>/dev/null | /bin/busybox od -An -tx1 | /bin/busybox tr -d ' \n')"
 [ "$magic" = 0000 ] || fail unknown_media_refuse_format
 /usr/sbin/mkfs.ext4 -F -q -L R26TEST /dev/sda || fail mkfs_failed
 /bin/busybox mount -t ext4 /dev/sda /mnt/usb || fail mount_formatted_failed
 echo R26_N2_ACTUAL_GUEST_EXT4_FORMAT=PASS
fi
stage=0
[ -f /mnt/usb/r26_stage ] && stage="$(/bin/busybox cat /mnt/usb/r26_stage)"
boot="$(/bin/busybox cat /proc/sys/kernel/random/boot_id)"
case "$mode:$stage" in
 initial:0)
  [ ! -e /mnt/usb/first.txt ] || fail unexpected_first_file
  echo R26_SYNTHETIC_ALPHA_2026 > /mnt/usb/first.txt
  echo "$boot" > /mnt/usb/first_boot_id
  echo 1 > /mnt/usb/r26_stage
  /bin/busybox sync
  /bin/busybox umount /mnt/usb || fail first_unmount
  echo R26_N2_GUEST_FILE_FIRST_WRITE_SYNC_UMOUNT=PASS
  /bin/busybox reboot -f
  /bin/busybox sleep 10
  ;;
 initial:1)
  [ "$(/bin/busybox cat /mnt/usb/first.txt)" = R26_SYNTHETIC_ALPHA_2026 ] || fail first_file_lost_on_reboot
  [ "$boot" != "$(/bin/busybox cat /mnt/usb/first_boot_id)" ] || fail no_kernel_reboot
  echo R26_N2_SAME_QEMU_KERNEL_REBOOT_FILE_PERSISTED=PASS
  echo R26_SYNTHETIC_BETA_2026 > /mnt/usb/second.txt
  echo 2 > /mnt/usb/r26_stage
  /bin/busybox sync
  /bin/busybox umount /mnt/usb || fail second_unmount
  echo R26_N2_SECOND_BOOT_FILE_WRITE_SYNC_UMOUNT=PASS
  /bin/busybox poweroff -f
  /bin/busybox sleep 5
  ;;
 second:2)
  [ "$(/bin/busybox cat /mnt/usb/first.txt)" = R26_SYNTHETIC_ALPHA_2026 ] || fail cross_instance_lost_alpha
  [ "$(/bin/busybox cat /mnt/usb/second.txt)" = R26_SYNTHETIC_BETA_2026 ] || fail cross_instance_lost_beta
  echo R26_N2_DIFFERENT_QEMU_VM_READ_PRIOR_FILES=PASS
  echo R26_SYNTHETIC_GAMMA_2026 > /mnt/usb/third.txt
  echo "$boot" > /mnt/usb/second_instance_boot_id
  echo 3 > /mnt/usb/r26_stage
  /bin/busybox sync
  /bin/busybox umount /mnt/usb || fail third_unmount
  echo R26_N2_DIFFERENT_QEMU_VM_WRITE_SYNC_UMOUNT=PASS
  /bin/busybox poweroff -f
  /bin/busybox sleep 5
  ;;
 verify:3)
  [ "$(/bin/busybox cat /mnt/usb/first.txt)" = R26_SYNTHETIC_ALPHA_2026 ] || fail alpha_mismatch
  [ "$(/bin/busybox cat /mnt/usb/second.txt)" = R26_SYNTHETIC_BETA_2026 ] || fail beta_mismatch
  [ "$(/bin/busybox cat /mnt/usb/third.txt)" = R26_SYNTHETIC_GAMMA_2026 ] || fail gamma_mismatch
  [ "$boot" != "$(/bin/busybox cat /mnt/usb/second_instance_boot_id)" ] || fail no_new_instance
  echo R26_N2_THIRD_QEMU_INSTANCE_ALL_THREE_FILES_VALID=PASS
  /bin/busybox sha256sum /mnt/usb/first.txt /mnt/usb/second.txt /mnt/usb/third.txt
  /bin/busybox umount /mnt/usb || fail final_umount
  /bin/busybox poweroff -f
  /bin/busybox sleep 5
  ;;
 *) fail unexpected_stage_or_reformat_attempt ;;
esac
exit 0
