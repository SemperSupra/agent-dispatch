#!/usr/bin/env bash
# R33 K2a public synthetic: can unmodified Ubuntu OVMF discover and EFI-boot
# an actual QEMU SDHCI/eMMC *user-area* GPT+FAT ESP with NO USB/SATA fallback?
# This experiment does not execute Linux, production signing, or owner media.
set -Eeuo pipefail
umask 077
test -n "$RUNNER_TEMP"
test -n "$GITHUB_SHA"
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
W=$(mktemp -d "$RUNNER_TEMP/wyse-emmc-ovmf-XXXXXX")
mkdir -p evidence/public "$W/mnt"
cleanup() {
  sudo umount "$W/mnt" 2>/dev/null || :
  if test -n "$loop"; then sudo losetup -d "$loop" 2>/dev/null || :; fi
  rm -rf -- "$W"
}
loop=''
trap cleanup EXIT
echo "R33_SOURCE_HEAD=$GITHUB_SHA"
echo 'R33_SCOPE=PUBLIC_QEMU_EMMC_UEFI_ENUMERATION_ONLY'
qemu-system-x86_64 --version | head -n 1
test -f /usr/share/OVMF/OVMF_CODE_4M.fd
test -f /usr/share/OVMF/OVMF_VARS_4M.fd
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$W/vars.fd"
cat > "$W/grub.cfg" <<'GRUB'
serial --unit=0 --speed=115200
terminal_input console serial
terminal_output console serial
echo R33_EMMC_UEFI_BOOT_FROM_USER_AREA=PASS
sleep 3
halt
GRUB
grub-mkstandalone -O x86_64-efi -o "$W/BOOTX64.EFI" \
  --modules="part_gpt fat serial terminal echo" \
  "boot/grub/grub.cfg=$W/grub.cfg" > evidence/public/grub-build.txt 2>&1
test -s "$W/BOOTX64.EFI"
# QEMU eMMC backing order: boot0 1MiB, boot1 1MiB, RPMB 2MiB,
# then user region exactly 256MiB (power-of-two requirement).
truncate -s 256M "$W/user.raw"
sgdisk --zap-all --clear -n 1:2048:+128M -t 1:ef00 "$W/user.raw" > evidence/public/partition-layout.txt
loop=$(sudo losetup --find --partscan --show "$W/user.raw")
test "$(lsblk -ndo TYPE "$loop")" = loop
back=$(sudo losetup -n -O BACK-FILE "$loop" | xargs)
test "$(readlink -f "$back")" = "$(readlink -f "$W/user.raw")"
sudo udevadm settle
sudo mkfs.vfat -F 32 -n WYSEEMMC "$loop"p1 > evidence/public/mkfs-public.txt
sudo mount "$loop"p1 "$W/mnt"
sudo mkdir -p "$W/mnt/EFI/BOOT"
sudo cp "$W/BOOTX64.EFI" "$W/mnt/EFI/BOOT/BOOTX64.EFI"
sudo cmp "$W/BOOTX64.EFI" "$W/mnt/EFI/BOOT/BOOTX64.EFI"
sudo sync
sudo umount "$W/mnt"
sudo losetup -d "$loop"
loop=''
truncate -s 260M "$W/emmc.raw"
dd if="$W/user.raw" of="$W/emmc.raw" bs=4M seek=1 conv=notrunc status=none
test "$(stat -c %s "$W/emmc.raw")" -eq 272629760
echo "R33_EMMC_SYNTHETIC_IMAGE_SHA256=$(sha256sum "$W/emmc.raw" | cut -d' ' -f1)"
echo 'R33_NO_USB_SATA_OR_NETWORK_FALLBACK=PASS'
accel=tcg
if test -w /dev/kvm; then accel=kvm; fi
# This VM has ONE bootable block device: SDHCI+QEMU eMMC. OVMF's
# ability to enumerate it is the subject, not a foregone conclusion.
timeout -s TERM -k 5 50s qemu-system-x86_64 \
  -machine q35 -accel "$accel" -cpu max -m 1024 -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$W/vars.fd" \
  -drive if=none,id=emmc,format=raw,file="$W/emmc.raw" \
  -device sdhci-pci \
  -device emmc,drive=emmc,boot-partition-size=1048576,rpmb-partition-size=2097152 \
  -net none -display none -monitor none \
  -serial file:evidence/public/emmc-ovmf-serial.txt -no-reboot \
  > evidence/public/emmc-ovmf-qemu-log.txt 2>&1 || :
# QEMU/OVMF reports BdsDxe eMMC User Data before GRUB executes.
# GRUB may echo to serial and console on the SAME line; accept a bounded
# guest-only substring, but never a host-only echoed marker. Require both.
if grep -Eq 'BdsDxe: starting Boot[0-9]{4}.*eMMC User Data.*PciRoot.*/eMMC\(' evidence/public/emmc-ovmf-serial.txt \
   && grep -Fq 'R33_EMMC_UEFI_BOOT_FROM_USER_AREA=PASS' evidence/public/emmc-ovmf-serial.txt; then
  echo 'R33_OVMF_CONFIRMED_BOOT_ENTRY_EMMC_USER_AREA=PASS'
  echo 'R33_GRUB_EFI_ACTUAL_EMMC_GUEST_SERIAL=PASS'
  echo 'R33_QEMU_OVMF_EMMC_UEFI_BOOT=PASS'
else
  echo 'R33_QEMU_OVMF_EMMC_UEFI_BOOT=RED_UNPROVEN' >&2
  echo 'R33_QEMU_OVMF_MISSING_SDMMC_DRIVER_OR_LAYOUT=NOT_DETERMINED' >&2
  tail -n 65 evidence/public/emmc-ovmf-serial.txt >&2 || :
  exit 1
fi
echo 'R33_SIGNED_LINUX_KERNEL_ON_EMMC=NOT_TESTED'
echo 'R33_PHYSICAL_DELL_EMMC_BOOTORDER_AND_PRODUCTION_KEYS=NOT_TESTED'
