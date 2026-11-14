#!/usr/bin/env bash
set -Eeuo pipefail
mkdir -p evidence/public evidence/private
echo 'PUBLIC_SYNTHETIC_ONLY=YES' > evidence/public/receipt.txt
qemu-system-x86_64 --version | head -1 >> evidence/public/receipt.txt
echo "KVM=$(test -w /dev/kvm && echo YES || echo NO)" >> evidence/public/receipt.txt
make_disk() {
  name="$1"; marker="$2"
  test "$name" = usb || test "$name" = sata
  disk="$PWD/evidence/private/$name.img"
  truncate -s 256M "$disk"
  sgdisk --zap-all --clear -n 1:2048:+128M -t 1:ef00 "$disk" >/dev/null
  loop="$(sudo losetup --find --partscan --show "$disk")"
  test "$(lsblk -nd -o TYPE "$loop")" = loop
  back="$(sudo losetup -n -O BACK-FILE "$loop" | xargs)"
  test "$(readlink -f "$back")" = "$(readlink -f "$disk")"
  sudo mkfs.vfat -F 32 "$loop"p1 >/dev/null
  mkdir -p "evidence/private/$name-cfg" "evidence/private/$name-esp/EFI/BOOT" "evidence/private/$name-mnt"
  printf 'serial --unit=0 --speed=115200\nterminal_output console serial\necho %s\nsleep 10\n' "$marker" > "evidence/private/$name-cfg/grub.cfg"
  grub-mkstandalone -O x86_64-efi -o "evidence/private/$name-esp/EFI/BOOT/BOOTX64.EFI" --modules="part_gpt fat serial terminal echo sleep" \
    "boot/grub/grub.cfg=evidence/private/$name-cfg/grub.cfg"
  sudo mount "$loop"p1 "evidence/private/$name-mnt"
  sudo mkdir -p "evidence/private/$name-mnt/EFI/BOOT"
  sudo cp "evidence/private/$name-esp/EFI/BOOT/BOOTX64.EFI" "evidence/private/$name-mnt/EFI/BOOT/BOOTX64.EFI"
  sudo sync
  sudo umount "evidence/private/$name-mnt"
  sudo losetup -d "$loop"
  sgdisk -v "$disk" > "evidence/public/$name-gpt.txt"
  printf '%s_IMAGE_SHA256=%s\n' "$name" "$(sha256sum "$disk" | cut -d' ' -f1)" >> evidence/public/receipt.txt
}
make_disk usb WYSE_RECOVERY_USB_SYNTHETIC_BOOT
make_disk sata WYSE_SATA_DISPOSABLE_SYNTHETIC_BOOT
truncate -s 128M evidence/private/emmc.img
sgdisk --zap-all --clear -n 1:2048:+32M -t 1:8300 evidence/private/emmc.img >/dev/null
echo -n 'IMMUTABLE_EMMC_SENTINEL' | dd of=evidence/private/emmc.img bs=1 seek=16777216 conv=notrunc status=none
sha256sum evidence/private/emmc.img > evidence/private/emmc.sha256
dd if=evidence/private/usb.img of=evidence/private/usb-flashed.img bs=4M status=none
cmp evidence/private/usb.img evidence/private/usb-flashed.img
echo 'USB_RAW_IMAGE_WRITE_READBACK=PASS' >> evidence/public/receipt.txt
python3 - <<'PY'
from pathlib import Path
p=Path("evidence/private")
allowed=(p/"sata.img").resolve()
assert all((p/x).resolve()!=allowed for x in ("emmc.img","usb.img","usb-flashed.img"))
with open(allowed,"r+b") as f:
 f.seek(200*1024*1024) # beyond the EFI partition; preserve bootloader
 f.write(b"DISPOSABLE_SATA_ONLY")
PY
sha256sum -c evidence/private/emmc.sha256
echo 'SATA_WRITE_EMMC_UNCHANGED=PASS' >> evidence/public/receipt.txt
qemu-system-x86_64 -device help > evidence/public/devices.txt
EMMC=none
if grep -Eq 'name "emmc"|name emmc' evidence/public/devices.txt; then EMMC=emmc
elif grep -Eq 'name "sd-card"|name sd-card' evidence/public/devices.txt; then EMMC=sd-card
fi
echo "QEMU_EMMC_DEVICE_MODEL=$EMMC" >> evidence/public/receipt.txt
code=/usr/share/OVMF/OVMF_CODE_4M.fd
vars=/usr/share/OVMF/OVMF_VARS_4M.fd
if test ! -r "$code"; then code=/usr/share/OVMF/OVMF_CODE.fd; vars=/usr/share/OVMF/OVMF_VARS.fd; fi
test -r "$code" && test -r "$vars"
accel=tcg
test -w /dev/kvm && accel=kvm
for case in usb-first sata-fallback; do
  cp "$vars" "evidence/private/$case-vars.fd"
  set -- -device ich9-ahci,id=satactl -drive if=none,id=ssd,format=raw,file=evidence/private/sata.img -device ide-hd,bus=satactl.0,drive=ssd,bootindex=2
  if test "$case" = usb-first; then
    set -- "$@" -drive if=none,id=usb,format=raw,readonly=on,file=evidence/private/usb-flashed.img \
      -device qemu-xhci,id=usbctl -device usb-storage,bus=usbctl.0,drive=usb,bootindex=1
  fi
  if test "$EMMC" != none; then
    set -- "$@" -drive if=none,id=emmc,format=raw,readonly=on,file=evidence/private/emmc.img \
      -device sdhci-pci,id=sdhci -device "$EMMC",drive=emmc
  fi
  timeout 32 qemu-system-x86_64 -machine q35 -accel "$accel" -cpu max -m 768 -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file="$code" \
    -drive if=pflash,format=raw,file="evidence/private/$case-vars.fd" \
    "$@" -display none -monitor none -serial "file:evidence/public/$case-serial.txt" -no-reboot \
    > "evidence/public/$case-qemu.log" 2>&1 || true
  if test "$case" = usb-first; then marker=WYSE_RECOVERY_USB_SYNTHETIC_BOOT
  else marker=WYSE_SATA_DISPOSABLE_SYNTHETIC_BOOT
  fi
  if grep -q "$marker" "evidence/public/$case-serial.txt"; then
    echo "$case=BOOT_PASS" >> evidence/public/receipt.txt
  else
    echo "$case=BOOT_FAIL" >> evidence/public/receipt.txt
    tail -n 30 "evidence/public/$case-qemu.log"
    exit 1
  fi
done
sha256sum -c evidence/private/emmc.sha256
echo 'EMMC_UNCHANGED_AFTER_UEFI_BOOT=PASS' >> evidence/public/receipt.txt
echo 'DELL_SPECIFIC_EMMC_AND_SECUREBOOT=UNQUALIFIED' >> evidence/public/receipt.txt
