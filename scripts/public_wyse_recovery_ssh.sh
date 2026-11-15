#!/usr/bin/env bash
# Public-synthetic-only: UEFI USB -> real Linux initramfs -> key-only SSH,
# native eMMC and SATA behind QEMU; no physical media or private source.
set -Eeuo pipefail
trap 'echo "SYNTHETIC_RECOVERY_FAILURE_LINE=$LINENO" >&2' ERR
umask 077
mkdir -p evidence/public evidence/private/{root,work}
R="$PWD/evidence/private/root"; W="$PWD/evidence/private/work"
echo 'SCOPE=PUBLIC_SYNTHETIC_ONLY' > evidence/public/receipt.txt
qemu-system-x86_64 --version | head -1 >> evidence/public/receipt.txt
kernel=''
version=''
for candidate in /boot/vmlinuz-*; do
  v=$(basename "$candidate" | sed 's/^vmlinuz-//')
  if test -f "$candidate" && test -d "/lib/modules/$v"; then kernel="$candidate"; version="$v"; fi
done
test -n "$kernel"
sudo cp "$kernel" "$W/vmlinuz"
sudo chown "$(id -u):$(id -g)" "$W/vmlinuz"
echo "LINUX_VERSION=$version" >> evidence/public/receipt.txt
for folder in bin sbin usr/sbin usr/bin etc/dropbear root/.ssh dev proc sys run lib/modules; do mkdir -p "$R/$folder"; done
cp "$(command -v busybox)" "$R/bin/busybox"
for app in sh ip modprobe sleep mount; do ln -s busybox "$R/bin/$app"; done
DROP=$(command -v dropbear)
test -n "$DROP"
mkdir -p "$R$(dirname "$DROP")"
cp "$DROP" "$R$DROP"
for binary in "$DROP" "$(command -v busybox)" "$(command -v modprobe)"; do
  (ldd "$binary" 2>/dev/null || :) | (grep -oE '/[^[:space:]()]+' || :) | sort -u | while read -r lib; do
    if test -f "$lib"; then mkdir -p "$R$(dirname "$lib")"; cp -L "$lib" "$R$lib"; fi
  done
done
# Only ship the module dependency closure for this QEMU recovery topology.
# A full distro modules tree causes huge initramfs unpacking and is not
# appropriate for the Wyse recovery resource budget.
mkdir -p "$R/lib/modules/$version"
for metadata in /lib/modules/"$version"/modules.*; do
  test -f "$metadata" || continue
  cp -L "$metadata" "$R/lib/modules/$version/"
done
for mod in sdhci_pci sdhci mmc_block ahci libahci sd_mod e1000 usb_storage; do
  modprobe -S "$version" --show-depends "$mod" || :
done > evidence/public/modprobe-deps.txt
awk '$1 == "insmod" {print $2}' evidence/public/modprobe-deps.txt | sort -u | while read -r module; do
  test -f "$module" || continue
  mkdir -p "$R$(dirname "$module")"
  cp -L "$module" "$R$module"
done
cp -L "$(command -v modprobe)" "$R/sbin/modprobe"
echo "MODULE_FILE_COUNT=$(find "$R/lib/modules/$version" -type f | wc -l)" >> evidence/public/receipt.txt
ssh-keygen -q -t ed25519 -N '' -f "$W/id_ed25519"
dropbearkey -t ed25519 -f "$W/host_ed25519" > evidence/public/dropbearkey-build.txt 2>&1
cp "$W/id_ed25519.pub" "$R/root/.ssh/authorized_keys"
cp "$W/host_ed25519" "$R/etc/dropbear/dropbear_ed25519_host_key"
chmod 0700 "$R/root/.ssh"
chmod 0600 "$R/root/.ssh/authorized_keys" "$R/etc/dropbear/dropbear_ed25519_host_key"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$R/etc/passwd"
printf 'root:x:0:\n' > "$R/etc/group"
cat > "$R/init" <<'INIT'
#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
/bin/mount -t proc proc /proc
/bin/mount -t sysfs sysfs /sys
/bin/mount -t devtmpfs devtmpfs /dev
/bin/busybox --install -s /bin
echo 'WYSE_SYNTHETIC_LINUX_INIT=PASS'
for module in sdhci_pci sdhci mmc_block ahci libahci sd_mod e1000 usb_storage; do
  /sbin/modprobe "$module" 2>&1 || echo "MODULE_MISSING:$module"
done
/bin/sleep 4
for node in /sys/block/mmcblk*; do
  test -d "$node" && echo "EMMC_ENUMERATION=PASS" && break
done
for node in /sys/block/sd[a-z]*; do
  test -d "$node" && echo "SATA_ENUMERATION=PASS" && break
done
nic=''
for node in /sys/class/net/*; do
  iface=$(basename "$node")
  if test "$iface" != lo; then nic="$iface"; break; fi
done
test -n "$nic" || { echo 'NIC_MISSING'; exec /bin/sh; }
/bin/ip link set lo up
/bin/ip link set "$nic" up
/bin/ip addr add 10.0.2.15/24 dev "$nic"
/bin/ip route add default via 10.0.2.2
echo 'RECOVERY_NETWORK_READY=PASS'
/usr/sbin/dropbear -F -E -s -g -p 22 -r /etc/dropbear/dropbear_ed25519_host_key
INIT
chmod 0755 "$R/init"
(cd "$R" && find . -print0 | cpio --null -o -H newc --quiet | gzip -1 > "$W/initrd.gz")
echo "INITRD_BYTES=$(stat -c %s "$W/initrd.gz")" >> evidence/public/receipt.txt
mkdir -p "$W/efi/EFI/BOOT"
cat > "$W/grub.cfg" <<'GRUB'
serial --unit=0 --speed=115200
terminal_input console serial
terminal_output console serial
search --no-floppy --label WYSETEST --set=usb
echo WYSE_SYNTHETIC_UEFI_LOADER=PASS
linux ($usb)/vmlinuz console=ttyS0 rdinit=/init panic=2
initrd ($usb)/initrd.gz
boot
GRUB
grub-mkstandalone -O x86_64-efi -o "$W/efi/EFI/BOOT/BOOTX64.EFI" \
  --modules="part_gpt fat search search_label linux serial terminal echo" \
  "boot/grub/grub.cfg=$W/grub.cfg" > evidence/public/grub-build.txt 2>&1
truncate -s 768M "$W/usb.img"
sgdisk --zap-all --clear -n 1:2048:+650M -t 1:ef00 "$W/usb.img" >/dev/null
loop=$(sudo losetup --find --partscan --show "$W/usb.img")
trap 'sudo umount "$W/mnt" 2>/dev/null || :; sudo losetup -d "$loop" 2>/dev/null || :' EXIT
test "$(lsblk -ndo TYPE "$loop")" = loop
back=$(sudo losetup -n -O BACK-FILE "$loop" | xargs)
test "$(readlink -f "$back")" = "$(readlink -f "$W/usb.img")"
sudo udevadm settle
sudo mkfs.vfat -F 32 -n WYSETEST "$loop"p1 > /dev/null
mkdir -p "$W/mnt"
sudo mount "$loop"p1 "$W/mnt"
sudo cp -r "$W/efi/EFI" "$W/mnt/"
sudo cp "$W/vmlinuz" "$W/initrd.gz" "$W/mnt/"
sudo sync
sudo umount "$W/mnt"
sudo losetup -d "$loop"
trap - EXIT
dd if="$W/usb.img" of="$W/usb-copy.img" bs=8M status=none
cmp "$W/usb.img" "$W/usb-copy.img"
echo 'RAW_USB_WRITE_READBACK=PASS' >> evidence/public/receipt.txt
truncate -s 260M "$W/emmc-original.img" # 256MiB user + boot0/boot1 1MiB each + RPMB 2MiB
truncate -s 128M "$W/sata.img"
printf 'PROTECTED_EMMC_CANARY' | dd of="$W/emmc-original.img" bs=1 seek=18874368 conv=notrunc status=none
sha256sum "$W/emmc-original.img" > "$W/emmc-sha"
cp "$W/emmc-original.img" "$W/emmc-guest.img"
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$W/vars.fd"
accel=tcg
if test -w /dev/kvm; then accel=kvm; fi
qemu-system-x86_64 -machine q35 -accel "$accel" -cpu max -m 3072 -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$W/vars.fd" \
  -drive if=none,id=usb,format=raw,readonly=on,file="$W/usb-copy.img" \
  -device qemu-xhci,id=usbctl -device usb-storage,bus=usbctl.0,drive=usb,bootindex=1 \
  -drive if=none,id=emmc,format=raw,file="$W/emmc-guest.img" \
  -device sdhci-pci -device emmc,drive=emmc,boot-partition-size=1048576,rpmb-partition-size=2097152 \
  -device ich9-ahci,id=ahci -drive if=none,id=ssd,format=raw,file="$W/sata.img" \
  -device ide-hd,bus=ahci.0,drive=ssd,bootindex=2 \
  -netdev user,id=n,hostfwd=tcp:127.0.0.1:22222-:22 -device e1000,netdev=n \
  -display none -monitor none -serial file:evidence/public/guest-serial.txt -no-reboot \
  > evidence/public/qemu-log.txt 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || :' EXIT
success=0
for attempt in $(seq 1 105); do
  if ssh -q -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=1 -p 22222 -i "$W/id_ed25519" \
      root@127.0.0.1 'echo KEY_ONLY_SSH_LOGIN=PASS; grep -q mmcblk0 /proc/partitions && echo GUEST_EMMC=PASS; grep -q sda /proc/partitions && echo GUEST_SATA=PASS' \
      > evidence/public/ssh-oracle.txt 2> evidence/public/ssh-errors.txt; then success=1; break; fi
  sleep 1
done
kill "$pid" 2>/dev/null || :
wait "$pid" 2>/dev/null || :
trap - EXIT
sha256sum -c "$W/emmc-sha"
test "$success" -eq 1 || { tail -n 50 evidence/public/guest-serial.txt; exit 1; }
for marker in WYSE_SYNTHETIC_UEFI_LOADER=PASS WYSE_SYNTHETIC_LINUX_INIT=PASS EMMC_ENUMERATION=PASS SATA_ENUMERATION=PASS RECOVERY_NETWORK_READY=PASS; do
  grep -q "$marker" evidence/public/guest-serial.txt || { echo "MISSING:$marker"; exit 1; }
done
for marker in KEY_ONLY_SSH_LOGIN=PASS GUEST_EMMC=PASS GUEST_SATA=PASS; do
  grep -q "$marker" evidence/public/ssh-oracle.txt || exit 1
done
echo 'UEFI_USB_LINUX_EMMC_SATA_SSH=PASS' >> evidence/public/receipt.txt
echo 'EMMC_SOURCE_PRESERVED=PASS' >> evidence/public/receipt.txt
echo 'SIGNED_PRODUCTION_IMAGE=NOT_TESTED' >> evidence/public/receipt.txt
echo 'DELL_FIRMWARE_AND_PHYSICAL_TPM=NOT_TESTED' >> evidence/public/receipt.txt
