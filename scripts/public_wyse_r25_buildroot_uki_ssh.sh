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
if test -n "${WYSE_R29_OWNED_KERNEL_BZIMAGE:-}"; then
  # R29 K1: use the independently built Buildroot Linux 6.12.113 kernel,
  # never Ubuntu host kernel/modules. Checked source build provides drivers built-in.
  test -s "$WYSE_R29_OWNED_KERNEL_BZIMAGE"
  kernel="$WYSE_R29_OWNED_KERNEL_BZIMAGE"
  version='6.12.113'
  echo 'R29_SOURCE_OWNED_KERNEL_SELECTED=PASS' >> evidence/public/receipt.txt
else
  for candidate in /boot/vmlinuz-*; do
    v=$(basename "$candidate" | sed 's/^vmlinuz-//')
    if test -f "$candidate" && test -d "/lib/modules/$v"; then kernel="$candidate"; version="$v"; fi
  done
fi
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
if test -z "${WYSE_R29_OWNED_KERNEL_BZIMAGE:-}"; then
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
else
  : > evidence/public/modprobe-deps.txt
  echo 'R29_NO_UBUNTU_TEST_MODULES=PASS' >> evidence/public/receipt.txt
fi
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
  test -d "$node" || continue
  disk_path=$(cd "$node/device" 2>/dev/null && pwd -P) || { echo 'BLOCK_BUS_IDENTITY_UNKNOWN=RED'; continue; }
  case "$disk_path" in
    */ata[0-9]*/*) echo "SATA_ENUMERATION=PASS"; break ;;
    */usb[0-9]*/*) echo "USB_BOOT_STORAGE_ENUMERATION=PASS" ;;
    *) echo "BLOCK_BUS_IDENTITY_UNSUPPORTED=RED" ;;
  esac
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
# R25: Actual pinned Buildroot BusyBox+Dropbear userland with host test kernel.
# Retain experimental distinction from a standalone production Buildroot UKI.
if test -n "${WYSE_R25_BUILDROOT_CPIO:-}"; then
  test -s "$WYSE_R25_BUILDROOT_CPIO"
  B="$W/buildroot-unpacked"
  mkdir -p "$B"
  # Buildroot's original cpio includes a /dev/console character device.
  # An unprivileged extraction cannot mknod it. Permit only a bounded
  # disposable directory inside the public workcell; device bytes are never
  # attached to any real Wyse host or production storage.
  case "$(readlink -f "$B")" in
    "$(readlink -f "$PWD/evidence/private/work")"/*) ;;
    *) echo 'R25_EXTRACTION_PATH_OUTSIDE_WORKCELL=DENIED' >&2; exit 7 ;;
  esac
  (cd "$B" && sudo cpio -idmu --no-absolute-filenames --quiet < "$WYSE_R25_BUILDROOT_CPIO")
  sudo chown -R "$(id -u):$(id -g)" "$B"
  test -c "$B/dev/console"
  test -x "$B/bin/busybox"
  test -x "$B/usr/sbin/dropbear"
  test -x "$B/etc/init.d/S50dropbear"
  test -x "$B/etc/init.d/S01wyse-volatile"
  mkdir -p "$B/lib/modules" "$B/etc/wyse-ci-fixture"
  cp -a "$R/lib/modules/$version" "$B/lib/modules/"
  # R25 synthetic-only module fixture: materialize an exact, ordered,
  # decompressed kernel-module dependency closure on the host and use the
  # actual Buildroot BusyBox insmod in the guest. No Ubuntu dynamic loader
  # is shipped into recovery userland. This is NOT a production kernel.
  MODULE_LIST="$B/etc/wyse-ci-fixture/kernel-module-order.txt"
  : > "$MODULE_LIST"
  if test -n "${WYSE_R29_OWNED_KERNEL_BZIMAGE:-}"; then
    # Required recovery drivers were checked as builtin =y by R28 K0.
    # Guest must demonstrate eMMC, SATA, network and SSH with this kernel.
    : > "$MODULE_LIST"
    : > "$B/etc/wyse-ci-fixture/owned-kernel-builtins"
    echo 'R29_KERNEL_MODULE_LIST_EMPTY_BY_DESIGN=PASS' >> evidence/public/receipt.txt
  else
    awk '$1=="insmod" && !seen[$2]++ {print $2}' evidence/public/modprobe-deps.txt > "$W/ordered-test-modules.txt"
    while IFS= read -r module; do
      case "$module" in /lib/modules/"$version"/*) ;; *) echo "R25_BAD_MODULE_SOURCE:$module" >&2; exit 10 ;; esac
      test -f "$module" || { echo "R25_MODULE_SOURCE_MISSING:$module" >&2; exit 11; }
      raw="${module%.zst}"
      mkdir -p "$B$(dirname "$raw")"
      case "$module" in
        *.ko.zst) zstd -q -dc "$module" > "$B$raw" ;;
        *.ko) cp -L "$module" "$B$raw" ;;
        *) echo "R25_UNSUPPORTED_MODULE_FORMAT:$module" >&2; exit 12 ;;
      esac
      test -s "$B$raw"
      printf '%s\n' "$raw" >> "$MODULE_LIST"
    done < "$W/ordered-test-modules.txt"
    test -s "$MODULE_LIST"
    echo "R25_TEST_MODULE_COUNT=$(wc -l < "$MODULE_LIST")" >> evidence/public/receipt.txt
    echo 'R25_BUILDROOT_BUSYBOX_MODULE_LOAD_FIXTURE=STAGED' >> evidence/public/receipt.txt
  fi
  cp "$W/host_ed25519" "$B/etc/wyse-ci-fixture/ssh_host_ed25519_key"
  cp "$W/id_ed25519.pub" "$B/etc/wyse-ci-fixture/authorized_keys"
  cat > "$B/init" <<'BUILDROOT_INIT'
#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox --install -s /bin
echo 'WYSE_SYNTHETIC_LINUX_INIT=PASS'
echo 'WYSE_R25_BUILDROOT_USERLAND_INIT=PASS'
module_failed=0
while IFS= read -r module; do
  if ! /bin/busybox insmod "$module"; then
    echo "R25_BUILDROOT_INSMOD_FAILED:$module"
    module_failed=1
  fi
done < /etc/wyse-ci-fixture/kernel-module-order.txt
if [ "$module_failed" -ne 0 ]; then
  echo 'R25_BUILDROOT_MODULE_CLOSURE=RED'
  exec /bin/sh
fi
if [ -f /etc/wyse-ci-fixture/owned-kernel-builtins ]; then
  echo 'R29_BUILTIN_DRIVER_INIT=PASS'
else
  echo 'R25_BUILDROOT_MODULE_CLOSURE=PASS'
fi
/bin/busybox sleep 4
for node in /sys/block/mmcblk*; do
  test -d "$node" && echo 'EMMC_ENUMERATION=PASS' && break
done
for node in /sys/block/sd[a-z]*; do
  test -d "$node" || continue
  disk_path=$(cd "$node/device" 2>/dev/null && pwd -P) || { echo 'BLOCK_BUS_IDENTITY_UNKNOWN=RED'; continue; }
  case "$disk_path" in
    */ata[0-9]*/*) echo 'SATA_ENUMERATION=PASS'; break ;;
    */usb[0-9]*/*) echo 'USB_BOOT_STORAGE_ENUMERATION=PASS' ;;
    *) echo 'BLOCK_BUS_IDENTITY_UNSUPPORTED=RED' ;;
  esac
done
nic=''
for node in /sys/class/net/*; do
  iface=$(basename "$node")
  if test "$iface" != lo; then nic="$iface"; break; fi
done
test -n "$nic" || { echo NIC_MISSING; exec /bin/sh; }
/bin/busybox ip link set lo up
/bin/busybox ip link set "$nic" up
/bin/busybox ip addr add 10.0.2.15/24 dev "$nic"
/bin/busybox ip route add default via 10.0.2.2
echo 'RECOVERY_NETWORK_READY=PASS'
/etc/init.d/S01wyse-volatile start || { echo WYSE_R25_VOLATILE_INIT=RED; exec /bin/sh; }
cp /etc/wyse-ci-fixture/ssh_host_ed25519_key /run/wyse-keys/ssh_host_ed25519_key
cp /etc/wyse-ci-fixture/authorized_keys /run/wyse-keys/authorized_keys
chmod 600 /run/wyse-keys/ssh_host_ed25519_key /run/wyse-keys/authorized_keys
echo 'R25_SSH_SERVICE_PRECHECK=BEGIN'
echo "R25_SSH_HOST_KEY_MODE=$(stat -c %a /run/wyse-keys/ssh_host_ed25519_key 2>/dev/null || echo unavailable)"
echo "R25_SSH_KEY_ALLOWLIST_MODE=$(stat -c %a /run/wyse-keys/authorized_keys 2>/dev/null || echo unavailable)"
/usr/sbin/dropbear -V 2>&1 || echo 'R25_DROPBEAR_EXECUTABLE_VERSION_PROBE=RED'
if ! /bin/sh -x /etc/init.d/S50dropbear start; then
  echo 'WYSE_R25_BUILDROOT_DROPBEAR=RED'
  exec /bin/sh
fi
echo 'WYSE_R25_BUILDROOT_DROPBEAR_STARTED=PASS'
exec /bin/sh
BUILDROOT_INIT
  chmod 0755 "$B/init"
  R="$B"
  echo 'R25_BUILDROOT_ROOTFS_INJECTED=PASS' >> evidence/public/receipt.txt
  if test -n "${WYSE_R29_OWNED_KERNEL_BZIMAGE:-}"; then
    echo 'R29_UBUNTU_TEST_KERNEL_MODULES=ABSENT' >> evidence/public/receipt.txt
  else
    echo 'R25_UBUNTU_TEST_KERNEL_MODULES=TRUE_NOT_PRODUCTION=TRUE' >> evidence/public/receipt.txt
  fi
fi
(cd "$R" && find . -print0 | cpio --null -o -H newc --owner=0:0 --quiet | gzip -1 > "$W/initrd.gz")
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
if test "${WYSE_R23_UKI:-0}" = 1; then
  if command -v ukify >/dev/null 2>&1; then UKIFY=$(command -v ukify); else UKIFY=/usr/lib/systemd/ukify; fi
  test -x "$UKIFY"
  "$UKIFY" build --linux="$W/vmlinuz" --initrd="$W/initrd.gz" \
    --cmdline="console=ttyS0 rdinit=/init panic=2" \
    --output="$W/efi/EFI/BOOT/BOOTX64.EFI" > evidence/public/ukify-build.txt 2>&1
  "$UKIFY" inspect "$W/efi/EFI/BOOT/BOOTX64.EFI" > evidence/public/ukify-inspect.txt 2>&1
  for section in .linux .initrd .cmdline; do
    grep -Fq "$section" evidence/public/ukify-inspect.txt || { echo "UKI_MISSING:$section"; exit 1; }
  done
  echo 'R23_UKI_EMBEDDED_KERNEL_INITRD_CMDLINE=PASS' >> evidence/public/receipt.txt
else
  grub-mkstandalone -O x86_64-efi -o "$W/efi/EFI/BOOT/BOOTX64.EFI" \
    --modules="part_gpt fat search search_label linux serial terminal echo" \
    "boot/grub/grub.cfg=$W/grub.cfg" > evidence/public/grub-build.txt 2>&1
fi
# R23: Public synthetic EFI signature proof. Ephemeral test key only.
# OVMF below does NOT enroll this signer. Signature plus boot does not
# prove Secure Boot firmware enforcement or hardware applicability.
if test "$WYSE_R23_SIGNED_EFI" = 1; then
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 1 \
    -subj '/CN=Wyse R23 ephemeral CI EFI signer NOT TRUSTED' \
    -keyout "$W/ephemeral-sb.key" -out "$W/ephemeral-sb.crt" \
    > "$W/openssl-build.log" 2>&1
  chmod 0600 "$W/ephemeral-sb.key"
  cp "$W/efi/EFI/BOOT/BOOTX64.EFI" "$W/unsigned-efi.efi"
  sbsign --key "$W/ephemeral-sb.key" --cert "$W/ephemeral-sb.crt" \
    --output "$W/efi/EFI/BOOT/BOOTX64.EFI.signed" \
    "$W/efi/EFI/BOOT/BOOTX64.EFI" > "$W/sign.log" 2>&1
  mv "$W/efi/EFI/BOOT/BOOTX64.EFI.signed" "$W/efi/EFI/BOOT/BOOTX64.EFI"
  sbverify --cert "$W/ephemeral-sb.crt" "$W/efi/EFI/BOOT/BOOTX64.EFI" \
    > evidence/public/efi-signature-oracle.txt 2>&1
  echo 'R23_SIGNED_EFI_SIGNATURE_VERIFIED=PASS' >> evidence/public/receipt.txt
  cp "$W/efi/EFI/BOOT/BOOTX64.EFI" "$W/forged-efi.bin"
  printf X | dd of="$W/forged-efi.bin" bs=1 seek=4096 conv=notrunc status=none
  if sbverify --cert "$W/ephemeral-sb.crt" "$W/forged-efi.bin" \
      > "$W/forged-verification.txt" 2>&1; then
    echo 'R23_TAMPERED_EFI_SIGNATURE_REFUSAL=FAIL_OPEN' >> evidence/public/receipt.txt
    exit 1
  fi
  echo 'R23_TAMPERED_EFI_SIGNATURE_REFUSAL=PASS' >> evidence/public/receipt.txt
  echo "R23_EPHEMERAL_SIGNER_CERT_SHA256=$(openssl x509 -in "$W/ephemeral-sb.crt" -fingerprint -sha256 -noout | cut -d= -f2)" >> evidence/public/receipt.txt
  rm -f "$W/ephemeral-sb.key"
fi

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
ovmf_code=/usr/share/OVMF/OVMF_CODE_4M.fd
ovmf_machine=q35
if test "${WYSE_R23_ENFORCE_SB:-0}" = 1; then
  test "${WYSE_R23_SIGNED_EFI:-0}" = 1
  command -v virt-fw-vars
  ovmf_code=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
  ovmf_machine=q35,smm=on
  test -f "$ovmf_code"
  virt-fw-vars --input /usr/share/OVMF/OVMF_VARS_4M.fd \
    --output "$W/vars.fd" --enroll-cert "$W/ephemeral-sb.crt" \
    --add-db 603b0819-1cf7-46ef-bf6e-0d9c03ac23bb "$W/ephemeral-sb.crt" \
    --no-microsoft --secure-boot
  virt-fw-vars --input "$W/vars.fd" --print > evidence/public/ovmf-keys.txt
  cp "$W/vars.fd" "$W/vars-for-negative.fd"
  echo 'R23_OVMF_EPHEMERAL_TEST_ROOT_ENROLLED=PASS' >> evidence/public/receipt.txt
else
  cp /usr/share/OVMF/OVMF_VARS_4M.fd "$W/vars.fd"
fi
accel=tcg
if test -w /dev/kvm; then accel=kvm; fi
# R30 F1 opt-in virtual SSD loss: the signed recovery image and independent
# key-only SSH MUST remain healthy with the SATA device wholly absent.
# Default K1 topology and its strict SATA-positive oracle are unchanged.
sata_args=(-device ich9-ahci,id=ahci -drive "if=none,id=ssd,format=raw,file=$W/sata.img" -device ide-hd,bus=ahci.0,drive=ssd,bootindex=2)
if test "${WYSE_R30_NO_SATA:-0}" = 1; then
  test -n "${WYSE_R29_OWNED_KERNEL_BZIMAGE:-}"
  sata_args=()
  echo 'R30_FAULT_NO_SATA_QEMU_DEVICE_OMITTED=PASS' >> evidence/public/receipt.txt
fi
qemu-system-x86_64 -machine "$ovmf_machine" -accel "$accel" -cpu max -m 3072 -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file="$ovmf_code" \
  -drive if=pflash,format=raw,file="$W/vars.fd" \
  -drive if=none,id=usb,format=raw,readonly=on,file="$W/usb-copy.img" \
  -device qemu-xhci,id=usbctl -device usb-storage,bus=usbctl.0,drive=usb,bootindex=1 \
  -drive if=none,id=emmc,format=raw,file="$W/emmc-guest.img" \
  -device sdhci-pci -device emmc,drive=emmc,boot-partition-size=1048576,rpmb-partition-size=2097152 \
  "${sata_args[@]}" \
  -netdev user,id=n,hostfwd=tcp:127.0.0.1:22222-:22 -device e1000,netdev=n \
  -display none -monitor none -serial file:evidence/public/guest-serial.txt -no-reboot \
  > evidence/public/qemu-log.txt 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || :' EXIT
success=0
guest_probe='echo KEY_ONLY_SSH_LOGIN=PASS; grep -q mmcblk0 /proc/partitions && echo GUEST_EMMC=PASS; grep -q sda /proc/partitions && echo GUEST_SATA=PASS'
if test "${WYSE_R30_NO_SATA:-0}" = 1; then
  guest_probe='echo KEY_ONLY_SSH_LOGIN=PASS; grep -q mmcblk0 /proc/partitions && echo GUEST_EMMC=PASS; usb=0; for node in /sys/block/sd[a-z]*; do test -d "$node" || continue; disk_path=$(cd "$node/device" 2>/dev/null && pwd -P) || { echo R30_UNKNOWN_BLOCK_DEVICE=FAIL_CLOSED; exit 24; }; case "$disk_path" in */ata[0-9]*/*) echo R30_UNEXPECTED_SATA=FAIL_OPEN; exit 23 ;; */usb[0-9]*/*) usb=1 ;; *) echo R30_UNSUPPORTED_SCSI_BUS=FAIL_CLOSED; exit 25 ;; esac; done; test "$usb" = 1 || { echo R30_EXPECTED_USB_STORAGE_NOT_SEEN=RED; exit 26; }; echo R30_GUEST_USB_BLOCK_PRESENT=PASS; echo R30_GUEST_SATA_ABSENT=PASS'
fi
for attempt in $(seq 1 105); do
  if ssh -q -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=1 -p 22222 -i "$W/id_ed25519" \
      root@127.0.0.1 "$guest_probe" \
      > evidence/public/ssh-oracle.txt 2> evidence/public/ssh-errors.txt; then success=1; break; fi
  sleep 1
done
if test "$success" -eq 1; then
  ssh-keygen -q -t ed25519 -N '' -f "$W/unauthorized-id"
  if ssh -q -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
      -o PasswordAuthentication=no -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 -p 22222 \
      -i "$W/unauthorized-id" root@127.0.0.1 'echo SECURITY_FAILURE' \
      > "$W/unauthorized-out.txt" 2>&1; then
    echo 'UNAUTHORIZED_SSH_KEY_DENIAL=FAIL_OPEN' >> evidence/public/receipt.txt
    kill "$pid" 2>/dev/null || :
    exit 1
  fi
  echo 'UNAUTHORIZED_SSH_KEY_DENIAL=PASS' >> evidence/public/receipt.txt
fi
kill "$pid" 2>/dev/null || :
wait "$pid" 2>/dev/null || :
trap - EXIT
sha256sum -c "$W/emmc-sha"
echo "RAW_USB_SHA256=$(sha256sum "$W/usb-copy.img" | cut -d' ' -f1)" >> evidence/public/receipt.txt
echo "UEFI_LOADER_SHA256=$(sha256sum "$W/efi/EFI/BOOT/BOOTX64.EFI" | cut -d' ' -f1)" >> evidence/public/receipt.txt
echo "INITRD_SHA256=$(sha256sum "$W/initrd.gz" | cut -d' ' -f1)" >> evidence/public/receipt.txt
test "$success" -eq 1 || { tail -n 50 evidence/public/guest-serial.txt; exit 1; }
# Direct UKI executes the EFI stub, not GRUB; retain GRUB banner assertion
# only for the GRUB substrate. Linux, disks, networking and SSH remain
# required for both signed boot paths; no oracle is weakened.
boot_markers="WYSE_SYNTHETIC_LINUX_INIT=PASS EMMC_ENUMERATION=PASS SATA_ENUMERATION=PASS RECOVERY_NETWORK_READY=PASS"
if test "${WYSE_R30_NO_SATA:-0}" = 1; then
  boot_markers="WYSE_SYNTHETIC_LINUX_INIT=PASS EMMC_ENUMERATION=PASS RECOVERY_NETWORK_READY=PASS"
fi
if test "${WYSE_R23_UKI:-0}" != 1; then
  boot_markers="WYSE_SYNTHETIC_UEFI_LOADER=PASS $boot_markers"
fi
for marker in $boot_markers; do
  grep -q "$marker" evidence/public/guest-serial.txt || { echo "MISSING:$marker"; exit 1; }
done
if test "${WYSE_R30_NO_SATA:-0}" = 1; then
  for marker in KEY_ONLY_SSH_LOGIN=PASS GUEST_EMMC=PASS R30_GUEST_USB_BLOCK_PRESENT=PASS R30_GUEST_SATA_ABSENT=PASS; do
    grep -Fxq "$marker" evidence/public/ssh-oracle.txt || exit 1
  done
  if ! grep -Fq 'USB_BOOT_STORAGE_ENUMERATION=PASS' evidence/public/guest-serial.txt; then
    echo 'R30_USB_BOOT_BLOCK_NOT_PROVEN=RED' >> evidence/public/receipt.txt
    exit 1
  fi
  if grep -Fq 'SATA_ENUMERATION=PASS' evidence/public/guest-serial.txt; then
    echo 'R30_NO_SATA_GUEST_TOPOLOGY=FAIL_OPEN' >> evidence/public/receipt.txt
    exit 1
  fi
  echo 'R30_NO_SATA_RECOVERY_BOOT_AND_AUTH_SSH=PASS' >> evidence/public/receipt.txt
else
  for marker in KEY_ONLY_SSH_LOGIN=PASS GUEST_EMMC=PASS GUEST_SATA=PASS; do
    grep -q "$marker" evidence/public/ssh-oracle.txt || exit 1
  done
  echo 'UEFI_USB_LINUX_EMMC_SATA_SSH=PASS' >> evidence/public/receipt.txt
fi
echo 'EMMC_SOURCE_PRESERVED=PASS' >> evidence/public/receipt.txt
echo 'SIGNED_PRODUCTION_IMAGE=NOT_TESTED' >> evidence/public/receipt.txt
if test "$WYSE_R23_SIGNED_EFI" = 1; then
  echo 'R23_SIGNED_EFI_UEFI_BOOT_LINUX_SSH=PASS' >> evidence/public/receipt.txt
  echo 'OVMF_SECURE_BOOT_ENFORCEMENT=NOT_TESTED' >> evidence/public/receipt.txt
  echo 'OWNER_PK_KEK_DB_AND_HARDWARE_SECUREBOOT=NOT_TESTED' >> evidence/public/receipt.txt
fi
echo 'DELL_FIRMWARE_AND_PHYSICAL_TPM=NOT_TESTED' >> evidence/public/receipt.txt
if test "${WYSE_R23_UKI:-0}" = 1; then
  echo 'R23_UKI_SIGNED_ENROLLED_OVMF_LINUX_SSH=PASS' >> evidence/public/receipt.txt
  echo 'R23_PRODUCTION_OWNER_KEY_AND_PHYSICAL_SECUREBOOT=NOT_TESTED' >> evidence/public/receipt.txt
fi
if test "${WYSE_R23_ENFORCE_SB:-0}" = 1; then
  echo 'R23_OVMF_ENROLLED_ROOT_SIGNED_EFI_LINUX_SSH=PASS' >> evidence/public/receipt.txt
  echo 'R23_FIRMWARE_REFUSAL_OF_UNSIGNED_EFI=NOT_TESTED' >> evidence/public/receipt.txt
  echo 'R23_KERNEL_INITRD_SIGNED_CHAIN=NOT_TESTED' >> evidence/public/receipt.txt
fi

# R23 security-negative: boot the original structurally valid UNSIGNED UKI
# on a copy of the SAME USB image, firmware and test-enrolled EFI trust
# database. Require explicit BdsDxe firmware Access Denied on the USB;
# a hung VM, merely failed sbverify, or failed SSH is not enough.
if test "${WYSE_R23_FIRMWARE_UNSIGNED_NEGATIVE:-0}" = 1; then
  test "${WYSE_R23_UKI:-0}" = 1
  test "${WYSE_R23_ENFORCE_SB:-0}" = 1
  test -f "$W/unsigned-efi.efi"
  test -f "$W/vars-for-negative.fd"
  ukify inspect "$W/unsigned-efi.efi" > evidence/public/unsigned-uki-inspect.txt 2>&1
  for section in .linux .initrd .cmdline; do
    grep -Fq "$section" evidence/public/unsigned-uki-inspect.txt || exit 1
  done
  if sbverify --cert "$W/ephemeral-sb.crt" "$W/unsigned-efi.efi" > "$W/unsigned-offline-check.txt" 2>&1; then
    echo 'R23_UNSIGNED_VALID_UKI_SIGNATURE_NEGATIVE=FAIL_OPEN' >> evidence/public/receipt.txt
    exit 1
  fi
  cp "$W/usb-copy.img" "$W/unsigned-usb.img"
  mkdir -p "$W/negative-mnt"
  negloop=$(sudo losetup --find --partscan --show "$W/unsigned-usb.img")
  trap 'sudo umount "$W/negative-mnt" 2>/dev/null || :; sudo losetup -d "$negloop" 2>/dev/null || :' EXIT
  test "$(lsblk -ndo TYPE "$negloop")" = loop
  negback=$(sudo losetup -n -O BACK-FILE "$negloop" | xargs)
  test "$(readlink -f "$negback")" = "$(readlink -f "$W/unsigned-usb.img")"
  sudo udevadm settle
  sudo mount "$negloop"p1 "$W/negative-mnt"
  sudo cp "$W/unsigned-efi.efi" "$W/negative-mnt/EFI/BOOT/BOOTX64.EFI"
  sudo sync
  sudo umount "$W/negative-mnt"
  sudo losetup -d "$negloop"
  trap - EXIT
  cp "$W/emmc-original.img" "$W/emmc-negative.img"
  cp "$W/vars-for-negative.fd" "$W/vars-negative.fd"
  timeout -s TERM -k 5 45s qemu-system-x86_64 -machine "$ovmf_machine" -accel "$accel" -cpu max -m 3072 -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file="$ovmf_code" \
    -drive if=pflash,format=raw,file="$W/vars-negative.fd" \
    -drive if=none,id=usb,format=raw,readonly=on,file="$W/unsigned-usb.img" \
    -device qemu-xhci,id=usbctl -device usb-storage,bus=usbctl.0,drive=usb,bootindex=1 \
    -drive if=none,id=emmc,format=raw,file="$W/emmc-negative.img" \
    -device sdhci-pci -device emmc,drive=emmc,boot-partition-size=1048576,rpmb-partition-size=2097152 \
    -device ich9-ahci,id=ahci -drive if=none,id=ssd,format=raw,file="$W/sata.img" \
    -device ide-hd,bus=ahci.0,drive=ssd,bootindex=2 \
    -netdev user,id=n -device e1000,netdev=n \
    -display none -monitor none -serial file:evidence/public/negative-guest-serial.txt -no-reboot \
    > evidence/public/negative-qemu-log.txt 2>&1 || :
  if ! grep -Eq "BdsDxe: failed to load Boot[0-9]{4}.*Access Denied" evidence/public/negative-guest-serial.txt; then
    echo 'R23_UNSIGNED_UKI_FIRMWARE_REJECTION=UNPROVEN' >> evidence/public/receipt.txt
    tail -n 50 evidence/public/negative-guest-serial.txt
    exit 1
  fi
  if grep -q "WYSE_SYNTHETIC_LINUX_INIT=PASS" evidence/public/negative-guest-serial.txt; then
    echo 'R23_UNSIGNED_UKI_FIRMWARE_REJECTION=FAIL_OPEN' >> evidence/public/receipt.txt
    exit 1
  fi
  sha256sum -c "$W/emmc-sha"
  echo 'R23_UNSIGNED_UKI_WELL_FORMED_AND_FIRMWARE_DENIED=PASS' >> evidence/public/receipt.txt
  echo 'R23_UNSIGNED_UKI_LINUX_INIT_NOT_REACHED=PASS' >> evidence/public/receipt.txt
fi
