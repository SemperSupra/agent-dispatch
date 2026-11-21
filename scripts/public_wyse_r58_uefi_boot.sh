#!/usr/bin/env bash
# R58 public-synthetic Wyse UEFI/OVMF and PXE boot RDTE.
# NO owner keys, real machines, LAN listeners, host NIC bridges or USB writes.
set -Eeuo pipefail
umask 077
export LC_ALL=C TZ=UTC
: "\${RUNNER_TEMP:?}"
: "\${GITHUB_WORKSPACE:?}"
: "\${GITHUB_SHA:?}"
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
test "$GITHUB_WORKSPACE" = "$(pwd)"
K="$RUNNER_TEMP/wyse-r28-owned-kernel/out/images/bzImage"
I="$RUNNER_TEMP/wyse-r28-owned-kernel/out/images/rootfs.cpio"
test -s "$K" && test -s "$I"
test "$(sha256sum "$K" | cut -d' ' -f1)" = d51edcfc59aafabd11e7eb39bf1a5630bbfb3480c8bf7a2f25606d21121cc5ac
test "$(sha256sum "$I" | cut -d' ' -f1)" = 4023a48f55908bd4b9b3df3e0df4e6f2249f64812debc8f2f19a2896bcc0be81
for t in qemu-system-x86_64 mmd mcopy mkfs.vfat sbsign sbverify openssl timeout sha256sum; do command -v "$t" >/dev/null; done
if command -v ukify >/dev/null 2>&1; then UKIFY=$(command -v ukify); else UKIFY=/usr/lib/systemd/ukify; fi
test -x "$UKIFY"
CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
VARS=/usr/share/OVMF/OVMF_VARS_4M.fd
test -s "$CODE" && test -s "$VARS"
W=$(mktemp -d "$RUNNER_TEMP/wyse-r58-boot-XXXXXX")
trap 'rm -rf -- "$W"' EXIT
mkdir -p evidence/public "$W/tftp/EFI/BOOT"
"$UKIFY" build --linux="$K" --initrd="$I" \
  --cmdline="console=ttyS0,115200n8 rdinit=/init panic=2" \
  --output="$W/unsigned.efi" >"$W/ukify.log" 2>&1
"$UKIFY" inspect "$W/unsigned.efi" >"$W/inspect.txt" 2>&1
for section in .linux .initrd .cmdline; do grep -Fq "$section" "$W/inspect.txt"; done
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 1 \
  -subj '/CN=Wyse R58 isolated public synthetic test signer ONLY' \
  -keyout "$W/test-only.key" -out "$W/test-only.crt" >"$W/keygen.log" 2>&1
chmod 0600 "$W/test-only.key"
sbsign --key "$W/test-only.key" --cert "$W/test-only.crt" \
  --output "$W/signed.efi" "$W/unsigned.efi" >"$W/sbsign.log" 2>&1
sbverify --cert "$W/test-only.crt" "$W/signed.efi" >"$W/sbverify.log" 2>&1
cp "$W/signed.efi" "$W/tftp/EFI/BOOT/BOOTX64.EFI"
# QEMU FAT ESP is a scratch synthetic boot medium, never a host block device.
truncate -s 64M "$W/esp.img"
mkfs.vfat -F 16 "$W/esp.img" >"$W/mkfs.log" 2>&1
mmd -i "$W/esp.img" ::/EFI ::/EFI/BOOT
mcopy -i "$W/esp.img" "$W/signed.efi" ::/EFI/BOOT/BOOTX64.EFI
for disk in emmc sata; do truncate -s 64M "$W/mock-$disk.img"; done
SHA_ESP=$(sha256sum "$W/esp.img" | cut -d' ' -f1)
SHA_EMMC=$(sha256sum "$W/mock-emmc.img" | cut -d' ' -f1)
SHA_SATA=$(sha256sum "$W/mock-sata.img" | cut -d' ' -f1)
run_qemu(){
  local mode=$1 vars="$W/vars-$1.fd" log="$W/serial-$1.log" status=0
  cp "$VARS" "$vars"
  local -a devices=(
     -machine q35,accel=tcg -cpu max -m 1536 -smp 2
     -nodefaults -display none -monitor none -no-reboot
     -serial "file:$log"
     -drive "if=pflash,format=raw,readonly=on,file=$CODE"
     -drive "if=pflash,format=raw,file=$vars"
     -drive "file=$W/mock-emmc.img,if=virtio,format=raw,readonly=on"
     -drive "file=$W/mock-sata.img,if=virtio,format=raw,readonly=on"
  )
  if test "$mode" = esp; then
    devices+=( -drive "file=$W/esp.img,if=virtio,format=raw,readonly=on" -boot order=c -nic none )
  elif test "$mode" = pxe; then
    # QEMU slirp DHCP/TFTP is local to QEMU: no host DHCP or LAN bridge.
    devices+=( -netdev "user,id=pxe,restrict=on,tftp=$W/tftp,bootfile=EFI/BOOT/BOOTX64.EFI" \
       -device e1000,netdev=pxe,bootindex=1 -boot order=n )
  else exit 90; fi
  timeout -s TERM -k 5 135 qemu-system-x86_64 "\${devices[@]}" > "$W/qemu-$mode.log" 2>&1 || status=$?
  if test "$status" -ne 0 && test "$status" -ne 124 && test "$status" -ne 137; then
    echo "R58_\${mode^^}_QEMU_EXIT=$status"
    tail -n 30 "$W/qemu-$mode.log" || true
    return 71
  fi
  test -s "$log" || { echo "R58_\${mode^^}_SERIAL_MISSING=RED"; return 72; }
  if ! grep -Eq 'Linux version 6\.12\.113|Linux version 6\.12\.113-' "$log"; then
    echo "R58_\${mode^^}_LINUX_BOOT=RED"
    tail -n 35 "$log" || true
    return 73
  fi
  if ! grep -Fq 'WYSE_CORE_TMPFS_NO_EMMC_WRITES=ACTIVE' "$log"; then
    echo "R58_\${mode^^}_RECOVERY_INIT=RED"
    tail -n 45 "$log" || true
    return 74
  fi
  echo "R58_\${mode^^}_LINUX_INIT=PASS"
}
run_qemu esp
test "$(sha256sum "$W/esp.img" | cut -d' ' -f1)" = "$SHA_ESP"
test "$(sha256sum "$W/mock-emmc.img" | cut -d' ' -f1)" = "$SHA_EMMC"
test "$(sha256sum "$W/mock-sata.img" | cut -d' ' -f1)" = "$SHA_SATA"
echo R58_UEFI_FAT_ESP_NO_INTERNAL_DRIVE_WRITES=PASS
run_qemu pxe
test "$(sha256sum "$W/mock-emmc.img" | cut -d' ' -f1)" = "$SHA_EMMC"
test "$(sha256sum "$W/mock-sata.img" | cut -d' ' -f1)" = "$SHA_SATA"
cat > evidence/public/wyse-r58-boot.txt <<EOF
R58_SOURCE_SHA=$GITHUB_SHA
R58_KERNEL_SHA256=$(sha256sum "$K" | cut -d' ' -f1)
R58_CPIO_SHA256=$(sha256sum "$I" | cut -d' ' -f1)
R58_UNSIGNED_TEST_UKI_SHA256=$(sha256sum "$W/unsigned.efi" | cut -d' ' -f1)
R58_SIGNED_TEST_UKI_SHA256=$(sha256sum "$W/signed.efi" | cut -d' ' -f1)
R58_UEFI_ESP_LINUX_INIT=PASS
R58_QEMU_ISOLATED_PXE_LINUX_INIT=PASS
R58_SYNTHETIC_EMMC_SATA_UNCHANGED=PASS
R58_PRODUCTION_SECURE_BOOT_ENFORCEMENT=NOT_TESTED
R58_REAL_HYPERV_USB_DHCP_SSH_CONTROLLER_PHYSICAL_WYSE=NOT_TESTED
R58_NO_OWNER_SECRETS_OR_PHYSICAL_MEDIA=PASS
EOF
echo R58_BOUNDED_PUBLIC_SOURCE_BOOT_RDTE=PASS
