#!/usr/bin/env bash
# R36 public synthetic reproducibility qualification.
# Given IDENTICAL EFI payload bytes, does deterministic GPT+FAT+eMMC packaging
# produce the exact same 260MiB backing on two independent clean builds?
# Does NOT prove full signed UKI/signer reproducibility or physical eMMC.
set -Eeuo pipefail
umask 077
export TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=1577836800 MTOOLS_SKIP_CHECK=1
test -n "$RUNNER_TEMP" && test -n "$GITHUB_SHA"
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
W=$(mktemp -d "$RUNNER_TEMP/wyse-r36-emmc-repro-XXXXXX")
trap 'rm -rf -- "$W"' EXIT
mkdir -p evidence/public
cat > "$W/hello.cfg" <<'CFG'
serial --unit=0 --speed=115200
terminal_input console serial
terminal_output console serial
echo R36_EXACT_EFI_CONTENT_SOURCE=PASS
halt
CFG
grub-mkstandalone -O x86_64-efi -o "$W/BOOTX64.EFI" \
  --modules="part_gpt fat serial terminal echo" \
  "boot/grub/grub.cfg=$W/hello.cfg" > evidence/public/r36-grub-build.txt 2>&1
test -s "$W/BOOTX64.EFI"
touch -d "@$SOURCE_DATE_EPOCH" "$W/BOOTX64.EFI"
efi_sha=$(sha256sum "$W/BOOTX64.EFI" | awk '{print $1}')
printf 'R36_EFI_PAYLOAD_SHA256=%s\n' "$efi_sha"
build_emmc() {
  local n=$1 user="$W/user-$1.img" emmc="$W/emmc-$1.img" dest="$W/extract-$1.efi"
  truncate -s 256M "$user"
  sgdisk --zap-all --clear "$user" > "$W/gpt-clear-$n.txt"
  sgdisk -n 1:2048:+128M -t 1:ef00 -c 1:WYSE-ESP \
    -U 51783846-58c4-437d-81a7-8a2ee5637fc8 \
    -u 1:d0fcb731-554d-4214-a5d2-8724c96b4dcb "$user" > "$W/gpt-create-$n.txt"
  sgdisk -v "$user" > "$W/gpt-verify-$n.txt"
  sgdisk -i 1 "$user" | grep -Fiq 'd0fcb731-554d-4214-a5d2-8724c96b4dcb' || {
    echo 'R36_FIXED_GPT_PARTITION_GUID=RED'; exit 1;
  }
  # Exactly 128MiB FAT partition at LBA 2048, not entire 256MiB user area.
  mkfs.vfat -F 32 --invariant -i 4f2a3100 -n WYSEEMMC \
    --offset 2048 "$user" 131072 > "$W/mkfs-$n.txt"
  mmd -i "$user@@1048576" ::/EFI ::/EFI/BOOT
  mcopy -m -i "$user@@1048576" "$W/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
  mcopy -i "$user@@1048576" ::/EFI/BOOT/BOOTX64.EFI "$dest"
  cmp -s "$W/BOOTX64.EFI" "$dest" || {
    echo 'R36_EFI_PAYLOAD_READBACK=RED'; exit 1;
  }
  truncate -s 260M "$emmc"
  dd if="$user" of="$emmc" bs=4M seek=1 conv=notrunc status=none
  test "$(stat -c %s "$emmc")" -eq 272629760 || {
    echo 'R36_EMMC_LAYOUT_SIZE=RED'; exit 1;
  }
  echo "R36_CANDIDATE_${n}_SHA256=$(sha256sum "$emmc" | awk '{print $1}')"
}
build_emmc A
build_emmc B
if ! cmp -s "$W/emmc-A.img" "$W/emmc-B.img"; then
  echo R36_FULL_RAW_EMMC_IMAGE_CMP=RED
  echo R36_NONDETERMINISTIC_IMAGE_LOCATION_UNRESOLVED=TRUE
  exit 1
fi
echo R36_FULL_RAW_EMMC_IMAGE_CMP=PASS
echo "R36_DETERMINISTIC_260M_IMAGE_SHA256=$(sha256sum "$W/emmc-A.img" | awk '{print $1}')"
echo R36_PARTITION_ESP_AND_EFI_READBACK=PASS
echo R36_ORIGINAL_EFI_BYTE_PAYLOAD_REUSED_BOTH_BUILDS=PASS
echo R36_PRODUCTION_SIGNED_UKI_AND_CROSS_RUN_REPRODUCIBILITY=NOT_TESTED
echo R36_REAL_DELL_EMMC_AND_BOOTORDER=NOT_TESTED
