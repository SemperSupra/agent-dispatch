#!/usr/bin/env bash
# Synthetic vendor-image module census; no real Pi, mount or host modprobe.
set -Eeuo pipefail
test "$(uname -m)" = aarch64
kind="$1"
mkdir -p evidence
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
case "$kind" in
  dietpi)
    url=https://dietpi.com/downloads/images/DietPi_RPi234-ARMv8-Trixie.img.xz
    curl -fLsS --retry 2 --max-time 180 "$url" -o "$tmp/vendor.xz"
    curl -fLsS --retry 2 --max-time 30 "$url.sha256" -o "$tmp/vendor.sha256"
    expected="$(awk 'NR==1 {print $1}' "$tmp/vendor.sha256")"
    actual="$(sha256sum "$tmp/vendor.xz" | awk '{print $1}')"
    test "$actual" = "$expected"
    echo VENDOR_CHECKSUM=PASS > evidence/source-integrity.txt
    ;;
  raspios)
    url=https://downloads.raspberrypi.com/raspios_lite_arm64_latest
    curl -fLsS --retry 2 --max-time 300 "$url" -o "$tmp/vendor.xz"
    echo VENDOR_CHECKSUM=NOT_VERIFIED > evidence/source-integrity.txt
    ;;
  *) exit 2 ;;
esac
printf 'kind=%s\nsource_url=%s\n' "$kind" "$url" > evidence/source.txt
sha256sum "$tmp/vendor.xz" | awk '{print $1}' > evidence/download-sha256.txt
xz -T2 -dc "$tmp/vendor.xz" > "$tmp/vendor.img"
sfdisk -J "$tmp/vendor.img" > evidence/partitions.json
python3 - "$tmp/vendor.img" "$tmp/root.img" <<'PY'
import json,sys
t=json.load(open("evidence/partitions.json"))["partitiontable"]
size=t.get("sectorsize",512)
p=max(t["partitions"],key=lambda x:x["size"])
with open(sys.argv[1],"rb") as src,open(sys.argv[2],"wb") as dst:
    src.seek(p["start"]*size)
    remaining=p["size"]*size
    while remaining:
        chunk=src.read(min(remaining,8*1024*1024))
        if not chunk:raise RuntimeError("image truncated")
        dst.write(chunk)
        remaining-=len(chunk)
PY
debugfs -R 'cat /etc/os-release' "$tmp/root.img" > evidence/os-release.txt 2>&1
mkdir -p "$tmp/modules"
debugfs -R "rdump /lib/modules $tmp/modules" "$tmp/root.img" > evidence/debugfs.txt 2>&1
find "$tmp/modules" -type f \( -name '*.ko' -o -name '*.ko.xz' -o -name '*.ko.zst' -o -name '*.ko.gz' \) > "$tmp/ko-list.txt"
count="$(wc -l < "$tmp/ko-list.txt")"
printf 'MODULE_FILES=%s\n' "$count" > evidence/module-summary.txt
test "$count" -gt 0 || { echo KERNEL_MODULE_TREE=RED >> evidence/module-summary.txt; exit 43; }
for mod in usbip-core usbip-host vhci-hcd usbip-vudc libcomposite dummy_hcd usb_f_hid usb_f_acm; do
    if grep -Eq "/$mod[.]ko([.]|$)" "$tmp/ko-list.txt"; then
        echo "$mod=MODULE_PRESENT" >> evidence/module-summary.txt
    else
        echo "$mod=BUILTIN_OR_ABSENT_OR_UNKNOWN" >> evidence/module-summary.txt
    fi
done
find "$tmp/modules" -type f -name modules.dep -printf '%h\n' | sed "s|$tmp/modules/||" > evidence/kernel-versions.txt
echo STATIC_IMAGE_INSPECTION=PASS >> evidence/module-summary.txt
echo USBIP_RUNTIME_ON_PHYSICAL_PI=NOT_TESTED >> evidence/module-summary.txt
cat evidence/module-summary.txt
