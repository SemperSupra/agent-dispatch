#!/usr/bin/env bash
# Public synthetic ARM64-only OS artifact inspection. No host kernel/module/USB changes.
set -euo pipefail
: "${EVIDENCE_DIR:=evidence}"
mkdir -p "$EVIDENCE_DIR"
printf 'arch=%s\nkernel=%s\n' "$(uname -m)" "$(uname -r)" | tee "$EVIDENCE_DIR/host.txt"
test "$(uname -m)" = aarch64
case "${1:-}" in
  dietpi)
    name=dietpi
    url='https://dietpi.com/downloads/images/DietPi_RPi234-ARMv8-Trixie.img.xz'
    curl -fLsS --retry 2 --max-time 240 -o image.img.xz "$url"
    curl -fLsS --retry 2 --max-time 30 -o expected.sha256 "${url}.sha256"
    sha256sum -c expected.sha256
    ;;
  raspios)
    name=raspios
    url='https://downloads.raspberrypi.com/raspios_lite_arm64_latest'
    curl -fLsS --retry 2 --max-time 300 -o image.img.xz "$url"
    # Vendor checksum must be pinned at release qualification; report downloaded artifact hash here.
    ;;
  debian)
    name=debian
    sudo apt-get update -qq
    sudo apt-get install -y -qq --no-install-recommends debootstrap
    sudo debootstrap --arch=arm64 --variant=minbase trixie rootfs https://deb.debian.org/debian
    sudo du -sb rootfs | tee "$EVIDENCE_DIR/rootfs-bytes.txt"
    sudo find rootfs -xdev -type f | wc -l | tee "$EVIDENCE_DIR/file-count.txt"
    echo 'debootstrap-minbase-no-pi-firmware-bootloader-not-bootable' > "$EVIDENCE_DIR/scope.txt"
    exit 0
    ;;
  *) echo "Usage: $0 dietpi|raspios|debian" >&2; exit 2;;
esac
printf 'source=%s\nurl=%s\n' "$name" "$url" > "$EVIDENCE_DIR/source.txt"
sha256sum image.img.xz > "$EVIDENCE_DIR/download.sha256"
stat -c '%s' image.img.xz > "$EVIDENCE_DIR/compressed-bytes.txt"
xz -T2 -dk image.img.xz
stat -c '%s' image.img > "$EVIDENCE_DIR/raw-image-bytes.txt"
sfdisk -J image.img > "$EVIDENCE_DIR/partitions.json"
python3 - <<'PY'
import json, subprocess
p=json.load(open('evidence/partitions.json'))['partitiontable']
sectorsize=p.get('sectorsize',512)
parts=p['partitions']
# Root ext partition typically last/largest; only inspect it, never mount host devices.
root=max(parts, key=lambda part:part['size'])
off=root['start']*sectorsize
length=root['size']*sectorsize
with open('image.img','rb') as src, open('root.img','wb') as dst:
    src.seek(off)
    remaining=length
    while remaining:
        buf=src.read(min(8*1024*1024,remaining))
        if not buf: raise RuntimeError('truncated partition')
        dst.write(buf); remaining-=len(buf)
with open('evidence/root-partition-bytes.txt','w') as out:out.write(str(length)+'\n')
PY
dumpe2fs -h root.img > "$EVIDENCE_DIR/ext4-superblock.txt" 2>&1
debugfs -R 'cat /etc/os-release' root.img > "$EVIDENCE_DIR/os-release.txt" 2>&1 || true
debugfs -R 'stat /var/lib/dpkg/status' root.img > "$EVIDENCE_DIR/dpkg-status-metadata.txt" 2>&1 || true
debugfs -R 'ls -p /usr/lib/systemd/system-generators' root.img > "$EVIDENCE_DIR/generators.txt" 2>&1 || true
printf 'scope=static-official-image-no-boot-or-idle-ram-claim\n' > "$EVIDENCE_DIR/scope.txt"
rm -f root.img image.img image.img.xz
