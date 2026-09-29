#!/usr/bin/env bash
set -euo pipefail
SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    *) echo "usage: $0 --out RECEIPT" >&2; exit 2 ;;
  esac
done
[[ -n "$OUT" ]] || { echo "missing --out" >&2; exit 2; }
[[ "$(id -u)" -eq 0 ]] || { echo "self-test requires root" >&2; exit 2; }

for cmd in qemu-img qemu-nbd sgdisk blockdev partx udevadm lsblk blkid pvcreate pvs vgcreate vgs lvcreate lvs lvchange mkfs.ext4 mount umount mountpoint python3 sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing prerequisite: $cmd" >&2; exit 2; }
done

STATE="$(mktemp -d -t proxmox-p2-inspector.XXXXXX)"
IMAGE="$STATE/system.qcow2"
MNT="$STATE/mnt"
HOOK="$STATE/proxmox-first-boot"
NBD=""
PV=""
VG="pve"
ROOTDEV="/dev/pve/root"
CONNECTED_SIZE=0
READONLY_SIZE=0
LSBLK=""
BLKID_TYPE=""
DISCOVERED_VG=""
DISCOVERED_ROOT=""
SENTINEL_OK=false
HOOK_MATCH=false
cleanup() {
  set +e
  if mountpoint -q "$MNT" 2>/dev/null; then umount "$MNT"; fi
  if [[ -n "$PV" && -b "$PV" ]]; then
    lvchange --devices "$PV" -an "$ROOTDEV" >/dev/null 2>&1 || lvchange -an "$VG" >/dev/null 2>&1 || true
  else
    lvchange -an "$VG" >/dev/null 2>&1 || true
  fi
  if [[ -n "$NBD" && -b "$NBD" ]]; then qemu-nbd --disconnect "$NBD" >/dev/null 2>&1 || true; fi
  rm -rf -- "$STATE"
}
trap cleanup EXIT INT TERM

if vgs "$VG" >/dev/null 2>&1; then
  echo "host already has VG '$VG'; refusing synthetic collision" >&2
  exit 2
fi

modprobe nbd max_part=31
for candidate in /dev/nbd{0..15}; do
  [[ -b "$candidate" ]] || continue
  name="${candidate#/dev/}"
  if [[ ! -s "/sys/block/$name/pid" ]]; then NBD="$candidate"; break; fi
done
[[ -n "$NBD" ]] || { echo "no free nbd device" >&2; exit 2; }

wait_for_capacity() {
  local expected_min="$1" size=0
  for _ in $(seq 1 40); do
    size="$(blockdev --getsize64 "$NBD" 2>/dev/null || echo 0)"
    if [[ "$size" =~ ^[0-9]+$ ]] && (( size >= expected_min )); then
      printf '%s\n' "$size"
      return 0
    fi
    udevadm settle >/dev/null 2>&1 || true
    sleep 0.25
  done
  printf '%s\n' "$size"
  return 1
}

qemu-img create -q -f qcow2 "$IMAGE" 2G
qemu-nbd --connect="$NBD" --format=qcow2 "$IMAGE"
CONNECTED_SIZE="$(wait_for_capacity $((1024 * 1024 * 1024)))" || {
  echo "write attachment never exposed nonzero capacity: $CONNECTED_SIZE" >&2
  exit 1
}

sgdisk -Z "$NBD" >/dev/null
sgdisk -n2:1M:+512M -t2:EF00 -n3:513M:0 -t3:8E00 "$NBD" >/dev/null
sgdisk -a1 -n1:34:2047 -t1:EF02 "$NBD" >/dev/null
blockdev --rereadpt "$NBD" >/dev/null 2>&1 || true
partx -u "$NBD" >/dev/null 2>&1 || true
udevadm settle
PV="${NBD}p3"
[[ -b "$PV" ]] || { lsblk -o NAME,TYPE,SIZE,FSTYPE,PARTTYPE "$NBD" >&2; echo "synthetic p3 absent" >&2; exit 1; }

pvcreate --devices "$PV" --metadatasize 250k -y -ff "$PV" >/dev/null
vgcreate --devices "$PV" "$VG" "$PV" >/dev/null
lvcreate --devices "$PV" -Wy --yes -L512M -nroot "$VG" >/dev/null
mkfs.ext4 -q -F "$ROOTDEV"
mkdir -p "$MNT"
mount "$ROOTDEV" "$MNT"

printf '#!/bin/sh\necho synthetic-first-boot\n' >"$HOOK"
chmod 0700 "$HOOK"
mkdir -p "$MNT/var/lib/proxmox-first-boot" "$MNT/usr/lib/systemd/system" "$MNT/etc/systemd/system/multi-user.target.wants" "$MNT/var/lib/dpkg"
install -m 0700 "$HOOK" "$MNT/var/lib/proxmox-first-boot/proxmox-first-boot"
touch "$MNT/var/lib/proxmox-first-boot/pending-first-boot-setup"
printf 'synthetic-root-ok\n' >"$MNT/rdte-inspector-sentinel"
cat >"$MNT/usr/lib/systemd/system/proxmox-first-boot-network-online.service" <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target
ConditionPathExists=/var/lib/proxmox-first-boot/pending-first-boot-setup
[Service]
ExecStart=/var/lib/proxmox-first-boot/proxmox-first-boot network-online
[Install]
Alias=proxmox-first-boot.service
WantedBy=multi-user.target
EOF
ln -s usr/lib "$MNT/lib"
ln -s /lib/systemd/system/proxmox-first-boot-network-online.service "$MNT/etc/systemd/system/proxmox-first-boot.service"
ln -s /lib/systemd/system/proxmox-first-boot-network-online.service "$MNT/etc/systemd/system/multi-user.target.wants/proxmox-first-boot-network-online.service"
cat >"$MNT/var/lib/dpkg/status" <<'EOF'
Package: proxmox-first-boot
Status: install ok installed
Version: 9.2.5
Architecture: amd64
EOF
sync
umount "$MNT"
lvchange --devices "$PV" -an "$ROOTDEV" >/dev/null
qemu-nbd --disconnect "$NBD" >/dev/null
udevadm settle
sleep 0.25

PRODUCTION_PROBE_OUT="$STATE/production-probe.json"
bash "$SELF_DIR/proxmox_installed_disk_probe.sh" \
  --image "$IMAGE" \
  --source-hook "$HOOK" \
  --phase synthetic >"$PRODUCTION_PROBE_OUT"
python3 - "$PRODUCTION_PROBE_OUT" <<'PY'
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert payload["inspection_ok"] is True, payload
assert payload["connected_size_bytes"] == 2 * 1024 * 1024 * 1024, payload
assert payload["partition3_type"] == "LVM2_member", payload
assert payload["root_lv"] == "/dev/pve/root", payload
assert payload["first_boot_package_version"] == "9.2.5", payload
assert payload["first_boot_hook_present"] is True, payload
assert payload["first_boot_hook_executable"] is True, payload
assert payload["hook_matches_prepared_iso"] is True, payload
assert payload["pending_flag_present"] is True, payload
assert payload["network_online_unit_present"] is True, payload
assert payload["alias_target"] == "/lib/systemd/system/proxmox-first-boot-network-online.service", payload
assert payload["wanted_by_target"] == "/lib/systemd/system/proxmox-first-boot-network-online.service", payload
PY

qemu-nbd --connect="$NBD" --read-only --format=qcow2 "$IMAGE"
READONLY_SIZE="$(wait_for_capacity $((1024 * 1024 * 1024)))" || {
  echo "read-only attachment never exposed nonzero capacity: $READONLY_SIZE" >&2
  exit 1
}
udevadm settle
blockdev --rereadpt "$NBD" >/dev/null 2>&1 || true
partx -u "$NBD" >/dev/null 2>&1 || partx -a "$NBD" >/dev/null 2>&1 || true
udevadm settle
sleep 0.25

PV="${NBD}p3"
LSBLK="$(lsblk -lnpo NAME,TYPE,FSTYPE,PTTYPE,PARTTYPE,PARTLABEL,SIZE "$NBD")"
[[ -b "$PV" ]] || { printf '%s\n' "$LSBLK" >&2; echo "read-only p3 absent" >&2; exit 1; }
BLKID_TYPE="$(blkid -p -s TYPE -o value "$PV" 2>/dev/null || true)"
[[ "$BLKID_TYPE" == "LVM2_member" ]] || { printf '%s\n' "$LSBLK" >&2; echo "p3 type is '$BLKID_TYPE', expected LVM2_member" >&2; exit 1; }

DISCOVERED_VG="$(pvs --devices "$PV" --noheadings -o vg_name "$PV" 2>/dev/null | xargs || true)"
[[ "$DISCOVERED_VG" == "$VG" ]] || { echo "discovered VG '$DISCOVERED_VG', expected '$VG'" >&2; exit 1; }
DISCOVERED_ROOT="$(lvs --devices "$PV" --noheadings -o lv_path,lv_name "$VG" 2>/dev/null | awk '$2=="root" {print $1; exit}')"
[[ "$DISCOVERED_ROOT" == "$ROOTDEV" ]] || { echo "discovered root '$DISCOVERED_ROOT', expected '$ROOTDEV'" >&2; exit 1; }
lvchange --devices "$PV" -ay "$ROOTDEV" >/dev/null
mount -o ro,noload "$ROOTDEV" "$MNT"
[[ "$(cat "$MNT/rdte-inspector-sentinel")" == "synthetic-root-ok" ]] && SENTINEL_OK=true
HOOK_SHA="$(sha256sum "$HOOK" | awk '{print $1}')"
INSTALLED_HOOK_SHA="$(sha256sum "$MNT/var/lib/proxmox-first-boot/proxmox-first-boot" | awk '{print $1}')"
[[ "$HOOK_SHA" == "$INSTALLED_HOOK_SHA" ]] && HOOK_MATCH=true
[[ -e "$MNT/var/lib/proxmox-first-boot/pending-first-boot-setup" ]]
[[ -f "$MNT/lib/systemd/system/proxmox-first-boot-network-online.service" ]]
[[ "$(readlink "$MNT/etc/systemd/system/proxmox-first-boot.service")" == "/lib/systemd/system/proxmox-first-boot-network-online.service" ]]
[[ "$(readlink "$MNT/etc/systemd/system/multi-user.target.wants/proxmox-first-boot-network-online.service")" == "/lib/systemd/system/proxmox-first-boot-network-online.service" ]]
umount "$MNT"
lvchange --devices "$PV" -an "$ROOTDEV" >/dev/null

mkdir -p "$(dirname "$OUT")"
export R_OUT="$OUT" R_CONNECTED="$CONNECTED_SIZE" R_READONLY="$READONLY_SIZE" R_LSBLK="$LSBLK" R_BLKID="$BLKID_TYPE"
export R_VG="$DISCOVERED_VG" R_ROOT="$DISCOVERED_ROOT" R_SENTINEL="$SENTINEL_OK" R_HOOK_MATCH="$HOOK_MATCH"
export R_PRODUCTION_PROBE_OUT="$PRODUCTION_PROBE_OUT"
python3 - <<'PY'
import json, os, pathlib
production_probe = json.loads(pathlib.Path(os.environ["R_PRODUCTION_PROBE_OUT"]).read_text())
payload = {
    "contract": "proxmox-p2-offline-inspector-selftest/v1",
    "classification": "SUPPORTED",
    "oracleSatisfied": True,
    "connected_size_bytes": int(os.environ["R_CONNECTED"]),
    "readonly_size_bytes": int(os.environ["R_READONLY"]),
    "lsblk": os.environ["R_LSBLK"],
    "partition3_type": os.environ["R_BLKID"],
    "vg": os.environ["R_VG"],
    "root_lv": os.environ["R_ROOT"],
    "root_sentinel_readback": os.environ["R_SENTINEL"].lower() == "true",
    "hook_hash_matches": os.environ["R_HOOK_MATCH"].lower() == "true",
    "production_probe": production_probe,
}
pathlib.Path(os.environ["R_OUT"]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
cat "$OUT"
