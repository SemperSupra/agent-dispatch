#!/usr/bin/env bash
set -euo pipefail

IMAGE=""
SOURCE_HOOK=""
PHASE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --source-hook) SOURCE_HOOK="$2"; shift 2 ;;
    --phase) PHASE="$2"; shift 2 ;;
    *) echo "usage: $0 --image QCOW2 --source-hook FILE --phase LABEL" >&2; exit 2 ;;
  esac
done
[[ -n "$IMAGE" && -n "$SOURCE_HOOK" && -n "$PHASE" ]] || { echo "missing required arguments" >&2; exit 2; }
[[ "$(id -u)" -eq 0 ]] || { echo "installed-disk probe requires root" >&2; exit 2; }
[[ -f "$IMAGE" && -f "$SOURCE_HOOK" ]] || { echo "image or source hook missing" >&2; exit 2; }

for cmd in qemu-nbd blockdev partx udevadm lsblk blkid pvs lvs lvchange mount umount mountpoint readlink python3 sha256sum sed tail tr; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing prerequisite: $cmd" >&2; exit 2; }
done

STATE="$(mktemp -d -t proxmox-installed-probe.XXXXXX)"
MNT="$STATE/mnt"
NBD=""
PV=""
ROOTDEV=""
CONNECTED_SIZE=0
LAYOUT=""
BLKIDS=""
PARTITION3_TYPE=""
VG=""
mounted=false

capture_block_evidence() {
  if [[ -n "$NBD" && -b "$NBD" ]]; then
    CONNECTED_SIZE="$(blockdev --getsize64 "$NBD" 2>/dev/null || echo 0)"
    LAYOUT="$(lsblk -lnpo NAME,TYPE,FSTYPE,PTTYPE,PARTTYPE,PARTLABEL,SIZE "$NBD" 2>&1 || true)"
    BLKIDS="$(blkid 2>&1 | grep -F "$NBD" || true)"
  fi
}

cleanup() {
  set +e
  if [[ "$mounted" == true ]] && mountpoint -q "$MNT" 2>/dev/null; then umount "$MNT" >/dev/null 2>&1 || true; fi
  if [[ -n "$PV" && -n "$ROOTDEV" ]]; then lvchange --devices "$PV" -an "$ROOTDEV" >/dev/null 2>&1 || true; fi
  if [[ -n "$NBD" && -b "$NBD" ]]; then qemu-nbd --disconnect "$NBD" >/dev/null 2>&1 || true; fi
  rm -rf -- "$STATE"
}
trap cleanup EXIT INT TERM

emit_error() {
  local error="$1" nbd_max_part=""
  capture_block_evidence
  [[ -r /sys/module/nbd/parameters/max_part ]] && nbd_max_part="$(cat /sys/module/nbd/parameters/max_part 2>/dev/null || true)"
  R_PHASE="$PHASE" R_ERROR="$error" R_SIZE="$CONNECTED_SIZE" R_LAYOUT="$LAYOUT" R_BLKIDS="$BLKIDS" R_MAXPART="$nbd_max_part" python3 - <<'PY'
import json, os
try:
    size = int(os.environ.get("R_SIZE", ""))
except Exception:
    size = None
print(json.dumps({
    "phase": os.environ["R_PHASE"],
    "inspection_ok": False,
    "error": os.environ["R_ERROR"],
    "connected_size_bytes": size,
    "lsblk": os.environ.get("R_LAYOUT") or None,
    "blkid": os.environ.get("R_BLKIDS") or None,
    "nbd_max_part": os.environ.get("R_MAXPART") or None,
}, sort_keys=True))
PY
  exit 0
}

modprobe nbd max_part=31 >/dev/null 2>&1 || emit_error "could not load nbd"
[[ ! -e /dev/pve/root ]] || emit_error "host already has active /dev/pve/root before image attachment"

for candidate in /dev/nbd{0..15}; do
  [[ -b "$candidate" ]] || continue
  name="${candidate#/dev/}"
  if [[ ! -s "/sys/block/$name/pid" ]]; then NBD="$candidate"; break; fi
done
[[ -n "$NBD" ]] || emit_error "no free nbd device"

qemu-nbd --connect="$NBD" --read-only --format=qcow2 "$IMAGE" >/dev/null 2>&1 || emit_error "qemu-nbd connect failed"

for _ in $(seq 1 40); do
  CONNECTED_SIZE="$(blockdev --getsize64 "$NBD" 2>/dev/null || echo 0)"
  if [[ "$CONNECTED_SIZE" =~ ^[0-9]+$ ]] && (( CONNECTED_SIZE >= 1024 * 1024 * 1024 )); then break; fi
  udevadm settle >/dev/null 2>&1 || true
  sleep 0.25
done
if [[ ! "$CONNECTED_SIZE" =~ ^[0-9]+$ ]] || (( CONNECTED_SIZE < 1024 * 1024 * 1024 )); then
  emit_error "qemu-nbd attachment did not expose expected nonzero capacity"
fi

udevadm settle >/dev/null 2>&1 || true
blockdev --rereadpt "$NBD" >/dev/null 2>&1 || true
partx -u "$NBD" >/dev/null 2>&1 || partx -a "$NBD" >/dev/null 2>&1 || true
udevadm settle >/dev/null 2>&1 || true
sleep 0.25
capture_block_evidence

EXACT_PV="${NBD}p3"
if [[ -b "$EXACT_PV" ]]; then
  PARTITION3_TYPE="$(blkid -p -s TYPE -o value "$EXACT_PV" 2>/dev/null || true)"
  if [[ "$PARTITION3_TYPE" == "LVM2_member" ]]; then PV="$EXACT_PV"; fi
fi
if [[ -z "$PV" ]]; then
  while read -r dev type; do
    [[ "$type" == "part" ]] || continue
    if [[ "$(blkid -p -s TYPE -o value "$dev" 2>/dev/null || true)" == "LVM2_member" ]]; then PV="$dev"; break; fi
  done < <(lsblk -lnpo NAME,TYPE "$NBD" 2>/dev/null)
fi
[[ -n "$PV" ]] || emit_error "installed LVM PV not found"

VG="$(pvs --devices "$PV" --noheadings -o vg_name "$PV" 2>/dev/null | xargs || true)"
[[ "$VG" == "pve" ]] || emit_error "installed VG is '${VG:-absent}', expected exact PVE VG 'pve'"

ROOTDEV="$(lvs --devices "$PV" --noheadings -o lv_path,lv_name "$VG" 2>/dev/null | awk '$2=="root" {print $1; exit}')"
[[ "$ROOTDEV" == "/dev/pve/root" ]] || emit_error "installed root LV is '${ROOTDEV:-absent}', expected /dev/pve/root"
lvchange --devices "$PV" -ay "$ROOTDEV" >/dev/null 2>&1 || emit_error "installed root LV not activatable"

mkdir -p "$MNT"
mount -o ro,noload "$ROOTDEV" "$MNT" >/dev/null 2>&1 || emit_error "installed root LV mount failed"
mounted=true

HOOK="$MNT/var/lib/proxmox-first-boot/proxmox-first-boot"
PENDING="$MNT/var/lib/proxmox-first-boot/pending-first-boot-setup"
UNIT="$MNT/lib/systemd/system/proxmox-first-boot-network-online.service"
ALIAS="$MNT/etc/systemd/system/proxmox-first-boot.service"
WANTS="$MNT/etc/systemd/system/multi-user.target.wants/proxmox-first-boot-network-online.service"
LOG="$MNT/var/lib/proxmox-first-boot/rdte-first-boot.log"

HOOK_PRESENT=false
HOOK_EXEC=false
HOOK_SHA=""
HOOK_MATCH=false
PENDING_PRESENT=false
UNIT_PRESENT=false
ALIAS_TARGET=""
WANTS_TARGET=""
LOG_PRESENT=false
LOG_TEXT=""
if [[ -f "$HOOK" ]]; then
  HOOK_PRESENT=true
  [[ -x "$HOOK" ]] && HOOK_EXEC=true
  HOOK_SHA="$(sha256sum "$HOOK" | awk '{print $1}')"
  [[ "$HOOK_SHA" == "$(sha256sum "$SOURCE_HOOK" | awk '{print $1}')" ]] && HOOK_MATCH=true
fi
[[ -e "$PENDING" ]] && PENDING_PRESENT=true
[[ -f "$UNIT" ]] && UNIT_PRESENT=true
ALIAS_TARGET="$(readlink "$ALIAS" 2>/dev/null || true)"
WANTS_TARGET="$(readlink "$WANTS" 2>/dev/null || true)"
if [[ -f "$LOG" ]]; then LOG_PRESENT=true; LOG_TEXT="$(tail -c 16000 "$LOG" 2>/dev/null || true)"; fi

read_package_version() {
  local package="$1"
  sed -n "/^Package: ${package}$/,/^$/p" "$MNT/var/lib/dpkg/status" 2>/dev/null | sed -n 's/^Version: //p' | head -n 1
}
FIRST_BOOT_PACKAGE_VERSION="$(read_package_version proxmox-first-boot || true)"
PVE_MANAGER_VERSION="$(read_package_version pve-manager || true)"
PVE_CLUSTER_VERSION="$(read_package_version pve-cluster || true)"
INSTALLED_HOSTNAME="$(cat "$MNT/etc/hostname" 2>/dev/null | tr -d '\r\n' | tail -c 512 || true)"
INSTALLED_HOSTS="$(tail -c 8000 "$MNT/etc/hosts" 2>/dev/null || true)"
INSTALLED_INTERFACES="$(tail -c 12000 "$MNT/etc/network/interfaces" 2>/dev/null || true)"
capture_block_evidence

export R_PHASE="$PHASE" R_SIZE="$CONNECTED_SIZE" R_LAYOUT="$LAYOUT" R_BLKIDS="$BLKIDS" R_P3="$PARTITION3_TYPE"
export R_ROOT="$ROOTDEV" R_FBPKG="$FIRST_BOOT_PACKAGE_VERSION" R_MANAGER="$PVE_MANAGER_VERSION" R_CLUSTER="$PVE_CLUSTER_VERSION"
export R_HOSTNAME="$INSTALLED_HOSTNAME" R_HOSTS="$INSTALLED_HOSTS" R_INTERFACES="$INSTALLED_INTERFACES"
export R_HOOK_PRESENT="$HOOK_PRESENT" R_HOOK_EXEC="$HOOK_EXEC" R_HOOK_SHA="$HOOK_SHA" R_HOOK_MATCH="$HOOK_MATCH"
export R_PENDING="$PENDING_PRESENT" R_UNIT="$UNIT_PRESENT" R_ALIAS="$ALIAS_TARGET" R_WANTS="$WANTS_TARGET"
export R_LOG_PRESENT="$LOG_PRESENT" R_LOG="$LOG_TEXT"
python3 - <<'PY'
import json, os
def b(name):
    return os.environ.get(name, "false").lower() == "true"
try:
    size = int(os.environ.get("R_SIZE", ""))
except Exception:
    size = None
print(json.dumps({
    "phase": os.environ["R_PHASE"],
    "inspection_ok": True,
    "connected_size_bytes": size,
    "lsblk": os.environ.get("R_LAYOUT") or None,
    "blkid": os.environ.get("R_BLKIDS") or None,
    "partition3_type": os.environ.get("R_P3") or None,
    "root_lv": os.environ.get("R_ROOT") or None,
    "first_boot_package_version": os.environ.get("R_FBPKG") or None,
    "pve_manager_version": os.environ.get("R_MANAGER") or None,
    "pve_cluster_version": os.environ.get("R_CLUSTER") or None,
    "installed_hostname": os.environ.get("R_HOSTNAME") or None,
    "installed_hosts": os.environ.get("R_HOSTS") or None,
    "installed_network_interfaces": os.environ.get("R_INTERFACES") or None,
    "first_boot_hook_present": b("R_HOOK_PRESENT"),
    "first_boot_hook_executable": b("R_HOOK_EXEC"),
    "first_boot_hook_sha256": os.environ.get("R_HOOK_SHA") or None,
    "hook_matches_prepared_iso": b("R_HOOK_MATCH"),
    "pending_flag_present": b("R_PENDING"),
    "network_online_unit_present": b("R_UNIT"),
    "alias_target": os.environ.get("R_ALIAS") or None,
    "wanted_by_target": os.environ.get("R_WANTS") or None,
    "first_boot_log_present": b("R_LOG_PRESENT"),
    "first_boot_log": os.environ.get("R_LOG") or None,
}, sort_keys=True))
PY
