#!/usr/bin/env bash
set -euo pipefail

ISO_NAME="proxmox-ve_9.2-1.iso"
ISO_URL="https://enterprise.proxmox.com/iso/$ISO_NAME"
ISO_SHA256="4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c"
PVE_INSTALLER_SOURCE_VERSION="9.2.5"
PVE_INSTALLER_SOURCE_COMMIT="32afcd4cd534d8e2f99ae76aa0234a0a5c697ba9"
RAM_MIB=4096
VCPUS=2
DISK_SIZE="40G"
MIN_HOST_MEM_KIB=$((6 * 1024 * 1024))
MIN_HOST_FREE_KIB=$((16 * 1024 * 1024))
ROOT_PASSWORD="rdte-proxmox-${RANDOM}-${RANDOM}-${RANDOM}"

usage() {
  echo "Usage: gha_kvm_proxmox_rdte.sh --out RECEIPT [--state-dir DIR]"
}

OUT=""
STATE_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -n "$OUT" ]] || { usage >&2; exit 2; }

if [[ -z "$STATE_DIR" ]]; then STATE_DIR="$(mktemp -d -t gha-kvm-proxmox.XXXXXX)"; fi
mkdir -p "$STATE_DIR" "$(dirname "$OUT")"
STATE_DIR="$(realpath "$STATE_DIR")"
OUT="$(realpath -m "$OUT")"
[[ "$OUT" != "$STATE_DIR/"* ]] || { echo "receipt must be outside disposable state" >&2; exit 2; }

QEMU_PID=""
OBSERVED_ISO_SHA=""
API_VERSION_JSON=""
NESTED_KVM="unknown"
SSH_HOSTFWD_ACCEPTED="false"
API_HOSTFWD_ACCEPTED="false"
QEMU_ALIVE_AT_API_GATE="unknown"
GUEST_DIAGNOSTICS=""
FIRST_BOOT_WITNESS=""
FIRST_BOOT_WITNESS_OBSERVED="false"
INSTALL_SUCCESS_MARKER_OBSERVED="false"
INSTALLED_DISK_LAYOUT_OK="false"
ISO_FIRST_BOOT_PACKAGE=""
INSTALLED_DISK_PREBOOT=""
INSTALLED_DISK_POSTBOOT=""
cleanup() {
  set +e
  if [[ -n "$QEMU_PID" ]]; then
    sudo -n kill "$QEMU_PID" >/dev/null 2>&1 || true
    sleep 1
    sudo -n kill -9 "$QEMU_PID" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$STATE_DIR"
}
trap cleanup EXIT INT TERM

write_receipt() {
  local classification="$1" oracle="$2" phase="$3" detail="$4"
  local serial_tail=""
  if [[ -f "$STATE_DIR/serial.log" ]]; then
    serial_tail="$(tail -n 80 "$STATE_DIR/serial.log" | tr -d '\000' | sed -E 's/[^[:print:]\t]//g' | tail -c 12000)"
  fi
  export R_OUT="$OUT" R_CLASS="$classification" R_ORACLE="$oracle" R_PHASE="$phase" R_DETAIL="$detail"
  export R_SERIAL="$serial_tail" R_ISO_SHA="$OBSERVED_ISO_SHA" R_API="$API_VERSION_JSON" R_NESTED="$NESTED_KVM"
  export R_SSH_HOSTFWD_ACCEPTED="$SSH_HOSTFWD_ACCEPTED" R_API_HOSTFWD_ACCEPTED="$API_HOSTFWD_ACCEPTED"
  export R_QEMU_ALIVE="$QEMU_ALIVE_AT_API_GATE" R_GUEST_DIAGNOSTICS="$GUEST_DIAGNOSTICS"
  export R_FIRST_BOOT_WITNESS="$FIRST_BOOT_WITNESS" R_FIRST_BOOT_WITNESS_OBSERVED="$FIRST_BOOT_WITNESS_OBSERVED"
  export R_INSTALL_SUCCESS_MARKER_OBSERVED="$INSTALL_SUCCESS_MARKER_OBSERVED" R_INSTALLED_DISK_LAYOUT_OK="$INSTALLED_DISK_LAYOUT_OK"
  export R_ISO_FIRST_BOOT_PACKAGE="$ISO_FIRST_BOOT_PACKAGE"
  export R_DISK_PREBOOT="$INSTALLED_DISK_PREBOOT" R_DISK_POSTBOOT="$INSTALLED_DISK_POSTBOOT"
  python3 - <<'PY'
import json, os, pathlib
def load_json_env(name):
    raw = os.environ.get(name, "")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception as exc:
        return {"inspection_ok": False, "parse_error": str(exc), "raw": raw[:2000]}

payload = {
  "contract": "gha-kvm-system-lab/v1",
  "target": {"product": "proxmox-ve", "version": "9.2-1"},
  "classification": os.environ["R_CLASS"],
  "oracleSatisfied": os.environ["R_ORACLE"].lower() == "true",
  "phase": os.environ["R_PHASE"],
  "detail": os.environ["R_DETAIL"],
  "requested_shape": {"vcpus": 2, "ram_mib": 4096, "disk": "40G"},
  "source": {
    "iso_name": "proxmox-ve_9.2-1.iso",
    "iso_url": "https://enterprise.proxmox.com/iso/proxmox-ve_9.2-1.iso",
    "expected_sha256": "4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c",
    "observed_sha256": os.environ.get("R_ISO_SHA") or None,
    "installer_source_version": "9.2.5",
    "installer_source_commit": "32afcd4cd534d8e2f99ae76aa0234a0a5c697ba9",
    "iso_first_boot_package": os.environ.get("R_ISO_FIRST_BOOT_PACKAGE") or None,
  },
  "oracles": {
    "vendor_iso_digest": os.environ.get("R_ISO_SHA") == "4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c",
    "unattended_install_completed": os.environ.get("R_INSTALL_SUCCESS_MARKER_OBSERVED") == "true",
    "installed_disk_layout": os.environ.get("R_INSTALLED_DISK_LAYOUT_OK") == "true",
    "installed_https_api": bool(os.environ.get("R_API")),
    "nested_kvm_observed_via_ssh": os.environ.get("R_NESTED") == "yes",
  },
  "api_version": json.loads(os.environ["R_API"]) if os.environ.get("R_API") else None,
  "nested_kvm": os.environ.get("R_NESTED"),
  "diagnostics": {
    "qemu_alive_at_api_gate": os.environ.get("R_QEMU_ALIVE"),
    "ssh_hostfwd_accepted": os.environ.get("R_SSH_HOSTFWD_ACCEPTED") == "true",
    "api_hostfwd_accepted": os.environ.get("R_API_HOSTFWD_ACCEPTED") == "true",
    "guest": os.environ.get("R_GUEST_DIAGNOSTICS") or None,
    "first_boot_witness_observed": os.environ.get("R_FIRST_BOOT_WITNESS_OBSERVED") == "true",
    "first_boot_witness": os.environ.get("R_FIRST_BOOT_WITNESS") or None,
    "installed_disk_preboot": load_json_env("R_DISK_PREBOOT"),
    "installed_disk_postboot": load_json_env("R_DISK_POSTBOOT"),
  },
  "serial_tail": os.environ.get("R_SERIAL", ""),
  "limitations": [
    "Disposable virtual-hardware target profile; not physical-HBA/SMART/IPMI/HA qualification.",
    "Nested KVM is a separate oracle from Proxmox management-plane support.",
  ],
}
pathlib.Path(os.environ["R_OUT"]).write_text(json.dumps(payload, indent=2, sort_keys=True)+"\n", encoding="utf-8")
PY
}

fail_evidence() {
  local class="$1" phase="$2" detail="$3"
  write_receipt "$class" false "$phase" "$detail"
  echo "$class: $phase: $detail" >&2
  exit 0
}

for cmd in curl sha256sum qemu-img qemu-system-x86_64 xorriso python3 lsblk blkid mount umount readlink udevadm losetup mountpoint; do
  command -v "$cmd" >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: $cmd"
done
if ! command -v pvs >/dev/null 2>&1 || ! command -v lvs >/dev/null 2>&1 || ! command -v lvchange >/dev/null 2>&1; then
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends lvm2 >/dev/null 2>&1 ||
    fail_evidence ENVIRONMENT_FAILURE preflight "could not install lvm2 diagnostic dependency"
fi
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail_evidence ENVIRONMENT_FAILURE preflight "requires Linux x86_64"
[[ -e /dev/kvm ]] || fail_evidence ENVIRONMENT_FAILURE preflight "/dev/kvm absent"
sudo -n test -r /dev/kvm && sudo -n test -w /dev/kvm || fail_evidence ENVIRONMENT_FAILURE preflight "passwordless sudo KVM boundary unavailable"

MEM_AVAIL_KIB="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
FREE_KIB="$(df -Pk "$STATE_DIR" | awk 'NR==2 {print $4}')"
(( MEM_AVAIL_KIB >= MIN_HOST_MEM_KIB )) || fail_evidence SKIPPED_GUARDRAIL preflight "host memory headroom below 6 GiB"
(( FREE_KIB >= MIN_HOST_FREE_KIB )) || fail_evidence SKIPPED_GUARDRAIL preflight "host disk headroom below 16 GiB (observed ${FREE_KIB} KiB)"

ISO="$STATE_DIR/$ISO_NAME"
curl --fail --location --retry 3 --silent --show-error "$ISO_URL" -o "$ISO" || fail_evidence ENVIRONMENT_FAILURE acquire "vendor ISO download failed"
OBSERVED_ISO_SHA="$(sha256sum "$ISO" | awk '{print $1}')"
[[ "$OBSERVED_ISO_SHA" == "$ISO_SHA256" ]] || fail_evidence ORACLE_FAILURE acquire "vendor ISO digest mismatch"

ISO_FIRST_BOOT_PATHS="$(xorriso -indev "$ISO" -find /proxmox/packages -type f -name 'proxmox-first-boot_*.deb' -- 2>/dev/null)" ||
  fail_evidence HARNESS_FAILURE acquire "could not inspect first-boot package identity in vendor ISO"
ISO_FIRST_BOOT_PATH="$(printf '%s\n' "$ISO_FIRST_BOOT_PATHS" | sed -n '1p' | tr -d "'")"
ISO_FIRST_BOOT_PACKAGE="$(basename "$ISO_FIRST_BOOT_PATH")"
[[ "$ISO_FIRST_BOOT_PACKAGE" == proxmox-first-boot_${PVE_INSTALLER_SOURCE_VERSION}_*.deb ]] ||
  fail_evidence ORACLE_FAILURE acquire "ISO first-boot package does not match pinned source version ${PVE_INSTALLER_SOURCE_VERSION}: ${ISO_FIRST_BOOT_PACKAGE:-absent}"

cat >"$STATE_DIR/answer.toml" <<EOF
[global]
keyboard = "en-us"
country = "us"
fqdn = "pve-rdte.example.invalid"
mailto = "rdte@example.invalid"
timezone = "UTC"
root-password = "$ROOT_PASSWORD"

[first-boot]
source = "from-iso"
ordering = "network-online"

[network]
source = "from-dhcp"

[disk-setup]
filesystem = "ext4"
disk-list = ["sda"]
EOF
printf 'mode = "iso"\n' >"$STATE_DIR/auto-installer-mode.toml"

cat >"$STATE_DIR/proxmox-first-boot" <<'EOF'
#!/bin/sh
set +e
RDTE_FIRST_BOOT_LOG="/var/lib/proxmox-first-boot/rdte-first-boot.log"
exec >"$RDTE_FIRST_BOOT_LOG" 2>&1
echo "PVE_RDTE_WITNESS_BEGIN"
if [ -c /dev/ttyS0 ]; then
  echo "TTY_S0=character-device"
else
  echo "TTY_S0=absent-or-not-character-device"
fi
printf 'ORDERING_ARG=%s\n' "${1:-unset}"
printf 'HOSTNAME='; hostname -f 2>/dev/null || hostname 2>/dev/null || true
printf 'KERNEL='; uname -a 2>/dev/null || true
echo "HOSTS_BEGIN"
cat /etc/hosts 2>&1 || true
echo "HOSTS_END"
echo "IP_ADDR_BEGIN"
ip -brief address 2>&1 || true
echo "IP_ADDR_END"
echo "IP_ROUTE_BEGIN"
ip route 2>&1 || true
echo "IP_ROUTE_END"
echo "NETWORK_INTERFACES_BEGIN"
cat /etc/network/interfaces 2>&1 || true
echo "NETWORK_INTERFACES_END"
echo "PVE_INITIAL_SERVICES_BEGIN"
for service in pve-cluster pvedaemon pvestatd pveproxy ssh networking systemd-networkd; do
  printf '%s=' "$service"
  systemctl is-active "$service" 2>/dev/null || true
done
echo "PVE_INITIAL_SERVICES_END"

# network-online intentionally runs before the product proxy dependency used by
# the upstream "fully-up" first-boot unit. Poll without mutating so a failing
# pveproxy can still leave guest-originated evidence instead of deadlocking the oracle.
for _ in $(seq 1 45); do
  if systemctl is-active --quiet pveproxy 2>/dev/null && ss -lnt 2>/dev/null | grep -Eq '[:.]8006[[:space:]]'; then
    break
  fi
  sleep 2
done

echo "PVE_FINAL_SERVICES_BEGIN"
for service in pve-cluster pvedaemon pvestatd pveproxy ssh networking systemd-networkd; do
  printf '%s=' "$service"
  systemctl is-active "$service" 2>/dev/null || true
done
echo "PVE_FINAL_SERVICES_END"
echo "LISTENERS_BEGIN"
ss -lntp 2>&1 || true
echo "LISTENERS_END"
echo "FAILED_UNITS_BEGIN"
systemctl --failed --no-pager 2>&1 || true
echo "FAILED_UNITS_END"
echo "PVEPROXY_JOURNAL_BEGIN"
journalctl -u pveproxy -b --no-pager -n 80 2>&1 || true
echo "PVEPROXY_JOURNAL_END"
echo "PVECLUSTER_JOURNAL_BEGIN"
journalctl -u pve-cluster -b --no-pager -n 80 2>&1 || true
echo "PVECLUSTER_JOURNAL_END"
if [ -e /dev/kvm ]; then echo "KVM_DEVICE=present"; else echo "KVM_DEVICE=absent"; fi
if grep -Eq '(vmx|svm)' /proc/cpuinfo 2>/dev/null; then echo "CPU_VIRT_FLAG=present"; else echo "CPU_VIRT_FLAG=absent"; fi
echo "PVE_RDTE_WITNESS_END"
sync || true
if [ -c /dev/ttyS0 ]; then
  cat "$RDTE_FIRST_BOOT_LOG" >/dev/ttyS0 2>&1 || true
fi
exit 0
EOF
chmod 0755 "$STATE_DIR/proxmox-first-boot"

xorriso -osirrox on -indev "$ISO" -extract /boot/grub/grub.cfg "$STATE_DIR/grub.cfg" >/dev/null 2>&1 ||
  fail_evidence HARNESS_FAILURE prepare "could not extract Proxmox GRUB config"
chmod u+w "$STATE_DIR/grub.cfg"
python3 - "$STATE_DIR/grub.cfg" <<'PY'
import pathlib, sys
p=pathlib.Path(sys.argv[1])
s=p.read_text(encoding="utf-8")
lines=[]
changed=False
for line in s.splitlines():
    if "proxmox-start-auto-installer" in line and line.lstrip().startswith("linux") and "console=ttyS0" not in line:
        line += " console=ttyS0,115200"
        changed=True
    lines.append(line)
if not changed:
    raise SystemExit("automated installer kernel line not found")
p.write_text("\n".join(lines)+"\n", encoding="utf-8")
PY

AUTO_ISO="$STATE_DIR/proxmox-auto.iso"
cp --reflink=auto "$ISO" "$AUTO_ISO"
chmod u+w "$AUTO_ISO"
xorriso -boot_image any keep -dev "$AUTO_ISO" \
  -map "$STATE_DIR/auto-installer-mode.toml" /auto-installer-mode.toml \
  -map "$STATE_DIR/answer.toml" /answer.toml \
  -map "$STATE_DIR/proxmox-first-boot" /proxmox-first-boot \
  -map "$STATE_DIR/grub.cfg" /boot/grub/grub.cfg \
  -commit >/dev/null 2>"$STATE_DIR/xorriso.log" ||
  fail_evidence HARNESS_FAILURE prepare "failed to construct unattended Proxmox ISO"

# Prove that the same exact file name consumed by the upstream auto-installer
# (/cdrom/proxmox-first-boot) exists in the prepared ISO before spending a VM rep.
xorriso -osirrox on -indev "$AUTO_ISO" \
  -extract /proxmox-first-boot "$STATE_DIR/proxmox-first-boot.iso" >/dev/null 2>&1 ||
  fail_evidence HARNESS_FAILURE prepare "prepared ISO does not contain /proxmox-first-boot"
[[ "$(sha256sum "$STATE_DIR/proxmox-first-boot" | awk '{print $1}')" == \
   "$(sha256sum "$STATE_DIR/proxmox-first-boot.iso" | awk '{print $1}')" ]] ||
  fail_evidence HARNESS_FAILURE prepare "prepared ISO first-boot hook content mismatch"

qemu-img create -q -f qcow2 "$STATE_DIR/system.qcow2" "$DISK_SIZE"
SSH_PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)"
WEB_PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)"


port_open() {
  local port="$1"
  python3 - "$port" <<'PY'
import socket, sys
s=socket.socket()
s.settimeout(1.0)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    raise SystemExit(1)
finally:
    s.close()
PY
}

guest_diagnostics() {
  command -v sshpass >/dev/null 2>&1 || return 0
  sshpass -p "$ROOT_PASSWORD" ssh -p "$SSH_PORT"     -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5     root@127.0.0.1 '
      echo "===PVEVERSION===";
      pveversion -v 2>&1 || true;
      echo "===SYSTEMD_FAILED===";
      systemctl --failed --no-pager 2>&1 || true;
      echo "===PVE_SERVICES===";
      for s in pveproxy pvedaemon pvestatd pve-cluster networking systemd-networkd; do
        echo "--- $s ---";
        systemctl status "$s" --no-pager -l 2>&1 | tail -n 40 || true;
      done;
      echo "===LISTENERS===";
      ss -lntup 2>&1 || true;
      echo "===IP_ADDR===";
      ip -brief addr 2>&1 || true;
      echo "===IP_ROUTE===";
      ip route 2>&1 || true;
      echo "===RESOLV===";
      cat /etc/resolv.conf 2>&1 || true;
      echo "===PVE_PROXY_JOURNAL===";
      journalctl -u pveproxy -b --no-pager -n 100 2>&1 || true;
    ' 2>&1 | tail -c 24000
}

start_qemu() {
  local with_iso="$1"
  : >"$STATE_DIR/serial.log"
  local args=(
    -enable-kvm -cpu host -smp "$VCPUS" -m "$RAM_MIB"
    -device virtio-scsi-pci,id=scsi0
    -drive "file=$STATE_DIR/system.qcow2,if=none,format=qcow2,id=system"
    -device scsi-hd,drive=system
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$WEB_PORT-:8006"
    -device e1000,netdev=net0
    -display none -monitor none
    -serial "file:$STATE_DIR/serial.log"
    -daemonize -pidfile "$STATE_DIR/qemu.pid"
  )
  if [[ "$with_iso" == yes ]]; then args+=( -cdrom "$AUTO_ISO" -boot order=d ); else args+=( -boot order=c ); fi
  sudo -n qemu-system-x86_64 "${args[@]}"
  QEMU_PID="$(sudo -n cat "$STATE_DIR/qemu.pid")"
}
stop_qemu() {
  if [[ -n "$QEMU_PID" ]]; then
    sudo -n kill "$QEMU_PID" >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do sudo -n kill -0 "$QEMU_PID" >/dev/null 2>&1 || break; sleep 0.25; done
    sudo -n kill -9 "$QEMU_PID" >/dev/null 2>&1 || true
    QEMU_PID=""
  fi
}

inspect_installed_disk() {
  local phase="$1"
  local raw="$STATE_DIR/system-${phase}.raw"
  local loopdev="" pv="" vg="" rootdev="" mnt="$STATE_DIR/mnt-$phase"
  local hook_present=false hook_exec=false hook_sha="" hook_matches=false pending=false
  local unit_present=false alias_target="" wants_target="" log_present=false log_text="" package_version=""

  cleanup_inspection() {
    set +e
    if mountpoint -q "$mnt" 2>/dev/null; then sudo -n umount "$mnt" >/dev/null 2>&1 || true; fi
    if [[ -n "$rootdev" ]]; then sudo -n lvchange -an "$rootdev" >/dev/null 2>&1 || true; fi
    if [[ -n "$loopdev" ]]; then sudo -n losetup -d "$loopdev" >/dev/null 2>&1 || true; fi
    rm -f -- "$raw"
    set -e
  }

  emit_inspection_error() {
    local layout="" blkids="" image_info=""
    image_info="$(qemu-img info --output=json "$STATE_DIR/system.qcow2" 2>&1 || true)"
    if [[ -n "$loopdev" && -b "$loopdev" ]]; then
      layout="$(sudo -n lsblk -lnpo NAME,TYPE,FSTYPE,PTTYPE,PARTTYPE,PARTLABEL,SIZE "$loopdev" 2>&1 || true)"
      blkids="$(sudo -n blkid 2>&1 | grep -F "$loopdev" || true)"
    fi
    R_PHASE="$phase" R_ERROR="$1" R_LAYOUT="$layout" R_BLKIDS="$blkids" R_IMAGE_INFO="$image_info" python3 - <<'PY'
import json, os
print(json.dumps({
    "phase": os.environ["R_PHASE"],
    "inspection_ok": False,
    "error": os.environ["R_ERROR"],
    "qemu_img_info": os.environ.get("R_IMAGE_INFO") or None,
    "lsblk": os.environ.get("R_LAYOUT") or None,
    "blkid": os.environ.get("R_BLKIDS") or None,
}, sort_keys=True))
PY
    cleanup_inspection
  }

  # Keep the product disk immutable. Convert qcow2 to a sparse raw read-only
  # inspection copy, then let the kernel expose its partition table via loop.
  # This avoids making Proxmox evidence depend on the qemu-nbd daemon lifecycle.
  qemu-img convert -f qcow2 -O raw -S 4k "$STATE_DIR/system.qcow2" "$raw" >/dev/null 2>&1 ||
    { emit_inspection_error "qcow2 sparse-raw conversion failed"; return 0; }
  loopdev="$(sudo -n losetup --find --show --read-only --partscan "$raw" 2>/dev/null || true)"
  [[ -n "$loopdev" ]] || { emit_inspection_error "read-only loop attach failed"; return 0; }
  sudo -n udevadm settle >/dev/null 2>&1 || true
  sleep 1

  while read -r dev type; do
    [[ "$type" == "part" ]] || continue
    if [[ "$(sudo -n blkid -p -s TYPE -o value "$dev" 2>/dev/null || true)" == "LVM2_member" ]]; then
      pv="$dev"
      break
    fi
  done < <(sudo -n lsblk -lnpo NAME,TYPE "$loopdev" 2>/dev/null)

  [[ -n "$pv" ]] || { emit_inspection_error "installed LVM PV not found"; return 0; }

  sudo -n pvscan --cache "$pv" >/dev/null 2>&1 || true
  vg="$(sudo -n pvs --noheadings -o vg_name "$pv" 2>/dev/null | xargs || true)"
  [[ -n "$vg" ]] || { emit_inspection_error "installed VG not found"; return 0; }

  rootdev="$(sudo -n lvs --noheadings -o lv_path,lv_name "$vg" 2>/dev/null | awk '$2=="root" {print $1; exit}')"
  if [[ -z "$rootdev" ]] || ! sudo -n lvchange -ay "$rootdev" >/dev/null 2>&1; then
    emit_inspection_error "installed root LV not activatable"
    return 0
  fi

  mkdir -p "$mnt"
  if ! sudo -n mount -o ro,noload "$rootdev" "$mnt" >/dev/null 2>&1; then
    emit_inspection_error "installed root LV mount failed"
    return 0
  fi

  local hook="$mnt/var/lib/proxmox-first-boot/proxmox-first-boot"
  local pending_path="$mnt/var/lib/proxmox-first-boot/pending-first-boot-setup"
  local unit="$mnt/lib/systemd/system/proxmox-first-boot-network-online.service"
  local alias="$mnt/etc/systemd/system/proxmox-first-boot.service"
  local wants="$mnt/etc/systemd/system/multi-user.target.wants/proxmox-first-boot-network-online.service"
  local log="$mnt/var/lib/proxmox-first-boot/rdte-first-boot.log"

  if sudo -n test -f "$hook"; then
    hook_present=true
    sudo -n test -x "$hook" && hook_exec=true
    hook_sha="$(sudo -n sha256sum "$hook" 2>/dev/null | awk '{print $1}')"
    [[ "$hook_sha" == "$(sha256sum "$STATE_DIR/proxmox-first-boot" | awk '{print $1}')" ]] && hook_matches=true
  fi
  sudo -n test -e "$pending_path" && pending=true
  sudo -n test -f "$unit" && unit_present=true
  alias_target="$(sudo -n readlink "$alias" 2>/dev/null || true)"
  wants_target="$(sudo -n readlink "$wants" 2>/dev/null || true)"
  if sudo -n test -f "$log"; then
    log_present=true
    log_text="$(sudo -n tail -c 16000 "$log" 2>/dev/null || true)"
  fi
  package_version="$(sudo -n sed -n '/^Package: proxmox-first-boot$/,/^$/p' "$mnt/var/lib/dpkg/status" 2>/dev/null | sed -n 's/^Version: //p' | head -n 1)"

  R_PHASE="$phase" R_ROOT="$rootdev" R_HOOK_PRESENT="$hook_present" R_HOOK_EXEC="$hook_exec" \
  R_HOOK_SHA="$hook_sha" R_HOOK_MATCH="$hook_matches" R_PENDING="$pending" R_UNIT="$unit_present" \
  R_ALIAS="$alias_target" R_WANTS="$wants_target" R_LOG_PRESENT="$log_present" R_LOG="$log_text" \
  R_PACKAGE_VERSION="$package_version" python3 - <<'PY'
import json, os
def b(name): return os.environ.get(name, "false").lower() == "true"
print(json.dumps({
    "phase": os.environ["R_PHASE"],
    "inspection_ok": True,
    "root_lv": os.environ.get("R_ROOT") or None,
    "first_boot_package_version": os.environ.get("R_PACKAGE_VERSION") or None,
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
  cleanup_inspection
}

start_qemu yes
INSTALL_OK=false
for _ in $(seq 1 360); do
  # Exact pve-installer 9.2.5 source emits this only after run_installation()
  # returns Ok. Do not accept the earlier "Rebooting system after successful
  # installation" setup log, which is emitted before installation starts.
  if grep -Fq 'Installation done.' "$STATE_DIR/serial.log" 2>/dev/null; then
    INSTALL_OK=true
    INSTALL_SUCCESS_MARKER_OBSERVED="true"
    break
  fi
  if grep -Fq 'Installation failed:' "$STATE_DIR/serial.log" 2>/dev/null; then break; fi
  if ! sudo -n kill -0 "$QEMU_PID" >/dev/null 2>&1; then break; fi
  sleep 5
done
[[ "$INSTALL_OK" == true ]] || fail_evidence ORACLE_FAILURE install "exact post-run_installation success witness not observed within bounded window"
stop_qemu
INSTALLED_DISK_PREBOOT="$(inspect_installed_disk preboot)"
if python3 - "$INSTALLED_DISK_PREBOOT" <<'PY'
import json, sys
try:
    payload = json.loads(sys.argv[1])
except Exception:
    raise SystemExit(1)
ok = (
    payload.get("inspection_ok") is True
    and payload.get("root_lv") == "/dev/pve/root"
)
raise SystemExit(0 if ok else 1)
PY
then
  INSTALLED_DISK_LAYOUT_OK="true"
else
  fail_evidence ORACLE_FAILURE installed-disk "exact installer success marker observed but installed /dev/pve/root layout was not proven"
fi

start_qemu no
API_VERSION_JSON=""
SSH_HOSTFWD_ACCEPTED="false"
API_HOSTFWD_ACCEPTED="false"
QEMU_ALIVE_AT_API_GATE="unknown"
for _ in $(seq 1 120); do
  if sudo -n kill -0 "$QEMU_PID" >/dev/null 2>&1; then
    QEMU_ALIVE_AT_API_GATE="true"
  else
    QEMU_ALIVE_AT_API_GATE="false"
    break
  fi
  if grep -q 'PVE_RDTE_WITNESS_END' "$STATE_DIR/serial.log" 2>/dev/null; then
    FIRST_BOOT_WITNESS_OBSERVED="true"
    FIRST_BOOT_WITNESS="$(awk '/PVE_RDTE_WITNESS_BEGIN/{capture=1} capture{print} /PVE_RDTE_WITNESS_END/{exit}' "$STATE_DIR/serial.log" | tr -d '\000' | sed -E 's/[^[:print:]\t]//g' | tail -c 16000)"
  fi
  if port_open "$SSH_PORT"; then SSH_HOSTFWD_ACCEPTED="true"; fi
  if port_open "$WEB_PORT"; then API_HOSTFWD_ACCEPTED="true"; fi
  if [[ "$API_HOSTFWD_ACCEPTED" == "true" ]]; then
    API_VERSION_JSON="$(curl -sk --max-time 3 "https://127.0.0.1:$WEB_PORT/api2/json/version" 2>/dev/null || true)"
    if [[ "$API_VERSION_JSON" == *'"data"'* ]]; then break; fi
  fi
  if [[ "$FIRST_BOOT_WITNESS_OBSERVED" == "true" && -z "$API_VERSION_JSON" ]]; then
    break
  fi
  sleep 3
done
if [[ "$API_VERSION_JSON" != *'"data"'* ]]; then
  if command -v sshpass >/dev/null 2>&1 && sshpass -p "$ROOT_PASSWORD" ssh -p "$SSH_PORT" \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
      root@127.0.0.1 'true' >/dev/null 2>&1; then
    GUEST_DIAGNOSTICS="$(guest_diagnostics || true)"
  fi
  stop_qemu
  INSTALLED_DISK_POSTBOOT="$(inspect_installed_disk postboot)"
  fail_evidence ORACLE_FAILURE installed-api "installed Proxmox HTTPS API did not answer (qemu_alive=$QEMU_ALIVE_AT_API_GATE first_boot_witness=$FIRST_BOOT_WITNESS_OBSERVED)"
fi

NESTED_KVM="unknown"
if command -v sshpass >/dev/null 2>&1; then
  if sshpass -p "$ROOT_PASSWORD" ssh -p "$SSH_PORT" \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
      root@127.0.0.1 'test -e /dev/kvm && grep -Eq "(vmx|svm)" /proc/cpuinfo' >/dev/null 2>&1; then
    NESTED_KVM="yes"
  else
    NESTED_KVM="unknown"
  fi
fi

write_receipt SUPPORTED true complete "real Proxmox VE unattended install completed and installed HTTPS API answered"
