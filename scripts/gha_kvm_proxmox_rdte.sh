#!/usr/bin/env bash
set -euo pipefail

ISO_NAME="proxmox-ve_9.2-1.iso"
ISO_URL="https://enterprise.proxmox.com/iso/$ISO_NAME"
ISO_SHA256="4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c"
RAM_MIB=4096
VCPUS=2
DISK_SIZE="40G"
MIN_HOST_MEM_KIB=$((6 * 1024 * 1024))
MIN_HOST_FREE_KIB=$((24 * 1024 * 1024))

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
SSH_REACHABLE="false"
API_PORT_REACHABLE="false"
QEMU_ALIVE_AT_API_GATE="unknown"
GUEST_DIAGNOSTICS=""
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
  export R_SSH_REACHABLE="$SSH_REACHABLE" R_API_PORT_REACHABLE="$API_PORT_REACHABLE"
  export R_QEMU_ALIVE="$QEMU_ALIVE_AT_API_GATE" R_GUEST_DIAGNOSTICS="$GUEST_DIAGNOSTICS"
  python3 - <<'PY'
import json, os, pathlib
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
  },
  "oracles": {
    "vendor_iso_digest": bool(os.environ.get("R_ISO_SHA")),
    "unattended_install_completed": os.environ["R_PHASE"] in {"installed-api", "complete"},
    "installed_https_api": bool(os.environ.get("R_API")),
    "nested_kvm_observed_via_ssh": os.environ.get("R_NESTED") == "yes",
  },
  "api_version": json.loads(os.environ["R_API"]) if os.environ.get("R_API") else None,
  "nested_kvm": os.environ.get("R_NESTED"),
  "diagnostics": {
    "qemu_alive_at_api_gate": os.environ.get("R_QEMU_ALIVE"),
    "ssh_port_reachable": os.environ.get("R_SSH_REACHABLE") == "true",
    "api_port_reachable": os.environ.get("R_API_PORT_REACHABLE") == "true",
    "guest": os.environ.get("R_GUEST_DIAGNOSTICS") or None,
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

for cmd in curl sha256sum qemu-img qemu-system-x86_64 xorriso python3; do
  command -v "$cmd" >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: $cmd"
done
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail_evidence ENVIRONMENT_FAILURE preflight "requires Linux x86_64"
[[ -e /dev/kvm ]] || fail_evidence ENVIRONMENT_FAILURE preflight "/dev/kvm absent"
sudo -n test -r /dev/kvm && sudo -n test -w /dev/kvm || fail_evidence ENVIRONMENT_FAILURE preflight "passwordless sudo KVM boundary unavailable"

MEM_AVAIL_KIB="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
FREE_KIB="$(df -Pk "$STATE_DIR" | awk 'NR==2 {print $4}')"
(( MEM_AVAIL_KIB >= MIN_HOST_MEM_KIB )) || fail_evidence SKIPPED_GUARDRAIL preflight "host memory headroom below 6 GiB"
(( FREE_KIB >= MIN_HOST_FREE_KIB )) || fail_evidence SKIPPED_GUARDRAIL preflight "host disk headroom below 24 GiB"

ISO="$STATE_DIR/$ISO_NAME"
curl --fail --location --retry 3 --silent --show-error "$ISO_URL" -o "$ISO" || fail_evidence ENVIRONMENT_FAILURE acquire "vendor ISO download failed"
OBSERVED_ISO_SHA="$(sha256sum "$ISO" | awk '{print $1}')"
[[ "$OBSERVED_ISO_SHA" == "$ISO_SHA256" ]] || fail_evidence ORACLE_FAILURE acquire "vendor ISO digest mismatch"

cat >"$STATE_DIR/answer.toml" <<'EOF'
[global]
keyboard = "en-us"
country = "us"
fqdn = "pve-rdte.example.invalid"
mailto = "rdte@example.invalid"
timezone = "Etc/UTC"
root-password = "rdte-proxmox-ephemeral-9264"

[network]
source = "from-dhcp"

[disk-setup]
filesystem = "ext4"
disk-list = ["sda"]
EOF
printf 'mode = "iso"\n' >"$STATE_DIR/auto-installer-mode.toml"

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
  -map "$STATE_DIR/grub.cfg" /boot/grub/grub.cfg \
  -commit >/dev/null 2>"$STATE_DIR/xorriso.log" ||
  fail_evidence HARNESS_FAILURE prepare "failed to construct unattended Proxmox ISO"

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
  sshpass -p 'rdte-proxmox-ephemeral-9264' ssh -p "$SSH_PORT"     -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5     root@127.0.0.1 '
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

start_qemu yes
INSTALL_OK=false
for _ in $(seq 1 360); do
  if grep -Eqi 'Installation done|installation finished|powering off|rebooting' "$STATE_DIR/serial.log" 2>/dev/null; then INSTALL_OK=true; break; fi
  if ! sudo -n kill -0 "$QEMU_PID" >/dev/null 2>&1; then break; fi
  sleep 5
done
[[ "$INSTALL_OK" == true ]] || fail_evidence ORACLE_FAILURE install "unattended installer did not reach completion marker within bounded window"
stop_qemu

start_qemu no
API_VERSION_JSON=""
SSH_REACHABLE="false"
API_PORT_REACHABLE="false"
QEMU_ALIVE_AT_API_GATE="unknown"
for _ in $(seq 1 120); do
  if sudo -n kill -0 "$QEMU_PID" >/dev/null 2>&1; then
    QEMU_ALIVE_AT_API_GATE="true"
  else
    QEMU_ALIVE_AT_API_GATE="false"
    break
  fi
  if port_open "$SSH_PORT"; then SSH_REACHABLE="true"; fi
  if port_open "$WEB_PORT"; then API_PORT_REACHABLE="true"; fi
  if [[ "$API_PORT_REACHABLE" == "true" ]]; then
    API_VERSION_JSON="$(curl -sk --max-time 3 "https://127.0.0.1:$WEB_PORT/api2/json/version" 2>/dev/null || true)"
    if [[ "$API_VERSION_JSON" == *'"data"'* ]]; then break; fi
  fi
  sleep 3
done
if [[ "$API_VERSION_JSON" != *'"data"'* ]]; then
  if [[ "$SSH_REACHABLE" == "true" ]]; then
    GUEST_DIAGNOSTICS="$(guest_diagnostics || true)"
  fi
  fail_evidence ORACLE_FAILURE installed-api "installed Proxmox HTTPS API did not answer (qemu_alive=$QEMU_ALIVE_AT_API_GATE ssh=$SSH_REACHABLE tcp8006=$API_PORT_REACHABLE)"
fi

NESTED_KVM="unknown"
if command -v sshpass >/dev/null 2>&1; then
  if sshpass -p 'rdte-proxmox-ephemeral-9264' ssh -p "$SSH_PORT" \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
      root@127.0.0.1 'test -e /dev/kvm && grep -Eq "(vmx|svm)" /proc/cpuinfo' >/dev/null 2>&1; then
    NESTED_KVM="yes"
  else
    NESTED_KVM="no"
  fi
fi

write_receipt SUPPORTED true complete "real Proxmox VE unattended install completed and installed HTTPS API answered"
