#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VERSION="26.0.0-BETA.3"
ISO_NAME="TrueNAS-26.0.0-BETA.3.iso"
BASE_URL="https://download.sys.truenas.net/TrueNAS-26-BETA/26.0.0-BETA.3"
ISO_URL="$BASE_URL/$ISO_NAME"
SHA_URL="$ISO_URL.sha256"
RAM_MIB=8192
VCPUS=2
DISK_SIZE="24G"
MIN_HOST_MEM_KIB=$((11 * 1024 * 1024))
MIN_HOST_FREE_KIB=$((28 * 1024 * 1024))

usage() {
  echo "Usage: gha_kvm_truenas_rdte.sh --out RECEIPT [--state-dir DIR] [--rung t0|t1]"
}

OUT=""
STATE_DIR=""
RUNG="t0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --rung) RUNG="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -n "$OUT" ]] || { usage >&2; exit 2; }
[[ "$RUNG" == "t0" || "$RUNG" == "t1" ]] || { echo "rung must be t0 or t1" >&2; exit 2; }

if [[ -z "$STATE_DIR" ]]; then STATE_DIR="$(mktemp -d -t gha-kvm-truenas.XXXXXX)"; fi
mkdir -p "$STATE_DIR" "$(dirname "$OUT")"
STATE_DIR="$(realpath "$STATE_DIR")"
OUT="$(realpath -m "$OUT")"
[[ "$OUT" != "$STATE_DIR/"* ]] || { echo "receipt must be outside disposable state" >&2; exit 2; }

QEMU_PID=""
OBSERVED_ISO_SHA=""
EXPECTED_ISO_SHA=""
GRUB_PATH=""
T0_OBSERVED="false"
RPC_REACHABLE="false"
RPC_DISCOVERY_JSON=""
QEMU_ALIVE_AT_GATE="unknown"
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
    serial_tail="$(tail -n 120 "$STATE_DIR/serial.log" | tr -d '\000' | sed -E 's/[^[:print:]\t]//g' | tail -c 16000)"
  fi
  export R_OUT="$OUT" R_CLASS="$classification" R_ORACLE="$oracle" R_PHASE="$phase" R_DETAIL="$detail"
  export R_SERIAL="$serial_tail" R_ISO_SHA="$OBSERVED_ISO_SHA" R_EXPECTED="$EXPECTED_ISO_SHA" R_GRUB="$GRUB_PATH"
  export R_RUNG="$RUNG" R_T0="$T0_OBSERVED" R_RPC_REACHABLE="$RPC_REACHABLE"
  export R_RPC_DISCOVERY="$RPC_DISCOVERY_JSON" R_QEMU_ALIVE="$QEMU_ALIVE_AT_GATE"
  python3 - <<'PY'
import json, os, pathlib
payload = {
  "contract": "gha-kvm-system-lab/v1",
  "target": {"product": "truenas", "version": "26.0.0-BETA.3", "rung": os.environ.get("R_RUNG", "t0").upper()},
  "classification": os.environ["R_CLASS"],
  "oracleSatisfied": os.environ["R_ORACLE"].lower() == "true",
  "phase": os.environ["R_PHASE"],
  "detail": os.environ["R_DETAIL"],
  "requested_shape": {"vcpus": 2, "ram_mib": 8192, "boot_disk": "24G"},
  "source": {
    "iso_name": "TrueNAS-26.0.0-BETA.3.iso",
    "iso_url": "https://download.sys.truenas.net/TrueNAS-26-BETA/26.0.0-BETA.3/TrueNAS-26.0.0-BETA.3.iso",
    "vendor_sha256_url": "https://download.sys.truenas.net/TrueNAS-26-BETA/26.0.0-BETA.3/TrueNAS-26.0.0-BETA.3.iso.sha256",
    "expected_sha256": os.environ.get("R_EXPECTED") or None,
    "observed_sha256": os.environ.get("R_ISO_SHA") or None,
  },
  "installer_grub_path": os.environ.get("R_GRUB") or None,
  "oracles": {
    "vendor_iso_digest": bool(os.environ.get("R_ISO_SHA")) and os.environ.get("R_ISO_SHA") == os.environ.get("R_EXPECTED"),
    "installer_environment_observed": os.environ.get("R_T0") == "true",
    "installer_rpc_port_reachable": os.environ.get("R_RPC_REACHABLE") == "true",
    "installer_rpc_readonly": bool(os.environ.get("R_RPC_DISCOVERY")),
  },
  "rpc_discovery": json.loads(os.environ["R_RPC_DISCOVERY"]) if os.environ.get("R_RPC_DISCOVERY") else None,
  "qemu_alive_at_gate": os.environ.get("R_QEMU_ALIVE"),
  "serial_tail": os.environ.get("R_SERIAL", ""),
  "limitations": [
    "T0 proves pinned vendor media integrity and installer-environment boot under the disposable virtual target profile.",
    "T1 is read-only installer RPC discovery; installation, ZFS, middleware, Containers, Apps, and application lifecycle remain later gates.",
    "This does not qualify physical storage controllers, SMART, GPU, IPMI, or HA behavior.",
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

[[ -f "$SCRIPT_DIR/truenas_installer_rpc_probe.py" ]] ||
  fail_evidence HARNESS_FAILURE preflight "missing TrueNAS installer RPC probe"
for cmd in curl sha256sum qemu-img qemu-system-x86_64 xorriso python3; do
  command -v "$cmd" >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: $cmd"
done
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail_evidence ENVIRONMENT_FAILURE preflight "requires Linux x86_64"
[[ -e /dev/kvm ]] || fail_evidence ENVIRONMENT_FAILURE preflight "/dev/kvm absent"
sudo -n test -r /dev/kvm && sudo -n test -w /dev/kvm || fail_evidence ENVIRONMENT_FAILURE preflight "passwordless sudo KVM boundary unavailable"

MEM_AVAIL_KIB="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
FREE_KIB="$(df -Pk "$STATE_DIR" | awk 'NR==2 {print $4}')"
(( MEM_AVAIL_KIB >= MIN_HOST_MEM_KIB )) || fail_evidence SKIPPED_GUARDRAIL preflight "host memory headroom below 11 GiB required before allocating 8 GiB guest"
(( FREE_KIB >= MIN_HOST_FREE_KIB )) || fail_evidence SKIPPED_GUARDRAIL preflight "host disk headroom below 28 GiB"

ISO="$STATE_DIR/$ISO_NAME"
curl --fail --location --retry 3 --silent --show-error "$SHA_URL" -o "$STATE_DIR/vendor.sha256" ||
  fail_evidence ENVIRONMENT_FAILURE acquire "vendor SHA256 sidecar download failed"
EXPECTED_ISO_SHA="$(grep -Eo '[0-9a-fA-F]{64}' "$STATE_DIR/vendor.sha256" | head -n1 | tr 'A-F' 'a-f')"
[[ "$EXPECTED_ISO_SHA" =~ ^[0-9a-f]{64}$ ]] || fail_evidence HARNESS_FAILURE acquire "vendor SHA256 sidecar did not contain a digest"
curl --fail --location --retry 3 --silent --show-error "$ISO_URL" -o "$ISO" ||
  fail_evidence ENVIRONMENT_FAILURE acquire "vendor ISO download failed"
OBSERVED_ISO_SHA="$(sha256sum "$ISO" | awk '{print $1}')"
[[ "$OBSERVED_ISO_SHA" == "$EXPECTED_ISO_SHA" ]] || fail_evidence ORACLE_FAILURE acquire "vendor ISO digest mismatch"

GRUB_PATH=""
for candidate in /boot/grub/grub.cfg /EFI/BOOT/grub.cfg /efi/boot/grub.cfg; do
  if xorriso -osirrox on -indev "$ISO" -extract "$candidate" "$STATE_DIR/grub.cfg" >/dev/null 2>&1; then
    GRUB_PATH="$candidate"
    break
  fi
done
[[ -n "$GRUB_PATH" ]] || fail_evidence HARNESS_FAILURE prepare "could not locate installer GRUB config in pinned ISO"
chmod u+w "$STATE_DIR/grub.cfg"

python3 - "$STATE_DIR/grub.cfg" <<'PY'
import pathlib, sys
p=pathlib.Path(sys.argv[1])
s=p.read_text(encoding="utf-8", errors="replace")
prefix="""insmod serial
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
set timeout=0
"""
lines=[]
changed=False
for line in s.splitlines():
    stripped=line.lstrip()
    if (stripped.startswith("linux ") or stripped.startswith("linuxefi ")) and "console=ttyS0" not in line:
        line += " console=ttyS0,115200"
        changed=True
    lines.append(line)
if not changed:
    raise SystemExit("no Linux kernel command line found in GRUB config")
p.write_text(prefix + "\n".join(lines)+"\n", encoding="utf-8")
PY

SERIAL_ISO="$STATE_DIR/truenas-serial.iso"
cp --reflink=auto "$ISO" "$SERIAL_ISO"
chmod u+w "$SERIAL_ISO"
xorriso -boot_image any keep -dev "$SERIAL_ISO" \
  -map "$STATE_DIR/grub.cfg" "$GRUB_PATH" -commit >/dev/null 2>"$STATE_DIR/xorriso.log" ||
  fail_evidence HARNESS_FAILURE prepare "failed to construct serial-observable TrueNAS ISO"


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

qemu-img create -q -f qcow2 "$STATE_DIR/boot.qcow2" "$DISK_SIZE"
RPC_PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)"
: >"$STATE_DIR/serial.log"
sudo -n qemu-system-x86_64 \
  -enable-kvm -cpu host -smp "$VCPUS" -m "$RAM_MIB" \
  -drive "file=$STATE_DIR/boot.qcow2,if=virtio,format=qcow2" \
  -cdrom "$SERIAL_ISO" -boot order=d \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$RPC_PORT-:8080" -device virtio-net-pci,netdev=net0 \
  -display none -monitor none \
  -serial "file:$STATE_DIR/serial.log" \
  -daemonize -pidfile "$STATE_DIR/qemu.pid" ||
  fail_evidence ENVIRONMENT_FAILURE boot "QEMU could not start TrueNAS guest"
QEMU_PID="$(sudo -n cat "$STATE_DIR/qemu.pid")"

T0_OBSERVED="false"
RPC_REACHABLE="false"
for _ in $(seq 1 220); do
  if grep -Eqi 'TrueNAS|truenas-installer|TrueNAS Installer|Install/Upgrade' "$STATE_DIR/serial.log" 2>/dev/null; then
    T0_OBSERVED="true"
  fi
  if sudo -n kill -0 "$QEMU_PID" >/dev/null 2>&1; then
    QEMU_ALIVE_AT_GATE="true"
  else
    QEMU_ALIVE_AT_GATE="false"
    break
  fi
  if [[ "$RUNG" == "t0" && "$T0_OBSERVED" == "true" ]]; then
    break
  fi
  if [[ "$RUNG" == "t1" ]] && port_open "$RPC_PORT"; then
    RPC_REACHABLE="true"
    break
  fi
  sleep 3
done

if [[ "$RUNG" == "t0" ]]; then
  if [[ "$T0_OBSERVED" == "true" ]]; then
    write_receipt SUPPORTED true installer-boot "pinned TrueNAS vendor ISO reached a TrueNAS-labelled installer environment over serial"
  elif grep -Eqi 'Linux version|systemd|Starting' "$STATE_DIR/serial.log" 2>/dev/null; then
    fail_evidence INCONCLUSIVE installer-boot "Linux boot was observed but a TrueNAS-specific installer marker was not reached"
  else
    fail_evidence ORACLE_FAILURE installer-boot "no bounded installer-environment boot oracle was observed"
  fi
  exit 0
fi

[[ "$T0_OBSERVED" == "true" ]] || fail_evidence ORACLE_FAILURE installer-rpc "T1 did not preserve the T0 installer-environment oracle"
[[ "$RPC_REACHABLE" == "true" ]] || fail_evidence ORACLE_FAILURE installer-rpc "TrueNAS installer RPC port 8080 did not become reachable"

RPC_OUT="$STATE_DIR/rpc-discovery.json"
python3 "$SCRIPT_DIR/truenas_installer_rpc_probe.py"   --host 127.0.0.1 --port "$RPC_PORT" --out "$RPC_OUT" --timeout 8 || true
if [[ -f "$RPC_OUT" ]]; then
  RPC_DISCOVERY_JSON="$(cat "$RPC_OUT")"
fi
RPC_OK="$(python3 - "$RPC_OUT" <<'PY'
import json, pathlib, sys
try:
    data=json.loads(pathlib.Path(sys.argv[1]).read_text())
except Exception:
    print("false")
else:
    print("true" if data.get("oracleSatisfied") is True else "false")
PY
)"
[[ "$RPC_OK" == "true" ]] || fail_evidence ORACLE_FAILURE installer-rpc "TrueNAS installer WebSocket JSON-RPC answered but read-only discovery oracle failed"
write_receipt SUPPORTED true installer-rpc "pinned TrueNAS installer answered read-only JSON-RPC discovery methods"
