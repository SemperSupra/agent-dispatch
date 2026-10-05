#!/usr/bin/env bash
set -euo pipefail

ISO_NAME="proxmox-ve_9.2-1.iso"
ISO_URL="https://enterprise.proxmox.com/iso/$ISO_NAME"
ISO_SHA256="4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c"
PVE_INSTALLER_SOURCE_VERSION="9.2.5"
PVE_INSTALLER_SOURCE_COMMIT="32afcd4cd534d8e2f99ae76aa0234a0a5c697ba9"
P3_PVE_CONTAINER_SOURCE_COMMIT="5eb5574ee9158ac40a5230de2cf18d7d6345709f"
P3_TEMPLATE_NAME="debian-13-standard_13.1-2_amd64.tar.zst"
P3_TEMPLATE_URL="https://download.proxmox.com/images/system/$P3_TEMPLATE_NAME"
P3_TEMPLATE_SHA512="5aec4ab2ac5c16c7c8ecb87bfeeb10213abe96db6b85e2463585cea492fc861d7c390b3f9c95629bf690b95e9dfe1037207fc69c0912429605f208d5cb2621f8"
P3_VMID=9101
RAM_MIB=4096
VCPUS=2
DISK_SIZE="40G"
MIN_HOST_MEM_KIB=$((6 * 1024 * 1024))
MIN_HOST_FREE_KIB=$((16 * 1024 * 1024))
ROOT_PASSWORD="rdte-proxmox-${RANDOM}-${RANDOM}-${RANDOM}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: gha_kvm_proxmox_rdte.sh --out RECEIPT [--state-dir DIR] [--compute-fixture none|container-c0]"
}

OUT=""
STATE_DIR=""
COMPUTE_FIXTURE="none"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --compute-fixture) COMPUTE_FIXTURE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -n "$OUT" ]] || { usage >&2; exit 2; }
[[ "$COMPUTE_FIXTURE" == "none" || "$COMPUTE_FIXTURE" == "container-c0" ]] || { echo "unsupported compute fixture: $COMPUTE_FIXTURE" >&2; exit 2; }

if [[ -z "$STATE_DIR" ]]; then STATE_DIR="$(mktemp -d -t gha-kvm-proxmox.XXXXXX)"; fi
mkdir -p "$STATE_DIR" "$(dirname "$OUT")"
STATE_DIR="$(realpath "$STATE_DIR")"
OUT="$(realpath -m "$OUT")"
[[ "$OUT" != "$STATE_DIR/"* ]] || { echo "receipt must be outside disposable state" >&2; exit 2; }

QEMU_PID=""
OBSERVED_ISO_SHA=""
API_VERSION_JSON=""
HOSTFWD_API_VERSION_JSON=""
GUEST_LOCAL_API_VERSION_JSON=""
API_OBSERVATION_ROUTE=""
NESTED_KVM="unknown"
NESTED_KVM_INDICATORS="unknown"
NESTED_KVM_VCPU_JSON=""
P3_LXC_JSON=""
REST_API_CENSUS_JSON=""
REST_C0_JSON=""
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
  export R_NESTED_INDICATORS="$NESTED_KVM_INDICATORS" R_NESTED_VCPU="$NESTED_KVM_VCPU_JSON" R_P3_LXC="$P3_LXC_JSON" R_REST_API_CENSUS="$REST_API_CENSUS_JSON" R_REST_C0="$REST_C0_JSON" R_COMPUTE_FIXTURE="$COMPUTE_FIXTURE"
  export R_HOSTFWD_API="$HOSTFWD_API_VERSION_JSON" R_GUEST_LOCAL_API="$GUEST_LOCAL_API_VERSION_JSON" R_API_ROUTE="$API_OBSERVATION_ROUTE"
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

nested_vcpu = load_json_env("R_NESTED_VCPU")
p3_lxc = load_json_env("R_P3_LXC")
rest_api_census = load_json_env("R_REST_API_CENSUS")
rest_c0 = load_json_env("R_REST_C0")

payload = {
  "contract": "gha-kvm-system-lab/v1",
  "target": {"product": "proxmox-ve", "version": "9.2-1"},
  "classification": os.environ["R_CLASS"],
  "oracleSatisfied": os.environ["R_ORACLE"].lower() == "true",
  "phase": os.environ["R_PHASE"],
  "detail": os.environ["R_DETAIL"],
  "requested_shape": {"vcpus": 2, "ram_mib": 4096, "disk": "40G", "compute_fixture": os.environ.get("R_COMPUTE_FIXTURE", "none")},
  "source": {
    "iso_name": "proxmox-ve_9.2-1.iso",
    "iso_url": "https://enterprise.proxmox.com/iso/proxmox-ve_9.2-1.iso",
    "expected_sha256": "4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c",
    "observed_sha256": os.environ.get("R_ISO_SHA") or None,
    "installer_source_version": "9.2.5",
    "installer_source_commit": "32afcd4cd534d8e2f99ae76aa0234a0a5c697ba9",
    "pve_manager_source_commit": "b9984c6d90a4bd80",
    "pve_access_control_source_commit": "5ccd07d9302562b73374d331b63d25b04b86766c",
    "pve_version_api_source": "PVE/API2.pm",
    "pve_qemu_source_commit": "684796e835289dab11af8606fbf7358b93526dd6",
    "pve_qemu_submodule_commit": "98b060da3a4f92b2a994ead5b16a87e783baf77c",
    "pve_qemu_debugexit_source": "hw/misc/debugexit.c",
    "pve_qemu_expected_package": "11.0.0-3",
    "pve_container_source_commit": "5eb5574ee9158ac40a5230de2cf18d7d6345709f",
    "p3_template": "debian-13-standard_13.1-2_amd64.tar.zst",
    "p3_template_catalog_sha512": "5aec4ab2ac5c16c7c8ecb87bfeeb10213abe96db6b85e2463585cea492fc861d7c390b3f9c95629bf690b95e9dfe1037207fc69c0912429605f208d5cb2621f8",
    "iso_first_boot_package": os.environ.get("R_ISO_FIRST_BOOT_PACKAGE") or None,
  },
  "oracles": {
    "vendor_iso_digest": os.environ.get("R_ISO_SHA") == "4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c",
    "unattended_install_completed": os.environ.get("R_INSTALL_SUCCESS_MARKER_OBSERVED") == "true",
    "installed_disk_layout": os.environ.get("R_INSTALLED_DISK_LAYOUT_OK") == "true",
    "installed_https_api": bool(os.environ.get("R_API")),
    "nested_kvm_indicators_via_ssh": os.environ.get("R_NESTED_INDICATORS") == "yes",
    "nested_kvm_observed_via_ssh": os.environ.get("R_NESTED") == "yes",
    "nested_kvm_vcpu_executed": bool(nested_vcpu and nested_vcpu.get("oracleSatisfied") is True),
    "p3_lxc_lifecycle_exercised": bool(p3_lxc and p3_lxc.get("oracleSatisfied") is True),
    "rest_api_census_observed": bool(rest_api_census and rest_api_census.get("oracleSatisfied") is True and rest_api_census.get("phase") == "observe-only"),
    "rest_api_container_c0_exercised": bool(rest_c0 and rest_c0.get("oracleSatisfied") is True and rest_c0.get("api_materialization_oracle") is True),
  },
  "api_version": json.loads(os.environ["R_API"]) if os.environ.get("R_API") else None,
  "nested_kvm": os.environ.get("R_NESTED"),
  "p5_nested_kvm": nested_vcpu,
  "p3_lxc": p3_lxc,
  "rest_api_census": rest_api_census,
  "rest_api_container_c0": rest_c0,
  "diagnostics": {
    "qemu_alive_at_api_gate": os.environ.get("R_QEMU_ALIVE"),
    "ssh_hostfwd_accepted": os.environ.get("R_SSH_HOSTFWD_ACCEPTED") == "true",
    "api_hostfwd_accepted": os.environ.get("R_API_HOSTFWD_ACCEPTED") == "true",
    "api_observation_route": os.environ.get("R_API_ROUTE") or None,
    "hostfwd_https_api": load_json_env("R_HOSTFWD_API"),
    "guest_local_https_api": load_json_env("R_GUEST_LOCAL_API"),
    "nested_kvm_indicators": os.environ.get("R_NESTED_INDICATORS"),
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
    "P5 nested KVM requires p5_nested_kvm.oracleSatisfied=true from an actual nested vCPU debug-exit; device/CPU flags alone are diagnostic.",
    "P3 LXC is a separate lifecycle oracle using one exact public Debian template; P2/P5 are not inferred from it.",
    "REST API census is read-only discovery evidence only; it does not claim LXC or QEMU materialization.",
    "REST C0, when explicitly requested, proves only product-API LXC create/readback/start/stop/delete/absence; guest execution remains a separate C1 oracle.",
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

guest_local_https_api() {
  # Exact installed source contract: /access/ticket is user=world, while
  # /version requires an authenticated user; pve-http-server consumes the
  # returned ticket from the PVEAuthCookie cookie on the subsequent GET.
  local response=""
  for _ in 1 2 3; do
    response="$(
      {
        printf '%s\n' "$ROOT_PASSWORD"
        cat <<'PY'
import json
import os
import socket
import ssl
import sys
import urllib.parse

host = "127.0.0.1"
port = 8006
server_name = "pve-rdte.example.invalid"
password = os.environ["PVE_RDTE_PASSWORD"]
stage = "init"

def https_request(method, path, headers=None, body=b""):
    request_headers = {
        "Host": server_name,
        "Connection": "close",
    }
    if headers:
        request_headers.update(headers)
    if body:
        request_headers["Content-Length"] = str(len(body))
    request = [f"{method} {path} HTTP/1.0"]
    request.extend(f"{name}: {value}" for name, value in request_headers.items())
    wire = ("\r\n".join(request) + "\r\n\r\n").encode("ascii") + body

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as tls:
            tls.settimeout(5)
            tls.sendall(wire)
            chunks = []
            while True:
                block = tls.recv(65536)
                if not block:
                    break
                chunks.append(block)

    payload = b"".join(chunks)
    header, sep, response_body = payload.partition(b"\r\n\r\n")
    if not sep:
        raise RuntimeError("HTTP header terminator absent")
    status = header.split(b"\r\n", 1)[0].decode("ascii", "replace")
    return status, response_body

try:
    stage = "ticket"
    ticket_body = urllib.parse.urlencode({
        "username": "root@pam",
        "password": password,
    }).encode("ascii")
    ticket_status, ticket_response = https_request(
        "POST",
        "/api2/json/access/ticket",
        {"Content-Type": "application/x-www-form-urlencoded"},
        ticket_body,
    )
    if " 200 " not in f" {ticket_status} ":
        print(json.dumps({
            "probe_error": "http_status",
            "stage": stage,
            "status": ticket_status,
        }, sort_keys=True))
        raise SystemExit(0)

    ticket_payload = json.loads(ticket_response.decode("utf-8"))
    ticket = (ticket_payload.get("data") or {}).get("ticket")
    if not ticket:
        print(json.dumps({
            "probe_error": "ticket_absent",
            "stage": stage,
        }, sort_keys=True))
        raise SystemExit(0)

    stage = "version"
    version_status, version_response = https_request(
        "GET",
        "/api2/json/version",
        {"Cookie": f"PVEAuthCookie={ticket}"},
    )
    if " 200 " not in f" {version_status} ":
        print(json.dumps({
            "probe_error": "http_status",
            "stage": stage,
            "status": version_status,
            "body_preview": version_response[:1000].decode("utf-8", "replace"),
        }, sort_keys=True))
        raise SystemExit(0)

    version_payload = json.loads(version_response.decode("utf-8"))
    print(json.dumps(version_payload, separators=(",", ":"), sort_keys=True))
except SystemExit:
    raise
except Exception as exc:
    print(json.dumps({
        "probe_error": type(exc).__name__,
        "stage": stage,
        "message": str(exc),
    }, sort_keys=True))
PY
      } | sshpass -p "$ROOT_PASSWORD" ssh -p "$SSH_PORT" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
        root@127.0.0.1 'IFS= read -r PVE_RDTE_PASSWORD; export PVE_RDTE_PASSWORD; exec python3 -' \
        2>/dev/null || true
    )"
    if R_RESPONSE="$response" python3 - <<'PY'
import json, os
try:
    payload = json.loads(os.environ["R_RESPONSE"])
    data = payload.get("data")
    ok = isinstance(data, dict) and all(data.get(k) for k in ("version", "release", "repoid"))
except Exception:
    ok = False
raise SystemExit(0 if ok else 1)
PY
    then
      printf '%s' "$response"
      return 0
    fi
    sleep 2
  done
  printf '%s' "$response"
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



P3_STAGE_CLASS=""
P3_STAGE_PHASE=""
P3_STAGE_DETAIL=""

stage_exact_p3_template() {
  local template_host="$STATE_DIR/$P3_TEMPLATE_NAME"
  local template_guest="/var/lib/vz/template/cache/$P3_TEMPLATE_NAME"
  local observed_sha=""

  P3_STAGE_CLASS="ENVIRONMENT_FAILURE"
  P3_STAGE_PHASE="host-prerequisite"
  P3_STAGE_DETAIL="sha512sum or scp unavailable on GHA host"
  command -v sha512sum >/dev/null 2>&1 && command -v scp >/dev/null 2>&1 || return 1

  P3_STAGE_PHASE="template-acquire"
  P3_STAGE_DETAIL="exact public LXC template download failed"
  curl --fail --location --retry 3 --silent --show-error "$P3_TEMPLATE_URL" -o "$template_host" || return 1

  observed_sha="$(sha512sum "$template_host" | awk '{print $1}')"
  if [[ "$observed_sha" != "$P3_TEMPLATE_SHA512" ]]; then
    rm -f -- "$template_host"
    P3_STAGE_CLASS="ORACLE_FAILURE"
    P3_STAGE_PHASE="template-integrity"
    P3_STAGE_DETAIL="downloaded template SHA-512 did not match exact admitted PVE catalog"
    return 1
  fi

  P3_STAGE_CLASS="ENVIRONMENT_FAILURE"
  P3_STAGE_PHASE="template-stage"
  P3_STAGE_DETAIL="template destination already existed or guest cache could not be prepared"
  if ! sshpass -p "$ROOT_PASSWORD" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
      root@127.0.0.1 "test ! -e '$template_guest' && install -d -m 0755 /var/lib/vz/template/cache" >/dev/null 2>&1; then
    rm -f -- "$template_host"
    return 1
  fi
  P3_STAGE_DETAIL="exact template could not be copied into PVE"
  if ! sshpass -p "$ROOT_PASSWORD" scp -q -P "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      "$template_host" "root@127.0.0.1:$template_guest"; then
    rm -f -- "$template_host"
    return 1
  fi
  rm -f -- "$template_host"
  return 0
}

stage_failure_json() {
  R_CLASS="$P3_STAGE_CLASS" R_PHASE="$P3_STAGE_PHASE" R_DETAIL="$P3_STAGE_DETAIL" python3 - <<'PY'
import json, os
print(json.dumps({
  "classification": os.environ["R_CLASS"],
  "oracleSatisfied": False,
  "phase": os.environ["R_PHASE"],
  "detail": os.environ["R_DETAIL"],
}, separators=(",", ":")))
PY
}

probe_rest_lxc_c0() {
  local template_guest="/var/lib/vz/template/cache/$P3_TEMPLATE_NAME"
  local password_file="$STATE_DIR/pve-rest-c0-password"
  local probe_out="$STATE_DIR/proxmox-rest-c0.json"
  local template_absent="false"

  if ! stage_exact_p3_template; then
    R_STAGE="$(stage_failure_json)" python3 - <<'PY'
import json, os
p=json.loads(os.environ["R_STAGE"])
p.update({"schema":"proxmox-rest-compute-c0-v1","kind":"container","api_materialization_oracle":False,"cleanup":{"attempted":False,"absent":False,"fixture_input_absent":False}})
print(json.dumps(p,separators=(",",":")))
PY
    return 0
  fi

  printf '%s\n' "$ROOT_PASSWORD" >"$password_file"
  chmod 0400 "$password_file"
  rm -f -- "$probe_out"
  python3 "$SCRIPT_DIR/proxmox_rest_compute_probe.py" \
    --base-url "https://127.0.0.1:$WEB_PORT" \
    --password-file "$password_file" \
    --kind container \
    --vmid "$P3_VMID" \
    --template "local:vztmpl/$P3_TEMPLATE_NAME" \
    --apply --out "$probe_out" >/dev/null 2>&1 || true
  rm -f -- "$password_file"

  sshpass -p "$ROOT_PASSWORD" ssh -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
    root@127.0.0.1 "rm -f -- '$template_guest'; test ! -e '$template_guest'" >/dev/null 2>&1 && template_absent="true"

  if [[ ! -s "$probe_out" ]]; then
    printf '%s' '{"schema":"proxmox-rest-compute-c0-v1","kind":"container","classification":"HARNESS_FAILURE","oracleSatisfied":false,"api_materialization_oracle":false,"phase":"rest-api-lifecycle","detail":"REST materializer exited without a receipt","cleanup":{"attempted":true,"absent":false,"fixture_input_absent":false}}'
    return 0
  fi

  R_PROBE_OUT="$probe_out" R_TEMPLATE_ABSENT="$template_absent" R_TEMPLATE_SHA="$P3_TEMPLATE_SHA512" python3 - <<'PY'
import json, os, pathlib
p=json.loads(pathlib.Path(os.environ["R_PROBE_OUT"]).read_text())
cleanup=p.setdefault("cleanup",{})
cleanup["fixture_input_absent"]=os.environ["R_TEMPLATE_ABSENT"]=="true"
p["fixture_input"]={
  "template":"debian-13-standard_13.1-2_amd64.tar.zst",
  "catalog_sha512":os.environ["R_TEMPLATE_SHA"],
  "transport":"bounded SSH staging only; all container lifecycle mutation uses PVE REST",
}
if not cleanup["fixture_input_absent"]:
    p["classification"]="ORACLE_FAILURE"
    p["oracleSatisfied"]=False
    p["api_materialization_oracle"]=False
    p["detail"]=(p.get("detail","") + "; exact staged template remained after fixture cleanup").lstrip("; ")
print(json.dumps(p,separators=(",",":")))
PY
}

probe_lxc_lifecycle() {
  local response=""
  if ! stage_exact_p3_template; then
    R_STAGE="$(stage_failure_json)" python3 - <<'PY'
import json, os
p=json.loads(os.environ["R_STAGE"])
p["contract"]="proxmox-lxc-lifecycle/v1"
print(json.dumps(p,separators=(",",":")))
PY
    return 0
  fi

  response="$(sshpass -p "$ROOT_PASSWORD" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
    root@127.0.0.1 'bash -s' 2>/dev/null <<'REMOTE' || true
set +e
VMID=9101
TEMPLATE_NAME="debian-13-standard_13.1-2_amd64.tar.zst"
TEMPLATE="/var/lib/vz/template/cache/$TEMPLATE_NAME"
EXPECTED_SHA512="5aec4ab2ac5c16c7c8ecb87bfeeb10213abe96db6b85e2463585cea492fc861d7c390b3f9c95629bf690b95e9dfe1037207fc69c0912429605f208d5cb2621f8"
EXPECTED_PVE_CONTAINER="6.1.10"
CENSUS="$(mktemp)"; CREATE_LOG="$(mktemp)"; START_LOG="$(mktemp)"; STOP_LOG="$(mktemp)"; DESTROY_LOG="$(mktemp)"; CONFIG_SNAPSHOT="$(mktemp)"
cleanup() {
  if pct status "$VMID" >/dev/null 2>&1; then
    pct stop "$VMID" >/dev/null 2>&1 || true
    pct destroy "$VMID" --purge 1 >/dev/null 2>&1 || true
  fi
  rm -f -- "$TEMPLATE"
}
trap 'cleanup >/dev/null 2>&1' EXIT

OBS_SHA="$(sha512sum "$TEMPLATE" 2>/dev/null | awk '{print $1}')"
PKG="$(dpkg-query -W -f='${Version}' pve-container 2>/dev/null || true)"
STORAGE_STATUS="$(pvesm status --storage local-lvm 2>&1 || true)"
STORAGE_ACTIVE=false
printf '%s\n' "$STORAGE_STATUS" | awk 'NR>1 && $1=="local-lvm" && $3=="active"{ok=1} END{exit !ok}' && STORAGE_ACTIVE=true
PRECONDITION=""
[[ "$OBS_SHA" == "$EXPECTED_SHA512" ]] || PRECONDITION="template-sha512-mismatch"
[[ "$PKG" == "$EXPECTED_PVE_CONTAINER" ]] || [[ -n "$PRECONDITION" ]] || PRECONDITION="pve-container-version-mismatch"
[[ "$STORAGE_ACTIVE" == true ]] || [[ -n "$PRECONDITION" ]] || PRECONDITION="local-lvm-inactive"
if pct status "$VMID" >/dev/null 2>&1 || [[ -e "/etc/pve/lxc/$VMID.conf" ]]; then [[ -n "$PRECONDITION" ]] || PRECONDITION="vmid-preexisting"; fi

CREATE_RC=125; START_RC=125; EXEC_RC=125; STOP_RC=125; DESTROY_RC=125; RUNNING=false; CLEANUP_OK=false
if [[ -z "$PRECONDITION" ]]; then
  pct create "$VMID" "local:vztmpl/$TEMPLATE_NAME" --rootfs local-lvm:2 --memory 256 --cores 1 --unprivileged 1 \
    --hostname rdte-p3 --net0 "name=eth0,bridge=vmbr0,ip=10.0.2.16/24,type=veth" >"$CREATE_LOG" 2>&1
  CREATE_RC=$?
  if [[ "$CREATE_RC" -eq 0 ]]; then
    pct config "$VMID" >"$CONFIG_SNAPSHOT" 2>&1 || true
    pct start "$VMID" >"$START_LOG" 2>&1; START_RC=$?
    if [[ "$START_RC" -eq 0 ]]; then
      for _ in $(seq 1 20); do if pct status "$VMID" 2>/dev/null | grep -Fq 'status: running'; then RUNNING=true; break; fi; sleep 1; done
      if [[ "$RUNNING" == true ]]; then
        pct exec "$VMID" -- sh -c '
          echo P3_CENSUS_BEGIN
          printf "HOSTNAME="; hostname 2>&1 || true
          echo UNAME_BEGIN; uname -a 2>&1 || true; echo UNAME_END
          echo CPU_BEGIN; grep -E "^(processor|vendor_id|model name|flags|Features)" /proc/cpuinfo 2>&1 | head -n 40 || true; echo CPU_END
          echo MEM_BEGIN; head -n 30 /proc/meminfo 2>&1 || true; echo MEM_END
          echo CGROUP_BEGIN; cat /proc/self/cgroup 2>&1 || true; echo CGROUP_END
          echo MOUNTS_BEGIN; head -n 80 /proc/mounts 2>&1 || true; echo MOUNTS_END
          echo NET_BEGIN; ip -brief address 2>&1 || true; echo NET_END
          echo ROUTE_BEGIN; ip route 2>&1 || true; echo ROUTE_END
          echo DNS_BEGIN; cat /etc/resolv.conf 2>&1 || true; echo DNS_END
          echo DEV_BEGIN; ls -la /dev 2>&1 | head -n 80 || true; echo DEV_END
          echo P3_CENSUS_END
        ' >"$CENSUS" 2>&1
        EXEC_RC=$?
      fi
    fi
  fi
fi

if pct status "$VMID" >/dev/null 2>&1; then
  if pct status "$VMID" 2>/dev/null | grep -Fq 'status: running'; then pct stop "$VMID" >"$STOP_LOG" 2>&1; STOP_RC=$?; else STOP_RC=0; fi
  pct destroy "$VMID" --purge 1 >"$DESTROY_LOG" 2>&1; DESTROY_RC=$?
else
  STOP_RC=0; DESTROY_RC=0
fi
rm -f -- "$TEMPLATE"
CONFIG_ABSENT=true; VOLUME_ABSENT=true; TEMPLATE_ABSENT=true
[[ ! -e "/etc/pve/lxc/$VMID.conf" ]] || CONFIG_ABSENT=false
if pvesm list local-lvm 2>/dev/null | grep -Eq "(vm|subvol)-$VMID-"; then VOLUME_ABSENT=false; fi
[[ ! -e "$TEMPLATE" ]] || TEMPLATE_ABSENT=false
[[ "$CONFIG_ABSENT" == true && "$VOLUME_ABSENT" == true && "$TEMPLATE_ABSENT" == true ]] && CLEANUP_OK=true

CENSUS_TEXT="$(tail -c 12000 "$CENSUS" 2>/dev/null || true)"
CONFIG_TEXT="$(tail -c 6000 "$CONFIG_SNAPSHOT" 2>/dev/null || true)"
CREATE_TEXT="$(tail -c 4000 "$CREATE_LOG" 2>/dev/null || true)"; START_TEXT="$(tail -c 4000 "$START_LOG" 2>/dev/null || true)"
STOP_TEXT="$(tail -c 4000 "$STOP_LOG" 2>/dev/null || true)"; DESTROY_TEXT="$(tail -c 4000 "$DESTROY_LOG" 2>/dev/null || true)"
R_PRE="$PRECONDITION" R_SHA="$OBS_SHA" R_PKG="$PKG" R_STORAGE="$STORAGE_STATUS" R_CREATE="$CREATE_RC" R_START="$START_RC" R_EXEC="$EXEC_RC" \
R_STOP="$STOP_RC" R_DESTROY="$DESTROY_RC" R_RUNNING="$RUNNING" R_CLEAN="$CLEANUP_OK" R_CFGABS="$CONFIG_ABSENT" R_VOLABS="$VOLUME_ABSENT" R_TPLABS="$TEMPLATE_ABSENT" \
R_CENSUS="$CENSUS_TEXT" R_CONFIG="$CONFIG_TEXT" R_CREATE_LOG="$CREATE_TEXT" R_START_LOG="$START_TEXT" R_STOP_LOG="$STOP_TEXT" R_DESTROY_LOG="$DESTROY_TEXT" \
python3 - <<'PY'
import json, os
pre=os.environ.get("R_PRE",""); create=int(os.environ["R_CREATE"]); start=int(os.environ["R_START"]); exe=int(os.environ["R_EXEC"]); stop=int(os.environ["R_STOP"]); destroy=int(os.environ["R_DESTROY"])
running=os.environ["R_RUNNING"]=="true"; cleanup=os.environ["R_CLEAN"]=="true"
ok=(not pre and create==0 and start==0 and running and exe==0 and stop==0 and destroy==0 and cleanup)
classification="SUPPORTED" if ok else ("ENVIRONMENT_FAILURE" if pre else "ORACLE_FAILURE")
detail="run-owned unprivileged LXC completed create/start/exec/stop/destroy with zero experiment residue" if ok else (pre or "LXC lifecycle did not satisfy the bounded create/start/exec/stop/destroy/cleanup oracle")
print(json.dumps({
 "contract":"proxmox-lxc-lifecycle/v1","classification":classification,"oracleSatisfied":ok,"phase":"lxc-lifecycle","detail":detail,"vmid":9101,
 "template":{"name":"debian-13-standard_13.1-2_amd64.tar.zst","expected_sha512":"5aec4ab2ac5c16c7c8ecb87bfeeb10213abe96db6b85e2463585cea492fc861d7c390b3f9c95629bf690b95e9dfe1037207fc69c0912429605f208d5cb2621f8","observed_sha512":os.environ.get("R_SHA") or None},
 "pve_container_version":os.environ.get("R_PKG") or None,"source":{"pve_container_commit":"5eb5574ee9158ac40a5230de2cf18d7d6345709f"},"storage_status":os.environ.get("R_STORAGE") or None,
 "steps":{"create":create,"start":start,"running":running,"exec":exe,"stop":stop,"destroy":destroy},
 "cleanup":{"config_absent":os.environ["R_CFGABS"]=="true","root_volume_absent":os.environ["R_VOLABS"]=="true","template_absent":os.environ["R_TPLABS"]=="true","zero_residue":cleanup},
 "container_config":os.environ.get("R_CONFIG") or None,"census":os.environ.get("R_CENSUS") or None,
 "logs":{"create":os.environ.get("R_CREATE_LOG") or None,"start":os.environ.get("R_START_LOG") or None,"stop":os.environ.get("R_STOP_LOG") or None,"destroy":os.environ.get("R_DESTROY_LOG") or None},
},sort_keys=True,separators=(",",":")))
PY
trap - EXIT
rm -f -- "$CENSUS" "$CREATE_LOG" "$START_LOG" "$STOP_LOG" "$DESTROY_LOG" "$CONFIG_SNAPSHOT"
REMOTE
)"
  if [[ -n "$response" ]]; then printf '%s' "$response"; else printf '%s' '{"contract":"proxmox-lxc-lifecycle/v1","classification":"ENVIRONMENT_FAILURE","oracleSatisfied":false,"phase":"transport","detail":"guest SSH did not return an LXC receipt"}'; fi
}

probe_nested_kvm_vcpu() {
  local response=""
  command -v sshpass >/dev/null 2>&1 || {
    printf '%s' '{"contract":"proxmox-nested-kvm-vcpu/v1","classification":"ENVIRONMENT_FAILURE","oracleSatisfied":false,"phase":"transport","detail":"sshpass unavailable for guest observation"}'
    return 0
  }
  response="$(sshpass -p "$ROOT_PASSWORD" ssh -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
    root@127.0.0.1 'bash -s' 2>/dev/null <<'REMOTE' || true
set +e
EXPECTED_EXIT=85
EXPECTED_PACKAGE="11.0.0-3"
TMP_RDTE="$(mktemp -d)"
trap 'rm -rf "$TMP_RDTE"' EXIT
BOOT="$TMP_RDTE/p5-boot.img"
QERR="$TMP_RDTE/qemu.err"
python3 - "$BOOT" <<'PY'
import pathlib, sys
code = bytes.fromhex("fab02abaf400eef4ebfd")
image = code + bytes(510 - len(code)) + b"\x55\xaa"
pathlib.Path(sys.argv[1]).write_bytes(image)
PY
BOOT_SHA="$(sha256sum "$BOOT" 2>/dev/null | awk '{print $1}')"
PKG="$(dpkg-query -W -f='${Version}' pve-qemu-kvm 2>/dev/null || true)"
QVER="$(qemu-system-x86_64 --version 2>/dev/null | head -n 1 || true)"
KVM_DEVICE="absent"
CPU_VIRT_FLAG="absent"
PRECONDITION=""
[[ -c /dev/kvm ]] && KVM_DEVICE="present" || PRECONDITION="kvm-device-absent"
if grep -Eq '(vmx|svm)' /proc/cpuinfo 2>/dev/null; then CPU_VIRT_FLAG="present"; else [[ -n "$PRECONDITION" ]] || PRECONDITION="cpu-virt-flag-absent"; fi
command -v qemu-system-x86_64 >/dev/null 2>&1 || { [[ -n "$PRECONDITION" ]] || PRECONDITION="nested-qemu-absent"; }
RC=125
if [[ -z "$PRECONDITION" ]]; then
  timeout 15 qemu-system-x86_64 \
    -machine pc \
    -accel kvm \
    -cpu host \
    -m 64 \
    -smp 1 \
    -drive "file=$BOOT,format=raw,if=floppy,readonly=on" \
    -boot order=a,strict=on \
    -device isa-debug-exit,iobase=0xf4,iosize=0x4 \
    -display none \
    -serial none \
    -monitor none \
    -no-reboot \
    >"$TMP_RDTE/qemu.out" 2>"$QERR"
  RC=$?
fi
ERR="$(tail -c 4000 "$QERR" 2>/dev/null || true)"
R_RC="$RC" R_EXPECTED_EXIT="$EXPECTED_EXIT" R_EXPECTED_PACKAGE="$EXPECTED_PACKAGE" \
R_PKG="$PKG" R_QVER="$QVER" R_BOOT_SHA="$BOOT_SHA" R_ERR="$ERR" \
R_KVM_DEVICE="$KVM_DEVICE" R_CPU_VIRT_FLAG="$CPU_VIRT_FLAG" R_PRECONDITION="$PRECONDITION" \
python3 - <<'PY'
import json, os
rc = int(os.environ["R_RC"])
expected_exit = int(os.environ["R_EXPECTED_EXIT"])
pkg = os.environ.get("R_PKG", "")
expected_pkg = os.environ["R_EXPECTED_PACKAGE"]
precondition = os.environ.get("R_PRECONDITION", "")
ok = (not precondition and rc == expected_exit and pkg == expected_pkg and os.environ.get("R_KVM_DEVICE") == "present" and os.environ.get("R_CPU_VIRT_FLAG") == "present")
if ok:
    classification = "SUPPORTED"
    detail = "nested QEMU used KVM and the run-owned guest executed the expected isa-debug-exit instruction"
elif precondition or pkg != expected_pkg:
    classification = "ENVIRONMENT_FAILURE"
    detail = precondition or f"unexpected pve-qemu-kvm package {pkg!r}"
else:
    classification = "ORACLE_FAILURE"
    detail = f"nested QEMU exit code {rc} did not match expected guest debug-exit code {expected_exit}"
print(json.dumps({
    "contract": "proxmox-nested-kvm-vcpu/v1",
    "classification": classification,
    "oracleSatisfied": ok,
    "phase": "nested-vcpu",
    "detail": detail,
    "expected_debug_value": 42,
    "expected_exit_code": expected_exit,
    "observed_exit_code": rc,
    "pve_qemu_kvm_version": pkg or None,
    "qemu_version": os.environ.get("R_QVER") or None,
    "boot_image_sha256": os.environ.get("R_BOOT_SHA") or None,
    "kvm_device": os.environ.get("R_KVM_DEVICE"),
    "cpu_virt_flag": os.environ.get("R_CPU_VIRT_FLAG"),
    "stderr_tail": os.environ.get("R_ERR") or None,
    "source": {
        "pve_qemu_commit": "684796e835289dab11af8606fbf7358b93526dd6",
        "qemu_submodule_commit": "98b060da3a4f92b2a994ead5b16a87e783baf77c",
        "debugexit_source": "hw/misc/debugexit.c",
        "exit_code_rule": "(value << 1) | 1",
    },
}, sort_keys=True, separators=(",", ":")))
PY
REMOTE
)"
  if [[ -n "$response" ]]; then printf '%s' "$response"; else printf '%s' '{"contract":"proxmox-nested-kvm-vcpu/v1","classification":"ENVIRONMENT_FAILURE","oracleSatisfied":false,"phase":"transport","detail":"guest SSH did not return a nested-KVM receipt"}'; fi
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
HOSTFWD_API_VERSION_JSON=""
GUEST_LOCAL_API_VERSION_JSON=""
API_OBSERVATION_ROUTE=""
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
    HOSTFWD_API_VERSION_JSON="$(curl -sk --max-time 5 "https://127.0.0.1:$WEB_PORT/api2/json/version" 2>/dev/null || true)"
    if [[ "$HOSTFWD_API_VERSION_JSON" == *'"data"'* ]]; then
      API_VERSION_JSON="$HOSTFWD_API_VERSION_JSON"
      API_OBSERVATION_ROUTE="qemu-hostfwd-https"
      break
    fi
  fi
  if [[ "$FIRST_BOOT_WITNESS_OBSERVED" == "true" && "$SSH_HOSTFWD_ACCEPTED" == "true" ]]; then
    if sshpass -p "$ROOT_PASSWORD" ssh -p "$SSH_PORT"         -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5         root@127.0.0.1 'true' >/dev/null 2>&1; then
      GUEST_LOCAL_API_VERSION_JSON="$(guest_local_https_api || true)"
      if [[ "$GUEST_LOCAL_API_VERSION_JSON" == *'"data"'* ]]; then
        API_VERSION_JSON="$GUEST_LOCAL_API_VERSION_JSON"
        API_OBSERVATION_ROUTE="ssh-observed-guest-local-https"
        break
      fi
      # The guest witness already proved pveproxy active/listening. A bounded
      # guest-local TLS failure is now discriminating; do not spend the rest of
      # the workflow retrying an observation route.
      GUEST_DIAGNOSTICS="$(guest_diagnostics || true)"
      break
    fi
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
  fail_evidence ORACLE_FAILURE installed-api "installed Proxmox HTTPS API did not answer via direct hostfwd or SSH-observed guest-local HTTPS (qemu_alive=$QEMU_ALIVE_AT_API_GATE first_boot_witness=$FIRST_BOOT_WITNESS_OBSERVED)"
fi

# Read-only native REST census: capture exact installed PVE/package identity only
# after the installed HTTPS API is known-good.
PVE_PASSWORD_FILE="$STATE_DIR/pve-rest-password"
printf '%s\n' "$ROOT_PASSWORD" >"$PVE_PASSWORD_FILE"
chmod 0400 "$PVE_PASSWORD_FILE"
REST_API_CENSUS_JSON="$(
  python3 "$SCRIPT_DIR/proxmox_rest_compute_probe.py" \
    --base-url "https://127.0.0.1:$WEB_PORT" \
    --password-file "$PVE_PASSWORD_FILE" \
    --kind vm --observe-only 2>/dev/null || true
)"
rm -f "$PVE_PASSWORD_FILE"

if [[ "$COMPUTE_FIXTURE" == "container-c0" ]]; then
  REST_C0_JSON="$(probe_rest_lxc_c0 || true)"
  if ! R_REST_C0="$REST_C0_JSON" python3 - <<'PY'
import json, os
try:
    p=json.loads(os.environ.get("R_REST_C0",""))
    ok=(p.get("classification")=="SUPPORTED" and p.get("oracleSatisfied") is True and
        p.get("api_materialization_oracle") is True and
        p.get("cleanup",{}).get("absent") is True and
        p.get("cleanup",{}).get("fixture_input_absent") is True)
except Exception:
    ok=False
raise SystemExit(0 if ok else 1)
PY
  then
    REST_C0_CLASS="$(R_REST_C0="$REST_C0_JSON" python3 - <<'PY'
import json, os
try:
    c=json.loads(os.environ.get("R_REST_C0","")).get("classification","ORACLE_FAILURE")
except Exception:
    c="HARNESS_FAILURE"
print(c if c in {"HARNESS_FAILURE","ENVIRONMENT_FAILURE","ORACLE_FAILURE"} else "ORACLE_FAILURE")
PY
)"
    fail_evidence "$REST_C0_CLASS" compute-container-c0 "native PVE REST container C0 did not satisfy create/readback/start/stop/delete/absence plus fixture-input cleanup"
  fi
fi

NESTED_KVM="unknown"
NESTED_KVM_INDICATORS="unknown"
if [[ "$COMPUTE_FIXTURE" == "container-c0" ]]; then
  NESTED_KVM_INDICATORS="skipped"
  NESTED_KVM_VCPU_JSON='{"contract":"proxmox-nested-kvm-vcpu/v1","classification":"SKIPPED_GUARDRAIL","oracleSatisfied":false,"phase":"not-required-for-container-c0","detail":"nested KVM is outside the bounded native REST container C0 causal rep"}'
else
  if command -v sshpass >/dev/null 2>&1; then
    if sshpass -p "$ROOT_PASSWORD" ssh -p "$SSH_PORT" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
        root@127.0.0.1 'test -e /dev/kvm && grep -Eq "(vmx|svm)" /proc/cpuinfo' >/dev/null 2>&1; then
      NESTED_KVM_INDICATORS="yes"
    fi
  fi
  NESTED_KVM_VCPU_JSON="$(probe_nested_kvm_vcpu || true)"
  if R_NESTED_VCPU="$NESTED_KVM_VCPU_JSON" python3 - <<'PY'
import json, os
try:
    payload = json.loads(os.environ.get("R_NESTED_VCPU", ""))
    ok = payload.get("oracleSatisfied") is True
except Exception:
    ok = False
raise SystemExit(0 if ok else 1)
PY
  then
    NESTED_KVM="yes"
  fi
fi

if [[ "$COMPUTE_FIXTURE" == "container-c0" ]]; then
  P3_LXC_JSON='{"contract":"proxmox-lxc-lifecycle/v1","classification":"SKIPPED_GUARDRAIL","oracleSatisfied":false,"phase":"superseded-by-rest-c0","detail":"CLI P3 lifecycle intentionally skipped because this rep assigns the exact container fixture to native PVE REST"}'
elif [[ "$NESTED_KVM" == "yes" ]]; then
  P3_LXC_JSON="$(probe_lxc_lifecycle || true)"
else
  P3_LXC_JSON='{"contract":"proxmox-lxc-lifecycle/v1","classification":"SKIPPED_GUARDRAIL","oracleSatisfied":false,"phase":"prerequisite","detail":"P5 nested-vCPU oracle was not satisfied in this rep"}'
fi

write_receipt SUPPORTED true complete "real Proxmox VE unattended install completed and real HTTPS /api2/json/version answered via $API_OBSERVATION_ROUTE"
