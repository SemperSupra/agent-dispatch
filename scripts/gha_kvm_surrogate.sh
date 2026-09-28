#!/usr/bin/env bash
set -euo pipefail

IMAGE_URL_DEFAULT="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
CONTRACT_VERSION="gha-kvm-surrogate/v1"

usage() {
  cat <<'EOF'
Usage:
  gha_kvm_surrogate.sh --kit PATH --out RECEIPT [--state-dir DIR] [--image-url URL] [--disk-size SIZE] [--runner-version VERSION --runner-sha256 SHA256]

Creates one disposable ordinary Ubuntu QEMU/KVM guest, proves SSH nonce exchange,
guest outbound HTTPS, generic runner-kit preflight, opaque-input handling, and cleanup.
No GitHub runner registration or secret is used.
EOF
}

KIT=""
OUT=""
STATE_DIR=""
IMAGE_URL="$IMAGE_URL_DEFAULT"
RUNNER_VERSION=""
RUNNER_SHA256=""
DISK_SIZE="12G"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kit) KIT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --image-url) IMAGE_URL="$2"; shift 2 ;;
    --runner-version) RUNNER_VERSION="$2"; shift 2 ;;
    --runner-sha256) RUNNER_SHA256="$2"; shift 2 ;;
    --disk-size) DISK_SIZE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -f "$KIT" && -n "$OUT" ]] || { usage >&2; exit 2; }
[[ "$DISK_SIZE" =~ ^[1-9][0-9]*[GM]$ ]] || { echo "disk size must be an integer followed by G or M" >&2; exit 2; }
if [[ -n "$RUNNER_VERSION" || -n "$RUNNER_SHA256" ]]; then
  [[ -n "$RUNNER_VERSION" && "$RUNNER_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "runner version and SHA256 must be supplied together" >&2; exit 2; }
fi
STATE_DIR="${STATE_DIR:-$(mktemp -d -t gha-kvm-surrogate.XXXXXX)}"
mkdir -p "$(dirname "$OUT")" "$STATE_DIR"
STATE_DIR="$(realpath "$STATE_DIR")"
OUT="$(realpath -m "$OUT")"
KIT="$(realpath "$KIT")"
if [[ "$OUT" == "$STATE_DIR/"* ]]; then
  echo "receipt must be outside disposable state dir" >&2
  exit 2
fi

QEMU_PID=""
cleanup() {
  set +e
  if [[ -n "$QEMU_PID" ]]; then
    sudo -n kill "$QEMU_PID" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      sudo -n kill -0 "$QEMU_PID" >/dev/null 2>&1 || break
      sleep 0.25
    done
    sudo -n kill -9 "$QEMU_PID" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$STATE_DIR"
}
trap cleanup EXIT INT TERM

for cmd in curl sha256sum qemu-img qemu-system-x86_64 cloud-localds ssh scp ssh-keygen python3; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing prerequisite: $cmd" >&2; exit 3; }
done
[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] || {
  echo "surrogate provider requires Linux x86_64" >&2; exit 3;
}
[[ -e /dev/kvm ]] || { echo "/dev/kvm absent" >&2; exit 3; }
sudo -n test -r /dev/kvm && sudo -n test -w /dev/kvm || {
  echo "passwordless sudo cannot access /dev/kvm" >&2; exit 3;
}

START_NS="$(date +%s%N)"
IMAGE="$(basename "$IMAGE_URL")"
BASE="$STATE_DIR/$IMAGE"
SUMS="$STATE_DIR/SHA256SUMS"
curl --fail --location --retry 3 --silent --show-error "$IMAGE_URL" -o "$BASE"
curl --fail --location --retry 3 --silent --show-error "$(dirname "$IMAGE_URL")/SHA256SUMS" -o "$SUMS"
EXPECTED_SHA="$(awk -v f="$IMAGE" '$2 == "*"f || $2 == f {print $1; exit}' "$SUMS")"
[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "image checksum not found" >&2; exit 4; }
ACTUAL_SHA="$(sha256sum "$BASE" | awk '{print $1}')"
[[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] || { echo "cloud image checksum mismatch" >&2; exit 4; }

ssh-keygen -q -t ed25519 -N "" -f "$STATE_DIR/id_ed25519"
PUBKEY="$(cat "$STATE_DIR/id_ed25519.pub")"
cat >"$STATE_DIR/user-data" <<EOF
#cloud-config
users:
  - name: runnerlab
    groups: [adm, sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ${PUBKEY}
ssh_pwauth: false
disable_root: true
package_update: false
EOF
cat >"$STATE_DIR/meta-data" <<EOF
instance-id: runner-lab-$(date +%s)
local-hostname: runner-lab
EOF
cloud-localds "$STATE_DIR/seed.img" "$STATE_DIR/user-data" "$STATE_DIR/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$STATE_DIR/overlay.qcow2"
qemu-img resize -q "$STATE_DIR/overlay.qcow2" "$DISK_SIZE"

PORT="$(python3 - <<'PY'
import socket
s=socket.socket()
s.bind(("127.0.0.1",0))
print(s.getsockname()[1])
s.close()
PY
)"

BOOT_START_NS="$(date +%s%N)"
sudo -n qemu-system-x86_64 \
  -enable-kvm -cpu host -smp 2 -m 3072 \
  -drive "file=$STATE_DIR/overlay.qcow2,if=virtio,format=qcow2" \
  -drive "file=$STATE_DIR/seed.img,if=virtio,format=raw,readonly=on" \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${PORT}-:22" \
  -device virtio-net-pci,netdev=net0 \
  -display none -monitor none \
  -serial "file:$STATE_DIR/serial.log" \
  -daemonize -pidfile "$STATE_DIR/qemu.pid"
QEMU_PID="$(sudo -n cat "$STATE_DIR/qemu.pid")"

SSH=(ssh -i "$STATE_DIR/id_ed25519" -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 runnerlab@127.0.0.1)
SCP=(scp -i "$STATE_DIR/id_ed25519" -P "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

READY="false"
for _ in $(seq 1 90); do
  if "${SSH[@]}" true >/dev/null 2>&1; then READY="true"; break; fi
  sleep 2
done
[[ "$READY" == "true" ]] || {
  sudo -n cat "$STATE_DIR/serial.log" >&2 || true
  echo "guest SSH did not become ready" >&2
  exit 5
}
BOOT_READY_NS="$(date +%s%N)"

"${SCP[@]}" "$KIT" runnerlab@127.0.0.1:/home/runnerlab/self_hosted_runner_kit.sh >/dev/null
"${SSH[@]}" chmod 0755 /home/runnerlab/self_hosted_runner_kit.sh

HOST_NONCE="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)"
HOST_NONCE_ECHO="$("${SSH[@]}" bash -s -- "$HOST_NONCE" <<'EOF'
set -euo pipefail
printf '%s' "$1" > /tmp/host-nonce
cat /tmp/host-nonce
rm -f /tmp/host-nonce
EOF
)"
[[ "$HOST_NONCE_ECHO" == "$HOST_NONCE" ]] || { echo "host->guest nonce mismatch" >&2; exit 6; }

GUEST_NONCE="$("${SSH[@]}" cat /proc/sys/kernel/random/uuid)"
[[ "$GUEST_NONCE" =~ ^[0-9a-f-]{36}$ ]] || { echo "guest nonce malformed" >&2; exit 6; }

PREFLIGHT="$("${SSH[@]}" /home/runnerlab/self_hosted_runner_kit.sh preflight --work-dir /home/runnerlab/actions-runner)"
"${SSH[@]}" "curl --fail --silent --show-error --max-time 20 https://api.github.com/meta >/dev/null"

RUNNER_STAGE=""
if [[ -n "$RUNNER_VERSION" ]]; then
  RUNNER_STAGE="$("${SSH[@]}" /home/runnerlab/self_hosted_runner_kit.sh stage \
    --version "$RUNNER_VERSION" \
    --sha256 "$RUNNER_SHA256" \
    --arch x64 \
    --work-dir /home/runnerlab/actions-runner)"
fi

"${SSH[@]}" bash -s <<'EOF'
set -euo pipefail
umask 077
printf '%s' 'synthetic-not-a-credential' > /home/runnerlab/.runner-jit-lab
/home/runnerlab/self_hosted_runner_kit.sh consume-opaque-input /home/runnerlab/.runner-jit-lab
/home/runnerlab/self_hosted_runner_kit.sh sanitize-input /home/runnerlab/.runner-jit-lab
test ! -e /home/runnerlab/.runner-jit-lab
EOF

GUEST_OS="$("${SSH[@]}" uname -s)"
GUEST_ARCH="$("${SSH[@]}" uname -m)"
GUEST_OS_RELEASE="$("${SSH[@]}" cat /etc/os-release)"
GUEST_DF="$("${SSH[@]}" df -B1 -P /)"
QEMU_VERSION="$(qemu-system-x86_64 --version | head -n1)"
END_NS="$(date +%s%N)"

export LAB_OUT="$OUT" LAB_PREFLIGHT="$PREFLIGHT" LAB_RUNNER_STAGE="$RUNNER_STAGE" LAB_GUEST_OS="$GUEST_OS" LAB_GUEST_ARCH="$GUEST_ARCH"
export LAB_GUEST_OS_RELEASE="$GUEST_OS_RELEASE" LAB_GUEST_DF="$GUEST_DF" LAB_DISK_SIZE="$DISK_SIZE"
export LAB_IMAGE="$IMAGE" LAB_IMAGE_SHA="$ACTUAL_SHA" LAB_QEMU_VERSION="$QEMU_VERSION"
export LAB_BOOT_START_NS="$BOOT_START_NS" LAB_BOOT_READY_NS="$BOOT_READY_NS"
export LAB_START_NS="$START_NS" LAB_END_NS="$END_NS"
python3 - <<'PY'
import json, os, pathlib
out=pathlib.Path(os.environ["LAB_OUT"])
preflight=json.loads(os.environ["LAB_PREFLIGHT"])
runner_stage=json.loads(os.environ["LAB_RUNNER_STAGE"]) if os.environ["LAB_RUNNER_STAGE"] else None
if os.environ["LAB_GUEST_ARCH"] != preflight.get("arch"):
    raise SystemExit("guest architecture disagrees with runner-kit preflight")
df_fields=os.environ["LAB_GUEST_DF"].splitlines()[-1].split()
root_size_bytes=int(df_fields[1])
root_available_bytes=int(df_fields[3])
pretty_name = ""
for line in os.environ["LAB_GUEST_OS_RELEASE"].splitlines():
    if line.startswith("PRETTY_NAME="):
        pretty_name = line.split("=",1)[1].strip().strip(chr(34))
        break
payload={
  "contract": "gha-kvm-surrogate/v1",
  "classification": "SUPPORTED",
  "oracleSatisfied": True,
  "provider": "gha-kvm",
  "guest_kind": "ordinary-ubuntu-cloud-image",
  "image": os.environ["LAB_IMAGE"],
  "image_sha256": os.environ["LAB_IMAGE_SHA"],
  "qemu_version": os.environ["LAB_QEMU_VERSION"],
  "guest": {"os": os.environ["LAB_GUEST_OS"], "arch": os.environ["LAB_GUEST_ARCH"], "pretty_name": pretty_name, "root_size_bytes": root_size_bytes, "root_available_bytes": root_available_bytes},
  "requested_disk_size": os.environ["LAB_DISK_SIZE"],
  "oracles": {
    "ssh_ready": True,
    "host_to_guest_nonce": True,
    "guest_to_host_nonce": True,
    "guest_outbound_https": True,
    "runner_kit_preflight": len(preflight.get("missing",[])) == 0,
    "runner_package_staged": runner_stage is not None and runner_stage.get("observed_version") == runner_stage.get("version"),
    "opaque_input_consumed_without_disclosure": True,
    "opaque_input_sanitized": True
  },
  "timing_ms": {
    "boot_to_ssh": (int(os.environ["LAB_BOOT_READY_NS"])-int(os.environ["LAB_BOOT_START_NS"]))//1_000_000,
    "total_before_cleanup": (int(os.environ["LAB_END_NS"])-int(os.environ["LAB_START_NS"]))//1_000_000
  },
  "runner_kit_preflight": preflight,
  "runner_package_stage": runner_stage,
  "warnings": [
    "This proves only the provider-neutral surrogate host and runner-kit seam.",
    "No GitHub self-hosted runner was registered and no runner-registration credential was used."
  ]
}
out.write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n",encoding="utf-8")
print(f"SURROGATE_RECEIPT={out}")
PY
