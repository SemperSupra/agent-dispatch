#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET_REGISTRY="$SCRIPT_DIR/../config/truenas-rdte-targets.json"
TARGET_VERSION="26.0.0-BETA.3"
RAM_MIB=8192
VCPUS=2
DISK_SIZE="24G"
DATA_DISK_SIZE="8G"
DATA_DISK_COUNT=2
DATA_POOL_NAME="rdtepool"
DATA_SERIAL_PREFIX="RDTE_DATA_"
NIC_MAC="52:54:00:54:4e:26"
MIN_HOST_MEM_KIB=$((11 * 1024 * 1024))
MIN_HOST_FREE_KIB=$((28 * 1024 * 1024))

usage() {
  echo "Usage: gha_kvm_truenas_rdte.sh --out RECEIPT [--state-dir DIR] [--target-version VERSION] [--rung t0|t1|t2|t3|t4|t5|t6] [--t6-product litellm|wow-sidecar|garm|garm-provider-g2|garm-provider-g3|garm-provider-g4|garm-provider-g5|official-catalog|foliorelay] [--foundry-control-dir DIR] [--foundry-commit SHA] [--g2-fixture-dir DIR] [--g2-fixture-producer SHA] [--g3-fixture-dir DIR] [--g3-fixture-producer SHA] [--g4-fixture-dir DIR] [--g4-fixture-producer SHA] [--g5-matrix-dir DIR] [--g5-matrix-producer SHA] [--session-manifest FILE]"
}

OUT=""
STATE_DIR=""
RUNG="t0"
T6_PRODUCT="litellm"
FOUNDRY_CONTROL_DIR=""
FOUNDRY_COMMIT=""
G2_FIXTURE_DIR=""
G2_FIXTURE_PRODUCER=""
G3_FIXTURE_DIR=""
G3_FIXTURE_PRODUCER=""
G4_FIXTURE_DIR=""
G4_FIXTURE_PRODUCER=""
G5_MATRIX_DIR=""
G5_MATRIX_PRODUCER=""
SESSION_MANIFEST=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --target-version) TARGET_VERSION="$2"; shift 2 ;;
    --rung) RUNG="$2"; shift 2 ;;
    --t6-product) T6_PRODUCT="$2"; shift 2 ;;
    --foundry-control-dir) FOUNDRY_CONTROL_DIR="$2"; shift 2 ;;
    --foundry-commit) FOUNDRY_COMMIT="$2"; shift 2 ;;
    --g2-fixture-dir) G2_FIXTURE_DIR="$2"; shift 2 ;;
    --g2-fixture-producer) G2_FIXTURE_PRODUCER="$2"; shift 2 ;;
    --g3-fixture-dir) G3_FIXTURE_DIR="$2"; shift 2 ;;
    --g3-fixture-producer) G3_FIXTURE_PRODUCER="$2"; shift 2 ;;
    --g4-fixture-dir) G4_FIXTURE_DIR="$2"; shift 2 ;;
    --g4-fixture-producer) G4_FIXTURE_PRODUCER="$2"; shift 2 ;;
    --g5-matrix-dir) G5_MATRIX_DIR="$2"; shift 2 ;;
    --g5-matrix-producer) G5_MATRIX_PRODUCER="$2"; shift 2 ;;
    --session-manifest) SESSION_MANIFEST="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -n "$OUT" ]] || { usage >&2; exit 2; }
[[ -f "$TARGET_REGISTRY" ]] || { echo "missing exact TrueNAS target registry: $TARGET_REGISTRY" >&2; exit 2; }
TARGET_ENV="$(python3 "$SCRIPT_DIR/truenas_rdte_target.py" --registry "$TARGET_REGISTRY" --version "$TARGET_VERSION" --shell)" || exit 2
# truenas_rdte_target.py emits only shell-quoted values after strict registry validation.
eval "$TARGET_ENV"
[[ "$RUNG" == "t0" || "$RUNG" == "t1" || "$RUNG" == "t2" || "$RUNG" == "t3" || "$RUNG" == "t4" || "$RUNG" == "t5" || "$RUNG" == "t6" ]] || { echo "rung must be t0, t1, t2, t3, t4, t5, or t6" >&2; exit 2; }
if [[ "$RUNG" == "t6" ]]; then
  if [[ "$T6_PRODUCT" != "official-catalog" && "$T6_PRODUCT" != "garm-provider-g5" ]]; then
    [[ "$VERSION" == "26.0.0-BETA.3" ]] || { echo "product-specific T6 controls remain admitted only for exact TrueNAS 26.0.0-BETA.3" >&2; exit 2; }
  fi
  [[ "$T6_PRODUCT" == "litellm" || "$T6_PRODUCT" == "wow-sidecar" || "$T6_PRODUCT" == "garm" || "$T6_PRODUCT" == "garm-provider-g2" || "$T6_PRODUCT" == "garm-provider-g3" || "$T6_PRODUCT" == "garm-provider-g4" || "$T6_PRODUCT" == "garm-provider-g5" || "$T6_PRODUCT" == "official-catalog" || "$T6_PRODUCT" == "foliorelay" ]] || { echo "unsupported T6 product: $T6_PRODUCT" >&2; exit 2; }
  if [[ "$T6_PRODUCT" == "garm-provider-g2" ]]; then
    [[ -n "$G2_FIXTURE_DIR" && -d "$G2_FIXTURE_DIR" ]] || { echo "garm-provider-g2 requires --g2-fixture-dir" >&2; exit 2; }
    [[ "$G2_FIXTURE_PRODUCER" =~ ^[0-9a-f]{40}$ ]] || { echo "garm-provider-g2 requires exact --g2-fixture-producer SHA" >&2; exit 2; }
    G2_FIXTURE_DIR="$(realpath "$G2_FIXTURE_DIR")"
  elif [[ "$T6_PRODUCT" == "garm-provider-g3" ]]; then
    [[ -n "$G3_FIXTURE_DIR" && -d "$G3_FIXTURE_DIR" ]] || { echo "garm-provider-g3 requires --g3-fixture-dir" >&2; exit 2; }
    [[ "$G3_FIXTURE_PRODUCER" =~ ^[0-9a-f]{40}$ ]] || { echo "garm-provider-g3 requires exact --g3-fixture-producer SHA" >&2; exit 2; }
    G3_FIXTURE_DIR="$(realpath "$G3_FIXTURE_DIR")"
  elif [[ "$T6_PRODUCT" == "garm-provider-g4" ]]; then
    [[ -n "$G4_FIXTURE_DIR" && -d "$G4_FIXTURE_DIR" ]] || { echo "garm-provider-g4 requires --g4-fixture-dir" >&2; exit 2; }
    [[ "$G4_FIXTURE_PRODUCER" =~ ^[0-9a-f]{40}$ ]] || { echo "garm-provider-g4 requires exact --g4-fixture-producer SHA" >&2; exit 2; }
    G4_FIXTURE_DIR="$(realpath "$G4_FIXTURE_DIR")"
  elif [[ "$T6_PRODUCT" == "garm-provider-g5" ]]; then
    [[ -n "$G5_MATRIX_DIR" && -d "$G5_MATRIX_DIR" ]] || { echo "garm-provider-g5 requires --g5-matrix-dir" >&2; exit 2; }
    [[ "$G5_MATRIX_PRODUCER" =~ ^[0-9a-f]{40}$ ]] || { echo "garm-provider-g5 requires exact --g5-matrix-producer SHA" >&2; exit 2; }
    [[ -n "$G3_FIXTURE_DIR" && -d "$G3_FIXTURE_DIR" ]] || { echo "garm-provider-g5 requires --g3-fixture-dir" >&2; exit 2; }
    [[ "$G3_FIXTURE_PRODUCER" =~ ^[0-9a-f]{40}$ ]] || { echo "garm-provider-g5 requires exact --g3-fixture-producer SHA" >&2; exit 2; }
    G5_MATRIX_DIR="$(realpath "$G5_MATRIX_DIR")"
    G3_FIXTURE_DIR="$(realpath "$G3_FIXTURE_DIR")"
  else
    [[ -n "$FOUNDRY_CONTROL_DIR" && -d "$FOUNDRY_CONTROL_DIR" ]] || { echo "t6 requires --foundry-control-dir" >&2; exit 2; }
    [[ "$FOUNDRY_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "t6 requires exact --foundry-commit SHA" >&2; exit 2; }
    FOUNDRY_CONTROL_DIR="$(realpath "$FOUNDRY_CONTROL_DIR")"
  fi
fi

if [[ "$RUNG" == "t6" && ( "$T6_PRODUCT" == "garm-provider-g3" || "$T6_PRODUCT" == "garm-provider-g4" || "$T6_PRODUCT" == "garm-provider-g5" ) ]]; then
  VCPUS=4
fi

if [[ -n "$SESSION_MANIFEST" ]]; then
  [[ "$RUNG" == "t6" ]] || { echo "--session-manifest requires rung t6" >&2; exit 2; }
  [[ "$T6_PRODUCT" != garm-provider-* ]] || { echo "session equivalence currently wraps Foundry/control providers only" >&2; exit 2; }
  [[ -f "$SESSION_MANIFEST" ]] || { echo "session manifest does not exist: $SESSION_MANIFEST" >&2; exit 2; }
  SESSION_MANIFEST="$(realpath "$SESSION_MANIFEST")"
  SESSION_LOWERED="$(python3 "$SCRIPT_DIR/truenas_single_capsule_adapter.py"     --manifest "$SESSION_MANIFEST"     --targets "$TARGET_REGISTRY"     --providers "$SCRIPT_DIR/../config/truenas-capsule-providers.json")" || exit 2
  SESSION_SELECTOR="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["existing_selector"])' <<<"$SESSION_LOWERED")"
  SESSION_VERSION="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])' <<<"$SESSION_LOWERED")"
  [[ "$SESSION_SELECTOR" == "$T6_PRODUCT" ]] || { echo "session capsule selector $SESSION_SELECTOR does not match --t6-product $T6_PRODUCT" >&2; exit 2; }
  [[ "$SESSION_VERSION" == "$VERSION" ]] || { echo "session exact version $SESSION_VERSION does not match target $VERSION" >&2; exit 2; }
fi

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
RPC_HOSTFWD_ACCEPTED="false"
RPC_DISCOVERY_OK="false"
RPC_DISCOVERY_JSON=""
QEMU_ALIVE_AT_GATE="unknown"
INSTALL_RESULT_JSON=""
MIDDLEWARE_RESULT_JSON=""
POOL_RESULT_JSON=""
APP_RESULT_JSON=""
LIFECYCLE_RESULT_JSON=""
FOUNDRY_RESULT_JSON=""
SESSION_RESULT_JSON=""
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
  export R_TARGET_VERSION="$VERSION" R_EXPECTED_SYSTEM_VERSION="$EXPECTED_SYSTEM_VERSION"
  export R_ISO_NAME="$ISO_NAME" R_ISO_URL="$ISO_URL" R_SHA_URL="$SHA_URL"
  export R_MIDDLEWARE_REF="$MIDDLEWARE_REF" R_MIDDLEWARE_COMMIT="$MIDDLEWARE_COMMIT"
  export R_FOUNDRY_PROFILE="$FOUNDRY_PROFILE" R_HA_APPS_GATE="$HA_APPS_GATE" R_INSTALLER_RPC_PATH="$INSTALLER_RPC_PATH" R_INSTALLER_RPC_GUEST_PORT="$INSTALLER_RPC_GUEST_PORT" R_INSTALLER_SOURCE_REF="$INSTALLER_SOURCE_REF" R_INSTALLER_MAIN_BLOB_SHA="$INSTALLER_MAIN_BLOB_SHA" R_AUTHORITY_ISSUE="$AUTHORITY_ISSUE"
  export R_RUNG="$RUNG" R_T6_PRODUCT="$T6_PRODUCT" R_T0="$T0_OBSERVED" R_RPC_HOSTFWD="$RPC_HOSTFWD_ACCEPTED"
  export R_VCPUS="$VCPUS" R_RAM_MIB="$RAM_MIB"
  export R_RPC_OK="$RPC_DISCOVERY_OK" R_RPC_DISCOVERY="$RPC_DISCOVERY_JSON" R_QEMU_ALIVE="$QEMU_ALIVE_AT_GATE"
  export R_INSTALL_RESULT="$INSTALL_RESULT_JSON" R_MIDDLEWARE_RESULT="$MIDDLEWARE_RESULT_JSON" R_POOL_RESULT="$POOL_RESULT_JSON" R_APP_RESULT="$APP_RESULT_JSON" R_LIFECYCLE_RESULT="$LIFECYCLE_RESULT_JSON" R_FOUNDRY_RESULT="$FOUNDRY_RESULT_JSON" R_SESSION_RESULT="$SESSION_RESULT_JSON"
  python3 - <<'PY'
import json, os, pathlib
payload = {
  "contract": "gha-kvm-system-lab/v1",
  "target": {"product": "truenas", "version": os.environ["R_TARGET_VERSION"], "rung": os.environ.get("R_RUNG", "t0").upper()},
  "classification": os.environ["R_CLASS"],
  "oracleSatisfied": os.environ["R_ORACLE"].lower() == "true",
  "phase": os.environ["R_PHASE"],
  "detail": os.environ["R_DETAIL"],
  "requested_shape": {
    "vcpus": int(os.environ["R_VCPUS"]),
    "ram_mib": int(os.environ["R_RAM_MIB"]),
    "boot_disk": "24G",
    "data_disks": ["8G", "8G"] if os.environ.get("R_RUNG") in {"t3", "t4", "t5", "t6"} else [],
    "data_pool": {"name": "rdtepool", "topology": "MIRROR"} if os.environ.get("R_RUNG") in {"t3", "t4", "t5", "t6"} else None,
    "data_disk_serials": ["RDTE_DATA_0", "RDTE_DATA_1"] if os.environ.get("R_RUNG") in {"t3", "t4", "t5", "t6"} else [],
    "app": (
      {"name": "garm-provider-g2-fixtures", "image": "ghcr.io/actions/actions-runner:2.336.0@sha256:0cfdcc701ce933c6d243c6b0b2da767366dc9f2e99961d4c3754b0b78084cdda"}
      if os.environ.get("R_RUNG") == "t6" and os.environ.get("R_T6_PRODUCT") == "garm-provider-g2"
      else {"name": "garm-provider-g3-runner", "image": "ghcr.io/actions/actions-runner:2.336.0@sha256:0cfdcc701ce933c6d243c6b0b2da767366dc9f2e99961d4c3754b0b78084cdda"}
      if os.environ.get("R_RUNG") == "t6" and os.environ.get("R_T6_PRODUCT") == "garm-provider-g3"
      else {"name": "garm-provider-g4-pair", "count": 2, "image": "ghcr.io/actions/actions-runner:2.336.0@sha256:0cfdcc701ce933c6d243c6b0b2da767366dc9f2e99961d4c3754b0b78084cdda"}
      if os.environ.get("R_RUNG") == "t6" and os.environ.get("R_T6_PRODUCT") == "garm-provider-g4"
      else {"name": "garm-provider-g5-version-row", "count": 1, "image": "ghcr.io/actions/actions-runner:2.336.0@sha256:0cfdcc701ce933c6d243c6b0b2da767366dc9f2e99961d4c3754b0b78084cdda"}
      if os.environ.get("R_RUNG") == "t6" and os.environ.get("R_T6_PRODUCT") == "garm-provider-g5"
      else {"name": "rdte-t6-garm", "image": "ghcr.io/sempersupra/garm-appliance@sha256:1af67841ddd4589e3798dcda8be49230565c849d07ab57fd05899432dcdabca9"}
      if os.environ.get("R_RUNG") == "t6" and os.environ.get("R_T6_PRODUCT") == "garm"
      else {"name": "rdte-t6-wow-sidecar", "image": "ghcr.io/sempersupra/wow-sidecar@sha256:6b700ce7ba5ae44116b240ccbb54fb3b60dc952a9b4072ca1314b6f311bc5376"}
      if os.environ.get("R_RUNG") == "t6" and os.environ.get("R_T6_PRODUCT") == "wow-sidecar"
      else {"name": "rdte-t6-catalog-ntfy", "catalog_app": "ntfy", "catalog_version": "1.1.21"}
      if os.environ.get("R_RUNG") == "t6" and os.environ.get("R_T6_PRODUCT") == "official-catalog"
      else {"name": "rdte-t6-foliorelay", "images": ["ghcr.io/sempersupra/foliorelay-control@sha256:0ffabcc1ced0325c41c54d860c6fe248e4fc8afeea3994dcebb999d6a14ee1ce", "ghcr.io/sempersupra/foliorelay-cups@sha256:b644b4b1e064a1d10c18fbbb9f9aa09a2835e7e9a48ccda5a67d44cbda006b4f"]}
      if os.environ.get("R_RUNG") == "t6" and os.environ.get("R_T6_PRODUCT") == "foliorelay"
      else {"name": "rdte-t6-litellm", "image": "ghcr.io/sempersupra/litellm-appliance@sha256:225c899db85865929f6099d3e1fe27097cafaed5af823fa397e75e1eb6ec51ac"}
      if os.environ.get("R_RUNG") == "t6"
      else {"name": "rdte-t4-probe", "image": "nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10"}
      if os.environ.get("R_RUNG") in {"t4", "t5"} else None
    ),
  },
  "source": {
    "iso_name": os.environ["R_ISO_NAME"],
    "iso_url": os.environ["R_ISO_URL"],
    "vendor_sha256_url": os.environ["R_SHA_URL"],
    "expected_sha256": os.environ.get("R_EXPECTED") or None,
    "observed_sha256": os.environ.get("R_ISO_SHA") or None,
    "middleware_ref": os.environ["R_MIDDLEWARE_REF"],
    "middleware_commit": os.environ["R_MIDDLEWARE_COMMIT"],
    "foundry_profile": os.environ["R_FOUNDRY_PROFILE"],
    "ha_apps_gate": os.environ["R_HA_APPS_GATE"],
    "installer_rpc_path": os.environ["R_INSTALLER_RPC_PATH"],
    "installer_rpc_guest_port": int(os.environ["R_INSTALLER_RPC_GUEST_PORT"]),
    "installer_source_ref": os.environ["R_INSTALLER_SOURCE_REF"],
    "installer_main_blob_sha": os.environ["R_INSTALLER_MAIN_BLOB_SHA"],
    "system_version_expected": os.environ["R_EXPECTED_SYSTEM_VERSION"],
    "authority_issue": int(os.environ["R_AUTHORITY_ISSUE"]) if os.environ.get("R_AUTHORITY_ISSUE") else None,
  },
  "installer_grub_path": os.environ.get("R_GRUB") or None,
  "oracles": {
    "vendor_iso_digest": bool(os.environ.get("R_ISO_SHA")) and os.environ.get("R_ISO_SHA") == os.environ.get("R_EXPECTED"),
    "installer_environment_observed": os.environ.get("R_T0") == "true" or os.environ.get("R_RPC_OK") == "true",
    "installer_serial_marker_observed": os.environ.get("R_T0") == "true",
    "installer_rpc_hostfwd_accepted": os.environ.get("R_RPC_HOSTFWD") == "true",
    "installer_rpc_readonly": os.environ.get("R_RPC_OK") == "true",
    "installer_install_completed": bool(os.environ.get("R_INSTALL_RESULT")) and json.loads(os.environ["R_INSTALL_RESULT"]).get("oracleSatisfied") is True,
    "installed_middleware_authenticated": bool(os.environ.get("R_MIDDLEWARE_RESULT")) and json.loads(os.environ["R_MIDDLEWARE_RESULT"]).get("oracleSatisfied") is True,
    "data_pool_created": bool(os.environ.get("R_POOL_RESULT")) and json.loads(os.environ["R_POOL_RESULT"]).get("oracleSatisfied") is True,
    "apps_runtime_exercised": bool(os.environ.get("R_APP_RESULT")) and json.loads(os.environ["R_APP_RESULT"]).get("oracleSatisfied") is True,
    "app_lifecycle_exercised": bool(os.environ.get("R_LIFECYCLE_RESULT")) and json.loads(os.environ["R_LIFECYCLE_RESULT"]).get("oracleSatisfied") is True,
    "foundry_materialization_exercised": bool(os.environ.get("R_FOUNDRY_RESULT")) and json.loads(os.environ["R_FOUNDRY_RESULT"]).get("oracleSatisfied") is True,
  },
  "rpc_discovery": json.loads(os.environ["R_RPC_DISCOVERY"]) if os.environ.get("R_RPC_DISCOVERY") else None,
  "install_result": json.loads(os.environ["R_INSTALL_RESULT"]) if os.environ.get("R_INSTALL_RESULT") else None,
  "installed_middleware": json.loads(os.environ["R_MIDDLEWARE_RESULT"]) if os.environ.get("R_MIDDLEWARE_RESULT") else None,
  "data_pool": json.loads(os.environ["R_POOL_RESULT"]) if os.environ.get("R_POOL_RESULT") else None,
  "apps_runtime": json.loads(os.environ["R_APP_RESULT"]) if os.environ.get("R_APP_RESULT") else None,
  "app_lifecycle": json.loads(os.environ["R_LIFECYCLE_RESULT"]) if os.environ.get("R_LIFECYCLE_RESULT") else None,
  "foundry_materialization": json.loads(os.environ["R_FOUNDRY_RESULT"]) if os.environ.get("R_FOUNDRY_RESULT") else None,
  "session_execution": json.loads(os.environ["R_SESSION_RESULT"]) if os.environ.get("R_SESSION_RESULT") else None,
  "qemu_alive_at_gate": os.environ.get("R_QEMU_ALIVE"),
  "serial_tail": os.environ.get("R_SERIAL", ""),
  "limitations": [
    "T0 proves pinned vendor media integrity and installer-environment boot under the disposable virtual target profile.",
    "T1 is version-profiled read-only installer RPC discovery.",
    "T2 adds vendor installation plus installed middleware authentication/health.",
    "T3 adds two experiment-owned sparse data disks and a real middleware-created ZFS mirror pool.",
    "T4 initializes Apps on that pool and runs one synthetic public-safe custom Compose app.",
    "T5 exercises stop/start, config mutation/read-back, redeploy, stop, and delete for that digest-pinned custom app.",
    "T6 consumes one exact public TrueNAS App Foundry materialization control and verifies native Custom App realization/read-back.",
    "The first T6 control remains registry-tag mutable; T6 does not claim immutable upstream container-image identity.",
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
if [[ "$RUNG" == "t2" || "$RUNG" == "t3" || "$RUNG" == "t4" || "$RUNG" == "t5" || "$RUNG" == "t6" ]]; then
  [[ -f "$SCRIPT_DIR/truenas_installer_rpc_install.py" ]] ||
    fail_evidence HARNESS_FAILURE preflight "missing TrueNAS installer install client"
  [[ -f "$SCRIPT_DIR/truenas_middleware_ddp_probe.py" ]] ||
    fail_evidence HARNESS_FAILURE preflight "missing TrueNAS middleware health client"
  if [[ "$RUNG" == "t3" || "$RUNG" == "t4" || "$RUNG" == "t5" || "$RUNG" == "t6" ]]; then
    [[ -f "$SCRIPT_DIR/truenas_middleware_pool_probe.py" ]] ||
      fail_evidence HARNESS_FAILURE preflight "missing TrueNAS T3/T4 pool client"
  fi
  if [[ "$RUNG" == "t4" || "$RUNG" == "t5" || "$RUNG" == "t6" ]]; then
    [[ -f "$SCRIPT_DIR/truenas_middleware_app_probe.py" ]] ||
      fail_evidence HARNESS_FAILURE preflight "missing TrueNAS Apps client"
  fi
  if [[ "$RUNG" == "t5" || "$RUNG" == "t6" ]]; then
    [[ -f "$SCRIPT_DIR/truenas_middleware_app_lifecycle_probe.py" ]] ||
      fail_evidence HARNESS_FAILURE preflight "missing TrueNAS T5 lifecycle client"
  fi
  if [[ "$RUNG" == "t6" ]]; then
    if [[ "$T6_PRODUCT" == "official-catalog" ]]; then
      [[ -f "$SCRIPT_DIR/truenas_middleware_official_catalog_t6_probe.py" ]] ||
        fail_evidence HARNESS_FAILURE preflight "missing TrueNAS T6 official-catalog control client"
    elif [[ "$T6_PRODUCT" == "garm-provider-g2" ]]; then
      [[ -f "$SCRIPT_DIR/truenas_middleware_garm_provider_g2_probe.py" ]] ||
        fail_evidence HARNESS_FAILURE preflight "missing TrueNAS GARM provider G2 client"
      command -v docker >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: docker"
      command -v openssl >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: openssl"
    elif [[ "$T6_PRODUCT" == "garm-provider-g3" ]]; then
      [[ -f "$SCRIPT_DIR/truenas_middleware_garm_provider_g3_probe.py" ]] ||
        fail_evidence HARNESS_FAILURE preflight "missing TrueNAS GARM provider G3 client"
      command -v docker >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: docker"
      command -v openssl >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: openssl"
    elif [[ "$T6_PRODUCT" == "garm-provider-g4" ]]; then
      [[ -f "$SCRIPT_DIR/truenas_middleware_garm_provider_g4_probe.py" ]] ||
        fail_evidence HARNESS_FAILURE preflight "missing TrueNAS GARM provider G4 client"
      command -v docker >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: docker"
      command -v openssl >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: openssl"
    elif [[ "$T6_PRODUCT" == "garm-provider-g5" ]]; then
      [[ -f "$SCRIPT_DIR/truenas_middleware_garm_provider_g5_probe.py" ]] ||
        fail_evidence HARNESS_FAILURE preflight "missing TrueNAS GARM provider G5 client"
      command -v docker >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: docker"
      command -v openssl >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: openssl"
    elif [[ "$T6_PRODUCT" == "garm" ]]; then
      [[ -f "$SCRIPT_DIR/truenas_middleware_garm_t6_probe.py" ]] ||
        fail_evidence HARNESS_FAILURE preflight "missing TrueNAS T6 GARM control client"
    elif [[ "$T6_PRODUCT" == "wow-sidecar" ]]; then
      [[ -f "$SCRIPT_DIR/truenas_middleware_wow_sidecar_t6_probe.py" ]] ||
        fail_evidence HARNESS_FAILURE preflight "missing TrueNAS T6 WOW Sidecar control client"
    elif [[ "$T6_PRODUCT" == "foliorelay" ]]; then
      [[ -f "$SCRIPT_DIR/truenas_middleware_foliorelay_t6_probe.py" ]] ||
        fail_evidence HARNESS_FAILURE preflight "missing TrueNAS T6 FolioRelay control client"
      command -v ipptool >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: ipptool"
      command -v cc >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: C compiler"
      command -v go >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: go"
    else
      [[ -f "$SCRIPT_DIR/truenas_middleware_litellm_t6_probe.py" ]] ||
        fail_evidence HARNESS_FAILURE preflight "missing TrueNAS T6 LiteLLM control client"
    fi
  fi
fi
for cmd in curl sha256sum qemu-img qemu-system-x86_64 xorriso python3; do
  command -v "$cmd" >/dev/null 2>&1 || fail_evidence ENVIRONMENT_FAILURE preflight "missing prerequisite: $cmd"
done
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail_evidence ENVIRONMENT_FAILURE preflight "requires Linux x86_64"
[[ -e /dev/kvm ]] || fail_evidence ENVIRONMENT_FAILURE preflight "/dev/kvm absent"
sudo -n test -r /dev/kvm && sudo -n test -w /dev/kvm || fail_evidence ENVIRONMENT_FAILURE preflight "passwordless sudo KVM boundary unavailable"

MEM_AVAIL_KIB="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
FREE_KIB="$(df -Pk "$STATE_DIR" | awk 'NR==2 {print $4}')"
HOST_CPUS="$(nproc)"
(( HOST_CPUS >= VCPUS )) || fail_evidence SKIPPED_GUARDRAIL preflight "host CPU count $HOST_CPUS below requested guest vCPU count $VCPUS"
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

try_rpc_discovery() {
  local rpc_out="$STATE_DIR/rpc-discovery.json"
  rm -f "$rpc_out"
  python3 "$SCRIPT_DIR/truenas_installer_rpc_probe.py"     --host 127.0.0.1 --port "$RPC_PORT" --path "$INSTALLER_RPC_PATH" --out "$rpc_out" --timeout 3     >/dev/null 2>&1 || true
  [[ -f "$rpc_out" ]] || return 1
  RPC_DISCOVERY_JSON="$(cat "$rpc_out")"
  if python3 - "$rpc_out" <<'PY'
import json, pathlib, sys
try:
    data = json.loads(pathlib.Path(sys.argv[1]).read_text())
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if data.get("oracleSatisfied") is True else 1)
PY
  then
    RPC_DISCOVERY_OK="true"
    return 0
  fi
  return 1
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
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$RPC_PORT-:$INSTALLER_RPC_GUEST_PORT" -device "virtio-net-pci,netdev=net0,mac=$NIC_MAC,addr=0x3" \
  -display none -monitor none \
  -serial "file:$STATE_DIR/serial.log" \
  -daemonize -pidfile "$STATE_DIR/qemu.pid" ||
  fail_evidence ENVIRONMENT_FAILURE boot "QEMU could not start TrueNAS guest"
QEMU_PID="$(sudo -n cat "$STATE_DIR/qemu.pid")"

T0_OBSERVED="false"
RPC_HOSTFWD_ACCEPTED="false"
RPC_DISCOVERY_OK="false"
for attempt in $(seq 1 220); do
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
  # All post-T0 rungs share the installer RPC prerequisite; do not enumerate higher rungs here.
  if [[ "$RUNG" != "t0" ]]; then
    if port_open "$RPC_PORT"; then
      RPC_HOSTFWD_ACCEPTED="true"
    fi
    # QEMU hostfwd accepting TCP is only a scheduling hint. The oracle is a
    # completed vendor WebSocket/JSON-RPC discovery exchange.
    if (( attempt % 2 == 0 )) && try_rpc_discovery; then
      break
    fi
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

[[ "$RPC_DISCOVERY_OK" == "true" ]] ||
  fail_evidence ORACLE_FAILURE installer-rpc "TrueNAS installer did not complete the read-only WebSocket JSON-RPC discovery oracle"

if [[ "$RUNG" == "t1" ]]; then
  write_receipt SUPPORTED true installer-rpc "pinned TrueNAS installer answered read-only JSON-RPC discovery methods; stronger RPC evidence also establishes the installer environment for this rung"
  exit 0
fi

PASSWORD_FILE="$STATE_DIR/install-password"
python3 - "$PASSWORD_FILE" <<'PY'
import pathlib, secrets, sys
path = pathlib.Path(sys.argv[1])
path.write_text(secrets.token_urlsafe(24), encoding="utf-8")
path.chmod(0o600)
PY

INSTALL_OUT="$STATE_DIR/install-result.json"
python3 "$SCRIPT_DIR/truenas_installer_rpc_install.py" \
  --host 127.0.0.1 --port "$RPC_PORT" --path "$INSTALLER_RPC_PATH" \
  --password-file "$PASSWORD_FILE" \
  --out "$INSTALL_OUT" --timeout 120 >/dev/null 2>&1 || true
[[ -f "$INSTALL_OUT" ]] || fail_evidence HARNESS_FAILURE installer-install "installer mutation client did not emit a receipt"
INSTALL_RESULT_JSON="$(cat "$INSTALL_OUT")"
INSTALL_OK="$(python3 - "$INSTALL_OUT" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
print("true" if data.get("oracleSatisfied") is True else "false")
PY
)"
[[ "$INSTALL_OK" == "true" ]] ||
  fail_evidence ORACLE_FAILURE installer-install "vendor installer RPC did not complete installation on the sole disposable disk"

# The installer exports boot-pool before returning from install(). Terminate the
# disposable installer VM only after that completed response, then boot the same disk.
if [[ -n "$QEMU_PID" ]]; then
  sudo -n kill "$QEMU_PID" >/dev/null 2>&1 || true
  for _ in $(seq 1 40); do
    sudo -n kill -0 "$QEMU_PID" >/dev/null 2>&1 || break
    sleep 0.25
  done
  sudo -n kill -9 "$QEMU_PID" >/dev/null 2>&1 || true
  QEMU_PID=""
fi

DATA_DRIVE_ARGS=()
if [[ "$RUNG" == "t3" || "$RUNG" == "t4" || "$RUNG" == "t5" || "$RUNG" == "t6" ]]; then
  for index in $(seq 0 $((DATA_DISK_COUNT - 1))); do
    data_disk="$STATE_DIR/data${index}.qcow2"
    qemu-img create -q -f qcow2 "$data_disk" "$DATA_DISK_SIZE" ||
      fail_evidence HARNESS_FAILURE data-disk-prepare "failed to create sparse data disk $index"
    drive_id="rdtedata${index}"
    pci_slot=$((5 + index))
    DATA_DRIVE_ARGS+=(
      -drive "file=$data_disk,if=none,id=$drive_id,format=qcow2"
      -device "virtio-blk-pci,drive=$drive_id,serial=${DATA_SERIAL_PREFIX}${index},addr=0x${pci_slot}"
    )
  done
fi

HTTP_PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)"
HTTPS_PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)"
LITELLM_HOST_PORT=""
LITELLM_HOSTFWD=""
GARM_HOST_PORT=""
GARM_HOSTFWD=""
FOLIORELAY_CONTROL_HOST_PORT=""
FOLIORELAY_IPP_HOST_PORT=""
FOLIORELAY_OBSERVER_HOST_PORT=""
FOLIORELAY_HOSTFWD=""
if [[ "$RUNG" == "t6" && "$T6_PRODUCT" == "litellm" ]]; then
  LITELLM_HOST_PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)"
  LITELLM_HOSTFWD=",hostfwd=tcp:127.0.0.1:${LITELLM_HOST_PORT}-:30401"
fi
if [[ "$RUNG" == "t6" && "$T6_PRODUCT" == "garm" ]]; then
  GARM_HOST_PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)"
  GARM_HOSTFWD=",hostfwd=tcp:127.0.0.1:${GARM_HOST_PORT}-:30880"
fi
if [[ "$RUNG" == "t6" && "$T6_PRODUCT" == "foliorelay" ]]; then
  read -r FOLIORELAY_CONTROL_HOST_PORT FOLIORELAY_IPP_HOST_PORT FOLIORELAY_OBSERVER_HOST_PORT < <(python3 - <<'PY'
import socket
ports=[]
for _ in range(3):
    s=socket.socket(); s.bind(("127.0.0.1",0)); ports.append(str(s.getsockname()[1])); s.close()
print(" ".join(ports))
PY
)
  FOLIORELAY_HOSTFWD=",hostfwd=tcp:127.0.0.1:${FOLIORELAY_CONTROL_HOST_PORT}-:18080,hostfwd=tcp:127.0.0.1:${FOLIORELAY_IPP_HOST_PORT}-:8634,hostfwd=tcp:127.0.0.1:${FOLIORELAY_OBSERVER_HOST_PORT}-:18081"
fi
: >"$STATE_DIR/serial.log"
sudo -n qemu-system-x86_64 \
  -enable-kvm -cpu host -smp "$VCPUS" -m "$RAM_MIB" \
  -drive "file=$STATE_DIR/boot.qcow2,if=none,id=rdteboot,format=qcow2" \
  -device "virtio-blk-pci,drive=rdteboot,id=rdte-boot,addr=0x4,bootindex=1" \
  "${DATA_DRIVE_ARGS[@]}" \
  -boot strict=on \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$HTTP_PORT-:80,hostfwd=tcp:127.0.0.1:$HTTPS_PORT-:443${LITELLM_HOSTFWD}${GARM_HOSTFWD}${FOLIORELAY_HOSTFWD}" \
  -device "virtio-net-pci,netdev=net0,mac=$NIC_MAC,addr=0x3" \
  -display none -monitor none \
  -serial "file:$STATE_DIR/serial.log" \
  -daemonize -pidfile "$STATE_DIR/qemu.pid" ||
  fail_evidence ENVIRONMENT_FAILURE installed-boot "QEMU could not start installed TrueNAS guest"
QEMU_PID="$(sudo -n cat "$STATE_DIR/qemu.pid")"

MIDDLEWARE_OUT="$STATE_DIR/middleware-health.json"
MIDDLEWARE_OK="false"
MIDDLEWARE_PORT=""
MIDDLEWARE_TLS_ARG=()
for attempt in $(seq 1 180); do
  if ! sudo -n kill -0 "$QEMU_PID" >/dev/null 2>&1; then
    QEMU_ALIVE_AT_GATE="false"
    break
  fi
  QEMU_ALIVE_AT_GATE="true"

  if (( attempt % 2 == 0 )); then
    rm -f "$MIDDLEWARE_OUT"
    python3 "$SCRIPT_DIR/truenas_middleware_ddp_probe.py" \
      --host 127.0.0.1 --port "$HTTP_PORT" \
      --password-file "$PASSWORD_FILE" --out "$MIDDLEWARE_OUT" --timeout 4 \
      >/dev/null 2>&1 || true
    if [[ -f "$MIDDLEWARE_OUT" ]] && python3 - "$MIDDLEWARE_OUT" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
raise SystemExit(0 if data.get("oracleSatisfied") is True else 1)
PY
    then
      MIDDLEWARE_OK="true"
      MIDDLEWARE_PORT="$HTTP_PORT"
      MIDDLEWARE_TLS_ARG=()
      break
    fi

    rm -f "$MIDDLEWARE_OUT"
    python3 "$SCRIPT_DIR/truenas_middleware_ddp_probe.py" \
      --host 127.0.0.1 --port "$HTTPS_PORT" --tls \
      --password-file "$PASSWORD_FILE" --out "$MIDDLEWARE_OUT" --timeout 4 \
      >/dev/null 2>&1 || true
    if [[ -f "$MIDDLEWARE_OUT" ]] && python3 - "$MIDDLEWARE_OUT" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
raise SystemExit(0 if data.get("oracleSatisfied") is True else 1)
PY
    then
      MIDDLEWARE_OK="true"
      MIDDLEWARE_PORT="$HTTPS_PORT"
      MIDDLEWARE_TLS_ARG=(--tls)
      break
    fi
  fi
  sleep 3
done

if [[ -f "$MIDDLEWARE_OUT" ]]; then
  MIDDLEWARE_RESULT_JSON="$(cat "$MIDDLEWARE_OUT")"
fi
[[ "$MIDDLEWARE_OK" == "true" ]] ||
  fail_evidence ORACLE_FAILURE installed-middleware "installed TrueNAS did not authenticate and answer system.version/system.info within the bounded boot window"

if [[ "$RUNG" == "t2" ]]; then
  write_receipt SUPPORTED true installed-middleware "vendor installer completed and installed TrueNAS middleware authenticated and answered health methods"
  exit 0
fi

POOL_OUT="$STATE_DIR/data-pool.json"
python3 "$SCRIPT_DIR/truenas_middleware_pool_probe.py" \
  --host 127.0.0.1 --port "$MIDDLEWARE_PORT" \
  "${MIDDLEWARE_TLS_ARG[@]}" \
  --password-file "$PASSWORD_FILE" \
  --out "$POOL_OUT" --pool-name "$DATA_POOL_NAME" \
  --expected-data-disks "$DATA_DISK_COUNT" --data-serial-prefix "$DATA_SERIAL_PREFIX" \
  --timeout 15 --job-timeout 180 >/dev/null 2>&1 || true
[[ -f "$POOL_OUT" ]] || fail_evidence HARNESS_FAILURE data-pool "T3/T4 pool client did not emit a receipt"
POOL_RESULT_JSON="$(cat "$POOL_OUT")"
POOL_OK="$(python3 - "$POOL_OUT" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
print("true" if data.get("oracleSatisfied") is True else "false")
PY
)"
[[ "$POOL_OK" == "true" ]] ||
  fail_evidence ORACLE_FAILURE data-pool "installed TrueNAS did not create and independently verify the disposable ZFS mirror pool"

if [[ "$RUNG" == "t3" ]]; then
  write_receipt SUPPORTED true data-pool "installed TrueNAS created an ONLINE healthy two-disk mirror containing exactly the selected disposable data disks"
  exit 0
fi

APP_OUT="$STATE_DIR/apps-runtime.json"
python3 "$SCRIPT_DIR/truenas_middleware_app_probe.py" \
  --host 127.0.0.1 --port "$MIDDLEWARE_PORT" \
  "${MIDDLEWARE_TLS_ARG[@]}" \
  --password-file "$PASSWORD_FILE" \
  --out "$APP_OUT" --pool-name "$DATA_POOL_NAME" \
  --expected-version "$EXPECTED_SYSTEM_VERSION" \
  --middleware-ref "$MIDDLEWARE_REF" --middleware-commit "$MIDDLEWARE_COMMIT" \
  --ha-apps-gate "$HA_APPS_GATE" \
  --timeout 8 --job-timeout 300 --state-timeout 180 >/dev/null 2>&1 || true
[[ -f "$APP_OUT" ]] || fail_evidence HARNESS_FAILURE apps-runtime "T4 Apps client did not emit a receipt"
APP_RESULT_JSON="$(cat "$APP_OUT")"
APP_OK="$(python3 - "$APP_OUT" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
print("true" if data.get("oracleSatisfied") is True else "false")
PY
)"
[[ "$APP_OK" == "true" ]] ||
  fail_evidence ORACLE_FAILURE apps-runtime "TrueNAS Apps did not initialize and run the bounded custom app oracle"

if [[ "$RUNG" == "t4" ]]; then
  write_receipt SUPPORTED true apps-runtime "installed TrueNAS initialized Apps on rdtepool and ran the bounded digest-pinned custom nginx Compose app"
  exit 0
fi

LIFECYCLE_OUT="$STATE_DIR/app-lifecycle.json"
python3 "$SCRIPT_DIR/truenas_middleware_app_lifecycle_probe.py" \
  --host 127.0.0.1 --port "$MIDDLEWARE_PORT" \
  "${MIDDLEWARE_TLS_ARG[@]}" \
  --password-file "$PASSWORD_FILE" \
  --out "$LIFECYCLE_OUT" --expected-version "$EXPECTED_SYSTEM_VERSION" \
  --timeout 8 --job-timeout 300 --state-timeout 180 >/dev/null 2>&1 || true
[[ -f "$LIFECYCLE_OUT" ]] || fail_evidence HARNESS_FAILURE app-lifecycle "T5 lifecycle client did not emit a receipt"
LIFECYCLE_RESULT_JSON="$(cat "$LIFECYCLE_OUT")"
LIFECYCLE_OK="$(python3 - "$LIFECYCLE_OUT" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
print("true" if data.get("oracleSatisfied") is True else "false")
PY
)"
[[ "$LIFECYCLE_OK" == "true" ]] ||
  fail_evidence ORACLE_FAILURE app-lifecycle "custom app did not complete the bounded T5 lifecycle"

if [[ "$RUNG" == "t5" ]]; then
  write_receipt SUPPORTED true app-lifecycle "digest-pinned custom app completed stop/start, config mutation with public read-back, redeploy, stop, and delete"
  exit 0
fi

FOUNDRY_OUT="$STATE_DIR/foundry-control.json"
if [[ -n "$SESSION_MANIFEST" ]]; then
  SESSION_CONTEXT="$STATE_DIR/session-context.json"
  SESSION_OUT="$STATE_DIR/session-execution.json"
  SESSION_RECEIPTS="$STATE_DIR/session-capsules"
  export SCTX_PRODUCT="$T6_PRODUCT" SCTX_MIDDLEWARE_PORT="$MIDDLEWARE_PORT"
  export SCTX_PASSWORD_FILE="$PASSWORD_FILE" SCTX_CONTROL_DIR="$FOUNDRY_CONTROL_DIR" SCTX_FOUNDRY_COMMIT="$FOUNDRY_COMMIT"
  export SCTX_LITELLM_PORT="$LITELLM_HOST_PORT" SCTX_GARM_PORT="$GARM_HOST_PORT"
  export SCTX_FOLIO_CONTROL="$FOLIORELAY_CONTROL_HOST_PORT" SCTX_FOLIO_IPP="$FOLIORELAY_IPP_HOST_PORT" SCTX_FOLIO_OBSERVER="$FOLIORELAY_OBSERVER_HOST_PORT"
  if (( ${#MIDDLEWARE_TLS_ARG[@]} )); then SCTX_TLS=true; else SCTX_TLS=false; fi
  export SCTX_TLS
  python3 - "$SESSION_CONTEXT" <<'PY'
import json, os, pathlib, sys
selector=os.environ["SCTX_PRODUCT"]
provider_id={
  "litellm":"litellm-t6",
  "wow-sidecar":"wow-sidecar-t6",
  "garm":"garm-t6",
  "official-catalog":"official-catalog-t6",
  "foliorelay":"foliorelay-t6",
}[selector]
ports={}
if selector=="litellm": ports["service"]=int(os.environ["SCTX_LITELLM_PORT"])
elif selector=="garm": ports["service"]=int(os.environ["SCTX_GARM_PORT"])
elif selector=="foliorelay":
    ports={
      "control":int(os.environ["SCTX_FOLIO_CONTROL"]),
      "ipp":int(os.environ["SCTX_FOLIO_IPP"]),
      "observer":int(os.environ["SCTX_FOLIO_OBSERVER"]),
    }
payload={
  "schema":"truenas-capsule-context/v1",
  "host":"127.0.0.1",
  "middleware_port":int(os.environ["SCTX_MIDDLEWARE_PORT"]),
  "password_file":os.environ["SCTX_PASSWORD_FILE"],
  "tls":os.environ["SCTX_TLS"].lower()=="true",
  "providers":{
    provider_id:{
      "control_dir":os.environ["SCTX_CONTROL_DIR"],
      "foundry_commit":os.environ["SCTX_FOUNDRY_COMMIT"],
      "ports":ports,
    }
  },
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n",encoding="utf-8")
PY
  python3 "$SCRIPT_DIR/truenas_session_runner.py" \
    --manifest "$SESSION_MANIFEST" \
    --targets "$TARGET_REGISTRY" \
    --providers "$SCRIPT_DIR/../config/truenas-capsule-providers.json" \
    --executor "$SCRIPT_DIR/truenas_existing_probe_capsule_executor.py" \
    --context "$SESSION_CONTEXT" \
    --out-dir "$SESSION_RECEIPTS" \
    --out "$SESSION_OUT" >/dev/null 2>&1 || true
  [[ -f "$SESSION_OUT" ]] || fail_evidence HARNESS_FAILURE foundry-materialization "single-capsule session runner did not emit a receipt"
  SESSION_RESULT_JSON="$(cat "$SESSION_OUT")"
  SESSION_CAPSULE_VERDICT="$(python3 - "$SESSION_OUT" <<'PY'
import json, pathlib, sys
session=json.loads(pathlib.Path(sys.argv[1]).read_text())
caps=session.get("capsules") or []
print(caps[0].get("verdict","HARNESS_FAILURE") if len(caps)==1 else "HARNESS_FAILURE")
PY
)"
  if [[ "$SESSION_CAPSULE_VERDICT" != "SUPPORTED" ]]; then
    case "$SESSION_CAPSULE_VERDICT" in
      ORACLE_FAILURE|HARNESS_FAILURE|ENVIRONMENT_FAILURE|UNSUPPORTED)
        fail_evidence "$SESSION_CAPSULE_VERDICT" foundry-materialization "single-capsule session provider returned $SESSION_CAPSULE_VERDICT"
        ;;
      *)
        fail_evidence HARNESS_FAILURE foundry-materialization "single-capsule session returned unexpected verdict $SESSION_CAPSULE_VERDICT"
        ;;
    esac
  fi
  SESSION_OK="$(python3 - "$SESSION_OUT" <<'PY'
import json, pathlib, sys
session=json.loads(pathlib.Path(sys.argv[1]).read_text())
caps=session.get("capsules") or []
ok=(session.get("classification")=="SESSION_CLEAN" and len(caps)==1 and caps[0].get("verdict")=="SUPPORTED")
print("true" if ok else "false")
PY
)"
  [[ "$SESSION_OK" == "true" ]] || fail_evidence HARNESS_FAILURE foundry-materialization "single-capsule session envelope was not clean"
  python3 - "$SESSION_OUT" "$FOUNDRY_OUT" <<'PY'
import json, pathlib, sys
session=json.loads(pathlib.Path(sys.argv[1]).read_text())
provider=session["capsules"][0].get("provider_receipt")
if not isinstance(provider,dict) or provider.get("classification")!="SUPPORTED" or provider.get("oracleSatisfied") is not True:
    raise SystemExit("accepted capsule did not retain accepted provider receipt")
pathlib.Path(sys.argv[2]).write_text(json.dumps(provider,indent=2,sort_keys=True)+"\n",encoding="utf-8")
PY
else
if [[ "$T6_PRODUCT" == "official-catalog" ]]; then
  python3 "$SCRIPT_DIR/truenas_middleware_official_catalog_t6_probe.py" \
    --host 127.0.0.1 --port "$MIDDLEWARE_PORT" \
    "${MIDDLEWARE_TLS_ARG[@]}" \
    --password-file "$PASSWORD_FILE" \
    --control-dir "$FOUNDRY_CONTROL_DIR" \
    --foundry-commit "$FOUNDRY_COMMIT" \
    --out "$FOUNDRY_OUT" --timeout 8 --job-timeout 300 --state-timeout 240 >/dev/null 2>&1 || true
elif [[ "$T6_PRODUCT" == "garm-provider-g2" ]]; then
  python3 "$SCRIPT_DIR/truenas_middleware_garm_provider_g2_probe.py" \
    --host 127.0.0.1 --http-port "$HTTP_PORT" --https-port "$HTTPS_PORT" \
    --password-file "$PASSWORD_FILE" \
    --fixture-dir "$G2_FIXTURE_DIR" \
    --fixture-producer-commit "$G2_FIXTURE_PRODUCER" \
    --out "$FOUNDRY_OUT" --timeout 8 --job-timeout 300 >/dev/null 2>&1 || true
elif [[ "$T6_PRODUCT" == "garm-provider-g3" ]]; then
  python3 "$SCRIPT_DIR/truenas_middleware_garm_provider_g3_probe.py" \
    --host 127.0.0.1 --http-port "$HTTP_PORT" --https-port "$HTTPS_PORT" \
    --password-file "$PASSWORD_FILE" \
    --fixture-dir "$G3_FIXTURE_DIR" \
    --fixture-producer-commit "$G3_FIXTURE_PRODUCER" \
    --out "$FOUNDRY_OUT" --timeout 8 --job-timeout 300 >/dev/null 2>&1 || true
elif [[ "$T6_PRODUCT" == "garm-provider-g4" ]]; then
  python3 "$SCRIPT_DIR/truenas_middleware_garm_provider_g4_probe.py" \
    --host 127.0.0.1 --http-port "$HTTP_PORT" --https-port "$HTTPS_PORT" \
    --password-file "$PASSWORD_FILE" \
    --fixture-dir "$G4_FIXTURE_DIR" \
    --fixture-producer-commit "$G4_FIXTURE_PRODUCER" \
    --out "$FOUNDRY_OUT" --timeout 8 --job-timeout 300 >/dev/null 2>&1 || true
elif [[ "$T6_PRODUCT" == "garm-provider-g5" ]]; then
  python3 "$SCRIPT_DIR/truenas_middleware_garm_provider_g5_probe.py" \
    --host 127.0.0.1 --http-port "$HTTP_PORT" --https-port "$HTTPS_PORT" \
    --password-file "$PASSWORD_FILE" \
    --matrix-dir "$G5_MATRIX_DIR" \
    --matrix-producer-commit "$G5_MATRIX_PRODUCER" \
    --fixture-dir "$G3_FIXTURE_DIR" \
    --fixture-producer-commit "$G3_FIXTURE_PRODUCER" \
    --target-version "$VERSION" \
    --expected-middleware-commit "$MIDDLEWARE_COMMIT" \
    --out "$FOUNDRY_OUT" --timeout 8 --job-timeout 300 >/dev/null 2>&1 || true
elif [[ "$T6_PRODUCT" == "garm" ]]; then
  python3 "$SCRIPT_DIR/truenas_middleware_garm_t6_probe.py" \
    --host 127.0.0.1 --port "$MIDDLEWARE_PORT" --service-port "$GARM_HOST_PORT" \
    "${MIDDLEWARE_TLS_ARG[@]}" \
    --password-file "$PASSWORD_FILE" \
    --control-dir "$FOUNDRY_CONTROL_DIR" \
    --foundry-commit "$FOUNDRY_COMMIT" \
    --out "$FOUNDRY_OUT" --timeout 8 --job-timeout 300 --state-timeout 240 >/dev/null 2>&1 || true
elif [[ "$T6_PRODUCT" == "wow-sidecar" ]]; then
  python3 "$SCRIPT_DIR/truenas_middleware_wow_sidecar_t6_probe.py" \
    --host 127.0.0.1 --port "$MIDDLEWARE_PORT" \
    "${MIDDLEWARE_TLS_ARG[@]}" \
    --password-file "$PASSWORD_FILE" \
    --control-dir "$FOUNDRY_CONTROL_DIR" \
    --foundry-commit "$FOUNDRY_COMMIT" \
    --out "$FOUNDRY_OUT" --timeout 8 --job-timeout 300 --state-timeout 240 >/dev/null 2>&1 || true
elif [[ "$T6_PRODUCT" == "foliorelay" ]]; then
  FOLIORELAY_OBSERVER_BIN="$STATE_DIR/foliorelay-observer"
  GO111MODULE=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -buildid=" -o "$FOLIORELAY_OBSERVER_BIN" "$SCRIPT_DIR/../tools/foliorelay-observer"
  [[ -s "$FOLIORELAY_OBSERVER_BIN" ]] || fail_evidence HARNESS_FAILURE foundry-materialization "static FolioRelay observer build produced no binary"
  (( $(stat -c%s "$FOLIORELAY_OBSERVER_BIN") <= 6291456 )) || fail_evidence HARNESS_FAILURE foundry-materialization "static FolioRelay observer exceeds 6 MiB budget"
  python3 "$SCRIPT_DIR/truenas_middleware_foliorelay_t6_probe.py" \
    --host 127.0.0.1 --port "$MIDDLEWARE_PORT" \
    --control-port "$FOLIORELAY_CONTROL_HOST_PORT" \
    --ipp-port "$FOLIORELAY_IPP_HOST_PORT" \
    --observer-port "$FOLIORELAY_OBSERVER_HOST_PORT" \
    --observer-bin "$FOLIORELAY_OBSERVER_BIN" \
    "${MIDDLEWARE_TLS_ARG[@]}" \
    --password-file "$PASSWORD_FILE" \
    --control-dir "$FOUNDRY_CONTROL_DIR" \
    --foundry-commit "$FOUNDRY_COMMIT" \
    --out "$FOUNDRY_OUT" --timeout 8 --job-timeout 300 --state-timeout 300 >/dev/null 2>&1 || true
else
  python3 "$SCRIPT_DIR/truenas_middleware_litellm_t6_probe.py" \
    --host 127.0.0.1 --port "$MIDDLEWARE_PORT" --service-port "$LITELLM_HOST_PORT" \
    "${MIDDLEWARE_TLS_ARG[@]}" \
    --password-file "$PASSWORD_FILE" \
    --control-dir "$FOUNDRY_CONTROL_DIR" \
    --foundry-commit "$FOUNDRY_COMMIT" \
    --out "$FOUNDRY_OUT" --timeout 8 --job-timeout 300 --state-timeout 240 >/dev/null 2>&1 || true
fi
fi
[[ -f "$FOUNDRY_OUT" ]] || fail_evidence HARNESS_FAILURE foundry-materialization "T6 Foundry control client did not emit a receipt"
FOUNDRY_RESULT_JSON="$(cat "$FOUNDRY_OUT")"
FOUNDRY_OK="$(python3 - "$FOUNDRY_OUT" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
print("true" if data.get("oracleSatisfied") is True else "false")
PY
)"
[[ "$FOUNDRY_OK" == "true" ]] ||
  fail_evidence ORACLE_FAILURE foundry-materialization "exact Foundry-exported $T6_PRODUCT control did not realize and verify on TrueNAS"

if [[ "$T6_PRODUCT" == "official-catalog" ]]; then
  write_receipt SUPPORTED true foundry-materialization "exact Foundry-exported native catalog control passed observe/discover-plan-apply-verify convergence, stop/start, config update/read-back, redeploy, conditional native-upgrade receipt, retain-data delete/reinstall, NOOP convergence, and final cleanup"
elif [[ "$T6_PRODUCT" == "garm-provider-g2" ]]; then
  write_receipt SUPPORTED true foundry-materialization "exact packaged GARM TrueNAS provider passed verified WSS/API-key transport, valid local adoption, foreign exclusion, managed-drift fail-closed behavior, fresh-process readoption, and zero-residue cleanup; provider create/delete and GitHub/JIT intentionally not exercised"
elif [[ "$T6_PRODUCT" == "garm-provider-g3" ]]; then
  write_receipt SUPPORTED true foundry-materialization "exact packaged GARM TrueNAS provider CreateInstance realized the source-derived fixed runner App profile, exact Compose read-back and provider Get/List reconciliation passed, supported middleware moved the experiment App inactive, provider DeleteInstance retired it, and GitHub/JIT/private workload/physical/capacity claims remained unexercised"
elif [[ "$T6_PRODUCT" == "garm-provider-g4" ]]; then
  write_receipt SUPPORTED true foundry-materialization "exact packaged GARM TrueNAS provider realized two source-derived runner Apps concurrently, exact Compose and fresh-process Get/List reconciliation passed for both, active deletion failed closed, both retirement orders reached empty inventory with zero residue, and GitHub/JIT/private workload/physical/capacity claims remained unexercised"
elif [[ "$T6_PRODUCT" == "garm-provider-g5" ]]; then
  write_receipt SUPPORTED true foundry-materialization "exact G5 TrueNAS source-matrix row matched the RDTE target and the fixed packaged provider completed the capacity-one Create/read-back/Get/List/inactive/Delete/absence/empty-inventory/zero-residue lifecycle without runtime support inheritance or GitHub/JIT/private/physical/capacity claims"
elif [[ "$T6_PRODUCT" == "garm" ]]; then
  write_receipt SUPPORTED true foundry-materialization "exact Foundry-exported GARM controller control passed exact appliance and secret-normalized config read-back, persistent state, external HTTPS, restart persistence, and zero-residue cleanup; GitHub/JIT registration intentionally not exercised"
elif [[ "$T6_PRODUCT" == "wow-sidecar" ]]; then
  write_receipt SUPPORTED true foundry-materialization "exact Foundry-exported WOW Sidecar control passed immutable image/config read-back, permissions/seed metadata, public-fixture worker runtime, restart persistence, and zero-residue cleanup"
elif [[ "$T6_PRODUCT" == "foliorelay" ]]; then
  write_receipt SUPPORTED true foundry-materialization "exact Foundry-exported FolioRelay three-service control passed exact image/config read-back, portal and IPP reachability, canonical identity, PDF/URF exact-source Inbox preservation, independent in-guest DNS-SD observation, restart persistence, and zero-residue cleanup"
else
  write_receipt SUPPORTED true foundry-materialization "exact Foundry-exported LiteLLM control passed S1 projection, exact image/config read-back, health, restart persistence, and delete/absence"
fi
