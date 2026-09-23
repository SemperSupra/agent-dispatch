#!/usr/bin/env bash
set -euo pipefail

CONTRACT_VERSION="self-hosted-runner-kit/v1"

usage() {
  cat <<'EOF'
Usage:
  self_hosted_runner_kit.sh contract
  self_hosted_runner_kit.sh preflight [--work-dir PATH]
  self_hosted_runner_kit.sh plan --version VERSION --sha256 SHA256 [--arch x64|arm64] [--work-dir PATH] [--mode jit|persistent] [--labels CSV]
  self_hosted_runner_kit.sh stage --version VERSION --sha256 SHA256 [--arch x64|arm64] [--work-dir PATH]
  self_hosted_runner_kit.sh consume-opaque-input PATH
  self_hosted_runner_kit.sh sanitize-input PATH

The runner kit is host-provider-neutral. It never acquires GitHub runner-registration
authority. Control-side code supplies one-run/one-runner material as an opaque file.
EOF
}

contract() {
  cat <<EOF
{"contract":"${CONTRACT_VERSION}","provider_neutral":true,"credential_acquisition":"control-side","opaque_input_only":true,"supported_modes":["jit","persistent"],"requires":["linux","bash","curl","tar","python3","sha256sum","awk","df","stat"],"optional":["systemd"]}
EOF
}

preflight() {
  local work_dir="/opt/actions-runner"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --work-dir) work_dir="$2"; shift 2 ;;
      *) echo "unknown argument: $1" >&2; return 2 ;;
    esac
  done

  local os arch user systemd="false"
  local -a missing=()
  os="$(uname -s)"
  arch="$(uname -m)"
  user="$(id -un)"
  for cmd in bash curl tar python3 sha256sum awk df stat; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemd="true"
  fi

  local missing_json
  missing_json="$(printf '%s\n' "${missing[@]-}" | python3 -c 'import json,sys; print(json.dumps([x for x in sys.stdin.read().splitlines() if x]))')"
  python3 - "$CONTRACT_VERSION" "$os" "$arch" "$user" "$work_dir" "$systemd" "$missing_json" <<'PY'
import json, sys
contract, os_name, arch, user, work_dir, systemd, missing = sys.argv[1:]
print(json.dumps({
    "contract": contract,
    "os": os_name,
    "arch": arch,
    "user": user,
    "work_dir": work_dir,
    "systemd": systemd == "true",
    "missing": json.loads(missing),
}, sort_keys=True))
PY

  [[ "$os" == "Linux" && ${#missing[@]} -eq 0 ]]
}

plan() {
  local version="" sha256="" arch="" work_dir="/opt/actions-runner" mode="jit" labels=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version) version="$2"; shift 2 ;;
      --sha256) sha256="$2"; shift 2 ;;
      --arch) arch="$2"; shift 2 ;;
      --work-dir) work_dir="$2"; shift 2 ;;
      --mode) mode="$2"; shift 2 ;;
      --labels) labels="$2"; shift 2 ;;
      *) echo "unknown argument: $1" >&2; return 2 ;;
    esac
  done
  [[ -n "$version" && "$sha256" =~ ^[0-9a-fA-F]{64}$ ]] || {
    echo "version and a 64-hex SHA256 are required" >&2
    return 2
  }
  if [[ -z "$arch" ]]; then
    case "$(uname -m)" in
      x86_64) arch="x64" ;;
      aarch64|arm64) arch="arm64" ;;
      *) echo "unsupported architecture" >&2; return 2 ;;
    esac
  fi
  [[ "$mode" == "jit" || "$mode" == "persistent" ]] || {
    echo "mode must be jit or persistent" >&2
    return 2
  }

  local url="https://github.com/actions/runner/releases/download/v${version}/actions-runner-linux-${arch}-${version}.tar.gz"
  python3 - "$CONTRACT_VERSION" "$version" "$sha256" "$arch" "$work_dir" "$mode" "$labels" "$url" <<'PY'
import json, sys
contract, version, sha256, arch, work_dir, mode, labels, url = sys.argv[1:]
print(json.dumps({
    "contract": contract,
    "version": version,
    "sha256": sha256,
    "arch": arch,
    "work_dir": work_dir,
    "mode": mode,
    "labels": labels,
    "download_url": url,
}, sort_keys=True))
PY
}


stage() {
  local version="" sha256="" arch="" work_dir="/opt/actions-runner"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version) version="$2"; shift 2 ;;
      --sha256) sha256="$2"; shift 2 ;;
      --arch) arch="$2"; shift 2 ;;
      --work-dir) work_dir="$2"; shift 2 ;;
      *) echo "unknown argument: $1" >&2; return 2 ;;
    esac
  done
  [[ -n "$version" && "$sha256" =~ ^[0-9a-fA-F]{64}$ ]] || {
    echo "version and a 64-hex SHA256 are required" >&2
    return 2
  }
  if [[ -z "$arch" ]]; then
    case "$(uname -m)" in
      x86_64) arch="x64" ;;
      aarch64|arm64) arch="arm64" ;;
      *) echo "unsupported architecture" >&2; return 2 ;;
    esac
  fi

  local url="https://github.com/actions/runner/releases/download/v$version/actions-runner-linux-$arch-$version.tar.gz"
  local marker="$work_dir/.runner-kit-stage"
  local observed=""
  if [[ -d "$work_dir" && -f "$marker" ]] && grep -Fxq "$version $sha256" "$marker"; then
    observed="$(cd "$work_dir" && ./bin/Runner.Listener --version)"
    [[ "$observed" == "$version" ]] || { echo "staged runner version oracle failed" >&2; return 5; }
    STAGE_CONTRACT="$CONTRACT_VERSION" STAGE_VERSION="$version" STAGE_SHA="$sha256" STAGE_ARCH="$arch" STAGE_DIR="$work_dir" STAGE_OBSERVED="$observed" STAGE_REUSED=true python3 -c 'import json,os; print(json.dumps({"contract":os.environ["STAGE_CONTRACT"],"version":os.environ["STAGE_VERSION"],"sha256":os.environ["STAGE_SHA"],"arch":os.environ["STAGE_ARCH"],"work_dir":os.environ["STAGE_DIR"],"observed_version":os.environ["STAGE_OBSERVED"],"reused":os.environ["STAGE_REUSED"]=="true"},sort_keys=True))'
    return 0
  fi
  if [[ -e "$work_dir" ]]; then
    echo "refusing to stage into existing unowned or mismatched work directory" >&2
    return 3
  fi

  local parent tmp archive actual archive_bytes avail_bytes required_bytes
  parent="$(dirname "$work_dir")"
  mkdir -p "$parent"
  tmp="$(mktemp -d "$parent/.runner-stage.XXXXXX")"
  archive="$tmp/runner.tar.gz"
  cleanup_stage() { rm -rf -- "$tmp"; }
  trap cleanup_stage RETURN

  curl --fail --location --retry 3 --silent --show-error "$url" -o "$archive"
  actual="$(sha256sum "$archive" | awk '{print $1}')"
  [[ "$actual" == "$sha256" ]] || { echo "runner package checksum mismatch" >&2; return 4; }
  archive_bytes="$(stat -c %s "$archive")"
  avail_bytes="$(df -B1 --output=avail "$tmp" | awk 'NR==2 {print $1}')"
  required_bytes="$((archive_bytes * 4))"
  if (( avail_bytes < required_bytes )); then
    echo "insufficient staging disk: available=$avail_bytes required_at_least=$required_bytes archive=$archive_bytes" >&2
    return 6
  fi
  mkdir "$tmp/root"
  tar -xzf "$archive" -C "$tmp/root"
  observed="$(cd "$tmp/root" && ./bin/Runner.Listener --version)"
  [[ "$observed" == "$version" ]] || { echo "runner package version oracle failed" >&2; return 5; }
  printf '%s %s\n' "$version" "$sha256" > "$tmp/root/.runner-kit-stage"
  mv "$tmp/root" "$work_dir"

  STAGE_CONTRACT="$CONTRACT_VERSION" STAGE_VERSION="$version" STAGE_SHA="$sha256" STAGE_ARCH="$arch" STAGE_DIR="$work_dir" STAGE_OBSERVED="$observed" STAGE_REUSED=false python3 -c 'import json,os; print(json.dumps({"contract":os.environ["STAGE_CONTRACT"],"version":os.environ["STAGE_VERSION"],"sha256":os.environ["STAGE_SHA"],"arch":os.environ["STAGE_ARCH"],"work_dir":os.environ["STAGE_DIR"],"observed_version":os.environ["STAGE_OBSERVED"],"reused":os.environ["STAGE_REUSED"]=="true"},sort_keys=True))'
}

consume_opaque_input() {
  local path="$1"
  [[ -f "$path" ]] || { echo "opaque input is not a regular file" >&2; return 2; }
  local mode
  mode="$(stat -c '%a' "$path")"
  # Only owner bits may be set. 0400/0600 are the normal cases.
  if (( (8#$mode & 077) != 0 )); then
    echo "opaque input permissions expose group/other bits" >&2
    return 2
  fi
  # Deliberately read without printing, hashing, sizing, or otherwise disclosing content.
  cat "$path" >/dev/null
  printf '{"contract":"%s","opaque_input_present":true,"permissions":"%s"}\n' "$CONTRACT_VERSION" "$mode"
}

sanitize_input() {
  local path="$1"
  local base
  base="$(basename "$path")"
  [[ "$base" == .runner-jit-* ]] || {
    echo "refusing to remove non-runner-jit path" >&2
    return 2
  }
  rm -f -- "$path"
  [[ ! -e "$path" ]]
  printf '{"contract":"%s","opaque_input_absent":true}\n' "$CONTRACT_VERSION"
}

main() {
  [[ $# -ge 1 ]] || { usage; return 2; }
  local cmd="$1"; shift
  case "$cmd" in
    contract) contract "$@" ;;
    preflight) preflight "$@" ;;
    plan) plan "$@" ;;
    stage) stage "$@" ;;
    consume-opaque-input) [[ $# -eq 1 ]] || return 2; consume_opaque_input "$1" ;;
    sanitize-input) [[ $# -eq 1 ]] || return 2; sanitize_input "$1" ;;
    -h|--help|help) usage ;;
    *) echo "unknown command: $cmd" >&2; usage >&2; return 2 ;;
  esac
}

main "$@"
