#!/usr/bin/env bash
set -euo pipefail
mode="${1:---check-only}"
pkgs=(curl unzip zstd qemu-system-x86 qemu-utils python3 jq)
check() {
  local missing=()
  for c in curl unzip zstd qemu-system-x86_64 qemu-img python3 jq; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  printf '{"schema":"wrt-hil-host-linux-check/v1","mode":"%s","missing":[' "$mode"
  local sep=""
  for x in "${missing[@]}"; do printf '%s"%s"' "$sep" "$x"; sep=,; done
  printf ']}
'
  [ "${#missing[@]}" -eq 0 ]
}
case "$mode" in
  --install)
    if command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update -qq
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" >/dev/null
    else
      echo "unsupported package manager" >&2; exit 2
    fi
    check
    ;;
  --check-only) check ;;
  *) echo "usage: $0 [--check-only|--install]" >&2; exit 2 ;;
esac
