#!/usr/bin/env bash
set -euo pipefail

# Credential-free qualification for a GitHub-hosted runner that may later host
# a VS Code Remote Tunnel. This script never attempts user login.

: "${VSCODE_CLI_INSTALL_DIR:=${RUNNER_TEMP:-/tmp}/vscode-cli}"
: "${VSCODE_CLI_DATA_DIR:=${RUNNER_TEMP:-/tmp}/vscode-cli-data}"
: "${RECEIPT_PATH:=${RUNNER_TEMP:-/tmp}/vscode-worksite-preflight.txt}"

fail() {
  printf 'WORKSITE_PREFLIGHT_FAIL: %s\n' "$*" >&2
  exit 2
}

install_cli() {
  mkdir -p "$VSCODE_CLI_INSTALL_DIR" "$VSCODE_CLI_DATA_DIR"
  local arch os tarball
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) os="cli-alpine-x64" ;;
    aarch64|arm64) os="cli-alpine-arm64" ;;
    *) fail "unsupported architecture: $arch" ;;
  esac

  if [[ ! -x "$VSCODE_CLI_INSTALL_DIR/code" ]]; then
    tarball="$VSCODE_CLI_INSTALL_DIR/vscode_cli.tar.gz"
    curl       --fail       --location       --silent       --show-error       "https://code.visualstudio.com/sha/download?build=stable&os=${os}"       --output "$tarball"
    tar -xzf "$tarball" -C "$VSCODE_CLI_INSTALL_DIR"
    rm -f "$tarball"
  fi
  export PATH="$VSCODE_CLI_INSTALL_DIR:$PATH"
}

contains_flag() {
  local body="$1"
  local flag="$2"
  if grep -q -- "$flag" <<<"$body"; then
    printf 'true'
  else
    printf 'false'
  fi
}

probe_url() {
  local url="$1"
  local code
  if ! code="$(
    curl       --location       --silent       --show-error       --output /dev/null       --connect-timeout 10       --max-time 15       --write-out '%{http_code}'       "$url"
  )"; then
    printf 'unreachable'
    return
  fi
  printf '%s' "$code"
}

install_cli

version="$(code --version | head -n 1)"
login_help="$(code tunnel --cli-data-dir "$VSCODE_CLI_DATA_DIR" user login --help 2>&1)"
tunnel_help="$(code tunnel --cli-data-dir "$VSCODE_CLI_DATA_DIR" --help 2>&1)"
vscode_status="$(probe_url https://vscode.dev/)"
relay_status="$(probe_url https://global.rel.tunnels.api.visualstudio.com/)"

provider_flag="$(contains_flag "$login_help" '--provider')"
access_token_flag="$(contains_flag "$login_help" '--access-token')"
refresh_token_flag="$(contains_flag "$login_help" '--refresh-token')"
name_flag="$(contains_flag "$tunnel_help" '--name')"
no_sleep_flag="$(contains_flag "$tunnel_help" '--no-sleep')"
license_flag="$(contains_flag "$tunnel_help" '--accept-server-license-terms')"
install_extension_flag="$(contains_flag "$tunnel_help" '--install-extension')"

oracle=true
for required in   "$provider_flag"   "$access_token_flag"   "$name_flag"   "$no_sleep_flag"   "$license_flag"; do
  if [[ "$required" != true ]]; then
    oracle=false
  fi
done
if [[ "$vscode_status" == unreachable || "$relay_status" == unreachable ]]; then
  oracle=false
fi

mkdir -p "$(dirname "$RECEIPT_PATH")"
{
  printf 'schema=github-runner-vscode-worksite-preflight/v1\n'
  printf 'classification=%s\n'     "$([[ "$oracle" == true ]] && printf PREAUTH_SUPPORTED || printf PREAUTH_UNSUPPORTED)"
  printf 'oracleSatisfied=%s\n' "$oracle"
  printf 'vscode_cli_version=%s\n' "$version"
  printf 'login_provider_flag=%s\n' "$provider_flag"
  printf 'login_access_token_flag=%s\n' "$access_token_flag"
  printf 'login_refresh_token_flag=%s\n' "$refresh_token_flag"
  printf 'tunnel_name_flag=%s\n' "$name_flag"
  printf 'tunnel_no_sleep_flag=%s\n' "$no_sleep_flag"
  printf 'tunnel_accept_license_flag=%s\n' "$license_flag"
  printf 'tunnel_install_extension_flag=%s\n' "$install_extension_flag"
  printf 'vscode_dev_http_status=%s\n' "$vscode_status"
  printf 'relay_http_status=%s\n' "$relay_status"
  printf 'interactive_login_attempted=false\n'
  printf 'credential_material_recorded=false\n'
} | tee "$RECEIPT_PATH"

[[ "$oracle" == true ]] || fail "pre-authentication worksite oracle was not satisfied"
