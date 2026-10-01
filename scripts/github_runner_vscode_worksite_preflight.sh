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

status_output="$(code tunnel --cli-data-dir "$VSCODE_CLI_DATA_DIR" status 2>&1 || true)"
status_eval="$(
  printf '%s\n' "$status_output" | python3 -c '
import json
import sys

value = None
for raw in sys.stdin:
    line = raw.strip()
    if not (line.startswith("{") and line.endswith("}")):
        continue
    try:
        candidate = json.loads(line)
    except json.JSONDecodeError:
        continue
    if isinstance(candidate, dict) and "tunnel" in candidate:
        value = candidate

if value is None:
    print("false false unknown")
else:
    print(
        "true",
        str(value.get("tunnel") is None).lower(),
        str(bool(value.get("service_installed", False))).lower(),
    )
'
)"
read -r status_json_present status_no_running status_service_installed <<<"$status_eval"

set +e
code tunnel --cli-data-dir "$VSCODE_CLI_DATA_DIR" unregister >/dev/null 2>&1
clean_unregister_exit=$?
set -e

post_unregister_output="$(code tunnel --cli-data-dir "$VSCODE_CLI_DATA_DIR" status 2>&1 || true)"
post_unregister_eval="$(
  printf '%s\n' "$post_unregister_output" | python3 -c '
import json
import sys

value = None
for raw in sys.stdin:
    line = raw.strip()
    if not (line.startswith("{") and line.endswith("}")):
        continue
    try:
        candidate = json.loads(line)
    except json.JSONDecodeError:
        continue
    if isinstance(candidate, dict) and "tunnel" in candidate:
        value = candidate

clean = (
    isinstance(value, dict)
    and value.get("tunnel") is None
    and value.get("service_installed", False) is False
)
print(str(clean).lower())
'
)"

oracle=true
for required in   "$provider_flag"   "$access_token_flag"   "$name_flag"   "$no_sleep_flag"   "$license_flag"; do
  if [[ "$required" != true ]]; then
    oracle=false
  fi
done
if [[ "$vscode_status" == unreachable || "$relay_status" == unreachable ]]; then
  oracle=false
fi
if [[ "$status_json_present" != true || "$status_no_running" != true ]]; then
  oracle=false
fi
if [[ "$status_service_installed" != false ]]; then
  oracle=false
fi
if (( clean_unregister_exit != 0 )) || [[ "$post_unregister_eval" != true ]]; then
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
  printf 'tunnel_status_json_present=%s\n' "$status_json_present"
  printf 'tunnel_status_no_running=%s\n' "$status_no_running"
  printf 'tunnel_status_service_installed=%s\n' "$status_service_installed"
  printf 'clean_unregister_exit=%s\n' "$clean_unregister_exit"
  printf 'post_unregister_status_clean=%s\n' "$post_unregister_eval"
  printf 'vscode_dev_http_status=%s\n' "$vscode_status"
  printf 'relay_http_status=%s\n' "$relay_status"
  printf 'interactive_login_attempted=false\n'
  printf 'credential_material_recorded=false\n'
} | tee "$RECEIPT_PATH"

[[ "$oracle" == true ]] || fail "pre-authentication worksite oracle was not satisfied"
