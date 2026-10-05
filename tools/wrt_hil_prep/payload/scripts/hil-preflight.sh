#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-bundle.sh"
DUT_A="${1:-}"
DUT_B="${2:-}"

bundle_ok=false
if [ -f "$ROOT/metadata/SHA256SUMS" ] && "$VERIFY" >/tmp/wrt-hil-verify.out 2>/tmp/wrt-hil-verify.err; then
  bundle_ok=true
fi

serial_json='[]'
for dev in /dev/ttyUSB* /dev/ttyACM*; do
  [ -e "$dev" ] || continue
  serial_json="$(printf '%s\n' "$serial_json" | jq --arg d "$dev" '. + [$d]')"
done

check_dut() {
  target="$1"
  [ -n "$target" ] || { printf 'null'; return; }
  if ! command -v ssh >/dev/null 2>&1; then
    jq -n --arg t "$target" '{target:$t,ssh_reachable:false,r1_eligible:false,reason:"ssh missing"}'
    return
  fi
  out="$(ssh -o BatchMode=yes -o ConnectTimeout=4 "$target" "printf 'R1_SSH_OK\n'; (cat /tmp/sysinfo/board_name 2>/dev/null || true)" 2>&1 || true)"
  if printf '%s' "$out" | grep -q 'R1_SSH_OK'; then
    eligible="$bundle_ok"
    jq -n --arg t "$target" --arg obs "$out" --argjson e "$eligible" '{target:$t,ssh_reachable:true,r1_eligible:$e,observation:$obs,next_action:("scripts/r1-readonly-remote.sh " + $t)}'
  else
    jq -n --arg t "$target" --arg obs "$out" '{target:$t,ssh_reachable:false,r1_eligible:false,observation:$obs,next_action:"DO_NOT_FLASH; resolve access/identity first"}'
  fi
}

a="$(check_dut "$DUT_A")"
b="$(check_dut "$DUT_B")"
duts='[]'
[ "$a" = "null" ] || duts="$(printf '%s' "$duts" | jq --argjson x "$a" '. + [$x]')"
[ "$b" = "null" ] || duts="$(printf '%s' "$duts" | jq --argjson x "$b" '. + [$x]')"

jq -n --argjson bundle "$bundle_ok" --argjson serial "$serial_json" --argjson duts "$duts" '{"schema":"wrt-hil-arrival-preflight/v1","authority":"R1_READ_ONLY","bundle_verified":$bundle,"serial_devices":$serial,"serial_requirement":"3.3V TTL; 115200 8N1; GND/TX/RX only; no VCC","dut_checks":$duts,"prohibited":["fw_setenv","sysupgrade","package installation","UCI mutation","reboot/power-cycle experiments","MTD/UBI writes","bootloader writes"]}'
