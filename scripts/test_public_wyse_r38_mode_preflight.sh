#!/usr/bin/env bash
# R38 fail-closed preflight: NO QEMU, media, tools or hardware access.
set -Eeuo pipefail
ROOT=${GITHUB_WORKSPACE:-$PWD}
SCRIPT="$ROOT/scripts/public_wyse_r25_buildroot_uki_ssh.sh"
test -s "$SCRIPT"
bash -n "$SCRIPT"
T=$(mktemp -d)
trap 'rm -rf -- "$T"' EXIT
must_refuse() {
  local label=$1 want_code=$2 want_marker=$3
  shift 3
  set +e
  (cd "$T" && env "$@" bash "$SCRIPT") > "$T/result" 2>&1
  got=$?
  set -e
  if test "$got" -ne "$want_code"; then
    echo "R38_FAIL_OPEN_WRONG_EXIT:$label:$got" >&2
    cat "$T/result" >&2
    exit 1
  fi
  if ! grep -Fxq "$want_marker" "$T/result"; then
    echo "R38_MISSING_DENIAL_REASON:$label" >&2
    cat "$T/result" >&2
    exit 1
  fi
  # If a preflight reaches images, evidence dirs or QEMU it has failed open.
  if test -d "$T/evidence"; then
    echo "R38_PREFLIGHT_ACTUATOR_REACHED:$label" >&2
    exit 1
  fi
  echo "R38_DENIAL_${label}=PASS"
}
must_refuse F0_F2_CONFLICT 56 R38_CONFLICTING_RECOVERY_MODES=FAIL_CLOSED \
  WYSE_R32_ASSERT_BUS_TOPOLOGY=1 WYSE_R32_NO_EMMC=1
must_refuse F0_K2B_CONFLICT 56 R38_CONFLICTING_RECOVERY_MODES=FAIL_CLOSED \
  WYSE_R32_ASSERT_BUS_TOPOLOGY=1 WYSE_R34_EMMC_SIGNED_BOOT=1
must_refuse F3_K2B_CONFLICT 56 R38_CONFLICTING_RECOVERY_MODES=FAIL_CLOSED \
  WYSE_R32_FIRMWARE_TAMPERED_NEGATIVE=1 WYSE_R34_EMMC_SIGNED_BOOT=1
must_refuse BAD_MODE_VALUE 55 R38_INVALID_MODE_VALUE=FAIL_CLOSED \
  WYSE_R32_ASSERT_BUS_TOPOLOGY=error
must_refuse BAD_SATA_VALUE 57 R38_INVALID_SATA_FAULT_VALUE=FAIL_CLOSED \
  WYSE_R30_NO_SATA=bogus
must_refuse F3_WITHOUT_NO_SATA 58 R38_TAMPERED_MODE_REQUIRES_F1=FAIL_CLOSED \
  WYSE_R32_FIRMWARE_TAMPERED_NEGATIVE=1 WYSE_R30_NO_SATA=0
echo R38_INTEGRATED_MODE_PRECHECK_AND_ISOLATION=PASS
