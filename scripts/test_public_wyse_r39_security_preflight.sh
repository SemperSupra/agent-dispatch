#!/usr/bin/env bash
# R39 offline, side-effect-free security admission negatives.
# Run entirely in a disposable temp cwd. No QEMU, sudo, host disks or keys.
set -Eeuo pipefail
ROOT=${GITHUB_WORKSPACE:-$PWD}
SCRIPT="$ROOT/scripts/public_wyse_r25_buildroot_uki_ssh.sh"
test -s "$SCRIPT"
bash -n "$SCRIPT"
T=$(mktemp -d)
trap 'rm -rf -- "$T"' EXIT

must_refuse() {
  local label=$1 expected_code=$2 expected_reason=$3
  shift 3
  local code=0
  (cd "$T" && env "$@" bash "$SCRIPT") > "$T/output" 2>&1 || code=$?
  if test "$code" -ne "$expected_code" ||
      ! grep -Fxq "$expected_reason" "$T/output"; then
    echo "R39_SECURITY_EXPECTED_DENIAL_MISSING:$label:actual=$code" >&2
    cat "$T/output" >&2
    exit 1
  fi
  # No evidence, host disk images, QEMU, mkdir, signing, SSH, or firmware access
  # is permitted for any refused configuration.
  if test -e "$T/evidence"; then
    echo "R39_SECURITY_SIDE_EFFECT_BEFORE_REFUSAL:$label" >&2
    exit 1
  fi
  echo "R39_SECURITY_DENIAL_${label}=PASS"
}
must_refuse F0_NO_SATA 59 R39_F0_REQUIRES_SATA=FAIL_CLOSED \
  WYSE_R32_ASSERT_BUS_TOPOLOGY=1 WYSE_R30_NO_SATA=1
must_refuse F2_NO_SATA 60 R39_F2_REQUIRES_SATA=FAIL_CLOSED \
  WYSE_R32_NO_EMMC=1 WYSE_R30_NO_SATA=1
must_refuse F0_UNSIGNED_DEFAULTS 61 R39_INCOMPLETE_SIGNED_RECOVERY_CHAIN=FAIL_CLOSED \
  WYSE_R32_ASSERT_BUS_TOPOLOGY=1
must_refuse F2_UNSIGNED_NEGATIVE_OMITTED 61 R39_INCOMPLETE_SIGNED_RECOVERY_CHAIN=FAIL_CLOSED \
  WYSE_R32_NO_EMMC=1 WYSE_R23_SIGNED_EFI=1 WYSE_R23_UKI=1 \
  WYSE_R23_ENFORCE_SB=1 WYSE_R23_FIRMWARE_UNSIGNED_NEGATIVE=0
must_refuse K2B_MISSING_OWNED_INPUTS 62 R39_MISSING_SOURCE_OWNED_RECOVERY_INPUT=FAIL_CLOSED \
  WYSE_R34_EMMC_SIGNED_BOOT=1 WYSE_R30_NO_SATA=1 \
  WYSE_R23_SIGNED_EFI=1 WYSE_R23_UKI=1 WYSE_R23_ENFORCE_SB=1 \
  WYSE_R23_FIRMWARE_UNSIGNED_NEGATIVE=1
must_refuse F3_PARTIAL_OWNED_INPUTS 62 R39_MISSING_SOURCE_OWNED_RECOVERY_INPUT=FAIL_CLOSED \
  WYSE_R32_FIRMWARE_TAMPERED_NEGATIVE=1 WYSE_R30_NO_SATA=1 \
  WYSE_R23_SIGNED_EFI=1 WYSE_R23_UKI=1 WYSE_R23_ENFORCE_SB=1 \
  WYSE_R23_FIRMWARE_UNSIGNED_NEGATIVE=1 WYSE_R29_OWNED_KERNEL_BZIMAGE=/tmp/synthetic-fixture
echo R39_SIX_ADDITIONAL_SECURITY_ADMISSION_NEGATIVES=PASS
