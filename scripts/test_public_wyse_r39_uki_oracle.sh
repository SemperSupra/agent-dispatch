#!/usr/bin/env bash
# Offline syntax/schema/fault unit tests: NO kernel build, QEMU or credentials.
set -Eeuo pipefail
ROOT=${GITHUB_WORKSPACE:-$PWD}
ORACLE="$ROOT/scripts/compare_public_wyse_r39_uki_receipts.sh"
test -s "$ORACLE"; bash -n "$ORACLE"
T=$(mktemp -d)
trap 'rm -rf -- "$T"' EXIT
h0=$(printf '%064d' 0)
h1=$(printf '%064d' 1)
certA=$(printf 'A%.0s' {1..64})
certB=$(printf 'B%.0s' {1..64})
write_manifest() {
  local name=$1 cert=$2
  cat > "$T/$name.txt" <<EOF
R39_REPLICA=$name
R39_KERNEL_SHA256=$h0
R39_CPIO_SHA256=$h0
R39_UNSIGNED_UKI_A_SHA256=$h0
R39_UNSIGNED_UKI_B_SHA256=$h0
R39_UNSIGNED_TWO_BUILDS_EQUAL=YES
R39_SIGNED_UKI_A_SHA256=$h0
R39_SIGNED_UKI_B_SHA256=$h0
R39_SIGNED_SAME_EPHEMERAL_KEY_EQUAL=YES
R39_EPHEMERAL_CERT_SHA256=$cert
R39_OWNER_SIGNER_AND_PHYSICAL_MEDIA=NOT_TESTED
EOF
}
write_manifest alpha "$certA"
write_manifest beta "$certB"
bash "$ORACLE" "$T/alpha.txt" "$T/beta.txt" | grep -Fxq R39_CROSS_RUN_SOURCE_OWNED_UNSIGNED_UKI_BYTE_REPRO=PASS
echo R39_MANIFEST_VALID_PAIR=PASS
must_fail() {
  local label=$1 want=$2 got=0
  bash "$ORACLE" "$T/alpha.txt" "$T/beta.txt" > "$T/output" 2>&1 || got=$?
  test "$got" -eq "$want" ||
    { echo "R39_ORACLE_FAILED_TO_REFUSE:$label:expected=$want:actual=$got"; cat "$T/output"; exit 1; }
  echo "R39_MANIFEST_DENIAL_$label=PASS"
}
sed -i "s/R39_UNSIGNED_UKI_A_SHA256=$h0/R39_UNSIGNED_UKI_A_SHA256=$h1/" "$T/beta.txt"
must_fail UNSIGNED_DRIFT 29
write_manifest beta "$certB"
sed -i 's/R39_SIGNED_SAME_EPHEMERAL_KEY_EQUAL=YES/R39_SIGNED_SAME_EPHEMERAL_KEY_EQUAL=NO/' "$T/beta.txt"
must_fail NONDETERMINISTIC_SIGNER 31
write_manifest beta "$certB"
sed -i 's/R39_OWNER_SIGNER_AND_PHYSICAL_MEDIA=NOT_TESTED/R39_OWNER_SIGNER_AND_PHYSICAL_MEDIA=PASS/' "$T/beta.txt"
must_fail FALSE_PRODUCTION_CLAIM 27
write_manifest beta "$certB"
sed -i '$d' "$T/beta.txt"
must_fail MISSING_LINE 21
write_manifest beta "$certB"
sed -i 's/R39_REPLICA=beta/R39_REPLICA=alpha/' "$T/beta.txt"
must_fail MISASSOCIATED 28
write_manifest beta "$certB"
sed -i "s/R39_EPHEMERAL_CERT_SHA256=$certB/R39_EPHEMERAL_CERT_SHA256=$certA/" "$T/beta.txt"
must_fail SHARED_SIGNER_NOT_PROVEN 32
echo R39_OFFLINE_MANIFEST_ORACLE_REGRESSIONS=PASS
