#!/usr/bin/env bash
# Compare two independent disposable runner receipts; never trust a green job
# without exact source/unsigned-byte concordance and a bounded evidence schema.
set -Eeuo pipefail
test "$#" -eq 2
A=$1 B=$2
for file in "$A" "$B"; do
  test -s "$file"
  test "$(wc -l < "$file")" -eq 11 || { echo R39_MANIFEST_LINE_COUNT=RED; exit 21; }
  if grep -Eq '[^A-Za-z0-9_=:]' "$file"; then
    echo R39_MANIFEST_UNSAFE_OR_UNKNOWN_CHARS=RED; exit 22
  fi
done
keys=(R39_REPLICA R39_KERNEL_SHA256 R39_CPIO_SHA256
  R39_UNSIGNED_UKI_A_SHA256 R39_UNSIGNED_UKI_B_SHA256
  R39_UNSIGNED_TWO_BUILDS_EQUAL R39_SIGNED_UKI_A_SHA256
  R39_SIGNED_UKI_B_SHA256 R39_SIGNED_SAME_EPHEMERAL_KEY_EQUAL
  R39_EPHEMERAL_CERT_SHA256 R39_OWNER_SIGNER_AND_PHYSICAL_MEDIA)
get() {
  local file=$1 key=$2 line
  line=$(grep -E "^$key=" "$file" || :)
  test "$(printf '%s\n' "$line" | grep -c . || :)" -eq 1 ||
    { echo "R39_MISSING_OR_DUPLICATE_KEY=$key"; exit 23; }
  printf '%s' "${line#*=}"
}
for file in "$A" "$B"; do
  for key in "${keys[@]}"; do
    val=$(get "$file" "$key")
    case "$key" in
      *_SHA256) [[ "$val" =~ ^[a-f0-9]{64}$ ]] ||
        { echo "R39_BAD_DIGEST=$key"; exit 24; } ;;
      R39_EPHEMERAL_CERT_SHA256) [[ "$val" =~ ^[A-F0-9]{64}$ ]] ||
        { echo R39_BAD_TEST_CERT_FP=RED; exit 24; } ;;
      R39_UNSIGNED_TWO_BUILDS_EQUAL|R39_SIGNED_SAME_EPHEMERAL_KEY_EQUAL)
        [[ "$val" == YES || "$val" == NO ]] || { echo R39_BAD_COMPARISON=RED; exit 25; } ;;
      R39_REPLICA) [[ "$val" == alpha || "$val" == beta ]] ||
        { echo R39_BAD_REPLICA=RED; exit 26; } ;;
      R39_OWNER_SIGNER_AND_PHYSICAL_MEDIA) test "$val" = NOT_TESTED ||
        { echo R39_FALSE_PRODUCTION_CLAIM=RED; exit 27; } ;;
    esac
  done
done
test "$(get "$A" R39_REPLICA)" = alpha &&
  test "$(get "$B" R39_REPLICA)" = beta ||
  { echo R39_REPLICA_MISASSOCIATED=RED; exit 28; }
for key in R39_KERNEL_SHA256 R39_CPIO_SHA256 R39_UNSIGNED_UKI_A_SHA256 R39_UNSIGNED_UKI_B_SHA256; do
  test "$(get "$A" "$key")" = "$(get "$B" "$key")" ||
    { echo "R39_CROSS_RUN_MISMATCH=$key"; exit 29; }
done
for file in "$A" "$B"; do
  test "$(get "$file" R39_UNSIGNED_TWO_BUILDS_EQUAL)" = YES ||
    { echo R39_UNSIGNED_SAME_RUN_NONDETERMINISTIC=RED; exit 30; }
  test "$(get "$file" R39_SIGNED_SAME_EPHEMERAL_KEY_EQUAL)" = YES ||
    { echo R39_SIGNED_SAME_RUN_NONDETERMINISTIC=RED; exit 31; }
done
# Different disposable signers => signed SHA across runners is NOT expected
# to match. Cert fingerprint is evidence of different trust roots, not PKI.
test "$(get "$A" R39_EPHEMERAL_CERT_SHA256)" != "$(get "$B" R39_EPHEMERAL_CERT_SHA256)" ||
  { echo R39_INDEPENDENT_EPHEMERAL_SIGNERS_NOT_PROVEN=RED; exit 32; }
echo R39_CROSS_RUN_SOURCE_OWNED_UNSIGNED_UKI_BYTE_REPRO=PASS
echo R39_TEST_SIGNER_WITHIN_RUN_BYTE_REPEAT=PASS
echo R39_INDEPENDENT_CI_KEYS_DISJOINT=PASS
echo R39_OWNER_SIGNER_CROSS_RUN_SIGNED_UKI_AND_PHYSICAL=NOT_TESTED
