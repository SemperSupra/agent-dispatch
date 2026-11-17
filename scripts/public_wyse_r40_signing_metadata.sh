#!/usr/bin/env bash
# R40 public synthetic EFI signature metadata investigation.
# Deterministic GRUB EFI, disposable signer, no Linux build or physical media.
# All key / EFI / signature bytes remain in ephemeral runner temp.
set -Eeuo pipefail
umask 077
export TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=1577836800
test -n "$RUNNER_TEMP" && test -n "$GITHUB_SHA"
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
W=$(mktemp -d "$RUNNER_TEMP/wyse-r40-signing-XXXXXX")
trap 'rm -rf -- "$W"' EXIT
mkdir -p evidence/public
cat > "$W/grub.cfg" <<'GRUB'
serial --unit=0 --speed=115200
terminal_input console serial
terminal_output console serial
echo R40_SYNTHETIC_EFI_ONLY=PASS
halt
GRUB
grub-mkstandalone -O x86_64-efi -o "$W/unsigned.efi" \
  --modules="part_gpt fat serial terminal echo" \
  "boot/grub/grub.cfg=$W/grub.cfg" > "$W/grub-build.log" 2>&1
test -s "$W/unsigned.efi"
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 1 \
  -subj '/CN=Wyse R40 ephemeral CI signer only' \
  -keyout "$W/temp.key" -out "$W/temp.crt" > "$W/openssl.log" 2>&1
chmod 0600 "$W/temp.key"
# Three signatures using the SAME disposable key + the SAME PE input.
# A and B adjacent; C deliberately separated from B to assess metadata.
for n in A B C; do
  sbsign --key "$W/temp.key" --cert "$W/temp.crt" \
    --output "$W/signed-$n.efi" "$W/unsigned.efi" > "$W/sign-$n.log" 2>&1
  sbverify --cert "$W/temp.crt" "$W/signed-$n.efi" > "$W/verify-$n.log" 2>&1
  if command -v sbattach >/dev/null 2>&1; then
    sbattach --detach "$W/sig-$n.p7b" --image "$W/signed-$n.efi" > "$W/detach-$n.log" 2>&1 || :
  fi
  if test -s "$W/sig-$n.p7b"; then
    if openssl asn1parse -inform DER -in "$W/sig-$n.p7b" > "$W/asn1-$n.txt" 2>&1; then
      printf 'R40_ASN1_PARSE_%s=PASS\n' "$n"
    else
      printf 'R40_ASN1_PARSE_%s=INCONCLUSIVE\n' "$n"
    fi
  fi
  if test "$n" = B; then sleep 3; fi
done
unsigned_sha=$(sha256sum "$W/unsigned.efi" | cut -d' ' -f1)
cat > evidence/public/r40-signature-metadata.txt <<EOF
R40_INPUT_EFI_SHA256=$unsigned_sha
R40_SIGNATURES_VERIFY=PASS
R40_SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
R40_DISPOSABLE_SIGNER=YES
R40_SIGNED_A_SHA256=$(sha256sum "$W/signed-A.efi" | cut -d' ' -f1)
R40_SIGNED_B_SHA256=$(sha256sum "$W/signed-B.efi" | cut -d' ' -f1)
R40_SIGNED_C_SHA256=$(sha256sum "$W/signed-C.efi" | cut -d' ' -f1)
R40_OWNER_KEYS_HARDWARE_AND_MEDIA=NOT_TESTED
EOF
for n in A B C; do
  if test -s "$W/sig-$n.p7b"; then
    printf 'R40_DETACHED_%s_SHA256=%s\n' "$n" \
      "$(sha256sum "$W/sig-$n.p7b" | cut -d' ' -f1)" >> evidence/public/r40-signature-metadata.txt
  else
    printf 'R40_DETACHED_%s_SHA256=UNAVAILABLE\n' "$n" >> evidence/public/r40-signature-metadata.txt
  fi
  if test -s "$W/asn1-$n.txt"; then
    printf 'R40_SIGNING_TIME_OID_%s=%s\n' "$n" \
      "$(grep -ic 'signingTime' "$W/asn1-$n.txt" || :)" >> evidence/public/r40-signature-metadata.txt
    printf 'R40_DER_TIME_NODES_%s=%s\n' "$n" \
      "$(grep -Ec 'UTCTIME|GENERALIZEDTIME' "$W/asn1-$n.txt" || :)" >> evidence/public/r40-signature-metadata.txt
  else
    printf 'R40_SIGNING_TIME_OID_%s=UNKNOWN\n' "$n" >> evidence/public/r40-signature-metadata.txt
    printf 'R40_DER_TIME_NODES_%s=UNKNOWN\n' "$n" >> evidence/public/r40-signature-metadata.txt
  fi
done
if cmp -s "$W/signed-A.efi" "$W/signed-B.efi"; then
  echo R40_ADJACENT_SIGNED_BYTES_EQUAL=YES >> evidence/public/r40-signature-metadata.txt
else
  echo R40_ADJACENT_SIGNED_BYTES_EQUAL=NO >> evidence/public/r40-signature-metadata.txt
fi
if cmp -s "$W/signed-B.efi" "$W/signed-C.efi"; then
  echo R40_TIME_SEPARATED_SIGNED_BYTES_EQUAL=YES >> evidence/public/r40-signature-metadata.txt
else
  echo R40_TIME_SEPARATED_SIGNED_BYTES_EQUAL=NO >> evidence/public/r40-signature-metadata.txt
fi
# Diagnostic succeeds for either YES or NO. Never convert verified-signature
# into the stronger bytewise reproduction claim.
grep -Fxq R40_SIGNATURES_VERIFY=PASS evidence/public/r40-signature-metadata.txt
test "$(grep -c '^R40_SIGNED_[ABC]_SHA256=' evidence/public/r40-signature-metadata.txt)" -eq 3
echo R40_DISPOSABLE_EFI_SIGNING_METADATA_EXPERIMENT=PASS
echo R40_PRODUCTION_SIGNED_BYTE_REPRODUCIBILITY=NOT_TESTED
