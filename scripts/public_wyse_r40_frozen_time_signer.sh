#!/usr/bin/env bash
# R40b: Does a controlled clock make sbsign byte-reproducible with the same
# ephemeral signer and identical test EFI source? Public synthetic only.
set -Eeuo pipefail
umask 077
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1577836800
test -n "$RUNNER_TEMP" && test -n "$GITHUB_SHA"
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
W=$(mktemp -d "$RUNNER_TEMP/wyse-r40b-clock-XXXXXX")
trap 'rm -rf -- "$W"' EXIT
mkdir -p evidence/public
cat > "$W/grub.cfg" <<'GRUB'
serial --unit=0 --speed=115200
terminal_input console serial
terminal_output console serial
echo R40B_PUBLIC_SYNTHETIC_EFI=PASS
halt
GRUB
grub-mkstandalone -O x86_64-efi -o "$W/unsigned.efi" \
  --modules="part_gpt fat serial terminal echo" \
  "boot/grub/grub.cfg=$W/grub.cfg" > "$W/grub-build.log" 2>&1
test -s "$W/unsigned.efi"
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 1 \
  -subj '/CN=Wyse R40b disposable CI signer only' \
  -keyout "$W/temp.key" -out "$W/temp.crt" > "$W/keygen.log" 2>&1
chmod 0600 "$W/temp.key"
# The chosen clock is this job's actual certificate-valid time rounded to
# seconds, not SOURCE_DATE_EPOCH; it proves one-run control only.
FROZEN_SIGN_TIME=$(date -u '+%Y-%m-%d %H:%M:%S')
for n in A B; do
  faketime -f "$FROZEN_SIGN_TIME" \
    sbsign --key "$W/temp.key" --cert "$W/temp.crt" \
    --output "$W/signed-$n.efi" "$W/unsigned.efi" \
    > "$W/sign-$n.log" 2>&1
  sbverify --cert "$W/temp.crt" "$W/signed-$n.efi" \
    > "$W/verify-$n.log" 2>&1
  if test "$n" = A; then sleep 3; fi
done
A=$(sha256sum "$W/signed-A.efi" | cut -d' ' -f1)
B=$(sha256sum "$W/signed-B.efi" | cut -d' ' -f1)
SAME=NO
if cmp -s "$W/signed-A.efi" "$W/signed-B.efi"; then SAME=YES; fi
cat > evidence/public/r40b-frozen-signing.txt <<EOF
R40B_INPUT_SHA256=$(sha256sum "$W/unsigned.efi" | cut -d' ' -f1)
R40B_SIGNED_A_SHA256=$A
R40B_SIGNED_B_SHA256=$B
R40B_SIGNED_AFTER_3S_SAME_FROZEN_CLOCK_EQUAL=$SAME
R40B_WITHIN_RUN_CERT_VERIFY=PASS
R40B_FROZEN_TIME_UTC=$FROZEN_SIGN_TIME
R40B_CROSS_RUN_OWNER_SIGNING=NOT_TESTED
R40B_REAL_DELL_OVMF_MEDIA=NOT_TESTED
EOF
# Do not soften the byte-reproducibility assertion: the experiment itself
# returns RED when the frozen clock does not produce identical bytes.
if test "$SAME" != YES; then
  echo R40B_FROZEN_SIGNER_BYTE_REPRODUCIBILITY=RED
  exit 41
fi
echo R40B_FROZEN_SIGNER_WITHIN_RUN_BYTE_REPRODUCIBILITY=PASS
echo R40B_OWNER_SIGNER_AND_FIRMWARE=NOT_TESTED
