#!/usr/bin/env bash
# R39 public-only source-owned UKI byte reproducibility experiment.
# Separate original Linux/Buildroot inputs, UKI assembly and ephemeral CI signing.
# No owner keys, media writes, production signing, or physical eMMC.
set -Eeuo pipefail
umask 077
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1577836800
test -n "${RUNNER_TEMP:-}"
test -n "${GITHUB_SHA:-}"
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
test -n "${R39_REPLICA:-}"
case "$R39_REPLICA" in alpha|beta) ;; *) echo R39_REPLICA_INVALID=FAIL_CLOSED; exit 3;; esac
K="$RUNNER_TEMP/wyse-r28-owned-kernel/out/images/bzImage"
I="$RUNNER_TEMP/wyse-r28-owned-kernel/out/images/rootfs.cpio"
test -s "$K" && test -s "$I"
W=$(mktemp -d "$RUNNER_TEMP/wyse-r39-uki-XXXXXX")
trap 'rm -rf -- "$W"' EXIT
mkdir -p evidence/public
# Frozen source-owned R38 qualified kernel and CPIO anchors.
K_SHA=$(sha256sum "$K" | cut -d' ' -f1)
I_SHA=$(sha256sum "$I" | cut -d' ' -f1)
test "$K_SHA" = d51edcfc59aafabd11e7eb39bf1a5630bbfb3480c8bf7a2f25606d21121cc5ac ||
  { echo R39_KERNEL_SOURCE_ANCHOR_DRIFT=RED; exit 11; }
test "$I_SHA" = 4023a48f55908bd4b9b3df3e0df4e6f2249f64812debc8f2f19a2896bcc0be81 ||
  { echo R39_BUILDROOT_SOURCE_ANCHOR_DRIFT=RED; exit 12; }
if command -v ukify >/dev/null 2>&1; then UKIFY=$(command -v ukify); else UKIFY=/usr/lib/systemd/ukify; fi
test -x "$UKIFY"
for n in A B; do
  "$UKIFY" build --linux="$K" --initrd="$I" \
    --cmdline="console=ttyS0 rdinit=/init panic=2" \
    --output="$W/unsigned-$n.efi" > "$W/ukify-$n.log" 2>&1
  "$UKIFY" inspect "$W/unsigned-$n.efi" > "$W/inspect-$n.txt" 2>&1
  for sec in .linux .initrd .cmdline; do
    grep -Fq "$sec" "$W/inspect-$n.txt" || { echo "R39_UKI_STRUCTURAL_SECTION_MISSING:$sec"; exit 13; }
  done
done
# Explicit independent unsigned UKI comparisons in the same controlled runner.
U1=$(sha256sum "$W/unsigned-A.efi" | cut -d' ' -f1)
U2=$(sha256sum "$W/unsigned-B.efi" | cut -d' ' -f1)
if cmp -s "$W/unsigned-A.efi" "$W/unsigned-B.efi"; then
  U_EQUAL=YES
else
  U_EQUAL=NO
fi
# One fresh CI test identity, never a real owner key. Keys and EFI bytes remain
# within disposable runner temp and never enter public text artifacts.
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 1 \
  -subj '/CN=Wyse R39 public disposable signing test only' \
  -keyout "$W/test-only.key" -out "$W/test-only.crt" > "$W/keygen.log" 2>&1
chmod 600 "$W/test-only.key"
for n in A B; do
  sbsign --key "$W/test-only.key" --cert "$W/test-only.crt" \
    --output "$W/signed-$n.efi" "$W/unsigned-A.efi" > "$W/sbsign-$n.log" 2>&1
  sbverify --cert "$W/test-only.crt" "$W/signed-$n.efi" > "$W/verify-$n.log" 2>&1
  # Deliberately cross a wall-clock boundary. Same-second Authenticode
  # timestamps could otherwise masquerade as signing reproducibility.
  if test "$n" = A; then sleep 2; fi
done
S1=$(sha256sum "$W/signed-A.efi" | cut -d' ' -f1)
S2=$(sha256sum "$W/signed-B.efi" | cut -d' ' -f1)
if cmp -s "$W/signed-A.efi" "$W/signed-B.efi"; then
  S_EQUAL=YES
else
  S_EQUAL=NO
fi
CERT_FP=$(openssl x509 -in "$W/test-only.crt" -fingerprint -sha256 -noout | cut -d= -f2 | tr -d :)
cat > "evidence/public/r39-uki-${R39_REPLICA}.txt" <<REPORT
R39_REPLICA=$R39_REPLICA
R39_KERNEL_SHA256=$K_SHA
R39_CPIO_SHA256=$I_SHA
R39_UNSIGNED_UKI_A_SHA256=$U1
R39_UNSIGNED_UKI_B_SHA256=$U2
R39_UNSIGNED_TWO_BUILDS_EQUAL=$U_EQUAL
R39_SIGNED_UKI_A_SHA256=$S1
R39_SIGNED_UKI_B_SHA256=$S2
R39_SIGNED_SAME_EPHEMERAL_KEY_EQUAL=$S_EQUAL
R39_EPHEMERAL_CERT_SHA256=$CERT_FP
R39_OWNER_SIGNER_AND_PHYSICAL_MEDIA=NOT_TESTED
REPORT
echo "R39_UKI_STRUCTURAL_AND_SBSIGN_VERIFY=PASS"
echo "R39_UNSIGNED_SAME_RUN_BYTES_EQUAL=$U_EQUAL"
echo "R39_SIGNED_SAME_RUN_BYTES_EQUAL=$S_EQUAL"
echo "R39_UKI_PUBLIC_TEXT_ONLY_RECEIPT=PASS"
