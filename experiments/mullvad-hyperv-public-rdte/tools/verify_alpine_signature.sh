#!/usr/bin/env bash
# Fixed, public-safe Alpine ISO supply-chain check. No VM/network configuration.
# Temporary downloaded input is deleted on EXIT; never published as artifact.
set -euo pipefail
export LC_ALL=C

iso="alpine-virt-3.24.2-x86_64.iso"
base="https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64"
expected_sha256="3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b"
expected_fingerprint="0482D84022F52DF1C4E7CD43293ACD0907D9495A"
expected_bytes=69206016

for tool in curl sha256sum gpg stat awk grep mktemp; do
  command -v "$tool" >/dev/null || { echo "missing public verification tool"; exit 1; }
done

dir="$(mktemp -d)"
chmod 700 "$dir"
trap 'rm -rf -- "$dir"' EXIT
mkdir -m 700 "$dir/gpg"

# Fixed HTTPS Alpine CDN assets + official Alpine signing key, no user-provided URLs.
curl -fsS --proto '=https' --connect-timeout 10 --max-time 120 \
  --max-filesize 128000000 "$base/$iso" -o "$dir/$iso"
curl -fsS --proto '=https' --connect-timeout 10 --max-time 30 \
  "$base/$iso.sha256" -o "$dir/$iso.sha256"
curl -fsS --proto '=https' --connect-timeout 10 --max-time 30 \
  "$base/$iso.asc" -o "$dir/$iso.asc"
curl -fsS --proto '=https' --connect-timeout 10 --max-time 30 \
  "https://alpinelinux.org/keys/ncopa.asc" -o "$dir/ncopa.asc"

actual_bytes="$(stat -c '%s' "$dir/$iso")"
test "$actual_bytes" = "$expected_bytes" || { echo "ISO size mismatch"; exit 1; }
listed_sha="$(awk 'NR==1 { print $1 }' "$dir/$iso.sha256")"
test "$listed_sha" = "$expected_sha256" || { echo "checksum manifest differs from pinned digest"; exit 1; }
(
  cd "$dir"
  sha256sum -c -- "$iso.sha256" >/dev/null
)

gpg --homedir "$dir/gpg" --batch --quiet --import "$dir/ncopa.asc"
gpg --homedir "$dir/gpg" --batch --with-colons --fingerprint |
  awk -F: '$1=="fpr" { print $10 }' |
  grep -Fxq "$expected_fingerprint" || { echo "official key fingerprint mismatch"; exit 1; }

gpg --homedir "$dir/gpg" --batch --verify "$dir/$iso.asc" "$dir/$iso" >/dev/null 2>&1 ||
  { echo "detached Alpine ISO signature verification failed"; exit 1; }

printf 'EVIDENCE_CLASS=PUBLIC_ALPINE_PINNED_SHA256_AND_GPG_VERIFIED\n'
printf 'IMAGE_NAME=%s\nIMAGE_SHA256=%s\nIMAGE_BYTES=%s\nGPG_KEY_FINGERPRINT=%s\n' \
  "$iso" "$expected_sha256" "$actual_bytes" "$expected_fingerprint"
printf 'VM_BOOT=NOT_RUN\nGUEST_NETWORK=NOT_RUN\nISO_ARTIFACT_RETAINED=false\n'
