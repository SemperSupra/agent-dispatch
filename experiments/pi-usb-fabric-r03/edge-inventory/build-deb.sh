#!/usr/bin/env bash
# Build a read-only package in caller-owned scratch. Never install/start/bind.
set -euo pipefail
test "$#" = 1
out="$1"
test -d "$out"
arch="$(dpkg --print-architecture)"
case "$arch" in arm64|amd64) ;; *) echo 'unsupported package architecture' >&2; exit 2;; esac
test "$(go env GOARCH)" = "$arch"
stage="$(mktemp -d "$out/edge-package-XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/share/doc/usb-edge-inventory"
CGO_ENABLED=0 go build -trimpath -o "$stage/usr/bin/usb-edge-inventory" .
install -m 0644 README.md "$stage/usr/share/doc/usb-edge-inventory/README.md"
cat >"$stage/DEBIAN/control" <<EOF
Package: usb-edge-inventory
Version: 0.0.1
Architecture: $arch
Maintainer: USB Edge contributors
Section: utils
Priority: optional
Description: Read-only USB Edge inventory, no device admission or export
EOF
dpkg-deb --root-owner-group --build "$stage" "$out/usb-edge-inventory_0.0.1_$arch.deb"
