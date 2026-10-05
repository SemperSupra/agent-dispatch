#!/usr/bin/env bash
set -euo pipefail
CP0_DIR="${1:?cp0 artifact directory required}"
E2_DIR="${2:?e2 artifact directory required}"
OUT="${3:?output directory required}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$RUNNER_TEMP/wrt-prehil"
rm -rf "$WORK"; mkdir -p "$WORK" "$OUT"

OPENWRT_VERSION=25.12.5
IB_NAME="openwrt-imagebuilder-${OPENWRT_VERSION}-x86-64.Linux-x86_64"
IB_ARCHIVE="$IB_NAME.tar.zst"
IB_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/x86/64/$IB_ARCHIVE"
IB_SHA="313221253d9bac534e4a4ee6492a4941b4ba0f43200eceb8d16a4785470ae9df"
E2_PRPL_SHA="ce91228d204b68cf37d0c46bf5f7492cfe3ac9d83463cb5d47cafb84197336d7"

echo "== host installer =="
"$ROOT/tools/wrt_hil_prequal/install-hil-host.sh" --install | tee "$OUT/linux-host-check.json"

echo "== build verified HIL prep kit =="
python3 "$ROOT/tools/wrt_hil_prep/build_kit.py" --output "$WORK/kit-dist" --cp0-dir "$CP0_DIR" | tee "$OUT/kit-build.json"
KIT="$WORK/kit-dist/wrt3200acm-hil-prep-kit-20261006"

echo "== acquire pinned imagebuilder =="
cd "$WORK"
curl -fL --retry 2 --connect-timeout 20 "$IB_URL" -o "$IB_ARCHIVE"
test "$(sha256sum "$IB_ARCHIVE" | awk '{print $1}')" = "$IB_SHA"
tar --use-compress-program=unzstd -xf "$IB_ARCHIVE"
IB="$WORK/$IB_NAME"

E2_PKG=$(find "$E2_DIR" -type f -name 'prplmesh-6.0.1-r1.apk' -print -quit)
test -n "$E2_PKG"
test "$(sha256sum "$E2_PKG" | awk '{print $1}')" = "$E2_PRPL_SHA"
mkdir -p "$IB/packages"; cp "$E2_PKG" "$IB/packages/"

echo "== render DUT configurations =="
python3 "$ROOT/tools/wrt_hil_prequal/generate_dut_overlays.py" "$WORK/overlays" | tee "$OUT/config-render.json"
find "$WORK/overlays" -type f -print0 | sort -z | xargs -0 sha256sum > "$OUT/config-sha256.txt"

build_image() {
  local name="$1" overlay="$2" packages="$3" partsize="${4:-160}"
  rm -rf "$IB/bin/targets/x86/64"/*
  ( cd "$IB" && make image PROFILE=generic PACKAGES="$packages" FILES="$overlay" ROOTFS_PARTSIZE="$partsize" > "$OUT/build-$name.log" 2>&1 )
  local img
  img=$(find "$IB/bin/targets/x86/64" -type f -name '*generic-ext4-combined.img.gz' -print -quit)
  test -n "$img"
  cp "$img" "$OUT/$name.img.gz"
  sha256sum "$OUT/$name.img.gz" >> "$OUT/images-sha256.txt"
}

echo "== build HIL-host USB image =="
USB_OV="$WORK/usb-overlay"
mkdir -p "$USB_OV/opt/wrt-hil" "$USB_OV/etc"
cp -a "$KIT" "$USB_OV/opt/wrt-hil/kit"
cat > "$USB_OV/etc/rc.local" <<'EOF'
#!/bin/sh
(
  sleep 8
  echo WRT_HIL_USB_READY=1 > /dev/ttyS0
  cd /opt/wrt-hil/kit || exit 1
  if sha256sum -c metadata/SHA256SUMS >/tmp/wrt-hil-verify.log 2>&1; then
    echo WRT_HIL_USB_MANIFEST_OK=1 > /dev/ttyS0
  else
    echo WRT_HIL_USB_MANIFEST_OK=0 > /dev/ttyS0
    cat /tmp/wrt-hil-verify.log > /dev/ttyS0
  fi
) &
exit 0
EOF
chmod +x "$USB_OV/etc/rc.local"
build_image "wrt-hil-host-usb" "$USB_OV" "openssh-client python3-light jq curl ca-bundle socat picocom kmod-usb-serial-ftdi kmod-usb-serial-cp210x kmod-usb-serial-ch341" 384

gzip -dc "$OUT/wrt-hil-host-usb.img.gz" > "$WORK/usb.img"
set +e
timeout 55 qemu-system-x86_64 -machine pc -m 768 -nographic -drive file="$WORK/usb.img",format=raw,if=virtio -netdev user,id=n0 -device virtio-net-pci,netdev=n0 > "$OUT/usb-qemu.log" 2>&1
usb_qemu_rc=$?
set -e

echo "== build Gold and RDTE digital twins =="
build_image "dut-a-gold" "$WORK/overlays/dut-a/gold" "ip-full" 160
build_image "dut-b-gold" "$WORK/overlays/dut-b/gold" "ip-full" 160
RDTE_PKGS="prplmesh kmod-mac80211-hwsim iw-full wpad-openssl ip-full -wpad-basic-mbedtls"
build_image "dut-a-rdte" "$WORK/overlays/dut-a/rdte" "$RDTE_PKGS" 192
build_image "dut-b-rdte" "$WORK/overlays/dut-b/rdte" "$RDTE_PKGS" 192

boot_one() {
  local name="$1"
  gzip -dc "$OUT/$name.img.gz" > "$WORK/$name.img"
  set +e
  timeout 80 qemu-system-x86_64 -machine pc -m 768 -nographic -drive file="$WORK/$name.img",format=raw,if=virtio -netdev user,id=n0 -device virtio-net-pci,netdev=n0 > "$OUT/$name-qemu.log" 2>&1
  echo $? > "$OUT/$name-qemu.rc"
  set -e
}
boot_one dut-a-gold
boot_one dut-b-gold

gzip -dc "$OUT/dut-a-rdte.img.gz" > "$WORK/dut-a-rdte.img"
gzip -dc "$OUT/dut-b-rdte.img.gz" > "$WORK/dut-b-rdte.img"
set +e
timeout 130 qemu-system-x86_64 -machine pc -m 768 -nographic   -drive file="$WORK/dut-a-rdte.img",format=raw,if=virtio   -netdev socket,id=n0,listen=127.0.0.1:31337 -device virtio-net-pci,netdev=n0,mac=52:54:00:12:77:0a   > "$OUT/dut-a-rdte-qemu.log" 2>&1 &
PA=$!
sleep 2
timeout 130 qemu-system-x86_64 -machine pc -m 768 -nographic   -drive file="$WORK/dut-b-rdte.img",format=raw,if=virtio   -netdev socket,id=n0,connect=127.0.0.1:31337 -device virtio-net-pci,netdev=n0,mac=52:54:00:12:77:0b   > "$OUT/dut-b-rdte-qemu.log" 2>&1 &
PB=$!
wait "$PA"; RCA=$?
wait "$PB"; RCB=$?
set -e
printf '%s
' "$RCA" > "$OUT/dut-a-rdte-qemu.rc"
printf '%s
' "$RCB" > "$OUT/dut-b-rdte-qemu.rc"

export OUT usb_qemu_rc
python3 - <<'PY' > "$OUT/verdict.json"
import json, os, pathlib, re
out=pathlib.Path(os.environ["OUT"])
def txt(n):
    p=out/n
    return p.read_text(errors="replace") if p.exists() else ""
u=txt("usb-qemu.log")
ga=txt("dut-a-gold-qemu.log"); gb=txt("dut-b-gold-qemu.log")
ra=txt("dut-a-rdte-qemu.log"); rb=txt("dut-b-rdte-qemu.log")
v={
 "schema":"wrt-prehil-artifact-qualification/v1",
 "usb_ready":"WRT_HIL_USB_READY=1" in u,
 "usb_manifest_ok":"WRT_HIL_USB_MANIFEST_OK=1" in u,
 "gold_a_ready":"RDTE_GOLD_READY=1" in ga and "RDTE_BOOT_MARKER dut-a gold" in ga,
 "gold_b_ready":"RDTE_GOLD_READY=1" in gb and "RDTE_BOOT_MARKER dut-b gold" in gb,
 "rdte_a_role_ready":"RDTE_ROLE_READY=1" in ra and "RDTE_BOOT_MARKER dut-a rdte" in ra,
 "rdte_b_role_ready":"RDTE_ROLE_READY=1" in rb and "RDTE_BOOT_MARKER dut-b rdte" in rb,
 "rdte_a_agent":"beerocks_agent" in ra,
 "rdte_b_agent":"beerocks_agent" in rb,
 "rdte_a_controller":"beerocks_controller" in ra,
 "rdte_b_controller_absent":"beerocks_controller" not in rb,
 "rdte_a_peer_ping":"RDTE_PEER_PING=1" in ra,
 "rdte_b_peer_ping":"RDTE_PEER_PING=1" in rb,
 "physical_write_authority":"DENIED_PREHIL",
 "digital_twin_claim":"configuration_boot_service_semantics_only"
}
required=[k for k in v if k not in ("schema","physical_write_authority","digital_twin_claim")]
v["passed"]=all(bool(v[k]) for k in required)
print(json.dumps(v,indent=2,sort_keys=True))
PY
cat "$OUT/verdict.json"
