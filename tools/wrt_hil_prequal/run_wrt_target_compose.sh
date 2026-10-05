#!/usr/bin/env bash
set -euo pipefail
CP0_DIR="${1:?cp0 artifact directory required}"
OUT="${2:?output directory required}"
ROOT="${RUNNER_TEMP:-/tmp}/wrt-target-compose"
rm -rf "$ROOT"; mkdir -p "$ROOT" "$OUT"
VER=25.12.5
IB="openwrt-imagebuilder-${VER}-mvebu-cortexa9.Linux-x86_64"
ARCHIVE="$IB.tar.zst"
URL="https://downloads.openwrt.org/releases/${VER}/targets/mvebu/cortexa9/$ARCHIVE"
IB_SHA="2aa43dd6743868ee2cbc0db15623835cdf908876911e6eae95fb8af4bcc84da2"
PKG_SHA="0adddf13bac7161fb97c5db3f9e9d9a1390c886add6793cd19a3037357e322a7"
cd "$ROOT"
curl -fL --retry 2 --connect-timeout 20 "$URL" -o "$ARCHIVE"
test "$(sha256sum "$ARCHIVE" | awk '{print $1}')" = "$IB_SHA"
tar --use-compress-program=unzstd -xf "$ARCHIVE"
pkg="$(find "$CP0_DIR" -type f -name 'prplmesh-6.0.1-r1.apk' -print -quit)"
test -n "$pkg"
test "$(sha256sum "$pkg" | awk '{print $1}')" = "$PKG_SHA"
mkdir -p "$IB/packages" "$ROOT/overlay/etc/rdte"
cp "$pkg" "$IB/packages/"
cat > "$ROOT/overlay/etc/rdte/PREHIL_NOT_FOR_FLASH.json" <<EOF
{"schema":"wrt-target-compose/v1","device":"linksys_wrt3200acm","openwrt":"25.12.5","prplmesh":"6.0.1-r1","prplmesh_enabled":false,"physical_write_authority":"DENIED_PREHIL"}
EOF
cd "$IB"
make image PROFILE=linksys_wrt3200acm PACKAGES="prplmesh iw-full wpad-openssl ip-full -wpad-basic-mbedtls" FILES="$ROOT/overlay" > "$OUT/imagebuilder.log" 2>&1
dir="$IB/bin/targets/mvebu/cortexa9"
factory="$(find "$dir" -type f -name '*wrt3200acm*squashfs-factory.img' -print -quit)"
sysupgrade="$(find "$dir" -type f -name '*wrt3200acm*squashfs-sysupgrade.bin' -print -quit)"
rootfs="$(find "$dir" -type f -name '*wrt3200acm*targz-rootfs.tar.gz' -print -quit)"
test -n "$factory" -a -n "$sysupgrade" -a -n "$rootfs"
tar tzf "$rootfs" > "$OUT/rootfs-files.txt"
grep -qx './etc/config/prplmesh' "$OUT/rootfs-files.txt"
grep -qx './etc/rdte/PREHIL_NOT_FOR_FLASH.json' "$OUT/rootfs-files.txt"
cp "$factory" "$sysupgrade" "$rootfs" "$OUT/"
(cd "$OUT" && sha256sum "$(basename "$factory")" "$(basename "$sysupgrade")" "$(basename "$rootfs")" > images-sha256.txt)
python3 - "$OUT" "$IB_SHA" "$PKG_SHA" <<'PY'
import json,sys,pathlib
out=pathlib.Path(sys.argv[1])
d={
 "schema":"wrt3200acm-target-compose-verdict/v1",
 "passed":True,
 "profile":"linksys_wrt3200acm",
 "openwrt":"25.12.5",
 "imagebuilder_sha256":sys.argv[2],
 "prplmesh_sha256":sys.argv[3],
 "prplmesh_present_in_rootfs":True,
 "prehil_marker_present":True,
 "prplmesh_runtime_enablement_authorized":False,
 "physical_write_authority":"DENIED_PREHIL",
 "claim":"target-package-and-image-composition-only"
}
(out/"verdict.json").write_text(json.dumps(d,indent=2,sort_keys=True)+"\n")
print(json.dumps(d,indent=2,sort_keys=True))
PY
