#!/usr/bin/env bash
# R26 public-safe Buildroot source reproducibility oracle, no rootfs upload.
set -Eeuo pipefail
umask 077
test -n "${GITHUB_SHA:-}" && test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
test -n "${GITHUB_OUTPUT:-}" && test -n "${RUNNER_TEMP:-}"
E="$RUNNER_TEMP/wyse-r26-repro"
mkdir -p "$E"
sh tools/wyse-buildroot/preflight-r19.sh
curl -fsSL --retry 3 https://buildroot.org/downloads/buildroot-2026.08.1.tar.xz -o "$E/source.tar.xz"
printf '%s  %s\n' '34fb7bea8a213ffde39cc02e61703391560f26e0850f03138c722d0b09880f2b' "$E/source.tar.xz" | sha256sum -c -
mkdir -p "${WYSE_R26_SOURCE_PARENT:-$E}"
tar -xf "$E/source.tar.xz" -C "${WYSE_R26_SOURCE_PARENT:-$E}"
chmod 0755 tools/wyse-buildroot/overlay/etc/init.d/S*
SRC_PARENT="${WYSE_R26_SOURCE_PARENT:-$E}"
OUT="${WYSE_R26_OUTPUT_DIR:-$E/out}"
case "$SRC_PARENT" in "$RUNNER_TEMP"|"$RUNNER_TEMP"/*) ;; *) echo 'R26_SOURCE_PARENT_OUTSIDE_RUNNER_TEMP=DENIED' >&2; exit 3 ;; esac
case "$OUT" in "$RUNNER_TEMP"/*) ;; *) echo 'R26_OUTPUT_OUTSIDE_RUNNER_TEMP=DENIED' >&2; exit 3 ;; esac
SRC="$SRC_PARENT/buildroot-2026.08.1"
echo "R26_BUILDROOT_SOURCE_PATH=$SRC"
echo "R26_BUILDROOT_OUTPUT_PATH=$OUT"
make -C "$SRC" O="$OUT" BR2_EXTERNAL="$GITHUB_WORKSPACE/tools/wyse-buildroot" wyse_minimal_defconfig > "$E/config.log" 2>&1
grep -Fxq 'BR2_REPRODUCIBLE=y' "$OUT/.config"
grep -Fxq 'BR2_PACKAGE_BUSYBOX=y' "$OUT/.config"
grep -Fq 'configs/busybox-stat.fragment' "$OUT/.config"
grep -Fxq 'BR2_PACKAGE_DROPBEAR=y' "$OUT/.config"
if ! timeout --signal=TERM --kill-after=10s 1800 make -C "$SRC" O="$OUT" -j4 > "$E/build.log" 2>&1; then
  tail -n 60 "$E/build.log"
  exit 1
fi
bconfig=$(find "$OUT/build" -maxdepth 2 -type f -path '*/busybox-*/.config' -print -quit)
test -f "$bconfig"
grep -Fxq 'CONFIG_STAT=y' "$bconfig"
grep -Fxq 'CONFIG_FEATURE_STAT_FORMAT=y' "$bconfig"
test -s "$OUT/images/rootfs.cpio" && test -s "$OUT/images/rootfs.squashfs"
test -x "$OUT/target/usr/sbin/dropbear"
test -x "$OUT/target/etc/init.d/S50dropbear"
cpio_sha=$(sha256sum "$OUT/images/rootfs.cpio" | cut -d' ' -f1)
squash_sha=$(sha256sum "$OUT/images/rootfs.squashfs" | cut -d' ' -f1)
test "${#cpio_sha}" -eq 64 && test "${#squash_sha}" -eq 64
printf 'cpio=%s\nsquash=%s\n' "$cpio_sha" "$squash_sha" >> "$GITHUB_OUTPUT"
echo "R26_EXACT_SOURCE_HEAD=$GITHUB_SHA"
echo "R26_ROOTFS_CPIO_SHA256=$cpio_sha"
echo "R26_ROOTFS_SQUASHFS_SHA256=$squash_sha"
echo "R26_REPRODUCIBLE_STAT_CONFIGURED_BUILD=PASS"
echo 'R26_PRODUCTION_SIGNER_DELL_HARDWARE=NOT_TESTED'
