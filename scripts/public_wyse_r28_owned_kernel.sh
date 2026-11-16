#!/usr/bin/env bash
# R28 K0 only: public-synthetic Buildroot-owned kernel + rootfs compilation.
# No physical hardware, production PKI, UKI boot, firmware/disk changes.
set -Eeuo pipefail
umask 077
test -n "$GITHUB_SHA" && test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
test -n "$RUNNER_TEMP" && test -n "$GITHUB_WORKSPACE"
W="$RUNNER_TEMP/wyse-r28-owned-kernel"
mkdir -p "$W/dl/linux"
sh tools/wyse-buildroot/preflight-r19.sh
curl -fsSL --retry 3 https://buildroot.org/downloads/buildroot-2026.08.1.tar.xz -o "$W/buildroot.tar.xz"
printf '%s  %s\n' '34fb7bea8a213ffde39cc02e61703391560f26e0850f03138c722d0b09880f2b' "$W/buildroot.tar.xz" | sha256sum -c -
curl -fsSL --retry 3 https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.113.tar.xz -o "$W/dl/linux/linux-6.12.113.tar.xz"
printf '%s  %s\n' 'e09b6727e5c521253f0d41694900b9c38fb7604db7d35238a8197aa9f7de2428' "$W/dl/linux/linux-6.12.113.tar.xz" | sha256sum -c -
echo R28_PINNED_BUILDROOT_AND_KERNEL_TARBALL_HASHES=PASS
tar -xf "$W/buildroot.tar.xz" -C "$W"
SRC="$W/buildroot-2026.08.1"
OUT="$W/out"
cp tools/wyse-buildroot/configs/wyse_minimal_defconfig "$SRC/configs/wyse_r28_owned_kernel_defconfig"
cat >> "$SRC/configs/wyse_r28_owned_kernel_defconfig" <<'DEFCONFIG'
BR2_LINUX_KERNEL=y
BR2_LINUX_KERNEL_CUSTOM_VERSION=y
BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="6.12.113"
BR2_LINUX_KERNEL_USE_DEFCONFIG=y
BR2_LINUX_KERNEL_DEFCONFIG="x86_64"
BR2_LINUX_KERNEL_BZIMAGE=y
BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES="$(BR2_EXTERNAL_WYSE_RECOVERY_PATH)/configs/wyse-kernel-r28.fragment"
DEFCONFIG
chmod 0755 tools/wyse-buildroot/overlay/etc/init.d/S*
make -C "$SRC" O="$OUT" BR2_EXTERNAL="$GITHUB_WORKSPACE/tools/wyse-buildroot" wyse_r28_owned_kernel_defconfig > "$W/config.log" 2>&1 || { tail -n 55 "$W/config.log"; exit 1; }
grep -Fxq 'BR2_REPRODUCIBLE=y' "$OUT/.config"
grep -Fxq 'BR2_LINUX_KERNEL=y' "$OUT/.config"
grep -Fxq 'BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="6.12.113"' "$OUT/.config"
grep -Fxq 'BR2_LINUX_KERNEL_BZIMAGE=y' "$OUT/.config"
grep -Fq 'configs/wyse-kernel-r28.fragment' "$OUT/.config"
if ! timeout --signal=TERM --kill-after=10s 1900 make -C "$SRC" O="$OUT" BR2_DL_DIR="$W/dl" -j4 > "$W/build.log" 2>&1; then
  echo R28_OWNED_KERNEL_BUILD=RED
  tail -n 90 "$W/build.log"
  exit 1
fi
KCFG="$OUT/build/linux-6.12.113/.config"
test -s "$KCFG"
for name in \
  CONFIG_X86_64 CONFIG_EFI CONFIG_EFI_STUB CONFIG_BLK_DEV_INITRD \
  CONFIG_RD_GZIP CONFIG_DEVTMPFS CONFIG_SERIAL_8250_CONSOLE \
  CONFIG_MMC CONFIG_MMC_BLOCK CONFIG_MMC_SDHCI CONFIG_MMC_SDHCI_PCI \
  CONFIG_ATA CONFIG_SATA_AHCI CONFIG_E1000 \
  CONFIG_USB_XHCI_HCD CONFIG_USB_STORAGE; do
  if ! grep -Fxq "$name=y" "$KCFG"; then
    echo "R28_REQUIRED_BUILTIN_DRIVER_MISSING=$name"
    exit 5
  fi
done
test -s "$OUT/images/bzImage"
test -s "$OUT/images/rootfs.cpio"
test -s "$OUT/images/rootfs.squashfs"
test -x "$OUT/target/usr/sbin/dropbear"
echo "R28_SOURCE_HEAD=$GITHUB_SHA"
echo "R28_LINUX_KERNEL_VERSION=6.12.113"
echo "R28_LINUX_BZIMAGE_SHA256=$(sha256sum "$OUT/images/bzImage" | cut -d' ' -f1)"
echo "R28_ROOTFS_CPIO_SHA256=$(sha256sum "$OUT/images/rootfs.cpio" | cut -d' ' -f1)"
echo "R28_ROOTFS_SQUASHFS_SHA256=$(sha256sum "$OUT/images/rootfs.squashfs" | cut -d' ' -f1)"
echo R28_OWNED_KERNEL_AND_CRITICAL_BUILTINS=PASS
echo R28_OWNED_KERNEL_SIGNED_UKI_ACTUAL_BOOT=NOT_TESTED
echo R28_PRODUCTION_SIGNER_DELL_HARDWARE=NOT_TESTED
