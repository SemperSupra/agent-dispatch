#!/bin/sh
# Source-level recovery SSH invariants; does NOT establish real key-only login.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
conf="$here/configs/wyse_minimal_defconfig"
svc="$here/overlay/etc/init.d/S50dropbear"
test -f "$conf" && test -f "$svc"
sh -n "$svc"
grep -Fq '# BR2_TARGET_ENABLE_ROOT_LOGIN is not set' "$conf"
grep -Fq 'BR2_PACKAGE_DROPBEAR=y' "$conf"
grep -Fq 'BR2_PACKAGE_DROPBEAR_SMALL=y' "$conf"
grep -Fq '# BR2_TARGET_GENERIC_REMOUNT_ROOTFS_RW is not set' "$conf"
grep -Fq 'key=/run/wyse-keys/ssh_host_ed25519_key' "$svc"
grep -Fq 'auth=/run/wyse-keys/authorized_keys' "$svc"
grep -Fq 'WYSE_SSH=HOLD_UNENROLLED_NO_HOST_KEY' "$svc"
grep -Fq 'cp "$auth" /root/.ssh/authorized_keys' "$svc"
grep -Fq '/usr/sbin/dropbear -s -g -p 22 -r "$key"' "$svc"
if grep -Eq '(^|[[:space:]])(-w|--disable-root-login)([[:space:]]|$)|dropbearkey|PasswordAuthentication[[:space:]]+yes' "$svc"; then
  echo "WYSE_SSH_STATIC_POLICY=FAIL"; exit 1
fi
echo "WYSE_SSH_STATIC_POLICY=PASS"
echo "WYSE_SSH_REAL_AUTHENTICATION=NOT_TESTED"
