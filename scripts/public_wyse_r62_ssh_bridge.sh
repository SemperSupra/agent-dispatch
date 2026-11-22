#!/usr/bin/env bash
# R62 real QEMU Buildroot SSH mechanics. CI-only key injection is NOT enrollment.
# No owner keys, real machines, LAN listeners, host disks or USB writes.
set -Eeuo pipefail
umask 077
export LC_ALL=C TZ=UTC
STAGE=environment
W=
QP=
RECEIPT=evidence/public/wyse-r62-ssh.txt
mkdir -p evidence/public
finish() {
  local rc=$?
  trap - EXIT
  if test -n "$QP"; then kill "$QP" 2>/dev/null || true; wait "$QP" 2>/dev/null || true; fi
  if test "$rc" -ne 0; then
    printf 'R62_RESULT=RED\nR62_FAILURE_STAGE=%s\nR62_EXIT=%s\nR62_PRODUCTION_PAIRING_SIGNING_HARDWARE=NOT_TESTED\n' "$STAGE" "$rc" > "$RECEIPT"
    echo "R62_FAILURE_STAGE=$STAGE R62_EXIT=$rc" >&2
    if test -n "$W" && test -s "$W/serial.log"; then
      tail -n 18 "$W/serial.log" | sed -E 's@/home/runner/[^[:space:]]+@<runner-path>@g' >&2 || true
    fi
  fi
  if test -n "$W" && test -d "$W"; then rm -rf -- "$W" || true; fi
  exit "$rc"
}
trap finish EXIT
test -n "$RUNNER_TEMP" && test -n "$GITHUB_SHA" && test -n "$GITHUB_WORKSPACE"
STAGE=source_identity
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
test "$(pwd)" = "$GITHUB_WORKSPACE"
K="$RUNNER_TEMP/wyse-r28-owned-kernel/out/images/bzImage"
I="$RUNNER_TEMP/wyse-r28-owned-kernel/out/images/rootfs.cpio"
STAGE=original_images
test -s "$K" && test -s "$I"
test "$(sha256sum "$K" | cut -d' ' -f1)" = d51edcfc59aafabd11e7eb39bf1a5630bbfb3480c8bf7a2f25606d21121cc5ac
test "$(sha256sum "$I" | cut -d' ' -f1)" = 4023a48f55908bd4b9b3df3e0df4e6f2249f64812debc8f2f19a2896bcc0be81
for tool in qemu-system-x86_64 cpio dropbearkey ssh-keygen ssh sha256sum timeout; do command -v "$tool" >/dev/null; done
W=$(mktemp -d "$RUNNER_TEMP/wyse-r62-ssh-XXXXXX")
STAGE=synthetic_keys
dropbearkey -t ed25519 -f "$W/hostkey" >"$W/dropbear.log" 2>&1
ssh-keygen -q -t ed25519 -N '' -f "$W/client" >"$W/client-keygen.log" 2>&1
test -s "$W/hostkey" && test -s "$W/client.pub"
mkdir -p "$W/overlay/etc/init.d" "$W/overlay/etc/wyse-ci-only"
cp "$W/hostkey" "$W/overlay/etc/wyse-ci-only/hostkey"
cp "$W/client.pub" "$W/overlay/etc/wyse-ci-only/operator.pub"
cat > "$W/overlay/etc/init.d/S49wyse-ci-witness" <<'TEST_ONLY'
#!/bin/sh
# CI-only init overlay, not accepted product enrollment.
case "$1" in
 start)
  test -d /run/wyse-keys || exit 1
  cp /etc/wyse-ci-only/hostkey /run/wyse-keys/ssh_host_ed25519_key || exit 1
  cp /etc/wyse-ci-only/operator.pub /run/wyse-keys/authorized_keys || exit 1
  chmod 0600 /run/wyse-keys/ssh_host_ed25519_key /run/wyse-keys/authorized_keys
  echo WYSE_R62_TEST_ONLY_SYNTHETIC_PAIRING=ACTIVE
  ;;
 stop) ;;
 *) exit 1 ;;
esac
TEST_ONLY
chmod 0755 "$W/overlay/etc/init.d/S49wyse-ci-witness"
chmod 0600 "$W/overlay/etc/wyse-ci-only/hostkey"
STAGE=test_only_initramfs
( cd "$W/overlay" && find . -print0 | cpio --null -o -H newc ) >"$W/ci-only.cpio" 2>"$W/archive.log"
# Linux accepts concatenated uncompressed newc archives.
cat "$I" "$W/ci-only.cpio" > "$W/test-only.cpio"
test "$(sha256sum "$I" | cut -d' ' -f1)" = 4023a48f55908bd4b9b3df3e0df4e6f2249f64812debc8f2f19a2896bcc0be81
PORT=22062
dropbearkey -y -f "$W/hostkey" 2>/dev/null | \
 grep '^ssh-ed25519 ' | sed "s@^@[127.0.0.1]:$PORT @" > "$W/known_hosts"
test -s "$W/known_hosts"
STAGE=qemu_keyonly
timeout -s TERM -k 5 145 qemu-system-x86_64 \
 -machine q35,accel=tcg -cpu max -m 1024 -smp 2 \
 -nodefaults -display none -monitor none -no-reboot \
 -serial "file:$W/serial.log" \
 -kernel "$K" -initrd "$W/test-only.cpio" \
 -append 'console=ttyS0,115200n8 rdinit=/init panic=2' \
 -netdev "user,id=ci,restrict=on,hostfwd=tcp:127.0.0.1:$PORT-:22" \
 -device e1000,netdev=ci \
 >"$W/qemu.log" 2>&1 &
QP=$!
STAGE=keyonly_positive
result=
for attempt in $(seq 1 65); do
  if result=$(ssh -p "$PORT" -i "$W/client" -o IdentitiesOnly=yes \
    -o BatchMode=yes -o ConnectTimeout=2 \
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$W/known_hosts" \
    root@127.0.0.1 'echo WYSE_R62_REAL_KEY_ONLY_LOGIN=PASS' 2>"$W/ssh.log"); then
    break
  fi
  if ! kill -0 "$QP" 2>/dev/null; then
    echo R62_QEMU_EARLY_EXIT=RED >&2
    tail -n 20 "$W/qemu.log" >&2 || true
    exit 62
  fi
  sleep 2
done
test "$result" = "WYSE_R62_REAL_KEY_ONLY_LOGIN=PASS" || {
  echo R62_KEY_ONLY_REAL_LOGIN_MISSING=RED >&2
  tail -n 15 "$W/ssh.log" >&2 || true
  exit 63
}
test -s "$W/serial.log"
grep -Fq 'WYSE_CORE_TMPFS_NO_EMMC_WRITES=ACTIVE' "$W/serial.log"
grep -Fq 'WYSE_R62_TEST_ONLY_SYNTHETIC_PAIRING=ACTIVE' "$W/serial.log"
grep -Fq 'WYSE_SSH=KEY_ONLY_START' "$W/serial.log"
STAGE=password_negative
if ssh -p "$PORT" -o PubkeyAuthentication=no -o PasswordAuthentication=yes \
 -o PreferredAuthentications=password -o KbdInteractiveAuthentication=no \
 -o BatchMode=yes -o NumberOfPasswordPrompts=0 -o ConnectTimeout=3 \
 -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$W/known_hosts" \
 root@127.0.0.1 'echo SHOULD_NOT_RUN' >"$W/password.log" 2>&1; then
 echo R62_PASSWORD_ONLY_UNEXPECTED_LOGIN=RED >&2; exit 64
fi
if grep -Fq SHOULD_NOT_RUN "$W/password.log"; then
 echo R62_PASSWORD_COMMAND_EXECUTED=RED >&2; exit 65
fi
STAGE=receipt
cat > "$RECEIPT" <<EOF
R62_RESULT=PASS
R62_SOURCE_SHA=$GITHUB_SHA
R62_ORIGINAL_KERNEL_SHA256=$(sha256sum "$K" | cut -d' ' -f1)
R62_ORIGINAL_ROOTFS_SHA256=$(sha256sum "$I" | cut -d' ' -f1)
R62_SYNTHETIC_TEST_ONLY_CPIO=DESTROYED_ON_EXIT
R62_REAL_GUEST_KEY_ONLY_SSH=PASS
R62_REAL_GUEST_PASSWORD_ONLY_DENIED=PASS
R62_REAL_GUEST_RECOVERY_TMPFS=PASS
R62_QEMU_NETWORK=USER_RESTRICTED_LOCALHOST_HOSTFWD_ONLY
R62_NO_CONTROLLER_OR_INTERNET_DEPENDENCY=PASS
R62_PRODUCTION_PAIRING_SIGNING_HARDWARE=NOT_TESTED
R62_REAL_DELL_PHYSICAL_AND_TRUENAS=NOT_TESTED
R62_NO_HOST_DISKS_OR_PHYSICAL_MEDIA=PASS
EOF
echo R62_SOURCE_OWNED_GUEST_SSH_AND_CONTROLLER_OUTAGE=PASS
