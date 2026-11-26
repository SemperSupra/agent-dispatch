#!/usr/bin/env bash
# R63 real source-built QEMU guest: restricted root key-only SSH oracle.
# CI ONLY synthetic injected SSH keys, never device enrollment or production.
# No physical media, privileged host access, LAN server, signer or private code.
set -Eeuo pipefail
umask 077
export LC_ALL=C TZ=UTC
STAGE=environment
W= QP= FP=
RECEIPT=evidence/public/wyse-r63-restricted-guest.txt
mkdir -p evidence/public
finish() {
  local rc=$?
  trap - EXIT
  if test -n "$FP"; then kill "$FP" 2>/dev/null || true; wait "$FP" 2>/dev/null || true; fi
  if test -n "$QP"; then kill "$QP" 2>/dev/null || true; wait "$QP" 2>/dev/null || true; fi
  if test "$rc" -ne 0; then
    printf 'R63_GUEST_RESULT=RED\nR63_FAILURE_STAGE=%s\nR63_EXIT=%s\nR63_PRODUCTION_ENROLLMENT_HARDWARE=NOT_TESTED\n' "$STAGE" "$rc" > "$RECEIPT"
    echo "R63_FAILURE_STAGE=$STAGE R63_EXIT=$rc" >&2
    if test -n "$W" && test -s "$W/serial.log"; then
      tail -n 15 "$W/serial.log" | sed -E 's@/home/runner/[^[:space:]]+@<runner-path>@g' >&2 || true
    fi
  fi
  if test -n "$W" && test -d "$W"; then rm -rf -- "$W" || true; fi
  exit "$rc"
}
trap finish EXIT
test -n "${RUNNER_TEMP:-}" && test -n "${GITHUB_SHA:-}" && test -n "${GITHUB_WORKSPACE:-}"
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
test "$(pwd)" = "$GITHUB_WORKSPACE"
K="$RUNNER_TEMP/wyse-r28-owned-kernel/out/images/bzImage"
I="$RUNNER_TEMP/wyse-r28-owned-kernel/out/images/rootfs.cpio"
STAGE=source_owned_images
test -s "$K" && test -s "$I"
test "$(sha256sum "$K" | cut -d' ' -f1)" = d51edcfc59aafabd11e7eb39bf1a5630bbfb3480c8bf7a2f25606d21121cc5ac
for tool in qemu-system-x86_64 dropbearkey ssh-keygen ssh ssh-keyscan cpio timeout; do command -v "$tool" >/dev/null; done
W=$(mktemp -d "$RUNNER_TEMP/wyse-r63-guest-XXXXXX")
STAGE=test_keys
dropbearkey -t ed25519 -f "$W/hostkey" >"$W/dropbearkey.log" 2>&1
ssh-keygen -q -t ed25519 -N '' -f "$W/client" >"$W/ssh-keygen.log" 2>&1
test -s "$W/hostkey" && test -s "$W/client.pub"
mkdir -p "$W/overlay/etc/init.d" "$W/overlay/etc/wyse-ci-only"
cp "$W/hostkey" "$W/overlay/etc/wyse-ci-only/hostkey"
cp "$W/client.pub" "$W/overlay/etc/wyse-ci-only/operator.pub"
cat > "$W/overlay/etc/init.d/S49wyse-ci-witness" <<'TEST_ONLY'
#!/bin/sh
# Test-only ephemeral fixture, NOT production enrollment or device identity.
case "$1" in
 start)
  test -d /run/wyse-keys || exit 1
  cp /etc/wyse-ci-only/hostkey /run/wyse-keys/ssh_host_ed25519_key || exit 1
  cp /etc/wyse-ci-only/operator.pub /run/wyse-keys/authorized_keys || exit 1
  chmod 0600 /run/wyse-keys/ssh_host_ed25519_key /run/wyse-keys/authorized_keys
  echo WYSE_R63_CI_ONLY_KEY_INJECTION=ACTIVE
  ;;
 stop) ;;
 *) exit 1 ;;
esac
TEST_ONLY
chmod 0755 "$W/overlay/etc/init.d/S49wyse-ci-witness"
chmod 0600 "$W/overlay/etc/wyse-ci-only/hostkey"
( cd "$W/overlay" && find . -print0 | cpio --null -o -H newc ) >"$W/ci-only.cpio" 2>"$W/cpio.log"
cat "$I" "$W/ci-only.cpio" > "$W/test-only.cpio"
test -s "$W/test-only.cpio"
PORT=22063
FWD_PORT=22064
dropbearkey -y -f "$W/hostkey" 2>/dev/null |
  grep '^ssh-ed25519 ' | sed "s@^@[127.0.0.1]:$PORT @" > "$W/known_hosts"
test -s "$W/known_hosts"
STAGE=qemu_boot_restricted
timeout -s TERM -k 5 165 qemu-system-x86_64 \
  -machine q35,accel=tcg -cpu max -m 1024 -smp 2 \
  -nodefaults -display none -monitor none -no-reboot \
  -serial "file:$W/serial.log" \
  -kernel "$K" -initrd "$W/test-only.cpio" \
  -append 'console=ttyS0,115200n8 rdinit=/init panic=2' \
  -netdev "user,id=ci,restrict=on,hostfwd=tcp:127.0.0.1:$PORT-:22" \
  -device e1000,netdev=ci >"$W/qemu.log" 2>&1 &
QP=$!
ssh_args=(-F /dev/null -p "$PORT" -i "$W/client" -o IdentitiesOnly=yes
  -o IdentityAgent=none -o BatchMode=yes -o ConnectTimeout=2
  -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$W/known_hosts")
STAGE=restricted_positive
observed=
for attempt in $(seq 1 70); do
  if observed=$(ssh "${ssh_args[@]}" root@127.0.0.1 status 2>"$W/ssh.log"); then break; fi
  if ! kill -0 "$QP" 2>/dev/null; then echo R63_QEMU_EARLY_EXIT=RED >&2; exit 62; fi
  sleep 2
done
expected=$(printf 'WYSE_RECOVERY_SSH_SCOPE=READ_ONLY\nWYSE_RECOVERD_INTEGRATION=NOT_QUALIFIED\nWYSE_PRODUCTION_PAIRING=NOT_QUALIFIED')
test "$observed" = "$expected" || { echo R63_RESTRICTED_STATUS_NOT_OBSERVED=RED >&2; exit 63; }
grep -Fq 'WYSE_CORE_TMPFS_NO_EMMC_WRITES=ACTIVE' "$W/serial.log"
grep -Fq 'WYSE_R63_CI_ONLY_KEY_INJECTION=ACTIVE' "$W/serial.log"
grep -Fq 'WYSE_SSH=KEY_ONLY_RESTRICTED_START' "$W/serial.log"
echo R63_REAL_GUEST_FORCED_STATUS=PASS
STAGE=remote_shell_negative
set +e
denied=$(ssh "${ssh_args[@]}" root@127.0.0.1 'echo R63_UNRESTRICTED_ROOT_SHELL=RED' 2>&1)
exit_code=$?
set -e
test "$exit_code" -eq 64 || { echo "R63_REMOTE_SHELL_DENIAL_EXIT=RED:$exit_code" >&2; exit 64; }
test "$denied" = 'WYSE_RECOVERY_SSH=DENIED_UNSUPPORTED_COMMAND' || {
 echo R63_REMOTE_SHELL_DENIAL_TEXT=RED >&2; exit 65;
}
echo R63_REAL_GUEST_ARBITRARY_ROOT_COMMAND_DENIED=PASS
STAGE=correct_key_liveness
test "$(ssh "${ssh_args[@]}" root@127.0.0.1 status)" = "$expected"
echo R63_REAL_GUEST_CORRECT_KEY_AFTER_DENIAL=PASS
STAGE=tunnel_negative
# The client may create its local socket even when the server rejects
# direct-tcpip. Probe for an ACTUAL forwarded SSH host key, not just exit code.
ssh "${ssh_args[@]}" -N -L "127.0.0.1:$FWD_PORT:127.0.0.1:22" \
  root@127.0.0.1 >"$W/forwarder.log" 2>&1 &
FP=$!
sleep 2
ssh-keyscan -T 3 -p "$FWD_PORT" -t ed25519 127.0.0.1 \
 >"$W/forward-hostkeys.log" 2>"$W/forward-scan.log" || true
if test -s "$W/forward-hostkeys.log"; then
  echo R63_SERVER_ALLOWED_ROOT_TCP_FORWARDING=RED >&2; exit 66
fi
test "$(ssh "${ssh_args[@]}" root@127.0.0.1 status)" = "$expected"
echo R63_REAL_GUEST_SSH_FORWARDING_DENIED=PASS
STAGE=receipt
cat > "$RECEIPT" <<EOF
R63_GUEST_RESULT=PASS
R63_BUILD_HEAD=$GITHUB_SHA
R63_KERNEL_SHA256=$(sha256sum "$K" | cut -d' ' -f1)
R63_RESTRICTED_ROOTFS_SHA256=$(sha256sum "$I" | cut -d' ' -f1)
R63_READ_ONLY_SSH_STATUS=PASS
R63_ARBITRARY_ROOT_COMMAND_DENIED=PASS
R63_LOCAL_TCP_FORWARDING_TO_SSH_DENIED=PASS
R63_CORRECT_KEY_AFTER_DENIAL=PASS
R63_TEST_ONLY_KEYS_AND_CPIO=DESTROYED_ON_EXIT
R63_DISPOSABLE_QEMU_NETWORK=USER_RESTRICTED_LOCALHOST_FORWARD
R63_GO_RECOVERD_PRODUCTION_ENROLLMENT_SIGNING_HARDWARE=NOT_TESTED
R63_REAL_DELL_AND_TRUENAS=NOT_TESTED
EOF
echo R63_REAL_GUEST_RESTRICTED_SSH=PASS
