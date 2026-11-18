#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
test -z "$(git status --porcelain --untracked-files=all)"
image="pi-r07-reconnect-${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; rm -f "$RUNNER_TEMP/r07-recovery.log"; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 18
echo "R07_PINNED_BASE=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --build-arg "BASE=$base" \
 -f experiments/pi-usb-fabric-r07/recovery/Dockerfile \
 -t "$image" .
timeout 210s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges --memory 2048m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,nosuid,nodev,size=32m,mode=1777 "$image" > "$RUNNER_TEMP/r07-recovery.log" 2>&1 || {
 tail -n 140 "$RUNNER_TEMP/r07-recovery.log"; echo USBFABRIC_R06_GUEST_BOOT_OR_IMPORT=RED; exit 21; }
tail -n 160 "$RUNNER_TEMP/r07-recovery.log"
for oracle in USBFABRIC_R04_GUEST_BOOT=PASS USBFABRIC_R04_PROC_MOUNT=PASS \
 USBFABRIC_R04_SYSFS_MOUNT=PASS USBFABRIC_R04_VUDC_NUM1_LOAD=PASS \
 USBFABRIC_R05_HID_FUNCTION_MODULE=PASS USBFABRIC_R05_HID_DESCRIPTOR_63_BYTES=PASS USBFABRIC_R05_GADGET_UDC_BOUND=PASS \
 USBFABRIC_R05_HIDG0_CHAR_DEVICE=PASS USBFABRIC_R06_USBIP_BINARIES=PASS \
 USBFABRIC_R06_NO_SERVER_NEGATIVE=PASS USBFABRIC_R06_REAL_USBIP_VUDC_EXPORT=PASS \
 USBFABRIC_R06_REAL_VHCI_IMPORT=PASS USBFABRIC_R06_EVDEV_OBSERVER_READY=PASS \
 USBFABRIC_R06_REAL_KEY_A_DOWN=PASS USBFABRIC_R06_REAL_KEY_A_UP=PASS \
 USBFABRIC_R06_EVDEV_REPORT_TRANSFER=PASS USBFABRIC_R06_GUEST_HID_INPUT_DATA=PASS \
 USBFABRIC_R07_FIRST_DETACH_QUIESCENT=PASS \
 USBFABRIC_R07_SECOND_IMPORT=PASS USBFABRIC_R07_SECOND_REAL_HID_KEY_SEQUENCE=PASS \
 USBFABRIC_R07_SECOND_DETACH=PASS USBFABRIC_R07_RECOVERY_PROBE_END=YES \
 USBFABRIC_R06_TRANSPORT_PROBE_END=YES \
 USBFABRIC_R05_GADGET_PROBE_END=YES; do
  if ! grep -q "$oracle" "$RUNNER_TEMP/r07-recovery.log"; then
    echo "R06_MISSING_ORACLE=$oracle"; exit 22
  fi
done
grep -q "^.*usbip-vudc.0" "$RUNNER_TEMP/r07-recovery.log" || { echo USBFABRIC_R06_UDC_NOT_ENUMERATED=RED; exit 23; }
echo USBFABRIC_R06_REAL_GUEST_USBIP_VUDC_VHCI=PASS
echo USBFABRIC_R07_REAL_RECONNECT_HID_KEY_EVENT=PASS
cleanup
trap - EXIT
test -z "$(git status --porcelain --untracked-files=all)"
echo USBFABRIC_R07_CLOUD_CLEANUP=PASS
