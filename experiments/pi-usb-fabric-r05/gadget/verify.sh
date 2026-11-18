#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
test -z "$(git status --porcelain --untracked-files=all)"
image="pi-r05-vudc-${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; rm -f "$RUNNER_TEMP/r05-gadget.log"; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 18
echo "R05_PINNED_BASE=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --build-arg "BASE=$base" \
 -f experiments/pi-usb-fabric-r05/gadget/Dockerfile \
 -t "$image" .
timeout 210s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges --memory 2048m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,nosuid,nodev,size=32m,mode=1777 "$image" > "$RUNNER_TEMP/r05-gadget.log" 2>&1 || {
 tail -n 140 "$RUNNER_TEMP/r05-gadget.log"; echo USBFABRIC_R05_GUEST_BOOT_OR_GADGET=RED; exit 21; }
tail -n 160 "$RUNNER_TEMP/r05-gadget.log"
for oracle in USBFABRIC_R04_GUEST_BOOT=PASS USBFABRIC_R04_PROC_MOUNT=PASS \
 USBFABRIC_R04_SYSFS_MOUNT=PASS USBFABRIC_R04_VUDC_NUM1_LOAD=PASS \
 USBFABRIC_R05_HID_FUNCTION_MODULE=PASS USBFABRIC_R05_HID_DESCRIPTOR_63_BYTES=PASS USBFABRIC_R05_GADGET_UDC_BOUND=PASS \
 USBFABRIC_R05_HIDG0_CHAR_DEVICE=PASS USBFABRIC_R05_GADGET_PROBE_END=YES; do
  if ! grep -q "$oracle" "$RUNNER_TEMP/r05-gadget.log"; then
    echo "R05_MISSING_ORACLE=$oracle"; exit 22
  fi
done
grep -q "^.*usbip-vudc.0" "$RUNNER_TEMP/r05-gadget.log" || { echo USBFABRIC_R05_UDC_NOT_ENUMERATED=RED; exit 23; }
echo USBFABRIC_R05_REAL_GUEST_GADGET_BIND=PASS
echo USBFABRIC_R05_REAL_USBIP_DEVICE_TRANSFER=NOT_TESTED
cleanup
trap - EXIT
test -z "$(git status --porcelain --untracked-files=all)"
echo USBFABRIC_R05_CLOUD_CLEANUP=PASS
