#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
test -z "$before"
image="usbfabric-r04c-${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]]
echo "USBFABRIC_R04_BASE=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --build-arg "BASE=$base" \
 -f experiments/pi-usb-fabric-r04/guest-kernel/Dockerfile \
 -t "$image" experiments/pi-usb-fabric-r04/guest-kernel
echo USBFABRIC_R04_GUEST_PROBE_BEGIN
timeout 210s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges --memory 2048m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,nosuid,nodev,size=32m,mode=1777 "$image" > /tmp/r04-guest.log 2>&1 || {
 tail -n 100 /tmp/r04-guest.log; echo USBFABRIC_R04_GUEST_RUN=RED; exit 24; }
cat /tmp/r04-guest.log
grep -q USBFABRIC_R04_GUEST_BOOT=PASS /tmp/r04-guest.log
grep -q USBFABRIC_R04_GUEST_PROBE_END=YES /tmp/r04-guest.log
grep -q USBFABRIC_R04_PROC_MOUNT=PASS /tmp/r04-guest.log
grep -q USBFABRIC_R04_SYSFS_MOUNT=PASS /tmp/r04-guest.log
if ! grep -q USBFABRIC_R04_VUDC_NUM1_LOAD=PASS /tmp/r04-guest.log || ! grep -q USBFABRIC_R04_CONFIGFS_MOUNT=PASS /tmp/r04-guest.log || ! grep -q usbip-vudc.0 /tmp/r04-guest.log; then
  echo USBFABRIC_R04_VUDC_REGISTERED_CONTROLLER=RED; exit 26
fi
echo USBFABRIC_R04_VUDC_REGISTERED_CONTROLLER=PASS
grep -q USBFABRIC_R04_REAL_USBIP_URB=NOT_TESTED /tmp/r04-guest.log
if grep -q 'USBFABRIC_R04_MODULE_usbip_vudc=FAILED' /tmp/r04-guest.log ||
   grep -q 'USBFABRIC_R04_MODULE_vhci_hcd=FAILED' /tmp/r04-guest.log; then
 echo USBFABRIC_R04_VUDC_VHCI_CAPABILITY=RED
 exit 25
fi
echo USBFABRIC_R04_VUDC_VHCI_CAPABILITY=PASS
test -z "$(git status --porcelain --untracked-files=all)"
cleanup
trap - EXIT
echo USBFABRIC_R04_DISPOSABLE_CLEANUP=PASS
