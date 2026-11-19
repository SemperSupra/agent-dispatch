#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
clean(){ git status --porcelain --untracked-files=all -- . ':(exclude).r25-existing-go' ':(exclude).r25-guest-signer' ':(exclude).r27-preenrollment'; }
[[ -z "$(clean)" ]] || { echo R25_B_SOURCE_DIRTY=RED; exit 10; }
test "$(git -C .r25-existing-go rev-parse HEAD)" = 2e580a0162452a6f59a449f769f9bfc5153e0aa3
test "$(git -C .r25-guest-signer rev-parse HEAD)" = dc96c80b78540bc5b05ad70179c7afff647c3cbc
test "$(git -C .r27-preenrollment rev-parse HEAD)" = 1a3b17e664eb6fe1127575a509492ef5baa67802
base_img="r27-b-r22-host-pin-${GITHUB_SHA:0:12}"
r25_img="r27-b-r25-parent-${GITHUB_SHA:0:12}"
r26_img="r27-b-r26-parent-${GITHUB_SHA:0:12}"
image="r27-b-usbip-host-pin-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r27-b-actual-usbip-preboot-hostpin.log"
cleanup(){ docker image rm -f "$image" "$r26_img" "$r25_img" "$base_img" >/dev/null 2>&1 || :; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 11
echo "R25_B_BASE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --no-cache \
 --build-context gosource=.r25-existing-go \
 --build-context r22source=.r25-guest-signer \
 --build-context pinsource=.r27-preenrollment \
 --build-arg "BASE=$base" \
 -f experiments/pi-usb-fabric-r27/usbip-hostpin/Dockerfile.base \
 -t "$base_img" .
DOCKER_BUILDKIT=1 docker build --no-cache \
 --build-arg "PARENT=$base_img" \
 -f experiments/pi-usb-fabric-r25/qmp-usbip-vm-observer/Dockerfile \
 -t "$r25_img" .
DOCKER_BUILDKIT=1 docker build --no-cache \
 --build-arg "PARENT=$r25_img" \
 -f experiments/pi-usb-fabric-r26/qmp-vhci-domain/Dockerfile \
 -t "$r26_img" .
DOCKER_BUILDKIT=1 docker build --no-cache \
 --build-arg "PARENT=$r26_img" \
 -f experiments/pi-usb-fabric-r27/usbip-hostpin/Dockerfile \
 -t "$image" .
set +e
timeout 300s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 5120m --memory-swap 5120m --cpus 3 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 "$image" >"$log" 2>&1
rc=$?
set -e
cat "$log"
if [[ "$rc" -ne 0 ]];then echo "R25_B_QMP_USBIP_GUEST_OBSERVER=RED rc=$rc";exit 22;fi
for marker in \
 R25_B_QMP_CONSUMER_A_VM_NAME_UUID_STATUS=PASS \
 R25_B_FOREIGN_VM_UUID_REJECTED=PASS \
 R25_B_REAL_USBIP_GUEST_AND_QMP_VM_QUERY_SAME_RUN=PASS \
 R25_B_READONLY_QMP_IS_NOT_USBIP_RELEASE_AUTHORITY=PASS \
 R25_B_REAL_R26_QMP_ACK_TO_USBIP_VUDC=NOT_TESTED \
 R22_B_REAL_GUEST_ED25519_TO_REAL_USBIP_B_HANDOFF=PASS \
 R11_CONSUMER_B_REAL_USBIP_REASSIGNMENT=PASS \
 R26_A_REAL_LINUX_VHCI_AND_HOST_QMP_PCI_SAME_RUN=PASS \
 R26_A_QMP_PROVENANCE_NOT_KERNEL_USBIP_RELEASE=PASS \
 R26_A_REAL_QMP_ACTUATOR_FOR_LINUX_USBIP=NOT_TESTED \
 R27_B_HOST_PUB_PIN_READY_BEFORE_CONSUMER_A_QEMU_BOOT=PASS \
 R27_B_REAL_USBIP_VHCI_GUEST_PREBOOT_HOST_KEY_MATCH=PASS \
 R27_B_INDEPENDENT_PUBLIC_KEY_ENROLLED_BEFORE_REAL_CONSUMER_A_BOOT=PASS \
 R27_B_REAL_LINUX_USBIP_ED25519_PREBOOT_PIN_SAME_RUN=PASS \
 R27_B_GUEST_SIGNED_DYNAMIC_BLUE_LEASE_SCOPE=NOT_TESTED; do
 grep -Fq "$marker" "$log" || { echo "R25_B_REQUIRED_REAL_WITNESS_MISSING=$marker";exit 23; }
done
[[ -z "$(clean)" ]] || exit 24
cleanup;trap - EXIT
echo R27_B_DISPOSABLE_PREBOOT_KEY_USBIP_CLEANUP=PASS
