#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
clean(){ git status --porcelain --untracked-files=all -- . ':(exclude).r27-typed-go' ':(exclude).r25-guest-signer' ':(exclude).r27-preenrollment' ':(exclude).r27-udc-source'; }
[[ -z "$(clean)" ]] || { echo R25_B_SOURCE_DIRTY=RED; exit 10; }
# R27-T reuses the original Go module lineage INCLUDING qualified R27-S
# write-ahead admission and protected Linux recovered-owner additions.
test "$(git -C .r27-typed-go rev-parse HEAD)" = bb842a13447b520d4a548fbba6e3556669b070c1
test "$(git -C .r25-guest-signer rev-parse HEAD)" = dc96c80b78540bc5b05ad70179c7afff647c3cbc
test "$(git -C .r27-preenrollment rev-parse HEAD)" = 1a3b17e664eb6fe1127575a509492ef5baa67802
test "$(git -C .r27-udc-source rev-parse HEAD)" = 740d1eb115fe1b62364118ee07e5867f0625683b
base_img="r27-g-real-typed-kernel-hostpin-${GITHUB_SHA:0:12}"
r25_img="r27-g-r25-parent-${GITHUB_SHA:0:12}"
r26_img="r27-g-r26-parent-${GITHUB_SHA:0:12}"
r27b_img="r27-g-r27-b-layer-${GITHUB_SHA:0:12}"
r27f_img="r27-g-r27-f-layer-${GITHUB_SHA:0:12}"
image="r27-g-original-kernel-isolated-usbip-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r27-g-original-kernel-isolated-a-usbip.log"
cleanup(){ docker image rm -f "$image" "$r27f_img" "$r27b_img" "$r26_img" "$r25_img" "$base_img" >/dev/null 2>&1 || :; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 11
echo "R25_B_BASE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --no-cache \
 --build-context gosource=.r27-typed-go \
 --build-context r22source=.r25-guest-signer \
 --build-context pinsource=.r27-preenrollment \
 --build-context udcsource=.r27-udc-source \
 --build-arg "BASE=$base" \
 -f experiments/pi-usb-fabric-r27/typed-kernel-runtime/Dockerfile.base \
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
 -t "$r27b_img" .
DOCKER_BUILDKIT=1 docker build --no-cache \
 --build-arg "PARENT=$r27b_img" \
 -f experiments/pi-usb-fabric-r27/udc-hostpin-composite/Dockerfile \
 -t "$r27f_img" .
DOCKER_BUILDKIT=1 docker build --no-cache \
 --build-arg "PARENT=$r27f_img" \
 -f experiments/pi-usb-fabric-r27/typed-kernel-runtime/Dockerfile \
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
if [[ "$rc" -ne 0 ]];then echo "R27_G_ORIGINAL_TYPED_LIVE_KERNEL_USBIP=RED rc=$rc";exit 22;fi
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
 R27_B_GUEST_SIGNED_DYNAMIC_BLUE_LEASE_SCOPE=NOT_TESTED \
 R27_F_ACTUAL_PROVIDER_UNBIND_BEFORE_A_VHCI_DETACH=PASS \
 R27_F_ACTUAL_B_RAW_IMPORT_DENIED_WHILE_UDC_UNBOUND=PASS \
 R27_F_PREBOOT_ED25519_SIGNED_VHCI_AND_QMP_PROVENANCE_SAME_RUN=PASS \
 R27_F_HOST_ONLY_GO_GRANT_BEFORE_REAL_UDC_REBIND_AND_B_IMPORT=PASS \
 R27_F_ONE_RUN_THREE_REAL_LINUX_KERNELS_A_TO_B=PASS \
 R27_F_ORIGINAL_TYPED_KERNEL_PHASE_IN_SAME_RUN=NOT_TESTED \
 R27_F_GUEST_SIGNED_DYNAMIC_LEASE_SCOPE=NOT_TESTED \
 R27_G_ORIGINAL_GO_KERNEL_ISOLATED_THEN_SIGNED_CURRENT_UP_SAME_RUN=PASS \
 R27_G_ORIGINAL_GO_RESTORED_B_BEFORE_PROVIDER_UDC_REBIND=PASS \
 R27_G_REAL_KERNEL_B_HID_AFTER_TYPED_A_RELEASE=PASS \
 R27_G_ACTUAL_3KERNEL_TYPED_STAGE_USES_TEST_ONLY_SERIAL_SENSOR=PASS \
 R27_G_FULL_P0_TRUSTED_HOST_SENSOR_DYNAMIC_SCOPE_AND_CRASH=NOT_TESTED \
 R27_I_NO_FAKE_QMP_ACK_FOR_LINUX_VHCI_B=PASS \
 R27_I_TEST_ONLY_B_RELEASE_PROOF_REJECTED_JOURNAL_BYTE_IDENTICAL=PASS \
 R27_I_B_DURABLE_HELD_RELEASE_INTENT_AFTER_REAL_HID=PASS \
 R27_I_CONSUMER_C_DENIED_UNTIL_INDEPENDENT_B_RELEASE=PASS \
 R27_I_GUEST_SIGNED_B_KERNEL_RELEASE=NOT_TESTED \
 R27_I_TYPED_A_LIVE_HANDOFF_B_ENDS_QUARANTINED=PASS \
 R27_T_REAL_3_KERNEL_B_HELD_RESTART_OWNER_QUARANTINED=PASS \
 R27_T_RECOVERY_REFUSAL_JOURNAL_BYTE_IDENTICAL=PASS \
 R27_T_CLEAN_FIRST_BOOT_RUNTIME_OWNER_MIGRATION=NOT_TESTED \
 R27_T_LIVE_QEMU_SIGKILL_VHCI_RESTART=NOT_TESTED \
 R27_L_HOST_OBSERVED_ACTUAL_PROVIDER_UART_READY=PASS \
 R27_L_HOST_RECEIVED_ACTUAL_PROVIDER_POST_UDC_ACK=PASS \
 R27_L_PROVIDER_REAL_UDC_REBOUND_BEFORE_UART_ACK=PASS \
 R27_L_PROVIDER_UART_NO_ECHO=PASS; do
 grep -Fq "$marker" "$log" || { echo "R27_G_REQUIRED_REAL_WITNESS_MISSING=$marker";exit 23; }
done
[[ -z "$(clean)" ]] || exit 24
cleanup;trap - EXIT
echo R27_G_DISPOSABLE_ORIGINAL_MANAGER_KERNEL_CLEANUP=PASS
echo R27_I_NO_TAINT_AND_HELD_QUARANTINE=PASS
