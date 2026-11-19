#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
clean(){ git status --porcelain --untracked-files=all -- . ':(exclude).r22-existing-go' ':(exclude).r22-a-qualified'; }
test -z "$(clean)" || { echo R22_B_SIGNED_USBIP_SOURCE_TAINT=RED;exit 10; }
test "$(git -C .r22-existing-go rev-parse HEAD)" = 2e580a0162452a6f59a449f769f9bfc5153e0aa3
test "$(git -C .r22-a-qualified rev-parse HEAD)" = dc96c80b78540bc5b05ad70179c7afff647c3cbc
image="r22b-guest-ed25519-actual-usbip-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r22-b-real-usbip-signed-guest.log"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 11
echo "R22_B_SIGNED_USBIP_BASE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --no-cache \
 --build-context gosource=.r22-existing-go \
 --build-context r22source=.r22-a-qualified \
 --build-arg "BASE=$base" \
 -f experiments/pi-usb-fabric-r22/qmp-usbip-compose/usbip-guest-signing/Dockerfile \
 -t "$image" .
set +e
timeout 270s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 5120m --memory-swap 5120m --cpus 3 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 "$image" >"$log" 2>&1
rc=$?
set -e
cat "$log"
if [[ "$rc" -ne 0 ]];then echo "R22_B_ACTUAL_SIGNED_GUEST_USBIP_HANDFOFF=RED rc=$rc";exit 22;fi
for marker in \
 R22_B_RANDOM_HOST_CHALLENGE_READY=PASS \
 R22_B_REAL_USBIP_CONSUMER_A_IN_GUEST_ED25519_VERIFIED=PASS \
 R22_B_REAL_USBIP_GUEST_ED25519_SIGNER_READY=PASS \
 R22_B_GUEST_ORIGIN_ED25519_DURABLE_HELD_RELEASE=PASS \
 R22_B_SIGNED_GUEST_A_PROOF_TO_REAL_CONFIGFS_VUDC_REBIND=PASS \
 R18_SAME_RUN_REAL_USBIP_EXISTING_GO_BROKER_TEST_ONLY_GATE=PASS \
 R11_CONSUMER_B_REAL_USBIP_REASSIGNMENT=PASS \
 R22_B_REAL_GUEST_ED25519_TO_REAL_USBIP_B_HANDOFF=PASS \
 R22_B_REAL_QMP_AND_DYNAMIC_SIGNED_LEASE_SCOPE=NOT_TESTED; do
 grep -q "$marker" "$log" || { echo "R22_B_MISSING_SIGNED_GUEST_USBIP_ORACLE=$marker";exit 23; }
done
cleanup;trap - EXIT
test -z "$(clean)" || exit 24
echo R22_B_SIGNED_GUEST_REAL_USBIP_DISPOSABLE_CLEANUP=PASS
