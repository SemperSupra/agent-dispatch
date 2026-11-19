#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R24_B_DIRTY_INPUT=RED; exit 10; }
guest="public-r26b-qmp-preapproved-guest-${GITHUB_SHA:0:12}"
image="public-r26b-real-qmp-host-pinned-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r26-b-qmp-host-pinned.log"
cleanup(){ docker image rm -f "$image" "$guest" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
deb="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
docker pull golang:1.23-bookworm >/dev/null
golang="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.23-bookworm)"
[[ "$deb" == *@sha256:* && "$golang" == *@sha256:* ]] || exit 11
echo "R24_B_PINNED_BUILD_DIGESTS=$deb $golang"
DOCKER_BUILDKIT=1 docker build --pull --no-cache \
  -f experiments/pi-usb-fabric-r26/host-pin/Dockerfile.guest \
  --build-arg "DEBIAN_BASE=$deb" --build-arg "GO_BASE=$golang" \
  -t "$guest" .
DOCKER_BUILDKIT=1 docker build --no-cache \
  -f experiments/pi-usb-fabric-r26/host-pin/Dockerfile.integrated \
  --build-arg "R15_IMAGE=$guest" --build-arg "GO_BASE=$golang" \
  -t "$image" .
set +e
timeout 275s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2560m --memory-swap 2560m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 --entrypoint python3 "$image" -B /guest/r26-l9c-scoped-release-detach-oracle.py \
 >"$log" 2>&1
rc=$?
set -e
cat "$log"
if [[ "$rc" -ne 0 ]];then echo "R24_B_REAL_QMP_DYNAMIC_SIGNER=RED rc=$rc";exit 22;fi
for marker in \
 R26_B_HOST_PIN_WRITTEN_BEFORE_REAL_QEMU_GUEST_BOOT=PASS \
 R24_B_ACTUAL_R26_DYNAMIC_SCOPE_BOUND=PASS \
 R24_B_REAL_QMP_GUEST_ED25519_DOWN_AUTHORITY=PASS \
 R24_B_REAL_QMP_GUEST_ED25519_UP_FSYNCED=PASS \
 R26_L9C_REAL_GUEST_UP_FSYNC_AND_RELEASE=PASS \
 R26_L9C_SAME_RUN_TWO_SCOPED_RELEASES_AND_GUEST_DETACH=PASS \
 R24_B_ONE_REAL_QMP_DYNAMIC_ED25519_GUEST_LEASE_FSYNCED=PASS \
 R26_B_REAL_GUEST_PUB_MATCHES_PREBOOT_HOST_ENROLLMENT=PASS \
 R26_B_REAL_QMP_PREPINNED_GUEST_ED25519_TEST_ONLY=PASS \
 R26_B_SAME_RUN_ACTUAL_USBIP_VUDC=NOT_TESTED; do
 grep -Fq "$marker" "$log" || { echo "R24_B_MISSING_EXPECTED_PROOF=$marker";exit 23; }
done
# A second independently observed *real* QEMU session, reusing the
# unchanged disposable guest initrd but pre-enrolling the WRONG host key.
neg="$RUNNER_TEMP/r26-b-wrong-pin-real-qmp.log"
set +e
timeout 170s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2560m --memory-swap 2560m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 --entrypoint python3 "$image" -B /guest/r26-wrong-pin-oracle.py \
 >"$neg" 2>&1
neg_rc=$?
set -e
cat "$neg"
if [[ "$neg_rc" -ne 0 ]];then echo "R26_B_WRONG_PIN_ACTUAL_QEMU=RED rc=$neg_rc";exit 24;fi
for marker in \
 R26_B_WRONG_HOST_PIN_ESTABLISHED_BEFORE_QEMU_BOOT=PASS \
 R26_B_WRONG_ED25519_SIGNER_ACTUAL_GUEST_RECEIPT_DENIED=PASS \
 R26_B_WRONG_KEY_SECOND_LEASE_DENIED=PASS \
 R26_B_WRONG_HOST_PIN_HELD_AND_NO_READMISSION=PASS \
 R26_B_WRONG_KEY_ALL_DISPOSABLE_PROCESSES_STOPPED=PASS; do
 grep -Fq "$marker" "$neg" || { echo "R26_B_WRONG_PIN_MISSING=$marker";exit 25;}
done
test "$(git status --porcelain --untracked-files=all)" = "$before"
cleanup;trap - EXIT
echo R24_B_PUBLIC_DISPOSABLE_QMP_GUEST_PROOF_CLEANUP=PASS
echo R26_B_DISPOSABLE_GUEST_KEY_BUILD_AND_HOST_PIN_CLEANUP=PASS
