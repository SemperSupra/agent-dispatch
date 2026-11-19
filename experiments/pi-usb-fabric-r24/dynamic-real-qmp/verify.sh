#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R24_B_DIRTY_INPUT=RED; exit 10; }
guest="public-r24b-qmp-ed25519-guest-${GITHUB_SHA:0:12}"
image="public-r24b-real-qmp-dynamic-lease-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r24-b-qmp-ed25519.log"
cleanup(){ docker image rm -f "$image" "$guest" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
deb="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
docker pull golang:1.23-bookworm >/dev/null
golang="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.23-bookworm)"
[[ "$deb" == *@sha256:* && "$golang" == *@sha256:* ]] || exit 11
echo "R24_B_PINNED_BUILD_DIGESTS=$deb $golang"
DOCKER_BUILDKIT=1 docker build --pull --no-cache \
  -f experiments/pi-usb-fabric-r24/dynamic-real-qmp/Dockerfile.guest \
  --build-arg "DEBIAN_BASE=$deb" --build-arg "GO_BASE=$golang" \
  -t "$guest" .
DOCKER_BUILDKIT=1 docker build --no-cache \
  -f experiments/pi-usb-fabric-r24/dynamic-real-qmp/Dockerfile.integrated \
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
 R24_B_GUEST_RUNTIME_KEY_TEST_PINNED_FROM_QEMU_SERIAL=PASS \
 R24_B_ACTUAL_R26_DYNAMIC_SCOPE_BOUND=PASS \
 R24_B_REAL_QMP_GUEST_ED25519_DOWN_AUTHORITY=PASS \
 R24_B_REAL_QMP_GUEST_ED25519_UP_FSYNCED=PASS \
 R26_L9C_REAL_GUEST_UP_FSYNC_AND_RELEASE=PASS \
 R26_L9C_SAME_RUN_TWO_SCOPED_RELEASES_AND_GUEST_DETACH=PASS \
 R24_B_ONE_REAL_QMP_DYNAMIC_ED25519_GUEST_LEASE_FSYNCED=PASS \
 R24_B_GUEST_SERIAL_ENROLLMENT_IS_TRUSTED_HARDWARE=NOT_TESTED \
 R24_B_SAME_RUN_CONFIGFS_VUDC_B_HANDOFF=NOT_TESTED; do
 grep -Fq "$marker" "$log" || { echo "R24_B_MISSING_EXPECTED_PROOF=$marker";exit 23; }
done
test "$(git status --porcelain --untracked-files=all)" = "$before"
cleanup;trap - EXIT
echo R24_B_PUBLIC_DISPOSABLE_QMP_GUEST_PROOF_CLEANUP=PASS
