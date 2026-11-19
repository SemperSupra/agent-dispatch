#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R22_A_DIRTY_INPUT=RED; exit 11; }
image="public-r22a-real-guest-ed25519-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r22-a-real-qemu-guest-ed25519.log"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
deb="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
docker pull golang:1.23-bookworm >/dev/null
golang="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.23-bookworm)"
[[ "$deb" == *@sha256:* && "$golang" == *@sha256:* ]] || exit 12
echo "R22_A_PINNED_BASE_DIGESTS=$deb $golang"
DOCKER_BUILDKIT=1 docker build --pull --no-cache \
  --build-arg "DEBIAN_BASE=$deb" --build-arg "GO_BASE=$golang" \
  -f experiments/pi-usb-fabric-r22/guest-ed25519/Dockerfile \
  -t "$image" .
set +e
timeout 250s docker run --rm --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 2560m --memory-swap 2560m --cpus 2 --pids-limit 128 \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
  "$image" >"$log" 2>&1
rc=$?
set -e
cat "$log"
if [[ "$rc" -ne 0 ]]; then echo "R22_A_REAL_QEMU_GUEST_SIGNING=RED rc=$rc"; exit 22; fi
for marker in \
  R22_A_REAL_QEMU_GUEST_ED25519_DOWN_VERIFIED=PASS \
  R22_A_BAD_SIGNATURE_AND_CHALLENGE_DENIED=PASS \
  R22_A_REAL_QEMU_GUEST_ED25519_UP_VERIFIED=PASS \
  R22_A_TAMPERED_EVENT_AND_TRANSPORT_PROOF_DENIED=PASS \
  R22_A_SAME_RUN_REAL_QMP_EVDEV_SIGNED_GUEST_RECEIPTS=PASS \
  R22_A_ACTUAL_GUEST_ED25519_IS_R26_RELEASE_GATE_AUTHORITY=PASS \
  R26_L8_SIGNED_EVENT_REPLAY_REJECTED=PASS \
  R22_A_GUEST_PUBLIC_KEY_IDENTITY_ATTESTATION=NOT_TESTED; do
  grep -q "$marker" "$log" || { echo "R22_A_MISSING_ORACLE=RED $marker";exit 25; }
done
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || exit 26
cleanup
trap - EXIT
echo R22_A_REAL_QEMU_GUEST_SIGNING_TEST_ONLY_CLEAN=PASS
