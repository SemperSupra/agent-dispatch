#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
test -z "$(git status --porcelain --untracked-files=all)"
stage="$(mktemp -d)"
image="usbnet-g3b-${GITHUB_SHA:0:12}"
log="${RUNNER_TEMP:-/tmp}/usbnet-g3b-two-guest.log"
cleanup() { docker image rm -f "$image" >/dev/null 2>&1 || :; rm -rf "$stage"; }
trap cleanup EXIT
python3 experiments/usb-fabric-network-n1/g3b/prepare.py "$stage"
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || { echo N3_G3B_BASE_UNPINNED_RED; exit 11; }
echo "N3_G3B_BASE_IMAGE=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --build-arg "BASE=$base" \
  -f "$stage/experiments/pi-usb-fabric-r08/two-guest/Dockerfile" -t "$image" "$stage"
set +e
timeout 215s docker run --rm --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 4096m --memory-swap 4096m --cpus 3 --pids-limit 128 \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 "$image" > "$log" 2>&1
rc=$?
set -e
cat "$log"
if [[ "$rc" != 0 ]]; then echo "N3_G3B_TWO_GUEST=RED rc=$rc"; exit 22; fi
for oracle in R08_TWO_SEPARATE_QEMU_KERNELS_REMOTE_USBIP_HID=PASS \
 R08_CONSUMER_REAL_REMOTE_HID_DATA=PASS R08_CONSUMER_DETACH=PASS \
 N3_PROVIDER_NFT_DENY_POLICY=PASS \
 N3_CONSUMER_UNAUTHORIZED_SOURCE_DENIED=PASS \
 N3_CONSUMER_NETWORK_RESTORED=PASS; do
  if ! grep -Fq "$oracle" "$log"; then echo "N3_G3B_MISSING_ORACLE=$oracle";exit 23;fi
done
echo N3_G3B_NFT_RESTRICTED_REAL_USBIP_DATA=PASS
echo N3_G3B_BROKER_AND_PHYSICAL_PI=NOT_TESTED
test -z "$(git status --porcelain --untracked-files=all)"
