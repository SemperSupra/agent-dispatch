#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R26_M2_SOURCE_DIRTY=RED; exit 11; }
local_snapshot() {
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
loc_before="$(local_snapshot)"
vol_before="$(docker volume ls -q | LC_ALL=C sort)"
base="r26-m2-base-${GITHUB_SHA:0:12}"
image="r26-m2-guest-${GITHUB_SHA:0:12}"
cleanup() {
 docker image rm -f "$image" "$base" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
deb="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$deb" == *@sha256:* ]] || exit 12
echo "R26_M2_BASE_DIGEST=$deb"
DOCKER_BUILDKIT=1 docker build --no-cache --pull \
 -f experiments/agent-sandbox-r15/Dockerfile \
 --build-arg "BASE_IMAGE=$deb" \
 -t "$base" experiments/agent-sandbox-r15
DOCKER_BUILDKIT=1 docker build --no-cache \
 -f experiments/usb-fabric-r26/matrix-388/Dockerfile \
 --build-arg "R15_IMAGE=$base" \
 -t "$image" experiments/usb-fabric-r26/matrix-388
for mode in usb-storage usb-bot usb-uas; do
 echo "R26_M2_GUEST_START=$mode"
 timeout 135s docker run --rm --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 2048m --memory-swap 2048m --cpus 2 --pids-limit 128 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 \
  "$image" --mode "$mode"
done
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$vol_before" ]] || { echo R26_M2_VOLUME_TAINT=RED; exit 13; }
[[ "$(local_snapshot)" == "$loc_before" ]] || { echo R26_M2_LOCAL_TAINT=RED; exit 14; }
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || { echo R26_M2_SOURCE_TAINT=RED; exit 15; }
cleanup
trap - EXIT
echo R26_M2_DISPOSABLE_CLEANUP=PASS
echo R26_M2_PHYSICAL_USB_HOST_PASSTHROUGH=NOT_TESTED
