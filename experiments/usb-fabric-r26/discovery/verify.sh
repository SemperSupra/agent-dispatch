#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R26_G_SOURCE_INPUT_DIRTY=RED; exit 11; }
snap() {
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
local_before="$(snap)"
volumes_before="$(docker volume ls -q | LC_ALL=C sort)"
img="public-usbfabric-r26-g-${GITHUB_SHA:0:12}"
cleanup() {
 docker image rm -f "$img" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || { echo R26_G_UNPINNED_IMAGE=RED;exit 12; }
echo "R26_G_BASE=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --pull \
  -f experiments/usb-fabric-r26/discovery/Dockerfile \
  --build-arg "BASE_IMAGE=$base" \
  -t "$img" experiments/usb-fabric-r26/discovery
timeout 55s docker run --rm --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges --memory 1024m --memory-swap 1024m \
  --cpus 2 --pids-limit 96 --tmpfs /tmp:rw,nosuid,nodev,size=32m,mode=1777 "$img"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$volumes_before" ]] || { echo R26_G_VOLUMES_TAINT=RED;exit 13; }
[[ "$(snap)" == "$local_before" ]] || { echo R26_G_LOCAL_TAINT=RED;exit 14; }
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || { echo R26_G_SOURCE_TAINT=RED;exit 15; }
cleanup;trap - EXIT
echo R26_G_DISPOSABLE_CLEANUP=PASS
