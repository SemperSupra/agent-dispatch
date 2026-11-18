#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R26_L9C_DIRTY_SOURCE=RED; exit 11; }
snapshot(){
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum; else echo ABSENT;fi
 done
}
local_before="$(snapshot)"
volumes_before="$(docker volume ls -q | LC_ALL=C sort)"
guest="public-r26-l9c-guest-${GITHUB_SHA:0:12}"
image="public-r26-l9c-actuator-${GITHUB_SHA:0:12}"
cleanup(){
 docker image rm -f "$image" "$guest" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
deb="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
docker pull golang:1.23-bookworm >/dev/null
golang="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.23-bookworm)"
[[ "$deb" == *@sha256:* && "$golang" == *@sha256:* ]] || exit 12
echo "R26_L9C_BASES=$deb $golang"

DOCKER_BUILDKIT=1 docker build --pull --no-cache \
 -f experiments/usb-fabric-r26/releasegate/guestwire/Dockerfile \
 --build-arg "DEBIAN_BASE=$deb" --build-arg "GO_BASE=$golang" \
 -t "$guest" .
DOCKER_BUILDKIT=1 docker build --no-cache \
 -f experiments/usb-fabric-r26/integrated/Dockerfile \
 --build-arg "R15_IMAGE=$guest" --build-arg "GO_BASE=$golang" \
 -t "$image" .
echo R26_L9C_ACTUAL_GUEST_AND_ACTUATOR_BUILD=PASS
timeout 230s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2048m --memory-swap 2048m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 --entrypoint python3 "$image" -B /guest/r26-l9c-scoped-release-detach-oracle.py
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$volumes_before" ]] || { echo R26_L9C_VOLUME_TAINT=RED;exit 13; }
[[ "$(snapshot)" == "$local_before" ]] || { echo R26_L9C_LOCAL_TAINT=RED;exit 14; }
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || { echo R26_L9C_SOURCE_TAINT=RED;exit 15; }
cleanup;trap - EXIT
echo R26_L9C_DISPOSABLE_CLEANUP=PASS
echo R26_L9C_PHYSICAL_USB_AND_PRODUCTION_AUTH=NOT_TESTED
