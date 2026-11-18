#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
test -z "$(git status --porcelain --untracked-files=all)"
image="pi-usb-r04d-${GITHUB_SHA:0:12}"
network="pi-usb-r04d-${GITHUB_RUN_ID}"
cleanup(){
 docker network rm "$network" >/dev/null 2>&1 || true
 docker image rm -f "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull ubuntu:24.04 >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04)"
[[ "$base" == *@sha256:* ]] || exit 30
echo "USBIPD_BASE=$base"
docker build --pull --no-cache --build-arg "BASE=$base" -f experiments/pi-usb-fabric-r04/usbipd/Containerfile -t "$image" experiments/pi-usb-fabric-r04/usbipd
docker network create --internal "$network" >/dev/null
timeout 50s docker run --rm --network "$network" --read-only --user 65532:65532 --cap-drop ALL \
 --security-opt no-new-privileges --memory 512m --cpus 1 --pids-limit 64 \
 --tmpfs /tmp:rw,nosuid,nodev,size=16m,mode=1777 "$image"
test -z "$(docker ps -aq --filter label=pi-usb-fabric-r04d)"
cleanup
trap - EXIT
test -z "$(git status --porcelain --untracked-files=all)"
echo USBIPD_CLOUD_DISPOSABLE_CLEANUP=PASS
