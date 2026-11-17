#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
source_before="$(git status --porcelain --untracked-files=all)"
[[ -z "$source_before" ]] || { echo R26_L6_SOURCE_INPUT_DIRTY=RED; exit 11; }
snapshot() {
  for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
    if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
  done
}
local_before="$(snapshot)"
volumes_before="$(docker volume ls -q | LC_ALL=C sort)"
base="public-r26-base-${GITHUB_SHA:0:12}"
image="public-r26-l6-${GITHUB_SHA:0:12}"
cleanup() {
  docker image rm -f "$image" "$base" >/dev/null 2>&1 || true
  docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker pull debian:trixie-slim >/dev/null
deb="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
docker pull golang:1.23-bookworm >/dev/null
golang="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.23-bookworm)"
[[ "$deb" == *@sha256:* && "$golang" == *@sha256:* ]] || { echo R26_L6_UNPINNED_BASE=RED;exit 12; }
echo "R26_L6_BASES=$deb $golang"

DOCKER_BUILDKIT=1 docker build --pull --no-cache \
 -f experiments/agent-sandbox-r15/Dockerfile \
 --build-arg "BASE_IMAGE=$deb" -t "$base" experiments/agent-sandbox-r15
DOCKER_BUILDKIT=1 docker build --no-cache \
 -f experiments/usb-fabric-r26/integrated/Dockerfile \
 --build-arg "R15_IMAGE=$base" --build-arg "GO_BASE=$golang" \
 -t "$image" .
echo R26_L6_SOLE_QMP_ACTUATOR_BUILD=PASS
timeout 210s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2048m --memory-swap 2048m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 --entrypoint python3 "$image" -B /guest/r26-l6-dual-qmp-owner-oracle.py

[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$volumes_before" ]] || { echo R26_L6_VOLUME_TAINT=RED;exit 13; }
[[ "$(snapshot)" == "$local_before" ]] || { echo R26_L6_LOCAL_TAINT=RED;exit 14; }
[[ "$(git status --porcelain --untracked-files=all)" == "$source_before" ]] || { echo R26_L6_SOURCE_TAINT=RED;exit 15; }
cleanup
trap - EXIT
if docker image inspect "$image" >/dev/null 2>&1;then echo R26_L6_IMAGE_CLEANUP=RED;exit 16;fi
echo R26_L6_DISPOSABLE_CLEANUP=PASS
echo R26_L6_DEVICE_USBIP_OR_PHYSICAL_FORWARDING=NOT_TESTED
echo R26_L6_HARDENED_AUTHENTICATED_MULTI_HOST=NOT_TESTED
echo R26_L6_OS_PROCESS_OWNER_FENCING=INTEGRATION_ONLY
echo R26_L6_PUBLIC_SYNTHETIC_PROCESS_CRASH_ONLY=PASS
