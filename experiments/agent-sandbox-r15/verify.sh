#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
source_before="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$source_before" ]] || { echo R15_INPUT_DIRTY=RED; exit 10; }
snapshot(){
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
local_before="$(snapshot)"
volumes_before="$(docker volume ls -q | LC_ALL=C sort)"
image="public-r15-${GITHUB_SHA:0:12}"
cleanup(){
 docker image rm -f "$image" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || { echo R15_DEBIAN_BASE_NOT_DIGEST_PINNED=RED;exit 11; }
echo "R15_BASE_REFERENCE=$base"
DOCKER_BUILDKIT=1 docker build --pull --no-cache -f Dockerfile --build-arg "BASE_IMAGE=$base" -t "$image" .
echo R15_DISPOSABLE_DEBIAN_KERNEL_AND_DRIVER_BUILD=PASS
docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2048m --memory-swap 2048m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,nosuid,nodev,size=16m,mode=1777 "$image"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$volumes_before" ]] || { echo R15_VOLUME_TAINT=RED;exit 12; }
[[ "$(snapshot)" == "$local_before" ]] || { echo R15_LOCAL_TAINT=RED;exit 13; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$source_before" ]] || { echo R15_SOURCE_TAINT=RED;exit 14; }
cleanup;trap - EXIT
if docker image inspect "$image" >/dev/null 2>&1;then echo R15_IMAGE_CLEANUP=RED;exit 15;fi
echo R15_DISPOSABLE_KERNEL_QEMU_AND_RUNTIME_CLEANUP=PASS
echo R15_HOME_PROJECT_LOCAL_SOURCE_ZERO_TAINT=PASS
