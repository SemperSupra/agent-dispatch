#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
before_source="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$before_source" ]] || { echo R06_SOURCE_DIRTY=RED; exit 11; }
snapshot(){
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
before_local="$(snapshot)"
before_volumes="$(docker volume ls -q | LC_ALL=C sort)"
image="public-sandbox-r06:${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true;docker builder prune -af >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull ubuntu:24.04 >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04)"
[[ "$base" == *@sha256:* ]] || { echo R06_BASE_DIGEST=RED; exit 12; }
echo "R06_BASE_IMAGE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --pull --build-arg "BASE_IMAGE=$base" -t "$image" .
docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges --memory 512m \
 --memory-swap 512m --cpus 1 --pids-limit 128 \
 --tmpfs /tmp:rw,nosuid,nodev,size=32m,mode=1777 "$image"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$before_volumes" ]] || { echo R06_VOLUME_TAINT=RED; exit 13; }
[[ "$(snapshot)" == "$before_local" ]] || { echo R06_LOCAL_TAINT=RED; exit 14; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$before_source" ]] || { echo R06_CHECKOUT_TAINT=RED; exit 15; }
cleanup;trap - EXIT
if docker image inspect "$image" >/dev/null 2>&1;then echo R06_IMAGE_CLEANUP=RED; exit 16;fi
echo R06_EPHEMERAL_QEMU_IMAGE_AND_TOOLS_REMOVED=PASS
echo R06_HOME_PROJECT_LOCAL_AND_SOURCE_ZERO_TAINT=PASS
