#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
source_before="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$source_before" ]] || { echo R12_SOURCE_DIRTY=RED; exit 10; }
watch_paths(){
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
local_before="$(watch_paths)"
vol_before="$(docker volume ls -q | LC_ALL=C sort)"
image="public-r12-${GITHUB_SHA:0:12}"
cleanup(){
 docker image rm -f "$image" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || { echo R12_BASE_DIGEST_INVALID=RED; exit 11; }
echo "R12_BASE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --pull --no-cache -f Dockerfile \
 --build-arg "BASE_IMAGE=$base" -t "$image" .
docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 128m --memory-swap 128m --cpus 1 --pids-limit 48 \
 --tmpfs /tmp:rw,nosuid,nodev,noexec,size=8m,mode=1777 "$image"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$vol_before" ]] || { echo R12_VOLUME_TAINT=RED; exit 12; }
[[ "$(watch_paths)" == "$local_before" ]] || { echo R12_LOCAL_TAINT=RED; exit 13; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$source_before" ]] || { echo R12_CHECKOUT_TAINT=RED; exit 14; }
cleanup; trap - EXIT
if docker image inspect "$image" >/dev/null 2>&1;then echo R12_IMAGE_TAINT=RED;exit 15;fi
echo R12_ALL_USBIP_TOOLS_MOCK_SERVER_AND_CACHE_DISPOSED=PASS
echo R12_HOME_PROJECT_LOCAL_AND_SOURCE_ZERO_TAINT=PASS
