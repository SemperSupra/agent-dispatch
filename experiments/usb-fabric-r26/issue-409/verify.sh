#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R26_P5_SOURCE_DIRTY=RED;exit 11; }
snapshot() {
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
local_before="$(snapshot)"
vol_before="$(docker volume ls -q|LC_ALL=C sort)"
image="r26-p5-mix-${GITHUB_SHA:0:12}"
cleanup(){
 docker image rm -f "$image" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
deb="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$deb" == *@sha256:* ]] || exit 12
echo "R26_P5_BASE=$deb"
DOCKER_BUILDKIT=1 docker build --no-cache --pull \
 -f experiments/usb-fabric-r26/issue-409/Dockerfile \
 --build-arg "BASE_IMAGE=$deb" -t "$image" .
timeout 350s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2304m --memory-swap 2304m --cpus 2 --pids-limit 144 \
 --tmpfs /tmp:rw,nosuid,nodev,size=192m,mode=1777 "$image"
[[ "$(docker volume ls -q|LC_ALL=C sort)" == "$vol_before" ]] || { echo R26_P5_VOLUME_TAINT=RED;exit 13; }
[[ "$(snapshot)" == "$local_before" ]] || { echo R26_P5_LOCAL_TAINT=RED;exit 14; }
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || { echo R26_P5_SOURCE_TAINT=RED;exit 15; }
cleanup;trap - EXIT
echo R26_P5_DISPOSABLE_CLEANUP=PASS
