#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R26_P2_SOURCE_DIRTY=RED;exit 11; }
local_before="$(if [[ -d "$HOME/.local" ]];then find "$HOME/.local" -type f -printf '%P %s %T@\n'|sort|sha256sum;else echo ABSENT;fi)"
vol_before="$(docker volume ls -q|sort)"
image="r26-p2-net-audio-${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1||true;docker builder prune -af >/dev/null 2>&1||true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 12
echo "R26_P2_BASE=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --pull \
 -f experiments/usb-fabric-r26/issue-405/Dockerfile \
 --build-arg "BASE_IMAGE=$base" -t "$image" experiments/usb-fabric-r26/issue-405
for mode in network audio;do
 echo "R26_P2_BEGIN_MODE=$mode"
 timeout 170s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2304m --memory-swap 2304m --cpus 2 --pids-limit 144 \
 --tmpfs /tmp:rw,nosuid,nodev,size=128m,mode=1777 "$image" --mode "$mode"
done
[[ "$(docker volume ls -q|sort)" == "$vol_before" ]] || { echo R26_P2_VOLUME_TAINT=RED;exit 13; }
[[ "$(if [[ -d "$HOME/.local" ]];then find "$HOME/.local" -type f -printf '%P %s %T@\n'|sort|sha256sum;else echo ABSENT;fi)" == "$local_before" ]] || exit 14
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || exit 15
cleanup;trap - EXIT
echo R26_P2_DISPOSABLE_NO_NETWORK_CLEANUP=PASS
