#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R26_N5_INPUT_DIRTY=RED;exit 11; }
snap() {
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
local_before="$(snap)"
vol_before="$(docker volume ls -q | LC_ALL=C sort)"
base="r26-n5-base-${GITHUB_SHA:0:12}"
image="r26-n5-ccid-${GITHUB_SHA:0:12}"
cleanup() {
 docker image rm -f "$image" "$base" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
deb="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
docker pull golang:1.23-bookworm >/dev/null
golang="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.23-bookworm)"
[[ "$deb" == *@sha256:* && "$golang" == *@sha256:* ]] || exit 12
echo "R26_N5_BASE_DIGESTS=$deb $golang"
DOCKER_BUILDKIT=1 docker build --no-cache --pull -f experiments/agent-sandbox-r15/Dockerfile \
 --build-arg "BASE_IMAGE=$deb" -t "$base" experiments/agent-sandbox-r15
DOCKER_BUILDKIT=1 docker build --no-cache -f experiments/usb-fabric-r26/issue-394/Dockerfile \
 --build-arg "R15_IMAGE=$base" --build-arg "GO_BASE=$golang" \
 -t "$image" experiments/usb-fabric-r26/issue-394
timeout 150s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2048m --memory-swap 2048m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,nosuid,nodev,size=120m,mode=1777 "$image"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$vol_before" ]] || { echo R26_N5_VOLUMES_TAINT=RED;exit 13; }
[[ "$(snap)" == "$local_before" ]] || { echo R26_N5_LOCAL_TAINT=RED;exit 14; }
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || { echo R26_N5_SOURCE_TAINT=RED;exit 15; }
cleanup
trap - EXIT
echo R26_N5_DISPOSABLE_SYNTHETIC_CERT_CLEANUP=PASS
