#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R26_N4_SOURCE_DIRTY=RED; exit 11; }
local_snapshot() {
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
loc_before="$(local_snapshot)"
vol_before="$(docker volume ls -q | LC_ALL=C sort)"
image="r26-n4-intl-keyboard-${GITHUB_SHA:0:12}"
cleanup() {
 docker image rm -f "$image" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull golang:1.23-bookworm >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.23-bookworm)"
[[ "$base" == *@sha256:* ]] || exit 12
echo "R26_N4_GO_BASE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --no-cache \
 -f experiments/usb-fabric-r26/issue-393/Dockerfile \
 --build-arg "GO_BASE=$base" -t "$image" experiments/usb-fabric-r26/issue-393
timeout 35s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges --memory 1024m --memory-swap 1024m \
 --cpus 2 --pids-limit 96 --tmpfs /tmp:rw,nosuid,nodev,size=32m,mode=1777 "$image"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$vol_before" ]] || exit 13
[[ "$(local_snapshot)" == "$loc_before" ]] || exit 14
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || exit 15
cleanup
trap - EXIT
echo R26_N4_PUBLIC_FREE_SYNTHETIC_CLEANUP=PASS
echo R26_N4_PHYSICAL_KEYCOUNT_AND_GUEST_IME=NOT_TESTED
