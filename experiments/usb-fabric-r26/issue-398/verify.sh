#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R26_N5C_SOURCE_DIRTY=RED;exit 11; }
snapshot(){
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
local_before="$(snapshot)"
vol_before="$(docker volume ls -q | LC_ALL=C sort)"
image="r26-n5c-vcard-${GITHUB_SHA:0:12}"
trap 'docker image rm -f "$image" >/dev/null 2>&1 || true' EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 12
echo "R26_N5C_BASE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --pull \
 -f experiments/usb-fabric-r26/issue-398/Dockerfile \
 --build-arg "BASE_IMAGE=$base" -t "$image" experiments/usb-fabric-r26/issue-398
timeout 100s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 1024m --memory-swap 1024m --cpus 2 --pids-limit 96 \
 --tmpfs /tmp:rw,nosuid,nodev,size=32m,mode=1777 \
 --tmpfs /run:rw,nosuid,nodev,size=16m,mode=1777 "$image"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$vol_before" ]] || { echo R26_N5C_VOLUME_TAINT=RED;exit 13; }
[[ "$(snapshot)" == "$local_before" ]] || { echo R26_N5C_LOCAL_TAINT=RED;exit 14; }
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || { echo R26_N5C_SOURCE_TAINT=RED;exit 15; }
echo R26_N5C_DISPOSABLE_SYNTHETIC_CLEANUP=PASS
echo R26_N5C_QEMU_USB_CCID_AND_REAL_CAC=NOT_TESTED
