#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R26_L8_SOURCE_INPUT_DIRTY=RED;exit 11; }
snapshot() {
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
locals_before="$(snapshot)"
volumes_before="$(docker volume ls -q | LC_ALL=C sort)"
image="r26-l8-virtio-${GITHUB_SHA:0:12}"
cleanup(){
 docker image rm -f "$image" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
deb="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
docker pull golang:1.23-bookworm >/dev/null
golang="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.23-bookworm)"
[[ "$deb" == *@sha256:* && "$golang" == *@sha256:* ]] || { echo R26_L8_UNPINNED_BASE=RED;exit 12; }
echo "R26_L8_BASES=$deb $golang"
DOCKER_BUILDKIT=1 docker build --pull --no-cache \
 -f experiments/usb-fabric-r26/releasegate/guestwire/Dockerfile \
 --build-arg "DEBIAN_BASE=$deb" --build-arg "GO_BASE=$golang" \
 -t "$image" .
echo R26_L8_REAL_GUEST_RECEIPT_BUILD=PASS
timeout 215s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2048m --memory-swap 2048m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 "$image"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$volumes_before" ]] || { echo R26_L8_VOLUME_TAINT=RED;exit 13; }
[[ "$(snapshot)" == "$locals_before" ]] || { echo R26_L8_LOCAL_TAINT=RED;exit 14; }
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || { echo R26_L8_SOURCE_TAINT=RED;exit 15; }
cleanup;trap - EXIT
echo R26_L8_DISPOSABLE_CLEANUP=PASS
echo R26_L8_PRODUCTION_GUEST_ATTESTATION=NOT_TESTED
echo R26_L8_JOURNAL_FSYNC_AND_NEW_LEASE=NOT_TESTED
