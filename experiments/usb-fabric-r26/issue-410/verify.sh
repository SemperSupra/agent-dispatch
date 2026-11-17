#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R26_P1B_SOURCE_DIRTY=RED;exit 11; }
base="$(docker pull debian:trixie-slim >/dev/null && docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 12
echo "R26_P1B_BASE=$base"
image="r26-p1b-pcsc-${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; docker builder prune -af >/dev/null 2>&1 || true; }
trap cleanup EXIT
vol_before="$(docker volume ls -q|sort)"
DOCKER_BUILDKIT=1 docker build --no-cache --pull \
 -f experiments/usb-fabric-r26/issue-410/Dockerfile \
 --build-arg "BASE_IMAGE=$base" -t "$image" experiments/usb-fabric-r26
timeout 100s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 1024m --memory-swap 1024m --cpus 2 --pids-limit 96 \
 --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 \
 --tmpfs /run:rw,nosuid,nodev,size=16m,mode=1777 "$image"
[[ "$(docker volume ls -q|sort)" == "$vol_before" ]] || exit 13
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || exit 14
cleanup;trap - EXIT
echo R26_P1B_DISPOSABLE_TEST_ONLY_PCSC_CLEANUP=PASS
echo R26_P1B_ACTUAL_GUEST_USB_CCID_REAL_GOVERNMENT_CAC=NOT_TESTED
