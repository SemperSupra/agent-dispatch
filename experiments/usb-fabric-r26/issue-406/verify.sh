#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R26_P3_SOURCE_DIRTY=RED;exit 11; }
before_vol="$(docker volume ls -q|sort)"
base="$(docker pull debian:trixie-slim >/dev/null && docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 12
echo "R26_P3_BASE=$base"
img="r26-p3-optical-${GITHUB_SHA:0:12}"
cleanup(){docker image rm -f "$img" >/dev/null 2>&1 || true;docker builder prune -af >/dev/null 2>&1||true;}
trap cleanup EXIT
DOCKER_BUILDKIT=1 docker build --no-cache --pull \
 -f experiments/usb-fabric-r26/issue-406/Dockerfile \
 --build-arg "BASE_IMAGE=$base" -t "$img" experiments/usb-fabric-r26/issue-406
for kind in iso9660 udf;do
 echo "R26_P3_MEDIA_TEST=$kind"
 timeout 155s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2304m --memory-swap 2304m --cpus 2 --pids-limit 144 \
 --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 "$img" --kind "$kind"
done
[[ "$(docker volume ls -q|sort)" == "$before_vol" ]] || { echo R26_P3_VOLUME_TAINT=RED;exit 13; }
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || { echo R26_P3_SOURCE_TAINT=RED;exit 14; }
cleanup;trap - EXIT
echo R26_P3_DISPOSABLE_CLEANUP=PASS
