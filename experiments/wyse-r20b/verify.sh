#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
case "$R20B_LANE" in kernel|backend|exporter) ;; *) echo R20B_INVALID_LANE=RED;exit 2;; esac
root="$(git rev-parse --show-toplevel)"
old="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$old" ]] || { echo R20B_SOURCE_INPUT_DIRTY=RED;exit 10; }
snapshot(){ for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
 if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
done; }
prev_local="$(snapshot)"
prev_vol="$(docker volume ls -q | LC_ALL=C sort)"
tag="public-r20b-${R20B_LANE}:${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$tag" >/dev/null 2>&1 || true;docker builder prune -af >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || { echo R20B_NO_DIGEST_PIN=RED;exit 11; }
DOCKER_BUILDKIT=1 docker build --pull --no-cache --build-arg "BASE_IMAGE=$base" -t "$tag" .
docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges --memory 768m --memory-swap 768m \
 --cpus 2 --pids-limit 100 --tmpfs /tmp:rw,nosuid,nodev,size=32m,mode=1777 \
 "$tag" --lane "$R20B_LANE"
echo "R20B_EXACT_LANE_${R20B_LANE}_CAPABILITY_SURVEY=PASS"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$prev_vol" ]] || { echo R20B_VOLUMES_TAINT=RED;exit 12; }
[[ "$(snapshot)" == "$prev_local" ]] || { echo R20B_LOCAL_TAINT=RED;exit 13; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$old" ]] || { echo R20B_SRC_TAINT=RED;exit 14; }
cleanup;trap - EXIT
if docker image inspect "$tag" >/dev/null 2>&1;then echo R20B_IMAGE_REMAINING=RED;exit 15;fi
echo R20B_DISPOSABLE_LINUX_KERNEL_QEMU_TOOLCHAIN_CLEANED=PASS
echo R20B_HOME_PROJECT_LOCAL_AND_SOURCE_ZERO_TAINT=PASS
echo R20B_LIVE_KERNEL_USBIP_GUEST_DRIVER_AND_URB=NOT_TESTED
