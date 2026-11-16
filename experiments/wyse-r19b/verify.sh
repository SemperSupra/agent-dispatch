#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
case "$R19B_LANE" in
 input) test_name=TestRealLocalQMPKeyboardAndRelease ;;
 race) test_name=TestConcurrentActualQMPAndRevokeBarrier ;;
 deny) test_name=TestUnauthorizedAndAmbiguousQMPFailureFailClosed ;;
 *) echo R19B_UNKNOWN_LANE=RED; exit 2 ;;
esac
root="$(git rev-parse --show-toplevel)"
pinned="$GITHUB_WORKSPACE/r19-source"
[[ "$(git -C "$pinned" rev-parse HEAD)" == 86b377a4b2d351aea3016852311a9100d8a76230 ]] || { echo R19B_R19_SOURCE_DRIFT=RED;exit 10; }
old_source="$(git -C "$root" status --porcelain --untracked-files=all)"
old_pin="$(git -C "$pinned" status --porcelain --untracked-files=all)"
[[ -z "$old_source" && -z "$old_pin" ]] || { echo R19B_SOURCE_INPUT_DIRTY=RED;exit 11; }
snapshot(){ for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local" "$pinned/.local";do
 if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
done; }
old_local="$(snapshot)"
old_vol="$(docker volume ls -q | LC_ALL=C sort)"
tag="r19b-${R19B_LANE}:${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$tag" >/dev/null 2>&1 || true;docker builder prune -af >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull golang:1.24-bookworm >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.24-bookworm)"
[[ "$base" == *@sha256:* ]] || { echo R19B_NO_DIGEST_BASE=RED;exit 12; }
echo "R19B_SOURCE_PIN_AND_BASE=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --pull --build-context "r19=$pinned" \
 --build-arg "BASE_IMAGE=$base" -t "$tag" .
docker run --rm --network none --read-only --user 65532:65532 --cap-drop ALL \
 --security-opt no-new-privileges --memory 2g --memory-swap 2g --cpus 2 --pids-limit 192 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=320m,mode=1777 "$tag" -run "^${test_name}$" ./...
echo "R19B_REAL_QMP_LANE_${R19B_LANE}=PASS"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$old_vol" ]] || { echo R19B_VOLUME_TAINT=RED;exit 13; }
[[ "$(snapshot)" == "$old_local" ]] || { echo R19B_LOCAL_TAINT=RED;exit 14; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$old_source" ]] || { echo R19B_SRC_TAINT=RED;exit 15; }
[[ "$(git -C "$pinned" status --porcelain --untracked-files=all)" == "$old_pin" ]] || { echo R19B_R19_SRC_TAINT=RED;exit 16; }
cleanup;trap - EXIT
if docker image inspect "$tag" >/dev/null 2>&1;then echo R19B_IMAGE_REMAINING=RED;exit 17;fi
echo R19B_DISPOSABLE_QEMU_GO_IMAGE_CLEANUP=PASS
echo R19B_HOME_PROJECT_LOCAL_AND_SOURCE_ZERO_TAINT=PASS
echo R19B_REAL_GUEST_EVDEV_CROSS_HOST_FENCING=NOT_TESTED
