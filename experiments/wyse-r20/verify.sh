#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
case "$R20_LANE" in
 discovery) test_name=TestActualUpstreamClientDeviceDiscovery ;;
 urb) test_name=TestSyntheticImportSubmitAndUnlinkWire ;;
 malformed) test_name=TestMalformedFramesAreClosedAndUnknownDeviceDenied ;;
 *) echo R20_UNKNOWN_LANE=RED;exit 2 ;;
esac
root="$(git rev-parse --show-toplevel)"
old_source="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$old_source" ]] || { echo R20_INPUT_DIRTY=RED;exit 10; }
snapshot(){
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
old_local="$(snapshot)"
old_vol="$(docker volume ls -q | LC_ALL=C sort)"
tag="r20-${R20_LANE}:${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$tag" >/dev/null 2>&1 || true;docker builder prune -af >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull golang:1.24-bookworm >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.24-bookworm)"
[[ "$base" == *@sha256:* ]] || { echo R20_UNPINNED_TOOL_BASE=RED;exit 11; }
echo "R20_BASE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --pull --build-arg "BASE_IMAGE=$base" -t "$tag" .
docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges --memory 1536m --memory-swap 1536m \
 --cpus 2 --pids-limit 160 --tmpfs /tmp:rw,exec,nosuid,nodev,size=256m,mode=1777 \
 "$tag" -run "^${test_name}$" ./...
echo "R20_EXACT_LANE_${R20_LANE}_GO_RACE=PASS"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$old_vol" ]] || { echo R20_VOLUME_TAINT=RED;exit 12; }
[[ "$(snapshot)" == "$old_local" ]] || { echo R20_LOCAL_TAINT=RED;exit 13; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$old_source" ]] || { echo R20_SOURCE_TAINT=RED;exit 14; }
cleanup;trap - EXIT
if docker image inspect "$tag" >/dev/null 2>&1;then echo R20_IMAGE_TAINT=RED;exit 15;fi
echo R20_DISPOSABLE_USBIP_TOOLCHAIN_AND_RUNTIME_REMOVED=PASS
echo R20_HOME_PROJECT_LOCAL_AND_SOURCE_ZERO_TAINT=PASS
echo R20_REAL_KERNEL_VHCI_QEMU_GUEST_URB=NOT_TESTED
