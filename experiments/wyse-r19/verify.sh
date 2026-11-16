#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
case "$R19_LANE" in
 race) test_name=TestRaceRevocationLinearization ;;
 restart) test_name=TestRestartMonotoneEpochAndFailClose ;;
 deny) test_name=TestInvalidScopeIdempotencyAndAmbiguousEffect ;;
 *) echo R19_UNKNOWN_LANE=RED;exit 2 ;;
esac
root="$(git rev-parse --show-toplevel)"
before="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R19_INPUT_DIRTY=RED;exit 10; }
snapshot() {
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
old_local="$(snapshot)"
old_vol="$(docker volume ls -q | LC_ALL=C sort)"
tag="r19-${R19_LANE}:${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$tag" >/dev/null 2>&1 || true; docker builder prune -af >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull golang:1.24-bookworm >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.24-bookworm)"
[[ "$base" == *@sha256:* ]] || { echo R19_UNPINNED_BASE=RED;exit 11; }
echo "R19_BASE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --pull --build-arg "BASE_IMAGE=$base" -t "$tag" .
docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges --memory 1536m --memory-swap 1536m \
 --cpus 2 --pids-limit 160 --tmpfs /tmp:rw,exec,nosuid,nodev,size=256m,mode=1777 \
 "$tag" -run "^${test_name}$" ./...
echo "R19_EXACT_LANE_${R19_LANE}_GO_RACE=PASS"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$old_vol" ]] || { echo R19_VOLUME_TAINT=RED;exit 12; }
[[ "$(snapshot)" == "$old_local" ]] || { echo R19_LOCAL_TAINT=RED;exit 13; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$before" ]] || { echo R19_SOURCE_TAINT=RED;exit 14; }
cleanup;trap - EXIT
if docker image inspect "$tag" >/dev/null 2>&1;then echo R19_IMAGE_CLEANUP=RED;exit 15;fi
echo R19_DISPOSABLE_GO_TOOLCHAIN_AND_RUNTIME_REMOVED=PASS
echo R19_HOME_PROJECT_LOCAL_AND_SOURCE_ZERO_TAINT=PASS
echo R19_REAL_QMP_CROSS_HOST_LOCK_PHYSICAL_USB=NOT_TESTED
