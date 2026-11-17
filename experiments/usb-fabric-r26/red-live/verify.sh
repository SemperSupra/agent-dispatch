#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R26_H_SOURCE_INPUT_DIRTY=RED;exit 10; }
local_snapshot() {
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
before_local="$(local_snapshot)"
before_volumes="$(docker volume ls -q | LC_ALL=C sort)"
base="public-r26-h-base-${GITHUB_SHA:0:12}"
image="public-r26-h-crash-${GITHUB_SHA:0:12}"
cleanup() {
 docker image rm -f "$image" "$base" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
deb="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
docker pull golang:1.23-bookworm >/dev/null
golang="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.23-bookworm)"
[[ "$deb" == *@sha256:* && "$golang" == *@sha256:* ]] || { echo R26_H_UNPINNED_IMAGES=RED;exit 11; }
DOCKER_BUILDKIT=1 docker build --pull --no-cache \
 -f experiments/agent-sandbox-r15/Dockerfile --build-arg "BASE_IMAGE=$deb" \
 -t "$base" experiments/agent-sandbox-r15
DOCKER_BUILDKIT=1 docker build --no-cache \
 -f experiments/usb-fabric-r26/integrated/Dockerfile \
 --build-arg "R15_IMAGE=$base" --build-arg "GO_BASE=$golang" -t "$image" .
echo R26_H_INTEGRATION_RUNTIME_BUILD=PASS
set +e
timeout 110s docker run --rm -i --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2048m --memory-swap 2048m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 --entrypoint python3 "$image" - < experiments/usb-fabric-r26/red-live/crash_while_key_down.py
result=$?
set -e
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$before_volumes" ]] || { echo R26_H_VOLUME_TAINT=RED;exit 12; }
[[ "$(local_snapshot)" == "$before_local" ]] || { echo R26_H_LOCAL_TAINT=RED;exit 13; }
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || { echo R26_H_SOURCE_TAINT=RED;exit 14; }
cleanup;trap - EXIT
echo R26_H_DISPOSABLE_CLEANUP=PASS
if [[ "$result" == 17 ]];then
 echo R26_H_EXPECTED_P0_RELEASE_OMISSION_REPRODUCED=RED
 exit 17
fi
echo "R26_H_INCONCLUSIVE_OR_UNEXPECTED_EXIT=$result"
exit 15
