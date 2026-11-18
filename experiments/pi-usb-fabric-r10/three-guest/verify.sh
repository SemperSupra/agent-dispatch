#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
test -z "$(git status --porcelain --untracked-files=all)"
image="pi-usb-r10a-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r10-three-guest.log"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 11
echo "R08_BASE_IMAGE=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --build-arg "BASE=$base" \
 -f experiments/pi-usb-fabric-r10/three-guest/Dockerfile -t "$image" .
set +e
timeout 235s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 5120m --memory-swap 5120m --cpus 3 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 "$image" >"$log" 2>&1
rc=$?
set -e
cat "$log"
if [[ "$rc" -ne 0 ]];then echo "R08_TWO_GUEST_RUN=RED rc=$rc"; exit 22; fi
grep -q 'R10_THREE_KERNELS_SINGLE_VUDC_CONTENTION=PASS' "$log"
cleanup
trap - EXIT
test -z "$(git status --porcelain --untracked-files=all)"
echo R10_THREE_GUEST_CLOUD_CLEANUP=PASS
