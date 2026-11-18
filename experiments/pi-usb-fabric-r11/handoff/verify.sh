#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
test -z "$(git status --porcelain --untracked-files=all)"
image="pi-usb-r11a-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r11-handoff.log"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 11
echo "R08_BASE_IMAGE=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --build-arg "BASE=$base" \
 -f experiments/pi-usb-fabric-r11/handoff/Dockerfile -t "$image" .
set +e
timeout 255s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 5120m --memory-swap 5120m --cpus 3 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 "$image" >"$log" 2>&1
rc=$?
set -e
cat "$log"
if [[ "$rc" -ne 0 ]];then echo "R11_THREE_GUEST_HANDOFF=RED rc=$rc"; exit 22; fi
grep -q 'R11_THREE_KERNELS_SEQUENTIAL_HID_HANDOFF=PASS' "$log"
cleanup
trap - EXIT
test -z "$(git status --porcelain --untracked-files=all)"
echo R11_THREE_GUEST_CLOUD_CLEANUP=PASS
