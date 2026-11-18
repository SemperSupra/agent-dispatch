#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
test -z "$(git status --porcelain --untracked-files=all)"
image="pi-usb-r09a-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r09-link-fault.log"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 11
echo "R08_BASE_IMAGE=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --build-arg "BASE=$base" \
 -f experiments/pi-usb-fabric-r08/two-guest/Dockerfile -t "$image" .
set +e
timeout 215s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 4096m --memory-swap 4096m --cpus 3 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 "$image" >"$log" 2>&1
rc=$?
set -e
cat "$log"
if [[ "$rc" -ne 0 ]];then echo "R08_TWO_GUEST_RUN=RED rc=$rc"; exit 22; fi
grep -q 'R09_REAL_GUEST_KEY_UP_AFTER_NETWORK_LOSS=PASS' "$log"
cleanup
trap - EXIT
test -z "$(git status --porcelain --untracked-files=all)"
echo R09_LINK_FAULT_CLOUD_CLEANUP=PASS
