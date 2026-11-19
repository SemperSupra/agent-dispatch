#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
test -z "$(git status --porcelain --untracked-files=all | grep -v '.r18-existing-go' || true)"
image="pi-usb-r21-467-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r21-restart-467.log"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 11
echo "R08_BASE_IMAGE=$base"
test -d .r18-existing-go/experiments/usb-fabric-r26/integrated
test "$(git -C .r18-existing-go rev-parse HEAD)" = "2e580a0162452a6f59a449f769f9bfc5153e0aa3"
DOCKER_BUILDKIT=1 docker build --no-cache --build-context gosource=.r18-existing-go --build-arg "BASE=$base" \
 -f experiments/pi-usb-fabric-r21/restart-fence/live-Dockerfile -t "$image" .
set +e
timeout 270s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 5120m --memory-swap 5120m --cpus 3 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 "$image" >"$log" 2>&1
rc=$?
set -e
cat "$log"
if [[ "$rc" -ne 0 ]];then echo "R18_REAL_KERNEL_BROKER_GATE=RED rc=$rc"; exit 22; fi
grep -q 'R20_REAL_USBIP_POST_KILL_B_DENIED=PASS' "$log"
grep -q 'R21_NEW_BROKER_BEFORE_SECOND_REAL_USBIP_PROBE=PASS' "$log"
grep -q 'R21_RECOVERED_GO_MANAGER_DENIED_REAL_B_RAW_ATTACH=PASS' "$log"
cleanup
trap - EXIT
test -z "$(git status --porcelain --untracked-files=all | grep -v '.r18-existing-go' || true)"
echo R20_KILL_FENCE_CLOUD_CLEANUP=PASS
