#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
test -z "$(git status --porcelain --untracked-files=all | grep -v '.r18-existing-go' || true)"
image="pi-usb-r19-464-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r19-blue-464.log"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 11
echo "R08_BASE_IMAGE=$base"
test -d .r18-existing-go/experiments/usb-fabric-r26/integrated
test "$(git -C .r18-existing-go rev-parse HEAD)" = "2e580a0162452a6f59a449f769f9bfc5153e0aa3"
DOCKER_BUILDKIT=1 docker build --no-cache --build-context gosource=.r18-existing-go --build-arg "BASE=$base" \
 -f experiments/pi-usb-fabric-r19/export-fence/Dockerfile -t "$image" .
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
grep -q 'R19_BLUE_UNAUTHORIZED_IMPORT_DENIED_UNTIL_HOST_AUTHORIZE=PASS' "$log"
cleanup
trap - EXIT
test -z "$(git status --porcelain --untracked-files=all | grep -v '.r18-existing-go' || true)"
echo R18_THREE_GUEST_BROKER_CLOUD_CLEANUP=PASS
