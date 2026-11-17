#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || exit 11
docker pull golang:1.23-bookworm >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.23-bookworm)"
[[ "$base" == *@sha256:* ]] || exit 12
echo "R26_N4B_GO_BASE=$base"
tar -C experiments/usb-fabric-r26/issue-396 -cf - . | \
 docker run --rm -i --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2048m --memory-swap 2048m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=1536m,mode=1777 \
 -e HOME=/tmp -e GOCACHE=/tmp/cache -e GOPATH=/tmp/gopath \
 -e GOPROXY=off -e GOSUMDB=off -e GOTOOLCHAIN=local "$base" \
 sh -ec 'mkdir -p /tmp/work; cd /tmp/work; tar -xf -; go test -race -count=1 -v ./...; go vet ./...'
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || exit 13
echo R26_N4B_BOOT_AND_NKRO_REPORT_DESCRIPTOR_MODEL=PASS
echo R26_N4B_PHYSICAL_KEY_COUNT_FROM_HID_REPORT=UNKNOWABLE_WITHOUT_MODEL_DATA
