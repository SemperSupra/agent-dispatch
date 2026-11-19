#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R27H6_SOURCE_ALREADY_DIRTY=RED; exit 11; }
volumes="$(docker volume ls -q | LC_ALL=C sort)"
guest="r27h6-guest-${GITHUB_SHA:0:12}"
image="r27h6-actuator-${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$image" "$guest" >/dev/null 2>&1 || true; docker builder prune -af >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
deb="$(docker image inspect -f '{{index .RepoDigests 0}}' debian:trixie-slim)"
docker pull golang:1.23-bookworm >/dev/null
go="$(docker image inspect -f '{{index .RepoDigests 0}}' golang:1.23-bookworm)"
[[ "$deb" == *@sha256:* && "$go" == *@sha256:* ]] || exit 12
DOCKER_BUILDKIT=1 docker build --pull --no-cache \
 -f experiments/usb-fabric-r26/releasegate/guestwire/Dockerfile \
 --build-arg "DEBIAN_BASE=$deb" --build-arg "GO_BASE=$go" -t "$guest" .
DOCKER_BUILDKIT=1 docker build --no-cache \
 -f experiments/usb-fabric-r26/integrated/Dockerfile \
 --build-arg "R15_IMAGE=$guest" --build-arg "GO_BASE=$go" -t "$image" .
timeout 230s docker run --rm --network none --read-only --user 0:0 \
 --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add FOWNER \
 --security-opt no-new-privileges \
 --memory 2048m --memory-swap 2048m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 --entrypoint python3 "$image" -B /guest/r27h6_joint_signed_private_qmp_oracle.py
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$volumes" ]] || { echo R27H6_VOLUME_TAINT=RED; exit 13; }
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || { echo R27H6_SOURCE_TAINT=RED; exit 14; }
cleanup; trap - EXIT
echo R27H6_DISPOSABLE_CLEANUP=PASS
