#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
source_before="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$source_before" ]] || { echo R13_SOURCE_DIRTY=RED; exit 10; }
snapshot() {
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
  if [[ -d "$p" ]]; then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum
  else echo ABSENT; fi
 done
}
locals_before="$(snapshot)"
volumes_before="$(docker volume ls -q | LC_ALL=C sort)"
case "$R13_ARCH" in
 x86_64) package=qemu-system-x86 ;;
 aarch64) package=qemu-system-arm ;;
 riscv64) package=qemu-system-misc ;;
 *) echo R13_UNKNOWN_ARCH=RED; exit 11 ;;
esac
image="public-r13-${R13_ARCH}:${GITHUB_SHA:0:12}"
cleanup() {
 docker image rm -f "$image" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull ubuntu:24.04 >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04)"
[[ "$base" == *@sha256:* ]] || { echo R13_BASE_NOT_DIGEST_PINNED=RED; exit 12; }
echo "R13_BASE_REFERENCE=$base"
DOCKER_BUILDKIT=1 docker build --pull --no-cache \
 --build-arg "BASE_IMAGE=$base" --build-arg "QEMU_PACKAGE=$package" \
 -t "$image" .
docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 512m --memory-swap 512m --cpus 1 --pids-limit 96 \
 --tmpfs /tmp:rw,nosuid,nodev,size=32m,mode=1777 \
 "$image" --arch "$R13_ARCH"
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$volumes_before" ]] || { echo R13_VOLUME_TAINT=RED; exit 13; }
[[ "$(snapshot)" == "$locals_before" ]] || { echo R13_LOCAL_TAINT=RED; exit 14; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$source_before" ]] || { echo R13_CHECKOUT_TAINT=RED; exit 15; }
cleanup; trap - EXIT
if docker image inspect "$image" >/dev/null 2>&1; then echo R13_IMAGE_SURVIVED=RED; exit 16; fi
echo R13_DISPOSABLE_XHCI_INPUT_RUNTIME_AND_TOOLS_REMOVED=PASS
echo R13_HOME_PROJECT_LOCAL_AND_SOURCE_ZERO_TAINT=PASS
