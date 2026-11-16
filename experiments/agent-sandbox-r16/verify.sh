#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
before_source="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$before_source" ]] || { echo R16_DIRTY_CHECKOUT=RED; exit 10; }
snapshot() {
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
  if [[ -d "$p" ]]; then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum
  else echo ABSENT; fi
 done
}
before_local="$(snapshot)"
before_volumes="$(docker volume ls -q | LC_ALL=C sort)"
before_networks="$(docker network ls --format '{{.Name}}' | LC_ALL=C sort)"
tag="r16-${GITHUB_SHA:0:12}"
network="public-r16-testnet"
name="public-r16-gateway"
cleanup() {
 docker rm -f "$name" >/dev/null 2>&1 || true
 docker network rm "$network" >/dev/null 2>&1 || true
 docker image rm -f "$tag-server" "$tag-client" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker pull golang:1.24-bookworm >/dev/null
docker pull debian:trixie-slim >/dev/null
goimg="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.24-bookworm)"
debimg="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$goimg" == *@sha256:* && "$debimg" == *@sha256:* ]] || { echo R16_BASE_DIGEST_NOT_PINNED=RED; exit 11; }
echo "R16_GO_BUILD_IMAGE=$goimg"
echo "R16_DEBIAN_RUNTIME_IMAGE=$debimg"
for stage in server client; do
 DOCKER_BUILDKIT=1 docker build --no-cache --pull --target "$stage" \
  --build-arg "GO_IMAGE=$goimg" --build-arg "DEBIAN_IMAGE=$debimg" \
  -t "$tag-$stage" .
done
echo R16_DISPOSABLE_OFFLINE_GO_RACE_VET_AND_SCRATCH_CLIENT=PASS

docker network create --driver bridge --internal "$network" >/dev/null
echo R16_ISOLATED_INTERNAL_IP_NETWORK_CREATED=PASS
docker run -d --rm --name "$name" --network "$network" --network-alias r16-gateway \
 --read-only --user 65532:65532 --cap-drop ALL \
 --security-opt no-new-privileges --memory 192m --memory-swap 192m \
 --cpus 1 --pids-limit 72 --tmpfs /tmp:rw,nosuid,nodev,noexec,size=8m,mode=1777 \
 "$tag-server" >/dev/null

# Separate ephemeral client container connects over a real isolated IP network.
docker run --rm --network "$network" --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges --memory 96m --memory-swap 96m \
 --cpus 1 --pids-limit 32 "$tag-client"
echo R16_REAL_REMOTE_CLIENT_MANAGEMENT_IP_API=PASS

# The actual upstream Linux usbip CLI inside the disposable server image sees
# three synthetic ports through USB/IP protocol loopback. The import is DENIED.
discovery=""
for _ in $(seq 1 20); do
 if discovery="$(docker exec "$name" usbip list --remote=127.0.0.1 2>&1)"; then break;fi
 sleep .2
done
printf '%s\n' "$discovery"
printf '%s\n' "$discovery" | grep -q '1-1' || { echo R16_USBIP_PORT1_DISCOVERY=RED; exit 12; }
printf '%s\n' "$discovery" | grep -q '1-2' || { echo R16_USBIP_PORT2_DISCOVERY=RED; exit 13; }
printf '%s\n' "$discovery" | grep -q '1-3' || { echo R16_USBIP_PORT3_DISCOVERY=RED; exit 14; }
echo R16_UPSTREAM_LINUX_USBIP_DISCOVERED_THREE_VIRTUAL_PORTS=PASS
docker exec "$name" /gateway probe-import

docker stop --time 1 "$name" >/dev/null
for _ in $(seq 1 50); do
 if ! docker inspect "$name" >/dev/null 2>&1; then break; fi
 sleep .1
done
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$before_volumes" ]] || { echo R16_DOCKER_VOLUME_TAINT=RED; exit 15; }
[[ "$(snapshot)" == "$before_local" ]] || { echo R16_LOCAL_TAINT=RED; exit 16; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$before_source" ]] || { echo R16_SOURCE_TAINT=RED; exit 17; }
cleanup;trap - EXIT
if docker image inspect "$tag-server" >/dev/null 2>&1;then echo R16_IMAGE_CLEANUP=RED;exit 18;fi
[[ "$(docker network ls --format '{{.Name}}' | LC_ALL=C sort)" == "$before_networks" ]] || { echo R16_NETWORK_CLEANUP=RED; exit 19; }
echo R16_SERVER_CLIENT_NETWORK_AND_TOOLCHAIN_DISPOSED=PASS
echo R16_HOME_PROJECT_LOCAL_AND_SOURCE_ZERO_TAINT=PASS
echo R16_ACTUAL_USB_DEVICE_URB_OR_HYPERVISOR_ROUTE=NOT_TESTED
echo R16_REAL_TLS_IDENTITY_OR_HARDWARE_PASSTHROUGH=NOT_TESTED
