#!/usr/bin/env bash
# Public synthetic R17. Go compiler, QEMU, and deployed Linux adapter live only
# in disposable OCI images on a one-job public hosted GitHub Actions runner.
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
before_source="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$before_source" ]] || { echo "R17_INPUT_SOURCE_DIRTY=RED"; exit 10; }
snapshot() {
  for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
    if [[ -d "$p" ]]; then
      find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum
    else echo ABSENT; fi
  done
}
local_before="$(snapshot)"
vol_before="$(docker volume ls -q | LC_ALL=C sort)"
net_before="$(docker network ls --format '{{.Name}}' | LC_ALL=C sort)"
prefix="public-r17-${GITHUB_SHA:0:12}"
netname="public-r17-internal"
host="public-r17-broker"
cleanup() {
  docker rm -f "$host" >/dev/null 2>&1 || true
  docker network rm "$netname" >/dev/null 2>&1 || true
  docker image rm -f "$prefix-broker" "$prefix-client" >/dev/null 2>&1 || true
  docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker pull golang:1.24-bookworm >/dev/null
docker pull ubuntu:24.04 >/dev/null
goimg="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.24-bookworm)"
qemuimg="$(docker image inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04)"
[[ "$goimg" == *@sha256:* && "$qemuimg" == *@sha256:* ]] || { echo R17_BASE_DIGEST_NOT_RESOLVED=RED; exit 11; }
echo "R17_GO_BASE_DIGEST=$goimg"
echo "R17_QEMU_BASE_DIGEST=$qemuimg"
for stage in broker client; do
  DOCKER_BUILDKIT=1 docker build --no-cache --pull --target "$stage" \
    --build-arg "GO_IMAGE=$goimg" \
    --build-arg "QEMU_IMAGE=$qemuimg" \
    -t "$prefix-$stage" .
done
echo "R17_DISPOSABLE_GO_TEST_VET_BUILD=PASS"
docker network create --driver bridge --internal "$netname" >/dev/null
docker run -d --rm --name "$host" --network "$netname" \
  --network-alias r17-broker --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --cpus 1 --memory 512m --memory-swap 512m --pids-limit 96 \
  --tmpfs /tmp:rw,nosuid,nodev,size=24m,mode=1777 \
  "$prefix-broker" >/dev/null
echo "R17_DISPOSABLE_LINUX_QMP_BROKER_STARTED=PASS"
if ! docker run --rm --network "$netname" --read-only \
  --user 65532:65532 --cap-drop ALL \
  --security-opt no-new-privileges --cpus 1 \
  --memory 96m --memory-swap 96m --pids-limit 32 \
  "$prefix-client"; then
  echo "R17_REMOTE_CLIENT_OR_QMP_EXERCISE=RED"
  docker logs "$host" || true
  exit 12
fi
echo "R17_INDEPENDENT_IP_CLIENT_END_TO_END=PASS"
docker logs "$host"
# The broker's stdout is a separate, host-observed source. Do not accept a
# client-only assertion that a QMP key/pointer command was sent.
brokerlog="$(docker logs "$host" 2>&1)"
for oracle in \
  R17_LOCAL_QMP_XHCI_HID_TOPOLOGY_AND_RUNNING_VM=PASS \
  R17_QMP_RELEASE_ON_OWNER_REVOKE_SUBMITTED=PASS \
  R17_QMP_RELEASE_ON_EXPIRY_SUBMITTED=PASS; do
  printf '%s\n' "$brokerlog" | grep -Fq "$oracle" || { echo "R17_BROKER_ORACLE_MISSING=RED $oracle"; exit 13; }
done
echo "R17_INDEPENDENT_BROKER_QMP_RELEASE_LOGS=PASS"
docker stop --time 1 "$host" >/dev/null
for i in $(seq 1 40); do
  if ! docker inspect "$host" >/dev/null 2>&1; then break; fi
  sleep .1
done
if docker inspect "$host" >/dev/null 2>&1; then echo "R17_BROKER_NOT_REMOVED=RED"; exit 14; fi
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$vol_before" ]] || { echo "R17_VOLUMES_TAINT=RED"; exit 15; }
[[ "$(snapshot)" == "$local_before" ]] || { echo "R17_LOCAL_TAINT=RED"; exit 16; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$before_source" ]] || { echo "R17_SOURCE_TAINT=RED"; exit 17; }
cleanup
trap - EXIT
[[ "$(docker network ls --format '{{.Name}}' | LC_ALL=C sort)" == "$net_before" ]] || { echo "R17_NETWORK_NOT_DISCARDED=RED"; exit 18; }
if docker image inspect "$prefix-broker" >/dev/null 2>&1; then echo "R17_IMAGE_NOT_REMOVED=RED"; exit 19; fi
echo "R17_SERVER_CLIENT_NETWORK_QEMU_TOOLCHAIN_DISPOSED=PASS"
echo "R17_HOME_PROJECT_LOCAL_SOURCE_ZERO_TAINT=PASS"
echo "R17_NO_GUEST_USB_EVDEV_OR_WINDOWS_DRIVER_PROOF=NOT_TESTED"
echo "R17_PRODUCTION_CLIENT_CREDENTIALS_OR_TLS=NOT_TESTED"
