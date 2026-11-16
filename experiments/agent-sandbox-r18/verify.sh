#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
r16="$GITHUB_WORKSPACE/r16-source"
r17="$GITHUB_WORKSPACE/r17-source"
[[ "$(git -C "$r16" rev-parse HEAD)" == e5065cd859c15966d23dd929a79dc4a6b3751dd9 ]] || { echo R18_R16_SOURCE_SHA_MISMATCH=RED; exit 10; }
[[ "$(git -C "$r17" rev-parse HEAD)" == e76b1ad8d4c17c30a1912ed7415ccbbdd4cf0719 ]] || { echo R18_R17_SOURCE_SHA_MISMATCH=RED; exit 11; }
echo R18_INDEPENDENT_EXACT_SOURCE_PINS=PASS
before_source="$(git -C "$root" status --porcelain --untracked-files=all)"
before_r16="$(git -C "$r16" status --porcelain --untracked-files=all)"
before_r17="$(git -C "$r17" status --porcelain --untracked-files=all)"
[[ -z "$before_source" && -z "$before_r16" && -z "$before_r17" ]] || { echo R18_SOURCE_INPUT_DIRTY=RED; exit 12; }
snapshot() {
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local" "$r16/.local" "$r17/.local" "$root/.local"; do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum
  else echo ABSENT;fi
 done
}
local_before="$(snapshot)"
vol_before="$(docker volume ls -q | LC_ALL=C sort)"
net_before="$(docker network ls --format '{{.Name}}' | LC_ALL=C sort)"
prefix="public-r18-${GITHUB_SHA:0:12}"
front="public-r18-front"
back="public-r18-back"
names=(public-r18-hub public-r18-hid public-r18-policy)
cleanup() {
 for name in "${names[@]}";do docker rm -f "$name" >/dev/null 2>&1 || true;done
 docker network rm "$front" "$back" >/dev/null 2>&1 || true
 for stage in hub hid policy client;do docker image rm -f "$prefix-$stage" >/dev/null 2>&1 || true;done
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull golang:1.24-bookworm >/dev/null
docker pull ubuntu:24.04 >/dev/null
docker pull debian:trixie-slim >/dev/null
goimg="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.24-bookworm)"
ubimg="$(docker image inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04)"
debimg="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$goimg" == *@sha256:* && "$ubimg" == *@sha256:* && "$debimg" == *@sha256:* ]] || { echo R18_BASE_IMMUTABLE_DIGEST=RED; exit 13; }
echo "R18_GO_BASE=$goimg"
echo "R18_UBUNTU_BASE=$ubimg"
echo "R18_DEBIAN_BASE=$debimg"
DOCKER_BUILDKIT=1 docker build --no-cache --pull \
 -f "$r16/experiments/agent-sandbox-r16/Dockerfile" \
 --build-arg "GO_IMAGE=$goimg" --build-arg "DEBIAN_IMAGE=$debimg" \
 --target server -t "$prefix-hub" "$r16/experiments/agent-sandbox-r16"
DOCKER_BUILDKIT=1 docker build --no-cache --pull \
 -f "$r17/experiments/agent-sandbox-r17/Dockerfile" \
 --build-arg "GO_IMAGE=$goimg" --build-arg "QEMU_IMAGE=$ubimg" \
 --target broker -t "$prefix-hid" "$r17/experiments/agent-sandbox-r17"
for stage in gateway client;do
 label=policy;[[ "$stage" == client ]] && label=client
 DOCKER_BUILDKIT=1 docker build --no-cache --pull \
  --build-arg "GO_IMAGE=$goimg" --target "$stage" -t "$prefix-$label" .
done
echo R18_DISPOSABLE_R16_R17_AND_INTEGRATION_TOOLCHAINS=PASS
docker network create --internal --driver bridge "$front" >/dev/null
docker network create --internal --driver bridge "$back" >/dev/null
docker run -d --rm --name "${names[0]}" --network "$back" \
 --network-alias r16-gateway --user 65532:65532 --read-only \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 192m --memory-swap 192m --cpus 1 --pids-limit 72 \
 --tmpfs /tmp:rw,nosuid,nodev,noexec,size=8m,mode=1777 "$prefix-hub" >/dev/null
docker run -d --rm --name "${names[1]}" --network "$back" \
 --network-alias r17-broker --user 65532:65532 --read-only \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 512m --memory-swap 512m --cpus 1 --pids-limit 96 \
 --tmpfs /tmp:rw,nosuid,nodev,size=24m,mode=1777 "$prefix-hid" >/dev/null
docker run -d --rm --name "${names[2]}" --network "$back" \
 --user 65532:65532 --read-only \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 96m --memory-swap 96m --cpus 1 --pids-limit 32 "$prefix-policy" >/dev/null
docker network connect --alias r18-gateway "$front" "${names[2]}"
echo R18_TWO_DISPOSABLE_SEGMENTED_INTERNAL_IP_NETWORKS=PASS
if ! docker run --rm --network "$front" --user 65532:65532 --read-only \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 96m --memory-swap 96m --cpus 1 --pids-limit 32 "$prefix-client"; then
 echo R18_FRONT_CLIENT_END_TO_END=RED
 for name in "${names[@]}";do docker logs "$name" || true;done
 exit 14
fi
echo R18_INDEPENDENT_FRONTEND_CLIENT_ORACLES=PASS
for name in "${names[@]}";do echo "R18_SERVICE_LOG=$name";docker logs "$name" 2>&1;done
policy_log="$(docker logs "${names[2]}" 2>&1)"
qmp_log="$(docker logs "${names[1]}" 2>&1)"
for expected in \
 R18_LINUX_HUB_QMP_POLICY_GATEWAY_IP_READY=PASS \
 R18_R16_LEASE_PRECEDES_R17_FOCUS=PASS \
 R18_R16_GENERATION_VALIDATED_BEFORE_QMP_INPUT=PASS \
 R18_HUB_REVOKE_FENCED_REMOTE_QMP_INPUT=PASS \
 R18_OWNER_REVOKED_HUB_AND_QMP_FOCUS=PASS;do
 printf '%s\n' "$policy_log" | grep -Fq "$expected" || { echo "R18_POLICY_ORACLE_MISSING=RED $expected"; exit 15; }
done
for expected in \
 R17_LOCAL_QMP_XHCI_HID_TOPOLOGY_AND_RUNNING_VM=PASS \
 R17_QMP_RELEASE_ON_OWNER_REVOKE_SUBMITTED=PASS;do
 printf '%s\n' "$qmp_log" | grep -Fq "$expected" || { echo "R18_LOCAL_QMP_ORACLE_MISSING=RED $expected"; exit 16; }
done
echo R18_INDEPENDENT_HUB_POLICY_AND_LOCAL_QMP_RECEIPTS=PASS
cleanup
trap - EXIT
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$vol_before" ]] || { echo R18_VOLUME_TAINT=RED; exit 17; }
[[ "$(docker network ls --format '{{.Name}}' | LC_ALL=C sort)" == "$net_before" ]] || { echo R18_NETWORK_TAINT=RED; exit 18; }
[[ "$(snapshot)" == "$local_before" ]] || { echo R18_LOCAL_TAINT=RED; exit 19; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$before_source" ]] || { echo R18_SOURCE_TAINT=RED; exit 20; }
[[ "$(git -C "$r16" status --porcelain --untracked-files=all)" == "$before_r16" ]] || { echo R18_R16_SOURCE_TAINT=RED; exit 21; }
[[ "$(git -C "$r17" status --porcelain --untracked-files=all)" == "$before_r17" ]] || { echo R18_R17_SOURCE_TAINT=RED; exit 22; }
echo R18_ALL_FOUR_SERVICE_IMAGES_AND_NETWORKS_DISPOSED=PASS
echo R18_HOME_PROJECT_LOCAL_AND_ALL_SOURCES_ZERO_TAINT=PASS
echo R18_FULL_USBIP_URB_TO_GUEST_BRIDGE=NOT_TESTED
echo R18_ATOMIC_CROSS_BROKER_REVOCATION=NOT_TESTED
