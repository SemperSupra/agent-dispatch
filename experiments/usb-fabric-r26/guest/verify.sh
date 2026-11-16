#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
input_before="$(git status --porcelain --untracked-files=all)"
[[ -z "$input_before" ]] || { echo R26_GUEST_SOURCE_DIRTY=RED; exit 10; }
snapshot() {
  for path in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
    if [[ -d "$path" ]]; then
      find "$path" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum
    else
      echo ABSENT
    fi
  done
}
local_before="$(snapshot)"
volumes_before="$(docker volume ls -q | LC_ALL=C sort)"
image="public-r26-guest-${GITHUB_SHA:0:12}"
cleanup() {
  docker image rm -f "$image" >/dev/null 2>&1 || true
  docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || { echo R26_GUEST_BASE_NOT_DIGEST_PINNED=RED;exit 11; }
echo "R26_GUEST_BASE_REFERENCE=$base"
DOCKER_BUILDKIT=1 docker build --pull --no-cache \
  -f experiments/agent-sandbox-r15/Dockerfile \
  --build-arg "BASE_IMAGE=$base" \
  -t "$image" experiments/agent-sandbox-r15
run_flags=(--rm --network none --read-only --user 65532:65532
  --cap-drop ALL --security-opt no-new-privileges
  --memory 2048m --memory-swap 2048m --cpus 2 --pids-limit 128
  --tmpfs /tmp:rw,nosuid,nodev,size=16m,mode=1777)
echo R26_GUEST_QUALIFICATION_FROM_INDEPENDENT_R15_HARNESS_BEGIN
timeout 220s docker run "${run_flags[@]}" "$image"
echo R26_GUEST_R15_EXISTING_FUNCTIONAL_HID_ORACLE=PASS
echo R26_QMP_HOTPLUG_AND_PCAP_HEADER_PROBE_BEGIN
timeout 40s docker run -i "${run_flags[@]}" --entrypoint python3 "$image" - \
  < experiments/usb-fabric-r26/guest/lifecycle_pcap.py
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$volumes_before" ]] || { echo R26_GUEST_VOLUMES_TAINT=RED;exit 12; }
[[ "$(snapshot)" == "$local_before" ]] || { echo R26_GUEST_LOCAL_TAINT=RED;exit 13; }
[[ "$(git status --porcelain --untracked-files=all)" == "$input_before" ]] || { echo R26_GUEST_SOURCE_TAINT=RED;exit 14; }
cleanup
trap - EXIT
if docker image inspect "$image" >/dev/null 2>&1;then echo R26_GUEST_IMAGE_CLEANUP=RED;exit 15;fi
echo R26_GUEST_DISPOSABLE_CLEANUP=PASS
echo R26_REAL_USBIP_FORWARDING=NOT_TESTED
echo R26_FENCED_HOST_BROKER_TO_GUEST_INTEGRATION=NOT_TESTED
