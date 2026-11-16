#!/usr/bin/env bash
# Only executed on a standard one-job disposable public GitHub runner.
set -Eeuo pipefail
cd "$(dirname "$0")"
source_before="$(git -C ../.. status --porcelain --untracked-files=all)"
if [[ -n "$source_before" ]]; then echo 'R02_DIRTY_SOURCE_INPUT=RED'; exit 10; fi
watch_paths() {
  local item
  for item in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
    if [[ -d "$item" ]]; then
      find "$item" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum
    else
      printf 'ABSENT\n'
    fi
  done
}
local_before="$(watch_paths)"
volumes_before="$(docker volume ls -q | LC_ALL=C sort)"
image="public-sandbox-r02:${GITHUB_SHA:0:12}"
names=(public-r02-first public-r02-second)
cleanup() {
  local n
  for n in "${names[@]}"; do docker rm -f "$n" >/dev/null 2>&1 || true; done
  docker image rm -f "$image" >/dev/null 2>&1 || true
  docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker pull golang:1.24-bookworm >/dev/null
builder_digest="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.24-bookworm)"
[[ "$builder_digest" == *@sha256:* ]] || { echo 'R02_BUILDER_IMMUTABLE_DIGEST=RED'; exit 11; }
echo "R02_BUILDER_REFERENCE=$builder_digest"
DOCKER_BUILDKIT=1 docker build --no-cache --pull \
  --build-arg "BUILDER_IMAGE=$builder_digest" \
  --tag "$image" -f Dockerfile .
echo 'R02_EPHEMERAL_MULTI_STAGE_BUILD=PASS'

start() {
  local name="$1"
  docker run --rm -d --name "$name" \
    --network none --read-only --user 65532:65532 \
    --cap-drop ALL --security-opt no-new-privileges \
    --memory 128m --memory-swap 128m --cpus 1 --pids-limit 64 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
    "$image" >/dev/null
  python3 - "$name" <<'PY'
import json,subprocess,sys
cfg=json.loads(subprocess.check_output(["docker","inspect",sys.argv[1]]))[0]
host=cfg["HostConfig"]
assert host["ReadonlyRootfs"] is True
assert host["NetworkMode"]=="none"
assert host["Privileged"] is False
assert host["Memory"]==128*1024*1024
assert host["MemorySwap"]==128*1024*1024
assert host["PidsLimit"]==64
assert "ALL" in host["CapDrop"]
assert host["Binds"] in (None,[])
assert cfg["Mounts"] == [], cfg["Mounts"]
assert cfg["Config"]["User"]=="65532:65532"
assert "/tmp" in host["Tmpfs"], host["Tmpfs"]
print("R02_OCI_GUEST_DECLARED_CONFINEMENT=PASS")
PY
  local ok=0
  for _ in $(seq 1 30); do
    if docker exec "$name" /service probe empty; then ok=1; break; fi
    sleep 0.2
  done
  [[ "$ok" == 1 ]] || { echo 'R02_SERVICE_READINESS=RED'; exit 12; }
}
start "${names[0]}"
docker exec "${names[0]}" /service probe mark
docker exec "${names[0]}" /service probe readonly
first_id="$(docker exec "${names[0]}" /service probe id)"
docker stop "${names[0]}" >/dev/null
if docker inspect "${names[0]}" >/dev/null 2>&1; then echo 'R02_FIRST_RUNTIME_SURVIVED_DISPOSAL=RED'; exit 13; fi
start "${names[1]}"
second_id="$(docker exec "${names[1]}" /service probe id)"
if [[ "$first_id" == "$second_id" ]]; then echo 'R02_INCARNATION_NOT_REGENERATED=RED'; exit 14; fi
docker exec "${names[1]}" /service probe readonly
docker stop "${names[1]}" >/dev/null
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$volumes_before" ]] || { echo 'R02_PERSISTENT_VOLUME_TAINT=RED'; exit 15; }
[[ "$(watch_paths)" == "$local_before" ]] || { echo 'R02_HOME_OR_PROJECT_LOCAL_TAINT=RED'; exit 16; }
[[ "$(git -C ../.. status --porcelain --untracked-files=all)" == "$source_before" ]] || { echo 'R02_SOURCE_CHECKOUT_TAINT=RED'; exit 17; }
cleanup
trap - EXIT
if docker image inspect "$image" >/dev/null 2>&1; then echo 'R02_IMAGE_CACHE_CLEANUP=RED'; exit 18; fi
echo 'R02_DISPOSABLE_DEPLOYMENT_TWO_INCARCATIONS=PASS'
echo 'R02_EPHEMERAL_STATE_FORGOTTEN=PASS'
echo 'R02_HOME_PROJECT_LOCAL_AND_SOURCE_NO_TAINT=PASS'
echo 'R02_NO_PERSISTENT_MOUNTS_OR_HOST_APP_INSTALL=PASS'
echo 'R02_PRODUCTION_HOST_SECURITY_AND_EXTERNAL_DATA=NOT_TESTED'
