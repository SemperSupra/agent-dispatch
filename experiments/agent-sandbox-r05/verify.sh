#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
status_before="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$status_before" ]] || { echo 'R05_INPUT_CHECKOUT_DIRTY=RED'; exit 11; }
snapshot() {
  for d in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
    if [[ -d "$d" ]]; then find "$d" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum
    else echo "ABSENT"; fi
  done
}
before_local="$(snapshot)"
before_volumes="$(docker volume ls -q | LC_ALL=C sort)"
image="public-sandbox-r05:${GITHUB_SHA:0:12}"
hostmarker="$(mktemp "$RUNNER_TEMP/r05-host-XXXXXXXX")"
printf 'PUBLIC-TEST-ONLY-HOST-SYNTHETIC' > "$hostmarker"
names=(public-r05-first public-r05-second)
cleanup(){
  for name in "${names[@]}"; do docker rm -f "$name" >/dev/null 2>&1 || true; done
  docker image rm -f "$image" >/dev/null 2>&1 || true
  docker builder prune -af >/dev/null 2>&1 || true
  rm -f "$hostmarker"
}
trap cleanup EXIT

docker pull golang:1.24-bookworm >/dev/null
digest="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.24-bookworm)"
[[ "$digest" == *@sha256:* ]] || { echo 'R05_BUILDER_IMMUTABLE_DIGEST=RED'; exit 12; }
echo "R05_BUILDER_REFERENCE=$digest"
DOCKER_BUILDKIT=1 docker build --no-cache --pull \
  --build-arg "BUILDER_IMAGE=$digest" --tag "$image" -f Dockerfile .
echo 'R05_DISPOSABLE_OCI_BUILD=PASS'

start(){
  docker run -d --rm --name "$1" --network none --read-only \
    --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
    --memory 128m --memory-swap 128m --cpus 1 --pids-limit 64 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
    "$image" >/dev/null
  python3 - "$1" <<'PY'
import json,subprocess,sys
obj=json.loads(subprocess.check_output(["docker","inspect",sys.argv[1]]))[0]
h=obj["HostConfig"]
assert h["NetworkMode"]=="none" and h["ReadonlyRootfs"] and not h["Privileged"]
assert h["Binds"] in (None,[]) and obj["Mounts"]==[]
assert h["Memory"]==h["MemorySwap"]==128*1024*1024 and h["PidsLimit"]==64
assert "ALL" in h["CapDrop"] and h["SecurityOpt"] and "no-new-privileges" in h["SecurityOpt"]
assert obj["Config"]["User"]=="65532:65532"
print("R05_DECLARED_HOST_BOUNDARIES=PASS")
PY
  local ready=0
  for i in $(seq 1 30); do
    if docker exec "$1" /probe empty >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.2
  done
  [[ "$ready" == 1 ]] || { echo 'R05_GUEST_NOT_READY=RED'; exit 13; }
}
start "${names[0]}"
docker exec -e "R05_HOST_MARKER=$hostmarker" "${names[0]}" /probe examine
docker exec "${names[0]}" /probe mark
pids=""
count=0
for i in $(seq 1 30); do
  pids="$(docker top "${names[0]}" -eo pid,comm | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1}')"
  count="$(printf '%s\n' "$pids" | awk 'NF{n++} END{print n+0}')"
  if (( count >= 3 )); then break; fi
  sleep 0.1
done
if (( count < 3 )); then echo "R05_PROCESS_TREE_MEMBERS=RED count=$count"; exit 14; fi
echo "R05_SETSID_DESCENDANT_TREE_OBSERVED=PASS count=$count"
docker kill --signal KILL "${names[0]}" >/dev/null
for i in $(seq 1 40); do
  if ! docker inspect "${names[0]}" >/dev/null 2>&1; then break; fi
  sleep 0.1
done
if docker inspect "${names[0]}" >/dev/null 2>&1; then echo 'R05_CRASH_RUNTIME_NOT_DESTROYED=RED'; exit 15; fi
# Host PID observations are narrow cleanup evidence on a disposable runner.
python3 - "$pids" <<'PY'
import os,sys,time
pids=[int(x) for x in sys.argv[1].split() if x.isdigit()]
def alive(pid):
 try:
  with open(f"/proc/{pid}/stat",encoding="utf8") as stream: stat=stream.read()
  return stat.split(") ",1)[1][0] not in ("Z","X")
 except FileNotFoundError: return False
for i in range(30):
 if not any(alive(pid) for pid in pids): break
 time.sleep(0.1)
else: raise SystemExit("R05_PROCESS_TREE_ESCAPE_OR_CLEANUP=RED")
print("R05_CRASH_KILLS_PROCESS_TREE=PASS")
PY
start "${names[1]}"
docker exec "${names[1]}" /probe empty
docker kill --signal KILL "${names[1]}" >/dev/null
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$before_volumes" ]] || { echo 'R05_VOLUME_TAINT=RED'; exit 16; }
[[ "$(snapshot)" == "$before_local" ]] || { echo 'R05_LOCAL_TAINT=RED'; exit 17; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$status_before" ]] || { echo 'R05_SOURCE_TAINT=RED'; exit 18; }
cleanup; trap - EXIT
if docker image inspect "$image" >/dev/null 2>&1; then echo 'R05_IMAGE_CLEANUP=RED'; exit 19; fi
echo 'R05_EPHEMERAL_STATE_DISCARDED=PASS'
echo 'R05_HOME_PROJECT_LOCAL_SOURCE_ZERO_TAINT=PASS'
echo 'R05_NO_PERMANENT_TOOL_SERVICE_OR_MOUNT=PASS'
echo 'R05_HOST_KERNEL_ESCAPE_PROTECTION=NOT_TESTED'
