#!/usr/bin/env bash
# Public-safe disposable ARM64 qualification. Nonproduction.
set -Eeuo pipefail
candidate="$1"
root="$(cd "$(dirname "$0")" && pwd)"
export PATH="$RUNNER_TEMP/bakeoff-bin:$PATH"
mkdir -p "$RUNNER_TEMP/bakeoff-bin" "$RUNNER_TEMP/bakeoff-data"
export DAGU_HOME="$RUNNER_TEMP/bakeoff-data"
export HOME="$RUNNER_TEMP/bakeoff-home"
mkdir -p "$HOME"
echo "BAKEOFF_HOST candidate=$candidate arch=$(uname -m) cpu=$(nproc) mem_kib=$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
echo "BAKEOFF_POLICY synthetic-only; no private code, real prompt, credentials, admission, deployment, or effects"
report_boot() {
 CANDIDATE="$candidate" BOOT_STATUS="$1" BOOT_MS="$2" BOOT_DETAILS="$3" python3 - <<'PY'
import json,os,platform
print("BAKEOFF_RESULT="+json.dumps({"schema":"task-orchestrator-bakeoff/v1",
 "candidate":os.environ["CANDIDATE"],"architecture":platform.machine(),
 "comparison_scope":"service-startup-only","qualified":False,
 "startup_probe":os.environ["BOOT_STATUS"],"startup_ms":int(os.environ["BOOT_MS"]),
 "details":os.environ["BOOT_DETAILS"][:500],"workflow_runs":0,
 "owner_effect_accepted":False},sort_keys=True),flush=True)
PY
}
case "$candidate" in
baseline)
 python3 "$root/bench.py" baseline ;;
baseline_inprocess)
 python3 "$root/bench.py" baseline_inprocess ;;
dagu)
 version="2.26.0"
 image="ghcr.io/dagucloud/dagu:$version"
 if ! timeout 160 docker pull "$image"; then
   report_boot UNQUALIFIED 0 "Pinned Dagu multiarch container unavailable"; exit 0
 fi
 docker image inspect --format 'BAKEOFF_IMAGE {{.Size}} {{index .RepoDigests 0}}' "$image" || true
 binpath="$(docker run --rm --entrypoint sh "$image" -c 'command -v dagu')"
 echo "BAKEOFF_DAGU_BINARY $binpath"
 cid="$(docker create "$image")"
 docker cp "$cid:$binpath" "$RUNNER_TEMP/bakeoff-bin/dagu"
 docker rm "$cid" >/dev/null
 chmod +x "$RUNNER_TEMP/bakeoff-bin/dagu"
 python3 "$root/bench.py" dagu ;;
dbos)
 python3 -m venv "$RUNNER_TEMP/bakeoff-venv"
 "$RUNNER_TEMP/bakeoff-venv/bin/pip" install --disable-pip-version-check --quiet "dbos==3.4.0"
 "$RUNNER_TEMP/bakeoff-venv/bin/python" "$root/bench.py" dbos ;;
restate)
 t0=$(date +%s%3N)
 image="docker.restate.dev/restatedev/restate:1.8.1-hotfix.2"
 if ! timeout 180 docker pull "$image"; then
   report_boot UNQUALIFIED "$(( $(date +%s%3N) - t0 ))" "Pinned Restate ARM64 image unavailable"; exit 0
 fi
 if ! docker run --detach --name restate-bakeoff --memory=2g --cpus=2 \
    --add-host=host.docker.internal:host-gateway \
    --publish 127.0.0.1:8080:8080 \
    --publish 127.0.0.1:9070:9070 --publish 127.0.0.1:9071:9071 "$image" >/dev/null; then
   report_boot UNQUALIFIED "$(( $(date +%s%3N) - t0 ))" "Docker startup failed"; exit 0
 fi
 ok=0
 for i in $(seq 1 45); do
   if docker ps --format '{{.Names}}' | grep -qx restate-bakeoff && curl --silent --max-time 2 http://127.0.0.1:9070/health >/dev/null; then ok=1; break; fi
   sleep 2
 done
 docker stats --no-stream --format 'BAKEOFF_DOCKER_MEM_IDLE {{.Name}} {{.MemUsage}} {{.CPUPerc}}' restate-bakeoff || true
 docker image inspect --format 'BAKEOFF_IMAGE_DIGEST {{index .RepoDigests 0}}' "$image" || true
 if [ "$ok" -ne 1 ]; then
   docker logs --tail 25 restate-bakeoff || true
   report_boot UNQUALIFIED "$(( $(date +%s%3N) - t0 ))" "Server did not answer health"; docker rm -f restate-bakeoff >/dev/null; exit 0
 fi
 python3 -m venv "$RUNNER_TEMP/restate-venv"
 "$RUNNER_TEMP/restate-venv/bin/pip" install --quiet --disable-pip-version-check "restate-sdk[serve]==1.4.1" "hypercorn==0.17.3"
 PYTHONPATH="$root" "$RUNNER_TEMP/restate-venv/bin/python" -m hypercorn restate_app:app --bind 0.0.0.0:9080 > "$RUNNER_TEMP/restate-asgi.log" 2>&1 &
 apppid=$!
 registered=0
 for i in $(seq 1 25); do
   if curl --silent --fail --show-error --max-time 4 \
     --header 'Content-Type: application/json' \
     --data '{"uri":"http://host.docker.internal:9080"}' \
     http://127.0.0.1:9070/deployments > "$RUNNER_TEMP/restate-register.json" 2>/dev/null; then
       registered=1; break
   fi
   if ! kill -0 "$apppid" 2>/dev/null; then break; fi
   sleep 2
 done
 if [ "$registered" -eq 1 ]; then
   python3 "$root/bench.py" restate
   docker stats --no-stream --format 'BAKEOFF_DOCKER_MEM_ACTIVE {{.Name}} {{.MemUsage}} {{.CPUPerc}}' restate-bakeoff || true
   ps -o rss= -p "$apppid" | awk '{print "BAKEOFF_HANDLER_RSS_KIB " $1}' || true
 else
   tail -35 "$RUNNER_TEMP/restate-asgi.log" || true
   cat "$RUNNER_TEMP/restate-register.json" || true
   report_boot UNQUALIFIED "$(( $(date +%s%3N) - t0 ))" "Server booted but native handler registration failed"
 fi
 kill "$apppid" 2>/dev/null || true
 wait "$apppid" 2>/dev/null || true
 docker rm --force restate-bakeoff >/dev/null || true ;;
hatchet)
 version="0.114.2"
 t0=$(date +%s%3N)
 archive="hatchet_"$version"_Linux_arm64.tar.gz"
 url="https://github.com/hatchet-dev/hatchet/releases/download/v$version/$archive"
 if ! curl --fail --location --retry 2 --max-time 100 --silent --show-error "$url" -o "$RUNNER_TEMP/$archive"; then
   report_boot UNQUALIFIED "$(( $(date +%s%3N) - t0 ))" "Pinned Hatchet CLI ARM64 asset unavailable"; exit 0
 fi
 tar -xzf "$RUNNER_TEMP/$archive" -C "$RUNNER_TEMP/bakeoff-bin"
 find "$RUNNER_TEMP/bakeoff-bin" -maxdepth 3 -type f | head -12
 if [ ! -x "$RUNNER_TEMP/bakeoff-bin/hatchet" ]; then
   report_boot UNQUALIFIED "$(( $(date +%s%3N) - t0 ))" "CLI archive missing expected executable"; exit 0
 fi
 timeout 150 hatchet server start --disable-auth > "$RUNNER_TEMP/hatchet.log" 2>&1 &
 pid=$!
 ok=0
 for i in $(seq 1 60); do
   if curl --silent --max-time 2 --fail http://127.0.0.1:8888/ >/dev/null; then ok=1; break; fi
   if ! kill -0 "$pid" 2>/dev/null; then break; fi
   sleep 2
 done
 docker ps --format 'BAKEOFF_DOCKER {{.Names}} {{.Image}} {{.Status}}' || true
 docker stats --no-stream --format 'BAKEOFF_DOCKER_MEM {{.Name}} {{.MemUsage}} {{.CPUPerc}}' || true
 tail -25 "$RUNNER_TEMP/hatchet.log" | sed -E 's/(token|password|secret)=[^ ]+/\1=[REDACTED]/gi' || true
 report_boot "$([ "$ok" -eq 1 ] && echo BOOTED || echo UNQUALIFIED)" "$(( $(date +%s%3N) - t0 ))" "Development service only; no workflow or security qualification"
 kill "$pid" 2>/dev/null || true
 wait "$pid" 2>/dev/null || true ;;
*)
 echo "unknown candidate" >&2; exit 2 ;;
esac
