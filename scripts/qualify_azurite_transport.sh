#!/usr/bin/env bash
# PUBLIC-SYNTHETIC local Azurite Blob test, no real Azure resource or credentials.
set -euo pipefail
IMAGE='mcr.microsoft.com/azure-storage/azurite@sha256:830430c1da1a2d537e08f3e6764dd1f5ae00cf0346bcaf625b968ec3f0971fd5'
NET="azq-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
CONTAINER="$NET"
OUT="$RUNNER_TEMP/azurite-blob"
case "$GITHUB_EVENT_NAME" in
  pull_request|workflow_dispatch) ;;
  *) echo "AZURITE_EVENT_DENIED" >&2; exit 2 ;;
esac
test "$RUNNER_ARCH" = X64
mkdir -p "$OUT"
chmod 700 "$OUT"
cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Pull the reviewed digest while network is available, then isolate the actual test.
docker pull --platform linux/amd64 "$IMAGE" >/dev/null
docker network create --driver bridge --internal "$NET" >/dev/null
test "$(docker network inspect "$NET" --format '{{.Internal}}')" = true
docker run --detach --name "$CONTAINER" \
  --network "$NET" --read-only \
  --tmpfs /data:rw,nosuid,nodev,size=64m \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 96 --memory 700m --cpus 1 \
  --mount "type=bind,src=$GITHUB_WORKSPACE/scripts/azurite_blob_etag.js,dst=/qual/azurite_blob_etag.js,readonly" \
  "$IMAGE" azurite-blob --blobHost 127.0.0.1 --blobPort 10000 \
    --location /data --silent --disableTelemetry >/dev/null

ready=0
for _ in $(seq 1 28); do
  if docker exec "$CONTAINER" node -e \
      'const n=require("node:net");const s=n.connect(10000,"127.0.0.1");s.on("connect",()=>{s.destroy();process.exit(0)});s.on("error",()=>process.exit(2));setTimeout(()=>process.exit(2),1500)' \
      >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "AZURITE_EMULATOR_NOT_READY" >&2
  exit 2
fi

# Separate Node processes are essential to prove recovery not tied to client memory.
docker exec "$CONTAINER" node /qual/azurite_blob_etag.js write > "$OUT/write.json"
ETAG=$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));e=d["etag"];assert isinstance(e,str) and len(e)<130;print(e)' "$OUT/write.json")
docker exec "$CONTAINER" node /qual/azurite_blob_etag.js recover "$ETAG" > "$OUT/recover.json"

python3 scripts/verify_azurite_transport.py \
    --write "$OUT/write.json" --recover "$OUT/recover.json" \
    --out "$OUT/verified.json"
test -s "$OUT/verified.json"
echo "AZURITE_BLOB_ETAG_RESTORE_QUALIFIED"
