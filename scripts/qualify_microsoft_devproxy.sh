#!/usr/bin/env bash
# Exact-version, public-synthetic Microsoft Dev Proxy canary (existing public typed CPU workflow).
set -euo pipefail
IMAGE='ghcr.io/dotnet/dev-proxy@sha256:18b2ac21a29bc60c3bbbe7a0e00fa3fed2179b492632ca5d5aad6ed60bd8e875'
NETWORK="msmock-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
CONTAINER="$NETWORK-proxy"
OUT="$RUNNER_TEMP/microsoft-mock"
mkdir -p "$OUT"
chmod 700 "$OUT"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

case "$GITHUB_EVENT_NAME" in pull_request|workflow_dispatch) ;; *) echo "MICROSOFT_MOCK_EVENT_BLOCKED" >&2; exit 2 ;; esac
test "$RUNNER_ARCH" = X64
python3 scripts/microsoft_devproxy_contract.py --action validate
docker pull --platform linux/amd64 "$IMAGE" >/dev/null
docker network create --driver bridge --internal "$NETWORK" >/dev/null
test "$(docker network inspect "$NETWORK" --format '{{.Internal}}')" = true
docker run --detach --name "$CONTAINER" \
  --network "$NETWORK" --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 128 --memory 768m --cpus 1 \
  --mount "type=bind,src=$GITHUB_WORKSPACE/fixtures/microsoft,dst=/config,readonly" \
  "$IMAGE" --config-file /config/devproxyrc.json >/dev/null
ready=0
for _ in $(seq 1 45); do
  if docker exec "$CONTAINER" curl --fail --silent --max-time 3 --proxy http://127.0.0.1:8000 http://graph-fixture.invalid/v1.0/approot/ok >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "MICROSOFT_MOCK_PROXY_STARTUP_FAILED" >&2
  exit 2
fi
python3 scripts/microsoft_devproxy_contract.py \
  --action probe --container "$CONTAINER" --receipt "$OUT/producer.json"
echo "MICROSOFT_MOCK_PRODUCER_RECEIPT_CREATED"
python3 scripts/verify_microsoft_devproxy_receipt.py \
  --receipt "$OUT/producer.json" --out "$OUT/verified.json" \
  --source "$GITHUB_SHA" --run-id "$GITHUB_RUN_ID"
