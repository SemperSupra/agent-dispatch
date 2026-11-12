#!/usr/bin/env bash
# Synthetic ONLY; not production OAuth, workset admission, or durable audit.
set -euo pipefail
phase="$1"
test "$phase" = source || test "$phase" = restore
mkdir -p runtime-receipts external-state
cleanup() {
  docker rm -f m1-r22-gateway >/dev/null 2>&1 || true
  for p in runtime-receipts/upstream-*.pid; do
    if test -f "$p"; then kill "$(cat "$p")" 2>/dev/null || true; fi
  done
  rm -f private.pem jwks.json token-*.txt runtime-receipts/*.jwt runtime-receipts/*-config.yaml
}
trap cleanup EXIT
if test "$phase" = source; then
  python3 - <<'PY'
import json,pathlib,secrets
pathlib.Path("runtime-receipts/old.json").write_text(json.dumps({
  "schema":"m1.gitops.synthetic/v1",
  "catalog":["alpha_echo","beta_echo"],
  "belts":{"research":{"owner":"shared","tools":["alpha_echo"]},
           "engineering":{"owner":"shared","tools":["beta_echo"]}}},sort_keys=True)+"\n")
pathlib.Path("external-state/journal.jsonl").write_text(json.dumps({
  "event":"synthetic.belt.saved","synthetic":True,
  "auditDurability":"not-qualified","sentinel":secrets.token_hex(16),
  "belts":["research","engineering"]},sort_keys=True)+"\n")
PY
  cat /proc/sys/kernel/random/boot_id > external-state/source-boot-id.txt
else
  sha256sum -c external-state/checksums.sha256
  if cmp -s /proc/sys/kernel/random/boot_id external-state/source-boot-id.txt; then
    echo "FAIL: source/restore runner boot-id identical"; exit 1
  fi
  python3 - <<'PY'
import json,pathlib
j=json.loads(pathlib.Path("external-state/journal.jsonl").read_text())
assert j["event"]=="synthetic.belt.saved" and j["synthetic"] is True
assert len(j["sentinel"])==32 and set(j["belts"])=={"research","engineering"}
PY
  cp external-state/old.json runtime-receipts/old.json
fi
go -C gitops/experiments/mcp-gitops-m1 run ./cmd/validate \
  "$PWD/runtime-receipts/old.json" > runtime-receipts/old-digest.json
if test "$phase" = restore; then
  cmp external-state/old-digest.json runtime-receipts/old-digest.json
fi
python3 jwt-harness/experiments/mcp-jwt-authz/make_issuer.py
chmod 600 private.pem token-*.txt
python3 experiments/supratoolbelt-gitops-e2e/probe.py prepare old
for spec in "alpha 39101" "beta 39102"; do
  read -r name port <<< "$spec"
  python3 jwt-harness/experiments/mcp-jwt-authz/fixture.py --serve --label "$name" --port "$port" &
  echo $! > "runtime-receipts/upstream-$name.pid"
done
for port in 39101 39102; do
  ready=no
  for i in $(seq 1 30); do
    if curl -fsS --max-time 2 "http://127.0.0.1:$port/health" >/dev/null; then ready=yes; break; fi
    sleep 0.3
  done
  test "$ready" = yes
done
docker pull cr.agentgateway.dev/agentgateway@sha256:60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b
docker run -d --name m1-r22-gateway --network host --read-only \
  --cap-drop ALL --security-opt=no-new-privileges --memory 512m --cpus 1 --pids-limit 128 \
  --mount "type=bind,source=$PWD/runtime-receipts/old-config.yaml,target=/config.yaml,readonly" \
  --mount "type=bind,source=$PWD/jwks.json,target=/keys/jwks.json,readonly" \
  cr.agentgateway.dev/agentgateway@sha256:60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b \
  -f /config.yaml
ready=no
for i in $(seq 1 40); do
  status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:39200/mcp || true)
  if test "$status" = 401 || test "$status" = 403; then ready=yes; break; fi
  sleep 0.3
done
test "$ready" = yes || { docker logs --tail 25 m1-r22-gateway; exit 1; }
python3 experiments/supratoolbelt-gitops-e2e/probe.py test old
if test "$phase" = source; then
  cp runtime-receipts/old.json external-state/old.json
  cp runtime-receipts/old-digest.json external-state/old-digest.json
  sha256sum external-state/old.json external-state/old-digest.json \
    external-state/journal.jsonl external-state/source-boot-id.txt \
    > external-state/checksums.sha256
else
  python3 - <<'PY'
import json,pathlib,platform
r=json.loads(pathlib.Path("runtime-receipts/old-e2e-receipt.json").read_text())
j=json.loads(pathlib.Path("external-state/journal.jsonl").read_text())
assert r["passed"] and len(r["checks"])==8
x={"schema":"m1-r22-cross-runner-rehydration-v1","passed":True,
  "architecture":platform.machine(),"sourceBootIdDifferent":True,
  "snapshotDigest":r["snapshotDigest"],
  "externalSentinelRestored":j["sentinel"],"gatewayRealContainer":True,
  "actualMcpChecks":len(r["checks"]),
  "limits":["GitHub artifact is synthetic off-runner state, not production database",
            "not native workset authority, live OAuth or durable audit",
            "not application HA or a real user/model invocation"]}
pathlib.Path("runtime-receipts/rehydration-receipt.json").write_text(
  json.dumps(x,indent=2,sort_keys=True)+"\n")
print(json.dumps(x,sort_keys=True))
PY
fi
echo "PASS phase=$phase runner_arch=$(uname -m)"
