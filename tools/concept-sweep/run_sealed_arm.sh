#!/usr/bin/env bash
# Fixed public synthetic transport: ONE arm per independent GHA workcell.
# Real CPE provenance and blind reference custody remain private authority.
set -euo pipefail
umask 077
: "${MCP_GHA_ARM:?arm required}"
: "${MCP_GHA_AGE_RECIPIENT:?persistent age public recipient required}"
: "${MCP_GHA_SEALED_OUT:?sealed result destination required}"
case "$MCP_GHA_ARM" in reference|cpe) ;; *) echo BLOCKED_UNKNOWN_ARM >&2; exit 2;; esac
if [[ ! "$MCP_GHA_AGE_RECIPIENT" =~ ^age1[023456789acdefghjklmnpqrstuvwxyz]{58}$ ]]; then
  echo BLOCKED_PERSISTENT_RECIPIENT >&2
  exit 2
fi
: "${GITHUB_SHA:?GitHub source SHA required}"
: "${GITHUB_RUN_ID:?GitHub run ID required}"
for utility in age go docker curl python3 openssl sha256sum; do
  command -v "$utility" >/dev/null || { echo BLOCKED_TOOL >&2; exit 2; }
done
source_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$source_root/../.." && pwd)"
# Cannot accept a user-supplied URL or path. Each job has only its arm fixture.
plan="$repo_root/pilot/arms/$MCP_GHA_ARM/plan.json"
config="$source_root/searxng.settings.yml"
image='ghcr.io/searxng/searxng:2026.10.23-629368e40@sha256:66d58661af069af77b29153aa8e5b9504d8681de905f87e58188f2ba6084ebf2'
expected_config='66698b385c68ae5982caab9f6e60b42efebf10f08a92f6cfe59d04e80d7f76a9'
[[ -f "$plan" ]] || { echo BLOCKED_ARM_INPUT_MISSING >&2; exit 2; }
[[ "$(sha256sum "$config"|cut -d' ' -f1)" == "$expected_config" ]] || { echo BLOCKED_CONFIG_DRIFT >&2; exit 2; }
mkdir -p "$MCP_GHA_SEALED_OUT"
test ! -e "$MCP_GHA_SEALED_OUT/result.age" || { echo BLOCKED_OVERWRITE >&2; exit 2; }
scratch="$(mktemp -d)"
container=''
cleanup(){
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  rm -rf "$scratch"
}
trap cleanup EXIT INT TERM
# Optional fixed-path prewarm is used ONLY by the synthetic qualification.
# No caller-controlled executable path or image ref is accepted.
prewarmed=0
if [[ "${MCP_GHA_PREWARMED:-}" == 1 ]]; then
  [[ "${MCP_GHA_TOPOLOGY_SYNTHETIC_ONLY:-}" == 1 ]] || { echo BLOCKED_PREWARM_NOT_SYNTHETIC >&2; exit 2; }
  : "${RUNNER_TEMP:?GHA runner temp required}"
  binary="$RUNNER_TEMP/mcp-gha-stage-r-prebuilt"
  [[ -f "$binary" && -x "$binary" && ! -L "$binary" && -f "$RUNNER_TEMP/mcp-gha-prewarm-receipt.json" ]] || {
    echo BLOCKED_PREWARM_BINARY_OR_PROVENANCE >&2; exit 2;
  }
  # Verify the prewarm receipt is for THIS public Actions run, attempt,
  # commit and fixed binary+image. The runner cannot use an arbitrary binary.
  export MCP_GHA_ATTEST_BINARY="$binary"
  export MCP_GHA_ATTEST_RECEIPT="$RUNNER_TEMP/mcp-gha-prewarm-receipt.json"
  export MCP_GHA_ATTEST_IMAGE="$image"
  if ! python3 - <<'PY'
import hashlib,json,os,pathlib
r=json.loads(pathlib.Path(os.environ["MCP_GHA_ATTEST_RECEIPT"]).read_text())
binary=pathlib.Path(os.environ["MCP_GHA_ATTEST_BINARY"])
with binary.open("rb") as stream:
    digest=hashlib.file_digest(stream,"sha256").hexdigest()
assert r["schema"]=="mcp-gha-prewarm-qualification/v1"
assert r["classification"]=="PUBLIC_SYNTHETIC_ONLY"
assert r["run_id"]==os.environ["GITHUB_RUN_ID"]
assert r["run_attempt"]==os.environ.get("GITHUB_RUN_ATTEMPT","1")
assert r["source_sha"]==os.environ["GITHUB_SHA"]
assert r["provider_image_digest"]==os.environ["MCP_GHA_ATTEST_IMAGE"]
assert r["binary_sha256"]==digest
PY
  then
    echo BLOCKED_PREWARM_ATTESTATION >&2
    exit 2
  fi
  docker image inspect "$image" >/dev/null || { echo BLOCKED_PREWARM_IMAGE >&2; exit 2; }
  prewarmed=1
fi
pull_began="$(date +%s%3N)"
if ((prewarmed == 0)); then docker pull "$image" >/dev/null; fi
pull_ended="$(date +%s%3N)"
if ((prewarmed == 1)); then
  image_verify_ms="$((pull_ended-pull_began))"
  image_pull_ms=0
else
  image_verify_ms=0
  image_pull_ms="$((pull_ended-pull_began))"
fi
startup_began="$(date +%s%3N)"
container="$(docker run --detach --rm \
  --publish 127.0.0.1:18888:8080 \
  --mount type=bind,src="$config",dst=/etc/searxng/settings.yml,readonly \
  --env SEARXNG_SETTINGS_PATH=/etc/searxng/settings.yml \
  --env SEARXNG_SECRET="$(openssl rand -hex 32)" \
  --cap-drop ALL --cap-add CHOWN --cap-add SETGID --cap-add SETUID \
  --cap-add DAC_OVERRIDE --security-opt no-new-privileges "$image")"
ready=0
for _ in $(seq 1 35); do
  if [[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:18888/ || true)" == 200 ]]; then ready=1;break;fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo BLOCKED_PROVIDER_STARTUP >&2;exit 3; }
startup_ended="$(date +%s%3N)"
build_began="$(date +%s%3N)"
if ((prewarmed == 0)); then
  (cd "$source_root" && GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go build -trimpath -o "$scratch/stage-r" .)
  binary="$scratch/stage-r"
fi
build_ended="$(date +%s%3N)"
export MCP_GHA_PULL_MS="$image_pull_ms"
export MCP_GHA_IMAGE_VERIFY_MS="$image_verify_ms"
export MCP_GHA_STARTUP_MS="$((startup_ended-startup_began))"
if ((prewarmed == 1)); then
  export MCP_GHA_BUILD_MS=0
else
  export MCP_GHA_BUILD_MS="$((build_ended-build_began))"
fi
set +e
"$binary" --arm-plan "$plan" --endpoint http://127.0.0.1:18888 \
  --out "$scratch/arm-result.json" > "$scratch/stage-r-verdict.txt" 2>&1
result_code=$?
set -e
[[ -s "$scratch/arm-result.json" ]] || { echo BLOCKED_NO_STAGE_R_PACKET >&2;exit 3; }
# The only files that leave the isolated workcell are ciphertext and
# non-sensitive receipt metadata. A private key NEVER enters public GHA.
age --encrypt --recipient "$MCP_GHA_AGE_RECIPIENT" \
  --output "$MCP_GHA_SEALED_OUT/result.age" "$scratch/arm-result.json"
export MCP_GHA_RESULT_PATH="$scratch/arm-result.json"
export MCP_GHA_CIPHER_PATH="$MCP_GHA_SEALED_OUT/result.age"
export MCP_GHA_RECEIPT_PATH="$MCP_GHA_SEALED_OUT/receipt.json"
python3 - <<'PY'
import hashlib,json,os,pathlib
p=pathlib.Path(os.environ["MCP_GHA_RESULT_PATH"])
r=json.loads(p.read_text())
arm=os.environ["MCP_GHA_ARM"]
assert r["schema"]=="mcp-gha-stage-r-arm-result/v1"
assert r["arm"]==arm and {x["track"] for x in r["attempts"]}=={arm}
assert r["science_class"]=="SYNTHETIC_TRANSPORT_ONLY"
assert r["authority_status"]=="SYNTHETIC_NO_CPE_AUTHORITY_ATTESTATION"
assert r["planned_requests"]==3 and r["attempted_network"]==3
cipher=pathlib.Path(os.environ["MCP_GHA_CIPHER_PATH"])
receipt={
 "schema":"mcp-gha-sealed-arm-receipt/v1",
 "arm":arm,
 "research_status":"SYNTHETIC_TRANSPORT_ONLY_NOT_BLIND_RESEARCH",
 "source_sha":os.environ["GITHUB_SHA"],
 "run_id":os.environ["GITHUB_RUN_ID"],
 "run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT","1"),
 "plan_sha256":r["plan_sha256"],
 "provider_image_digest":r["searxng_image_digest"],
 "config_sha256":r["searxng_config_sha256"],
 "terminal_state":r["terminal_state"],
 "attempted":r["attempted_network"],
 "succeeded":r["succeeded_provider"],
 "failed":r["failed_provider"],
 "image_pull_ms":int(os.environ["MCP_GHA_PULL_MS"]),
 "provider_ready_ms":int(os.environ["MCP_GHA_STARTUP_MS"]),
 "go_build_ms":int(os.environ["MCP_GHA_BUILD_MS"]),
 "prewarmed_image_verify_ms":int(os.environ["MCP_GHA_IMAGE_VERIFY_MS"]),
 "runner_prepared_once":bool(int(os.environ.get("MCP_GHA_PREWARMED","0"))),
 "ciphertext_sha256":hashlib.sha256(cipher.read_bytes()).hexdigest(),
 "ciphertext_bytes":cipher.stat().st_size,
}
pathlib.Path(os.environ["MCP_GHA_RECEIPT_PATH"]).write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
PY
echo "MCP_GHA_${MCP_GHA_ARM}_SEALED_ARM_READY"
exit "$result_code"
