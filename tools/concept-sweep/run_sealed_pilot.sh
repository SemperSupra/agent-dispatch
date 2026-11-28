#!/usr/bin/env bash
# Fixed public-safe MCP GHA transport canary; NEVER a real CPE science run.
set -euo pipefail
umask 077

: "${MCP_GHA_SEALED_OUT:?Output dir required}"
: "${MCP_GHA_AGE_RECIPIENT:?Persistent age public recipient must be configured}"
if [[ ! "$MCP_GHA_AGE_RECIPIENT" =~ ^age1[023456789acdefghjklmnpqrstuvwxyz]{58}$ ]]; then
  echo 'BLOCKED_PERSISTENT_AGE_RECIPIENT' >&2
  exit 2
fi
for utility in age go docker curl python3 openssl sha256sum; do
  command -v "$utility" >/dev/null || { echo 'BLOCKED_REQUIRED_TOOL' >&2; exit 2; }
done

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
plan="$root/pilot-plan.json"
projection="$root/pilot-projection.json"
config="$root/searxng.settings.yml"
image='ghcr.io/searxng/searxng:2026.10.23-629368e40@sha256:66d58661af069af77b29153aa8e5b9504d8681de905f87e58188f2ba6084ebf2'
expected_config='66698b385c68ae5982caab9f6e60b42efebf10f08a92f6cfe59d04e80d7f76a9'
actual_config="$(sha256sum "$config" | cut -d' ' -f1)"
[[ "$actual_config" == "$expected_config" ]] || { echo 'BLOCKED_SEARXNG_CONFIG_DRIFT' >&2; exit 2; }
[[ -f "$plan" && -f "$projection" ]] || { echo 'BLOCKED_APPROVED_PUBLIC_FIXTURES' >&2; exit 2; }
[[ -n "${GITHUB_SHA:-}" && -n "${GITHUB_RUN_ID:-}" ]] || { echo 'BLOCKED_MISSING_GHA_PROVENANCE' >&2; exit 2; }

# No stdout/stderr from queries or provider result payloads.
work="$(mktemp -d)"
container=''
cleanup() {
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  rm -rf -- "$work"
}
trap cleanup EXIT INT TERM
mkdir -p -- "$MCP_GHA_SEALED_OUT"
test ! -e "$MCP_GHA_SEALED_OUT/result.age" || { echo 'BLOCKED_EXISTING_SEALED_ARTIFACT' >&2; exit 2; }

docker pull "$image" >/dev/null
container="$(docker run --detach --rm \
  --publish 127.0.0.1:18888:8080 \
  --mount type=bind,src="$config",dst=/etc/searxng/settings.yml,readonly \
  --env SEARXNG_SETTINGS_PATH=/etc/searxng/settings.yml \
  --env SEARXNG_SECRET="$(openssl rand -hex 32)" \
  --cap-drop ALL --cap-add CHOWN --cap-add SETGID --cap-add SETUID \
  --cap-add DAC_OVERRIDE --security-opt no-new-privileges "$image")"
ready=0
for _ in $(seq 1 35); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:18888/ 2>/dev/null || true)"
  if [[ "$code" == 200 ]]; then ready=1; break; fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo 'BLOCKED_SEARXNG_STARTUP'; exit 3; }

(cd "$root" && GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go build -trimpath -o "$work/stage-r" .)
set +e
"$work/stage-r" --plan "$plan" --projection "$projection" \
  --endpoint http://127.0.0.1:18888 --out "$work/stage-r.json" >"$work/verdict.txt" 2>&1
rc=$?
set -e
if [[ ! -f "$work/stage-r.json" ]]; then
  echo 'BLOCKED_STAGE_R_NO_OUTPUT'
  exit 3
fi

# Never upload plaintext. Persist only the age recipient's ciphertext.
age --encrypt --recipient "$MCP_GHA_AGE_RECIPIENT" \
  --output "$MCP_GHA_SEALED_OUT/result.age" "$work/stage-r.json"
export MCP_GHA_PILOT_RESULT="$work/stage-r.json"
export MCP_GHA_PILOT_CIPHER="$MCP_GHA_SEALED_OUT/result.age"
export MCP_GHA_PILOT_RECEIPT="$MCP_GHA_SEALED_OUT/receipt.json"
python3 - <<'PY'
import hashlib, json, os, pathlib
result=json.loads(pathlib.Path(os.environ["MCP_GHA_PILOT_RESULT"]).read_text())
cipher=pathlib.Path(os.environ["MCP_GHA_PILOT_CIPHER"])
assert result["schema"]=="mcp-gha-stage-r/v1"
assert result["authority_status"]=="PROJECTION_DIGEST_MATCH_ONLY_NOT_AUTHORITY_VERIFIED"
assert result["planned_requests"]==6 and result["attempted_network"]==6
assert {a["track"] for a in result["attempts"]}=={"reference","cpe"}
assert {a["language"] for a in result["attempts"]}=={"en","de","th"}
receipt={
    "schema":"mcp-gha-sealed-transport-canary/v1",
    "science_valid":False,
    "treatment_authenticity":"SYNTHETIC_TEST_ONLY_NOT_CPE_AUTHORITY",
    "public_run_id":os.environ["GITHUB_RUN_ID"],
    "public_run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT","1"),
    "source_sha":os.environ["GITHUB_SHA"],
    "plan_sha256":result["plan_sha256"],
    "projection_sha256":result["projection_sha256"],
    "searxng_image_digest":result["searxng_image_digest"],
    "searxng_config_sha256":result["searxng_config_sha256"],
    "terminal_state":result["terminal_state"],
    "attempted":result["attempted_network"],
    "succeeded":result["succeeded_provider"],
    "failed":result["failed_provider"],
    "ciphertext_sha256":hashlib.sha256(cipher.read_bytes()).hexdigest(),
    "ciphertext_bytes":cipher.stat().st_size,
}
pathlib.Path(os.environ["MCP_GHA_PILOT_RECEIPT"]).write_text(
    json.dumps(receipt,sort_keys=True,indent=2)+"\n")
PY
echo 'MCP_GHA_PUBLIC_SYNTHETIC_SEALED_RESULT_READY'
# A provider failure is evidence, not a fabricated successful search.
exit "$rc"
