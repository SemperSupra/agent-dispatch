#!/usr/bin/env bash
# One-shot preparation for a single, synthetic-only ephemeral GitHub VM.
# Image/binary stay local to this job; never upload executables or shared cache.
set -euo pipefail
umask 077
[[ "${MCP_GHA_TOPOLOGY_SYNTHETIC_ONLY:-}" == 1 ]] || { echo BLOCKED_NON_SYNTHETIC_PREWARM >&2; exit 2; }
: "${RUNNER_TEMP:?GHA isolated runner temp required}"
: "${GITHUB_RUN_ID:?native provenance required}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
image='ghcr.io/searxng/searxng:2026.10.23-629368e40@sha256:66d58661af069af77b29153aa8e5b9504d8681de905f87e58188f2ba6084ebf2'
for utility in go docker date python3 sha256sum; do
  command -v "$utility" >/dev/null || { echo BLOCKED_PREWARM_TOOL >&2; exit 2; }
done
binary="$RUNNER_TEMP/mcp-gha-stage-r-prebuilt"
receipt="$RUNNER_TEMP/mcp-gha-prewarm-receipt.json"
[[ ! -e "$binary" && ! -e "$receipt" ]] || { echo BLOCKED_PREWARM_REPLAY >&2; exit 2; }
pull_started="$(date +%s%3N)"
docker pull "$image" >/dev/null
pull_finished="$(date +%s%3N)"
build_started="$(date +%s%3N)"
(cd "$root" && GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go build -trimpath -o "$binary" .)
build_finished="$(date +%s%3N)"
[[ -f "$binary" && -x "$binary" && ! -L "$binary" ]] || { echo BLOCKED_PREWARM_BINARY >&2; exit 2; }
export PREP_PULL_MS="$((pull_finished-pull_started))"
export PREP_BUILD_MS="$((build_finished-build_started))"
export PREP_RECEIPT="$receipt"
export PREP_BINARY_SHA256="$(sha256sum "$binary" | cut -d' ' -f1)"
export PREP_PINNED_IMAGE="$image"
python3 - <<'PY'
import json,os,pathlib
d={
 "schema":"mcp-gha-prewarm-qualification/v1",
 "classification":"PUBLIC_SYNTHETIC_ONLY",
 "run_id":os.environ["GITHUB_RUN_ID"],
 "run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT","1"),
 "source_sha":os.environ["GITHUB_SHA"],
 "binary_sha256":os.environ["PREP_BINARY_SHA256"],
 "provider_image_digest":os.environ["PREP_PINNED_IMAGE"],
 "image_pull_ms":int(os.environ["PREP_PULL_MS"]),
 "go_build_ms":int(os.environ["PREP_BUILD_MS"]),
 "runner_os":os.environ.get("RUNNER_OS","unknown"),
 "runner_arch":os.environ.get("RUNNER_ARCH","unknown"),
}
pathlib.Path(os.environ["PREP_RECEIPT"]).write_text(json.dumps(d,sort_keys=True,indent=2)+"\n")
PY
echo "MCP_GHA_PREWARM_SYNTHETIC_PASS image_pull_ms=$PREP_PULL_MS go_build_ms=$PREP_BUILD_MS"
