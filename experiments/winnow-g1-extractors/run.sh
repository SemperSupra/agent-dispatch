#!/usr/bin/env bash
# Restricted public-only G1 tool compatibility comparison. No Instagram access.
set -Eeuo pipefail
candidate="$1"
case "$candidate" in
  gallery) dist='gallery-dl==1.32.19'; wheel='gallery_dl-1.32.19-py3-none-any.whl'; hash='f6b1eb5e9a7409a988b754335d99dbb1873e130d133ed5d164d32e5e645d1c50' ;;
  parth) dist='parth-dl==1.2.1'; wheel='parth_dl-1.2.1-py3-none-any.whl'; hash='3117e4c7bd6fe7c6f1b668d05c40c303e54fc3992019bf6a40ab13b98434ebff' ;;
  *) echo "unsupported candidate" >&2; exit 2 ;;
esac
BASE="$(cd "$(dirname "$0")" && pwd)"
OUT="$GITHUB_WORKSPACE/winnow-g1-evidence/$candidate"
mkdir -p "$OUT"
tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT
python3 -m venv "$tmp/venv"
source "$tmp/venv/bin/activate"
python -m pip --version > "$OUT/python-pip-version.txt"
mkdir -p "$tmp/wheels"
# The only package-network request: fetch an exact public PyPI wheel.
python -m pip --disable-pip-version-check download \
    --only-binary=:all: --no-deps --index-url https://pypi.org/simple \
    --dest "$tmp/wheels" "$dist" > "$OUT/pip-fetch.txt"
printf '%s  %s\n' "$hash" "$tmp/wheels/$wheel" | sha256sum -c - | tee "$OUT/wheel-sha256.txt"
# Offline installation: no dependency resolution, build, auto-update or scripts.
python -m pip --disable-pip-version-check install --no-index --no-deps \
    --find-links "$tmp/wheels" "$dist" > "$OUT/install.txt"
# No live Instagram URL is passed to either candidate.
python "$BASE/verify.py" "$candidate" "$OUT" "$tmp/wheels/$wheel"
python - "$OUT/result.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]))
assert v["instagram_network_requests"] == 0
assert v["instagram_bytes_retrieved"] == 0
assert not v["login_free_source_verified"]
assert not v["acceptable_for_winnow_release"]
print("PUBLIC_SAFE_G1_PROBE_COMPLETE", v["candidate"], v["runner_architecture"], v["verdict"],
      "security_failures=",v["rejected_security_checks"])
PY
