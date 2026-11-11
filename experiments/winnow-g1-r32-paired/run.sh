#!/usr/bin/env bash
# Public-safe paired G1 tool dispatch matrix; NO real Instagram/source requests.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${GITHUB_WORKSPACE:-$ROOT}/winnow-g1-r32-evidence"
mkdir -p "$OUT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
python3 -m venv "$TMP/venv"
source "$TMP/venv/bin/activate"
python -m pip --disable-pip-version-check --version > "$OUT/pip-version.txt"
mkdir -p "$TMP/wheels"

# Public PyPI package installation is the *only permitted internet phase*.
# Main tool artifacts are independently hash checked; transitive requests
# closure is recorded, not represented as an accepted production lock/SBOM.
python -m pip --disable-pip-version-check download --only-binary=:all: \
  --no-deps --index-url https://pypi.org/simple --dest "$TMP/wheels" \
  'gallery-dl==1.32.19' 'parth-dl==1.2.1' > "$OUT/pip-download.txt"
python -m pip --disable-pip-version-check download --only-binary=:all: \
  --index-url https://pypi.org/simple --dest "$TMP/wheels" \
  'requests==2.32.5' >> "$OUT/pip-download.txt"

printf '%s  %s\n' \
  f6b1eb5e9a7409a988b754335d99dbb1873e130d133ed5d164d32e5e645d1c50 \
  "$TMP/wheels/gallery_dl-1.32.19-py3-none-any.whl" | sha256sum -c -
printf '%s  %s\n' \
  3117e4c7bd6fe7c6f1b668d05c40c303e54fc3992019bf6a40ab13b98434ebff \
  "$TMP/wheels/parth_dl-1.2.1-py3-none-any.whl" | sha256sum -c -

(cd "$TMP/wheels" && sha256sum -- * > "$OUT/wheel-closure-sha256.txt")
python -m pip --disable-pip-version-check install --no-index \
  --find-links "$TMP/wheels" 'gallery-dl==1.32.19' \
  'parth-dl==1.2.1' 'requests==2.32.5' > "$OUT/install.txt"
python -m pip freeze > "$OUT/resolved-closure.txt"

# Native API calls only. In-process Python socket calls are denied with
# a positive canary; no OS-level network or child process guarantee claimed.
python "$ROOT/paired.py" "$OUT/result.json" | tee "$OUT/summary.txt"
python - "$OUT/result.json" <<'PY'
import json, sys
r=json.load(open(sys.argv[1],encoding="utf-8"))
assert r["case_count"] == 14 and r["candidate_count"] == 2
assert r["python_socket_guard_canary_pass"]
assert r["python_socket_attempts_during_classification"] == 0
assert not r["os_kernel_egress_confinement_verified"]
assert not r["no_login_instagram_access_verified"]
assert not r["original_image_bytes_verified"]
assert not r["production_go_boundary_exercised"]
assert all(len(x["observations"])==2 for x in r["cases"])
print("R32_PAIRED_REPORT_ORACLE_VALID", r["arch"], r["reference_policy_mismatches"])
PY
