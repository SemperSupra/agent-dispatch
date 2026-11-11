#!/usr/bin/env bash
# Disposable PUBLIC GitHub-hosted systemd+Podman S2 signed bundle RDTE.
set -Eeuo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
out="$GITHUB_WORKSPACE/opa-signed-bundle-evidence"
root=/run/opa-signed-rdte
image=docker.io/openpolicyagent/opa:1.22.3
mkdir -p "$out"
server_pid=""
cleanup() {
  rc="$?"
  sudo journalctl --no-pager -u opa-signed-rdte.service --since "15 minutes ago" > "$out/opa-journal.txt" 2>&1 || :
  sudo podman ps -a --format '{{.Names}} {{.Image}} {{.Status}}' > "$out/container-status.txt" 2>&1 || :
  sudo podman stats --no-stream --format json > "$out/container-memory.json" 2>&1 || :
  sudo systemctl stop opa-signed-rdte.service >/dev/null 2>&1 || :
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || :; fi
  if [[ "$rc" -ne 0 && ! -e "$out/result.json" ]]; then
    python3 - "$out/result.json" "$rc" <<'PY'
import json,sys
open(sys.argv[1],"w").write(json.dumps({"status":"INFRA_BLOCKED",
"exit_code":int(sys.argv[2]),"synthetic_only":True},indent=2)+"\n")
PY
  fi
}
trap cleanup EXIT
echo "native=$(uname -m) utc=$(date -u +%FT%TZ)"
sudo apt-get update -qq >>"$out/setup.log" 2>&1
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq podman openssl >>"$out/setup.log" 2>&1
sudo podman pull "$image" >>"$out/pull.log" 2>&1
sudo podman image inspect --format 'name={{.RepoTags}} digest={{.Digest}} arch={{.Architecture}} size={{.Size}}' "$image" > "$out/image-digest.txt"
sudo podman run --rm "$image" version > "$out/opa-version.txt"
grep -F 'Version: 1.22.3' "$out/opa-version.txt" >/dev/null
sudo install -d -m 0755 "$root"
sudo chown "$(id -u):$(id -g)" "$root"
mkdir -p "$root"/allow/authz "$root"/deny/authz
cp "$base/policy.rego" "$root/allow/authz/policy.rego"
cp "$base/policy.rego" "$root/deny/authz/policy.rego"
printf '{"enabled":true}\n' > "$root/allow/authz/data.json"
printf '{"enabled":false}\n' > "$root/deny/authz/data.json"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$root/private.pem" >/dev/null 2>&1
openssl pkey -in "$root/private.pem" -pubout -out "$root/public.pem" >/dev/null 2>&1
chmod 0600 "$root/private.pem"
# The only signing key is an EPHEMERAL synthetic test key, never a product key.
opa() {
  sudo podman run --rm -v "$root:/work:rw" "$image" "$@"
}
opa check /work/allow/authz/policy.rego > "$out/policy-check.txt"
opa build --bundle --signing-key /work/private.pem \
  --verification-key-id synthetic --revision synthetic-allow-001 \
  --output /work/allow.tar.gz /work/allow >>"$out/build.log" 2>&1
opa build --bundle --signing-key /work/private.pem \
  --verification-key-id synthetic --revision synthetic-deny-002 \
  --output /work/deny.tar.gz /work/deny >>"$out/build.log" 2>&1
opa build --bundle --revision synthetic-unsigned --output /work/unsigned.tar.gz \
  /work/deny >>"$out/build.log" 2>&1
tar tzf "$root/allow.tar.gz" > "$out/allow-members.txt"
tar tzf "$root/deny.tar.gz" > "$out/deny-members.txt"
grep -F '.signatures.json' "$out/allow-members.txt" >/dev/null
grep -F '.signatures.json' "$out/deny-members.txt" >/dev/null
python3 "$base/bundle_fixtures.py" "$root"
python3 - "$root/public.pem" "$root/opa.yaml" <<'PY'
from pathlib import Path
import sys
pub=Path(sys.argv[1]).read_text()
config="""services:
  - name: synthetic
    url: http://127.0.0.1:8099
bundles:
  authz:
    service: synthetic
    resource: bundle.tar.gz
    polling:
      min_delay_seconds: 1
      max_delay_seconds: 2
    signing:
      keyid: synthetic
keys:
  synthetic:
    algorithm: RS256
    key: |
"""
config += "".join("      "+line+"\n" for line in pub.splitlines())
Path(sys.argv[2]).write_text(config)
PY
chmod 0644 "$root/opa.yaml"
cp "$root/allow.tar.gz" "$root/active.tar.gz"
python3 "$base/bundle_server.py" "$root" > "$out/bundle-server.log" 2>&1 &
server_pid="$!"
python3 - <<'PY'
import time,urllib.request
for _ in range(100):
    try:
        with urllib.request.urlopen("http://127.0.0.1:8099/bundle.tar.gz",timeout=1) as v:
            if v.status==200: break
    except Exception: time.sleep(.1)
else: raise SystemExit("local bundle-server failed startup")
PY
sudo install -d /etc/containers/systemd
sudo cp "$base/opa-signed-rdte.container" /etc/containers/systemd/
sudo systemctl daemon-reload
sudo systemctl cat opa-signed-rdte.service > "$out/generated-systemd-unit.txt"
sudo systemctl start opa-signed-rdte.service
sudo systemctl --quiet is-active opa-signed-rdte.service
python3 "$base/qualify.py" "$root" "$out" | tee "$out/qualification.log"
echo "OPA_SIGNED_BUNDLE_PUBLIC_SYNTHETIC_PASS native=$(uname -m)"
