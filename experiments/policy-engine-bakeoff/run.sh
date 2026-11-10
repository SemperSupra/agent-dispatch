#!/usr/bin/env bash
# Native GitHub-hosted systemd+Podman Quadlet smoke and synthetic HTTP benchmark.
# Only disposable PUBLIC Linux x64/arm64 runners; no user secrets or protected code.
set -Eeuo pipefail
engine="$1"
case "$engine" in opa|openfga|spicedb|casbin|opal) ;; *) exit 2;; esac
base="$(cd "$(dirname "$0")" && pwd)"
out="$GITHUB_WORKSPACE/policy-bakeoff-evidence/$engine"
mkdir -p "$out"
results="$out/metrics.json"
log="$out/operator.log"
: >"$log"
on_exit() {
  rc="$?"
  if [[ "$rc" -ne 0 ]]; then
    echo "FAILED exit $rc" >>"$log"
    if [[ ! -s "$results" ]]; then
      python3 - "$results" "$engine" "$rc" <<'PY'
import json,sys,platform,pathlib
pathlib.Path(sys.argv[1]).write_text(json.dumps({
 "schema_version":1,"status":"INFRA_BLOCKED","engine":sys.argv[2],
 "exit_code":int(sys.argv[3]),"architecture":platform.machine(),
 "synthetic_only":True},sort_keys=True,indent=2)+"\n")
PY
    fi
  fi
  sudo systemctl stop "policy-bakeoff-$engine.service" >/dev/null 2>&1 || :
  if [[ "$engine" == opal ]]; then
    sudo systemctl stop policy-bakeoff-opal-client.service policy-bakeoff-opal-server.service policy-bakeoff-opal-broadcast.service >/dev/null 2>&1 || :
  fi
}
trap on_exit EXIT
echo "engine=$engine arch=$(uname -m) time=$(date -u +%FT%TZ)" | tee -a "$log"
echo "installing Podman for disposable runner (no host secrets)" | tee -a "$log"
time sudo apt-get update -qq >>"$log" 2>&1
time sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq podman >>"$log" 2>&1
sudo podman --version | tee -a "$log"
systemctl --version | head -1 | tee -a "$log"
sudo install -d -m 0755 /etc/containers/systemd
sudo cp "$base/quadlets/policy-bakeoff.network" /etc/containers/systemd/
case "$engine" in
 opa) units="policy-bakeoff-opa.container"; images="docker.io/openpolicyagent/opa:latest";;
 openfga) units="policy-bakeoff-openfga.container"; images="docker.io/openfga/openfga:latest";;
 spicedb) units="policy-bakeoff-spicedb.container"; images="ghcr.io/authzed/spicedb:v1.57.0";;
 casbin) units="policy-bakeoff-casbin.container"; images="";;
 opal) units="policy-bakeoff-opal-broadcast.container policy-bakeoff-opal-server.container policy-bakeoff-opal-client.container";
       images="docker.io/library/postgres:16-alpine docker.io/permitio/opal-server:latest docker.io/permitio/opal-client:latest";;
esac
for unit in $units; do sudo cp "$base/quadlets/$unit" /etc/containers/systemd/; done
echo "image source/arch/digest captured at execution time, never trust floating tags for production" >>"$log"
for img in $images; do
  echo "pull $img" | tee -a "$log"
  sudo podman pull "$img" >>"$log" 2>&1
  sudo podman image inspect --format 'name={{.RepoTags}} digest={{.Digest}} arch={{.Architecture}} size={{.Size}}' "$img" >>"$log"
done
if [[ "$engine" == casbin ]]; then
  echo "building synthetic Casbin v3 adapter from Go module" | tee -a "$log"
  (cd "$base/casbin"
    go version
    GOPROXY=https://proxy.golang.org go get github.com/casbin/casbin/v3@latest
    GOPROXY=https://proxy.golang.org go mod tidy
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o casbin-pdp .
    go list -m all > "$out/casbin-effective-modules.txt"
    sudo podman build -t localhost/policy-bakeoff-casbin:rdte -f Containerfile . >>"$log" 2>&1
  ) >>"$log" 2>&1
  sudo podman image inspect --format 'name={{.RepoTags}} digest={{.Digest}} arch={{.Architecture}} size={{.Size}}' localhost/policy-bakeoff-casbin:rdte >>"$log"
fi
sudo systemctl daemon-reload
echo "generated Quadlet service units" | tee -a "$log"
for unit in $units; do
  target="$(printf '%s' "$unit" | sed 's/\.container$/.service/')"
  sudo systemctl cat "$target" | head -n 24 >>"$log" || :
done
started="$(date +%s%3N)"
if [[ "$engine" == opal ]]; then
  sudo systemctl start policy-bakeoff-opal-broadcast.service >>"$log" 2>&1
  for i in $(seq 1 45); do
    if sudo podman exec policy-bakeoff-broadcast pg_isready -U postgres >/dev/null 2>&1; then break; fi
    sleep 1
  done
  sudo systemctl start policy-bakeoff-opal-server.service >>"$log" 2>&1
  sudo systemctl start policy-bakeoff-opal-client.service >>"$log" 2>&1
  checkservice="policy-bakeoff-opal-client"
else
  sudo systemctl start "policy-bakeoff-$engine.service" >>"$log" 2>&1
  checkservice="policy-bakeoff-$engine"
fi
echo "quadlet_systemd_start_ms=$(($(date +%s%3N)-started))" | tee -a "$log"
if ! sudo systemctl --quiet is-active "$checkservice.service"; then
  echo "systemd service is not active" >>"$log"
  exit 1
fi
RDTE_SAMPLES=160 RDTE_RESULT="$results" python3 "$base/bench.py" "$engine" | tee "$out/bench-output.txt"
sudo podman ps --format '{{.Names}} {{.Image}} {{.Status}}' >>"$log" || :
sudo podman stats --no-stream --format json >"$out/podman-stats.json" 2>>"$log" || :
echo "PASS $engine $(uname -m)" | tee -a "$log"
