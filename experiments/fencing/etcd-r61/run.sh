#!/usr/bin/env bash
set -euo pipefail
root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/r61-etcd.XXXXXXXX")"
declare -a pids=()
cleanup() {
  for p in "${pids[@]}"; do test -z "${p:-}" || kill "$p" 2>/dev/null || :; done
  sleep 1
  rm -rf "$root"
}
trap cleanup EXIT
url="https://github.com/etcd-io/etcd/releases/download/v3.6.16/etcd-v3.6.16-linux-amd64.tar.gz"
archive="$root/etcd.tar.gz"
curl --fail --location --silent --show-error --retry 2 --connect-timeout 15 --max-time 120 "$url" -o "$archive"
printf '%s  %s\n' 'c8c0d96d8292ef085deabbf735e9561d3d396768e4d606df005aa25964f21911' "$archive" | sha256sum --check --status
tar xzf "$archive" --directory "$root" --strip-components=1
"$root/etcd" --version | head -n 1
cluster="e1=http://127.0.0.1:2380,e2=http://127.0.0.1:2381,e3=http://127.0.0.1:2382"
start() {
  local n="$1" c="$2" p="$3"
  "$root/etcd" \
    --name="e${n}" --data-dir="$root/e${n}-data" \
    --listen-client-urls="http://127.0.0.1:${c}" \
    --advertise-client-urls="http://127.0.0.1:${c}" \
    --listen-peer-urls="http://127.0.0.1:${p}" \
    --initial-advertise-peer-urls="http://127.0.0.1:${p}" \
    --initial-cluster="$cluster" --initial-cluster-state=new \
    --initial-cluster-token=r61-public-synthetic \
    >"$root/e${n}.log" 2>&1 &
  pids[$n]="$!"
}
ready() {
  local i
  for i in $(seq 1 45); do
    if "$root/etcdctl" --endpoints=http://127.0.0.1:2379 --command-timeout=2s endpoint health >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "etcd cluster readiness failed; last 20 lines of synthetic local peer logs:" >&2
  for n in 1 2 3; do echo "--- e$n ---" >&2; tail -n 20 "$root/e$n.log" >&2 || :; done
  return 1
}
start 1 2379 2380
start 2 22379 2381
start 3 32379 2382
ready
python3 experiments/fencing/etcd-r61/txn_test.py race
python3 experiments/fencing/etcd-r61/gateway_txn_test.py
kill "${pids[3]}" 2>/dev/null || :
wait "${pids[3]}" 2>/dev/null || :
sleep 3
python3 experiments/fencing/etcd-r61/txn_test.py quorum2
kill "${pids[2]}" 2>/dev/null || :
wait "${pids[2]}" 2>/dev/null || :
sleep 3
python3 experiments/fencing/etcd-r61/txn_test.py noquorum
start 2 22379 2381
ready
python3 experiments/fencing/etcd-r61/txn_test.py recovered
echo 'R61_NATIVE_ETCD_ONE_HOST_QUORUM_PASS; REAL_CROSS_HOST_FENCING_NOT_TESTED'
