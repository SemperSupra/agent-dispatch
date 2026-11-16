#!/usr/bin/env bash
set -euo pipefail
command -v docker >/dev/null
root=$(mktemp -d "${RUNNER_TEMP:-/tmp}/ad-r62-net.XXXXXXXX")
net="ad-r62-etcd-${GITHUB_RUN_ID:-$$}"
image="ad-r62-etcd:${GITHUB_RUN_ID:-local}"
names=("${net}-e1" "${net}-e2" "${net}-e3")
cleanup() {
  for n in "${names[@]}"; do docker rm -f "$n" >/dev/null 2>&1 || :; done
  docker network rm "$net" >/dev/null 2>&1 || :
  docker image rm "$image" >/dev/null 2>&1 || :
  rm -rf "$root"
}
trap cleanup EXIT
url="https://github.com/etcd-io/etcd/releases/download/v3.6.16/etcd-v3.6.16-linux-amd64.tar.gz"
curl --fail --location --silent --show-error --retry 2 --connect-timeout 15 --max-time 120 "$url" -o "$root/upstream.tar.gz"
printf '%s  %s\n' 'c8c0d96d8292ef085deabbf735e9561d3d396768e4d606df005aa25964f21911' "$root/upstream.tar.gz" | sha256sum --check --status
mkdir -p "$root/unpack" "$root/build"
tar -xzf "$root/upstream.tar.gz" -C "$root/unpack" --strip-components=1
cp "$root/unpack/etcd" "$root/build/etcd"
printf 'FROM scratch\nCOPY etcd /etcd\nUSER 65532:65532\nENTRYPOINT ["/etcd"]\n' > "$root/build/Dockerfile"
docker build --quiet --network none --tag "$image" "$root/build" >/dev/null
docker network create --driver bridge --internal --subnet 172.29.62.0/24 "$net" >/dev/null
cluster='e1=http://172.29.62.11:2380,e2=http://172.29.62.12:2380,e3=http://172.29.62.13:2380'
start_peer(){
  local i="$1"
  local ip="172.29.62.1${i}" port="$2" nm="${names[$((i-1))]}"
  docker run --detach --rm --name "$nm" --network "$net" --ip "$ip" \
    -p "127.0.0.1:${port}:2379" \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /data:rw,nosuid,nodev,size=64m,mode=1777 --user 65532:65532 \
    "$image" \
    --name "e${i}" --data-dir=/data \
    --listen-client-urls=http://0.0.0.0:2379 \
    --advertise-client-urls="http://${ip}:2379" \
    --listen-peer-urls=http://0.0.0.0:2380 \
    --initial-advertise-peer-urls="http://${ip}:2380" \
    --initial-cluster="$cluster" --initial-cluster-state=new \
    --initial-cluster-token=r62-synthetic-containers \
    --log-level=warn >/dev/null
}
start_peer 1 2379
start_peer 2 22379
start_peer 3 32379
ready(){
  local i
  for i in $(seq 1 45); do
    if python3 experiments/fencing/net-r62/test_net.py ready >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "R62 startup failed; synthetic tail logs" >&2
  for n in "${names[@]}"; do docker logs --tail 10 "$n" >&2 || :; done
  return 1
}
ready
python3 experiments/fencing/net-r62/test_net.py start
# Disconnect the peer network without terminating e3; e1 and e2 keep quorum.
docker network disconnect --force "$net" "${names[2]}"
sleep 7
python3 experiments/fencing/net-r62/test_net.py two
docker network disconnect --force "$net" "${names[1]}"
sleep 7
python3 experiments/fencing/net-r62/test_net.py one
docker network connect --ip 172.29.62.12 "$net" "${names[1]}"
docker network connect --ip 172.29.62.13 "$net" "${names[2]}"
sleep 10
python3 experiments/fencing/net-r62/test_net.py recover
echo 'R62_ETCD_CONTAINER_NETWORK_PARTITION_PASS; PHYSICAL_CROSS_HOST_NOT_TESTED'
