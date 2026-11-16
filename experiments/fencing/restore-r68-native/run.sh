#!/usr/bin/env bash
set -euo pipefail
umask 077
root="$(mktemp -d "/tmp/r68-etcd-witness.XXXXXXXX")"
pid=""
cleanup(){ if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi; rm -rf "$root"; }
trap cleanup EXIT
curl --fail --location --silent --show-error --retry 2 --connect-timeout 15 --max-time 120 \
  'https://github.com/etcd-io/etcd/releases/download/v3.6.16/etcd-v3.6.16-linux-amd64.tar.gz' -o "$root/etcd.tgz"
printf '%s  %s\n' c8c0d96d8292ef085deabbf735e9561d3d396768e4d606df005aa25964f21911 "$root/etcd.tgz" | sha256sum -c --status
mkdir "$root/bin"
tar xzf "$root/etcd.tgz" -C "$root/bin" --strip-components=1
export ETCDCTL_API=3 ETCDCTL_ENDPOINTS=http://127.0.0.1:13379
start(){
 local dir="$1" ready=0
 "$root/bin/etcd" --name=r68 --data-dir="$dir" \
 --listen-client-urls=http://127.0.0.1:13379 \
 --advertise-client-urls=http://127.0.0.1:13379 \
 --listen-peer-urls=http://127.0.0.1:13380 \
 --initial-advertise-peer-urls=http://127.0.0.1:13380 \
 --initial-cluster=r68=http://127.0.0.1:13380 \
 --initial-cluster-token=r68-test-restore >"$root/etcd.log" 2>&1 &
 pid="$!"
 for i in $(seq 1 45); do
  if "$root/bin/etcdctl" --command-timeout=2s endpoint health >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
 done
 if [[ "$ready" != 1 ]]; then tail -n 20 "$root/etcd.log" >&2; exit 1; fi
}
ctl(){ "$root/bin/etcdctl" "$@"; }
expect_status(){
 local want="$1"; shift; local actual=0
 "$@" || actual="$?"
 if [[ "$actual" != "$want" ]]; then echo "FAIL expected $want got $actual" >&2; exit 1; fi
}
head -c 32 /dev/urandom > "$root/key.bin"
start "$root/original"
ctl put r68/epoch 7 >/dev/null
ctl put r68/budget 1 >/dev/null
ctl put r68/effect NONE >/dev/null
python3 experiments/fencing/restore-r68-native/witness.py issue "$root/bin/etcdctl" "$root/key.bin" "$root/old.json"
ctl snapshot save "$root/stale.db" >/dev/null
"$root/bin/etcdutl" snapshot status "$root/stale.db" >/dev/null
ctl put r68/epoch 8 >/dev/null
ctl put r68/budget 0 >/dev/null
ctl put r68/effect UNKNOWN >/dev/null
python3 experiments/fencing/restore-r68-native/witness.py issue "$root/bin/etcdctl" "$root/key.bin" "$root/new.json"
expect_status 43 python3 experiments/fencing/restore-r68-native/witness.py check "$root/bin/etcdctl" "$root/key.bin" "$root/new.json"
kill "$pid"; wait "$pid" 2>/dev/null || :; pid=""
"$root/bin/etcdutl" snapshot restore "$root/stale.db" \
 --name=r68 --data-dir="$root/restored" \
 --initial-cluster=r68=http://127.0.0.1:13380 \
 --initial-advertise-peer-urls=http://127.0.0.1:13380 \
 --bump-revision=100000 --mark-compacted >"$root/restore.log" 2>&1
start "$root/restored"
[[ "$(ctl get r68/epoch --print-value-only)" == 7 ]]
[[ "$(ctl get r68/budget --print-value-only)" == 1 ]]
[[ "$(ctl get r68/effect --print-value-only)" == NONE ]]
expect_status 42 python3 experiments/fencing/restore-r68-native/witness.py check "$root/bin/etcdctl" "$root/key.bin" "$root/new.json"
expect_status 43 python3 experiments/fencing/restore-r68-native/witness.py check "$root/bin/etcdctl" "$root/key.bin" "$root/old.json"
python3 - "$root/old.json" "$root/tamper.json" <<'PY'
import json,sys
with open(sys.argv[1]) as f: data=json.load(f)
data["state"]["budget"]="99"
with open(sys.argv[2],"w") as f: json.dump(data,f)
PY
expect_status 44 python3 experiments/fencing/restore-r68-native/witness.py check "$root/bin/etcdctl" "$root/key.bin" "$root/tamper.json"
expect_status 45 python3 experiments/fencing/restore-r68-native/witness.py check "$root/bin/etcdctl" "$root/key.bin" "$root/missing.json"
printf '%s\n' '{"r68_native_etcd_authenticated_restore_oracle":"PASS","native_provider":"etcd-3.6.16","new_signed_receipt_vs_old_restore":"HOLD","valid_old_db_and_valid_old_receipt":"EXPECTED_RED_TO_ANTIROLLBACK","missing_tampered":"HOLD","externally_durable_witness":"NOT_TESTED","protected_host_restore":"NOT_TESTED","production_sink":"NOT_TESTED"}'
