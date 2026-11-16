#!/usr/bin/env bash
set -euo pipefail
root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/ad-r62-restore.XXXXXXXX")"
pid=''
cleanup(){ if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi; rm -rf "$root"; }
trap cleanup EXIT
url='https://github.com/etcd-io/etcd/releases/download/v3.6.16/etcd-v3.6.16-linux-amd64.tar.gz'
curl --fail --location --silent --show-error --retry 2 --connect-timeout 15 --max-time 120 "$url" -o "$root/upstream.tar.gz"
printf '%s  %s\n' 'c8c0d96d8292ef085deabbf735e9561d3d396768e4d606df005aa25964f21911' "$root/upstream.tar.gz" | sha256sum --check --status
mkdir -p "$root/bin"
tar -xzf "$root/upstream.tar.gz" -C "$root/bin" --strip-components=1
export ETCDCTL_API=3
export ETCDCTL_ENDPOINTS='http://127.0.0.1:12379'
start(){
  local dir="$1"
  "$root/bin/etcd" --name=r62 --data-dir="$dir" \
    --listen-client-urls='http://127.0.0.1:12379' \
    --advertise-client-urls='http://127.0.0.1:12379' \
    --listen-peer-urls='http://127.0.0.1:12380' \
    --initial-advertise-peer-urls='http://127.0.0.1:12380' \
    --initial-cluster='r62=http://127.0.0.1:12380' \
    --initial-cluster-token=r62-disposable-restore \
    >"$root/etcd.log" 2>&1 &
  pid="$!"
  local i
  for i in $(seq 1 30); do
    if "$root/bin/etcdctl" --command-timeout=2s endpoint health >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  tail -n 20 "$root/etcd.log" >&2
  return 1
}
read_value(){ "$root/bin/etcdctl" get "$1" --print-value-only; }
start "$root/initial-data"
"$root/bin/etcdctl" put r62/epoch 7 >/dev/null
"$root/bin/etcdctl" put r62/budget 1 >/dev/null
"$root/bin/etcdctl" snapshot save "$root/stale-snapshot.db" >/dev/null
"$root/bin/etcdutl" snapshot status "$root/stale-snapshot.db" >/dev/null
"$root/bin/etcdctl" put r62/epoch 8 >/dev/null
"$root/bin/etcdctl" put r62/budget 0 >/dev/null
"$root/bin/etcdctl" put r62/effect/first UNKNOWN >/dev/null
[[ "$(read_value r62/epoch)" == "8" ]]
[[ "$(read_value r62/budget)" == "0" ]]
[[ "$(read_value r62/effect/first)" == "UNKNOWN" ]]
printf 'epoch=8;budget=0;effect/first=UNKNOWN\n' > "$root/test-independent-receipt.txt"
kill "$pid"; wait "$pid" 2>/dev/null || :; pid=''
"$root/bin/etcdutl" snapshot restore "$root/stale-snapshot.db" \
  --name=r62 --data-dir="$root/restored-data" \
  --initial-cluster='r62=http://127.0.0.1:12380' \
  --initial-advertise-peer-urls='http://127.0.0.1:12380' \
  --bump-revision=100000 --mark-compacted >"$root/restore.log" 2>&1
start "$root/restored-data"
[[ "$(read_value r62/epoch)" == "7" ]]
[[ "$(read_value r62/budget)" == "1" ]]
[[ -z "$(read_value r62/effect/first)" ]]
# Real conditionally admitted new budget claim against stale restored state.
python3 - <<'PY'
import urllib.request,json,base64
b=lambda x:base64.b64encode(x.encode()).decode()
req=urllib.request.Request("http://127.0.0.1:12379/v3/kv/txn",
  data=json.dumps({
    "compare":[{"target":"VALUE","key":b("r62/budget"),"value":b("1"),"result":"EQUAL"},
               {"target":"VERSION","key":b("r62/effect/second"),"version":"0"}],
    "success":[{"request_put":{"key":b("r62/budget"),"value":b("0")}},
               {"request_put":{"key":b("r62/effect/second"),"value":b("UNKNOWN")}}],
    "failure":[]}).encode(),headers={"Content-Type":"application/json"},method="POST")
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(req,timeout=5) as r: response=json.loads(r.read())
assert "header" in response and response.get("succeeded") is True,response
print(json.dumps({"provider":"native-etcd-v3.6.16","stale_snapshot_revision_bumped":True,
  "epoch_rolled_back":"EXPECTED_RED","unknown_effect_erased":"EXPECTED_RED",
  "budget_reopened":"EXPECTED_RED","new_claim_conditionally_admitted":"EXPECTED_RED",
  "external_test_receipt":"LOSS_DETECTED","production_restore":"NOT_TESTED",
  "authenticated_independent_high_water":"NOT_IMPLEMENTED","pass":True},sort_keys=True))
PY
[[ -s "$root/test-independent-receipt.txt" ]]
echo 'R62_ETCD_NATIVE_SNAPSHOT_STALE_RESTORE_COUNTEREXAMPLE_PASS'
