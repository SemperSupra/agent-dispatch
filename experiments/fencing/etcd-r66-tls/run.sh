#!/usr/bin/env bash
# R66: disposable native etcd mTLS + native RBAC (one public CI host only).
set -euo pipefail
umask 077
work="$(mktemp -d "/tmp/r66-etcd-tls.XXXXXXXX")"
pid=""
cleanup() {
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
  rm -rf "$work"
}
trap cleanup EXIT
archive="$work/etcd.tar.gz"
curl --fail --location --silent --show-error --retry 2 --connect-timeout 15 --max-time 120 \
  'https://github.com/etcd-io/etcd/releases/download/v3.6.16/etcd-v3.6.16-linux-amd64.tar.gz' -o "$archive"
printf '%s  %s\n' c8c0d96d8292ef085deabbf735e9561d3d396768e4d606df005aa25964f21911 "$archive" | sha256sum -c --status
tar xzf "$archive" -C "$work" --strip-components=1
openssl req -new -x509 -nodes -newkey rsa:2048 -days 1 \
  -keyout "$work/ca.key" -out "$work/ca.crt" -subj '/CN=R66 disposable CA' >/dev/null 2>&1
cert() {
  local name="$1" subject="$2" purpose="$3"
  openssl req -new -nodes -newkey rsa:2048 -keyout "$work/$name.key" \
    -out "$work/$name.csr" -subj "/CN=$subject" >/dev/null 2>&1
  if [[ "$purpose" == server ]]; then
    printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n' > "$work/$name.ext"
  else
    printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n' > "$work/$name.ext"
  fi
  openssl x509 -req -in "$work/$name.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
    -CAcreateserial -days 1 -out "$work/$name.crt" -extfile "$work/$name.ext" >/dev/null 2>&1
}
cert server server server
cert root root client
cert a r66_a client
cert b r66_b client
cert outsider r66_outsider client
"$work/etcd" --name=default --data-dir="$work/data" \
  --listen-client-urls=https://127.0.0.1:2379 \
  --advertise-client-urls=https://127.0.0.1:2379 \
  --listen-peer-urls=http://127.0.0.1:2380 \
  --initial-advertise-peer-urls=http://127.0.0.1:2380 \
  --initial-cluster=default=http://127.0.0.1:2380 \
  --initial-cluster-token=r66-disposable-one-host \
  --client-cert-auth=true --trusted-ca-file="$work/ca.crt" \
  --cert-file="$work/server.crt" --key-file="$work/server.key" \
  > "$work/server.log" 2>&1 &
pid="$!"
ctl() {
  local who="$1"; shift
  "$work/etcdctl" --endpoints=https://127.0.0.1:2379 --cacert="$work/ca.crt" \
    --cert="$work/$who.crt" --key="$work/$who.key" \
    --dial-timeout=2s --command-timeout=6s "$@"
}
ready=0
for i in $(seq 1 45); do
  if ctl root endpoint health >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then echo 'FAIL: native TLS listener not ready' >&2; tail -n 20 "$work/server.log" >&2; exit 1; fi
rootpw="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
apw="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
bpw="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
ctl root role add root >/dev/null 2>&1 || :
ctl root user add root --interactive=false --new-user-password="$rootpw" >/dev/null
ctl root user grant-role root root >/dev/null
ctl root role add r66_role_a >/dev/null
ctl root role grant-permission --prefix r66_role_a readwrite r66/tenant-a/ >/dev/null
ctl root role add r66_role_b >/dev/null
ctl root role grant-permission --prefix r66_role_b readwrite r66/tenant-b/ >/dev/null
ctl root user add r66_a --interactive=false --new-user-password="$apw" >/dev/null
ctl root user add r66_b --interactive=false --new-user-password="$bpw" >/dev/null
ctl root user grant-role r66_a r66_role_a >/dev/null
ctl root user grant-role r66_b r66_role_b >/dev/null
ctl root auth enable >/dev/null
# A and B use only their certificate identity, not --user credential.
ctl a put r66/tenant-a/ok owner-a >/dev/null
ctl b put r66/tenant-b/ok owner-b >/dev/null
[[ "$(ctl a get r66/tenant-a/ok --print-value-only)" == owner-a ]]
[[ "$(ctl b get r66/tenant-b/ok --print-value-only)" == owner-b ]]
deny() {
  local who="$1" key="$2" out
  if out="$(ctl "$who" put "$key" forbidden 2>&1)"; then
    echo "FAIL: $who unexpectedly wrote $key" >&2; return 1
  fi
  if ! grep -Eqi 'permission denied|authentication failed|invalid auth|user name is empty|user not found' <<< "$out"; then
    echo "FAIL: $who denied for an unexpected reason" >&2; return 1
  fi
}
deny a r66/tenant-b/cross
deny b r66/tenant-a/cross
deny a r66/gateway/epoch
deny outsider r66/tenant-a/outsider
if "$work/etcdctl" --endpoints=https://127.0.0.1:2379 --cacert="$work/ca.crt" \
    --dial-timeout=2s --command-timeout=3s get r66/tenant-a/ok >/dev/null 2>&1; then
  echo 'FAIL: no-client-certificate request succeeded' >&2; exit 1
fi
ctl root user revoke-role r66_b r66_role_b >/dev/null
deny b r66/tenant-b/after-revoke
ctl a put r66/tenant-a/after-revoke still-allowed >/dev/null
[[ "$(ctl root get r66/tenant-a/after-revoke --print-value-only)" == still-allowed ]]
echo '{"r66_native_etcd_mtls_rbac":"PASS","synthetic_client_certs":3,"no_cert":"DENIED","cross_scope":"DENIED","epoch_write":"DENIED","revoked_b":"DENIED","a_continuity":"PASS","independent_hosts":"NOT_TESTED","downstream_effect_sink":"NOT_TESTED","nonrollbackable_restore":"NOT_TESTED"}'
