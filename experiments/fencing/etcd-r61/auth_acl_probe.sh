#!/usr/bin/env bash
# R63 synthetic native etcd authentication. Never use with real credentials.
set -euo pipefail
dir="$1"
ctl() { "$dir/etcdctl" --endpoints=http://127.0.0.1:2379 --command-timeout=8s "$@"; }
# Ephemeral randomness: values are never printed, written or committed.
rootpw=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
apw=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
bpw=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
# root is a reserved cluster-wide management role. No external grants.
ctl role add root >/dev/null 2>&1 || :
ctl user add root --interactive=false --new-user-password="$rootpw" >/dev/null
ctl user grant-role root root >/dev/null
ctl role add r63_role_a >/dev/null
ctl role grant-permission --prefix r63_role_a readwrite r63/tenant-a/ >/dev/null
ctl role add r63_role_b >/dev/null
ctl role grant-permission --prefix r63_role_b readwrite r63/tenant-b/ >/dev/null
ctl user add r63_a --interactive=false --new-user-password="$apw" >/dev/null
ctl user add r63_b --interactive=false --new-user-password="$bpw" >/dev/null
ctl user grant-role r63_a r63_role_a >/dev/null
ctl user grant-role r63_b r63_role_b >/dev/null
ctl auth enable >/dev/null
# Separate real etcd auth principal can operate ONLY its own key prefix.
ctl --user="r63_a:$apw" put r63/tenant-a/ok A >/dev/null
ctl --user="r63_b:$bpw" put r63/tenant-b/ok B >/dev/null
[[ "$(ctl --user="r63_a:$apw" get r63/tenant-a/ok --print-value-only)" == A ]]
[[ "$(ctl --user="r63_b:$bpw" get r63/tenant-b/ok --print-value-only)" == B ]]
expect_permission_deny() {
 local principal="$1" pw="$2" key="$3" response
 if response=$(ctl --user="$principal:$pw" put "$key" forbidden 2>&1); then
   echo 'FAIL unauthorized etcd effect admitted' >&2; return 1
 fi
 if ! grep -qi 'permission denied' <<<"$response"; then
   echo 'FAIL failed request was not classified permission denial' >&2; return 1
 fi
}
expect_permission_deny r63_a "$apw" r63/tenant-b/cross
expect_permission_deny r63_b "$bpw" r63/tenant-a/cross
expect_permission_deny r63_a "$apw" r63/gateway/epoch
expect_permission_deny r63_b "$bpw" r63/gateway/epoch
# Root can revoke the user's role; previously working tenant now must fail.
ctl --user="root:$rootpw" user revoke-role r63_b r63_role_b >/dev/null
expect_permission_deny r63_b "$bpw" r63/tenant-b/after-revoke
ctl --user="r63_a:$apw" put r63/tenant-a/after-revoke still-allowed >/dev/null
[[ "$(ctl --user="root:$rootpw" get r63/tenant-a/after-revoke --print-value-only)" == still-allowed ]]
echo '{"r63_native_etcd_auth":"PASS","scoped_tenants":2,"cross_scope_writes":"DENIED","epoch_write_by_nonroot":"DENIED","revoked_user":"DENIED","independent_physical_hosts":"NOT_TESTED","client_TLS":"NOT_TESTED","root_restore_hardening":"NOT_TESTED"}'
