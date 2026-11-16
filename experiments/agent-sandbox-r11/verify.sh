#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
before_source="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$before_source" ]] || { echo "R11_DIRTY_INPUT=RED"; exit 10; }
watch_paths(){
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
local_before="$(watch_paths)"
vols_before="$(docker volume ls -q | LC_ALL=C sort)"
prefix="public-r11-${GITHUB_SHA:0:12}"
tmp="$(mktemp -d "$RUNNER_TEMP/r11-XXXXXXXX")"
mkdir -p "$tmp/ipc" "$tmp/trust" "$tmp/public" "$tmp/grants" "$tmp/state"
chmod 0777 "$tmp" "$tmp/ipc" "$tmp/trust" "$tmp/public" "$tmp/grants" "$tmp/state"
name=public-r11-broker
cleanup(){
 docker rm -f "$name" >/dev/null 2>&1 || true
 for i in broker client issuer;do docker image rm -f "$prefix-$i" >/dev/null 2>&1 || true;done
 docker builder prune -af >/dev/null 2>&1 || true
 rm -rf "$tmp"
}
trap cleanup EXIT
docker pull golang:1.24-bookworm >/dev/null
base="$(docker image inspect --format '{{ index .RepoDigests 0}}' golang:1.24-bookworm)"
[[ "$base" == *@sha256:* ]] || { echo R11_GO_BASE_DIGEST=RED; exit 11; }
echo "R11_DISPOSABLE_BASE_REFERENCE=$base"
for stage in broker client issuer;do
 DOCKER_BUILDKIT=1 docker build --no-cache --pull --build-arg "GO_IMAGE=$base" --target "$stage" -t "$prefix-$stage" .
done
echo "R11_DISPOSABLE_TOOLCHAIN_AND_THREE_SCRATCH_ROLES=PASS"

opts=(--rm --read-only --network none --user 65532:65532 --cap-drop ALL
 --security-opt no-new-privileges --memory 96m --memory-swap 96m --cpus 1 --pids-limit 40)
issuer(){
 docker run "${opts[@]}" \
  --mount "type=bind,src=$tmp/trust,dst=/trust" \
  --mount "type=bind,src=$tmp/grants,dst=/grants" \
  "$prefix-issuer" "$@"
}
issuer keygen
if [[ ! -s "$tmp/trust/issuer.pub" || ! -s "$tmp/trust/owner.pub" ]];then
 echo "R11_TEST_KEY_MATERIAL_MISSING=RED"; exit 12
fi
sudo cp "$tmp/trust/issuer.pub" "$tmp/trust/owner.pub" "$tmp/public/"
sudo chmod 0644 "$tmp/public/"*.pub
printf '2\n' > "$tmp/state/epoch_min"
chmod 0666 "$tmp/state/epoch_min"
start_broker(){
 docker run --rm -d --name "$name" --read-only --network none --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 96m --memory-swap 96m --cpus 1 --pids-limit 40 \
 --mount "type=bind,src=$tmp/public,dst=/trust,readonly" \
 --mount "type=bind,src=$tmp/state,dst=/state" \
 --mount "type=bind,src=$tmp/ipc,dst=/ipc" \
 "$prefix-broker" >/dev/null
 local ready=0
 for _ in $(seq 1 50);do
  if [[ -S "$tmp/ipc/broker.sock" ]];then ready=1;break;fi
  sleep 0.1
 done
 if [[ "$ready" != 1 ]];then
  echo "R11_BROKER_SOCKET_UNAVAILABLE=RED";docker logs "$name" || true; exit 13
 fi
}
client(){
 docker run "${opts[@]}" \
 --mount "type=bind,src=$tmp/ipc,dst=/ipc,readonly" \
 --mount "type=bind,src=$tmp/grants,dst=/grants,readonly" \
 "$prefix-client" "$@"
}
mint(){ issuer mint "$@"; }
start_broker
mint "nonce-01" "guest.tools" no 2 "token-guest"
client token-guest guest.tools ALLOW
client token-guest guest.tools DENY
echo 'R11_SIGNED_GRANT_REPLAY_DENIED=PASS'

mint "nonce-02" "host.raw_qmp" yes 2 "token-host"
client token-host host.raw_qmp DENY
mint "nonce-03" "external.synthetic_effect" no 2 "token-noowner"
client token-noowner external.synthetic_effect DENY
mint "nonce-04" "external.synthetic_effect" yes 2 "token-effect"
client token-effect external.synthetic_effect ALLOW
[[ "$(sudo grep -c '^SYNTHETIC_ONLY:nonce-04$' "$tmp/state/effects.log")" == 1 ]] || { echo R11_SYNTHETIC_EFFECT_NOT_OBSERVED=RED; exit 14; }
echo "R11_EXTERNAL_MOCK_EFFECT_INDEPENDENTLY_OBSERVED=PASS"
client token-effect external.synthetic_effect DENY

mint "nonce-05" "guest.root" no 2 "token-tamper"
client token-tamper guest.root DENY tamper
mint "nonce-06" "guest.root" no 2 "token-wrong"
client token-wrong guest.root DENY wrong_actor
mint "nonce-07" "guest.root" no 2 "token-revoked"
printf '3\n' > "$tmp/state/epoch_min"
client token-revoked guest.root DENY
echo "R11_REVOCATION_EPOCH_ENFORCED_EXTERNALLY=PASS"
mint "nonce-08" "guest.root" no 3 "token-fresh"
client token-fresh guest.root ALLOW
docker stop "$name" >/dev/null
for _ in $(seq 1 50);do
 if ! docker inspect "$name" >/dev/null 2>&1;then break;fi
 sleep 0.1
done
if docker inspect "$name" >/dev/null 2>&1;then echo "R11_BROKER_NOT_DISPOSABLE=RED"; exit 15;fi
start_broker
client token-fresh guest.root DENY
client token-effect external.real_network DENY
[[ "$(grep -c '^SYNTHETIC_ONLY:' "$tmp/state/effects.log")" == 1 ]] || { echo R11_UNAUTHORIZED_EXTRA_EFFECT=RED; exit 16; }
echo "R11_EXTERNAL_LEDGER_SURVIVED_BROKER_RESTART=PASS"
echo "R11_ONLY_ONE_APPROVED_SYNTHETIC_EFFECT=PASS"
docker stop "$name" >/dev/null
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$vols_before" ]] || { echo R11_HOST_VOLUME_TAINT=RED; exit 17; }
[[ "$(watch_paths)" == "$local_before" ]] || { echo R11_LOCAL_TAINT=RED; exit 18; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$before_source" ]] || { echo R11_SOURCE_TAINT=RED; exit 19; }
cleanup;trap - EXIT
echo "R11_BROKER_ISSUER_CLIENT_AND_TEST_KEY_DISPOSAL=PASS"
echo "R11_HOME_PROJECT_LOCAL_SOURCE_ZERO_TAINT=PASS"
echo "R11_REAL_PRODUCTION_ISSUER_AND_HYPERVISOR_AUTHORITY=NOT_TESTED"
