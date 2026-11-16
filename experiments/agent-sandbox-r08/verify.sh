#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
start_status="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$start_status" ]] || { echo "R08_SOURCE_DIRTY=RED"; exit 10; }
snapshot(){
  for path in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
    if [[ -d "$path" ]]; then
      find "$path" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum
    else echo ABSENT; fi
  done
}
start_local="$(snapshot)"
volumes_before="$(docker volume ls -q | LC_ALL=C sort)"
tag="public-r08-synthetic:${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$tag" >/dev/null 2>&1 || true;docker builder prune -af >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull golang:1.24-bookworm >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' golang:1.24-bookworm)"
[[ "$base" == *@sha256:* ]] || { echo 'R08_BASE_IMMUTABLE=RED';exit 11; }
echo "R08_BASE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --pull --build-arg "GO_IMAGE=$base" -t "$tag" .
echo "R08_OFFLINE_GO_TESTS_IN_DISPOSABLE_OCI=PASS"
test "$(docker image inspect "$tag" --format '{{.Config.User}}')" = "" || { echo "R08_SCRATCH_RUNTIME_NOT_REQUIRED"; }
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$volumes_before" ]] || { echo 'R08_VOLUMES_TAINT=RED'; exit 12; }
[[ "$(snapshot)" == "$start_local" ]] || { echo 'R08_LOCAL_TAINT=RED'; exit 13; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$start_status" ]] || { echo 'R08_SOURCE_TAINT=RED';exit 14; }
cleanup; trap - EXIT
if docker image inspect "$tag" >/dev/null 2>&1; then echo "R08_DISPOSABLE_IMAGE_SURVIVED=RED";exit 15;fi
echo "R08_DISPOSABLE_TOOLCHAIN_IMAGE_CLEANUP=PASS"
echo "R08_HOME_PROJECT_SOURCE_NO_TAINT=PASS"
echo "R08_REAL_ISSUER_OR_EXTERNAL_ENFORCEMENT=NOT_TESTED"
