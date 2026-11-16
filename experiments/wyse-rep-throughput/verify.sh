#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
old_source="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$old_source" ]] || { echo BENCH_INPUT_DIRTY=RED;exit 10; }
snapshot() {
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local";do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
old_local="$(snapshot)"
vol_before="$(docker volume ls -q | LC_ALL=C sort)"
tag="wyse-throughput:${GITHUB_SHA:0:12}"
tmp="$(mktemp -d "${RUNNER_TEMP:-/tmp}/wyse-measure-XXXXXX")"
cleanup() {
 docker image rm -f "$tag" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
 rm -rf "$tmp"
}
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || { echo BENCH_DIGEST_RESOLUTION=RED;exit 11; }
echo "BENCH_BASE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --pull --build-arg "BASE_IMAGE=$base" -t "$tag" .
one() {
 docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges --memory 128m --memory-swap 128m \
 --cpus 1 --pids-limit 32 --tmpfs /tmp:rw,nosuid,nodev,size=48m,mode=1777 \
 -e "BENCH_ACTOR=$1" "$tag"
}
seq_run() {
 local id result
 for id in alpha bravo charlie;do
  result="$(one "$id")"
  [[ "$result" == "BENCH_ACTOR_${id}=PASS" ]] || return 2
 done
}
par_run() {
 local id pid failed=0
 local -a pids=()
 for id in alpha bravo charlie;do
  one "$id" >"$tmp/$id.out" 2>"$tmp/$id.err" &
  pids+=("$!")
 done
 for pid in "${pids[@]}";do wait "$pid" || failed=1;done
 [[ "$failed" -eq 0 ]] || { echo BENCH_PARALLEL_CHILD_FAILURE=RED;cat "$tmp"/*.err;return 3; }
 for id in alpha bravo charlie;do
  grep -Fxq "BENCH_ACTOR_${id}=PASS" "$tmp/$id.out" || return 4
 done
}
measure() {
 local start end
 start="$(date +%s%N)"
 "$1"
 end="$(date +%s%N)"
 echo "$(( (end-start)/1000000 ))"
}
seq_ms=()
par_ms=()
for rep in 1 2 3 4;do
 if (( rep % 2 ));then
  seq_ms+=("$(measure seq_run)")
  par_ms+=("$(measure par_run)")
 else
  par_ms+=("$(measure par_run)")
  seq_ms+=("$(measure seq_run)")
 fi
 echo "BENCH_REP_${rep}_SEQUENTIAL_MS=${seq_ms[$((rep-1))]}"
 echo "BENCH_REP_${rep}_PARALLEL_MS=${par_ms[$((rep-1))]}"
done
median() {
 printf '%s\n' "$@" | LC_ALL=C sort -n | awk 'NR==2{a=$1} NR==3{print (a+$1)/2}'
}
ms_seq="$(median "${seq_ms[@]}")"
ms_par="$(median "${par_ms[@]}")"
ratio="$(awk -v s="$ms_seq" -v p="$ms_par" 'BEGIN{if(p<=0)exit 1;printf "%.3f",s/p}')"
echo "BENCH_SEQUENTIAL_MEDIAN_MS=$ms_seq"
echo "BENCH_PARALLEL_MEDIAN_MS=$ms_par"
echo "BENCH_OBSERVED_RATIO_SEQ_OVER_PAR=$ratio"
echo BENCH_THREE_INDEPENDENT_DISPOSABLE_OCI_WORKLOADS=PASS
echo BENCH_NOT_CONTROLLED_ACROSS_ACTOR_MODEL_THROUGHPUT=YES
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$vol_before" ]] || { echo BENCH_VOLUME_TAINT=RED;exit 12; }
[[ "$(snapshot)" == "$old_local" ]] || { echo BENCH_LOCAL_TAINT=RED;exit 13; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$old_source" ]] || { echo BENCH_SOURCE_TAINT=RED;exit 14; }
cleanup;trap - EXIT
if docker image inspect "$tag" >/dev/null 2>&1;then echo BENCH_IMAGE_CLEANUP=RED;exit 15;fi
echo BENCH_DISPOSABLE_TOOLS_IMAGE_AND_TEMP_RESULTS_CLEANED=PASS
echo BENCH_HOME_PROJECT_LOCAL_SOURCE_ZERO_TAINT=PASS
