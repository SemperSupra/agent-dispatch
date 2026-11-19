#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
original="$(git status --porcelain --untracked-files=all)"
[[ -z "$original" ]] || { echo R27H3_DIRTY_SOURCE=RED; exit 11; }
before="$(docker volume ls -q | LC_ALL=C sort)"
suffix="${GITHUB_SHA:-local}"
suffix="${suffix:0:12}"
a="r27h3-owner-a-$suffix"; b="r27h3-owner-b-$suffix"
cleanup(){ docker rm -f "$a" "$b" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull python:3.12-slim >/dev/null
image="$(docker image inspect -f '{{index .RepoDigests 0}}' python:3.12-slim)"
[[ "$image" == *@sha256:* ]] || exit 12
echo "R27H3_PINNED_IMAGE=$image"
code='import os,socket,time; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind("\0r27h-public-owner-same-name");s.listen();print("R27H3_ABSTRACT_SOCKET_BOUND=PASS",flush=True);print("R27H3_NETWORK_NAMESPACE="+os.readlink("/proc/self/ns/net"),flush=True);time.sleep(20)'
for name in "$a" "$b"; do
 docker run -d --name "$name" --network none --read-only --user 65534:65534 \
   --cap-drop ALL --security-opt no-new-privileges \
   --memory 128m --memory-swap 128m --cpus 1 --pids-limit 32 \
   --entrypoint python3 "$image" -u -c "$code" >/dev/null
done
sleep 2
for name in "$a" "$b"; do
 [[ "$(docker inspect -f '{{.State.Running}}' "$name")" == true ]] || { docker logs "$name"; exit 13; }
 logs="$(docker logs "$name" 2>&1)"
 echo "$name: $logs"
 grep -Fq 'R27H3_ABSTRACT_SOCKET_BOUND=PASS' <<<"$logs" || exit 14
done
id_a="$(docker logs "$a" 2>&1 | sed -n 's/^R27H3_NETWORK_NAMESPACE=//p' | head -n1)"
id_b="$(docker logs "$b" 2>&1 | sed -n 's/^R27H3_NETWORK_NAMESPACE=//p' | head -n1)"
[[ -n "$id_a" && -n "$id_b" && "$id_a" != "$id_b" ]] || { echo R27H3_INDEPENDENT_NETNS=RED; exit 15; }
echo R27H3_TWO_INDEPENDENT_NETNS_SAME_ABSTRACT_NAME=REPRODUCED
echo R27H3_SAME_QEMU_DUAL_ACTUATOR=NOT_TESTED
echo R27H3_PRODUCTION_FENCING=NOT_TESTED
cleanup
trap - EXIT
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$before" ]] || { echo R27H3_VOLUME_TAINT=RED; exit 16; }
[[ "$(git status --porcelain --untracked-files=all)" == "$original" ]] || { echo R27H3_SOURCE_TAINT=RED; exit 17; }
echo R27H3_DISPOSABLE_CLEANUP=PASS
