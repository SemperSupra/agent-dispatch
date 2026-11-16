#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
source_before="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$source_before" ]] || { echo 'R04_INPUT_DIRTY=RED'; exit 10; }
case "$R04_TARGET" in
  aarch64)
    debian_arch=arm64; libc=arm64; qemu_pkg=qemu-system-arm
    sha=9c37ace54ef7e1919411fd912e9f34d6982ddd7f4c8ef3c8aee56f4c4d70db67
    ;;
  riscv64)
    debian_arch=riscv64; libc=riscv64; qemu_pkg=qemu-system-misc
    sha=8898c27a38f0bfcc3d9a4b0687ee752c4a2b3028576f919ba8955d2cbd6d4722
    ;;
  *) echo 'R04_UNKNOWN_ARCH=RED'; exit 11 ;;
esac
local_snapshot(){
  for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
    if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum
    else echo ABSENT;fi
  done
}
local_before="$(local_snapshot)"
volumes_before="$(docker volume ls -q | LC_ALL=C sort)"
image="public-sandbox-r04-${R04_TARGET}:${GITHUB_SHA:0:12}"
cleanup(){
  docker image rm -f "$image" >/dev/null 2>&1 || true
  docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull ubuntu:24.04 >/dev/null
digest="$(docker image inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04)"
[[ "$digest" == *@sha256:* ]] || { echo 'R04_BASE_DIGEST=RED'; exit 12; }
echo "R04_BASE_IMMUTABLE_REFERENCE=$digest"
DOCKER_BUILDKIT=1 docker build --no-cache --pull -f Dockerfile \
  --build-arg "BASE_IMAGE=$digest" \
  --build-arg "TARGET_TRIPLE=$R04_TARGET" \
  --build-arg "TARGET_LIBC=$libc" \
  --build-arg "DEBIAN_ARCH=$debian_arch" \
  --build-arg "KERNEL_SHA=$sha" \
  --build-arg "QEMU_PACKAGE=$qemu_pkg" \
  --build-arg "TARGET_NAME=$R04_TARGET" \
  --tag "$image" .
echo 'R04_DISPOSABLE_BUILD_AND_KERNEL_DIGEST_VALIDATION=PASS'
python3 - "$image" "$R04_TARGET" <<'PY'
import json, subprocess,sys,time
image,arch=sys.argv[1:3]
cmd=["docker","run","--rm","--network","none","--read-only",
"--user","65532:65532","--cap-drop","ALL","--security-opt","no-new-privileges",
"--memory","1024m","--memory-swap","1024m","--cpus","2","--pids-limit","128",
"--tmpfs","/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",image]
start=time.monotonic()
try:
 result=subprocess.run(cmd,capture_output=True,text=True,errors="replace",timeout=120)
except subprocess.TimeoutExpired as ex:
 print("R04_ACTUAL_GUEST_BOOT=RED_TIMEOUT")
 print("R04_BOUNDED_CONSOLE_TAIL="+str((ex.stdout or b"")[-800:]))
 raise SystemExit(13)
out=result.stdout+"\n"+result.stderr
elapsed=time.monotonic()-start
marker="R04_GUEST_INIT_REACHED=PASS ARCH="+arch
if "Linux version" not in out or marker not in out or result.returncode!=0:
 print("R04_ACTUAL_GUEST_BOOT=RED")
 print("R04_VM_EXIT="+str(result.returncode))
 print("R04_KERNEL_VERSION_PRESENT="+str("Linux version" in out))
 print("R04_INIT_MARKER_PRESENT="+str(marker in out))
 print("R04_GUEST_CONSOLE_TAIL="+out[-1700:].replace("\r",""))
 raise SystemExit(14)
print("R04_ACTUAL_FOREIGN_LINUX_KERNEL_AND_INIT_BOOT=PASS ARCH="+arch)
print("R04_VM_EXIT_CLEAN=PASS")
print("R04_COLD_START_TO_GUEST_SHUTDOWN_SECONDS=%.3f"%elapsed)
print("R04_QEMU_SYSTEM_TCG_ISA="+arch)
print("R04_NO_GUEST_NETWORK_OR_PERSISTENT_STORAGE=DECLARED")
print("R04_GUEST_INTERACTIVE_OS_INSTALLER=NOT_TESTED")
print("R04_ACTOR_PERFORMANCE_AND_HOST_ISOLATION=NOT_TESTED")
PY
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$volumes_before" ]] || { echo 'R04_VOLUME_TAINT=RED'; exit 15; }
[[ "$(local_snapshot)" == "$local_before" ]] || { echo 'R04_LOCAL_TAINT=RED'; exit 16; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$source_before" ]] || { echo 'R04_SOURCE_TAINT=RED'; exit 17; }
cleanup;trap - EXIT
if docker image inspect "$image" >/dev/null 2>&1; then echo 'R04_IMAGE_CACHE_CLEANUP=RED'; exit 18; fi
echo 'R04_TOOLCHAIN_AND_RUNTIME_REMOVED=PASS'
echo 'R04_HOME_PROJECT_LOCAL_AND_SOURCE_NO_TAINT=PASS'
echo 'R04_NO_DURABLE_HOST_DEPLOYMENT=PASS'
