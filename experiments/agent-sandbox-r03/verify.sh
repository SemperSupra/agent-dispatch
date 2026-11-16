#!/usr/bin/env bash
# All compilers, qemu-user and development dependencies live in ephemeral OCI
# build stages. All application execution occurs in short-lived scratch OCI.
set -Eeuo pipefail
cd "$(dirname "$0")"
case "${TARGET_ARCH:-}" in
  aarch64|riscv64) ;;
  *) echo 'R03_INVALID_TARGET=RED'; exit 10 ;;
esac
image="public-sandbox-r03-${TARGET_ARCH}:${GITHUB_SHA:0:12}"
status_before="$(git -C ../.. status --porcelain --untracked-files=all)"
[[ -z "$status_before" ]] || { echo 'R03_DIRTY_SOURCE=RED'; exit 11; }
snapshot_local() {
  local p
  for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
    if [[ -d "$p" ]]; then
      find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum
    else
      echo 'ABSENT'
    fi
  done
}
local_before="$(snapshot_local)"
vol_before="$(docker volume ls -q | LC_ALL=C sort)"
cleanup() {
  docker image rm -f "$image" >/dev/null 2>&1 || true
  docker image rm ubuntu:24.04 >/dev/null 2>&1 || true
  docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull ubuntu:24.04 >/dev/null
base_image="$(docker image inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04)"
[[ "$base_image" == *@sha256:* ]] || { echo 'R03_BUILDER_BASE_NOT_DIGEST=RED'; exit 12; }
echo "R03_BASE_IMMUTABLE_REFERENCE=$base_image"
DOCKER_BUILDKIT=1 docker build --no-cache --pull -f Dockerfile \
  --build-arg "BASE_IMAGE=$base_image" \
  --build-arg "TARGET_TRIPLE=$TARGET_ARCH" \
  --build-arg "TARGET_NAME=$TARGET_ARCH" \
  --tag "$image" .
echo 'R03_DISPOSABLE_CROSS_COMPILER_STAGE=PASS'

python3 - "$image" "$TARGET_ARCH" <<'PY'
import json, subprocess, sys, time
image, arch = sys.argv[1:3]
inspect = json.loads(subprocess.check_output(["docker", "image", "inspect", image]))[0]
assert inspect["Config"]["User"] == "65532:65532"
assert inspect["Config"]["Entrypoint"] == ["/qemu", "/app"]
cmd = [
    "docker", "run", "--rm", "--network", "none", "--read-only",
    "--user", "65532:65532", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--pids-limit", "64",
    "--memory", "192m", "--memory-swap", "192m", "--cpus", "1",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m", image
]
begin = time.monotonic()
out = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
elapsed = time.monotonic() - begin
expected = "R03_FOREIGN_ELF_FUNCTIONAL_ORACLE=PASS ARCH=" + arch + " SUM=5000050000"
if out.returncode != 0 or expected not in out.stdout:
    print("R03_FOREIGN_ISA_EXECUTION=RED")
    print("exit=", out.returncode, "stdout=", out.stdout[-600:], "stderr=", out.stderr[-600:])
    sys.exit(13)
print(expected)
print("R03_SINGLE_EXECUTION_WALL_SECONDS=%.4f" % elapsed)
print("R03_CROSS_HOST_PERFORMANCE_ENVELOPE=NOT_TESTED")
print("R03_REAL_GUEST_KERNEL_OS_BOOT=NOT_TESTED")
print("R03_RUNTIME_NETWORK_MODE=NONE_DECLARED")
PY

[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$vol_before" ]] || { echo 'R03_VOLUMES_TAINT=RED'; exit 14; }
[[ "$(snapshot_local)" == "$local_before" ]] || { echo 'R03_HOME_PROJECT_LOCAL_TAINT=RED'; exit 15; }
[[ "$(git -C ../.. status --porcelain --untracked-files=all)" == "$status_before" ]] || { echo 'R03_CHECKOUT_TAINT=RED'; exit 16; }
cleanup
trap - EXIT
if docker image inspect "$image" >/dev/null 2>&1; then echo 'R03_BUILDER_RUNTIME_CACHE_CLEANUP=RED'; exit 17; fi
echo 'R03_RUNTIME_IMAGE_REMOVED=PASS'
echo 'R03_HOME_PROJECT_LOCAL_AND_SOURCE_NO_TAINT=PASS'
echo 'R03_NO_PERSISTENT_APPLICATION_INSTALL=PASS'
echo 'R03_HOST_SECURITY_AND_AGENT_INTERVIEW=NOT_TESTED'
