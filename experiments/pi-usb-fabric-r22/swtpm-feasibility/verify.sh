#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R22_C_SOURCE_INPUT_DIRTY=RED; exit 10; }
image="public-r22c-swtpm-qmp-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r22-c-swtpm-qmp.log"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 11
echo "R22_C_DIGEST_PINNED_BASE=$base"
DOCKER_BUILDKIT=1 docker build --no-cache --pull --build-arg "BASE=$base" \
  -f experiments/pi-usb-fabric-r22/swtpm-feasibility/Dockerfile -t "$image" .
set +e
timeout 100s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 1536m --memory-swap 1536m --cpus 2 --pids-limit 72 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=64m,mode=1777 \
 "$image" >"$log" 2>&1
rc=$?
set -e
cat "$log"
if [[ "$rc" -ne 0 ]];then echo "R22_C_QEMU_SWTMP_GATE=RED rc=$rc";exit 21;fi
for marker in \
 R22_C_SOFTWARE_TPM2_CONTROL_SOCKET_READY=PASS \
 R22_C_REAL_QEMU_QMP_TPM2_EMULATOR_TIS_OBSERVED=PASS \
 R22_C_QMP_TPM_TYPES_AND_BACKEND_PRESENT=PASS \
 R22_C_MISSING_SWTMP_BACKEND_FAIL_CLOSED=PASS \
 R22_C_IN_GUEST_TPM_COMMANDS_AND_QUOTE=NOT_TESTED \
 R22_C_PROTECTED_HARDWARE_ROOT_GUEST_ATTESTATION=NOT_TESTED; do
 grep -q "$marker" "$log" || { echo "R22_C_MISSING_ORACLE=RED $marker";exit 22; }
done
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || exit 23
cleanup;trap - EXIT
echo R22_C_FREE_CLOUD_SWTMP_NO_HOST_DEVICE_CLEANUP=PASS
