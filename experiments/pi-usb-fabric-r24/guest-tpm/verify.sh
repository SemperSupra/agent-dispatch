#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R24_C_DIRTY_SOURCE=RED; exit 10; }
image="r24c-qemu-linux-guest-tpm-${GITHUB_SHA:0:12}"
log="$RUNNER_TEMP/r24-c-real-guest-tpm.log"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull debian:trixie-slim >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' debian:trixie-slim)"
[[ "$base" == *@sha256:* ]] || exit 11
echo "R24_C_BASE_IMAGE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --no-cache \
 --build-arg "BASE=$base" \
 -f experiments/pi-usb-fabric-r24/guest-tpm/Dockerfile -t "$image" .
set +e
timeout 230s docker run --rm --network none --read-only --user 65532:65532 \
 --cap-drop ALL --security-opt no-new-privileges \
 --memory 2304m --memory-swap 2304m --cpus 2 --pids-limit 128 \
 --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m,mode=1777 \
 "$image" >"$log" 2>&1
rc=$?
set -e
cat "$log"
if [[ "$rc" -ne 0 ]];then echo "R24_C_LINUX_GUEST_TPM=RED rc=$rc"; exit 22; fi
for marker in \
 R24_C_UPSTREAM_SOFTWARE_TPM2_DUAL_SOCKETS=PASS \
 R24_C_SAME_QEMU_TPM_TIS_QMP_OBSERVED=PASS \
 R24_C_GUEST_TPM_TIS_CHARACTER_DEVICE=PASS \
 R24_C_REAL_GUEST_TPM_GETRANDOM=PASS \
 R24_C_REAL_GUEST_TPM_PCR_READ=PASS \
 R24_C_REAL_GUEST_TPM_NONCE_QUOTE_VERIFIED=PASS \
 R24_C_GUEST_TPM_WRONG_NONCE_DENIED=PASS \
 R24_C_REAL_GUEST_CHANGED_PCR_QUOTE_DENIED=PASS \
 R24_C_REAL_IN_GUEST_TPM2_PCR_QUOTE_TEST_ONLY=PASS \
 R24_C_TRUSTED_HARDWARE_EK_ATTESTATION=NOT_TESTED; do
 grep -Fq "$marker" "$log" || { echo "R24_C_PROOF_MARKER_MISSING=$marker"; exit 23; }
done
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || exit 24
cleanup;trap - EXIT
echo R24_C_QEMU_GUEST_TPM_CLEANUP=PASS
