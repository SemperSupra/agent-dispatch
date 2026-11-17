#!/usr/bin/env bash
# Non-mutating public free-tier Android emulator capability census.
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
before="$(git status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || exit 11
echo PASSKEY_R0_ANDROID_CENSUS_BEGIN
uname -sm
echo "PASSKEY_R0_RUNNER_CPU=$(nproc)"
echo "PASSKEY_R0_RUNNER_MEM_KIB=$(awk '/MemTotal/{print $2}' /proc/meminfo)"
if [[ -e /dev/kvm ]];then
  stat -c 'PASSKEY_R0_KVM_PATH_PERMS=%a:%U:%G' /dev/kvm
  if [[ -r /dev/kvm && -w /dev/kvm ]];then echo PASSKEY_R0_KVM_USER_ACCESS=PASS
  else echo PASSKEY_R0_KVM_USER_ACCESS=DENIED;fi
else
  echo PASSKEY_R0_KVM_DEVICE=ABSENT
fi
echo "PASSKEY_R0_ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT:-unset}"
for binary in adb emulator sdkmanager avdmanager;do
  resolved="$(command -v "$binary" || true)"
  if [[ -z "$resolved" && -n "${ANDROID_SDK_ROOT:-}" ]];then
    for p in "$ANDROID_SDK_ROOT/emulator/$binary" "$ANDROID_SDK_ROOT/platform-tools/$binary" "$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/$binary";do
      if [[ -x "$p" ]];then resolved="$p";break;fi
    done
  fi
  if [[ -z "$resolved" ]];then
    echo "PASSKEY_R0_ANDROID_TOOL_${binary^^}=ABSENT"
  else
    echo "PASSKEY_R0_ANDROID_TOOL_${binary^^}=PRESENT"
    case "$binary" in
      emulator) timeout 15s "$resolved" -version 2>&1 | head -n 4 || true ;;
      adb) timeout 10s "$resolved" version 2>&1 | head -n 4 || true ;;
    esac
  fi
done
if [[ -n "${ANDROID_SDK_ROOT:-}" && -d "$ANDROID_SDK_ROOT/system-images" ]];then
  find "$ANDROID_SDK_ROOT/system-images" -maxdepth 4 -name source.properties -type f -print |
  while IFS= read -r prop;do
    rev="$(sed -n 's/^Pkg.Revision=//p' "$prop" | head -n 1)"
    rel="${prop#"$ANDROID_SDK_ROOT/system-images/"}"
    echo "PASSKEY_R0_INSTALLED_IMAGE=${rel%/source.properties} revision=$rev"
  done
else
  echo PASSKEY_R0_SYSTEM_IMAGES=NONE_PREINSTALLED
fi
# Data only; do NOT attempt sudo chmod /dev/kvm or install packages.
echo PASSKEY_R0_EMULATOR_BIOMETRIC_ATTEMPT=NOT_TESTED
echo PASSKEY_R0_CREDENTIAL_PROVIDER_APK=NOT_TESTED
[[ "$(git status --porcelain --untracked-files=all)" == "$before" ]] || exit 12
echo PASSKEY_R0_NON_MUTATING_ANDROID_CENSUS=PASS
