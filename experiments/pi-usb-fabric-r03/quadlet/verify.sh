#!/usr/bin/env bash
# Disposably qualify installed generator on ARM64 GHA; no host kernel module changes.
set -Eeuo pipefail
mkdir -p evidence
test "$(uname -m)" = aarch64
uname -a > evidence/uname.txt
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends podman uidmap linux-tools-common linux-tools-generic
dpkg-query -W podman linux-tools-common linux-tools-generic > evidence/packages.txt
podman --version | tee evidence/podman.txt
(dpkg -L podman | grep -Ei 'quadlet|generator' || true) > evidence/podman-generator-manifest.txt
(find /usr/lib /usr/libexec -name podman-system-generator -print 2>/dev/null || true) > evidence/generator-paths.txt
generator="$(head -n1 evidence/generator-paths.txt)"
if [[ -z "$generator" || ! -x "$generator" ]]; then
  echo QUADLET_GENERATOR_MISSING=RED | tee evidence/result.txt
  exit 32
fi
mkdir -p "$RUNNER_TEMP/quadlet-synthetic"
cat > "$RUNNER_TEMP/quadlet-synthetic/synthetic.container" <<'EOF'
[Unit]
Description=Pi USB Fabric synthetic canary
[Container]
Image=docker.io/library/alpine:3.20
Network=none
ReadOnly=true
NoNewPrivileges=true
[Service]
Restart=no
MemoryMax=64M
[Install]
WantedBy=multi-user.target
EOF
QUADLET_UNIT_DIRS="$RUNNER_TEMP/quadlet-synthetic" "$generator" --dryrun >evidence/generated.txt 2>&1
if ! grep -q 'synthetic.service' evidence/generated.txt; then
  echo QUADLET_DRYRUN_EXPECTED_UNIT_MISSING=RED | tee evidence/result.txt
  exit 33
fi
cat > "$RUNNER_TEMP/quadlet-synthetic/invalid.container" <<'EOF'
[Container]
ThisIsNotAQuadletDirective=true
EOF
QUADLET_UNIT_DIRS="$RUNNER_TEMP/quadlet-synthetic" "$generator" --dryrun >evidence/negative.txt 2>&1 || true
if grep -q 'ExecStart=.*invalid' evidence/negative.txt; then
  echo QUADLET_MALFORMED_UNIT_ACCEPTED=RED | tee evidence/result.txt
  exit 34
fi
for module in usbip_core usbip_host vhci_hcd usbip_vudc libcomposite dummy_hcd; do
  if modinfo "$module" >/dev/null 2>&1; then
    echo "$module=MODULE_AVAILABLE_ON_UBUNTU_RUNNER"
  else
    echo "$module=UNAVAILABLE_OR_BUILTIN_OR_UNKNOWN"
  fi
done > evidence/runner-modules.txt
(find /usr/lib/linux-tools -type f \( -name usbip -o -name usbipd \) -print 2>/dev/null || true) > evidence/usbip-tool-paths.txt
echo ARM64_QUADLET_GENERATOR_DRYRUN=PASS | tee evidence/result.txt
echo USBIP_VUDC_VHCI_REAL_ATTACH=NOT_TESTED | tee -a evidence/result.txt
echo PHYSICAL_PI_OTG=NOT_TESTED | tee -a evidence/result.txt
