#!/usr/bin/env bash
# Read-only generator qualification on disposable ARM64 GHA; no host module insertion.
set -Eeuo pipefail
mkdir -p evidence
uname -m | tee evidence/arch.txt
test "$(uname -m)" = aarch64
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends podman uidmap linux-tools-common linux-tools-generic
dpkg-query -W podman linux-tools-common linux-tools-generic >evidence/packages.txt
podman --version | tee evidence/podman.txt
(find /usr/lib /usr/libexec -name podman-system-generator -print 2>/dev/null || true; dpkg -L podman | grep -E '/(quadlet|podman-system-generator)
if ! test -s evidence/generator-paths.txt; then
  echo "QUADLET_GENERATOR_MISSING=RED" | tee evidence/result.txt
  exit 32
fi
generator="$(grep -m1 -E "^/" evidence/generator-paths.txt || true)"
if ! test -x "$generator"; then echo "QUADLET_GENERATOR_NOT_EXECUTABLE=RED" | tee evidence/result.txt; exit 35; fi
mkdir -p "$RUNNER_TEMP/quadlet-synthetic"
cat > "$RUNNER_TEMP/quadlet-synthetic/usb-fabric-synthetic.container" <<'EOF'
[Unit]
Description=USB Fabric synthetic standalone no-network canary
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
if ! grep -q 'usb-fabric-synthetic.service' evidence/generated.txt; then
  echo "QUADLET_DRYRUN_EXPECTED_UNIT_ABSENT=RED" | tee evidence/result.txt
  exit 33
fi
# Verify an intentionally invalid parser input does not produce a runnable unit.
cat > "$RUNNER_TEMP/quadlet-synthetic/invalid.container" <<'EOF'
[Container]
ThisIsNotAQuadletDirective=true
EOF
QUADLET_UNIT_DIRS="$RUNNER_TEMP/quadlet-synthetic" "$generator" --dryrun >evidence/negative.txt 2>&1 || true
if grep -q '^---invalid.service---' evidence/negative.txt; then
 echo "QUADLET_MALFORMED_UNIT_ACCEPTED=RED" | tee evidence/result.txt
 exit 34
fi
for module in usbip_core usbip_host vhci_hcd usbip_vudc libcomposite dummy_hcd; do
  if modinfo "$module" >/dev/null 2>&1; then echo "$module=AVAILABLE_ON_RUNNER_KERNEL"; else echo "$module=UNAVAILABLE_OR_BUILTIN_OR_UNKNOWN"; fi
done >evidence/runner-modules.txt
find /usr/lib/linux-tools -type f \( -name usbip -o -name usbipd \) -print 2>/dev/null >evidence/usbip-tool-paths.txt || true
echo "ARM64_QUADLET_GENERATOR_DRYRUN=PASS" | tee evidence/result.txt
echo "USBIP_VUDC_VHCI_REAL_ATTACH=NOT_TESTED" | tee -a evidence/result.txt
echo "PI_PHYSICAL_GADGET_OTG=NOT_TESTED" | tee -a evidence/result.txt
 || true) | sort -u >evidence/generator-paths.txt
(dpkg -L podman | grep -Ei 'quadlet|generator' || true) >evidence/podman-generator-manifest.txt
if ! test -s evidence/generator-paths.txt; then
  echo "QUADLET_GENERATOR_MISSING=RED" | tee evidence/result.txt
  exit 32
fi
generator="$(head -n1 evidence/generator-paths.txt)"
test -x "$generator"
mkdir -p "$RUNNER_TEMP/quadlet-synthetic"
cat > "$RUNNER_TEMP/quadlet-synthetic/usb-fabric-synthetic.container" <<'EOF'
[Unit]
Description=USB Fabric synthetic standalone no-network canary
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
if ! grep -q 'usb-fabric-synthetic.service' evidence/generated.txt; then
  echo "QUADLET_DRYRUN_EXPECTED_UNIT_ABSENT=RED" | tee evidence/result.txt
  exit 33
fi
# Verify an intentionally invalid parser input does not produce a runnable unit.
cat > "$RUNNER_TEMP/quadlet-synthetic/invalid.container" <<'EOF'
[Container]
ThisIsNotAQuadletDirective=true
EOF
QUADLET_UNIT_DIRS="$RUNNER_TEMP/quadlet-synthetic" "$generator" --dryrun >evidence/negative.txt 2>&1 || true
if grep -q '^---invalid.service---' evidence/negative.txt; then
 echo "QUADLET_MALFORMED_UNIT_ACCEPTED=RED" | tee evidence/result.txt
 exit 34
fi
for module in usbip_core usbip_host vhci_hcd usbip_vudc libcomposite dummy_hcd; do
  if modinfo "$module" >/dev/null 2>&1; then echo "$module=AVAILABLE_ON_RUNNER_KERNEL"; else echo "$module=UNAVAILABLE_OR_BUILTIN_OR_UNKNOWN"; fi
done >evidence/runner-modules.txt
find /usr/lib/linux-tools -type f \( -name usbip -o -name usbipd \) -print 2>/dev/null >evidence/usbip-tool-paths.txt || true
echo "ARM64_QUADLET_GENERATOR_DRYRUN=PASS" | tee evidence/result.txt
echo "USBIP_VUDC_VHCI_REAL_ATTACH=NOT_TESTED" | tee -a evidence/result.txt
echo "PI_PHYSICAL_GADGET_OTG=NOT_TESTED" | tee -a evidence/result.txt
