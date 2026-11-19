#!/usr/bin/env bash
# N1 G3: reuse exact existing R08 two-QEMU guest source, never replace with mock.
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
SRC=experiments/pi-usb-fabric-r08/two-guest
echo "N1_G3_SOURCE_SHA=$(git rev-parse HEAD)"
echo "N1_G3_REUSE=$SRC"
# Demand actual isolated two-kernel socket transport and explicit URB/evdev checks.
grep -Fq 'qemu-system-x86_64' "$SRC/run.sh"
test "$(grep -c 'qemu-system-x86_64' "$SRC/run.sh")" -eq 2
grep -Fq -- '-netdev socket' "$SRC/run.sh"
grep -Fq '10.77.0.1:3240/usbip-vudc.0' "$SRC/run.sh"
grep -Fq 'R08_CONSUMER_REAL_REMOTE_HID_DATA=PASS' "$SRC/run.sh"
grep -Fq 'R08_CONSUMER_DETACH=PASS' "$SRC/run.sh"
grep -Fq 'R08_TWO_SEPARATE_QEMU_KERNELS_REMOTE_USBIP_HID=PASS' "$SRC/run.sh"
grep -Fq -- '--network none' "$SRC/verify.sh"
grep -Fq -- '--cap-drop ALL' "$SRC/verify.sh"
# Reject accidental same-guest/localhost USBIP substitution in real-guest proof.
if grep -E 'usbip attach .*127\.0\.0\.1|usbip attach .*localhost' "$SRC/consumer.init";then
  echo N1_G3_LOOPBACK_USBIP_SUBSTITUTION=RED; exit 42
fi
echo N1_G3_PRECONDITION_SOURCE_ORACLE=PASS
bash "$SRC/verify.sh"
echo N1_G3_REUSED_TWO_GUEST_TRANSPORT=PASS
echo N1_G3_FIREWALL_AND_BROKER_INTEGRATION=NOT_TESTED
