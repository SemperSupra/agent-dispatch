#!/bin/sh
# Runs two independent QEMU TCG Linux kernels inside nonroot isolated OCI.
set -eu
p=/tmp/r08-provider.log
c=/tmp/r08-consumer.log
cleanup() {
  if [ -n "\${P:-}" ]; then kill "$P" 2>/dev/null || :; wait "$P" 2>/dev/null || :; fi
  if [ -n "\${C:-}" ]; then kill "$C" 2>/dev/null || :; wait "$C" 2>/dev/null || :; fi
}
trap cleanup EXIT INT TERM
# QEMU socket network is only inside this outer container's loopback namespace.
timeout 170s qemu-system-x86_64 -machine q35 -accel tcg -cpu qemu64 \
  -m 448 -smp 1 -kernel /guest/kernel -initrd /guest/provider.gz \
  -append 'console=ttyS0 rdinit=/init panic=1' \
  -nographic -monitor none -no-reboot \
  -netdev socket,id=n0,listen=127.0.0.1:22123 \
  -device e1000,netdev=n0,mac=52:54:00:00:08:01 >"$p" 2>&1 &
P=$!
timeout 170s qemu-system-x86_64 -machine q35 -accel tcg -cpu qemu64 \
  -m 448 -smp 1 -kernel /guest/kernel -initrd /guest/consumer.gz \
  -append 'console=ttyS0 rdinit=/init panic=1' \
  -nographic -monitor none -no-reboot \
  -netdev socket,id=n0,connect=127.0.0.1:22123 \
  -device e1000,netdev=n0,mac=52:54:00:00:08:02 >"$c" 2>&1 &
C=$!
set +e
wait "$C"; client_rc=$?
wait "$P"; provider_rc=$?
set -e
P=""; C=""
echo R08_PROVIDER_SERIAL_BEGIN
cat "$p"
echo R08_PROVIDER_SERIAL_END
echo R08_CONSUMER_SERIAL_BEGIN
cat "$c"
echo R08_CONSUMER_SERIAL_END
echo "R08_PROVIDER_QEMU_EXIT=$provider_rc"
echo "R08_CONSUMER_QEMU_EXIT=$client_rc"
test "$provider_rc" -eq 0 && test "$client_rc" -eq 0 || exit 31
for oracle in \
  R08_PROVIDER_DISTINCT_KERNEL_BOOT=PASS R08_PROVIDER_ETHERNET=PASS \
  R08_PROVIDER_USBIPD_READY=PASS R08_PROVIDER_REMOTE_CONTROL_TRIGGER=PASS \
  R08_PROVIDER_SYNTHETIC_HID_REPORTS=PASS R08_PROVIDER_FINISHED=YES; do
  grep -q "$oracle" "$p" || { echo "R08_MISSING_PROVIDER_ORACLE=$oracle"; exit 32; }
done
for oracle in \
  R08_CONSUMER_DISTINCT_KERNEL_BOOT=PASS R08_CONSUMER_ETHERNET=PASS \
  R08_CONSUMER_REMOTE_PROVIDER_DISCOVERED=PASS R08_CONSUMER_REAL_REMOTE_VHCI_ATTACH=PASS \
  R08_CONSUMER_REAL_REMOTE_HID_DATA=PASS USBFABRIC_R06_REAL_KEY_A_DOWN=PASS \
  USBFABRIC_R06_REAL_KEY_A_UP=PASS R08_CONSUMER_DETACH=PASS R08_CONSUMER_FINISHED=YES; do
  grep -q "$oracle" "$c" || { echo "R08_MISSING_CONSUMER_ORACLE=$oracle"; exit 33; }
done
grep -q '10.77.0.1:3240/usbip-vudc.0' "$c" || {
  echo R08_REMOTE_NOT_ISOLATED=RED; exit 34;
}
echo R08_TWO_SEPARATE_QEMU_KERNELS_REMOTE_USBIP_HID=PASS
echo R08_BROKER_LEASE_AND_PHYSICAL_PI=NOT_TESTED
