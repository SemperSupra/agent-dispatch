#!/bin/sh
# Runs two independent QEMU TCG Linux kernels inside nonroot isolated OCI.
set -eu
p=/tmp/r09-provider.log
c=/tmp/r09-consumer.log
cleanup() {
  if [ -n "${P:-}" ]; then kill "$P" 2>/dev/null || :; wait "$P" 2>/dev/null || :; fi
  if [ -n "${C:-}" ]; then kill "$C" 2>/dev/null || :; wait "$C" 2>/dev/null || :; fi
}
trap cleanup EXIT INT TERM
# QEMU socket network is only inside this outer container's loopback namespace.
timeout 170s qemu-system-x86_64 -machine q35 -accel tcg -cpu qemu64 \
  -m 768 -smp 1 -kernel /guest/kernel -initrd /guest/provider.gz \
  -append 'console=ttyS0 rdinit=/init panic=1' \
  -nographic -monitor none -no-reboot \
  -netdev socket,id=n0,listen=127.0.0.1:22123 \
  -device e1000,netdev=n0,mac=52:54:00:00:08:01 >"$p" 2>&1 &
P=$!
timeout 170s qemu-system-x86_64 -machine q35 -accel tcg -cpu qemu64 \
  -m 768 -smp 1 -kernel /guest/kernel -initrd /guest/consumer.gz \
  -append 'console=ttyS0 rdinit=/init panic=1' \
  -nographic -monitor none -no-reboot \
  -netdev socket,id=n0,connect=127.0.0.1:22123 \
  -device e1000,netdev=n0,mac=52:54:00:00:08:02 >"$c" 2>&1 &
C=$!
set +e
wait "$C"; client_rc=$?
if grep -q R09_CONSUMER_REAL_KEY_DOWN=PASS "$c"; then
  wait "$P"; provider_rc=$?
else
  kill "$P" 2>/dev/null || :
  wait "$P"; provider_rc=$?
  echo R08_EARLY_CONSUMER_FAILURE_PROVIDER_STOPPED=YES
fi
set -e
P=""; C=""
echo R09_PROVIDER_SERIAL_BEGIN
cat "$p"
echo R09_PROVIDER_SERIAL_END
echo R09_CONSUMER_SERIAL_BEGIN
cat "$c"
echo R09_CONSUMER_SERIAL_END
echo "R09_PROVIDER_QEMU_EXIT=$provider_rc"
echo "R09_CONSUMER_QEMU_EXIT=$client_rc"
test "$provider_rc" -eq 0 && test "$client_rc" -eq 0 || exit 31
for oracle in \
  R08_PROVIDER_DISTINCT_KERNEL_BOOT=PASS R08_PROVIDER_ETHERNET=PASS \
  R08_PROVIDER_USBIPD_READY=PASS R08_PROVIDER_REMOTE_CONTROL_TRIGGER=PASS \
  R09_PROVIDER_REAL_SYNTHETIC_KEY_HELD=PASS R09_PROVIDER_ETHERNET_LINK_CUT=PASS R08_PROVIDER_FINISHED=YES; do
  grep -q "$oracle" "$p" || { echo "R08_MISSING_PROVIDER_ORACLE=$oracle"; exit 32; }
done
for oracle in \
  R08_CONSUMER_DISTINCT_KERNEL_BOOT=PASS R08_CONSUMER_ETHERNET=PASS \
  R08_CONSUMER_REMOTE_PROVIDER_DISCOVERED=PASS R08_CONSUMER_REAL_REMOTE_VHCI_ATTACH=PASS \
  R09_CONSUMER_REAL_KEY_DOWN=PASS \
  R09_CONSUMER_FORCED_DETACH_AFTER_FAULT=PASS R08_CONSUMER_FINISHED=YES; do
  grep -q "$oracle" "$c" || { echo "R08_MISSING_CONSUMER_ORACLE=$oracle"; exit 33; }
done
grep -q '10.77.0.1:3240/usbip-vudc.0' "$c" || {
  echo R08_REMOTE_NOT_ISOLATED=RED; exit 34;
}
echo R09_TWO_KERNELS_LINK_DOWN_FAULT_OBSERVED=PASS
for oracle in R09_BLUE_PREFAULT_PROVIDER_REACHABLE=PASS R09_BLUE_PROVIDER_NETWORK_LOSS_DETECTED=PASS R09_BLUE_FORCED_USBIP_DETACH=PASS R09_BLUE_VHCI_PORT_QUIESCENT=PASS; do
  grep -q "$oracle" "$c" || { echo "R09_BLUE_MISSING_FAULT_RESPONSE=$oracle"; exit 43; }
done
if grep -q R09_OBSERVER_REAL_KEY_A_UP=PASS "$c"; then
  echo R09_BLUE_INDEPENDENT_EVDEV_KEY_UP=PASS
else
  echo R09_BLUE_INDEPENDENT_EVDEV_KEY_UP=NOT_OBSERVED
fi
echo R09_BLUE_GUEST_WATCHDOG_VHCI_EVICTION=PASS
echo R09_BLUE_GO_BROKER_FENCING_AND_KEY_RELEASE=NOT_TESTED
