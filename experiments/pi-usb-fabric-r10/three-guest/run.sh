#!/bin/sh
# Three genuinely independent QEMU Linux kernel guests; no host device USB.
set -eu
p=/tmp/r10-provider.log
a=/tmp/r10-consumer-a.log
b=/tmp/r10-consumer-b.log
P=""; A=""; B=""
cleanup() {
 for pid in "$P" "$A" "$B"; do
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
 done
}
trap cleanup EXIT INT TERM
timeout 195s qemu-system-x86_64 -machine q35 -accel tcg -cpu qemu64 \
 -m 768 -smp 1 -kernel /guest/kernel -initrd /guest/provider.gz \
 -append 'console=ttyS0 rdinit=/init panic=1' \
 -nographic -monitor none -no-reboot \
 -netdev socket,id=n0,listen=127.0.0.1:22123 \
 -device e1000,netdev=n0,mac=52:54:00:00:10:01 \
 -netdev socket,id=n1,listen=127.0.0.1:22124 \
 -device e1000,netdev=n1,mac=52:54:00:00:10:02 >"$p" 2>&1 &
P=$!
timeout 195s qemu-system-x86_64 -machine q35 -accel tcg -cpu qemu64 \
 -m 768 -smp 1 -kernel /guest/kernel -initrd /guest/consumer-a.gz \
 -append 'console=ttyS0 rdinit=/init panic=1' \
 -nographic -monitor none -no-reboot \
 -netdev socket,id=n0,connect=127.0.0.1:22123 \
 -device e1000,netdev=n0,mac=52:54:00:00:10:03 >"$a" 2>&1 &
A=$!
timeout 195s qemu-system-x86_64 -machine q35 -accel tcg -cpu qemu64 \
 -m 768 -smp 1 -kernel /guest/kernel -initrd /guest/consumer-b.gz \
 -append 'console=ttyS0 rdinit=/init panic=1' \
 -nographic -monitor none -no-reboot \
 -netdev socket,id=n0,connect=127.0.0.1:22124 \
 -device e1000,netdev=n0,mac=52:54:00:00:10:04 >"$b" 2>&1 &
B=$!
set +e
wait "$A"; arc=$?
wait "$B"; brc=$?
wait "$P"; prc=$?
set -e
P=""; A=""; B=""
echo R10_PROVIDER_SERIAL_BEGIN
cat "$p"
echo R10_PROVIDER_SERIAL_END
echo R10_CONSUMER_A_SERIAL_BEGIN
cat "$a"
echo R10_CONSUMER_A_SERIAL_END
echo R10_CONSUMER_B_SERIAL_BEGIN
cat "$b"
echo R10_CONSUMER_B_SERIAL_END
echo "R10_VM_EXITS provider=$prc consumer_a=$arc consumer_b=$brc"
if [ "$prc" != 0 ] || [ "$arc" != 0 ] || [ "$brc" != 0 ]; then
 echo R10_THREE_GUEST_PROCESS_STATUS=RED
 exit 31
fi
for marker in R08_PROVIDER_DISTINCT_KERNEL_BOOT=PASS R08_PROVIDER_ETHERNET=PASS R10_PROVIDER_SECOND_CONSUMER_NETWORK=PASS \
 R08_PROVIDER_USBIPD_READY=PASS R08_PROVIDER_REMOTE_CONTROL_TRIGGER=PASS \
 R10_PROVIDER_A_HID_COMPLETE=PASS R10_PROVIDER_B_CHALLENGE_ISSUED=PASS \
 R10_PROVIDER_B_RESULT_RECEIVED=PASS R10_PROVIDER_A_RELEASE_SIGNAL=PASS R08_PROVIDER_FINISHED=YES; do
 grep -q "$marker" "$p" || { echo "R10_MISSING_PROVIDER=$marker"; exit 32; }
done
for marker in R08_CONSUMER_DISTINCT_KERNEL_BOOT=PASS R08_CONSUMER_ETHERNET=PASS \
 R08_CONSUMER_REAL_REMOTE_VHCI_ATTACH=PASS R08_CONSUMER_REAL_REMOTE_HID_DATA=PASS \
 USBFABRIC_R06_REAL_KEY_A_DOWN=PASS USBFABRIC_R06_REAL_KEY_A_UP=PASS \
 R10_CONSUMER_A_HELD_UNTIL_B_RESULT=PASS R08_CONSUMER_DETACH=PASS R08_CONSUMER_FINISHED=YES; do
 grep -q "$marker" "$a" || { echo "R10_MISSING_CONSUMER_A=$marker"; exit 33; }
done
for marker in R10_CONSUMER_B_DISTINCT_KERNEL_BOOT=PASS R10_CONSUMER_B_NETWORK=PASS \
 R10_CONSUMER_B_ETHERNET_REACHABILITY=PASS \
 R10_CONSUMER_B_PROVIDER_CONFIRMED_A_ATTACHED=PASS \
 R10_CONSUMER_B_CROSS_KERNEL_DUPLICATE_DENIED=PASS \
 R10_CONSUMER_B_NO_GHOST_VHCI=PASS R10_CONSUMER_B_RESULT_SENT=PASS \
 R10_CONSUMER_B_FINISHED=YES; do
 grep -q "$marker" "$b" || { echo "R10_MISSING_CONSUMER_B=$marker"; exit 34; }
done
grep -q '10.77.0.1:3240/usbip-vudc.0' "$a" || exit 35
echo R10_THREE_KERNELS_SINGLE_VUDC_CONTENTION=PASS
echo R10_GO_BROKER_LEASE_FENCING=NOT_TESTED
