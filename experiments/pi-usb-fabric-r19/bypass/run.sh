#!/bin/sh
# Three genuinely independent QEMU Linux kernel guests; no host device USB.
set -eu
p=/tmp/r19-red-provider.log
a=/tmp/r19-red-consumer-a.log
b=/tmp/r19-red-consumer-b.log
P=""; A=""; B=""; G=""
cleanup() {
 for pid in "$P" "$A" "$B" "$G"; do
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
 done
}
trap cleanup EXIT INT TERM
timeout 220s qemu-system-x86_64 -machine q35 -accel tcg -cpu qemu64 \
 -m 768 -smp 1 -kernel /guest/kernel -initrd /guest/provider.gz \
 -append 'console=ttyS0 rdinit=/init panic=1' \
 -nographic -monitor none -no-reboot -serial stdio \
 -netdev socket,id=n0,listen=127.0.0.1:22123 \
 -device e1000,netdev=n0,mac=52:54:00:00:10:01 \
 -netdev socket,id=n1,listen=127.0.0.1:22124 \
 -device e1000,netdev=n1,mac=52:54:00:00:10:02 \
 -chardev socket,id=r18hostserial,path=/tmp/r18-provider-gate.sock,server=on,wait=off \
 -device isa-serial,chardev=r18hostserial,index=1 >"$p" 2>&1 &
P=$!
# START sole test-only host Go broker after provider socket creation and before
# consumer starts. Host process controls the ONLY B handoff authorization wire.
timeout 190s /guest/r18-broker "$p" "$a" "$b" /tmp/r18-provider-gate.sock >/tmp/r18-broker.log 2>&1 &
G=$!
socket_ready=no
for tick in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
 if grep -qi ':566B ' /proc/net/tcp && grep -qi ':566C ' /proc/net/tcp && [ -S /tmp/r18-provider-gate.sock ]; then socket_ready=yes; break; fi
 sleep 1
done
if [ "$socket_ready" = yes ]; then echo R18_DUAL_QEMU_NETWORK_AND_HOST_CONTROL_SOCKETS=PASS; else echo R18_DUAL_QEMU_NETWORK_AND_HOST_CONTROL_SOCKETS=RED; fi
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
wait "$G"; grc=$?
set -e
P=""; A=""; B=""; G=""
echo R18_BROKER_SERIAL_BEGIN
cat /tmp/r18-broker.log
echo R18_BROKER_SERIAL_END
echo R10_PROVIDER_SERIAL_BEGIN
cat "$p"
echo R10_PROVIDER_SERIAL_END
echo R10_CONSUMER_A_SERIAL_BEGIN
cat "$a"
echo R10_CONSUMER_A_SERIAL_END
echo R10_CONSUMER_B_SERIAL_BEGIN
cat "$b"
echo R10_CONSUMER_B_SERIAL_END
echo "R10_VM_EXITS provider=$prc consumer_a=$arc consumer_b=$brc broker=$grc"
if [ "$prc" != 0 ] || [ "$arc" != 0 ] || [ "$brc" != 0 ] || [ "$grc" != 0 ]; then
 echo R10_THREE_GUEST_PROCESS_STATUS=RED
 exit 31
fi
for marker in R08_PROVIDER_DISTINCT_KERNEL_BOOT=PASS R08_PROVIDER_ETHERNET=PASS R10_PROVIDER_SECOND_CONSUMER_NETWORK=PASS \
 R08_PROVIDER_USBIPD_READY=PASS R08_PROVIDER_REMOTE_CONTROL_TRIGGER=PASS \
 R10_PROVIDER_A_HID_COMPLETE=PASS R10_PROVIDER_B_CHALLENGE_ISSUED=PASS \
 R10_PROVIDER_B_RESULT_RECEIVED=PASS R10_PROVIDER_A_RELEASE_SIGNAL=PASS \
 R11_PROVIDER_A_DETACH_CONFIRMED_BEFORE_B_RETRY=PASS \
 R19_PROVIDER_HOST_HELD_BYPASS_PREPARED=PASS R19_PROVIDER_NONCOOPERATIVE_B_IMPORT_ATTEMPT_SIGNAL=PASS \
 R19_PROVIDER_NATIVE_USBIP_BYPASS_PROBE_COMPLETE=PASS R18_PROVIDER_HOST_SERIAL_GATE_WAITING=PASS \
 R18_PROVIDER_B_RETRY_AFTER_HOST_GATE=PASS R11_PROVIDER_B_RETRY_AUTHORIZED=PASS \
 R11_PROVIDER_SECOND_CONSUMER_EVENT_TRIGGER=PASS R11_PROVIDER_SECOND_SYNTHETIC_HID_PAIR=PASS \
 R11_PROVIDER_B_DETACHED_CONFIRMED=PASS R08_PROVIDER_FINISHED=YES; do
 grep -q "$marker" "$p" || { echo "R10_MISSING_PROVIDER=$marker"; exit 32; }
done
for marker in R08_CONSUMER_DISTINCT_KERNEL_BOOT=PASS R08_CONSUMER_ETHERNET=PASS \
 R08_CONSUMER_REAL_REMOTE_VHCI_ATTACH=PASS R08_CONSUMER_REAL_REMOTE_HID_DATA=PASS \
 USBFABRIC_R06_REAL_KEY_A_DOWN=PASS USBFABRIC_R06_REAL_KEY_A_UP=PASS \
 R10_CONSUMER_A_HELD_UNTIL_B_RESULT=PASS R08_CONSUMER_DETACH=PASS \
 R11_CONSUMER_A_ACTUAL_VHCI_QUIESCENT=PASS R11_CONSUMER_A_RELEASE_RECEIPT_SENT=PASS R08_CONSUMER_FINISHED=YES; do
 grep -q "$marker" "$a" || { echo "R10_MISSING_CONSUMER_A=$marker"; exit 33; }
done
for marker in R10_CONSUMER_B_DISTINCT_KERNEL_BOOT=PASS R10_CONSUMER_B_NETWORK=PASS \
 R10_CONSUMER_B_ETHERNET_REACHABILITY=PASS \
 R10_CONSUMER_B_PROVIDER_CONFIRMED_A_ATTACHED=PASS \
 R10_CONSUMER_B_CROSS_KERNEL_DUPLICATE_DENIED=PASS \
 R10_CONSUMER_B_NO_GHOST_VHCI=PASS R10_CONSUMER_B_RESULT_SENT=PASS \
 R19_B_UNTRUSTED_DIRECT_IMPORT_CHALLENGE_RECEIVED=PASS \
 R19_B_REAL_PROVIDER_NETWORK_REACHABLE=PASS \
 R19_B_NATIVE_USBIP_LIST_RESPONDED=PASS \
 R19_RED_UNAUTHORIZED_REAL_USBIP_IMPORT=PASS R19_B_DIRECT_IMPORT_PROBE_RECEIPT_SENT=PASS \
 R11_CONSUMER_B_WAITED_FOR_A_RELEASE=PASS \
 R11_CONSUMER_B_REAL_USBIP_REASSIGNMENT=PASS R11_CONSUMER_B_SECOND_EVENT_REQUEST=PASS \
 R11_CONSUMER_B_INDEPENDENT_SECOND_HID_EVENTS=PASS R11_CONSUMER_B_FINAL_VHCI_QUIESCENT=PASS \
 R11_CONSUMER_B_RELEASE_RECEIPT_SENT=PASS R10_CONSUMER_B_FINISHED=YES; do
 grep -q "$marker" "$b" || { echo "R10_MISSING_CONSUMER_B=$marker"; exit 34; }
done
grep -q '10.77.0.1:3240/usbip-vudc.0' "$a" || exit 35
# Both clients must have separate observed kernel KEY_A events, not one echoed marker.
grep -q 'USBFABRIC_R06_REAL_KEY_A_DOWN=PASS' "$b" || exit 36
grep -q 'USBFABRIC_R06_REAL_KEY_A_UP=PASS' "$b" || exit 36
grep -q '10.78.0.1:3240/usbip-vudc.0' "$b" || exit 36
echo R10_THREE_KERNELS_SINGLE_VUDC_CONTENTION=PASS
echo R11_THREE_KERNELS_SEQUENTIAL_HID_HANDOFF=PASS
for marker in R18_HOST_ONLY_QEMU_ISA_SERIAL_CHANNEL=PASS \
 R18_TWO_INDEPENDENT_QEMU_KERNEL_EVDEV_AND_BUSY_OBSERVED=PASS \
 R18_TEST_ONLY_QMP_ACK_HELD_QUARANTINE=PASS \
 R18_GUEST_TRANSPORT_SIGNAL_NOT_AUTHORIZED_FOR_REASSIGNMENT=PASS \
 R18_EXISTING_GO_BROKER_GRANTED_HOST_SERIAL_B_AFTER_FSYNC=PASS \
 R18_B_ACTUAL_KERNEL_EVDEV_AFTER_GO_B_GATE=PASS \
 R18_STALE_A_PROOF_DENIED_AND_B_FRESH_RELEASE=PASS \
 R18_EXISTING_GO_MANAGER_CONTROLLED_REAL_USBIP_B_TRIGGER=PASS \
 R19_HOST_GO_LEDGER_HELD_BEFORE_UNTRUSTED_CLIENT_PROBE=PASS \
 R19_RED_BYPASS_PROVEN=PASS; do
 grep -q "$marker" /tmp/r18-broker.log || { echo "R18_MISSING_BROKER=$marker"; exit 43; }
done
echo R18_SAME_RUN_REAL_USBIP_EXISTING_GO_BROKER_TEST_ONLY_GATE=PASS
grep -q R19_RED_BYPASS_PORT_CLEANUP=PASS "$b" || exit 47
echo R19_RED_UNAUTHORIZED_BYPASS_REPRODUCED_SAFETY_FAILURE=PASS
echo R19_PRODUCTION_SECURE_ADMISSION=RED
echo R18_PRODUCTION_ATTESTATION_AND_ACTUAL_QMP=NOT_TESTED
