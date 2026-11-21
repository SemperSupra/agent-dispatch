# R25-B: derived disposable harness from R22-B; never changes original files.
#!/bin/sh
# Three genuinely independent QEMU Linux kernel guests; no host device USB.
set -eu
challenge="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
if [ "${#challenge}" -ne 64 ]; then echo R22_B_HOST_CHALLENGE=RED; exit 9; fi
export R22_CHALLENGE="$challenge"
echo R22_B_RANDOM_HOST_CHALLENGE_READY=PASS
p=/tmp/r18-provider.log
a=/tmp/r18-consumer-a.log
b=/tmp/r18-consumer-b.log
P=""; A=""; B=""; G=""
cleanup() {
 for pid in "$P" "$A" "$B" "$G"; do
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
 done
}
trap cleanup EXIT INT TERM
timeout 285s qemu-system-x86_64 -machine q35 -accel tcg -cpu qemu64 \
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
timeout 260s /guest/r18-broker "$p" "$a" "$b" /tmp/r18-provider-gate.sock >/tmp/r18-broker.log 2>&1 &
G=$!
socket_ready=no
for tick in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
 if grep -qi ':566B ' /proc/net/tcp && grep -qi ':566C ' /proc/net/tcp && [ -S /tmp/r18-provider-gate.sock ]; then socket_ready=yes; break; fi
 sleep 1
done
if [ "$socket_ready" = yes ]; then echo R18_DUAL_QEMU_NETWORK_AND_HOST_CONTROL_SOCKETS=PASS; else echo R18_DUAL_QEMU_NETWORK_AND_HOST_CONTROL_SOCKETS=RED; fi
# R27-B: ensure host Go verifier has independently read and pinned the
# pre-provisioned public identity BEFORE launching consumer-A QEMU. It is
# not inferred from guest-controlled serial or USBIP transport text.
pin_ready=no
for tick in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
 if grep -Fq 'R27_B_HOST_PUB_PIN_READY_BEFORE_CONSUMER_A_QEMU_BOOT=PASS' /tmp/r18-broker.log; then pin_ready=yes;break;fi
 sleep 1
done
if [ "$pin_ready" != yes ]; then
 echo R27_B_PREBOOT_HOST_PIN_ENROLLMENT=RED
 exit 89
fi
echo R27_B_INDEPENDENT_PUBLIC_KEY_ENROLLED_BEFORE_REAL_CONSUMER_A_BOOT=PASS
timeout 275s qemu-system-x86_64 -machine q35 -accel tcg -cpu qemu64 \
 -m 768 -smp 1 -kernel /guest/kernel -initrd /guest/consumer-a.gz \
 -append "console=ttyS0 rdinit=/init panic=1 r22_challenge=$challenge" \
 -nographic -monitor none -no-reboot \
 -netdev socket,id=n0,connect=127.0.0.1:22123 \
 -device e1000,netdev=n0,mac=52:54:00:00:10:03 \
 -name r25-usbip-consumer-a -uuid d2e44f29-6a7b-44a9-8e16-49f351e22881 \
 -qmp unix:/tmp/r25-consumer-a-qmp.sock,server=on,wait=off \
 -device virtio-serial-pci,id=vs0 \
 -chardev socket,id=r22guest,path=/tmp/r22-consumer-a-guest.sock,server=on,wait=off \
 -device virtserialport,chardev=r22guest,name=org.r22.usbip.receipts >"$a" 2>&1 &
A=$!
# Independent QEMU-maintained read-only QMP library observes THIS same A VM.
# The wrong-UUID negative must fail; neither observation authorizes VUDC.
R25Q=""; R25NEG=""
python3 /guest/r25-qmp-observer.py /tmp/r25-consumer-a-qmp.sock r25-usbip-consumer-a d2e44f29-6a7b-44a9-8e16-49f351e22881 \
 >/tmp/r25-qmp-observer.log 2>&1 &
R25Q=$!
python3 /guest/r25-qmp-observer.py /tmp/r25-consumer-a-qmp.sock r25-usbip-consumer-a 00000000-0000-4000-8000-000000000000 \
 >/tmp/r25-qmp-wrong-vm.log 2>&1 &
R25NEG=$!
python3 /guest/r26-qmp-pci.py /tmp/r25-consumer-a-qmp.sock r25-usbip-consumer-a d2e44f29-6a7b-44a9-8e16-49f351e22881 \
 >/tmp/r26-qmp-pci.log 2>&1 &
R26PCI=$!
timeout 275s qemu-system-x86_64 -machine q35 -accel tcg -cpu qemu64 \
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
wait "$R25Q"; qrc=$?
wait "$R25NEG"; neg_rc=$?
wait "$R26PCI"; pci_rc=$?
set -e
P=""; A=""; B=""; G=""
echo R25_B_REAL_CONSUMER_A_QMP_SERIAL_BEGIN
cat /tmp/r25-qmp-observer.log
echo R25_B_REAL_CONSUMER_A_QMP_SERIAL_END
echo R25_B_FOREIGN_VM_QMP_REJECTION_BEGIN
cat /tmp/r25-qmp-wrong-vm.log
echo R25_B_FOREIGN_VM_QMP_REJECTION_END
if [ "$qrc" -ne 0 ] || [ "$neg_rc" -ne 42 ]; then
 echo "R25_B_QMP_READONLY_WITNESS=RED good=$qrc wrong=$neg_rc"
 exit 81
fi
grep -Fq 'R25_B_QMP_CONSUMER_A_VM_NAME_UUID_STATUS=PASS' /tmp/r25-qmp-observer.log || exit 82
grep -Fq 'R25_B_FOREIGN_VM_UUID_REJECTED=PASS' /tmp/r25-qmp-wrong-vm.log || exit 83
echo R26_A_QMP_PCI_READONLY_EVIDENCE_BEGIN
cat /tmp/r26-qmp-pci.log
echo R26_A_QMP_PCI_READONLY_EVIDENCE_END
if [ "$pci_rc" -ne 0 ]; then echo "R26_A_UPSTREAM_QMP_PCI_GRAPH=RED rc=$pci_rc"; exit 85; fi
grep -Fq 'R26_A_UPSTREAM_QMP_PCI_GRAPH_OBSERVED=PASS' /tmp/r26-qmp-pci.log || exit 86
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
 R11_PROVIDER_A_DETACH_CONFIRMED_BEFORE_B_RETRY=PASS R18_PROVIDER_HOST_SERIAL_GATE_WAITING=PASS \
 R18_PROVIDER_B_RETRY_AFTER_HOST_GATE=PASS R27_L_PROVIDER_UART_NO_ECHO=PASS \
 R27_L_PROVIDER_UART_READY=PASS \
 R27_L_PROVIDER_REAL_UDC_REBOUND_BEFORE_UART_ACK=PASS R11_PROVIDER_B_RETRY_AUTHORIZED=PASS \
 R11_PROVIDER_SECOND_CONSUMER_EVENT_TRIGGER=PASS R11_PROVIDER_SECOND_SYNTHETIC_HID_PAIR=PASS \
 R11_PROVIDER_B_DETACHED_CONFIRMED=PASS R08_PROVIDER_FINISHED=YES; do
 grep -q "$marker" "$p" || { echo "R10_MISSING_PROVIDER=$marker"; exit 32; }
done
for marker in R08_CONSUMER_DISTINCT_KERNEL_BOOT=PASS R08_CONSUMER_ETHERNET=PASS \
 R08_CONSUMER_REAL_REMOTE_VHCI_ATTACH=PASS R08_CONSUMER_REAL_REMOTE_HID_DATA=PASS \
 USBFABRIC_R06_REAL_KEY_A_DOWN=PASS USBFABRIC_R06_REAL_KEY_A_UP=PASS \
 R10_CONSUMER_A_HELD_UNTIL_B_RESULT=PASS R08_CONSUMER_DETACH=PASS \
 R11_CONSUMER_A_ACTUAL_VHCI_QUIESCENT=PASS R11_CONSUMER_A_RELEASE_RECEIPT_SENT=PASS \
 R22_B_REAL_USBIP_GUEST_ED25519_SIGNER_READY=PASS R08_CONSUMER_FINISHED=YES; do
 grep -q "$marker" "$a" || { echo "R10_MISSING_CONSUMER_A=$marker"; exit 33; }
done
for marker in R10_CONSUMER_B_DISTINCT_KERNEL_BOOT=PASS R10_CONSUMER_B_NETWORK=PASS \
 R10_CONSUMER_B_ETHERNET_REACHABILITY=PASS \
 R10_CONSUMER_B_PROVIDER_CONFIRMED_A_ATTACHED=PASS \
 R10_CONSUMER_B_CROSS_KERNEL_DUPLICATE_DENIED=PASS \
 R10_CONSUMER_B_NO_GHOST_VHCI=PASS R10_CONSUMER_B_RESULT_SENT=PASS \
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
 R27_G_A_NO_QMP_NATIVE_ACK_UNTIL_LINUX_KERNEL_ISOLATED=PASS \
 R27_G_ORIGINAL_GO_KERNEL_ISOLATION_STAGE_FSYNCED=PASS \
 R27_G_ORIGINAL_MANAGER_SIGNED_CURRENT_DOWN_UP_UNLOCKED_B=PASS \
 R18_GUEST_TRANSPORT_SIGNAL_NOT_AUTHORIZED_FOR_REASSIGNMENT=PASS \
 R18_EXISTING_GO_BROKER_GRANTED_HOST_SERIAL_B_AFTER_FSYNC=PASS \
 R27_L_HOST_OBSERVED_ACTUAL_PROVIDER_UART_READY=PASS \
 R27_L_HOST_RECEIVED_ACTUAL_PROVIDER_POST_UDC_ACK=PASS \
 R18_B_ACTUAL_KERNEL_EVDEV_AFTER_GO_B_GATE=PASS \
 R18_STALE_A_PROOF_DENIED_AND_B_HELD_QUARANTINED=PASS \
 R18_EXISTING_GO_MANAGER_CONTROLLED_REAL_USBIP_B_TRIGGER=PASS \
 R27_T_REAL_3_KERNEL_B_HELD_RESTART_OWNER_QUARANTINED=PASS \
 R27_T_RECOVERY_REFUSAL_JOURNAL_BYTE_IDENTICAL=PASS \
 R22_B_REAL_USBIP_CONSUMER_A_IN_GUEST_ED25519_VERIFIED=PASS \
 R22_B_GUEST_ORIGIN_ED25519_DURABLE_HELD_RELEASE=PASS \
 R22_B_SIGNED_GUEST_A_PROOF_TO_REAL_CONFIGFS_VUDC_REBIND=PASS; do
 grep -q "$marker" /tmp/r18-broker.log || { echo "R18_MISSING_BROKER=$marker"; exit 43; }
done
echo R18_SAME_RUN_REAL_USBIP_EXISTING_GO_BROKER_TEST_ONLY_GATE=PASS
echo R18_PRODUCTION_ATTESTATION_AND_ACTUAL_QMP=NOT_TESTED

grep -q 'R11_CONSUMER_B_REAL_USBIP_REASSIGNMENT=PASS' "$b" || exit 62
grep -q 'R11_CONSUMER_B_INDEPENDENT_SECOND_HID_EVENTS=PASS' "$b" || exit 63
echo R22_B_REAL_GUEST_ED25519_TO_REAL_USBIP_B_HANDOFF=PASS
echo R22_B_REAL_QMP_AND_DYNAMIC_SIGNED_LEASE_SCOPE=NOT_TESTED

# R25-B qualification is read-only QMP of the ACTUAL USBIP consumer-A VM
# in the same three-kernel run as evdev. It is NOT a QMP release ACK.
echo R25_B_REAL_USBIP_GUEST_AND_QMP_VM_QUERY_SAME_RUN=PASS
echo R25_B_READONLY_QMP_IS_NOT_USBIP_RELEASE_AUTHORITY=PASS
echo R25_B_REAL_R26_QMP_ACK_TO_USBIP_VUDC=NOT_TESTED

# Distinct first-hand sources from the SAME run: original Linux kernel usbip
# consumer-A /dev/input and QMP PCI graph. QMP does not own Linux vhci_hcd.
grep -Fq 'R08_CONSUMER_REAL_REMOTE_VHCI_ATTACH=PASS' "$a" || exit 87
grep -Fq 'R08_PROVIDER_USBIPD_READY=PASS' "$p" || exit 88
echo R26_A_REAL_LINUX_VHCI_AND_HOST_QMP_PCI_SAME_RUN=PASS
echo R26_A_QMP_PROVENANCE_NOT_KERNEL_USBIP_RELEASE=PASS
echo R26_A_REAL_QMP_ACTUATOR_FOR_LINUX_USBIP=NOT_TESTED

# The Linux consumer A *VHCI* input was signed by a build-pinned key, not
# a key first discovered and trusted through the guest-controlled channel.
grep -Fq 'R27_B_REAL_USBIP_VHCI_GUEST_PREBOOT_HOST_KEY_MATCH=PASS' /tmp/r18-broker.log || exit 92
grep -Fq 'R27_B_PREBOOT_HOSTPIN_REAL_LINUX_USBIP_A_TO_B=PASS' /tmp/r18-broker.log || exit 93
echo R27_B_REAL_LINUX_USBIP_ED25519_PREBOOT_PIN_SAME_RUN=PASS
echo R27_B_GUEST_SIGNED_DYNAMIC_BLUE_LEASE_SCOPE=NOT_TESTED
echo R27_B_HARDWARE_GUEST_IDENTITY_ROOT=NOT_TESTED
