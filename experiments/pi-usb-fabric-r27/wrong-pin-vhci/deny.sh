#!/bin/sh
# Real three-QEMU Linux USBIP guest wrong-host-pin. The R27-B original
# Go broker rejects a correctly signed guest receipt when the independent
# host-approved public test key differs. Do not invent HELD assertions:
# the verifier exits before initializing its Go heldledger.
set -eu
runner=""
cleanup(){
 if [ -n "$runner" ];then
   kill -TERM "$runner" 2>/dev/null || :
   wait "$runner" 2>/dev/null || :
 fi
}
trap cleanup EXIT INT TERM
/bin/sh /guest/r27-b-run.sh >/tmp/r27-e-three-guest-run.log 2>&1 &
runner=$!
good=0
i=0
while [ "$i" -lt 360 ];do
 if [ -f /tmp/r18-broker.log ] &&
    grep -Fq 'R18_CROSS_KERNEL_HOST_GO_GATE=RED: R27-B real Linux USBIP guest signer mismatched preapproved host key' /tmp/r18-broker.log;then
     good=1
     break
 fi
 if ! kill -0 "$runner" 2>/dev/null;then break;fi
 i=$((i+1))
 sleep 0.25
done
if [ "$good" -ne 1 ];then
 echo R27_E_BROKER_WRONG_PIN_REFUSAL=RED
 cat /tmp/r18-broker.log 2>/dev/null || :
 cat /tmp/r27-e-three-guest-run.log 2>/dev/null || :
 exit 49
fi
# The existing host Go broker has checked TWO actual signed guest evdev
# events before testing independently preapproved identity.
grep -Fq 'R27_B_HOST_PUB_PIN_READY_BEFORE_CONSUMER_A_QEMU_BOOT=PASS' /tmp/r18-broker.log || exit 50
grep -Fq 'R08_CONSUMER_REAL_REMOTE_VHCI_ATTACH=PASS' /tmp/r18-consumer-a.log || exit 51
grep -Fq 'USBFABRIC_R06_REAL_KEY_A_DOWN=PASS' /tmp/r18-consumer-a.log || exit 52
grep -Fq 'USBFABRIC_R06_REAL_KEY_A_UP=PASS' /tmp/r18-consumer-a.log || exit 53
if grep -Fq 'R18_EXISTING_GO_BROKER_GRANTED_HOST_SERIAL_B_AFTER_FSYNC=PASS' /tmp/r18-broker.log;then
 echo R27_E_WRONG_PIN_GRANTED_B=RED
 exit 54
fi
if grep -Fq 'R11_CONSUMER_B_REAL_USBIP_REASSIGNMENT=PASS' /tmp/r18-consumer-b.log 2>/dev/null;then
 echo R27_E_WRONG_PIN_B_KERNEL_IMPORT=RED
 exit 55
fi
echo R27_E_REAL_USBIP_VHCI_SIGNED_KEY_A_OBSERVED=PASS
echo R27_E_PREBOOT_WRONG_HOST_PIN_REJECTED_BY_GO_BROKER=PASS
echo R27_E_NO_HOST_GRANT_AND_NO_B_IMPORT_BEFORE_REJECTION=PASS
echo R27_E_JOURNAL_HELD_AFTER_WRONG_PIN=NOT_TESTED
echo R27_E_SAME_RUN_LINUX_VHCI_SIGNED_DYNAMIC_LEASE=NOT_TESTED
cleanup
runner=""
echo R27_E_REAL_QEMU_DISPOSABLE_WRONG_PIN_CLEANUP=PASS
