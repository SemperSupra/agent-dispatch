#!/bin/sh
# R27-F actual one-run SOURCE COMPOSITION; no QMP-native release authority.
# R27-A Linux kernel ConfigFS fence and direct B bypass oracle sourced from
# immutable #912, while R27-B independently host-pins signed Linux VHCI A.
set -eu
/bin/sh /guest/r27-b-run.sh
p=/tmp/r18-provider.log
a=/tmp/r18-consumer-a.log
b=/tmp/r18-consumer-b.log
broker=/tmp/r18-broker.log
for marker in \
 R27_A_PROVIDER_REAL_CONFIGFS_UDC_UNBOUND_BEFORE_A_DETACH=PASS \
 R27_A_REAL_RAW_B_LATE_IMPORT_DENIED_BEFORE_HOST_GRANT=PASS \
 R27_A_REAL_CONFIGFS_UDC_REBOUND_AFTER_HOST_GRANT=PASS; do
 grep -Fq "$marker" "$p" || { echo "R27_F_PROVIDER_PROOF_MISSING=$marker";exit 71; }
done
for marker in \
 R27_A_B_LATE_RAW_USBIP_IMPORT_ATTEMPTED=PASS \
 R27_A_B_LATE_RAW_USBIP_IMPORT_DENIED_WHILE_UNBOUND=PASS \
 R11_CONSUMER_B_REAL_USBIP_REASSIGNMENT=PASS \
 R11_CONSUMER_B_INDEPENDENT_SECOND_HID_EVENTS=PASS; do
 grep -Fq "$marker" "$b" || { echo "R27_F_B_PROOF_MISSING=$marker";exit 72; }
done
for marker in \
 R27_B_HOST_PUB_PIN_READY_BEFORE_CONSUMER_A_QEMU_BOOT=PASS \
 R27_B_REAL_USBIP_VHCI_GUEST_PREBOOT_HOST_KEY_MATCH=PASS \
 R22_B_GUEST_ORIGIN_ED25519_DURABLE_HELD_RELEASE=PASS \
 R18_EXISTING_GO_BROKER_GRANTED_HOST_SERIAL_B_AFTER_FSYNC=PASS; do
 grep -Fq "$marker" "$broker" || { echo "R27_F_GO_SIGNER_PROOF_MISSING=$marker";exit 73; }
done
grep -Fq 'R08_CONSUMER_REAL_REMOTE_VHCI_ATTACH=PASS' "$a" || exit 74
# Sequence in the provider's own genuine Linux guest serial log.
line(){
 grep -n -F "$1" "$p" | head -1 | cut -d: -f1
}
unbound="$(line 'R27_A_PROVIDER_REAL_CONFIGFS_UDC_UNBOUND_BEFORE_A_DETACH=PASS')"
detached="$(line 'R11_PROVIDER_A_DETACH_CONFIRMED_BEFORE_B_RETRY=PASS')"
raw="$(line 'R27_A_REAL_RAW_B_LATE_IMPORT_DENIED_BEFORE_HOST_GRANT=PASS')"
waiting="$(line 'R18_PROVIDER_HOST_SERIAL_GATE_WAITING=PASS')"
rebound="$(line 'R27_A_REAL_CONFIGFS_UDC_REBOUND_AFTER_HOST_GRANT=PASS')"
if [ -z "$unbound" ] || [ -z "$detached" ] || [ -z "$raw" ] || [ -z "$waiting" ] || [ -z "$rebound" ] ||
   [ "$unbound" -ge "$detached" ] || [ "$detached" -ge "$raw" ] ||
   [ "$raw" -ge "$waiting" ] || [ "$waiting" -ge "$rebound" ];then
 echo "R27_F_REAL_CONFIGFS_EVENT_ORDER=RED unbound=$unbound detached=$detached raw=$raw waiting=$waiting rebound=$rebound"
 exit 75
fi
echo R27_F_ACTUAL_PROVIDER_UNBIND_BEFORE_A_VHCI_DETACH=PASS
echo R27_F_ACTUAL_B_RAW_IMPORT_DENIED_WHILE_UDC_UNBOUND=PASS
echo R27_F_PREBOOT_ED25519_SIGNED_VHCI_AND_QMP_PROVENANCE_SAME_RUN=PASS
echo R27_F_HOST_ONLY_GO_GRANT_BEFORE_REAL_UDC_REBIND_AND_B_IMPORT=PASS
echo R27_F_ONE_RUN_THREE_REAL_LINUX_KERNELS_A_TO_B=PASS
# These are OPEN despite successful data-plane composition:
echo R27_F_ORIGINAL_TYPED_KERNEL_PHASE_IN_SAME_RUN=NOT_TESTED
echo R27_F_GUEST_SIGNED_DYNAMIC_LEASE_SCOPE=NOT_TESTED
echo R27_F_HARDWARE_ROOTED_GUEST_IDENTITY=NOT_TESTED
