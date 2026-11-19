package main

import "testing"

// R26-C RED oracle: changing the self-described evidence "kind" must not
// turn a QMP-native actuation receipt into proof of kernel USBIP handoff.
// A transport endpoint is controlled by Linux vhci_hcd + provider VUDC,
// not by QMP's unrelated USB device object.
func TestR26RejectsQMPNativeEvidenceForKernelUSBIPGate(t *testing.T) {
    m:=example()
    m.Receipts[0].Kind="real-qemu"
    m.Receipts[0].Marker="R24_B_ONE_REAL_QMP_DYNAMIC_ED25519_GUEST_LEASE_FSYNCED=PASS"
    m.Gates[0].RequiredKind="real-qemu"
    if verdict:=Validate(m);verdict.Valid {
        t.Fatalf("R26_C_RED cross-domain QMP-native evidence laundered into kernel USBIP release: %+v",verdict)
    }
    t.Log("R26_C_QMP_NATIVE_NOT_KERNEL_USBIP_RELEASE=PASS")
}

func TestR26ReadOnlyVMQMPCannotQualifyUSBIPKernelRelease(t *testing.T) {
    m:=example()
    // Even a real-QEMU receipt with a matching VM UUID cannot discharge
    // transport release. The assertion requires separate actuator domain.
    m.Receipts[0].Kind="real-qemu"
    m.Receipts[0].Marker="R25_B_QMP_CONSUMER_A_VM_NAME_UUID_STATUS=PASS"
    m.Gates[0].RequiredKind="real-qemu"
    if verdict:=Validate(m);verdict.Valid {
        t.Fatalf("R26_C_RED read-only QMP VM identity was accepted as kernel USBIP release: %+v",verdict)
    }
    t.Log("R26_C_QMP_READONLY_VM_ID_NOT_USBIP_CONTROL=PASS")
}
