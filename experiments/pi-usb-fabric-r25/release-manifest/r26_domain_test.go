package main

import "testing"

// Source-authored RED first (Actions 44626894872): the old checker accepted
// a self-described kind as proof of a different actuator domain. These
// new cases require both a compatible receipt domain/kind and an EXACT
// evidence-domain match with the gate. Neither change grants real device
// authority: live job/source revalidation remains mandatory.
func TestR26RejectsQMPNativeEvidenceForKernelUSBIPGate(t *testing.T) {
    m:=example()
    m.Receipts[0].Kind="real-usbip" // deliberately inflated self-description
    m.Receipts[0].Domain="qmp-native" // source still QMP-native
    m.Gates[0].ID="kernel-usbip-release"
    m.Gates[0].RequiredKind="real-usbip"
    m.Gates[0].RequiredDomain="usbip-kernel"
    if verdict:=Validate(m);verdict.Valid {
        t.Fatalf("R26_C_RED cross-domain QMP-native evidence laundered into kernel USBIP release: %+v",verdict)
    }
    t.Log("R26_C_QMP_NATIVE_NOT_KERNEL_USBIP_RELEASE=PASS")
}

func TestR26ReadOnlyVMQMPCannotQualifyUSBIPKernelRelease(t *testing.T) {
    m:=example()
    m.Receipts[0].Kind="real-usbip"
    m.Receipts[0].Domain="vm-provenance" // valid label; only VM observation
    m.Receipts[0].Marker="R25_B_QMP_CONSUMER_A_VM_NAME_UUID_STATUS=PASS"
    m.Gates[0].ID="kernel-usbip-release"
    m.Gates[0].RequiredKind="real-usbip"
    m.Gates[0].RequiredDomain="usbip-kernel"
    if verdict:=Validate(m);verdict.Valid {
        t.Fatalf("R26_C_RED read-only QMP VM identity was accepted as kernel USBIP release: %+v",verdict)
    }
    t.Log("R26_C_QMP_READONLY_VM_ID_NOT_USBIP_CONTROL=PASS")
}
