package main

import (
    "strings"
    "testing"
)
func example() Manifest {
    return Manifest{
        Schema:"usb-fabric-r25/1",
        EvidenceRepository:"SemperSupra/agent-dispatch",
        Authority:"mark-e-deyoung/infrastructure-as-code-private",
        ObservationDate:"2026-11-19",
        Receipts:[]Receipt{
            {ID:"r24b",PR:876,Head:"49930c8fb8a8b2171d6483dc26b6ed87937e6ed8",Run:44570236188,Job:135722949490,Kind:"real-qemu",Outcome:"PASS",Marker:"R24_B_ONE_REAL_QMP_DYNAMIC_ED25519_GUEST_LEASE_FSYNCED=PASS",ChangedPaths:[]string{"experiments/r24/qmp.go"}},
            {ID:"r25a",PR:884,Head:"fcf79544ed617e196ac03461b6ce079ec5d1ac35",Run:44606660454,Job:135852039364,Kind:"contract",Outcome:"PASS",Marker:"R25_A_EXISTING_R24_R23_R22_COMPOSITION_TEST_ONLY=PASS",ChangedPaths:[]string{"experiments/r25/interlock.go"}},
        },
        Gates:[]Gate{
            {ID:"real-qmp",Priority:"P0",State:"PASS",RequiredKind:"real-qemu",ReceiptID:"r24b"},
            {ID:"offline-policy",Priority:"P0",State:"PASS",RequiredKind:"contract",ReceiptID:"r25a"},
            {ID:"causal-usbip",Priority:"P0",State:"NOT_TESTED",RequiredKind:"real-usbip"},
        },
    }
}
func TestDLEValidOfflineSnapshotRefusesPrematureRelease(t *testing.T) {
    m:=example();result:=Validate(m)
    if !result.Valid||result.ReleaseEligible||len(result.CriticalRemaining)!=1{
        t.Fatalf("unexpected snapshot verdict: %+v",result)
    }
    t.Log("R25_D_SOURCE_SNAPSHOT_VALID_BUT_RELEASE_BLOCKED=PASS")
    m.ReleaseRequested=true;m.OwnerApproved=true
    result=Validate(m)
    if result.Valid||result.ReleaseEligible {
        t.Fatalf("unqualified P0 attempted promotion: %+v",result)
    }
    t.Log("R25_D_UNQUALIFIED_P0_EVEN_OWNER_APPROVED_REFUSED=PASS")
}
func TestDLEContractCannotMasqueradeAsPhysicalOrRealUSBIP(t *testing.T){
    m:=example()
    m.Gates[2].State="PASS"
    m.Gates[2].ReceiptID="r25a"
    r:=Validate(m)
    if r.Valid{t.Fatalf("contract promoted to real USBIP: %+v",r)}
    t.Log("R25_D_CONTRACT_TO_REAL_USBIP_EVIDENCE_INFLATION_DENIED=PASS")
}
func TestDLEUnapprovedOrConflictingEvidenceRejected(t *testing.T) {
    m:=example()
    m.ReleaseRequested=true
    m.Gates=m.Gates[:2]
    r:=Validate(m)
    if r.Valid{t.Fatal("unapproved release accepted")}
    m=example()
    m.Receipts[1].ChangedPaths=[]string{"experiments/r24/qmp.go"}
    r=Validate(m)
    if r.Valid || !strings.Contains(strings.Join(r.Errors,","),"path ownership collision"){
        t.Fatalf("overlapping write paths accepted: %+v",r)
    }
    m=example()
    m.Receipts[1].Head="unverified"
    r=Validate(m)
    if r.Valid{t.Fatal("unqualified head SHA accepted")}
    m=example()
    m.Receipts[1].Run=0
    r=Validate(m)
    if r.Valid{t.Fatal("missing real workflow ID accepted")}
    t.Log("R25_D_UNAPPROVED_CONFLICTING_OR_UNSOURCED_RELEASE_DENIED=PASS")
}
