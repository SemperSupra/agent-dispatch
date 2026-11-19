package composition

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "testing"

 "example.org/usb-fabric-r26-integrated/blue"
 "example.org/usb-fabric-r26-integrated/heldledger"
 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
 "example.org/usb-fabric-r26-releasegate/guestwire"
)

// Reuse the EXISTING Go Manager, heldledger, R26 releasegate and evidence
// bridge. There is intentionally NO new controller, QMP client or USBIP
// network stack. All signatures and QMP ACKs in this unit test are TEST-ONLY.
func TestR22ComposeExistingGuestGateAndHeldJournalBeforeNextAdmission(t *testing.T){
 scope:=guestwire.Scope()
 store:=heldledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
 initial,err:=store.Transition(0,true);if err!=nil{t.Fatal(err)}
 if _,err=store.RequestRelease(initial.Sequence);err!=nil{t.Fatal(err)}
 if _,err=store.AcknowledgeQMPRelease(initial.Sequence);err!=nil{t.Fatal(err)} // simulated QMP ACK
 before,err:=os.ReadFile(store.Path);if err!=nil{t.Fatal(err)}
 manager:=blue.New(scope.DeviceID,"xhci0/auto",nil)
 manager.Offline() // quarantine before any frontend publication
 if _,err=manager.Reserve("consumer-B",scope.DeviceID,"xhci0/auto");!errors.Is(err,blue.ErrQuarantined){t.Fatalf("B before guest proof: %v",err)}
 gate,err:=releasegate.New(scope);if err!=nil{t.Fatal(err)}
 bridge,err:=evidence.New(gate,scope,guestwire.VerifySyntheticGuest);if err!=nil{t.Fatal(err)}
 down:=guestwire.SignForSyntheticGuest(evidence.Event{Scope:scope,Source:"guest.evdev",KeyCode:"key-a",Down:true,EventSequence:10})
 up:=guestwire.SignForSyntheticGuest(evidence.Event{Scope:scope,Source:"guest.evdev",KeyCode:"key-a",Down:false,EventSequence:11})
 if err=bridge.ObserveDown(down);err!=nil{t.Fatal(err)}
 if err=bridge.ConfirmUp(up);!errors.Is(err,evidence.ErrUntrusted){t.Fatalf("guest-UP without QMP allowed: %v",err)}
 if err=gate.RequestRelease(scope);err!=nil{t.Fatal(err)}
 if err=gate.AcknowledgeQMP(scope);err!=nil{t.Fatal(err)} // simulated, not real QEMU
 if bridge.Reclaimable(){t.Fatal("QMP ACK alone reclaimed guest")}
 if _,err=manager.Reserve("consumer-B",scope.DeviceID,"xhci0/auto");!errors.Is(err,blue.ErrQuarantined){t.Fatalf("QMP-only B admission: %v",err)}
 after,err:=os.ReadFile(store.Path);if err!=nil||!bytes.Equal(before,after){t.Fatalf("unproven release modified held journal: %v",err)}
 claim:=heldledger.ReleaseClaim{
  GuestID:scope.GuestID,DeviceID:scope.DeviceID,HostEpoch:scope.HostEpoch,
  GuestEpoch:scope.GuestEpoch,LeaseEpoch:scope.LeaseEpoch,Generation:scope.Generation,
  ReleaseSequence:scope.ReleaseSequence,DownEventSequence:down.EventSequence,
  EventSequence:up.EventSequence,Source:up.Source,Key:heldledger.KeyA,KeyReleased:true,Proof:up.Proof,
 }
 verify:=func(c heldledger.ReleaseClaim)bool{
  return guestwire.VerifySyntheticGuest(up) &&
   c.GuestID==scope.GuestID && c.DeviceID==scope.DeviceID &&
   c.HostEpoch==scope.HostEpoch && c.GuestEpoch==scope.GuestEpoch &&
   c.LeaseEpoch==scope.LeaseEpoch && c.Generation==scope.Generation &&
   c.ReleaseSequence==scope.ReleaseSequence && c.DownEventSequence==down.EventSequence &&
   c.EventSequence==up.EventSequence && c.Proof==up.Proof &&
   c.Source=="guest.evdev" && c.Key==heldledger.KeyA && c.KeyReleased
 }
 fake:=claim;fake.Source="usbip.detach"
 if err=manager.RestoreAfterVerifiedGuestUp(store,1,fake,verify);!errors.Is(err,heldledger.ErrUnverified){t.Fatalf("transport proof admitted: %v",err)}
 fake=claim;fake.Generation++
 if err=manager.RestoreAfterVerifiedGuestUp(store,1,fake,verify);!errors.Is(err,heldledger.ErrUnverified){t.Fatalf("wrong generation admitted: %v",err)}
 after,err=os.ReadFile(store.Path);if err!=nil||!bytes.Equal(before,after){t.Fatalf("wrong proof changed HELD: %v",err)}
 if err=bridge.ConfirmUp(up);err!=nil{t.Fatal(err)}
 if !bridge.Reclaimable(){t.Fatal("guest event did not clear R26 test gate")}
 if err=manager.RestoreAfterVerifiedGuestUp(store,1,claim,verify);err!=nil{t.Fatal(err)}
 state,err:=store.Read();if err!=nil||state.Held||state.Sequence!=2{t.Fatalf("journal not cleared %+v %v",state,err)}
 lease,err:=manager.Reserve("consumer-B",scope.DeviceID,"xhci0/auto");if err!=nil||lease.Generation==0{t.Fatalf("no next B lease: %+v %v",lease,err)}
 t.Log("R22_B_EXISTING_R26_GATE_TO_R21_GO_LEDGER_COMPOSITION_TEST=PASS")
 t.Log("R22_B_REAL_QMP_USBIP_SAME_RUN_INTERLOCK=NOT_TESTED")
}
