package heldledger

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

// A USB/IP transport management success (or remote device disappearance)
// cannot be upgraded to guest evdev proof. This test executes the EXISTING
// durable journal transition and a valid public TEST-ONLY MAC verifier.
func TestR11TransportCleanupIsNotGuestReleaseEvidence(t *testing.T) {
 store:=Store{Path:filepath.Join(t.TempDir(),"held.json")}
 held,err:=store.Transition(0,true)
 if err!=nil||!held.Held||held.Sequence!=1{t.Fatalf("initial journal: %+v %v",held,err)}
 stage(t,store,1) // persisted release-intent and genuine actuator QMP ACK stage
 pre,err:=os.ReadFile(store.Path)
 if err!=nil{t.Fatal(err)}
 for _,tc:=range []struct{name,source string}{
  {"usbip detach", "usbip.detach"},
  {"empty vhci port", "usbip.port"},
  {"kernel node disappeared", "kernel.device_removed"},
  {"network heartbeat recovered", "network.heartbeat"},
  {"provider device busy", "usbip.device_busy"},
 } {
  t.Run(tc.name,func(t *testing.T){
   fake:=claim(1,20,21)
   fake.Source=tc.source
   fake.KeyReleased=true // deliberately try to promote transport state to trusted up
   fake.Proof=testMAC(fake)
   if !signed(fake){t.Fatal("fixture must have valid test-only MAC")}
   if _,err:=store.ConfirmGuestRelease(1,fake,signed);!errors.Is(err,ErrUnverified){
    t.Fatalf("R11_UNSAFE_TRANSPORT_RECEIPT_ACCEPTED source=%s err=%v",tc.source,err)
   }
   after,err:=os.ReadFile(store.Path)
   if err!=nil||!bytes.Equal(pre,after){t.Fatalf("transport receipt changed HELD journal source=%s err=%v",tc.source,err)}
   state,err:=store.Read()
   if err!=nil||!state.Held||state.Sequence!=1||state.ReleasePhase!="qmp-acked"{
    t.Fatalf("transport receipt removed held state source=%s state=%+v err=%v",tc.source,state,err)
   }
  })
 }
 t.Log("R11_TRANSPORT_DETACH_NOT_GUEST_RELEASE_PROOF=PASS")
 verified:=claim(1,20,21)
 clean,err:=store.ConfirmGuestRelease(1,verified,signed)
 if err!=nil||clean.Held||clean.Sequence!=2{
  t.Fatalf("correct scoped guest evdev proof cannot clear held: %+v %v",clean,err)
 }
 t.Log("R11_REAL_SCOPED_GUEST_EVDEV_ONLY_RELEASES_HELD=PASS")
}
