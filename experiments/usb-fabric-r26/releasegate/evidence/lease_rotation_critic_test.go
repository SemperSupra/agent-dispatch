package evidence_test

import (
 "errors"
 "testing"

 gate "example.org/usb-fabric-r26-releasegate"
 evidence "example.org/usb-fabric-r26-releasegate/evidence"
 "example.org/usb-fabric-r26-releasegate/guestwire"
)

func signedReceipt(scope gate.Scope,down bool,n uint64)evidence.Event {
 return guestwire.SignForSyntheticGuest(evidence.Event{
  Scope:scope,Source:"guest.evdev",KeyCode:"key-a",
  Down:down,EventSequence:n,
 })
}
func attempt(t *testing.T,b *evidence.Bridge,g *gate.Gate,s gate.Scope,down,up uint64){
 t.Helper()
 if err:=b.ObserveDown(signedReceipt(s,true,down));err!=nil{t.Fatal(err)}
 if err:=b.ConfirmUp(signedReceipt(s,false,up));!errors.Is(err,evidence.ErrUntrusted){
  t.Fatal("guest up before QMP ACK admitted",err)
 }
 if err:=g.RequestRelease(s);err!=nil{t.Fatal(err)}
 if err:=g.AcknowledgeQMP(s);err!=nil{t.Fatal(err)}
 if b.Reclaimable(){t.Fatal("QMP ACK alone made device available")}
 if err:=b.ConfirmUp(signedReceipt(s,false,up));err!=nil{t.Fatal(err)}
 if !b.Reclaimable(){t.Fatal("independent guest release blocked")}
}

func TestTwoDistinctGuestProofLeaseScopesAndStaleReplay(t *testing.T){
 first:=guestwire.Scope()
 first.HostEpoch="actual-synthetic-host-epoch-xyz"
 first.LeaseEpoch="ephemeral-lease-1"
 first.Generation=1
 first.ReleaseSequence=1
 second:=first
 second.LeaseEpoch="ephemeral-lease-2"
 second.Generation=4
 second.ReleaseSequence=3
 if first==second{t.Fatal("lease generation not rotated")}
 g1,err:=gate.New(first);if err!=nil{t.Fatal(err)}
 b1,err:=evidence.New(g1,first,guestwire.VerifySyntheticGuest)
 if err!=nil{t.Fatal(err)}
 attempt(t,b1,g1,first,10,11)
 stored:=gate.Restore(g1.Snapshot())
 if stored.Reclaimable()||stored.Snapshot().Phase!=gate.Quarantined{
  t.Fatal("reboot-restored first lease automatically accepted")
 }
 g2,err:=gate.New(second);if err!=nil{t.Fatal(err)}
 b2,err:=evidence.New(g2,second,guestwire.VerifySyntheticGuest)
 if err!=nil{t.Fatal(err)}
 // Replaying a real first-lease signed input event must not begin second
 // lease, even though the test MAC is valid and event sequence is newer.
 for _,old:=range []evidence.Event{
  signedReceipt(first,true,10),
  signedReceipt(first,false,11),
  signedReceipt(first,false,13),
 }{
  if err:=b2.ObserveDown(old);!errors.Is(err,evidence.ErrUntrusted){
   t.Fatal("old lease evidence admitted as second down",err)
  }
  if err:=b2.ConfirmUp(old);!errors.Is(err,evidence.ErrUntrusted){
   t.Fatal("old lease UP accepted",err)
  }
  if b2.Reclaimable(){t.Fatal("replayed first lease reclaimed second")}
 }
 // A forged lease generation with a legitimate MAC for the wrong scope
 // cannot pass: scope equality is an independent structural fence.
 wrong:=second;wrong.GuestEpoch="another-guest"
 if err:=b2.ObserveDown(signedReceipt(wrong,true,12));!errors.Is(err,evidence.ErrUntrusted){
  t.Fatal("wrong VM incarnation down accepted",err)
 }
 wrong=second;wrong.Generation++
 if err:=b2.ObserveDown(signedReceipt(wrong,true,12));!errors.Is(err,evidence.ErrUntrusted){
  t.Fatal("wrong generation down accepted",err)
 }
 attempt(t,b2,g2,second,12,13)
 if err:=b2.ConfirmUp(signedReceipt(second,false,13));!errors.Is(err,evidence.ErrUntrusted){
  t.Fatal("same-lease UP replay accepted",err)
 }
 t.Log("R26_L9D_TWO_SCOPED_LEASES_AND_FIRST_LEASE_REPLAY_DENIED=PASS")
}
