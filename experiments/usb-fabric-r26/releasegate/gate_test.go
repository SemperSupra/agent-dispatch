package releasegate

import (
 "crypto/hmac"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "testing"
)
var syntheticTestKey=[]byte("TEST-ONLY-R26-NOT-PRODUCTION-AUTH")
func scope()Scope{
 return Scope{GuestID:"synthetic-linux",DeviceID:"qemu-usb-keyboard",
  HostEpoch:"host-epoch-01",GuestEpoch:"guest-epoch-02",
  LeaseEpoch:"lease-epoch-03",Generation:4,ReleaseSequence:7}
}
func mac(r Receipt)string{
 h:=hmac.New(sha256.New,syntheticTestKey)
 _,_ = fmt.Fprintf(h,"%s|%s|%s|%s|%s|%d|%d|%s|%d|%v",
  r.Scope.GuestID,r.Scope.DeviceID,r.Scope.HostEpoch,
  r.Scope.GuestEpoch,r.Scope.LeaseEpoch,r.Scope.Generation,
  r.Scope.ReleaseSequence,r.Source,r.EventSequence,r.KeyReleased)
 return hex.EncodeToString(h.Sum(nil))
}
func signed()Receipt{
 r:=Receipt{Scope:scope(),Source:"guest.evdev",
  EventSequence:8,KeyReleased:true}
 r.Proof=mac(r)
 return r
}
func verifier(r Receipt)bool{
 return hmac.Equal([]byte(mac(r)),[]byte(r.Proof))
}
func TestQMPAckIsNotGuestRelease(t *testing.T){
 g,e:=New(scope());if e!=nil{t.Fatal(e)}
 if g.Reclaimable(){t.Fatal("pressed input incorrectly available")}
 if e=g.RequestRelease(scope());e!=nil{t.Fatal(e)}
 if g.Reclaimable(){t.Fatal("pending QMP release became available")}
 if e=g.AcknowledgeQMP(scope());e!=nil{t.Fatal(e)}
 if g.Reclaimable(){t.Fatal("P0: QMP ACK implicitly allowed new lease")}
 g2:=Restore(g.Snapshot())
 if g2.Reclaimable()||g2.Snapshot().Phase!=QMPAcknowledged{
  t.Fatal("restart silently promoted unproven QMP ACK")
 }
}
func TestSignedGuestReceiptRequiredAndScoped(t *testing.T){
 g,_:=New(scope())
 if e:=g.RequestRelease(scope());e!=nil{t.Fatal(e)}
 if e:=g.AcknowledgeQMP(scope());e!=nil{t.Fatal(e)}
 proof:=signed()
 for _,bad:=range []Receipt{
  func()Receipt{x:=proof;x.Scope.GuestID="other";return x}(),
  func()Receipt{x:=proof;x.Scope.LeaseEpoch="old";return x}(),
  func()Receipt{x:=proof;x.Scope.GuestEpoch="oldguest";return x}(),
  func()Receipt{x:=proof;x.Scope.ReleaseSequence=6;return x}(),
  func()Receipt{x:=proof;x.KeyReleased=false;return x}(),
  func()Receipt{x:=proof;x.EventSequence=0;return x}(),
  func()Receipt{x:=proof;x.Source="client";return x}(),
  func()Receipt{x:=proof;x.Proof="fabricated";return x}(),
 }{
  if e:=g.ConfirmGuest(bad,verifier);!errors.Is(e,ErrUnproven){
   t.Fatalf("accepted stale/forged receipt %+v err=%v",bad,e)
  }
  if g.Reclaimable(){t.Fatal("bad receipt allowed reallocation")}
 }
 if e:=g.ConfirmGuest(proof,nil);!errors.Is(e,ErrUnproven){t.Fatal("nil verifier accepted")}
 if e:=g.ConfirmGuest(proof,verifier);e!=nil{t.Fatal(e)}
 if !g.Reclaimable(){t.Fatal("verified guest receipt did not clear hold")}
 if e:=g.ConfirmGuest(proof,verifier);!errors.Is(e,ErrUnproven){t.Fatal("replay accepted")}
}
func TestTimeoutQuarantineAndUnknownSnapshot(t *testing.T){
 g,_:=New(scope())
 _=g.RequestRelease(scope())
 g.FailClosed()
 if g.Reclaimable(){t.Fatal("quarantined device re-admitted")}
 if e:=g.AcknowledgeQMP(scope());!errors.Is(e,ErrDenied){t.Fatal("QMP ack ended quarantine")}
 forgedPersistence:=Restore(Snapshot{Version:1,Scope:scope(),Phase:GuestConfirmed})
 if forgedPersistence.Reclaimable(){t.Fatal("persisted confirmation re-admitted without independent signature revalidation")}
 uncertain:=Restore(Snapshot{Version:20,Scope:scope(),Phase:GuestConfirmed})
 if uncertain.Reclaimable()||uncertain.Snapshot().Phase!=Quarantined{t.Fatal("unknown version trusted")}
 unknown:=Restore(Snapshot{Version:1,Scope:scope(),Phase:"mystery"})
 if unknown.Reclaimable(){t.Fatal("unknown state treated as free")}
}
func TestCrossEpochReleaseRequestDenied(t *testing.T){
 g,_:=New(scope())
 stale:=scope();stale.HostEpoch="reused-host"
 if e:=g.RequestRelease(stale);!errors.Is(e,ErrDenied){t.Fatal("host epoch bypass")}
 if e:=g.AcknowledgeQMP(scope());!errors.Is(e,ErrDenied){t.Fatal("unsolicited QMP ACK accepted")}
}
