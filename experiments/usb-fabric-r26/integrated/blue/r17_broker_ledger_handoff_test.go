package blue

import (
 "bytes"
 "crypto/hmac"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "testing"

 "example.org/usb-fabric-r26-integrated/heldledger"
)

// R17 exercises existing Manager and real fsynced Store methods. The executor
// is TEST-ONLY: it simulates an actuator's successful QMP ACK and deliberately
// withholds guest release proof. It performs no QMP/USB/IP/network operations.
var errR17PendingGuest = errors.New("R17 TEST-ONLY QMP ACK awaiting guest evdev")

type r17JournalExecutor struct{ journal heldledger.Store }

func (e *r17JournalExecutor) Input(command string)error {
 state,err:=e.journal.Read()
 if err!=nil{return err}
 switch command {
 case "key-a-down":
  if state.Held{return ErrDenied}
  _,err=e.journal.Transition(state.Sequence,true)
  return err
 case "key-a-up":
  if !state.Held{return ErrDenied}
  if state.ReleasePhase=="" {
   if _,err=e.journal.RequestRelease(state.Sequence);err!=nil{return err}
  }
  if state.ReleasePhase!="qmp-acked" {
   if _,err=e.journal.AcknowledgeQMPRelease(state.Sequence);err!=nil{return err}
  }
  return errR17PendingGuest
 default:return ErrDenied
 }
}
func (e *r17JournalExecutor) ReleaseAll()error{return e.Input("key-a-up")}

// PUBLIC and TEST-ONLY MAC. It cannot authenticate a real VM. This fixture
// catches scope/lease/sequence regressions in the already existing Go APIs.
var r17Key=[]byte("PUBLIC-TEST-ONLY-R17-NOT-A-REAL-GUEST-KEY")
func r17MAC(c heldledger.ReleaseClaim)string{
 h:=hmac.New(sha256.New,r17Key)
 _,_=fmt.Fprintf(h,"%s|%s|%s|%s|%s|%d|%d|%d|%d|%s|%s|%t",
  c.GuestID,c.DeviceID,c.HostEpoch,c.GuestEpoch,c.LeaseEpoch,
  c.Generation,c.ReleaseSequence,c.DownEventSequence,c.EventSequence,
  c.Source,c.Key,c.KeyReleased)
 return hex.EncodeToString(h.Sum(nil))
}
func r17Claim(l Lease,sequence,down,up uint64)heldledger.ReleaseClaim{
 c:=heldledger.ReleaseClaim{
  GuestID:"qemu-test-guest",DeviceID:l.Device,
  HostEpoch:"host-R17-test",GuestEpoch:"guest-R17-test",
  LeaseEpoch:l.Epoch,Generation:l.Generation,ReleaseSequence:sequence,
  DownEventSequence:down,EventSequence:up,Source:"guest.evdev",
  Key:heldledger.KeyA,KeyReleased:true,
 }
 c.Proof=r17MAC(c)
 return c
}
func r17Verifier(expected Lease)heldledger.ReleaseVerifier{
 return func(c heldledger.ReleaseClaim)bool{
  if c.GuestID!="qemu-test-guest"||c.DeviceID!=expected.Device||
   c.HostEpoch!="host-R17-test"||c.GuestEpoch!="guest-R17-test"||
   c.LeaseEpoch!=expected.Epoch||c.Generation!=expected.Generation||
   c.Source!="guest.evdev"||c.Key!=heldledger.KeyA||!c.KeyReleased{
   return false
  }
  got,err:=hex.DecodeString(c.Proof);if err!=nil{return false}
  want,err:=hex.DecodeString(r17MAC(c));return err==nil&&hmac.Equal(got,want)
 }
}
func r17AssertHeldUnchanged(t *testing.T,s heldledger.Store,original []byte){
 t.Helper()
 got,err:=os.ReadFile(s.Path)
 if err!=nil||!bytes.Equal(original,got){t.Fatalf("R17_HELD_JOURNAL_CHANGED_ON_DENIED_HANDOFF: %v",err)}
 state,err:=s.Read()
 if err!=nil||!state.Held||state.ReleasePhase!="qmp-acked"{
  t.Fatalf("R17_HELD_JOURNAL_NOT_QUARANTINED %+v err=%v",state,err)
 }
}
func r17RequireQuarantine(t *testing.T,m *Manager){
 t.Helper()
 if state,_,_:=m.Snapshot();state!=Quarantined{t.Fatalf("R17_LEASE_GATE_NOT_QUARANTINED=%s",state)}
 if _,err:=m.Reserve("consumer-B","keyboard","xhci0/auto");!errors.Is(err,ErrQuarantined){
  t.Fatalf("R17_NEW_CONSUMER_ADMITTED_WITHOUT_GUEST_PROOF=%v",err)
 }
}

// This is a deterministic composition test of the sole existing Go broker's
// Manager+Store, not an end-to-end running USBIP / hardware attestation test.
func TestR17USBIPTransportDetachCannotAdmitSecondLease(t *testing.T){
 ledger:=heldledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
 m:=New("keyboard","xhci0/auto",&r17JournalExecutor{journal:ledger})
 a,err:=m.Reserve("consumer-A","keyboard","xhci0/auto")
 if err!=nil{t.Fatal(err)}
 if err:=m.Attach(a);err!=nil{t.Fatal(err)}
 if err:=m.Input(a,"key-a-down");err!=nil{t.Fatal(err)}
 if _,err:=m.Reserve("consumer-B","keyboard","xhci0/auto");!errors.Is(err,ErrUnavailable){
  t.Fatalf("R17_CONCURRENT_B_ADMITTED_WHILE_A_ATTACHED=%v",err)
 }
 if err:=m.Revoke(a);!errors.Is(err,errR17PendingGuest){
  t.Fatalf("R17_ACK_PENDING_GUEST_EXPECTED=%v",err)
 }
 state,err:=ledger.Read()
 if err!=nil||!state.Held||state.ReleasePhase!="qmp-acked"||state.Sequence!=1{
  t.Fatalf("R17_QMP_ACK_MUST_KEEP_JOURNAL_HELD %+v %v",state,err)
 }
 original,err:=os.ReadFile(ledger.Path);if err!=nil{t.Fatal(err)}
 r17RequireQuarantine(t,m)
 t.Log("R17_QMP_ACK_AND_USBIP_DETACH_DO_NOT_ADMIT_B=PASS")

 // A device may have disappeared, port may be empty, and a TCP A_DETACHED
 // signal may arrive. None represents an independently authenticated UP.
 transports:=[]string{"usbip.detach","usbip.port","kernel.device_removed","tcp.A_DETACHED"}
 for _,source:=range transports{
  c:=r17Claim(a,state.Sequence,10,11)
  c.Source=source
  c.Proof=r17MAC(c) // even a syntactically valid test-MAC is not evdev
  if err:=m.RestoreAfterVerifiedGuestUp(ledger,state.Sequence,c,r17Verifier(a));!errors.Is(err,heldledger.ErrUnverified){
   t.Fatalf("R17_UNTRUSTED_TRANSPORT_EVENT_ADMITTED source=%s err=%v",source,err)
  }
  r17AssertHeldUnchanged(t,ledger,original)
  r17RequireQuarantine(t,m)
 }
 t.Log("R17_TRANSPORT_ONLY_RELEASE_REJECTED=PASS")

 // Wrong guest scope/generation is NOT fixed by a valid public test MAC.
 wrong:=r17Claim(a,state.Sequence,10,11)
 wrong.GuestEpoch="foreign-guest"
 wrong.Proof=r17MAC(wrong)
 if err:=m.RestoreAfterVerifiedGuestUp(ledger,state.Sequence,wrong,r17Verifier(a));!errors.Is(err,heldledger.ErrUnverified){
  t.Fatalf("R17_WRONG_GUEST_RELEASE_ADMITTED=%v",err)
 }
 wrong=r17Claim(a,state.Sequence,10,11)
 wrong.Generation++
 wrong.Proof=r17MAC(wrong)
 if err:=m.RestoreAfterVerifiedGuestUp(ledger,state.Sequence,wrong,r17Verifier(a));!errors.Is(err,heldledger.ErrUnverified){
  t.Fatalf("R17_WRONG_GENERATION_RELEASE_ADMITTED=%v",err)
 }
 r17AssertHeldUnchanged(t,ledger,original)
 r17RequireQuarantine(t,m)
 t.Log("R17_WRONG_EPOCH_AND_GENERATION_DENIED=PASS")

 good:=r17Claim(a,state.Sequence,10,11)
 if err:=m.RestoreAfterVerifiedGuestUp(ledger,state.Sequence,good,r17Verifier(a));err!=nil{
  t.Fatalf("R17_SCOPED_GUEST_UP_DENIED=%v",err)
 }
 clean,err:=ledger.Read()
 if err!=nil||clean.Held||clean.Sequence!=2||clean.LastReleaseEventSequence!=11{
  t.Fatalf("R17_VERIFIED_UP_NOT_FSYNCED %+v %v",clean,err)
 }
 b,err:=m.Reserve("consumer-B","keyboard","xhci0/auto")
 if err!=nil||b.Generation<=a.Generation||b.Epoch!=a.Epoch{
  t.Fatalf("R17_B_FRESH_LEASE_NOT_ADMITTED after guest proof: %+v %v",b,err)
 }
 if err:=m.Input(a,"key-a-down");!errors.Is(err,ErrDenied){
  t.Fatalf("R17_STALE_A_INPUT_ACCEPTED_AFTER_B=%v",err)
 }
 if err:=m.Attach(b);err!=nil{t.Fatal(err)}
 if err:=m.Input(b,"key-a-down");err!=nil{t.Fatal(err)}
 if err:=m.Revoke(b);!errors.Is(err,errR17PendingGuest){t.Fatal(err)}
 bHeld,err:=ledger.Read()
 if err!=nil||bHeld.Sequence!=3||!bHeld.Held||bHeld.ReleasePhase!="qmp-acked"{t.Fatalf("R17_B_NOT_DURABLY_HELD %+v %v",bHeld,err)}
 r17RequireQuarantine(t,m)
 if err:=m.RestoreAfterVerifiedGuestUp(ledger,bHeld.Sequence,good,r17Verifier(a));!errors.Is(err,heldledger.ErrUnverified){
  t.Fatalf("R17_REPLAYED_A_RELEASE_ADMITTED_FOR_B=%v",err)
 }
 later:=r17Claim(b,bHeld.Sequence,12,13)
 if err:=m.RestoreAfterVerifiedGuestUp(ledger,bHeld.Sequence,later,r17Verifier(b));err!=nil{t.Fatalf("R17_B_FRESH_RELEASE_DENIED=%v",err)}
 final,err:=ledger.Read()
 if err!=nil||final.Held||final.LastReleaseEventSequence!=13||final.Sequence!=4{t.Fatalf("R17_B_RELEASE_STATE %+v %v",final,err)}
 if state,_,_:=m.Snapshot();state!=Available{t.Fatalf("R17_MANAGER_NOT_AVAILABLE_AFTER_TWO_PROVED_RELEASES=%s",state)}
 t.Log("R17_EXISTING_BROKER_TWO_PROVEN_LEASE_READMISSIONS=PASS")
}
