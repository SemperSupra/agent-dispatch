package blue

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "sync"
 "testing"
 "time"

 "example.org/usb-fabric-r26-integrated/heldledger"
)

// R18 critic uses the EXACT existing broker mutex and durable Store.
// The only synthetic component is the explicitly TEST-ONLY QMP actuator and
// public signer imported from r17_broker_ledger_handoff_test.go.
func TestR18ConcurrentReAdmissionWaitsForDurableGuestRelease(t *testing.T) {
 journal:=heldledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
 m:=New("keyboard","xhci0/auto",&r17JournalExecutor{journal:journal})
 a,err:=m.Reserve("A","keyboard","xhci0/auto")
 if err!=nil{t.Fatal(err)}
 if err=m.Attach(a);err!=nil{t.Fatal(err)}
 if err=m.Input(a,"key-a-down");err!=nil{t.Fatal(err)}
 if err=m.Revoke(a);!errors.Is(err,errR17PendingGuest){t.Fatalf("R18_REVOKE_NOT_QUARANTINED=%v",err)}
 state,err:=journal.Read()
 if err!=nil||!state.Held||state.Sequence!=1||state.ReleasePhase!="qmp-acked"{
  t.Fatalf("R18_TEST_ONLY_RELEASE_NOT_DURABLE %+v %v",state,err)
 }
 raw,err:=os.ReadFile(journal.Path);if err!=nil{t.Fatal(err)}
 transport:=r17Claim(a,1,10,11)
 transport.Source="usbip.detach";transport.Proof=r17MAC(transport)
 if err=m.RestoreAfterVerifiedGuestUp(journal,1,transport,r17Verifier(a));!errors.Is(err,heldledger.ErrUnverified){
  t.Fatalf("R18_UNTRUSTED_TRANSPORT_DETACH_GRANTED_RELEASE=%v",err)
 }
 changed,err:=os.ReadFile(journal.Path)
 if err!=nil||!bytes.Equal(raw,changed){t.Fatalf("R18_HELD_JOURNAL_MUTATED_BY_TRANSPORT=%v",err)}
 r17RequireQuarantine(t,m)
 t.Log("R18_TRANSPORT_ONLY_QUARANTINE_AND_DURABLE_BYTES=PASS")

 // Block the ACTUAL existing Manager.RestoreAfterVerifiedGuestUp *inside*
 // independent proof verification, while holding its sole-owner mutex.
 // Racing reserve attempts may block or be denied, but never succeed early.
 entered:=make(chan struct{})
 release:=make(chan struct{})
 verify:=func(c heldledger.ReleaseClaim)bool{
  close(entered)
  <-release
  return r17Verifier(a)(c)
 }
 restoreDone:=make(chan error,1)
 go func(){restoreDone<-m.RestoreAfterVerifiedGuestUp(journal,1,r17Claim(a,1,10,11),verify)}()
 select{
 case <-entered:
 case <-time.After(5*time.Second):t.Fatal("R18_VERIFIER_DID_NOT_ENTER")
 }
 const n=24
 type answer struct{lease Lease;err error}
 answers:=make(chan answer,n)
 var started sync.WaitGroup
 started.Add(n)
 for i:=0;i<n;i++{
  go func(){
   started.Done()
   l,e:=m.Reserve("B","keyboard","xhci0/auto")
   answers<-answer{lease:l,err:e}
  }()
 }
 started.Wait()
 // The verifier has NOT approved the only guest proof; neither storage nor
 // Manager may make a fresh lease visible. Any completion is scrutinized.
 select{
 case r:=<-answers:
  if r.err==nil{t.Fatalf("R18_EARLY_B_LEASE_WHILE_PROOF_BLOCKED=%+v",r.lease)}
 case <-time.After(150*time.Millisecond):
 }
 held,err:=journal.Read()
 if err!=nil||!held.Held||held.Sequence!=1{t.Fatalf("R18_DURABLE_HELD_CLEARED_BEFORE_VERIFIER=%+v %v",held,err)}
 close(release)
 select{
 case err=<-restoreDone:
  if err!=nil{t.Fatalf("R18_REAL_EXISTING_RESTORE_FAILED=%v",err)}
 case <-time.After(8*time.Second):t.Fatal("R18_PROOF_BARRIER_DEADLOCK")
 }
 winners:=0
 var b Lease
 for i:=0;i<n;i++{
  select{
  case r:=<-answers:
   if r.err==nil{winners++;b=r.lease
   }else if !errors.Is(r.err,ErrUnavailable)&&!errors.Is(r.err,ErrQuarantined){
    t.Fatalf("R18_WRONG_LOSER_ERROR=%v",r.err)
   }
  case <-time.After(5*time.Second):t.Fatal("R18_WAITING_FOR_RACERS_TIMED_OUT")
  }
 }
 if winners!=1||b.Generation<=a.Generation||b.Epoch!=a.Epoch{
  t.Fatalf("R18_EXACTLY_ONE_NEW_LEASE_REQUIRED winners=%d lease=%+v prior=%+v",winners,b,a)
 }
 after,err:=journal.Read()
 if err!=nil||after.Held||after.Sequence!=2{t.Fatalf("R18_UNFSYNCED_RELEASE_ADMITTED %+v %v",after,err)}
 t.Log("R18_RACE_EXACTLY_ONE_B_AFTER_PROVEN_FSYNC=PASS")

 if err=m.Input(a,"key-a-down");!errors.Is(err,ErrDenied){t.Fatalf("R18_STALE_A_INPUT_GRANTED=%v",err)}
 if err=m.Revoke(a);!errors.Is(err,ErrDenied){t.Fatalf("R18_STALE_A_REVOKE_GRANTED=%v",err)}
 if err=m.Attach(a);!errors.Is(err,ErrDenied){t.Fatalf("R18_STALE_A_ATTACH_GRANTED=%v",err)}
 if err=m.Attach(b);err!=nil{t.Fatal(err)}
 if err=m.Input(b,"key-a-down");err!=nil{t.Fatal(err)}
 if err=m.Revoke(b);!errors.Is(err,errR17PendingGuest){t.Fatal(err)}
 if err=m.RestoreAfterVerifiedGuestUp(journal,3,r17Claim(a,1,10,11),r17Verifier(a));!errors.Is(err,heldledger.ErrUnverified){
  t.Fatalf("R18_REPLAYED_A_PROOF_CLEARED_B=%v",err)
 }
 r17RequireQuarantine(t,m)
 if err=m.RestoreAfterVerifiedGuestUp(journal,3,r17Claim(b,3,12,13),r17Verifier(b));err!=nil{t.Fatalf("R18_FRESH_B_PROOF_DENIED=%v",err)}
 final,err:=journal.Read()
 if err!=nil||final.Held||final.Sequence!=4||final.LastReleaseEventSequence!=13{t.Fatalf("R18_FINAL_LEASE_JOURNAL %+v %v",final,err)}
 t.Log("R18_STALE_ACTOR_AND_REPLAY_DENIED_DURING_SECOND_HELD=PASS")
}
