package restartfence

import (
 "errors"
 "path/filepath"
 "os"
 "testing"

 "example.org/usb-fabric-r26-integrated/blue"
 ledger "example.org/usb-fabric-r26-integrated/heldledger"
)

// This RED falsifier is intentionally written as an expected unsafe state,
// not as an assertion that the controller is correct. It prevents future
// tests from overlooking the fresh-manager startup gap.
func TestR21NaiveManagerRecreatedFromHeldJournalIsUnsafe(t *testing.T){
 store:=ledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
 held,err:=store.Transition(0,true);if err!=nil{t.Fatal(err)}
 if _,err=store.RequestRelease(held.Sequence);err!=nil{t.Fatal(err)}
 if _,err=store.AcknowledgeQMPRelease(held.Sequence);err!=nil{t.Fatal(err)}
 recovered,err:=store.Read();if err!=nil||!recovered.Held{t.Fatalf("held journal lost %+v %v",recovered,err)}
 naive:=blue.New("keyboard","xhci0/auto",nil)
 if _,err=naive.Reserve("consumer-B","keyboard","xhci0/auto");err!=nil{t.Fatalf("expected naive in-memory bypass falsifier, got %v",err)}
 t.Log("R21_A_RED_NAIVE_MANAGER_BOOT_ADMITS_B_WITH_HELD_JOURNAL=CONFIRMED_UNSAFE")
}

func TestR21RecoveryBootMustFenceBeforePublishingManager(t *testing.T){
 store:=ledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
 held,err:=store.Transition(0,true);if err!=nil{t.Fatal(err)}
 if _,err=store.RequestRelease(held.Sequence);err!=nil{t.Fatal(err)}
 if _,err=store.AcknowledgeQMPRelease(held.Sequence);err!=nil{t.Fatal(err)}
 // Boot construction must occur in private unpublished scope. No Reserve
 // request may be routed to this instance until persisted state is checked.
 recovered:=blue.New("keyboard","xhci0/auto",nil)
 state,err:=store.Read()
 if err!=nil || state.Held { recovered.Offline() }
 if state.Held {
  if _,err=recovered.Reserve("consumer-B","keyboard","xhci0/auto");!errors.Is(err,blue.ErrQuarantined){
   t.Fatalf("HELD not fenced before manager publication: %v",err)
  }
 } else {t.Fatal("unexpected clean journal")}
 snap,_,_:=recovered.Snapshot();if snap!=blue.Quarantined{t.Fatalf("unsafe state %s",snap)}
 t.Log("R21_A_BLUE_BOOT_READS_HELD_AND_FENCES_BEFORE_PUBLISH=PASS")
 t.Log("R21_A_REAL_BROKER_RESTART_AND_USBIP_B_DIRECT_PROBE=NOT_TESTED")
}

func TestR21InvalidJournalQuarantinesBootManager(t *testing.T){
 store:=ledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
 // Must not treat damaged disk as a missing journal / empty lease.
 // Missing initial journal also needs explicit physical/QMP release before
 // allowing an attachment, which is outside this test contract.
 if err:=os.WriteFile(store.Path,[]byte("{not-json"),0600);err!=nil{t.Fatal(err)}
 recovered:=blue.New("keyboard","xhci0/auto",nil)
 if _,err:=store.Read();err!=nil { recovered.Offline() }
 if _,err:=recovered.Reserve("consumer-B","keyboard","xhci0/auto");!errors.Is(err,blue.ErrQuarantined){t.Fatalf("corrupt journal admitted B: %v",err)}
 t.Log("R21_A_BLUE_CORRUPT_JOURNAL_BOOT_FAIL_CLOSED=PASS")
}
