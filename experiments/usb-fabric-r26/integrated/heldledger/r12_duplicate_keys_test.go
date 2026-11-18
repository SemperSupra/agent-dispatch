package heldledger

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

// Ambiguous duplicate keys can turn a persisted HELD journal into apparent
// clean state under encoding/json's default last-key-wins behavior.
// These are on-disk integrity negatives, NOT simulated QMP/kernel receipts.
func TestR12DuplicateJournalKeysFailClosed(t *testing.T) {
 fixtures:=[]struct{name,json string}{
  {"held-and-key-overridden",`{"version":1,"sequence":1,"held":true,"key":"key-a","held":false,"key":""}`},
  {"same-held-repeated",`{"version":1,"sequence":1,"held":true,"key":"key-a","held":true}`},
  {"case-alias-overrides-held",`{"version":1,"sequence":1,"held":true,"key":"key-a","Held":false,"Key":""}`},
  {"sequence-overridden",`{"version":1,"sequence":1,"held":true,"key":"key-a","sequence":2}`},
  {"version-repeated",`{"version":1,"sequence":1,"held":true,"key":"key-a","version":1}`},
  {"release-phase-overridden",`{"version":1,"sequence":1,"held":true,"key":"key-a","release_phase":"release-intent","release_phase":"qmp-acked"}`},
 }
 for _,tt:=range fixtures {t.Run(tt.name,func(t *testing.T){
  s:=Store{Path:filepath.Join(t.TempDir(),"held.json")}
  original:=[]byte(tt.json+"\n")
  if err:=os.WriteFile(s.Path,original,0600);err!=nil{t.Fatal(err)}
  if got,err:=s.Read();!errors.Is(err,ErrInvalid){
   t.Fatalf("R12_RED_DUPLICATE_JOURNAL_ADMITTED: state=%+v err=%v",got,err)
  }
  // Even a previously held journal must never become lease-eligible
  // because a duplicate key makes it look clean.
  if next,err:=s.Transition(1,true);!errors.Is(err,ErrInvalid){
   t.Fatalf("R12_RED_DUPLICATE_JOURNAL_ALLOWED_LEASE: state=%+v err=%v",next,err)
  }
  persisted,err:=os.ReadFile(s.Path)
  if err!=nil||!bytes.Equal(original,persisted){
   t.Fatalf("R12_RED_INVALID_JOURNAL_WAS_REWRITTEN err=%v",err)
  }
 })}
 s:=Store{Path:filepath.Join(t.TempDir(),"valid.json")}
 if _,err:=s.Transition(0,true);err!=nil{t.Fatal("valid write failed:",err)}
 if state,err:=s.Read();err!=nil||!state.Held||state.Sequence!=1{
  t.Fatalf("valid unambiguous journal rejected: %+v %v",state,err)
 }
 t.Log("R12_DUPLICATE_JSON_JOURNAL_FAIL_CLOSED=PASS")
 t.Log("R12_VALID_DURABLE_JOURNAL_STILL_ACCEPTED=PASS")
}
