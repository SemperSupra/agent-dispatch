package heldledger

import (
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

func TestWriteAheadHeldSurvivesReopen(t *testing.T){
 path:=filepath.Join(t.TempDir(),"held.json")
 first:=Store{Path:path}
 st,e:=first.Read();if e!=nil||st.Version!=1||st.Held{t.Fatalf("bad initial %+v %v",st,e)}
 st,e=first.Transition(0,true);if e!=nil||st.Sequence!=1{t.Fatalf("mark held %v",e)}
 // Simulated process reconstruction; state must survive independent Store.
 second:=Store{Path:path}
 st,e=second.Read();if e!=nil||!st.Held||st.Key!=KeyA{t.Fatalf("lost write ahead journal %+v %v",st,e)}
 if _,e=second.Transition(0,false);!errors.Is(e,ErrUnverified){t.Fatalf("legacy ACK-only release allowed: %v",e)}
 if _,e=second.RequestRelease(1);e!=nil{t.Fatal(e)}
 if _,e=second.AcknowledgeQMPRelease(1);e!=nil{t.Fatal(e)}
 st,e=second.ConfirmGuestRelease(1,claim(1,10,11),signed);if e!=nil||st.Held||st.Sequence!=2{t.Fatalf("guest-confirmed release %v %+v",e,st)}
 if st.Key!="" {t.Fatal("raw key retained on release")}
 info,e:=os.Stat(path);if e!=nil{t.Fatal(e)}
 if info.Mode().Perm()!=0600{t.Fatalf("ledger mode too broad %v",info.Mode())}
 if _,e=second.Transition(2,false);!errors.Is(e,ErrUnverified){t.Fatal("legacy double release allowed")}
}
func TestMalformedAndUnknownStateNeverResets(t *testing.T){
 dir:=t.TempDir();path:=filepath.Join(dir,"held.json");s:=Store{Path:path}
 bad:=[]string{
  "{", `{"version":2,"sequence":1,"held":true,"key":"key-a"}`,
  `{"version":1,"sequence":1,"held":true,"key":"other"}`,
  `{"version":1,"sequence":1,"held":false,"key":"key-a"}`,
  `{"version":1,"sequence":1,"held":false,"extra":true}`,
  `{"version":1,"sequence":1,"held":false}{"x":1}`,
 }
 for _,c:=range bad{
  if e:=os.WriteFile(path,[]byte(c),0600);e!=nil{t.Fatal(e)}
  if _,e:=s.Read();!errors.Is(e,ErrInvalid){t.Fatalf("bad record accepted: %s => %v",c,e)}
  if _,e:=s.ConfirmGuestRelease(1,claim(1,10,11),signed);!errors.Is(e,ErrInvalid){t.Fatalf("bad record modified %v",e)}
 }
}
func TestMonotonicHeldTransitions(t *testing.T){
 s:=Store{Path:filepath.Join(t.TempDir(),"ledger")}
 st,e:=s.Transition(0,true);if e!=nil{t.Fatal(e)}
 if _,e=s.Transition(st.Sequence,true);!errors.Is(e,ErrConflict){t.Fatal("double down accepted")}
 if _,e=s.RequestRelease(st.Sequence);e!=nil{t.Fatal(e)}
 if _,e=s.AcknowledgeQMPRelease(st.Sequence);e!=nil{t.Fatal(e)}
 st,e=s.ConfirmGuestRelease(st.Sequence,claim(1,10,11),signed);if e!=nil{t.Fatal(e)}
 st,e=s.Transition(st.Sequence,true);if e!=nil{t.Fatal(e)}
 if st.Sequence!=3 || !st.Held {t.Fatal("incorrect monotonic rehold")}
 data,e:=os.ReadFile(s.Path);if e!=nil{t.Fatal(e)}
 var wire map[string]any;if e=json.Unmarshal(data,&wire);e!=nil{t.Fatal(e)}
 if _,ok:=wire["raw_report"];ok{t.Fatal("payload leaked")}
}
func TestNoJournalPathFailsClosed(t *testing.T){
 if _,e:=(Store{}).Read();!errors.Is(e,ErrInvalid){t.Fatal("empty path accepted")}
 if _,e:=(Store{}).Transition(0,true);!errors.Is(e,ErrInvalid){t.Fatal("write to empty path accepted")}
}
