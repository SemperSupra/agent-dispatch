package heldledger

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

func TestR13SymlinkJournalCannotImpersonateCleanState(t *testing.T) {
 dir:=t.TempDir()
 clean:=filepath.Join(dir,"clean.json")
 cleanBytes:=[]byte("{\"version\":1,\"sequence\":2,\"held\":false}\n")
 if err:=os.WriteFile(clean,cleanBytes,0600);err!=nil{t.Fatal(err)}
 held:=filepath.Join(dir,"held.json")
 heldBytes:=[]byte("{\"version\":1,\"sequence\":1,\"held\":true,\"key\":\"key-a\"}\n")
 if err:=os.WriteFile(held,heldBytes,0600);err!=nil{t.Fatal(err)}
 for _,tt:=range []struct{name,target string}{
  {"symlink-clean",clean},{"symlink-held",held},{"symlink-dangling",filepath.Join(dir,"absent")},
 } {
  t.Run(tt.name,func(t *testing.T){
   link:=filepath.Join(dir,tt.name+".json")
   if err:=os.Symlink(tt.target,link);err!=nil{t.Fatal(err)}
   s:=Store{Path:link}
   if st,err:=s.Read();!errors.Is(err,ErrInvalid){
    t.Fatalf("R13_RED_SYMLINK_JOURNAL_ADMITTED: state=%+v err=%v",st,err)
   }
   if st,err:=s.Transition(2,true);!errors.Is(err,ErrInvalid){
    t.Fatalf("R13_RED_SYMLINK_ALLOWED_LEASE: state=%+v err=%v",st,err)
   }
   if b,err:=os.ReadFile(clean);err!=nil||!bytes.Equal(b,cleanBytes){t.Fatalf("clean target mutated: %v",err)}
   if b,err:=os.ReadFile(held);err!=nil||!bytes.Equal(b,heldBytes){t.Fatalf("held target mutated: %v",err)}
  })
 }
 s:=Store{Path:clean}
 if st,err:=s.Read();err!=nil||st.Held||st.Sequence!=2{t.Fatalf("regular clean journal rejected: %+v %v",st,err)}
 t.Log("R13_SYMLINKED_DURABLE_JOURNAL_REJECTED=PASS")
 t.Log("R13_REGULAR_JOURNAL_STILL_READABLE=PASS")
}
