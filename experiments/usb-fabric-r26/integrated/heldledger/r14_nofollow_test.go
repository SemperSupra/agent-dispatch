package heldledger

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "runtime"
 "sync"
 "testing"
)

// The R13 Lstat/Open pair is not an atomic no-follow open. This deterministic
// critic requires the Linux syscall-level no-follow flag on the actual source;
// runtime negatives below separately verify symlink rejection and data safety.
func TestR14LinuxJournalOpenUsesAtomicNoFollow(t *testing.T) {
 if runtime.GOOS!="linux"{t.Skip("Linux-only kernel path")}
 source,err:=os.ReadFile("ledger_open_linux.go")
 if errors.Is(err,os.ErrNotExist){t.Fatal("R14_RED_NO_ATOMIC_NOFOLLOW_HELPER")}
 if err!=nil{t.Fatal(err)}
 if !bytes.Contains(source,[]byte("syscall.O_NOFOLLOW")){
  t.Fatal("R14_RED_NO_ATOMIC_NOFOLLOW_FLAG")
 }
 t.Log("R14_LINUX_ATOMIC_NOFOLLOW_SOURCE_GATE=PASS")
}

func TestR14ConcurrentJournalSymlinkReplacementNeverAdmitsTarget(t *testing.T) {
 if runtime.GOOS!="linux"{t.Skip("Linux-only")}
 dir:=t.TempDir()
 clean:=filepath.Join(dir,"target-clean.json")
 original:=[]byte("{\"version\":1,\"sequence\":9,\"held\":false}\n")
 if err:=os.WriteFile(clean,original,0600);err!=nil{t.Fatal(err)}
 link:=filepath.Join(dir,"swap.json")
 regular:=filepath.Join(dir,"regular.json")
 safe:=[]byte("{\"version\":1,\"sequence\":7,\"held\":true,\"key\":\"key-a\"}\n")
 if err:=os.WriteFile(regular,safe,0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(link,safe,0600);err!=nil{t.Fatal(err)}
 tmp:=filepath.Join(dir,"link-next")
 if err:=os.Symlink(clean,tmp);err!=nil{t.Fatal(err)}
 // Swapper repeatedly atomically replaces the visible journal with a
 // symlink or a regular file; only the latter may ever be accepted.
 var wg sync.WaitGroup
 wg.Add(1)
 go func(){
  defer wg.Done()
  for i:=0;i<350;i++{
   if i%2==0{
    _=os.Rename(tmp,link)
    _=os.Symlink(clean,tmp)
   }else{
    _=os.Rename(regular,link)
    _=os.WriteFile(regular,safe,0600)
   }
  }
 }()
 s:=Store{Path:link}
 for i:=0;i<700;i++{
  state,err:=s.Read()
  if err==nil && (!state.Held||state.Sequence!=7){
   t.Fatalf("R14_RED_PATH_SWAP_ADMITTED_WRONG_JOURNAL: %+v",state)
  }
  if err!=nil && !errors.Is(err,ErrInvalid) && !errors.Is(err,os.ErrNotExist){
   t.Fatalf("R14_UNEXPECTED_OPEN_ERROR: %v",err)
  }
 }
 wg.Wait()
 got,err:=os.ReadFile(clean)
 if err!=nil||!bytes.Equal(got,original){t.Fatalf("R14_TARGET_CHANGED: %v",err)}
 t.Log("R14_CONCURRENT_JOURNAL_SYMLINK_SWAP_REJECTED=PASS")
 t.Log("R14_JOURNAL_TARGET_BYTES_UNCHANGED=PASS")
}
