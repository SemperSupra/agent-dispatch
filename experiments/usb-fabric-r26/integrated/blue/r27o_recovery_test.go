package blue

import (
 "errors"
 "os"
 "path/filepath"
 "testing"
 "example.org/usb-fabric-r26-integrated/heldledger"
)

func r27ORequireBlocked(t *testing.T,path string){
 t.Helper()
 m,err:=NewAfterJournalRecovery("keyboard","xhci0/auto",nil,heldledger.Store{Path:path})
 if !errors.Is(err,ErrQuarantined){t.Fatalf("startup did not quarantine: %v",err)}
 if _,err=m.Reserve("consumer-B","keyboard","xhci0/auto");!errors.Is(err,ErrQuarantined){
  t.Fatalf("restarted manager admitted B: %v",err)
 }
}

func TestR27ORecoveredStartupDenyUnsafeJournal(t *testing.T){
 dir:=t.TempDir()
 missing:=filepath.Join(dir,"absent.json")
 r27ORequireBlocked(t,missing)
 t.Log("R27_O_ABSENT_JOURNAL_MUST_NOT_BOOTSTRAP_UNFENCED=PASS")
 held:=filepath.Join(dir,"held.json")
 store:=heldledger.Store{Path:held}
 if _,err:=store.Transition(0,true);err!=nil{t.Fatal(err)}
 r27ORequireBlocked(t,held)
 t.Log("R27_O_RESTART_DURABLE_HELD_DENIES_B=PASS")
 if _,err:=store.RequestRelease(1);err!=nil{t.Fatal(err)}
 r27ORequireBlocked(t,held)
 t.Log("R27_O_RELEASE_INTENT_DENIES_B=PASS")
 corrupt:=filepath.Join(dir,"corrupt.json")
 if err:=os.WriteFile(corrupt,[]byte("{\"version\":1,\"sequence\":2,\"held\":false,\"held\":true}\n"),0600);err!=nil{t.Fatal(err)}
 r27ORequireBlocked(t,corrupt)
 t.Log("R27_O_CORRUPT_DUPLICATE_KEYS_DENIED=PASS")
 symlink:=filepath.Join(dir,"link.json")
 if err:=os.Symlink(held,symlink);err!=nil{t.Fatal(err)}
 r27ORequireBlocked(t,symlink)
 r27ORequireBlocked(t,dir)
 t.Log("R27_O_SYMLINK_NONREGULAR_JOURNAL_DENIED=PASS")
}

func TestR27ORecoveredStartupOnlyValidClearedJournal(t *testing.T){
 dir:=t.TempDir()
 path:=filepath.Join(dir,"clean.json")
 // Offline fixture only: in production this clean state must be minted by
 // actual paired host kernel isolation + verified guest UP through original
 // heldledger. A raw JSON file is not an independent trust witness.
 data:=[]byte("{\"version\":1,\"sequence\":2,\"held\":false,\"last_release_event_sequence\":11,\"last_release_proof_hash\":\"")
 for i:=0;i<64;i++{data=append(data,'a')}
 data=append(data,[]byte("\"}\n")...)
 if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
 m,err:=NewAfterJournalRecovery("keyboard","xhci0/auto",nil,heldledger.Store{Path:path})
 if err!=nil{t.Fatalf("clean journal refused: %v",err)}
 a,err:=m.Reserve("consumer-B","keyboard","xhci0/auto")
 if err!=nil || a.Generation==0 || a.Epoch==""{t.Fatalf("fresh clean lease refused %+v %v",a,err)}
 t.Log("R27_O_VALID_PERSISTED_CLEAN_STARTUP_AVAILABLE=PASS")
}
