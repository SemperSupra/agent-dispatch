//go:build linux

package blue

import (
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "example.org/usb-fabric-r26-integrated/heldledger"
)

func r27QCleanJournal(t *testing.T) heldledger.Store{
 t.Helper()
 // CI Go test runners may create their parent test dirs with wider
 // permissions. Model the required private host-owned journal root explicitly.
 dir:=t.TempDir()
 if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 path:=filepath.Join(dir,"held.json")
 if err:=os.WriteFile(path,[]byte("{\"version\":1,\"sequence\":2,\"held\":false}\n"),0600);err!=nil{t.Fatal(err)}
 return heldledger.Store{Path:path}
}

func TestR27QExclusiveOriginalGoManagerRecoveredCleanPort(t *testing.T){
 store:=r27QCleanJournal(t)
 m,owner,err:=NewAfterExclusiveJournalRecovery("keyboard","vhci_hcd/port0",nil,store)
 if err!=nil{t.Fatalf("first owner refused: %v",err)}
 _,duplicate,err:=NewAfterExclusiveJournalRecovery("keyboard","vhci_hcd/port0",nil,store)
 if duplicate!=nil{_=duplicate.Close();t.Fatal("duplicate acquired owner")}
 if !errors.Is(err,ErrQuarantined){t.Fatalf("second manager was not rejected: %v",err)}
 t.Log("R27_Q_SAME_PORT_SECOND_OWNER_DENIED=PASS")
 lease,err:=m.Reserve("consumer-A","keyboard","vhci_hcd/port0")
 if err!=nil{t.Fatal(err)}
 if err:=owner.Close();!errors.Is(err,ErrDenied){t.Fatalf("active lease owner could exit voluntarily: %v",err)}
 t.Log("R27_Q_ACTIVE_LEASE_OWNER_CANNOT_CLOSE=PASS")
 if err:=m.Revoke(lease);err!=nil{t.Fatal(err)}
 if err:=owner.Close();err!=nil{t.Fatal(err)}
 _,owner2,err:=NewAfterExclusiveJournalRecovery("keyboard","vhci_hcd/port0",nil,store)
 if err!=nil{t.Fatalf("clean released owner cannot restart: %v",err)}
 if err:=owner2.Close();err!=nil{t.Fatal(err)}
 t.Log("R27_Q_CLEAN_OS_OWNER_RELEASE_AND_NEW_EPOCH=PASS")
}

func TestR27QTwoPIDOwner(t *testing.T){
 if os.Getenv("R27Q_CHILD")=="1"{
  store:=heldledger.Store{Path:os.Getenv("R27Q_JOURNAL")}
  _,o,err:=NewAfterExclusiveJournalRecovery("keyboard","vhci_hcd/port0",nil,store)
  if o!=nil{_=o.Close();t.Fatal("second Linux PID acquired owner")}
  if !errors.Is(err,ErrQuarantined){t.Fatalf("second Linux PID not fenced: %v",err)}
  t.Log("R27_Q_INDEPENDENT_SECOND_LINUX_PID_DENIED=PASS")
  return
 }
 store:=r27QCleanJournal(t)
 _,owner,err:=NewAfterExclusiveJournalRecovery("keyboard","vhci_hcd/port0",nil,store)
 if err!=nil{t.Fatal(err)}
 defer owner.Close()
 cmd:=exec.Command(os.Args[0],"-test.v","-test.run=^TestR27QTwoPIDOwner$")
 cmd.Env=append(os.Environ(),"R27Q_CHILD=1","R27Q_JOURNAL="+store.Path)
 output,err:=cmd.CombinedOutput()
 if err!=nil{t.Fatalf("isolated second PID failed unexpectedly: %v output=%s",err,output)}
 if !strings.Contains(string(output),"R27_Q_INDEPENDENT_SECOND_LINUX_PID_DENIED=PASS"){
  t.Fatalf("child never demonstrated real Linux owner deny: %s",output)
 }
 t.Log("R27_Q_TRUE_TWO_PID_SAME_USBIP_PORT_FENCED=PASS")
}

func TestR27QRejectHeldAndUntrustedJournal(t *testing.T){
 dir:=t.TempDir()
 if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 cases:=[]string{"missing","held","symlink"}
 for _,mode:=range cases{
  t.Run(mode,func(t *testing.T){
   path:=filepath.Join(dir,mode+".json")
   switch mode{
   case "held":
    store:=heldledger.Store{Path:path}
    if _,err:=store.Transition(0,true);err!=nil{t.Fatal(err)}
   case "symlink":
    if err:=os.Symlink(filepath.Join(dir,"missing-target"),path);err!=nil{t.Fatal(err)}
   }
   _,owner,err:=NewAfterExclusiveJournalRecovery("keyboard","vhci_hcd/port0",nil,heldledger.Store{Path:path})
   if owner!=nil{_=owner.Close();t.Fatalf("untrusted %s journal minted owner",mode)}
   if !errors.Is(err,ErrQuarantined){t.Fatalf("untrusted %s journal permitted: %v",mode,err)}
  })
 }
 t.Log("R27_Q_MISSING_HELD_SYMLINK_DURABLE_JOURNAL_DENIED=PASS")
}

func TestR27QRejectUnprotectedJournalRoot(t *testing.T){
 dir:=t.TempDir()
 path:=filepath.Join(dir,"held.json")
 if err:=os.WriteFile(path,[]byte("{\"version\":1,\"sequence\":2,\"held\":false}\n"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Chmod(dir,0755);err!=nil{t.Fatal(err)}
 _,owner,err:=NewAfterExclusiveJournalRecovery("keyboard","vhci_hcd/port0",nil,heldledger.Store{Path:path})
 if owner!=nil{_=owner.Close();t.Fatal("weak journal parent minted owner")}
 if !errors.Is(err,ErrQuarantined){t.Fatalf("world-readable journal root not rejected: %v",err)}
 t.Log("R27_Q_UNPROTECTED_HOST_JOURNAL_DIRECTORY_DENIED=PASS")
}
