//go:build linux

package blue

import (
 "bufio"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "syscall"
 "testing"
 "time"
 "example.org/usb-fabric-r26-integrated/heldledger"
)

func TestR27SActualSIGKILLAfterAttachMustNotAdmitFreshB(t *testing.T) {
 const port="vhci_hcd/port0"
 if os.Getenv("R27S_CHILD")=="1" {
  st:=heldledger.Store{Path:os.Getenv("R27S_JOURNAL")}
  m,owner,err:=NewAfterExclusiveDurableAdmission("keyboard",port,nil,st)
  if err!=nil{t.Fatalf("child cannot acquire owner: %v",err)}
  _=owner // Retain OS lock for lifetime, deliberately killed by parent.
  lease,err:=m.Reserve("consumer-A","keyboard",port)
  if err!=nil{t.Fatalf("child reserve: %v",err)}
  if err=m.Attach(lease);err!=nil{t.Fatalf("child attach: %v",err)}
  fmt.Println("R27_S_CHILD_ATTACHED_AND_LOCK_HELD=PASS")
  time.Sleep(30*time.Second)
  return
 }
 dir:=t.TempDir()
 if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 path:=filepath.Join(dir,"held.json")
 if err:=os.WriteFile(path,[]byte("{\"version\":1,\"sequence\":2,\"held\":false}\n"),0600);err!=nil{t.Fatal(err)}
 // Admission intent is a fsynced original-heldledger field. New startup must
 // reject after actual SIGKILL even though held=false (no key down occurred).
 cmd:=exec.Command(os.Args[0],"-test.v","-test.run=^TestR27SActualSIGKILLAfterAttachMustNotAdmitFreshB$")
 cmd.Env=append(os.Environ(),"R27S_CHILD=1","R27S_JOURNAL="+path)
 stdout,err:=cmd.StdoutPipe()
 if err!=nil{t.Fatal(err)}
 if err=cmd.Start();err!=nil{t.Fatal(err)}
 reader:=bufio.NewReader(stdout)
 ready:=make(chan error,1)
 go func(){
  for {
   line,e:=reader.ReadString('\n')
   if strings.Contains(line,"R27_S_CHILD_ATTACHED_AND_LOCK_HELD=PASS"){ready<-nil;return}
   if e!=nil{ready<-fmt.Errorf("child quit before lease attach: %w",e);return}
  }
 }()
 select {
 case e:= <-ready:
  if e!=nil{_ = cmd.Process.Kill();_ = cmd.Wait();t.Fatal(e)}
 case <-time.After(8*time.Second):
  _=cmd.Process.Kill();_=cmd.Wait();t.Fatal("child owner attach startup exceeded bounded deadline")
 }
 if err:=cmd.Process.Signal(syscall.SIGKILL);err!=nil{t.Fatal(err)}
 _=cmd.Wait() // signal exit is expected; OS owner lock must be released.
 // Restarted broker sees same durable journal. It MUST NOT presume that
 // SIGKILL of the host frontend means the previously attached VHCI is safe.
 st:=heldledger.Store{Path:path}
 recovered,owner,err:=NewAfterExclusiveDurableAdmission("keyboard",port,nil,st)
 if err!=nil{
  t.Log("R27_S_SIGKILL_ATTACHED_RESTART_QUARANTINED=PASS")
  return
 }
 if owner!=nil{defer owner.Close()}
 _,err=recovered.Reserve("consumer-B","keyboard",port)
 if err==nil {
  t.Fatal("R27_S_SIGKILL_ADMISSION_INTENT_BYPASS=RED: OS owner reaped after SIGKILL while durable journal remained clean, new manager admitted B without independently proven kernel release")
 }
 if errors.Is(err,ErrQuarantined)||errors.Is(err,ErrUnavailable){
  t.Log("R27_S_SIGKILL_ATTACHED_RESTART_QUARANTINED=PASS")
  return
 }
 t.Fatalf("R27_S_UNEXPECTED_RESTART_ERROR=%v",err)
}
