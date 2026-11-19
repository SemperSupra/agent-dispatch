package restartfence

import (
 "bytes"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"

 ledger "example.org/usb-fabric-r26-integrated/heldledger"
)

// The same test binary is started as a separate host-side process for every
// phase. This qualifies on-disk restart recovery of the EXISTING Store, not a
// real broker supervisor or QEMU/USBIP post-restart export control.
func TestHelperRestartJournalProcess(t *testing.T) {
 if os.Getenv("R21_HELPER_PROCESS") != "1" { return }
 store := ledger.Store{Path:os.Getenv("R21_JOURNAL_PATH")}
 fail:=func(err error){fmt.Fprintln(os.Stderr,err);os.Exit(21)}
 switch os.Getenv("R21_PHASE") {
 case "writer":
  state,err:=store.Transition(0,true);if err!=nil {fail(err)}
  _,err=store.RequestRelease(state.Sequence);if err!=nil {fail(err)}
  _,err=store.AcknowledgeQMPRelease(state.Sequence);if err!=nil {fail(err)}
  fmt.Println("R21_DISK_HELD_QMP_ACK_SIMULATED=PASS")
 case "reader":
  state,err:=store.Read();if err!=nil{fail(err)}
  if !state.Held || state.Key!=ledger.KeyA || state.Sequence!=1 || state.ReleasePhase!="qmp-acked" {
   fail(fmt.Errorf("unsafe recovered state %+v",state))
  }
  if _,err=store.Transition(state.Sequence,true);!errors.Is(err,ledger.ErrConflict){fail(fmt.Errorf("second held admission %v",err))}
  if _,err=store.Transition(state.Sequence,false);!errors.Is(err,ledger.ErrUnverified){fail(fmt.Errorf("unverified release %v",err))}
  if _,err=store.ConfirmGuestRelease(state.Sequence,ledger.ReleaseClaim{},nil);!errors.Is(err,ledger.ErrUnverified){fail(fmt.Errorf("unauthenticated release %v",err))}
  fmt.Println("R21_SEPARATE_PROCESS_HELD_RELOAD_DENIES_ADMISSION=PASS")
 case "bad":
  _,err:=store.Read();if !errors.Is(err,ledger.ErrInvalid) {fail(fmt.Errorf("malformed journal accepted %v",err))}
  fmt.Println("R21_SEPARATE_PROCESS_CORRUPT_JOURNAL_DENIED=PASS")
 default:
  fail(fmt.Errorf("unknown phase"))
 }
 os.Exit(0)
}

func invoke(t *testing.T,path,phase string) string {
 t.Helper()
 binary,err:=os.Executable();if err!=nil{t.Fatal(err)}
 cmd:=exec.Command(binary,"-test.run=^TestHelperRestartJournalProcess$")
 cmd.Env=append(os.Environ(),"R21_HELPER_PROCESS=1","R21_JOURNAL_PATH="+path,"R21_PHASE="+phase)
 output,err:=cmd.CombinedOutput()
 if err!=nil {t.Fatalf("phase %s: %v: %s",phase,err,output)}
 return string(output)
}

func TestR21SeparateProcessesReloadDurableHeldFailClosed(t *testing.T){
 path:=filepath.Join(t.TempDir(),"held.json")
 writer:=invoke(t,path,"writer")
 if !strings.Contains(writer,"R21_DISK_HELD_QMP_ACK_SIMULATED=PASS"){t.Fatal(writer)}
 original,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 reader:=invoke(t,path,"reader")
 if !strings.Contains(reader,"R21_SEPARATE_PROCESS_HELD_RELOAD_DENIES_ADMISSION=PASS"){t.Fatal(reader)}
 again,err:=os.ReadFile(path);if err!=nil||!bytes.Equal(original,again){t.Fatalf("reader mutated durable HELD: %v",err)}
 t.Log("R21_A_MULTIPROCESS_HELD_RESTART_POLICY=PASS")
 t.Log("R21_A_REAL_BROKER_RESTART_USBIP_IMPORT=NOT_TESTED")
}

func TestR21SeparateProcessRejectsCorruptedDurableRecord(t *testing.T){
 path:=filepath.Join(t.TempDir(),"held.json")
 if err:=os.WriteFile(path,[]byte("{\"version\":1,\"sequence\":1,\"key\":\"key-a\",\"held\":true,\"release_phase\":\"qmp-acked\",\"held\":false}\n"),0600);err!=nil {t.Fatal(err)}
 original,_:=os.ReadFile(path)
 out:=invoke(t,path,"bad")
 if !strings.Contains(out,"R21_SEPARATE_PROCESS_CORRUPT_JOURNAL_DENIED=PASS"){t.Fatal(out)}
 now,_:=os.ReadFile(path);if !bytes.Equal(original,now){t.Fatal("corrupt journal mutated")}
 t.Log("R21_A_CORRUPT_JOURNAL_FAIL_CLOSED=PASS")
}
