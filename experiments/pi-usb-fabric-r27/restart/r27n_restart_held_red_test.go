package blue

import (
 "errors"
 "path/filepath"
 "testing"
 "example.org/usb-fabric-r26-integrated/heldledger"
)

// RED critic: a restarted host must NOT admit a new lease while its
// authoritative durable journal remains HELD. The original Manager.New
// does not accept a journal so this test is intentionally independent.
func TestR27NRestartHeldJournalMustFenceFreshAdmission(t *testing.T) {
 ledger:=heldledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
 st,err:=ledger.Transition(0,true)
 if err!=nil || st.Sequence!=1 || !st.Held {t.Fatalf("could not fsync HELD before simulated crash: %+v err=%v",st,err)}
 // Simulate fresh process incarnation with original authoritative constructor
 // and original executor. A persisted HELD lease survives a host crash.
 restarted:=New("keyboard","xhci0/auto",&r27Executor{store:ledger})
 _,err=restarted.Reserve("consumer-B","keyboard","xhci0/auto")
 if errors.Is(err,ErrQuarantined) || errors.Is(err,ErrUnavailable) {
  t.Log("R27_N_RESTART_PERSISTED_HELD_DENIES_NEW_LEASE=PASS")
  return
 }
 if err==nil {
  t.Fatal("R27_N_RESTART_HELD_ADMISSION_BYPASS=RED: restarted original Manager admitted consumer-B while existing durable ledger is HELD; reserve must fail closed")
 }
 t.Fatalf("R27_N_RESTART_HELD_INCORRECT_DENIAL=%v",err)
}
