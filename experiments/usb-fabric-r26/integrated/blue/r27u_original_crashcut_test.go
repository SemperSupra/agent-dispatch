package blue

// R27-U: bounded actual-source crash-cut exploration of the original
// heldledger -> original blue.Manager recovered startup state machine.
// This is not a model of physical QEMU/KVM kernel state or full formal proof.
import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "testing"

 "example.org/usb-fabric-r26-integrated/heldledger"
)

func TestR27UActualLedgerCrashCutsRemainQuarantined(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"held.json")
 // Test-only clean fixture: NOT a production authenticated release proof.
 if err:=os.WriteFile(path,[]byte("{\"version\":1,\"sequence\":2,\"held\":false}\n"),0600);err!=nil{t.Fatal(err)}
 store:=heldledger.Store{Path:path}
 check:=func(stage string,allow bool){
  t.Helper()
  m,err:=NewAfterJournalRecovery("keyboard","vhci_hcd/port0",nil,store)
  if allow {
   if err!=nil{t.Fatalf("%s clean startup denied: %v",stage,err)}
   return
  }
  if !errors.Is(err,ErrQuarantined){t.Fatalf("%s recovered manager not quarantined: %v",stage,err)}
  if m!=nil{
   if _,err=m.Reserve("consumer-B","keyboard","vhci_hcd/port0");!errors.Is(err,ErrQuarantined){
    t.Fatalf("%s quarantined recovery admitted B: %v",stage,err)
   }
  }
 }
 check("clean",true)
 st,err:=store.BeginAdmission(2)
 if err!=nil||!st.AdmissionIntent||st.Held{t.Fatalf("admission-intent not durable %+v %v",st,err)}
 check("after admission fsync",false)
 t.Log("R27_U_CRASH_AFTER_ADMISSION_FSYNC_DENIED=PASS")
 before,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if _,err=store.BeginAdmission(2);!errors.Is(err,heldledger.ErrConflict){
  t.Fatalf("duplicate admission admitted: %v",err)
 }
 after,err:=os.ReadFile(path)
 if err!=nil||!bytes.Equal(before,after){t.Fatal("duplicate admission mutated journal")}
 t.Log("R27_U_ADMISSION_REPLAY_BYTE_IDENTICAL=PASS")
 st,err=store.Transition(2,true)
 if err!=nil||st.Sequence!=3||!st.Held||st.AdmissionIntent{
  t.Fatalf("key-down failed to convert to durable HELD %+v %v",st,err)
 }
 check("after keydown",false)
 t.Log("R27_U_CRASH_AFTER_KEYDOWN_DENIED=PASS")
 st,err=store.RequestRelease(3)
 if err!=nil||st.ReleasePhase!="release-intent"||!st.Held{t.Fatalf("release intent failed %+v %v",st,err)}
 check("after release intent",false)
 t.Log("R27_U_CRASH_AFTER_RELEASE_INTENT_DENIED=PASS")
 k:=heldledger.KernelIsolationClaim{
  VMIncarnation:"qemu-A-actual-VM-incarnation-test",
  GuestID:"guest-a",DeviceID:"keyboard",
  HostEpoch:"host-e1",GuestEpoch:"guest-e1",LeaseEpoch:"lease-e1",
  Generation:1,ReleaseSequence:3,
  GuestDownEventSequence:12,GuestUpEventSequence:13,
  ExporterBusID:"usbip-vudc.0",ConsumerVHCIPort:"vhci_hcd/port0",
  ProviderUDCUnbound:true,ConsumerVHCIQuiescent:true,
 }
 host:=func(claim heldledger.KernelIsolationClaim)bool{return claim==k}
 st,err=store.AcknowledgeKernelIsolation(3,k,host)
 if err!=nil||!st.Held||st.ReleasePhase!="kernel-isolated"{
  t.Fatalf("kernel isolation durable stage absent %+v %v",st,err)
 }
 check("after kernel-isolated fsync but no authenticated guest UP",false)
 t.Log("R27_U_CRASH_AFTER_KERNEL_ISOLATION_WITHOUT_GUEST_UP_DENIED=PASS")
 before,err=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 // No authentically signed guest UP: reject even when host kernel witness
 // fields look correct and kernel-isolated phase has been fsynced.
 bad:=heldledger.ReleaseClaim{
  GuestID:k.GuestID,DeviceID:k.DeviceID,
  HostEpoch:k.HostEpoch,GuestEpoch:k.GuestEpoch,
  LeaseEpoch:k.LeaseEpoch,Generation:k.Generation,ReleaseSequence:3,
  DownEventSequence:12,EventSequence:13,
  Source:"guest.evdev",Key:heldledger.KeyA,KeyReleased:true,Proof:"untrusted",
 }
 if _,err=store.ConfirmGuestKernelRelease(3,k,host,bad,nil);!errors.Is(err,heldledger.ErrUnverified){
  t.Fatalf("unauthenticated guest UP cleared original HELD: %v",err)
 }
 after,err=os.ReadFile(path)
 if err!=nil||!bytes.Equal(before,after){t.Fatal("unsigned guest release mutated held bytes")}
 t.Log("R27_U_UNAUTHENTICATED_GUEST_UP_DENIED_BYTE_IDENTICAL=PASS")
}

func TestR27UMalformedPendingNeverBootstraps(t *testing.T){
 path:=filepath.Join(t.TempDir(),"pending.json")
 for _,raw:=range []string{
  "{\"version\":1,\"sequence\":2,\"held\":true,\"key\":\"key-a\",\"admission_intent\":true}",
  "{\"version\":1,\"sequence\":3,\"held\":false,\"admission_intent\":true}",
  "{\"version\":1,\"sequence\":2,\"held\":false,\"admission_intent\":true,\"admission_intent\":false}",
 }{
  if err:=os.WriteFile(path,[]byte(raw+"\n"),0600);err!=nil{t.Fatal(err)}
  store:=heldledger.Store{Path:path}
  if _,err:=store.Read();!errors.Is(err,heldledger.ErrInvalid){
   t.Fatalf("malformed pending journal read as clean: %v",err)
  }
  if _,err:=NewAfterJournalRecovery("keyboard","vhci_hcd/port0",nil,store);
   !errors.Is(err,ErrQuarantined){t.Fatalf("malformed pending admitted: %v",err)}
 }
 t.Log("R27_U_MALFORMED_ADMISSION_PHASE_FAIL_CLOSED=PASS")
}
