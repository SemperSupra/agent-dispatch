package blue

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "sync"
 "testing"
 "example.org/usb-fabric-r26-integrated/heldledger"
)
var r27Pending=errors.New("test-only kernel isolation pending")
type r27Executor struct{ store heldledger.Store }
func(e *r27Executor)Input(cmd string)error{
 st,err:=e.store.Read();if err!=nil{return err}
 switch cmd {
 case "key-a-down": _,err=e.store.Transition(st.Sequence,true);return err
 case "key-a-up":
  if st.ReleasePhase==""{if _,err=e.store.RequestRelease(st.Sequence);err!=nil{return err}}
  return r27Pending
 default:return ErrDenied
 }
}
func(e *r27Executor)ReleaseAll()error{return e.Input("key-a-up")}

func TestR27OriginalManagerKernelIsolationLockedReadmission(t *testing.T){
 ledger:=heldledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
 m:=New("keyboard","usbip-vudc.0",&r27Executor{store:ledger})
 a,err:=m.Reserve("consumer-A","keyboard","usbip-vudc.0")
 if err!=nil{t.Fatal(err)}
 if err=m.Attach(a);err!=nil{t.Fatal(err)}
 if err=m.Input(a,"key-a-down");err!=nil{t.Fatal(err)}
 if err=m.Revoke(a);!errors.Is(err,r27Pending){t.Fatal("expected quarantine",err)}
 st,err:=ledger.Read()
 if err!=nil||!st.Held||st.Sequence!=1||st.ReleasePhase!="release-intent"{t.Fatalf("bad held %+v %v",st,err)}
 if _,err=m.Reserve("consumer-B","keyboard","usbip-vudc.0");!errors.Is(err,ErrQuarantined){t.Fatal("early B lease",err)}
 witness:=heldledger.KernelIsolationClaim{
  VMIncarnation:"host-observed-qemu-A",GuestID:"qemu-test-guest",DeviceID:a.Device,
  HostEpoch:"host-R17-test",GuestEpoch:"guest-R17-test",LeaseEpoch:a.Epoch,
  Generation:a.Generation,ReleaseSequence:1,GuestDownEventSequence:10,GuestUpEventSequence:11,
  ExporterBusID:"usbip-vudc.0",ConsumerVHCIPort:"vhci_hcd/0",
  ProviderUDCUnbound:true,ConsumerVHCIQuiescent:true,
 }
 host:=func(w heldledger.KernelIsolationClaim)bool{return w==witness}
 if _,err=ledger.AcknowledgeKernelIsolation(1,witness,host);err!=nil{t.Fatal(err)}
 before,_:=os.ReadFile(ledger.Path)
 invalid:=r17Claim(a,1,10,11);invalid.GuestEpoch="foreign";invalid.Proof=r17MAC(invalid)
 if err=m.RestoreAfterVerifiedKernelUp(ledger,1,witness,host,invalid,r17Verifier(a));!errors.Is(err,heldledger.ErrUnverified){t.Fatal("wrong guest",err)}
 after,_:=os.ReadFile(ledger.Path)
 if !bytes.Equal(before,after){t.Fatal("wrong guest changed HELD bytes")}
 if _,err=m.Reserve("consumer-B","keyboard","usbip-vudc.0");!errors.Is(err,ErrQuarantined){t.Fatal("wrong signer admitted B",err)}
 t.Log("R27_C_ORIGINAL_MANAGER_KERNEL_WRONG_GUEST_HELD_AND_B_FENCED=PASS")
 good:=r17Claim(a,1,10,11)
 results:=make(chan error,2)
 var wg sync.WaitGroup
 for i:=0;i<2;i++{wg.Add(1);go func(){defer wg.Done();results<-m.RestoreAfterVerifiedKernelUp(ledger,1,witness,host,good,r17Verifier(a))}()}
 wg.Wait();close(results)
 accepted:=0
 for e:=range results{if e==nil{accepted++}}
 if accepted!=1{t.Fatalf("concurrent approvals=%d",accepted)}
 clean,err:=ledger.Read()
 if err!=nil||clean.Held||clean.Sequence!=2||clean.LastReleaseEventSequence!=11{t.Fatalf("not fsynced %+v %v",clean,err)}
 b,err:=m.Reserve("consumer-B","keyboard","usbip-vudc.0")
 if err!=nil||b.Generation<=a.Generation{t.Fatalf("valid B denied %+v %v",b,err)}
 if err=m.Input(a,"key-a-down");!errors.Is(err,ErrDenied){t.Fatal("old lease input allowed",err)}
 t.Log("R27_C_EXISTING_MANAGER_KERNEL_GUEST_ONE_TIME_FSYNCED_RELEASE=PASS")
}
