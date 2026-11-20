package heldledger

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

func r27KernelWitness(sequence,guestUp uint64)KernelIsolationClaim{
 return KernelIsolationClaim{
  VMIncarnation:"qemu-VM-boot-incarnation-1",
  GuestID:"guest-qemu1",DeviceID:"usb-kbd",
  HostEpoch:"host1",GuestEpoch:"g1",
  LeaseEpoch:func()string{if sequence==1{return "lease-1"};return "lease-3"}(),
  Generation:sequence,ReleaseSequence:sequence,
  GuestDownEventSequence:guestUp-1,GuestUpEventSequence:guestUp,ExporterBusID:"usbip-vudc.0",
  ConsumerVHCIPort:"vhci_hcd/port0",ProviderUDCUnbound:true,
  ConsumerVHCIQuiescent:true,
 }
}
func r27KernelVerifier(k KernelIsolationClaim)bool{
 if k.VMIncarnation!="qemu-VM-boot-incarnation-1" ||
  k.ExporterBusID!="usbip-vudc.0" ||
  k.ConsumerVHCIPort!="vhci_hcd/port0" ||
  !k.ProviderUDCUnbound || !k.ConsumerVHCIQuiescent{return false}
 return true // TEST-ONLY substitute for trusted host kernel/VM sensors.
}
func r27HeldBytes(t *testing.T,s Store,before []byte){
 t.Helper()
 got,err:=os.ReadFile(s.Path)
 if err!=nil||!bytes.Equal(got,before){t.Fatalf("R27 unauthorized release modified fsynced HELD bytes: %v",err)}
 st,err:=s.Read()
 if err!=nil||!st.Held{t.Fatalf("R27 denied release changed held: %+v err=%v",st,err)}
}
func TestR27KernelWitnessMissingOrInvalidFailClosed(t *testing.T){
 s:=Store{Path:filepath.Join(t.TempDir(),"held.json")}
 if _,err:=s.Transition(0,true);err!=nil{t.Fatal(err)}
 if _,err:=s.RequestRelease(1);err!=nil{t.Fatal(err)}
 k:=r27KernelWitness(1,11)
 before,err:=os.ReadFile(s.Path);if err!=nil{t.Fatal(err)}
 cases:=[]struct{name string;k KernelIsolationClaim;verify KernelIsolationVerifier}{
  {"nil-host-verifier",k,nil},
  {"untrusted-host",k,func(KernelIsolationClaim)bool{return false}},
  {"UDC-not-unbound",func()KernelIsolationClaim{x:=k;x.ProviderUDCUnbound=false;return x}(),r27KernelVerifier},
  {"VHCI-not-quiescent",func()KernelIsolationClaim{x:=k;x.ConsumerVHCIQuiescent=false;return x}(),r27KernelVerifier},
  {"wrong-VM",func()KernelIsolationClaim{x:=k;x.VMIncarnation="foreign";return x}(),func(x KernelIsolationClaim)bool{return x==k}},
  {"wrong-busid",func()KernelIsolationClaim{x:=k;x.ExporterBusID="other";return x}(),func(x KernelIsolationClaim)bool{return x==k}},
  {"wrong-port",func()KernelIsolationClaim{x:=k;x.ConsumerVHCIPort="port1";return x}(),func(x KernelIsolationClaim)bool{return x==k}},
  {"stale-release",func()KernelIsolationClaim{x:=k;x.ReleaseSequence=99;return x}(),r27KernelVerifier},
 }
 for _,c:=range cases{t.Run(c.name,func(t *testing.T){
  if _,err:=s.AcknowledgeKernelIsolation(1,c.k,c.verify);!errors.Is(err,ErrUnverified){
   t.Fatalf("false kernel witness accepted: %v",err)
  }
  r27HeldBytes(t,s,before)
 })}
 t.Log("R27_C_NO_UNVERIFIED_KERNEL_ISOLATION_HELD_MUTATION=PASS")
}
func TestR27KernelIsolationPhaseCannotBorrowQMPAckOrReplay(t *testing.T){
 s:=Store{Path:filepath.Join(t.TempDir(),"held.json")}
 if _,err:=s.Transition(0,true);err!=nil{t.Fatal(err)}
 if _,err:=s.RequestRelease(1);err!=nil{t.Fatal(err)}
 k:=r27KernelWitness(1,11)
 guest:=claim(1,10,11)
 if _,err:=s.ConfirmGuestKernelRelease(1,k,r27KernelVerifier,guest,signed);!errors.Is(err,ErrUnverified){
  t.Fatal("guest UP without kernel isolation allowed")
 }
 if _,err:=s.AcknowledgeQMPRelease(1);err!=nil{t.Fatal(err)}
 before,_:=os.ReadFile(s.Path)
 if _,err:=s.ConfirmGuestKernelRelease(1,k,r27KernelVerifier,guest,signed);!errors.Is(err,ErrUnverified){
  t.Fatal("QMP-native ACK laundered as kernel USBIP release")
 }
 r27HeldBytes(t,s,before)
 t.Log("R27_C_QMP_ACK_CANNOT_AUTHORIZE_LINUX_VHCI_RELEASE=PASS")

 second:=Store{Path:filepath.Join(t.TempDir(),"kernel-held.json")}
 if _,err:=second.Transition(0,true);err!=nil{t.Fatal(err)}
 if _,err:=second.RequestRelease(1);err!=nil{t.Fatal(err)}
 if st,err:=second.AcknowledgeKernelIsolation(1,k,r27KernelVerifier);
  err!=nil||st.ReleasePhase!="kernel-isolated"||!st.Held||len(st.KernelWitnessHash)!=64{
  t.Fatalf("fsynced kernel stage missing: %+v %v",st,err)
 }
 before,_=os.ReadFile(second.Path)
 if _,err:=second.ConfirmGuestRelease(1,guest,signed);!errors.Is(err,ErrUnverified){
  t.Fatal("kernel isolation laundered as QMP-native release")
 }
 if _,err:=second.AcknowledgeQMPRelease(1);!errors.Is(err,ErrUnverified){
  t.Fatal("QMP ACK allowed to override existing kernel phase")
 }
 incorrect:=guest;incorrect.EventSequence=909;incorrect.Proof=testMAC(incorrect)
 if _,err:=second.ConfirmGuestKernelRelease(1,k,r27KernelVerifier,incorrect,signed);!errors.Is(err,ErrUnverified){
  t.Fatal("different independently signed guest UP event spliced into kernel witness")
 }
 r27HeldBytes(t,second,before)
 t.Log("R27_C_LINUX_KERNEL_PHASE_CANNOT_AUTHORIZE_QMP_NATIVE=PASS")
 t.Log("R27_C_CROSS_EVENT_SEQUENCE_SPLICE_REFUSED=PASS")

 clean,err:=second.ConfirmGuestKernelRelease(1,k,r27KernelVerifier,guest,signed)
 if err!=nil||clean.Held||clean.Sequence!=2||clean.LastReleaseEventSequence!=11{
  t.Fatalf("independent kernel+guest claims not fsynced: %+v %v",clean,err)
 }
 if _,err:=second.ConfirmGuestKernelRelease(1,k,r27KernelVerifier,guest,signed);!errors.Is(err,ErrUnverified){
  t.Fatal("replayed same kernel isolation/guest claim")
 }
 if _,err:=second.Transition(2,true);err!=nil{t.Fatal(err)}
 if _,err:=second.RequestRelease(3);err!=nil{t.Fatal(err)}
 next:=r27KernelWitness(3,13)
 if _,err:=second.AcknowledgeKernelIsolation(3,next,r27KernelVerifier);err!=nil{t.Fatal(err)}
 stale:=claim(3,10,11)
 if _,err:=second.ConfirmGuestKernelRelease(3,next,r27KernelVerifier,stale,signed);!errors.Is(err,ErrUnverified){
  t.Fatal("stale guest event sequence admitted on fresh kernel isolation")
 }
 newer:=claim(3,12,13)
 if st,err:=second.ConfirmGuestKernelRelease(3,next,r27KernelVerifier,newer,signed);
  err!=nil||st.Sequence!=4||st.Held{t.Fatalf("legitimate new kernel+guest release: %+v %v",st,err)}
 t.Log("R27_C_REAL_SCOPE_KERNEL_AND_SIGNED_EVENT_CONTRACT_FSYNC_REPLAY_FENCE=PASS")
}
