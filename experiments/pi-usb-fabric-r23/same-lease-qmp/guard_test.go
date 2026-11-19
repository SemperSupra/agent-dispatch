package samelease

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "testing"

 "example.org/usb-fabric-r26-integrated/blue"
 "example.org/usb-fabric-r26-integrated/heldledger"
 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
 "example.org/usb-fabric-r26-releasegate/guestwire"
 composition "example.org/usb-fabric-r22-qmp-usbip-compose"
)

type testUDC struct{ bound bool;binds int;unbinds int }
func(u *testUDC)Unbind()error{u.bound=false;u.unbinds++;return nil}
func(u *testUDC)Bind()error{u.bound=true;u.binds++;return nil}
func(u *testUDC)Bound()(bool,error){return u.bound,nil}
func setup(t *testing.T)(*Guard,*testUDC,evidence.Event,evidence.Event){
 t.Helper()
 m:=blue.New("keyboard","xhci0/auto",nil)
 lease,err:=m.Reserve("consumer-A","keyboard","xhci0/auto");if err!=nil{t.Fatal(err)}
 scope:=releasegate.Scope{GuestID:"QEMU-r23",DeviceID:lease.Device,HostEpoch:"host-epoch-1",GuestEpoch:"vm-epoch-1",LeaseEpoch:lease.Epoch,Generation:lease.Generation,ReleaseSequence:1}
 store:=heldledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
 st,err:=store.Transition(0,true);if err!=nil{t.Fatal(err)}
 if _,err=store.RequestRelease(st.Sequence);err!=nil{t.Fatal(err)}
 if _,err=store.AcknowledgeQMPRelease(st.Sequence);err!=nil{t.Fatal(err)} // UNIT TEST synthetic ack only
 udc:=&testUDC{bound:true}
 g,err:=New(lease,scope,store,udc,guestwire.VerifySyntheticGuest)
 if err!=nil{t.Fatal(err)}
 down:=guestwire.SignForSyntheticGuest(evidence.Event{Scope:scope,Source:"guest.evdev",KeyCode:"key-a",Down:true,EventSequence:100})
 up:=guestwire.SignForSyntheticGuest(evidence.Event{Scope:scope,Source:"guest.evdev",KeyCode:"key-a",Down:false,EventSequence:101})
 return g,udc,down,up
}
func TestR23SameLeaseQMPAckAloneAndGuestUPAloneBothDenyBind(t *testing.T){
 g,udc,down,up:=setup(t)
 if err:=g.ObserveDown(down);err!=nil{t.Fatal(err)}
 original,err:=os.ReadFile(g.Store.Path);if err!=nil{t.Fatal(err)}
 if err=g.ConfirmAndBind(up);!errors.Is(err,evidence.ErrUntrusted){t.Fatalf("guest up without ACK admitted: %v",err)}
 if _,err=g.ReserveNext("consumer-B");!errors.Is(err,composition.ErrProofRequired){t.Fatal("early B admitted",err)}
 if err=g.AcknowledgeQMP();err!=nil{t.Fatal(err)}
 if g.Bridge.Reclaimable()||udc.binds!=0||udc.bound{t.Fatal("QMP ACK alone rebound UDC")}
 after,err:=os.ReadFile(g.Store.Path);if err!=nil||!bytes.Equal(original,after){t.Fatal("QMP alone altered durable HELD")}
 if err=g.ConfirmAndBind(up);err!=nil{t.Fatal(err)}
 if !udc.bound||udc.binds!=1{t.Fatal("scoped verified UP never bound export")}
 next,err:=g.ReserveNext("consumer-B")
 if err!=nil||next.Generation==0{t.Fatalf("B not admitted after proof %+v %v",next,err)}
 if err=g.ConfirmAndBind(up);err==nil{t.Fatal("replayed guest UP permitted second bind")}
 t.Log("R23_A_SAME_LEASE_QMP_AND_GUEST_GATE_ONLY_ONCE=PASS")
 t.Log("R23_A_REAL_QMP_USBIP_SINGLE_CAUSAL_JOB=NOT_TESTED")
}
func TestR23WrongVMGenerationOrTransportCannotOpenUDC(t *testing.T){
 g,udc,down,up:=setup(t)
 if err:=g.ObserveDown(down);err!=nil{t.Fatal(err)}
 if err:=g.AcknowledgeQMP();err!=nil{t.Fatal(err)}
 original,_:=os.ReadFile(g.Store.Path)
 candidates:=[]evidence.Event{}
 x:=up;x.Scope.Generation++;candidates=append(candidates,x)
 x=up;x.Scope.GuestEpoch="wrong-vm";candidates=append(candidates,x)
 x=up;x.Scope.HostEpoch="wrong-host";candidates=append(candidates,x)
 x=up;x.Source="usbip.detach";candidates=append(candidates,x)
 x=up;x.Proof="forged";candidates=append(candidates,x)
 for _,e:=range candidates{
  if err:=g.ConfirmAndBind(e);err==nil{t.Fatal("untrusted guest release bound real exporter")}
  if udc.bound||udc.binds!=0{t.Fatal("export bound by invalid proof")}
  after,_:=os.ReadFile(g.Store.Path);if !bytes.Equal(original,after){t.Fatal("invalid proof mutated HELD journal")}
 }
 if err:=g.ConfirmAndBind(up);err!=nil{t.Fatal(err)}
 t.Log("R23_A_WRONG_SCOPE_OR_TRANSPORT_BEFORE_BIND_REFUSED=PASS")
}
func TestR23RestartedGateDoesNotInheritGuestProof(t *testing.T){
 g,_,down,up:=setup(t)
 if err:=g.ObserveDown(down);err!=nil{t.Fatal(err)}
 if err:=g.AcknowledgeQMP();err!=nil{t.Fatal(err)}
 // Restart means fresh gate/bridge without a signed down; disk still held.
 d:=&testUDC{bound:true}
 recovered,err:=New(g.Lease,g.Scope,g.Store,d,guestwire.VerifySyntheticGuest)
 if err!=nil{t.Fatal(err)}
 if err=recovered.ConfirmAndBind(up);!errors.Is(err,ErrNotProven){t.Fatalf("restart skipped evidence: %v",err)}
 if d.bound||d.binds!=0{t.Fatal("restart re-bound exporter on ACK-only state")}
 t.Log("R23_A_RESTART_DROPS_UNATTESTED_QMP_ONLY_RELEASE=PASS")
}
