package composition

import (
 "errors"
 "os"
 "path/filepath"
 "testing"

 "example.org/usb-fabric-r26-integrated/blue"
 "example.org/usb-fabric-r26-integrated/heldledger"
)

type fakeUDC struct {
 bound bool
 binds int
 unbinds int
 failBind bool
 failUnbind bool
 partialBind bool
}
func(f *fakeUDC)Unbind()error{
 f.unbinds++
 if f.failUnbind{return errors.New("UDC cannot be withdrawn")}
 f.bound=false
 return nil
}
func(f *fakeUDC)Bind()error{
 f.binds++
 if f.partialBind{f.bound=true;return errors.New("bind half succeeded")}
 if f.failBind{return errors.New("bind failed")}
 f.bound=true
 return nil
}
func(f *fakeUDC)Bound()(bool,error){return f.bound,nil}
func heldFixture(t *testing.T)(heldledger.Store,heldledger.ReleaseClaim,heldledger.ReleaseVerifier){
 t.Helper()
 store:=heldledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
 st,err:=store.Transition(0,true);if err!=nil{t.Fatal(err)}
 if _,err=store.RequestRelease(st.Sequence);err!=nil{t.Fatal(err)}
 if _,err=store.AcknowledgeQMPRelease(st.Sequence);err!=nil{t.Fatal(err)} // TEST-ONLY QMP ACK
 claim:=heldledger.ReleaseClaim{GuestID:"qemu-test",DeviceID:"keyboard",HostEpoch:"h1",GuestEpoch:"g1",LeaseEpoch:"l1",Generation:1,ReleaseSequence:1,DownEventSequence:10,EventSequence:11,Source:"guest.evdev",Key:heldledger.KeyA,KeyReleased:true,Proof:"test-only-evidence"}
 verify:=func(c heldledger.ReleaseClaim)bool{
  return c==claim
 }
 return store,claim,verify
}
func TestR22JournalGuestProofBeforeKernelUDCRebind(t *testing.T){
 store,claim,verify:=heldFixture(t)
 udc:=&fakeUDC{bound:true} // previously exported before broker crash
 coordinator,err:=NewFenced(store,udc,"keyboard","xhci0/auto");if err!=nil{t.Fatal(err)}
 if udc.bound||udc.unbinds!=1{t.Fatal("bootstrap did not withdraw export")}
 if _,err=coordinator.Reserve("consumer-B","keyboard","xhci0/auto");!errors.Is(err,ErrProofRequired){t.Fatal("preproof B admitted",err)}
 raw,err:=os.ReadFile(store.Path);if err!=nil{t.Fatal(err)}
 bad:=claim;bad.Source="usbip.detach"
 if err=coordinator.ReleaseAndBind(1,bad,verify);!errors.Is(err,heldledger.ErrUnverified){t.Fatal("transport proof accepted",err)}
 if udc.bound||udc.binds!=0{t.Fatal("transport proof exposed physical export")}
 after,_:=os.ReadFile(store.Path)
 if string(raw)!=string(after){t.Fatal("rejected transport proof changed HELD journal")}
 if err=coordinator.ReleaseAndBind(1,claim,verify);err!=nil{t.Fatal(err)}
 if !udc.bound||udc.binds!=1{t.Fatal("verified release failed to bind export")}
 st,err:=store.Read();if err!=nil||st.Held{t.Fatalf("journal not released %+v %v",st,err)}
 lease,err:=coordinator.Reserve("consumer-B","keyboard","xhci0/auto")
 if err!=nil||lease.Generation==0{t.Fatalf("B re-admission denied %+v %v",lease,err)}
 t.Log("R22_B_TEST_ONLY_JOURNAL_PROOF_BEFORE_UDC_BIND=PASS")
 t.Log("R22_B_REAL_CONFIGFS_VUDC_CONTROL=NOT_TESTED")
}
func TestR22PartialBindRollsBackOrRefusesSafety(t *testing.T){
 for _,partial:=range []bool{false,true}{
  store,claim,verify:=heldFixture(t)
  udc:=&fakeUDC{partialBind:partial,failBind:!partial}
  c,err:=NewFenced(store,udc,"keyboard","xhci0/auto");if err!=nil{t.Fatal(err)}
  if err=c.ReleaseAndBind(1,claim,verify);err==nil{t.Fatal("failed bind promoted")}
  if udc.bound{t.Fatal("UDC remained bound after failed bind")}
  if _,err=c.Reserve("consumer-B","keyboard","xhci0/auto");!errors.Is(err,ErrProofRequired){t.Fatal("failed bind admitted B",err)}
 }
 store,claim,verify:=heldFixture(t)
 udc:=&fakeUDC{partialBind:true}
 c,err:=NewFenced(store,udc,"keyboard","xhci0/auto");if err!=nil{t.Fatal(err)}
 udc.failUnbind=true // fail while handling partial bind
 if err=c.ReleaseAndBind(1,claim,verify);!errors.Is(err,ErrIsolationUnknown){t.Fatalf("uncertain export isolation was not refused: %v",err)}
 if _,err=c.Reserve("consumer-B","keyboard","xhci0/auto");!errors.Is(err,ErrProofRequired){t.Fatal("unsafe export admitted B",err)}
 t.Log("R22_B_PARTIAL_EXPORT_REBIND_FAIL_CLOSED_OR_REFUSED=PASS")
}
func TestR22NoExportGateNeverPublishesManager(t *testing.T){
 store,_,_:=heldFixture(t)
 if c,err:=NewFenced(store,nil,"keyboard","xhci0/auto");!errors.Is(err,ErrIsolationUnknown)||c!=nil{t.Fatal("nil UDC admitted")}
 udc:=&fakeUDC{bound:true,failUnbind:true}
 c,err:=NewFenced(store,udc,"keyboard","xhci0/auto")
 if !errors.Is(err,ErrIsolationUnknown){t.Fatalf("unbound-withdraw failure not surfaced: %v",err)}
 if _,err=c.Reserve("consumer-B","keyboard","xhci0/auto");!errors.Is(err,ErrProofRequired){t.Fatal("unisolated export reserved B",err)}
 t.Log("R22_B_NO_UNVERIFIED_UDC_REBIND_OR_BOOTSTRAP_ADMISSION=PASS")
}
var _=blue.ErrDenied
