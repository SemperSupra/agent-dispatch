package identity

import (
    "bytes"
    "errors"
    "os"
    "path/filepath"
    "sync"
    "testing"

    "example.org/usb-fabric-r26-integrated/blue"
    "example.org/usb-fabric-r26-integrated/heldledger"
    releasegate "example.org/usb-fabric-r26-releasegate"
    "example.org/usb-fabric-r26-releasegate/evidence"
    "example.org/usb-fabric-r26-releasegate/guestwire"
    composition "example.org/usb-fabric-r22-qmp-usbip-compose"
    samelease "example.org/usb-fabric-r23-same-lease-qmp"
)

type r25UDC struct { bound bool; binds int; unbinds int }
func (u *r25UDC) Unbind() error {u.bound=false;u.unbinds++;return nil}
func (u *r25UDC) Bind() error {u.bound=true;u.binds++;return nil}
func (u *r25UDC) Bound() (bool,error) {return u.bound,nil}

type r25Suite struct {
    handoff *Handoff
    guard *samelease.Guard
    udc *r25UDC
    q QMPWitness
    u USBIPWitness
    down, up evidence.Event
}
func r25Setup(t *testing.T) r25Suite {
    t.Helper()
    m:=blue.New("keyboard","xhci0/auto",nil)
    lease,err:=m.Reserve("consumer-A","keyboard","xhci0/auto")
    if err!=nil{t.Fatal(err)}
    scope:=releasegate.Scope{GuestID:"consumer-A",DeviceID:lease.Device,
        HostEpoch:"host-boot-25",GuestEpoch:"guest-boot-25",
        LeaseEpoch:lease.Epoch,Generation:lease.Generation,ReleaseSequence:1}
    store:=heldledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
    st,err:=store.Transition(0,true);if err!=nil{t.Fatal(err)}
    if _,err=store.RequestRelease(st.Sequence);err!=nil{t.Fatal(err)}
    if _,err=store.AcknowledgeQMPRelease(st.Sequence);err!=nil{t.Fatal(err)}
    udc:=&r25UDC{bound:true}
    guard,err:=samelease.New(lease,scope,store,udc,guestwire.VerifySyntheticGuest)
    if err!=nil{t.Fatal(err)}
    topo:=Topology{VMIncarnation:"qemu-pid-100/boot-25",QMPObjectID:"r26-l-kbd",
        USBIPExporter:"usbip-vudc.0",GuestInputDeviceID:"linux-vhci-hid"}
    q:=QMPWitness{VMIncarnation:topo.VMIncarnation,ObjectID:topo.QMPObjectID,
        LeaseEpoch:lease.Epoch,Generation:lease.Generation,ReleaseSequence:1,ActualAck:true}
    u:=USBIPWitness{VMIncarnation:topo.VMIncarnation,Exporter:topo.USBIPExporter,
        InputDeviceID:topo.GuestInputDeviceID,LeaseEpoch:lease.Epoch,
        Generation:lease.Generation,ReleaseSequence:1,EventSequence:101,GuestUP:true}
    // These callbacks are deliberately TEST fixtures. Real input provenance
    // must be supplied by genuine R26 QMP + USBIP event sensors later.
    pair,err:=New(lease,scope,topo,
        func(w QMPWitness)bool{return w==q},
        func(w USBIPWitness)bool{return w==u})
    if err!=nil{t.Fatal(err)}
    handoff,err:=NewHandoff(pair,guard);if err!=nil{t.Fatal(err)}
    down:=guestwire.SignForSyntheticGuest(evidence.Event{
        Scope:scope,Source:"guest.evdev",KeyCode:"key-a",Down:true,EventSequence:100})
    up:=guestwire.SignForSyntheticGuest(evidence.Event{
        Scope:scope,Source:"guest.evdev",KeyCode:"key-a",Down:false,EventSequence:101})
    return r25Suite{handoff,guard,udc,q,u,down,up}
}
func TestR25BDirectImportDeniedUntilMatchedPairAndDurableGuestUP(t *testing.T){
    s:=r25Setup(t)
    if s.udc.bound || s.udc.unbinds!=1 {t.Fatal("boot did not withdraw exporter")}
    if _,err:=s.handoff.ReserveNext("consumer-B");!errors.Is(err,composition.ErrProofRequired){
        t.Fatalf("early B reservation accepted: %v",err)
    }
    if err:=s.guard.ObserveDown(s.down);err!=nil{t.Fatal(err)}
    if err:=s.guard.AcknowledgeQMP();err!=nil{t.Fatal(err)}
    prior,err:=os.ReadFile(s.guard.Store.Path);if err!=nil{t.Fatal(err)}
    forgedQ:=s.q;forgedQ.ObjectID="unrelated-qmp-tablet"
    if err:=s.handoff.Commit(forgedQ,s.u,s.up);!errors.Is(err,ErrUnbound){
        t.Fatalf("wrong QMP object admitted: %v",err)
    }
    forgedU:=s.u;forgedU.InputDeviceID="other-USBIP-input"
    if err:=s.handoff.Commit(s.q,forgedU,s.up);!errors.Is(err,ErrUnbound){
        t.Fatalf("wrong VHCI input admitted: %v",err)
    }
    noAck:=s.q;noAck.ActualAck=false
    if err:=s.handoff.Commit(noAck,s.u,s.up);!errors.Is(err,ErrUnbound){
        t.Fatalf("QMP request without actual ACK admitted: %v",err)
    }
    after,err:=os.ReadFile(s.guard.Store.Path)
    if err!=nil||!bytes.Equal(prior,after)||s.udc.bound||s.udc.binds!=0{
        t.Fatal("untrusted cross-device witness changed HELD or exported USBIP")
    }
    t.Log("R25_A_CROSS_DEVICE_ACK_AND_GUEST_MISMATCH_REFUSED_BEFORE_BIND=PASS")
    t.Log("R25_A_UNVERIFIED_RECEIPTS_KEEP_HELD_BYTE_IDENTICAL=PASS")
    if err:=s.handoff.Commit(s.q,s.u,s.up);err!=nil{t.Fatal(err)}
    state,err:=s.guard.Store.Read();if err!=nil{t.Fatal(err)}
    if state.Held||s.udc.binds!=1||!s.udc.bound{
        t.Fatal("verified complete proof did not clear durable HELD and bind once")
    }
    next,err:=s.handoff.ReserveNext("consumer-B")
    if err!=nil||next.Generation<=s.guard.Lease.Generation{t.Fatalf("B not admitted under fresh generation %+v %v",next,err)}
    if err:=s.handoff.Commit(s.q,s.u,s.up);!errors.Is(err,ErrUnbound){
        t.Fatalf("replayed complete pair admitted: %v",err)
    }
    if s.udc.binds!=1{t.Fatal("replay caused duplicate exporter bind")}
    t.Log("R25_A_MATCHED_TEST_PAIR_FSYNC_BEFORE_SINGLE_UDC_BIND=PASS")
    t.Log("R25_A_REAL_QMP_USBIP_CAUSAL_HANDOFF=NOT_TESTED")
}
func TestR25MismatchedManagerAndCrashStageQuarantine(t *testing.T){
    s:=r25Setup(t)
    wrong:=*s.handoff.pair
    wrong.Lease.Generation++
    if _,err:=NewHandoff(&wrong,s.guard);!errors.Is(err,ErrHandoff){
        t.Fatal("foreign generation manager combined with exporter")
    }
    if err:=s.guard.ObserveDown(s.down);err!=nil{t.Fatal(err)}
    // Pair cannot promote a real export if the R23 gate missed its QMP
    // ACK stage; consumed evidence is not replayable after failure.
    if err:=s.handoff.Commit(s.q,s.u,s.up);err==nil{
        t.Fatal("unacknowledged QMP release authorized export")
    }
    if s.udc.bound||s.udc.binds!=0{t.Fatal("failed release bound exporter")}
    if err:=s.handoff.Commit(s.q,s.u,s.up);!errors.Is(err,ErrUnbound){
        t.Fatal("post-failure witness replay admitted")
    }
    t.Log("R25_A_MISSING_QMP_RELEASE_STAGE_FAILS_CLOSED_NO_RETRY=PASS")
}
func TestR25ConcurrentWitnessReplayOnlyOneBind(t *testing.T){
    s:=r25Setup(t)
    if err:=s.guard.ObserveDown(s.down);err!=nil{t.Fatal(err)}
    if err:=s.guard.AcknowledgeQMP();err!=nil{t.Fatal(err)}
    var wg sync.WaitGroup
    results:=make(chan error,2)
    for n:=0;n<2;n++{
        wg.Add(1)
        go func(){defer wg.Done();results<-s.handoff.Commit(s.q,s.u,s.up)}()
    }
    wg.Wait();close(results)
    success,denied:=0,0
    for e:=range results{
        switch{
        case e==nil:success++
        case errors.Is(e,ErrUnbound):denied++
        default:t.Fatalf("unexpected commit result: %v",e)
        }
    }
    if success!=1||denied!=1||s.udc.binds!=1{
        t.Fatalf("double-use accepted success=%d denied=%d binds=%d",success,denied,s.udc.binds)
    }
    t.Log("R25_A_CONCURRENT_REPLAY_ONE_USE_ONLY=PASS")
}
