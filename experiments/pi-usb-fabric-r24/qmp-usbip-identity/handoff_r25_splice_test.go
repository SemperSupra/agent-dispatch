package identity

// R25-C independent adversarial critic: two individually verified but
// DIFFERENT guest-UP events must never be spliced into one USB/IP release.
// A signed event at seq 101 cannot discharge a trusted VHCI sensor's
// observation at seq 909, even when both cite the same VM and lease.
import (
    "bytes"
    "errors"
    "os"
    "testing"

    "example.org/usb-fabric-r26-releasegate/evidence"
)

func TestR25CVHCIWitnessCannotBeSplicedWithDifferentSignedGuestUp(t *testing.T) {
    s:=r25Setup(t)
    if err:=s.guard.ObserveDown(s.down);err!=nil{t.Fatal(err)}
    if err:=s.guard.AcknowledgeQMP();err!=nil{t.Fatal(err)}
    trustedQ,foreignU:=s.q,s.u
    foreignU.EventSequence=909
    pair,err:=New(s.guard.Lease,s.guard.Scope,s.handoff.pair.Topology,
        func(w QMPWitness)bool{return w==trustedQ},
        func(w USBIPWitness)bool{return w==foreignU})
    if err!=nil{t.Fatal(err)}
    candidate,err:=NewHandoff(pair,s.guard);if err!=nil{t.Fatal(err)}
    before,err:=os.ReadFile(s.guard.Store.Path);if err!=nil{t.Fatal(err)}

    // VALID guest-signed UP at 101 and VALID independently verified VHCI
    // UP at 909 have mismatched causality. Neither alone can release.
    if err:=candidate.Commit(trustedQ,foreignU,s.up);!errors.Is(err,ErrHandoff) {
        t.Fatalf("independent-event proof splice admitted: %v",err)
    }
    after,err:=os.ReadFile(s.guard.Store.Path)
    if err!=nil || !bytes.Equal(before,after) || s.udc.bound || s.udc.binds!=0 {
        t.Fatal("mismatched events altered durable HELD or bound exporter")
    }
    t.Log("R25_C_CROSS_EVENT_SIGNED_GUEST_UP_SPLICE_REFUSED=PASS")
    t.Log("R25_C_MISMATCHED_SIGNED_UP_PRESERVES_HELD_BYTES=PASS")

    // Correct evidence can still complete the same scope after rejected
    // mismatched evidence; reject-before-consumption is essential.
    properU:=s.u
    genuine,err:=New(s.guard.Lease,s.guard.Scope,s.handoff.pair.Topology,
        func(w QMPWitness)bool{return w==trustedQ},
        func(w USBIPWitness)bool{return w==properU})
    if err!=nil{t.Fatal(err)}
    h,err:=NewHandoff(genuine,s.guard);if err!=nil{t.Fatal(err)}
    if err:=h.Commit(trustedQ,properU,s.up);err!=nil{t.Fatal(err)}
    if !s.udc.bound||s.udc.binds!=1{t.Fatal("valid causally matched pair not bound exactly once")}
    t.Log("R25_C_SAME_EVENT_SIGNED_GUEST_UP_AUTHORIZED_ONCE=PASS")
}
func TestR25CNoTransportOnlyUpOrDifferentGuestScope(t *testing.T){
    variants:=[]struct{name string;edit func(*evidence.Event)}{
        {"transport",func(e *evidence.Event){e.Source="usbip.detach"}},
        {"wrong guest epoch",func(e *evidence.Event){e.Scope.GuestEpoch="foreign-guest"}},
        {"wrong guest key",func(e *evidence.Event){e.KeyCode="key-b"}},
    }
    for _,v:=range variants{
        t.Run(v.name,func(t *testing.T){
            s:=r25Setup(t)
            if err:=s.guard.ObserveDown(s.down);err!=nil{t.Fatal(err)}
            if err:=s.guard.AcknowledgeQMP();err!=nil{t.Fatal(err)}
            e:=s.up;v.edit(&e)
            before,_:=os.ReadFile(s.guard.Store.Path)
            if err:=s.handoff.Commit(s.q,s.u,e);err==nil {
                t.Fatal("invalid or unauthenticated guest UP allowed exporter")
            }
            after,_:=os.ReadFile(s.guard.Store.Path)
            if !bytes.Equal(before,after)||s.udc.bound{
                t.Fatal("invalid signed guest variant changed held/UDC")
            }
        })
    }
    t.Log("R25_C_TRANSPORT_SCOPE_AND_KEY_REJECTED_BEFORE_EXPORT=PASS")
}
