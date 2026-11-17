package evidence

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "testing"

    releasegate "example.org/usb-fabric-r26-releasegate"
)

var syntheticKey=[]byte("TEST-ONLY-NO-PRODUCTION-EVIDENCE-KEY")

func s() releasegate.Scope {
    return releasegate.Scope{
        GuestID:"synthetic-linux",DeviceID:"qemu-usb-kbd",
        HostEpoch:"h-1",GuestEpoch:"g-1",LeaseEpoch:"l-1",
        Generation:3,ReleaseSequence:7,
    }
}
func proof(e Event) string {
    h:=hmac.New(sha256.New,syntheticKey)
    _,_=fmt.Fprintf(h,"%s|%s|%s|%s|%s|%d|%d|%s|%s|%t|%d",
        e.Scope.GuestID,e.Scope.DeviceID,e.Scope.HostEpoch,
        e.Scope.GuestEpoch,e.Scope.LeaseEpoch,e.Scope.Generation,
        e.Scope.ReleaseSequence,e.Source,e.KeyCode,e.Down,e.EventSequence)
    return hex.EncodeToString(h.Sum(nil))
}
func signed(e Event)Event {e.Proof=proof(e);return e}
func verify(e Event)bool {
    want:=proof(e)
    return hmac.Equal([]byte(want),[]byte(e.Proof))
}
func event(down bool,seq uint64)Event {
    return signed(Event{Scope:s(),Source:"guest.evdev",KeyCode:"key-a",
        Down:down,EventSequence:seq})
}
func fresh(t *testing.T)(*releasegate.Gate,*Bridge){
    t.Helper()
    g,err:=releasegate.New(s())
    if err!=nil{t.Fatal(err)}
    b,err:=New(g,s(),verify)
    if err!=nil{t.Fatal(err)}
    return g,b
}
func release(t *testing.T,g *releasegate.Gate){
    t.Helper()
    if err:=g.RequestRelease(s());err!=nil{t.Fatal(err)}
    if err:=g.AcknowledgeQMP(s());err!=nil{t.Fatal(err)}
}

func TestSignedActualSequenceAndQMPAckRequired(t *testing.T){
    g,b:=fresh(t)
    if b.Reclaimable(){t.Fatal("fresh pressed key is reclaimable")}
    if err:=b.ConfirmUp(event(false,12));!errors.Is(err,ErrUntrusted){
        t.Fatal("release without signed down accepted",err)
    }
    if err:=b.ObserveDown(event(true,10));err!=nil{t.Fatal(err)}
    if err:=b.ConfirmUp(event(false,11));!errors.Is(err,ErrUntrusted){
        t.Fatal("guest up before QMP release gate accepted",err)
    }
    release(t,g)
    if b.Reclaimable(){t.Fatal("QMP ACK alone reclaimed key")}
    if err:=b.ConfirmUp(event(false,11));err!=nil{t.Fatal(err)}
    if !b.Reclaimable(){t.Fatal("independently verified guest up failed to release")}
    if err:=b.ConfirmUp(event(false,11));!errors.Is(err,ErrUntrusted){
        t.Fatal("guest up replay accepted",err)
    }
    t.Log("R26_L4_SCOPED_GUEST_KEYDOWN_RELEASE_UP=PASS")
}

func TestForgedOldScopeAndConsoleReceiptDenied(t *testing.T){
    g,b:=fresh(t)
    down:=event(true,40)
    if err:=b.ObserveDown(down);err!=nil{t.Fatal(err)}
    release(t,g)
    correct:=event(false,41)
    wrongGuest:=correct;wrongGuest.Scope.GuestID="other"
    wrongHost:=correct;wrongHost.Scope.HostEpoch="old"
    wrongLease:=correct;wrongLease.Scope.LeaseEpoch="old"
    wrongGeneration:=correct;wrongGeneration.Scope.Generation=2
    wrongRelease:=correct;wrongRelease.Scope.ReleaseSequence=6
    forged:=correct;forged.Proof="forged"
    console:=correct;console.Source="qemu.serial";console.Proof="R15_GUEST_USB_KEY_A_UP=PASS"
    replay:=event(false,40)
    reverse:=event(true,41)
    wrongCode:=correct;wrongCode.KeyCode="key-b"
    unsigned:=correct;unsigned.Proof=""
    cases:=[]struct{name string;e Event}{
        {"wrong guest",wrongGuest},{"wrong host epoch",wrongHost},
        {"wrong lease epoch",wrongLease},{"wrong generation",wrongGeneration},
        {"wrong release sequence",wrongRelease},{"forged",forged},
        {"console output",console},{"replayed seq",replay},
        {"key still down",reverse},{"wrong key",wrongCode},
        {"unsigned",unsigned},
    }
    for _,tc:=range cases {
        if err:=b.ConfirmUp(tc.e);!errors.Is(err,ErrUntrusted){
            t.Errorf("%s accepted: %v",tc.name,err)
        }
        if b.Reclaimable(){t.Fatalf("%s unexpectedly reclaimed lease",tc.name)}
    }
    if err:=b.ConfirmUp(correct);err!=nil{t.Fatal(err)}
    t.Log("R26_L4_FORGED_CONSOLE_STALE_SCOPE_REJECTED=PASS")
}

func TestNoVerifierOrUntrustedDown(t *testing.T){
    g,_:=releasegate.New(s())
    if _,err:=New(g,s(),nil);!errors.Is(err,ErrUntrusted){
        t.Fatal("nil verifier accepted",err)
    }
    other:=s();other.HostEpoch="other"
    if _,err:=New(g,other,verify);!errors.Is(err,ErrUntrusted){
        t.Fatal("bridge accepted different scope",err)
    }
    _,b:=fresh(t)
    bad:=event(true,1);bad.Proof="none"
    if err:=b.ObserveDown(bad);!errors.Is(err,ErrUntrusted){
        t.Fatal("unsigned down accepted",err)
    }
    if err:=b.ObserveDown(event(true,1));err!=nil{t.Fatal(err)}
    if err:=b.ObserveDown(event(true,2));!errors.Is(err,ErrUntrusted){
        t.Fatal("duplicate down accepted",err)
    }
    t.Log("R26_L4_NO_NULL_VERIFIER_NO_DOWN_REPLAY=PASS")
}

func TestPersistedGuestConfirmedIsNotLiveProof(t *testing.T){
    g,b:=fresh(t)
    if err:=b.ObserveDown(event(true,6));err!=nil{t.Fatal(err)}
    release(t,g)
    if err:=b.ConfirmUp(event(false,7));err!=nil{t.Fatal(err)}
    restored:=releasegate.Restore(g.Snapshot())
    if restored.Reclaimable() || restored.Snapshot().Phase!=releasegate.Quarantined {
        t.Fatal("crash-restored proof silently re-admitted")
    }
    t.Log("R26_L4_RESTART_REQUIRES_REATTESTATION=PASS")
}
