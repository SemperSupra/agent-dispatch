package runtimeproof_test

import (
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "testing"

 releasegate "example.org/usb-fabric-r26-releasegate"
 rp "example.org/usb-fabric-r26-releasegate/runtimeproof"
)
func testKey(t *testing.T)(ed25519.PublicKey,ed25519.PrivateKey){
 t.Helper()
 pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 return pub,priv
}
func scope(generation,release uint64)releasegate.Scope{
 return releasegate.Scope{
  GuestID:"actual-synthetic-linux-guest",
  DeviceID:"qemu-kbd-1",HostEpoch:"host-boot-42",
  GuestEpoch:"guest-incarnation-123",
  LeaseEpoch:"distinct-lease-epoch-"+string(rune('A'+int(generation))),
  Generation:generation,ReleaseSequence:release,
 }
}
func signed(t *testing.T,priv ed25519.PrivateKey,s releasegate.Scope,challenge [32]byte,down bool,sequence uint64)rp.Event{
 t.Helper()
 e,err:=rp.Sign(priv,rp.Event{
  Scope:s,Challenge:challenge,Source:"guest.evdev",
  KeyCode:"key-a",Down:down,EventSequence:sequence,
 })
 if err!=nil{t.Fatal(err)}
 return e
}
func denied(t *testing.T,err error){
 t.Helper()
 if !errors.Is(err,rp.ErrUntrusted){t.Fatalf("expected fail-closed, got: %v",err)}
}
func TestTwoIndependentHostPinnedGuestReleaseSessions(t *testing.T){
 pub,priv:=testKey(t)
 old:=scope(1,1)
 fresh:=scope(4,3)
 c1,err:=rp.NewHostChallenge();if err!=nil{t.Fatal(err)}
 c2,err:=rp.NewHostChallenge();if err!=nil{t.Fatal(err)}
 if c1==c2||c1==([32]byte{})||c2==([32]byte{}){
  t.Fatal("host challenge repeated or blank")
 }
 a,err:=rp.NewAuthority(pub,old,c1);if err!=nil{t.Fatal(err)}
 b,err:=rp.NewAuthority(pub,fresh,c2);if err!=nil{t.Fatal(err)}
 down1:=signed(t,priv,old,c1,true,10)
 up1:=signed(t,priv,old,c1,false,11)
 denied(t,a.ConfirmUp(up1))
 if err:=a.ObserveDown(down1);err!=nil{t.Fatal(err)}
 denied(t,a.ConfirmUp(up1))
 if a.Reclaimable(){t.Fatal("ACK-only clearance allowed")}
 if err:=a.MarkQMPAcknowledged();err!=nil{t.Fatal(err)}
 if a.Reclaimable(){t.Fatal("QMP ACK alone cleared input")}
 if err:=a.ConfirmUp(up1);err!=nil{t.Fatal(err)}
 if !a.Reclaimable(){t.Fatal("valid guest UP not accepted")}
 denied(t,a.ConfirmUp(up1))
 denied(t,b.ObserveDown(down1))
 denied(t,b.ConfirmUp(up1))
 denied(t,b.MarkQMPAcknowledged())
 if b.Reclaimable(){t.Fatal("old signature made new lease available")}
 down2:=signed(t,priv,fresh,c2,true,12)
 up2:=signed(t,priv,fresh,c2,false,13)
 if err:=b.ObserveDown(down2);err!=nil{t.Fatal(err)}
 if err:=b.MarkQMPAcknowledged();err!=nil{t.Fatal(err)}
 if err:=b.ConfirmUp(up2);err!=nil{t.Fatal(err)}
 if !b.Reclaimable(){t.Fatal("new session did not complete")}
 t.Log("R27_RUNTIME_ED25519_TWO_LEASE_CHALLENGES=PASS")
}
func TestForgedScopesProofsAndReorderedEventsNeverRelease(t *testing.T){
 pub,priv:=testKey(t)
 _,wrongPriv:=testKey(t)
 s:=scope(1,1)
 challenge,err:=rp.NewHostChallenge();if err!=nil{t.Fatal(err)}
 a,err:=rp.NewAuthority(pub,s,challenge);if err!=nil{t.Fatal(err)}
 wrongKey:=signed(t,wrongPriv,s,challenge,true,10)
 denied(t,a.ObserveDown(wrongKey))
 stale:=s;stale.GuestEpoch="guest-reset"
 denied(t,a.ObserveDown(signed(t,priv,stale,challenge,true,10)))
 stale=s;stale.ReleaseSequence=3
 denied(t,a.ObserveDown(signed(t,priv,stale,challenge,true,10)))
 wrongChallenge,err:=rp.NewHostChallenge();if err!=nil{t.Fatal(err)}
 denied(t,a.ObserveDown(signed(t,priv,s,wrongChallenge,true,10)))
 badSource:=signed(t,priv,s,challenge,true,10)
 badSource.Source="qemu.serial"
 denied(t,a.ObserveDown(badSource))
 trueDown:=signed(t,priv,s,challenge,true,10)
 if err:=a.ObserveDown(trueDown);err!=nil{t.Fatal(err)}
 denied(t,a.ObserveDown(trueDown))
 if err:=a.MarkQMPAcknowledged();err!=nil{t.Fatal(err)}
 denied(t,a.MarkQMPAcknowledged())
 wrongUp:=signed(t,wrongPriv,s,challenge,false,11)
 denied(t,a.ConfirmUp(wrongUp))
 swapped:=signed(t,priv,s,challenge,false,11)
 swapped.Signature[0]^=1
 denied(t,a.ConfirmUp(swapped))
 stale=s;stale.LeaseEpoch="previous"
 denied(t,a.ConfirmUp(signed(t,priv,stale,challenge,false,11)))
 stale=s;stale.HostEpoch="old-host"
 denied(t,a.ConfirmUp(signed(t,priv,stale,challenge,false,11)))
 stale=s;stale.Generation++
 denied(t,a.ConfirmUp(signed(t,priv,stale,challenge,false,11)))
 denied(t,a.ConfirmUp(signed(t,priv,s,challenge,false,10)))
 denied(t,a.ConfirmUp(signed(t,priv,s,challenge,true,11)))
 wrongChallengeUp:=signed(t,priv,s,wrongChallenge,false,11)
 denied(t,a.ConfirmUp(wrongChallengeUp))
 if a.Reclaimable(){t.Fatal("forged or old claim cleared held input")}
 if err:=a.ConfirmUp(signed(t,priv,s,challenge,false,11));err!=nil{t.Fatal(err)}
 t.Log("R27_RUNTIME_ED25519_FORGERY_REPLAY_SCOPE_QUARANTINE=PASS")
}
func TestInvalidTrustAnchorOrChallengeCannotEnroll(t *testing.T){
 pub,priv:=testKey(t)
 challenge,_:=rp.NewHostChallenge()
 s:=scope(1,1)
 _,err:=rp.NewAuthority(nil,s,challenge);denied(t,err)
 _,err=rp.NewAuthority(pub,s,[32]byte{});denied(t,err)
 _,err=rp.NewAuthority(pub,releasegate.Scope{},challenge);denied(t,err)
 _,err=rp.Sign(nil,rp.Event{Scope:s,Challenge:challenge,EventSequence:1})
 denied(t,err)
 _,err=rp.Sign(priv,rp.Event{Scope:s,Challenge:challenge})
 denied(t,err)
 var nilAuthority *rp.Authority
 denied(t,nilAuthority.ObserveDown(rp.Event{}))
 denied(t,nilAuthority.MarkQMPAcknowledged())
 denied(t,nilAuthority.ConfirmUp(rp.Event{}))
 if nilAuthority.Reclaimable(){t.Fatal("nil verifier allowed release")}
 // A correct public key is insufficient without explicit host pinning.
 // The API never reads a key from guest data and refuses missing anchors.
 t.Log("R27_RUNTIME_NO_TOFU_OR_UNPINNED_KEY=PASS")
}
