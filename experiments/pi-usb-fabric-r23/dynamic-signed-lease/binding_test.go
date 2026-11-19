package dynamiclease

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "os"
 "path/filepath"
 "testing"

 "example.org/usb-fabric-r26-integrated/blue"
 "example.org/usb-fabric-r26-integrated/heldledger"
 gate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
 guest "example.org/usb-fabric-r22-guest-ed25519"
)

func setup(t *testing.T)(Binding,ed25519.PrivateKey){
 t.Helper()
 m:=blue.New("keyboard","xhci0/auto",nil)
 l,err:=m.Reserve("consumer-A","keyboard","xhci0/auto");if err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 var nonce [32]byte;if _,err=rand.Read(nonce[:]);err!=nil{t.Fatal(err)}
 b,err:=New(l,"host-r23-epoch","qemu-vm-r23-epoch","consumer-A-vm",1,nonce,pub)
 if err!=nil{t.Fatal(err)}
 if b.Scope.LeaseEpoch!=l.Epoch || b.Scope.Generation!=l.Generation || b.Scope.DeviceID!=l.Device{
  t.Fatal("R23 scope not bound to real generated blue.Lease")
 }
 return b,priv
}
func signed(t *testing.T,b Binding,priv ed25519.PrivateKey,down bool,seq uint64)evidence.Event{
 t.Helper()
 e,err:=guest.SignForDisposableGuest(evidence.Event{Scope:b.Scope,Source:"guest.evdev",KeyCode:"key-a",Down:down,EventSequence:seq},b.Nonce,priv)
 if err!=nil{t.Fatal(err)}
 return e
}
func held(t *testing.T)heldledger.Store {
 t.Helper()
 store:=heldledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
 st,err:=store.Transition(0,true);if err!=nil{t.Fatal(err)}
 if _,err=store.RequestRelease(st.Sequence);err!=nil{t.Fatal(err)}
 if _,err=store.AcknowledgeQMPRelease(st.Sequence);err!=nil{t.Fatal(err)} // TEST-only synthetic QMP ACK
 return store
}
func TestR23DynamicBlueLeaseEd25519ScopedGate(t *testing.T){
 b,priv:=setup(t)
 down,up:=signed(t,b,priv,true,100),signed(t,b,priv,false,101)
 g,bridge,err:=b.NewEvidenceGate();if err!=nil{t.Fatal(err)}
 if err=bridge.ObserveDown(down);err!=nil{t.Fatal(err)}
 if err=bridge.ConfirmUp(up);!errors.Is(err,evidence.ErrUntrusted){t.Fatalf("UP before QMP permitted: %v",err)}
 if err=g.RequestRelease(b.Scope);err!=nil{t.Fatal(err)}
 if err=g.AcknowledgeQMP(b.Scope);err!=nil{t.Fatal(err)}
 if bridge.Reclaimable(){t.Fatal("QMP ACK alone permitted release")}
 if err=bridge.ConfirmUp(up);err!=nil{t.Fatal(err)}
 if !bridge.Reclaimable(){t.Fatal("scoped signed release not accepted")}
 if err=bridge.ConfirmUp(up);!errors.Is(err,evidence.ErrUntrusted){t.Fatalf("replay permitted: %v",err)}
 store:=held(t)
 claim,err:=b.Claim(down,up);if err!=nil{t.Fatal(err)}
 st,err:=store.ConfirmGuestRelease(1,claim,b.Verifier(down,up))
 if err!=nil||st.Held{t.Fatalf("durable dynamic scope not released: %+v %v",st,err)}
 t.Log("R23_B_DYNAMIC_BLUE_LEASE_ED25519_R26_GATE_AND_LEDGER=PASS")
 t.Log("R23_B_ACTUAL_QEMU_DYNAMIC_SCOPE_PROVISIONING=NOT_TESTED")
}
func TestR23AttackerFirstAndStaleLeaseCannotClearHeld(t *testing.T){
 b,priv:=setup(t)
 goodDown,goodUp:=signed(t,b,priv,true,100),signed(t,b,priv,false,101)
 store:=held(t);orig,err:=os.ReadFile(store.Path);if err!=nil{t.Fatal(err)}
 foreignPub,foreignPriv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 attacker:=signed(t,b,foreignPriv,true,100)
 if b.Verify(attacker){t.Fatal("correct-scope attacker-first with foreign signing key accepted")}
 wrong:=b;wrong.PublicKey=foreignPub
 if wrong.Verify(goodDown){t.Fatal("valid signed event accepted against foreign pinned key")}
 candidates:=[]evidence.Event{}
 c:=goodUp;c.Scope.Generation++;candidates=append(candidates,c)
 c=goodUp;c.Scope.LeaseEpoch="stale-lease";candidates=append(candidates,c)
 c=goodUp;c.Scope.GuestEpoch="stale-vm";candidates=append(candidates,c)
 c=goodUp;c.Scope.HostEpoch="stale-host";candidates=append(candidates,c)
 c=goodUp;c.Scope.ReleaseSequence++;candidates=append(candidates,c)
 c=goodUp;c.Source="usbip.detach";candidates=append(candidates,c)
 c=goodUp;c.EventSequence++;candidates=append(candidates,c)
 for _,bad:=range candidates{
  if b.Verify(bad){t.Fatal("tampered scope or transport accepted")}
  if _,err=store.ConfirmGuestRelease(1,heldledger.ReleaseClaim{
   GuestID:b.Scope.GuestID,DeviceID:b.Scope.DeviceID,
   HostEpoch:b.Scope.HostEpoch,GuestEpoch:b.Scope.GuestEpoch,LeaseEpoch:b.Scope.LeaseEpoch,
   Generation:b.Scope.Generation,ReleaseSequence:b.Scope.ReleaseSequence,
   DownEventSequence:100,EventSequence:bad.EventSequence,
   Source:bad.Source,Key:heldledger.KeyA,KeyReleased:true,Proof:bad.Proof,
  },b.Verifier(goodDown,bad));!errors.Is(err,heldledger.ErrUnverified){t.Fatalf("bad proof cleared HELD: %v",err)}
  after,_:=os.ReadFile(store.Path);if !bytes.Equal(orig,after){t.Fatal("invalid proof mutated held bytes")}
 }
 badUp:=signed(t,b,priv,false,99)
 if _,err=b.Claim(goodDown,badUp);!errors.Is(err,ErrBinding){t.Fatalf("out-of-order signed event accepted: %v",err)}
 var nonce2 [32]byte;copy(nonce2[:],b.Nonce[:]);nonce2[0]^=0x42
 revised:=b;revised.Nonce=nonce2
 if revised.Verify(goodDown){t.Fatal("old challenge accepted")}
 newManager:=blue.New("keyboard","xhci0/auto",nil)
 newLease,err:=newManager.Reserve("consumer-A","keyboard","xhci0/auto");if err!=nil{t.Fatal(err)}
 newest,err:=New(newLease,b.Scope.HostEpoch,"new-VM","consumer-A-vm",1,b.Nonce,b.PublicKey)
 if err!=nil{t.Fatal(err)}
 if newest.Verify(goodUp){t.Fatal("old VM lease replay accepted")}
 t.Log("R23_B_PINNED_KEY_ATTACKER_FIRST_DYNAMIC_EPOCH_REPLAY_DENIED=PASS")
 t.Log("R23_B_REJECTED_CLAIMS_PRESERVE_BYTE_IDENTICAL_HELD=PASS")
}
func TestR23RejectUnboundOrMissingApprovedIdentity(t *testing.T){
 b,_:=setup(t)
 _,err:=New(blue.Lease{},b.Scope.HostEpoch,b.Scope.GuestEpoch,b.Scope.GuestID,1,b.Nonce,b.PublicKey)
 if !errors.Is(err,ErrBinding){t.Fatal("missing active blue lease accepted")}
 _,err=New(b.Lease,b.Scope.HostEpoch,b.Scope.GuestEpoch,b.Scope.GuestID,1,b.Nonce,nil)
 if !errors.Is(err,ErrBinding){t.Fatal("guest-supplied key admitted without approved pin")}
 _,err=New(b.Lease,b.Scope.HostEpoch,"",b.Scope.GuestID,1,b.Nonce,b.PublicKey)
 if !errors.Is(err,ErrBinding){t.Fatal("unbound VM epoch accepted")}
 t.Log("R23_B_MISSING_HOST_APPROVED_LEASE_OR_KEY_REFUSED=PASS")
}
var _=gate.ErrDenied
