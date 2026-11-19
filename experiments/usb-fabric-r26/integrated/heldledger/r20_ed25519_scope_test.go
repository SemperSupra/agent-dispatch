package heldledger

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

// R20 is TEST-ONLY cryptographic verifier qualification over the EXISTING
// heldledger state machine, NOT a guest-key provisioning/attestation service.
// The keypair lives only in this test runner. No production trust asserted.
func r20WireClaim(c ReleaseClaim) []byte {
 c.Proof=""
 b,err:=json.Marshal(c)
 if err!=nil {panic(err)}
 return b
}
func r20Sign(c ReleaseClaim,k ed25519.PrivateKey) ReleaseClaim{
 c.Proof=hex.EncodeToString(ed25519.Sign(k,r20WireClaim(c)))
 return c
}
func r20Verifier(pub ed25519.PublicKey,scope ReleaseClaim) ReleaseVerifier {
 return func(c ReleaseClaim)bool {
  if c.GuestID!=scope.GuestID||c.DeviceID!=scope.DeviceID||
   c.HostEpoch!=scope.HostEpoch||c.GuestEpoch!=scope.GuestEpoch||
   c.LeaseEpoch!=scope.LeaseEpoch||c.Generation!=scope.Generation||
   c.ReleaseSequence!=scope.ReleaseSequence||
   c.Source!="guest.evdev"||c.Key!=KeyA||!c.KeyReleased{
   return false
  }
  b,err:=hex.DecodeString(c.Proof)
  return err==nil&&ed25519.Verify(pub,r20WireClaim(c),b)
 }
}
func TestR20Ed25519ScopedReleaseClaimsCannotClearWrongHeldLease(t *testing.T){
 pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 _,foreign,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 store:=Store{Path:filepath.Join(t.TempDir(),"held.json")}
 first,err:=store.Transition(0,true)
 if err!=nil||!first.Held||first.Sequence!=1 {t.Fatalf("initial: %+v %v",first,err)}
 stage(t,store,1) // TEST-ONLY QMP-ACK stage, not actual QMP
 initial,err:=os.ReadFile(store.Path)
 if err!=nil{t.Fatal(err)}
 scope:=claim(1,40,41)
 valid:=r20Sign(scope,priv)
 verify:=r20Verifier(pub,scope)
 if !verify(valid){t.Fatal("fresh ed25519 fixture must be valid")}
 fixtures:=[]struct{
  name string
  c ReleaseClaim
 }{
  {"wrong guest",func()ReleaseClaim{c:=valid;c.GuestID="other-guest";return r20Sign(c,priv)}()},
  {"wrong device",func()ReleaseClaim{c:=valid;c.DeviceID="other-device";return r20Sign(c,priv)}()},
  {"wrong host epoch",func()ReleaseClaim{c:=valid;c.HostEpoch="host-restarted";return r20Sign(c,priv)}()},
  {"wrong guest epoch",func()ReleaseClaim{c:=valid;c.GuestEpoch="guest-reset";return r20Sign(c,priv)}()},
  {"wrong lease epoch",func()ReleaseClaim{c:=valid;c.LeaseEpoch="old-lease";return r20Sign(c,priv)}()},
  {"wrong generation",func()ReleaseClaim{c:=valid;c.Generation=9;return r20Sign(c,priv)}()},
  {"wrong release sequence",func()ReleaseClaim{c:=valid;c.ReleaseSequence=99;return r20Sign(c,priv)}()},
  {"transport detach with valid signature",func()ReleaseClaim{c:=valid;c.Source="usbip.detach";return r20Sign(c,priv)}()},
  {"kernel device removed with valid signature",func()ReleaseClaim{c:=valid;c.Source="kernel.device_removed";return r20Sign(c,priv)}()},
  {"other key with valid signature",func()ReleaseClaim{c:=valid;c.Key="key-b";return r20Sign(c,priv)}()},
  {"release flag false with signature",func()ReleaseClaim{c:=valid;c.KeyReleased=false;return r20Sign(c,priv)}()},
  {"signed wrong guest key",r20Sign(scope,foreign)},
  {"tampered up event after signature",func()ReleaseClaim{c:=valid;c.EventSequence=42;return c}()},
  {"tampered key-down after signature",func()ReleaseClaim{c:=valid;c.DownEventSequence=39;return c}()},
  {"out of order with signature",func()ReleaseClaim{c:=valid;c.EventSequence=39;return r20Sign(c,priv)}()},
  {"empty proof",func()ReleaseClaim{c:=valid;c.Proof="";return c}()},
 }
 for _,tc:=range fixtures{
  t.Run(tc.name,func(t *testing.T){
   if _,err:=store.ConfirmGuestRelease(1,tc.c,verify);!errors.Is(err,ErrUnverified){
    t.Fatalf("R20_UNAUTHORIZED_ED25519_PROOF_ACCEPTED name=%s err=%v",tc.name,err)
   }
   got,err:=os.ReadFile(store.Path)
   if err!=nil||!bytes.Equal(initial,got){t.Fatalf("R20_DENIED_PROOF_MUTATED_FSYNC_HELD_JOURNAL name=%s err=%v",tc.name,err)}
  })
 }
 t.Log("R20_ED25519_SCOPE_TAMPER_FOREIGN_SIGNER_TRANSPORT_DENIED=PASS")
 // No trust decisions based only on a high-water hash or encoded signature.
 clean,err:=store.ConfirmGuestRelease(1,valid,verify)
 if err!=nil||clean.Held||clean.Sequence!=2||clean.LastReleaseEventSequence!=41{
  t.Fatalf("R20_VALID_ED25519_GUEST_RELEASE_DENIED %+v %v",clean,err)
 }
 t.Log("R20_TEST_ONLY_ED25519_FRESH_SCOPED_RELEASE=PASS")
 if _,err:=store.ConfirmGuestRelease(1,valid,verify);!errors.Is(err,ErrUnverified){
  t.Fatalf("R20_REUSED_PROOF_AFTER_CLEAR_ACCEPTED=%v",err)
 }
 second,err:=store.Transition(2,true)
 if err!=nil||!second.Held||second.Sequence!=3{t.Fatalf("second held: %+v %v",second,err)}
 stage(t,store,3)
 before,err:=os.ReadFile(store.Path);if err!=nil{t.Fatal(err)}
 secondScope:=claim(3,42,43)
 secondVerify:=r20Verifier(pub,secondScope)
 replay:=r20Sign(valid,priv)
 if _,err:=store.ConfirmGuestRelease(3,replay,secondVerify);!errors.Is(err,ErrUnverified){
  t.Fatalf("R20_PREVIOUS_LEASE_ED25519_SIGNATURE_REPLAY_ACCEPTED=%v",err)
 }
 // A fresh signature over a new UP cannot justify an old DOWN event.
 staleDown:=r20Sign(claim(3,40,43),priv)
 if _,err:=store.ConfirmGuestRelease(3,staleDown,secondVerify);!errors.Is(err,ErrUnverified){
  t.Fatalf("R20_VALID_SIGNATURE_STALE_DOWN_EVENT_ACCEPTED=%v",err)
 }
 after,err:=os.ReadFile(store.Path)
 if err!=nil||!bytes.Equal(before,after){t.Fatalf("R20_REPLAY_MUTATED_NEW_HELD_JOURNAL err=%v",err)}
 final,err:=store.ConfirmGuestRelease(3,r20Sign(secondScope,priv),secondVerify)
 if err!=nil||final.Held||final.LastReleaseEventSequence!=43||final.Sequence!=4{
  t.Fatalf("R20_SECOND_FRESH_PROOF_NOT_ADMITTED %+v %v",final,err)
 }
 t.Log("R20_ED25519_CROSS_LEASE_REPLAY_AND_STALE_DOWN_DENIED=PASS")
}
