package liveevdevproof

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

 ledger "example.org/usb-fabric-r26-integrated/heldledger"
)

func TestR21TraceParserRejectsTransportAndOutOfOrder(t *testing.T){
 good:="USBFABRIC_R06_REAL_KEY_A_DOWN=PASS\nUSBFABRIC_R06_REAL_KEY_A_UP=PASS\n"
 if _,err:=ParseGuestEvdevConsole(good);err!=nil{t.Fatal(err)}
 for _,bad:=range []string{
  "R08_CONSUMER_DETACH=PASS\n",
  "USBFABRIC_R06_REAL_KEY_A_UP=PASS\nUSBFABRIC_R06_REAL_KEY_A_DOWN=PASS\n",
  "USBFABRIC_R06_REAL_KEY_A_DOWN=PASS\n",
  "prefix USBFABRIC_R06_REAL_KEY_A_DOWN=PASS\nUSBFABRIC_R06_REAL_KEY_A_UP=PASS\n",
  "USBFABRIC_R06_REAL_KEY_A_DOWN=PASS\nUSBFABRIC_R06_REAL_KEY_A_DOWN=PASS\nUSBFABRIC_R06_REAL_KEY_A_UP=PASS\n",
 }{
  if _,err:=ParseGuestEvdevConsole(bad);!errors.Is(err,ErrIncomplete){t.Fatalf("trace wrongly accepted %q: %v",bad,err)}
 }
 t.Log("R21_B_GUEST_CONSOLE_PARSER_NEGATIVE_CRITICS=PASS")
}

// This derives a scoped test-only receipt from a *fixture*. It demonstrates
// glue to existing heldledger, not genuine kernel provenance or guest signing.
func TestR21ScopedFixtureToExistingDurableJournal(t *testing.T){
 raw:="USBFABRIC_R06_REAL_KEY_A_DOWN=PASS\nUSBFABRIC_R06_REAL_KEY_A_UP=PASS\n"
 witness,err:=ParseGuestEvdevConsole(raw);if err!=nil || !witness.Down || !witness.Up {t.Fatal(err)}
 store:=ledger.Store{Path:filepath.Join(t.TempDir(),"held.json")}
 st,err:=store.Transition(0,true);if err!=nil{t.Fatal(err)}
 if _,err=store.RequestRelease(st.Sequence);err!=nil{t.Fatal(err)}
 if _,err=store.AcknowledgeQMPRelease(st.Sequence);err!=nil{t.Fatal(err)} // simulated QMP ACK
 before,err:=os.ReadFile(store.Path);if err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 scope:=ledger.ReleaseClaim{GuestID:"r21-test-fixture",DeviceID:"keyboard",HostEpoch:"host-1",GuestEpoch:"guest-1",LeaseEpoch:"lease-1",Generation:1,ReleaseSequence:1,DownEventSequence:10,EventSequence:11,Source:"guest.evdev",Key:ledger.KeyA,KeyReleased:true}
 wire:=func(c ledger.ReleaseClaim)[]byte {c.Proof="";b,e:=json.Marshal(c);if e!=nil{panic(e)};return b}
 sign:=func(c ledger.ReleaseClaim)ledger.ReleaseClaim {c.Proof=hex.EncodeToString(ed25519.Sign(priv,wire(c)));return c}
 verifier:=func(c ledger.ReleaseClaim)bool{
  if c.GuestID!=scope.GuestID||c.DeviceID!=scope.DeviceID||c.HostEpoch!=scope.HostEpoch||c.GuestEpoch!=scope.GuestEpoch||c.LeaseEpoch!=scope.LeaseEpoch||c.Generation!=scope.Generation||c.ReleaseSequence!=scope.ReleaseSequence||c.Source!="guest.evdev"||c.Key!=ledger.KeyA||!c.KeyReleased{return false}
  sig,e:=hex.DecodeString(c.Proof);return e==nil&&ed25519.Verify(pub,wire(c),sig)
 }
 bad:=scope;bad.Source="usbip.detach";bad=sign(bad)
 if _,err=store.ConfirmGuestRelease(1,bad,verifier);!errors.Is(err,ledger.ErrUnverified){t.Fatal("transport-only proof accepted",err)}
 after,_:=os.ReadFile(store.Path);if !bytes.Equal(before,after){t.Fatal("rejected receipt mutated journal")}
 valid:=sign(scope)
 clean,err:=store.ConfirmGuestRelease(1,valid,verifier);if err!=nil||clean.Held{t.Fatalf("valid test fixture refused %+v %v",clean,err)}
 if _,err=store.ConfirmGuestRelease(1,valid,verifier);!errors.Is(err,ledger.ErrUnverified){t.Fatal("replay accepted",err)}
 t.Log("R21_B_CONSOLE_FIXTURE_TO_SCOPED_SIGNATURE_LEDGER=PASS")
 t.Log("R21_B_REAL_GUEST_SIGNED_EVDEV=NOT_TESTED")
}
