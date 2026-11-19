package liveevdevproof

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "strings"
 "testing"

 ledger "example.org/usb-fabric-r26-integrated/heldledger"
)

// This independent experiment reads the ACTUAL consumer-A Linux kernel
// console from the pinned three-QEMU-guest R20 harness. UART is an
// unauthenticated lab transcript. The signer is HOST-SIDE TEST-ONLY.
// Do not call it guest-held attestation or production admission proof.
func TestR21ObservedQEMUEvdevToSignedHeldRelease(t *testing.T) {
 path:=os.Getenv("R21_REAL_QEMU_LOG")
 if path=="" {
  if os.Getenv("R21_REQUIRE_QEMU_TRACE")=="1"{t.Fatal("missing real QEMU trace")}
  t.Skip("live three-kernel trace provided only by dedicated workflow stage")
 }
 raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 text:=string(raw)
 const begin="R10_CONSUMER_A_SERIAL_BEGIN"
 const end="R10_CONSUMER_A_SERIAL_END"
 if strings.Count(text,begin)!=1||strings.Count(text,end)!=1{t.Fatal("missing or duplicate consumer A boundaries")}
 a:=strings.Index(text,begin)
 b:=strings.Index(text,end)
 if b<=a {t.Fatal("misordered first-hand guest console boundaries")}
 console:=text[a+len(begin):b]
 witness,err:=ParseGuestEvdevConsole(console)
 if err!=nil || !witness.Down || !witness.Up{t.Fatalf("real guest evdev markers invalid: %v",err)}
 if !strings.Contains(console,"R08_CONSUMER_REAL_REMOTE_HID_DATA=PASS") ||
  !strings.Contains(console,"R08_CONSUMER_REAL_REMOTE_VHCI_ATTACH=PASS") ||
  !strings.Contains(text,"R20_B_POST_KILL_NATIVE_USBIP_IMPORT_DENIED=PASS") ||
  !strings.Contains(text,"R20_PROVIDER_VUDC_REMAINS_UNBOUND_AFTER_KILL=PASS") {
  t.Fatal("missing independent USBIP transport preconditions")
 }
 t.Log("R21_B_ACTUAL_THIRD_KERNEL_QEMU_GUEST_EVDEV_OBSERVED=PASS")
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 var challenge [16]byte
 if _,err=rand.Read(challenge[:]);err!=nil{t.Fatal(err)}
 store:=ledger.Store{Path:t.TempDir()+"/held.json"}
 held,err:=store.Transition(0,true);if err!=nil{t.Fatal(err)}
 if _,err=store.RequestRelease(held.Sequence);err!=nil{t.Fatal(err)}
 if _,err=store.AcknowledgeQMPRelease(held.Sequence);err!=nil{t.Fatal(err)} // TEST-ONLY ACK
 // The host test adapter assigns synthetic counters to observed events;
 // the guest UART has NO cryptographically authenticated event sequences.
 scope:=ledger.ReleaseClaim{GuestID:"qemu-consumer-a-unauthenticated",DeviceID:"keyboard",HostEpoch:fmt.Sprintf("test-host-challenge-%x",challenge),GuestEpoch:"qemu-guest-epoch-TEST",LeaseEpoch:"lease-epoch-TEST",Generation:1,ReleaseSequence:1,DownEventSequence:100,EventSequence:101,Source:"guest.evdev",Key:ledger.KeyA,KeyReleased:true}
 wire:=func(c ledger.ReleaseClaim)[]byte{c.Proof="";b,e:=json.Marshal(c);if e!=nil{panic(e)};return b}
 sign:=func(c ledger.ReleaseClaim)ledger.ReleaseClaim{c.Proof=hex.EncodeToString(ed25519.Sign(priv,wire(c)));return c}
 verify:=func(c ledger.ReleaseClaim)bool {
  if c.GuestID!=scope.GuestID||c.DeviceID!=scope.DeviceID||c.HostEpoch!=scope.HostEpoch||c.GuestEpoch!=scope.GuestEpoch||c.LeaseEpoch!=scope.LeaseEpoch||c.Generation!=scope.Generation||c.ReleaseSequence!=scope.ReleaseSequence||c.Key!=ledger.KeyA||c.Source!="guest.evdev"||!c.KeyReleased {return false}
  sig,e:=hex.DecodeString(c.Proof);return e==nil&&ed25519.Verify(pub,wire(c),sig)
 }
 orig,err:=os.ReadFile(store.Path);if err!=nil{t.Fatal(err)}
 wrong:=scope;wrong.HostEpoch="replayed-challenge";wrong=sign(wrong)
 transport:=scope;transport.Source="usbip.detach";transport=sign(transport)
 for _,c:=range []ledger.ReleaseClaim{wrong,transport} {
  if _,err:=store.ConfirmGuestRelease(1,c,verify);!errors.Is(err,ledger.ErrUnverified){t.Fatalf("bad evidence cleared HELD: %v",err)}
  now,e:=os.ReadFile(store.Path);if e!=nil||!bytes.Equal(now,orig){t.Fatalf("bad proof mutated disk: %v",e)}
 }
 good:=sign(scope)
 state,err:=store.ConfirmGuestRelease(1,good,verify);if err!=nil||state.Held||state.Sequence!=2{t.Fatalf("test-only signed proof failed: %+v %v",state,err)}
 if _,err=store.ConfirmGuestRelease(1,good,verify);!errors.Is(err,ledger.ErrUnverified){t.Fatal("signed release replay not denied")}
 t.Log("R21_B_LIVE_QEMU_EVDEV_TEST_BRIDGE=PASS")
 t.Log("R21_B_GUEST_HELD_SIGNATURE_AND_REAL_QMP=NOT_TESTED")
}
