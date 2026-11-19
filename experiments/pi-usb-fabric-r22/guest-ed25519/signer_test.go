package guestsign

import (
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "testing"

 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
)

func scope()releasegate.Scope{
 return releasegate.Scope{GuestID:"r22-disposable-test",DeviceID:"usb-kbd-a",HostEpoch:"h1",GuestEpoch:"g1",LeaseEpoch:"l1",Generation:1,ReleaseSequence:1}
}
func event(down bool,seq uint64)evidence.Event{
 return evidence.Event{Scope:scope(),Source:"guest.evdev",KeyCode:"key-a",Down:down,EventSequence:seq}
}
func fixture(t *testing.T)(ed25519.PublicKey,ed25519.PrivateKey,[32]byte){
 t.Helper()
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 var nonce [32]byte;if _,err=rand.Read(nonce[:]);err!=nil{t.Fatal(err)}
 return pub,priv,nonce
}
func TestR22ScopedEd25519ReusesActualR26EvidenceBridge(t *testing.T){
 pub,priv,nonce:=fixture(t)
 gate,err:=releasegate.New(scope());if err!=nil{t.Fatal(err)}
 bridge,err:=evidence.New(gate,scope(),func(e evidence.Event)bool{return VerifyWithPinnedPublicKey(e,nonce,pub)})
 if err!=nil{t.Fatal(err)}
 down,err:=SignForDisposableGuest(event(true,10),nonce,priv);if err!=nil{t.Fatal(err)}
 up,err:=SignForDisposableGuest(event(false,11),nonce,priv);if err!=nil{t.Fatal(err)}
 if err=bridge.ObserveDown(down);err!=nil{t.Fatal(err)}
 if err=bridge.ConfirmUp(up);!errors.Is(err,evidence.ErrUntrusted){t.Fatalf("unacked QMP accepted: %v",err)}
 if err=gate.RequestRelease(scope());err!=nil{t.Fatal(err)}
 if err=gate.AcknowledgeQMP(scope());err!=nil{t.Fatal(err)}
 if bridge.Reclaimable(){t.Fatal("QMP ACK alone cleared held")}
 if err=bridge.ConfirmUp(up);err!=nil{t.Fatal(err)}
 if !bridge.Reclaimable(){t.Fatal("fresh signed TEST proof not accepted")}
 if err=bridge.ConfirmUp(up);!errors.Is(err,evidence.ErrUntrusted){t.Fatalf("proof replay accepted: %v",err)}
 t.Log("R22_A_EXISTING_R26_QMP_EVIDENCE_GATE_TEST_ED25519=PASS")
 t.Log("R22_A_REAL_GUEST_KEY_RESIDENCY_ATTESTATION=NOT_TESTED")
}
func TestR22WrongChallengeScopeAndForeignSignerRefused(t *testing.T){
 pub,priv,nonce:=fixture(t)
 foreignPub,_,_:=fixture(t)
 up,err:=SignForDisposableGuest(event(false,11),nonce,priv);if err!=nil{t.Fatal(err)}
 wrong:=nonce;wrong[0]^=0xff
 if VerifyWithPinnedPublicKey(up,wrong,pub){t.Fatal("wrong challenge accepted")}
 if VerifyWithPinnedPublicKey(up,nonce,foreignPub){t.Fatal("foreign key accepted")}
 var cases []evidence.Event
 e:=up;e.Scope.Generation=2;cases=append(cases,e)
 e=up;e.Scope.GuestEpoch="other";cases=append(cases,e)
 e=up;e.Scope.HostEpoch="other";cases=append(cases,e)
 e=up;e.Scope.LeaseEpoch="other";cases=append(cases,e)
 e=up;e.EventSequence=12;cases=append(cases,e)
 e=up;e.Source="usbip.detach";cases=append(cases,e)
 e=up;e.KeyCode="key-b";cases=append(cases,e)
 e=up;e.Down=true;cases=append(cases,e)
 e=up;e.Proof="bad";cases=append(cases,e)
 for i,c:=range cases{if VerifyWithPinnedPublicKey(c,nonce,pub){t.Fatalf("tamper %d admitted",i)}}
 var zero [32]byte
 if _,err=SignForDisposableGuest(event(true,10),zero,priv);!errors.Is(err,ErrInvalid){t.Fatal("no challenge accepted",err)}
 t.Log("R22_A_PINNED_KEY_NONCE_SCOPE_TAMPER_DENIED=PASS")
}
