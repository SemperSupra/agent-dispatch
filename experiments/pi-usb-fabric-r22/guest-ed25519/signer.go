// Package guestsign reuses R26 evidence.Event and releasegate.Scope.
// The caller must pin the verifier key independently. TEST-ONLY: a runner
// generated key is NOT a protected guest identity or production attestation.
package guestsign

import (
 "crypto/ed25519"
 "encoding/hex"
 "encoding/json"
 "errors"
 "example.org/usb-fabric-r26-releasegate/evidence"
)

var ErrInvalid=errors.New("guest Ed25519 evidence: invalid scope/challenge/key/event")

type envelope struct {
 Domain string
 Event evidence.Event
 Challenge [32]byte
}
func signable(e evidence.Event,challenge [32]byte)([]byte,error){
 if challenge==([32]byte{}) || e.Source!="guest.evdev" || e.KeyCode!="key-a" ||
  e.EventSequence==0 || e.Scope.GuestID=="" || e.Scope.DeviceID=="" ||
  e.Scope.HostEpoch=="" || e.Scope.GuestEpoch=="" || e.Scope.LeaseEpoch=="" ||
  e.Scope.Generation==0 || e.Scope.ReleaseSequence==0{return nil,ErrInvalid}
 e.Proof=""
 return json.Marshal(envelope{Domain:"USB-FABRIC-R22-TEST-ONLY-ED25519-v1",Event:e,Challenge:challenge})
}
func SignForDisposableGuest(e evidence.Event,challenge [32]byte,private ed25519.PrivateKey)(evidence.Event,error){
 if len(private)!=ed25519.PrivateKeySize{return evidence.Event{},ErrInvalid}
 b,err:=signable(e,challenge);if err!=nil{return evidence.Event{},err}
 e.Proof=hex.EncodeToString(ed25519.Sign(private,b))
 return e,nil
}
func VerifyWithPinnedPublicKey(e evidence.Event,challenge [32]byte,pub ed25519.PublicKey)bool{
 if len(pub)!=ed25519.PublicKeySize || len(e.Proof)!=ed25519.SignatureSize*2{return false}
 sig,err:=hex.DecodeString(e.Proof);if err!=nil{return false}
 b,err:=signable(e,challenge)
 return err==nil&&ed25519.Verify(pub,b,sig)
}
