// Package dynamiclease composes the EXISTING R26 lease and evidence types
// with R22's Ed25519 verifier. It is not a QMP client, broker or USB/IP stack.
// A key is provisioned by the host test BEFORE receiving guest events.
// The host-side fixture also knows its private key: NOT production identity.
package dynamiclease

import (
 "crypto/ed25519"
 "errors"

 "example.org/usb-fabric-r26-integrated/blue"
 "example.org/usb-fabric-r26-integrated/heldledger"
 gate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
 guest "example.org/usb-fabric-r22-guest-ed25519"
)

var ErrBinding=errors.New("R23: dynamic lease/provisioned identity required")

type Binding struct {
 Lease blue.Lease
 Scope gate.Scope
 Nonce [32]byte
 PublicKey ed25519.PublicKey
}
func New(lease blue.Lease,hostEpoch,guestEpoch,guestID string,releaseSequence uint64,challenge [32]byte,pinnedPub ed25519.PublicKey)(Binding,error){
 if lease.Device==""||lease.Port==""||lease.Actor==""||lease.Epoch==""||lease.Generation==0||
  hostEpoch==""||guestEpoch==""||guestID==""||releaseSequence==0||
  challenge==([32]byte{})||len(pinnedPub)!=ed25519.PublicKeySize{return Binding{},ErrBinding}
 scope:=gate.Scope{GuestID:guestID,DeviceID:lease.Device,HostEpoch:hostEpoch,
  GuestEpoch:guestEpoch,LeaseEpoch:lease.Epoch,Generation:lease.Generation,ReleaseSequence:releaseSequence}
 return Binding{Lease:lease,Scope:scope,Nonce:challenge,PublicKey:append(ed25519.PublicKey(nil),pinnedPub...)},nil
}
func(b Binding) Verify(e evidence.Event)bool {
 return e.Scope==b.Scope && e.Source=="guest.evdev" && e.KeyCode=="key-a" &&
  e.EventSequence>0 && guest.VerifyWithPinnedPublicKey(e,b.Nonce,b.PublicKey)
}
func(b Binding) NewEvidenceGate()(*gate.Gate,*evidence.Bridge,error){
 g,err:=gate.New(b.Scope);if err!=nil{return nil,nil,err}
 bridge,err:=evidence.New(g,b.Scope,b.Verify)
 return g,bridge,err
}
func(b Binding) Claim(down,up evidence.Event)(heldledger.ReleaseClaim,error){
 if !down.Down||up.Down||!b.Verify(down)||!b.Verify(up)||down.EventSequence>=up.EventSequence {
  return heldledger.ReleaseClaim{},ErrBinding
 }
 s:=b.Scope
 return heldledger.ReleaseClaim{
  GuestID:s.GuestID,DeviceID:s.DeviceID,HostEpoch:s.HostEpoch,
  GuestEpoch:s.GuestEpoch,LeaseEpoch:s.LeaseEpoch,Generation:s.Generation,
  ReleaseSequence:s.ReleaseSequence,DownEventSequence:down.EventSequence,
  EventSequence:up.EventSequence,Source:"guest.evdev",Key:heldledger.KeyA,
  KeyReleased:true,Proof:up.Proof,
 },nil
}
// Verifier is for the existing durable journal. The caller MUST separately
// require original R26 Gate.Reclaimable(), genuine QMP ACK and stable host
// exporter ownership; signature validity ALONE must not open USB/IP.
func(b Binding) Verifier(down,up evidence.Event)heldledger.ReleaseVerifier {
 wanted,err:=b.Claim(down,up)
 return func(c heldledger.ReleaseClaim)bool{
  return err==nil && c==wanted && b.Verify(down) && b.Verify(up)
 }
}
