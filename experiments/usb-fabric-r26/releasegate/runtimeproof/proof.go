// Package runtimeproof implements lease-scoped Ed25519 guest event checking.
//
// SECURITY BOUNDARY: The host controller MUST pin the guest public key via an
// independently authenticated VM provisioning/attestation channel, and create
// a cryptographically random per-lease challenge. A public key learned from
// this SAME guest-controlled virtio channel provides NO guest identity proof.
// No static test keys, automatic trust-on-first-use, or production key storage
// are supplied by this package. All event data remains untrusted until verified.
package runtimeproof

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/binary"
 "errors"
 "io"
 "sync"

 releasegate "example.org/usb-fabric-r26-releasegate"
)

var ErrUntrusted=errors.New("runtimeproof: untrusted or stale guest receipt")
const Domain="USB-Fabric-R27-Guest-EVKEY-Ed25519-v1"

type Event struct{
 Scope releasegate.Scope `json:"scope"`
 Challenge [32]byte `json:"challenge"`
 Source string `json:"source"`
 KeyCode string `json:"key_code"`
 Down bool `json:"down"`
 EventSequence uint64 `json:"event_sequence"`
 Signature []byte `json:"signature"`
}

// Canonical length-delimited binary input prevents delimiter or JSON
// reserialization ambiguities. Domain separation prevents cross-protocol
// authentication confusion. Never sign opaque frontend-controlled strings.
func message(e Event)[]byte{
 var b bytes.Buffer
 b.WriteString(Domain)
 b.WriteByte(0)
 b.Write(e.Challenge[:])
 str:=func(s string){
  var n [4]byte
  binary.BigEndian.PutUint32(n[:],uint32(len(s)))
  b.Write(n[:]);b.WriteString(s)
 }
 u64:=func(v uint64){var n [8]byte;binary.BigEndian.PutUint64(n[:],v);b.Write(n[:])}
 str(e.Scope.GuestID);str(e.Scope.DeviceID)
 str(e.Scope.HostEpoch);str(e.Scope.GuestEpoch)
 str(e.Scope.LeaseEpoch)
 u64(e.Scope.Generation);u64(e.Scope.ReleaseSequence)
 str(e.Source);str(e.KeyCode)
 if e.Down{b.WriteByte(1)}else{b.WriteByte(0)}
 u64(e.EventSequence)
 return b.Bytes()
}

func Sign(priv ed25519.PrivateKey,e Event)(Event,error){
 if len(priv)!=ed25519.PrivateKeySize||e.EventSequence==0{return Event{},ErrUntrusted}
 e.Signature=ed25519.Sign(priv,message(e))
 return e,nil
}

func NewHostChallenge()([32]byte,error){
 var c [32]byte
 if _,err:=io.ReadFull(rand.Reader,c[:]);err!=nil{return c,err}
 if c==([32]byte{}){return c,ErrUntrusted}
 return c,nil
}

type Authority struct{
 mu sync.Mutex
 public ed25519.PublicKey
 scope releasegate.Scope
 challenge [32]byte
 last uint64
 down uint64
 acked bool
 confirmed bool
}

// NewAuthority MUST be called ONLY with a trusted, pre-pinned guest public
// key. The host should never invoke this using an unauthenticated guest
// announcement or a client-provided public key.
func NewAuthority(pinned ed25519.PublicKey,scope releasegate.Scope,challenge [32]byte)(*Authority,error){
 if len(pinned)!=ed25519.PublicKeySize||challenge==([32]byte{})||
  scope.GuestID==""||scope.DeviceID==""||
  scope.HostEpoch==""||scope.GuestEpoch==""||scope.LeaseEpoch==""||
  scope.Generation==0||scope.ReleaseSequence==0{
  return nil,ErrUntrusted
 }
 p:=make([]byte,ed25519.PublicKeySize)
 copy(p,pinned)
 return &Authority{public:p,scope:scope,challenge:challenge},nil
}
func (a *Authority)allowed(e Event,down bool)bool {
 return a!=nil && e.Scope==a.scope && e.Challenge==a.challenge &&
  e.Source=="guest.evdev" && e.KeyCode=="key-a" && e.Down==down &&
  e.EventSequence>0 && len(e.Signature)==ed25519.SignatureSize &&
  ed25519.Verify(a.public,message(e),e.Signature)
}
func (a *Authority)ObserveDown(e Event)error {
 if a==nil{return ErrUntrusted}
 a.mu.Lock();defer a.mu.Unlock()
 if a.down!=0||a.acked||a.confirmed||
  !a.allowed(e,true)||e.EventSequence<=a.last{return ErrUntrusted}
 a.last=e.EventSequence;a.down=e.EventSequence
 return nil
}
// MarkQMPAcknowledged is callable only by the sole host QMP actuator,
// NEVER from guest event bytes, stdout or a user request.
func (a *Authority)MarkQMPAcknowledged()error{
 if a==nil{return ErrUntrusted}
 a.mu.Lock();defer a.mu.Unlock()
 if a.down==0||a.acked||a.confirmed{return ErrUntrusted}
 a.acked=true
 return nil
}
func (a *Authority)ConfirmUp(e Event)error{
 if a==nil{return ErrUntrusted}
 a.mu.Lock();defer a.mu.Unlock()
 if a.down==0||!a.acked||a.confirmed||
  e.EventSequence<=a.last||!a.allowed(e,false){return ErrUntrusted}
 a.last=e.EventSequence;a.confirmed=true
 return nil
}
func (a *Authority)Reclaimable()bool{
 if a==nil{return false}
 a.mu.Lock();defer a.mu.Unlock()
 return a.confirmed
}
