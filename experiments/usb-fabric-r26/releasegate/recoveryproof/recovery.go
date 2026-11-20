// Package recoveryproof specifies the synthetic signed post-crash rebind
// protocol. The guest sensor must independently sample a *real* kernel
// evdev held state (e.g. EVIOCGKEY) before signing HeldSnapshot. Merely
// reporting a cached host/QMP flag is NOT trustworthy. This package proves
// signature/scope/ordering only; it does not implement kernel observation,
// durable host journal, or measured guest attestation.
package recoveryproof

import(
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/binary"
 "errors"
 "io"
 "sync"

 releasegate "example.org/usb-fabric-r26-releasegate"
)
const domain="USB-Fabric-R27-Recovery-EVDEV-Snapshot-v1"
const(
 HeldSnapshot="held-snapshot"
 GuestKeyUp="guest-key-up"
)
var ErrUntrusted=errors.New("recoveryproof: stale, unpinned or out-of-order recovery receipt")
type Event struct{
 Scope releasegate.Scope `json:"scope"`
 Challenge [32]byte `json:"challenge"`
 Phase string `json:"phase"`
 Source string `json:"source"`
 KeyCode string `json:"key_code"`
 Held bool `json:"held"`
 EventSequence uint64 `json:"event_sequence"`
 Signature []byte `json:"signature"`
}
func message(e Event)[]byte{
 var b bytes.Buffer
 b.WriteString(domain);b.WriteByte(0);b.Write(e.Challenge[:])
 str:=func(s string){var n [4]byte;binary.BigEndian.PutUint32(n[:],uint32(len(s)));b.Write(n[:]);b.WriteString(s)}
 num:=func(n uint64){var d [8]byte;binary.BigEndian.PutUint64(d[:],n);b.Write(d[:])}
 str(e.Scope.GuestID);str(e.Scope.DeviceID)
 str(e.Scope.HostEpoch);str(e.Scope.GuestEpoch);str(e.Scope.LeaseEpoch)
 num(e.Scope.Generation);num(e.Scope.ReleaseSequence)
 str(e.Phase);str(e.Source);str(e.KeyCode)
 if e.Held{b.WriteByte(1)}else{b.WriteByte(0)}
 num(e.EventSequence)
 return b.Bytes()
}
func Sign(priv ed25519.PrivateKey,e Event)(Event,error){
 if len(priv)!=ed25519.PrivateKeySize||e.EventSequence==0{return Event{},ErrUntrusted}
 e.Signature=ed25519.Sign(priv,message(e))
 return e,nil
}
func Challenge()([32]byte,error){
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
 minOriginalSequence uint64
 snapshotSeq uint64
 acknowledged bool
 released bool
}
func NewAuthority(pinned ed25519.PublicKey,scope releasegate.Scope,challenge [32]byte,originalSequence uint64)(*Authority,error){
 if len(pinned)!=ed25519.PublicKeySize||challenge==([32]byte{})||
  scope.GuestID==""||scope.DeviceID==""||scope.HostEpoch==""||scope.GuestEpoch==""||
  scope.LeaseEpoch==""||scope.Generation==0||scope.ReleaseSequence==0||originalSequence==0{
  return nil,ErrUntrusted
 }
 return &Authority{public:append(ed25519.PublicKey(nil),pinned...),scope:scope,challenge:challenge,minOriginalSequence:originalSequence},nil
}
func(a *Authority)allowed(e Event,phase,source string,held bool)bool{
 return a!=nil && e.Scope==a.scope && e.Challenge==a.challenge &&
  e.Phase==phase && e.Source==source && e.KeyCode=="key-a" &&
  e.Held==held && e.EventSequence>0 &&
  len(e.Signature)==ed25519.SignatureSize &&
  ed25519.Verify(a.public,message(e),e.Signature)
}
func(a *Authority)ObserveHeldSnapshot(e Event)error{
 if a==nil{return ErrUntrusted}
 a.mu.Lock();defer a.mu.Unlock()
 if a.snapshotSeq!=0||a.acknowledged||a.released||
  e.EventSequence<=a.minOriginalSequence ||
  !a.allowed(e,HeldSnapshot,"guest.evdev-state",true){return ErrUntrusted}
 a.snapshotSeq=e.EventSequence
 return nil
}
func(a *Authority)MarkEmergencyQMPAcknowledged()error{
 if a==nil{return ErrUntrusted}
 a.mu.Lock();defer a.mu.Unlock()
 if a.snapshotSeq==0||a.acknowledged||a.released{return ErrUntrusted}
 a.acknowledged=true
 return nil
}
func(a *Authority)ConfirmGuestKeyUp(e Event)error{
 if a==nil{return ErrUntrusted}
 a.mu.Lock();defer a.mu.Unlock()
 if a.snapshotSeq==0||!a.acknowledged||a.released||
  e.EventSequence<=a.snapshotSeq||
  !a.allowed(e,GuestKeyUp,"guest.evdev",false){return ErrUntrusted}
 a.released=true
 return nil
}
func(a *Authority)Reclaimable()bool{
 if a==nil{return false}
 a.mu.Lock();defer a.mu.Unlock()
 return a.released
}
