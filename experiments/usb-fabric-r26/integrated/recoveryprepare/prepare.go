// Package recoveryprepare snapshots immutable pre-clear journal intent.
// It deliberately has NO journal-writing or new-lease API. A signed guest
// UP and QMP DEVICE_DELETED receipt are necessary but not sufficient for
// full source-verified exclusive-controller release.
package recoveryprepare

import(
 "crypto/sha256"
 "encoding/binary"
 "errors"
 "fmt"
 heldledger "example.org/usb-fabric-r26-integrated/heldledger"
)
var ErrUntrusted=errors.New("recoveryprepare: insufficient or stale evidence")
type Evidence struct {
 GuestSignedUp bool
 ExactDeviceDeleted bool
 QOMAbsent bool
 SameQEMUProcess bool
 SameHostEpoch bool
 SameGuestEpoch bool
 SameLeaseEpoch bool
 SoleQMPController bool
 NoHostileRawQMP bool
 ProductionGuestTrust bool
}
type Prepared struct{
 Digest [32]byte
 Sequence uint64
}
func digest(s heldledger.State)[32]byte{
 // Fields that must not change between evidence acquisition and eventual
 // owner-controlled transaction review. This is an optimistic guard only.
 var data [32]byte
 binary.BigEndian.PutUint64(data[:8],s.Sequence)
 binary.BigEndian.PutUint64(data[8:16],s.LastReleaseEventSequence)
 if s.Held{data[16]=1}
 phase:=[]byte(s.ReleasePhase)
 sum:=sha256.New()
 sum.Write(data[:17])
 sum.Write([]byte(s.Key));sum.Write([]byte{0})
 sum.Write(phase);sum.Write([]byte{0})
 sum.Write([]byte(s.LastReleaseProofHash))
 var out [32]byte;copy(out[:],sum.Sum(nil))
 return out
}
func Prepare(s heldledger.State,e Evidence)(Prepared,error){
 if s.Version!=heldledger.Version||!s.Held||s.Key!=heldledger.KeyA||s.Sequence==0{
  return Prepared{},ErrUntrusted
 }
 if !e.GuestSignedUp||!e.ExactDeviceDeleted||!e.QOMAbsent||
  !e.SameQEMUProcess||!e.SameHostEpoch||!e.SameGuestEpoch||
  !e.SameLeaseEpoch||!e.SoleQMPController||!e.NoHostileRawQMP||
  !e.ProductionGuestTrust{return Prepared{},ErrUntrusted}
 return Prepared{Digest:digest(s),Sequence:s.Sequence},nil
}
func (p Prepared)Recheck(store heldledger.Store)error{
 if p.Sequence==0||p.Digest==([32]byte{}){return ErrUntrusted}
 current,err:=store.Read()
 if err!=nil{return fmt.Errorf("%w: %v",ErrUntrusted,err)}
 if !current.Held||current.Sequence!=p.Sequence||digest(current)!=p.Digest{return ErrUntrusted}
 return nil
}
