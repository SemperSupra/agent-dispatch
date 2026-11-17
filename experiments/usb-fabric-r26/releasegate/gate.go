// Package releasegate models the exact trust boundary between a host QMP
// acknowledgment and a separately verified guest-visible USB key release.
// It is a pure synthetic policy model, not a guest attestation provider.
package releasegate

import (
 "errors"
 "sync"
)

type Phase string
const (
 Unknown Phase = "unknown"
 Held Phase = "held"
 ReleasePending Phase = "release-pending"
 QMPAcknowledged Phase = "qmp-acknowledged"
 GuestConfirmed Phase = "guest-confirmed"
 Quarantined Phase = "quarantined"
)

var (
 ErrDenied=errors.New("releasegate: denied or stale operation")
 ErrUnproven=errors.New("releasegate: missing trusted proof")
)

type Scope struct {
 GuestID string `json:"guest_id"`
 DeviceID string `json:"device_id"`
 HostEpoch string `json:"host_epoch"`
 GuestEpoch string `json:"guest_epoch"`
 LeaseEpoch string `json:"lease_epoch"`
 Generation uint64 `json:"generation"`
 ReleaseSequence uint64 `json:"release_sequence"`
}
func (s Scope) valid()bool{
 return s.GuestID!="" && s.DeviceID!="" && s.HostEpoch!="" &&
  s.GuestEpoch!="" && s.LeaseEpoch!="" && s.Generation>0 && s.ReleaseSequence>0
}
type Receipt struct {
 Scope Scope `json:"scope"`
 Source string `json:"source"`
 EventSequence uint64 `json:"event_sequence"`
 KeyReleased bool `json:"key_released"`
 Proof string `json:"proof"`
}
type Verifier func(Receipt)bool

type Snapshot struct{
 Version int `json:"version"`
 Scope Scope `json:"scope"`
 Phase Phase `json:"phase"`
}

type Gate struct{
 mu sync.Mutex
 snap Snapshot
}

func New(scope Scope)(*Gate,error){
 if !scope.valid(){return nil,ErrDenied}
 return &Gate{snap:Snapshot{Version:1,Scope:scope,Phase:Held}},nil
}

// Restore does not infer release from restart or from a prior QMP ACK.
// Invalid/unknown snapshots become quarantined, never AVAILABLE.
func Restore(s Snapshot)*Gate{
 valid:=s.Version==1 && s.Scope.valid()
 switch s.Phase {
 case Held,ReleasePending,QMPAcknowledged,GuestConfirmed,Quarantined:
 default:valid=false
 }
 // A persisted "guest-confirmed" bit is not itself a signed proof.
 // Revalidate trusted evidence after restart before any new lease is
 // admitted; a restored snapshot alone can never grant availability.
 if !valid || s.Phase==GuestConfirmed{s.Phase=Quarantined}
 return &Gate{snap:s}
}
func (g *Gate) Snapshot()Snapshot{
 g.mu.Lock();defer g.mu.Unlock()
 return g.snap
}
func (g *Gate) RequestRelease(s Scope)error{
 g.mu.Lock();defer g.mu.Unlock()
 if s!=g.snap.Scope || g.snap.Phase!=Held{return ErrDenied}
 g.snap.Phase=ReleasePending
 return nil
}
func (g *Gate) AcknowledgeQMP(s Scope)error{
 g.mu.Lock();defer g.mu.Unlock()
 if s!=g.snap.Scope || g.snap.Phase!=ReleasePending{return ErrDenied}
 g.snap.Phase=QMPAcknowledged
 return nil
}
func (g *Gate) ConfirmGuest(r Receipt,verify Verifier)error{
 g.mu.Lock();defer g.mu.Unlock()
 if g.snap.Phase!=QMPAcknowledged || r.Scope!=g.snap.Scope ||
  !r.KeyReleased || r.Source!="guest.evdev" || r.EventSequence==0 ||
  verify==nil || !verify(r) {
  return ErrUnproven
 }
 g.snap.Phase=GuestConfirmed
 return nil
}
func (g *Gate) Reclaimable()bool{
 g.mu.Lock();defer g.mu.Unlock()
 return g.snap.Phase==GuestConfirmed
}
func (g *Gate) FailClosed(){
 g.mu.Lock();defer g.mu.Unlock()
 g.snap.Phase=Quarantined
}
