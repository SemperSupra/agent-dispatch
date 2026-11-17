// R26-L9 test-only durable release-proof adapter. This is not a signer or
// trust-anchor provider. The caller MUST bind an independently authenticated
// guest evdev event to the actual QMP ACK and lease/VM epochs; merely setting
// Verified=true or reading a guest serial log is never sufficient.
package heldledger

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
)

var ErrUnverified=errors.New("heldledger: guest release proof unverified")

// ReleaseClaim carries scoped, ordered guest evdev evidence. Its Source and
// Proof fields are untrusted until the independently supplied verifier checks
// the complete claim against an authenticated guest identity.
type ReleaseClaim struct {
 GuestID string
 DeviceID string
 HostEpoch string
 GuestEpoch string
 LeaseEpoch string
 Generation uint64
 ReleaseSequence uint64
 DownEventSequence uint64
 EventSequence uint64
 Source string
 Key string
 KeyReleased bool
 Proof string
}

// ReleaseVerifier must authenticate the claim, including ALL scope/sequence
// fields, against a known guest-bound trust anchor. It is intentionally not
// implemented by production code in this experimental package.
type ReleaseVerifier func(ReleaseClaim)bool

func (c ReleaseClaim) valid()bool {
 return c.GuestID!="" && c.DeviceID!="" && c.HostEpoch!="" &&
  c.GuestEpoch!="" && c.LeaseEpoch!="" && c.Generation>0 &&
  c.ReleaseSequence>0 && c.DownEventSequence>0 &&
  c.EventSequence>c.DownEventSequence &&
  c.Source=="guest.evdev" && c.Key==KeyA && c.KeyReleased &&
  c.Proof!=""
}

// RequestRelease persists the release intent BEFORE sending a QMP key-up.
// A crash at this stage leaves Held=true and cannot authorize a new lease.
func (s Store)RequestRelease(expected uint64)(State,error) {
 state,err:=s.Read()
 if err!=nil{return State{},err}
 if !state.Held || state.Sequence!=expected || state.ReleasePhase!=""{
  return State{},ErrUnverified
 }
 state.ReleasePhase="release-intent"
 if err=s.writeAtomic(state);err!=nil{return State{},err}
 return state,nil
}

// AcknowledgeQMPRelease persists ONLY the fact that the trusted actuator
// successfully sent the QMP release command. It never clears held input.
// Only a trusted host actuator may call this after parsing a real QMP ACK.
func (s Store)AcknowledgeQMPRelease(expected uint64)(State,error) {
 state,err:=s.Read()
 if err!=nil{return State{},err}
 if !state.Held || state.Sequence!=expected ||
  state.ReleasePhase!="release-intent" {
  return State{},ErrUnverified
 }
 state.ReleasePhase="qmp-acked"
 if err=s.writeAtomic(state);err!=nil{return State{},err}
 return state,nil
}

// ConfirmGuestRelease is the ONLY synthetic held=>clean transition authorized
// to persist a receipt hash. A QMP ACK is NOT an input to this method.
// The caller must have observed the real QMP release ACK and must have a
// verifier bound to a first-hand guest evdev observation.
// On any error the persisted held=true record remains unchanged. Caller
// serializes this transition under the same host-wide actuator lock.
func (s Store) ConfirmGuestRelease(expected uint64,c ReleaseClaim,verify ReleaseVerifier)(State,error){
 state,err:=s.Read()
 if err!=nil{return State{},err}
 if !state.Held || state.Sequence!=expected || state.ReleasePhase!="qmp-acked" ||
  !c.valid() ||
  c.ReleaseSequence!=state.Sequence || verify==nil ||
  c.EventSequence<=state.LastReleaseEventSequence {
  return State{},ErrUnverified
 }
 if !verify(c){return State{},ErrUnverified}
 // A full independent verifier is responsible for checking all fields.
 // The proof hash is audit-only, not a token accepted after restart.
 raw:=sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%s|%d|%d|%d|%d|%s|%s|%t|%s",
  c.GuestID,c.DeviceID,c.HostEpoch,c.GuestEpoch,c.LeaseEpoch,
  c.Generation,c.ReleaseSequence,c.DownEventSequence,c.EventSequence,
  c.Source,c.Key,c.KeyReleased,c.Proof)))
 digest:=hex.EncodeToString(raw[:])
 if digest==state.LastReleaseProofHash{return State{},ErrUnverified}
 updated:=State{Version:Version,Sequence:state.Sequence+1,
  LastReleaseEventSequence:c.EventSequence,LastReleaseProofHash:digest}
 if err:=s.writeAtomic(updated);err!=nil{return State{},err}
 return updated,nil
}
