// R27-C: preserve the ORIGINAL durable Go release authority while adding a
// domain-specific Linux kernel USB/IP release stage. No second Manager,
// QMP client, USB/IP stack, signer or guest identity provider is introduced.
// TEST-ONLY contract: callers must verify real QEMU/guest/kernel witnesses.
package heldledger

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
)

// KernelIsolationClaim identifies the SAME real guest input + USBIP endpoint
// and lease that the *separate* signed evdev-UP is expected to discharge.
// Raw guest TCP A_DETACHED, QMP query-status, a QMP native-keyboard ACK,
// unverified sysfs text, or bool flags alone are NOT valid host authority.
type KernelIsolationClaim struct {
 VMIncarnation string
 GuestID string
 DeviceID string
 HostEpoch string
 GuestEpoch string
 LeaseEpoch string
 Generation uint64
 ReleaseSequence uint64
 GuestDownEventSequence uint64 // independently observed CURRENT USBIP VHCI key-down
 GuestUpEventSequence uint64
 ExporterBusID string
 ConsumerVHCIPort string
 ProviderUDCUnbound bool
 ConsumerVHCIQuiescent bool
}
type KernelIsolationVerifier func(KernelIsolationClaim)bool

func(k KernelIsolationClaim)valid()bool {
 return k.VMIncarnation!="" && k.GuestID!="" && k.DeviceID!="" &&
  k.HostEpoch!="" && k.GuestEpoch!="" && k.LeaseEpoch!="" &&
  k.Generation>0 && k.ReleaseSequence>0 &&
  k.GuestDownEventSequence>0 &&
  k.GuestUpEventSequence>k.GuestDownEventSequence &&
  k.ExporterBusID!="" && k.ConsumerVHCIPort!="" &&
  k.ProviderUDCUnbound && k.ConsumerVHCIQuiescent
}
func kernelDigest(k KernelIsolationClaim)string{
 data,_:=json.Marshal(k) // fixed concrete struct: no map/key-order ambiguity
 sum:=sha256.Sum256(data)
 return hex.EncodeToString(sum[:])
}

// AcknowledgeKernelIsolation fsyncs a distinct kernel-isolated phase ONLY
// after release-intent and a trusted independent HOST validator has observed
// both real provider ConfigFS UDC unbind and consumer Linux VHCI quiescence,
// on the correct QEMU VM/lease/port. This cannot be substituted by QMP ACK.
func(s Store)AcknowledgeKernelIsolation(expected uint64,k KernelIsolationClaim,verify KernelIsolationVerifier)(State,error){
 state,err:=s.Read();if err!=nil{return State{},err}
 if !state.Held || state.Sequence!=expected ||
  state.ReleasePhase!="release-intent" || !k.valid() ||
  k.ReleaseSequence!=expected || verify==nil || !verify(k){
  return State{},ErrUnverified
 }
 state.ReleasePhase="kernel-isolated"
 state.KernelWitnessHash=kernelDigest(k)
 if err=s.writeAtomic(state);err!=nil{return State{},err}
 return state,nil
}

// ConfirmGuestKernelRelease requires TWO independently verified domains:
//  (1) the SAME original host-observed kernel-isolation witness already
//      fsynced in HELD=TRUE, and
//  (2) the separately authenticated real in-guest evdev UP with matching
//      VM/guest/device/lease generation/release/event scope.
//
// A QMP-native keyboard ACK never satisfies this method. Only existing
// Manager.RestoreAfterVerifiedKernelUp may clear the journal and admit B.
func(s Store)ConfirmGuestKernelRelease(expected uint64,k KernelIsolationClaim,
 verifyKernel KernelIsolationVerifier, c ReleaseClaim,verifyGuest ReleaseVerifier,
)(State,error){
 state,err:=s.Read();if err!=nil{return State{},err}
 if !state.Held || state.Sequence!=expected ||
  state.ReleasePhase!="kernel-isolated" || !k.valid() ||
  verifyKernel==nil || !verifyKernel(k) ||
  state.KernelWitnessHash!=kernelDigest(k) ||
  !c.valid() || verifyGuest==nil ||
  c.ReleaseSequence!=state.Sequence ||
  c.GuestID!=k.GuestID || c.DeviceID!=k.DeviceID ||
  c.HostEpoch!=k.HostEpoch || c.GuestEpoch!=k.GuestEpoch ||
  c.LeaseEpoch!=k.LeaseEpoch || c.Generation!=k.Generation ||
  c.ReleaseSequence!=k.ReleaseSequence ||
  c.EventSequence!=k.GuestUpEventSequence ||
  c.DownEventSequence!=k.GuestDownEventSequence ||
  c.DownEventSequence<=state.LastReleaseEventSequence ||
  c.EventSequence<=state.LastReleaseEventSequence {
  return State{},ErrUnverified
 }
 if !verifyGuest(c){return State{},ErrUnverified}
 proof:=sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%s|%d|%d|%d|%d|%s|%s|%t|%s",
  c.GuestID,c.DeviceID,c.HostEpoch,c.GuestEpoch,c.LeaseEpoch,
  c.Generation,c.ReleaseSequence,c.DownEventSequence,c.EventSequence,
  c.Source,c.Key,c.KeyReleased,c.Proof)))
 digest:=hex.EncodeToString(proof[:])
 if digest==state.LastReleaseProofHash{return State{},ErrUnverified}
 clean:=State{Version:Version,Sequence:state.Sequence+1,
  LastReleaseEventSequence:c.EventSequence,LastReleaseProofHash:digest}
 if err=s.writeAtomic(clean);err!=nil{return State{},err}
 return clean,nil
}
