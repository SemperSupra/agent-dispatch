package recovery

import "errors"

// Phase describes a proposed controller restart state machine.
// This is a fail-closed offline contract, not production runtime wiring.
type Phase uint8
const (
 Held Phase=iota
 EmergencySent
 GuestReleaseVerified
 TopologyReconciled
 Eligible
 Quarantined
)
type Evidence struct{
 GuestReleaseSigned bool
 HostPinnedGuest bool
 FreshChallenge bool
 SameVMIncarnation bool
 SameHostEpoch bool
 SameGuestEpoch bool
 SameLeaseEpoch bool
 FreshReleaseSequence bool
 RealGuestEvdevUp bool
 TopologyAbsent bool
 ExclusiveQMPControl bool
 JournalFsyncedClear bool
}
type State struct{
 Phase Phase
 Held bool
 Generation uint64
 OriginalVM string
}
func NewHeld(vm string,generation uint64)(State,error){
 if vm==""||generation==0{return State{},errors.New("unknown original VM or generation")}
 return State{Phase:Held,Held:true,OriginalVM:vm,Generation:generation},nil
}
func (s State) EmergencyQMPUp() (State,error){
 if s.Phase!=Held||!s.Held{return s,errors.New("invalid emergency action")}
 s.Phase=EmergencySent
 return s,nil
}
func (s State) GuestProof(e Evidence)(State,error){
 if s.Phase!=EmergencySent||!s.Held{return s,errors.New("recovery proof not expected")}
 if !e.GuestReleaseSigned||!e.HostPinnedGuest||!e.FreshChallenge||
  !e.SameVMIncarnation||!e.SameHostEpoch||!e.SameGuestEpoch||
  !e.SameLeaseEpoch||!e.FreshReleaseSequence||!e.RealGuestEvdevUp{
  return s,errors.New("incomplete guest-origin signed release evidence")
 }
 s.Phase=GuestReleaseVerified
 return s,nil
}
func (s State) Reconcile(e Evidence)(State,error){
 if s.Phase!=GuestReleaseVerified||!s.Held{return s,errors.New("reconciliation without guest release")}
 if !e.TopologyAbsent||!e.ExclusiveQMPControl{return s,errors.New("topology or controller ownership unverified")}
 s.Phase=TopologyReconciled
 return s,nil
}
func (s State) CommitClear(e Evidence)(State,error){
 if s.Phase!=TopologyReconciled||!s.Held{return s,errors.New("premature clear")}
 if !e.JournalFsyncedClear{return s,errors.New("no fsynced journal clearance")}
 s.Phase=Eligible
 s.Held=false
 s.Generation++
 return s,nil
}
func (s State) Reserve()error{
 if s.Phase!=Eligible||s.Held{return errors.New("recovery incomplete: no new lease")}
 return nil
}
func (s State) Quarantine()State{s.Phase=Quarantined;s.Held=true;return s}
