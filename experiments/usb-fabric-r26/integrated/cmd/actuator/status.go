package main

import (
 "errors"

 blue "example.org/usb-fabric-r26-integrated/blue"
)

// PortInfo is a read-only, human/CLI/automation/agent-consumable view of the
// sole synthetic device. It contains no QMP path, guest MAC/key, or actor data.
type PortInfo struct {
 Protocol string `json:"protocol"`
 ID string `json:"id"`
 Device string `json:"device"`
 State blue.State `json:"state"`
 Occupied bool `json:"occupied"`
 Held bool `json:"held"`
 ReleasePhase string `json:"release_phase,omitempty"`
 Generation uint64 `json:"generation"`
 CredentialMode string `json:"credential_mode"`
}

// status requires the host-local authorized-peer mode. A frontend-provided
// Actor selector never authorizes metadata discovery or privileged QMP.
func (a *actuator)status()(PortInfo,error){
 if a.authorizedPeerUID<0{return PortInfo{},ErrPeerDenied}
 state,_,generation:=a.m.Snapshot()
 ledger,err:=a.journal.Read()
 if err!=nil{return PortInfo{},err}
 if state==""{return PortInfo{},errors.New("unknown lease state")}
 return PortInfo{
  Protocol:"usb-fabric-r27/v1",
  ID:"xhci0/auto",Device:"keyboard",
  State:state,Occupied:state!=blue.Available||ledger.Held,
  Held:ledger.Held,ReleasePhase:ledger.ReleasePhase,
  Generation:generation,CredentialMode:"linux-so-peercred-uid",
 },nil
}
