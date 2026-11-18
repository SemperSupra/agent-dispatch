// R26-L9C optional synthetic per-lease guest receipt and QMP hot-unplug proof.
// This is a test-only actorless QEMU workcell, not production guest auth.
package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "time"

 blue "example.org/usb-fabric-r26-integrated/blue"
 heldledger "example.org/usb-fabric-r26-integrated/heldledger"
 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
 "example.org/usb-fabric-r26-releasegate/guestwire"
)

// bindGuestLease is invoked only after the sole actor successfully starts
// the attached lease. Only the host actuator, never a frontend payload,
// establishes the next signed-guest scope and journal sequence.
func (a *actuator)bindGuestLease(lease blue.Lease)error {
 if !a.scoped{return nil}
 if a.runtimeMode{return a.bindRuntimeGuestLease(lease)}
 state,err:=a.journal.Read()
 if err!=nil{return err}
 if state.Held||state.ReleasePhase!=""||a.receiptConn==nil {
  return errors.New("cannot bind scope with held or untrusted guest state")
 }
 scope:=guestwire.Scope()
 // These are synthetic scoped epochs, not production VM attestation.
 scope.HostEpoch=lease.Epoch
 scope.LeaseEpoch=fmt.Sprintf("%s/%d",lease.Epoch,lease.Generation)
 scope.Generation=lease.Generation
 scope.ReleaseSequence=state.Sequence+1
 gate,err:=releasegate.New(scope)
 if err!=nil{return err}
 bridge,err:=evidence.New(gate,scope,guestwire.VerifySyntheticGuest)
 if err!=nil{return err}
 a.proofMu.Lock()
 a.scope=scope
 a.gate=gate
 a.bridge=bridge
 a.firstDownSequence=0
 a.ex.gate=gate
 a.proofMu.Unlock()
 a.receiptWriteMu.Lock()
 _=a.receiptConn.SetWriteDeadline(time.Now().Add(8*time.Second))
 err=json.NewEncoder(a.receiptConn).Encode(struct{
  Op string `json:"Op"`
  Scope releasegate.Scope `json:"Scope"`
 }{Op:"bind",Scope:scope})
 a.receiptWriteMu.Unlock()
 if err!=nil {a.m.Offline();return err}
 fmt.Printf("R26_L9C_HOST_PER_LEASE_SCOPE_BOUND=PASS generation=%d release=%d\n",
  scope.Generation,scope.ReleaseSequence)
 return nil
}

func (a *actuator)applyScopedGuestReceipt(event evidence.Event){
 a.proofMu.Lock()
 currentScope,bridge,gate,down:=a.scope,a.bridge,a.gate,a.firstDownSequence
 a.proofMu.Unlock()
 if bridge==nil||gate==nil{return}
 if event.Scope!=currentScope{
  // The test guest intentionally replays a signed prior-lease UP.
  // A real compromised guest could do the same: never authorize it.
  fmt.Println("R26_L9C_REPLAYED_OLD_LEASE_RECEIPT_REJECTED=PASS")
  return
 }
 if event.Down{
  if err:=bridge.ObserveDown(event);err!=nil{return}
  a.proofMu.Lock()
  if a.scope==event.Scope{a.firstDownSequence=event.EventSequence}
  a.proofMu.Unlock()
  fmt.Printf("R26_L9C_REAL_GUEST_DOWN_SCOPE_VERIFIED=PASS generation=%d\n",
   currentScope.Generation)
  return
 }
 if down==0 || event.EventSequence<=down || !guestwire.VerifySyntheticGuest(event){
  return
 }
 var state heldledger.State
 ready:=false
 for i:=0;i<150;i++{
  var err error
  state,err=a.journal.Read()
  if err!=nil{return}
  if state.Held && state.Sequence==currentScope.ReleaseSequence &&
   state.ReleasePhase=="qmp-acked" &&
   gate.Snapshot().Phase==releasegate.QMPAcknowledged {
   ready=true
   break
  }
  time.Sleep(20*time.Millisecond)
 }
 if !ready || bridge.ConfirmUp(event)!=nil {return}
 c:=heldledger.ReleaseClaim{
  GuestID:event.Scope.GuestID,DeviceID:event.Scope.DeviceID,
  HostEpoch:event.Scope.HostEpoch,GuestEpoch:event.Scope.GuestEpoch,
  LeaseEpoch:event.Scope.LeaseEpoch,Generation:event.Scope.Generation,
  ReleaseSequence:event.Scope.ReleaseSequence,
  DownEventSequence:down,EventSequence:event.EventSequence,
  Source:event.Source,Key:heldledger.KeyA,KeyReleased:!event.Down,Proof:event.Proof,
 }
 verify:=func(claim heldledger.ReleaseClaim)bool{
  return guestwire.VerifySyntheticGuest(event) &&
   claim.GuestID==event.Scope.GuestID &&
   claim.DeviceID==event.Scope.DeviceID &&
   claim.HostEpoch==event.Scope.HostEpoch &&
   claim.GuestEpoch==event.Scope.GuestEpoch &&
   claim.LeaseEpoch==event.Scope.LeaseEpoch &&
   claim.Generation==event.Scope.Generation &&
   claim.ReleaseSequence==event.Scope.ReleaseSequence &&
   claim.DownEventSequence==down &&
   claim.EventSequence==event.EventSequence &&
   claim.Source==event.Source &&
   claim.Key==heldledger.KeyA &&
   claim.KeyReleased && claim.Proof==event.Proof
 }
 if err:=a.m.RestoreAfterVerifiedGuestUp(a.journal,state.Sequence,c,verify);err!=nil{
  fmt.Println("R26_L9C_PROOF_DENIED_HELD=PASS",err)
  return
 }
 a.proofMu.Lock()
 if a.scope==event.Scope{a.firstDownSequence=0}
 a.proofMu.Unlock()
 fmt.Printf("R26_L9C_REAL_GUEST_UP_FSYNC_AND_RELEASE=PASS generation=%d release=%d\n",
  currentScope.Generation,currentScope.ReleaseSequence)
}

// recordQMPEvent is called while q.mu is held, from the sole QMP decoder.
func (q *qmp)recordQMPEvent(response map[string]json.RawMessage){
 var name string
 if err:=json.Unmarshal(response["event"],&name);err!=nil{return}
 if name!="DEVICE_DELETED"{return}
 var data struct{
  Device string `json:"device"`
  Path string `json:"path"`
 }
 if err:=json.Unmarshal(response["data"],&data);err!=nil{return}
 if data.Device!=""{
  if q.deleted==nil{q.deleted=map[string]bool{}}
  q.deleted[data.Device]=true
  fmt.Printf("R26_L9C_QMP_DEVICE_DELETED_EVENT=PASS id=%s\n",data.Device)
 }
}

func (q *qmp)waitDeviceDeleted(id string)error {
 for i:=0;i<75;i++{
  q.mu.Lock()
  matched:=q.deleted[id]
  q.mu.Unlock()
  if matched{return nil}
  if err:=q.call("query-status",nil);err!=nil{return err}
  time.Sleep(35*time.Millisecond)
 }
 return fmt.Errorf("QMP DEVICE_DELETED not observed for %s",id)
}

// detachKeyboard is invoked only after Blue.BeginDetach permanently
// quarantines the port, after the last authenticated guest key-up.
func (a *actuator)detachKeyboard()error {
 a.attachMu.Lock();defer a.attachMu.Unlock()
 if !a.devicesAttached{return errors.New("no keyboard attached")}
 if err:=a.q.call("device_del",map[string]any{"id":"r26-l-kbd"});err!=nil{return err}
 if err:=a.q.waitDeviceDeleted("r26-l-kbd");err!=nil{return err}
 fmt.Println("R26_L9C_HOST_QMP_KEYBOARD_DETACHED=PASS")
 return nil
}
