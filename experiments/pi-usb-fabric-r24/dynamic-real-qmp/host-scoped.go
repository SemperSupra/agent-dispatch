// R26-L9C optional synthetic per-lease guest receipt and QMP hot-unplug proof.
// This is a test-only actorless QEMU workcell, not production guest auth.
package main

import (
 "crypto/ed25519"
 "encoding/hex"
 "os"
 "strings"
 "sync"
 "encoding/json"
 "errors"
 "fmt"
 "time"

 blue "example.org/usb-fabric-r26-integrated/blue"
 heldledger "example.org/usb-fabric-r26-integrated/heldledger"
 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
 "example.org/usb-fabric-r26-releasegate/guestwire"
 guestsign "example.org/usb-fabric-r22-guest-ed25519"
)

// R24-B: source-first test-only OUT-OF-BAND public-key pin. The test
// orchestrator obtains the guest-generated public key from the guest serial
// observation channel BEFORE triggering any QMP key DOWN. That channel is
// still guest-controlled; it is NOT a protected VM identity attestation.
// The original R26 sole QMP client and release/journal remain unchanged.
var r24Pinned struct{
 sync.Once
 pub ed25519.PublicKey
 nonce [32]byte
 err error
}
func r24LoadPin(){
 r24Pinned.Do(func(){
  file:=os.Getenv("R24_APPROVED_GUEST_KEY_PATH")
  if file==""{r24Pinned.err=errors.New("no separate host public-key enrollment");return}
  raw,err:=os.ReadFile(file);if err!=nil{r24Pinned.err=err;return}
  k,err:=hex.DecodeString(strings.TrimSpace(string(raw)))
  if err!=nil||len(k)!=ed25519.PublicKeySize{
   r24Pinned.err=errors.New("wrong host-approved test Ed25519 key");return
  }
  nonce,err:=hex.DecodeString(os.Getenv("R24_GUEST_NONCE"))
  if err!=nil||len(nonce)!=32{
   r24Pinned.err=errors.New("invalid host challenge");return
  }
  copy(r24Pinned.nonce[:],nonce)
  if r24Pinned.nonce==([32]byte{}){
   r24Pinned.err=errors.New("zero host challenge");return
  }
  r24Pinned.pub=append(ed25519.PublicKey(nil),k...)
 })
}
func r24WirePublicKeyAllowed(s string)bool{
 r24LoadPin()
 if r24Pinned.err!=nil {
  fmt.Fprintln(os.Stderr,"R24_B_HOST_ENROLLMENT_ERROR=OBSERVED",r24Pinned.err)
  return false
 }
 if !strings.EqualFold(s,hex.EncodeToString(r24Pinned.pub)) {
  fmt.Fprintf(os.Stderr,"R24_B_GUEST_WIRE_PUB_MISMATCH=OBSERVED wireLen=%d pinnedLen=%d\\n",len(s),len(hex.EncodeToString(r24Pinned.pub)))
  return false
 }
 return true
}
func r24Verify(e evidence.Event)bool{
 r24LoadPin()
 return r24Pinned.err==nil &&
  e.Source=="guest.evdev" && e.KeyCode=="key-a" &&
  guestsign.VerifyWithPinnedPublicKey(e,r24Pinned.nonce,r24Pinned.pub)
}
// bindGuestLease is invoked only after the sole actor successfully starts
// the attached lease. Only the host actuator, never a frontend payload,
// establishes the next signed-guest scope and journal sequence.
func (a *actuator)bindGuestLease(lease blue.Lease)error {
 if !a.scoped{return nil}
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
 bridge,err:=evidence.New(gate,scope,r24Verify)
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
 fmt.Println("R24_B_ACTUAL_R26_DYNAMIC_SCOPE_BOUND=PASS")
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
  fmt.Println("R24_B_REAL_QMP_GUEST_ED25519_DOWN_AUTHORITY=PASS")
  return
 }
 if down==0 || event.EventSequence<=down || !r24Verify(event){
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
  return r24Verify(event) &&
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
 fmt.Println("R24_B_REAL_QMP_GUEST_ED25519_UP_FSYNCED=PASS")
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
