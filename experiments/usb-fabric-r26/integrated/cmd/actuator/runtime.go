// R27-C synthetic host-prepinned, image-provisioned Ed25519 guest receipt.
// This workcell DOES NOT prove measured-boot guest attestation: guest private
// key in initramfs can be extracted by anyone controlling the image.
package main

import (
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "time"

 blue "example.org/usb-fabric-r26-integrated/blue"
 heldledger "example.org/usb-fabric-r26-integrated/heldledger"
 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/guestwire"
 "example.org/usb-fabric-r26-releasegate/runtimeproof"
)

func (a *actuator)bindRuntimeGuestLease(lease blue.Lease)error{
 state,err:=a.journal.Read()
 if err!=nil{return err}
 if state.Held||state.ReleasePhase!=""||a.receiptConn==nil{
  return errors.New("cannot bind signed lease while held/unavailable")
 }
 scope:=guestwire.Scope()
 scope.HostEpoch=lease.Epoch
 scope.LeaseEpoch=fmt.Sprintf("%s/%d",lease.Epoch,lease.Generation)
 scope.Generation=lease.Generation
 scope.ReleaseSequence=state.Sequence+1
 challenge,err:=runtimeproof.NewHostChallenge()
 if err!=nil{return err}
 auth,err:=runtimeproof.NewAuthority(a.pinnedGuestKey,scope,challenge)
 if err!=nil{return err}
 a.proofMu.Lock()
 a.scope=scope
 a.runtimeProof=auth
 a.firstDownSequence=0
 a.proofMu.Unlock()
 a.ex.mu.Lock()
 a.ex.runtimeProof=auth
 a.ex.mu.Unlock()
 a.receiptWriteMu.Lock()
 _=a.receiptConn.SetWriteDeadline(time.Now().Add(8*time.Second))
 err=json.NewEncoder(a.receiptConn).Encode(struct{
  Op string `json:"Op"`
  Scope releasegate.Scope `json:"Scope"`
  Challenge [32]byte `json:"Challenge"`
 }{Op:"bind",Scope:scope,Challenge:challenge})
 a.receiptWriteMu.Unlock()
 if err!=nil{a.m.Offline();return err}
 fmt.Printf("R27C_HOST_FRESH_ED25519_SCOPE_BOUND=PASS generation=%d release=%d\n",
  scope.Generation,scope.ReleaseSequence)
 return nil
}

func (a *actuator)applyRuntimeGuestReceipt(event runtimeproof.Event){
 a.proofMu.Lock()
 scope,auth,down:=a.scope,a.runtimeProof,a.firstDownSequence
 a.proofMu.Unlock()
 if auth==nil{return}
 if event.Scope!=scope{
  fmt.Println("R27C_OLD_SIGNED_GUEST_SCOPE_REPLAY_REJECTED=PASS")
  return
 }
 if event.Down{
  if err:=auth.ObserveDown(event);err!=nil{return}
  a.proofMu.Lock()
  if a.scope==event.Scope{a.firstDownSequence=event.EventSequence}
  a.proofMu.Unlock()
  fmt.Printf("R27C_REAL_ED25519_GUEST_DOWN_VERIFIED=PASS generation=%d\n",scope.Generation)
  return
 }
 if down==0||event.EventSequence<=down{return}
 ready:=false
 var state heldledger.State
 for i:=0;i<175;i++{
  var err error
  state,err=a.journal.Read()
  if err!=nil{return}
  if state.Held&&state.Sequence==scope.ReleaseSequence&&
   state.ReleasePhase=="qmp-acked"{
   ready=true;break
  }
  time.Sleep(20*time.Millisecond)
 }
 if !ready||auth.ConfirmUp(event)!=nil{return}
 claim:=heldledger.ReleaseClaim{
  GuestID:event.Scope.GuestID,DeviceID:event.Scope.DeviceID,
  HostEpoch:event.Scope.HostEpoch,GuestEpoch:event.Scope.GuestEpoch,
  LeaseEpoch:event.Scope.LeaseEpoch,Generation:event.Scope.Generation,
  ReleaseSequence:event.Scope.ReleaseSequence,
  DownEventSequence:down,EventSequence:event.EventSequence,
  Source:event.Source,Key:heldledger.KeyA,KeyReleased:!event.Down,
  Proof:hex.EncodeToString(event.Signature),
 }
 // The separate authority checked the pinned Ed25519 public key,
 // host-generated nonce, both event signatures and real QMP ACK.
 verifier:=func(c heldledger.ReleaseClaim)bool{
  return auth.Reclaimable()&&c.GuestID==event.Scope.GuestID&&
   c.DeviceID==event.Scope.DeviceID&&
   c.HostEpoch==event.Scope.HostEpoch&&c.GuestEpoch==event.Scope.GuestEpoch&&
   c.LeaseEpoch==event.Scope.LeaseEpoch&&
   c.Generation==event.Scope.Generation&&
   c.ReleaseSequence==event.Scope.ReleaseSequence&&
   c.DownEventSequence==down&&c.EventSequence==event.EventSequence&&
   c.Source=="guest.evdev"&&c.Key==heldledger.KeyA&&
   c.KeyReleased&&c.Proof==hex.EncodeToString(event.Signature)
 }
 if err:=a.m.RestoreAfterVerifiedGuestUp(a.journal,state.Sequence,claim,verifier);err!=nil{
  fmt.Fprintln(os.Stderr,"R27C_GUEST_PROOF_DENIED_HELD",err)
  return
 }
 a.proofMu.Lock()
 if a.scope==event.Scope{a.firstDownSequence=0}
 a.proofMu.Unlock()
 fmt.Printf("R27C_ACTUAL_ED25519_UP_FSYNC_AND_READMISSION=PASS generation=%d release=%d\n",
  scope.Generation,scope.ReleaseSequence)
}
