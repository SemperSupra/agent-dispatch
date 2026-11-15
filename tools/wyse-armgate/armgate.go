// Package armgate joins two previously independent public-safe Wyse pure
// policy modules before a hypothetical host install. This is NOT an actuator.
package armgate

import (
 "context"
 "errors"
 "fmt"
 "time"

 modeplan "github.com/SemperSupra/agent-dispatch/tools/wyse-modeplan/modeplan"
 planpermit "github.com/SemperSupra/agent-dispatch/tools/wyse-planpermit"
)

// AuthorizeSyntheticArm validates live policy inputs against the exact
// preflighted intent and one-use Ed25519 permit; it returns an immutable
// proposed state transition only. No UEFI, disk, TPM or network operation.
func AuthorizeSyntheticArm(
 ctx context.Context,n modeplan.Node,p modeplan.Plan,
 signed planpermit.Permit,verifier *planpermit.Verifier,
 store planpermit.NonceStore,now time.Time,
)(modeplan.Plan,error){
 if p.Stage!=modeplan.Verified {return p,errors.New("host image staging/readback phase not verified")}
 if p.IntentSHA256==""||p.ApprovedChangeID==""||!p.SignedMutationGate{
  return p,errors.New("missing immutable plan digest or separately approved change scope")
 }
 next,fail:=modeplan.AdvanceInstall(n,p,modeplan.Armed)
 if len(fail)>0 {return p,fmt.Errorf("host plan denied: %v",fail)}
 exact:=planpermit.Target{
  DeviceID:p.DeviceID,
  Revision:p.ExpectedRevision,
  SSDByID:p.SSDDeviceIdentity,
  EMMCByID:p.EMMCDeviceIdentity,
  ArtifactSHA256:p.ArtifactSHA256,
  PlanIntentSHA256:p.IntentSHA256,
 }
 if err:=verifier.VerifyOnce(ctx,signed,exact,"HOST_INSTALL",now,store);err!=nil{
  return p,fmt.Errorf("signed approval denied: %w",err)
 }
 // Use only the pure output to drive future independently authorized code.
 // A successful synthetic result is NOT permission to start a physical write.
 return next,nil
}
