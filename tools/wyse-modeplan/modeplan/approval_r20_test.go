package modeplan

import "testing"

// The approved change identifier and synthetic mutation assertion must be
// immutable after preflight even before an external cryptographic permit is
// introduced. The SHA seal is consistency-only, not a signature.
func TestR20ApprovalIdentityAndMutationFlagSealed(t *testing.T) {
 n:=mkNode()
 p,errors:=AdvanceInstall(n,mkPlan(n),Preflighted)
 if len(errors)!=0 {t.Fatal(errors)}
 p.ApprovedChangeID="swapped-change-identifier"
 if _,fail:=AdvanceInstall(n,p,Staged);!has(fail,"PLAN_INTENT_CHANGED"){
  t.Fatalf("change approval retarget accepted: %v",fail)
 }
 p,errors=AdvanceInstall(n,mkPlan(n),Preflighted)
 if len(errors)!=0 {t.Fatal(errors)}
 p.SignedMutationGate=false
 if _,fail:=AdvanceInstall(n,p,Staged);!has(fail,"PLAN_INTENT_CHANGED"){
  t.Fatalf("approval assertion swapped: %v",fail)
 }
 p,errors=AdvanceInstall(n,mkPlan(n),Preflighted)
 if len(errors)!=0 {t.Fatal(errors)}
 p.ApprovedChangeID=""
 if _,fail:=AdvanceInstall(n,p,Staged);!has(fail,"PLAN_INTENT_CHANGED"){
  t.Fatalf("approval removed after preflight: %v",fail)
 }
}
