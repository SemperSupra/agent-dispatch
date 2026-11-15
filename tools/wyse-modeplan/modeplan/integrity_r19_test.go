package modeplan

import (
 "strings"
 "testing"
)

// Historical RED: AdvanceInstall validated host/disk only at PROPOSED,
// and accepted later retargeting or trust loss without rechecking.
func TestR19InstallRefusesPlanMutationAfterPreflight(t *testing.T){
 n:=mkNode()
 p,errCodes:=AdvanceInstall(n,mkPlan(n),Preflighted)
 if len(errCodes)>0{t.Fatal(errCodes)}
 p.SSDDeviceIdentity=p.EMMCDeviceIdentity
 if _,fail:=AdvanceInstall(n,p,Staged);!has(fail,"PLAN_INTENT_CHANGED"){t.Fatalf("retarget after preflight accepted: %v",fail)}
 p,errCodes=AdvanceInstall(n,mkPlan(n),Preflighted)
 if len(errCodes)>0{t.Fatal(errCodes)}
 p.ArtifactSHA256=strings.Repeat("b",64)
 if _,fail:=AdvanceInstall(n,p,Staged);!has(fail,"PLAN_INTENT_CHANGED"){t.Fatalf("new valid digest accepted: %v",fail)}
}
func TestR19InstallRefusesChangedHostTrust(t *testing.T){
 n:=mkNode();p,fail:=AdvanceInstall(n,mkPlan(n),Preflighted);if len(fail)>0{t.Fatal(fail)}
 n.TrustVerified=false
 if _,codes:=AdvanceInstall(n,p,Staged);!has(codes,"DEVICE_TRUST_MISSING"){t.Fatalf("trust loss fail-open: %v",codes)}
 n=mkNode();p,fail=AdvanceInstall(n,mkPlan(n),Preflighted);if len(fail)>0{t.Fatal(fail)}
 n.ID="different-synthetic-node"
 if _,codes:=AdvanceInstall(n,p,Staged);!has(codes,"DEVICE_ID_MISMATCH"){t.Fatalf("physical device changed: %v",codes)}
}
func TestR19InstallNormalFlowRetainsBinding(t *testing.T){
 n:=mkNode();p,fail:=AdvanceInstall(n,mkPlan(n),Preflighted);if len(fail)>0{t.Fatal(fail)}
 for _,next:=range []Stage{Staged,Verified,Armed,BootProbing} {
  p,fail=AdvanceInstall(n,p,next);if len(fail)>0{t.Fatalf("%s: %v",next,fail)}
 }
 n.ObservedBoot=HypervisorSSD;n.HostHealthy=true;n.Admission=Ready
 p,fail=AdvanceInstall(n,p,Healthy);if len(fail)>0{t.Fatalf("healthy: %v",fail)}
 p,fail=AdvanceInstall(n,p,Committed);if len(fail)>0{t.Fatalf("commit: %v",fail)}
}
