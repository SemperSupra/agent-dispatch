package admission

import (
 "encoding/json"
 "strings"
 "testing"
)
func accepted()Transition{
 h:=strings.Repeat("a",64)
 return Transition{
  Intent:"SYNTHETIC_PLAN_ONLY",Source:"passive_dhcp",NodeOpaqueID:"node_candidate_001",
  OperationID:"op_002",PreviousOperationID:"op_001",
  From:"DEPLOYED",To:"AVAILABLE",OwnerSelected:true,
  SignedBootstrapSHA256:h,PairingVerified:true,HardwareGeneration:h,
  CommissioningPass:true,ProfileVerified:true,ConfigProposalSHA256:h,
  QualificationPass:true,DeploymentOwnerApproved:true,
  DeploymentArtifactSHA256:h,DeploymentVerified:true,
 }
}
func TestEveryAdjacentStateCanBeCheckedIndependently(t *testing.T){
 for i:=0;i<len(stages)-1;i++{
  v:=accepted();v.From=stages[i];v.To=stages[i+1]
  if e:=Validate(v);e!=nil{t.Fatalf("valid synthetic %s => %s rejected: %v",v.From,v.To,e)}
 }
}
func TestUntrustedDiscoveryIsNeverAutomaticApproval(t *testing.T){
 for _,source:=range []string{"passive_dhcp","paired_agent","isolated_pxe","bmc"}{
  v:=accepted();v.Source=source;v.From=stages[0];v.To=stages[1]
  v.OwnerSelected=false
  if Validate(v)==nil {t.Fatalf("network hint %s self-enrolled",source)}
  v.OwnerSelected=true
  if e:=Validate(v);e!=nil{t.Fatalf("synthetic selection unexpectedly denied %v",e)}
 }
}
func TestModelCannotEscalateLifecycleOrFakeEvidence(t *testing.T){
 cases:=[]struct{name string; edit func(*Transition)}{
  {"unsupported-discovery",func(x *Transition){x.Source="internet_scan"}},
  {"wrong-intent",func(x *Transition){x.Intent="AUTO_DEPLOY"}},
  {"raw-network-identifier",func(x *Transition){x.NodeOpaqueID="b0:5a:da:7a:00:ff"}},
  {"operator-id-replay",func(x *Transition){x.PreviousOperationID=x.OperationID}},
  {"unknown-identity",func(x *Transition){x.NodeOpaqueID=""}},
  {"skip-qualification",func(x *Transition){x.From="CONFIG_PROPOSED"}},
  {"revert-to-same",func(x *Transition){x.From=x.To}},
  {"missing-owner",func(x *Transition){x.OwnerSelected=false}},
  {"unsigned-bootstrap",func(x *Transition){x.SignedBootstrapSHA256=""}},
  {"pairing-missing",func(x *Transition){x.PairingVerified=false}},
  {"G0-missing",func(x *Transition){x.HardwareGeneration="unknown"}},
  {"commission-failed",func(x *Transition){x.CommissioningPass=false}},
  {"profile-failed",func(x *Transition){x.ProfileVerified=false}},
  {"unversioned-proposal",func(x *Transition){x.ConfigProposalSHA256=""}},
  {"no-qualified-build",func(x *Transition){x.QualificationPass=false}},
  {"owner-deployment-approval-missing",func(x *Transition){x.DeploymentOwnerApproved=false}},
  {"unhashed-artifact",func(x *Transition){x.DeploymentArtifactSHA256=""}},
  {"deploy-not-verified",func(x *Transition){x.DeploymentVerified=false}},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  v:=accepted();tc.edit(&v)
  if Validate(v)==nil{t.Fatalf("unsafe state accepted: %s",tc.name)}
 })}
}
func TestOrdinaryStatusNeverExposesHardwareOrDiscovery(t *testing.T){
 for _,state:=range stages{
  v:=ProjectPublic(state)
  b,e:=json.Marshal(v);if e!=nil{t.Fatal(e)}
  for _,secret:=range []string{"hardware","pci","usb","iommu","generation","count","mac","serial","device","source"}{
   if strings.Contains(string(b),secret){t.Fatalf("public exposure %s",secret)}
  }
  if state=="AVAILABLE" && v.State!="available"{t.Fatal("available status missing")}
 }
}
