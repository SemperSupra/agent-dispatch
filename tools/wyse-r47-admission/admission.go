// Package admission checks a synthetic discovery/enrollment transition.
// It does not discover, attest, enroll, provision, authenticate or contact hosts.
package admission

import (
 "errors"
 "regexp"
)
type Transition struct {
 Intent string `json:"intent"`
 Source string `json:"source"` // passive_dhcp, paired_agent, isolated_pxe, bmc
 NodeOpaqueID string `json:"node_opaque_id"`
 OperationID string `json:"operation_id"`
 PreviousOperationID string `json:"previous_operation_id"`
 From string `json:"from"`
 To string `json:"to"`
 OwnerSelected bool `json:"owner_selected"`
 SignedBootstrapSHA256 string `json:"signed_bootstrap_sha256"`
 PairingVerified bool `json:"pairing_verified"`
 HardwareGeneration string `json:"hardware_generation"`
 CommissioningPass bool `json:"commissioning_pass"`
 ProfileVerified bool `json:"profile_verified"`
 ConfigProposalSHA256 string `json:"config_proposal_sha256"`
 QualificationPass bool `json:"qualification_pass"`
 DeploymentOwnerApproved bool `json:"deployment_owner_approved"`
 DeploymentArtifactSHA256 string `json:"deployment_artifact_sha256"`
 DeploymentVerified bool `json:"deployment_verified"`
}
var stages=[]string{
 "DETECTED_UNTRUSTED","OWNER_SELECTED","PAIRING_PENDING","PAIRING_VERIFIED",
 "G0_OBSERVED","COMMISSIONED","PROFILED","CONFIG_PROPOSED",
 "QUALIFICATION_PENDING","QUALIFIED","DEPLOYMENT_APPROVED",
 "DEPLOYED","AVAILABLE",
}
var digestRE=regexp.MustCompile("^[a-f0-9]{64}$")
var opaqueRE=regexp.MustCompile("^[a-z][a-z0-9_-]{3,63}$")
func no(code string)error{return errors.New("DENIED:"+code)}
func index(s string)int{for i,v:=range stages{if v==s{return i}};return -1}
func Validate(t Transition)error{
 if t.Intent!="SYNTHETIC_PLAN_ONLY" {return no("MUTATING_OR_FALSE_ATTESTATION_INTENT")}
 if !opaqueRE.MatchString(t.NodeOpaqueID)||!opaqueRE.MatchString(t.OperationID)||
  t.PreviousOperationID==t.OperationID{return no("INVALID_OR_REPLAYED_OPAQUE_ID")}
 switch t.Source{
 case "passive_dhcp","paired_agent","isolated_pxe","bmc":
 default:return no("UNKNOWN_DISCOVERY_SOURCE")
 }
 prev,next:=index(t.From),index(t.To)
 if prev<0||next!=prev+1{return no("STATE_SKIP_OR_INVALID")}
 if next>=1&&!t.OwnerSelected {return no("NO_EXPLICIT_OWNER_SELECTION")}
 if next>=2&&!digestRE.MatchString(t.SignedBootstrapSHA256) {return no("BOOTSTRAP_NOT_PINNED")}
 if next>=3&&!t.PairingVerified {return no("PAIRING_NOT_VERIFIED")}
 if next>=4&&!digestRE.MatchString(t.HardwareGeneration){return no("MISSING_PRIVATE_G0_GENERATION")}
 if next>=5&&!t.CommissioningPass{return no("COMMISSIONING_NOT_QUALIFIED")}
 if next>=6&&!t.ProfileVerified{return no("PROFILE_NOT_QUALIFIED")}
 if next>=7&&!digestRE.MatchString(t.ConfigProposalSHA256){return no("NO_SIGNED_OR_HASHED_CONFIG_PROPOSAL")}
 if next>=9&&!t.QualificationPass{return no("CANDIDATE_CONFIG_NOT_QUALIFIED")}
 if next>=10&&!t.DeploymentOwnerApproved{return no("NO_DEPLOYMENT_OWNER_APPROVAL")}
 if next>=11&&!digestRE.MatchString(t.DeploymentArtifactSHA256){return no("NO_PINNED_DEPLOYMENT_ARTIFACT")}
 if next>=12&&!t.DeploymentVerified{return no("DEPLOYMENT_NOT_VERIFIED")}
 // NOTE: Boolean fields in fixtures are NOT real attestations. Production
 // controller must verify signed receipts and physical identity out-of-band.
 return nil
}
// PublicView deliberately excludes *all* host-device inventories, counts,
// hardware generations, discovery MAC/IP and possible guest-assignment APIs.
type PublicView struct{
 State string `json:"state"`
}
func ProjectPublic(state string)PublicView{
 if state!="AVAILABLE" {return PublicView{State:"unavailable"}}
 return PublicView{State:"available"}
}
