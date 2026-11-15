// Package modeplan holds the hardware-independent Wyse lifecycle and remote
// provisioning guard contract. It is deliberately a PURE policy library:
// no filesystem, network, firmware, disk, TPM, GARM or power actuator exists.
package modeplan

import (
  "errors"
  "fmt"
  "strings"
)

type Enrollment string
const (
 Expected Enrollment = "EXPECTED"
 Discovered Enrollment = "DISCOVERED"
 ClaimPending Enrollment = "CLAIM_PENDING"
 Enrolled Enrollment = "ENROLLED"
 Disenrolled Enrollment = "DISENROLLED"
 Retired Enrollment = "RETIRED"
)
type Presence string
const (
 NotPresent Presence = "NOT_PRESENT"
 Present Presence = "PRESENT"
 Offline Presence = "OFFLINE"
 UnknownPresence Presence = "UNKNOWN"
)
type Admission string
const (
 Commissioning Admission = "COMMISSIONING"
 Ready Admission = "READY"
 Drained Admission = "DRAINED"
 Maintenance Admission = "MAINTENANCE"
 Quarantined Admission = "QUARANTINED"
)
type Profile string
const (
 ClusterNode Profile = "CLUSTER_NODE"
 DisposableBareMetal Profile = "DISPOSABLE_BARE_METAL"
 DisposableHosted Profile = "DISPOSABLE_HOSTED"
 RecoveryOnly Profile = "RECOVERY_ONLY"
 MaintenanceOnly Profile = "MAINTENANCE_ONLY"
)
type Boot string
const (
 RecoveryEMMC Boot = "RECOVERY_EMMC"
 RescueUSB Boot = "USB_RESCUE"
 BareMetalSSD Boot = "BARE_METAL_SSD"
 HypervisorSSD Boot = "HYPERVISOR_SSD"
 BootUnknown Boot = "UNKNOWN"
)
type Power string
const (
 PowerOn Power = "ON"
 PowerWOL Power = "OFF_WOL_ELIGIBLE"
 PowerNoWOL Power = "OFF_NO_WOL"
 PowerUnknown Power = "UNKNOWN"
)
type Link string
const (
 OverlayOnline Link = "OVERLAY_ONLINE"
 LANSSHOnly Link = "LAN_SSH_ONLY"
 LinkOffline Link = "OFFLINE"
)
type Nested string
const (
 NoNested Nested = "NONE"
 NestedKVM Nested = "KVM"
 NestedHyperV Nested = "HYPERV"
 NestedFirecracker Nested = "FIRECRACKER"
 NestedProxmox Nested = "PROXMOX"
)
type Stage string
const (
 Proposed Stage = "PROPOSED"
 Preflighted Stage = "PREFLIGHTED"
 Staged Stage = "STAGED"
 Verified Stage = "VERIFIED"
 Armed Stage = "ARMED"
 BootProbing Stage = "BOOT_PROBING"
 Healthy Stage = "HEALTHY"
 Committed Stage = "COMMITTED"
 RolledBack Stage = "ROLLED_BACK"
 Failed Stage = "FAILED"
)
type Node struct {
 ID string `json:"id"`
 Revision uint64 `json:"revision"`
 Enrollment Enrollment `json:"enrollment"`
 Presence Presence `json:"presence"`
 Admission Admission `json:"admission"`
 DesiredProfile Profile `json:"desired_profile"`
 DesiredBoot Boot `json:"desired_boot"`
 ObservedBoot Boot `json:"observed_boot"`
 Power Power `json:"power"`
 Network Link `json:"network"`
 TrustVerified bool `json:"trust_verified"`
 RecoveryVerified bool `json:"recovery_verified"`
 BackupCustodyVerified bool `json:"backup_custody_verified"`
 HardwareNestedVerified bool `json:"hardware_nested_verified"`
 HostNestedVerified bool `json:"host_nested_verified"`
 HostHealthy bool `json:"host_healthy"`
 ActualHypervisorInstalled bool `json:"actual_hypervisor_installed"`
 ActiveLeases uint32 `json:"active_leases"`
 ActiveGuests uint32 `json:"active_guests"`
 GARMHold bool `json:"garm_hold"`
}
type Plan struct {
 DeviceID string `json:"device_id"`
 ExpectedRevision uint64 `json:"expected_revision"`
 TargetProfile Profile `json:"target_profile"`
 TargetBoot Boot `json:"target_boot"`
 Stage Stage `json:"stage"`
 SSDDeviceIdentity string `json:"ssd_device_identity"`
 EMMCDeviceIdentity string `json:"emmc_device_identity"`
 ArtifactSHA256 string `json:"artifact_sha256"`
 ArtifactSigned bool `json:"artifact_signed"`
 RightToInstall bool `json:"right_to_install"`
 NestedRequirement Nested `json:"nested_requirement"`
 ApprovedChangeID string `json:"approved_change_id"`
 SignedMutationGate bool `json:"signed_mutation_gate"`
}
type Guest struct {
 GuestID string `json:"guest_id"`
 ImageSHA256 string `json:"image_sha256"`
 ImageSigned bool `json:"image_signed"`
 RightToInstall bool `json:"right_to_install"`
 IsolatedStorage bool `json:"isolated_storage"`
 IsolatedNetwork bool `json:"isolated_network"`
 NoPhysicalTPM bool `json:"no_physical_tpm"`
 NoRecoveryDisk bool `json:"no_recovery_disk"`
 VirtualTPM bool `json:"virtual_tpm"`
 NestedRequirement Nested `json:"nested_requirement"`
 ResourceBudgetVerified bool `json:"resource_budget_verified"`
}
func digest(s string) bool {
 if len(s)!=64{return false}
 for _,c:=range s {if !(c>='0'&&c<='9'||c>='a'&&c<='f'){return false}}
 return true
}
func knownProfile(x Profile) bool {
 switch x{case ClusterNode,DisposableBareMetal,DisposableHosted,RecoveryOnly,MaintenanceOnly:return true}
 return false
}
func knownBoot(x Boot)bool{
 switch x{case RecoveryEMMC,RescueUSB,BareMetalSSD,HypervisorSSD:return true}
 return false
}
func knownNested(x Nested)bool{
 switch x{case NoNested,NestedKVM,NestedHyperV,NestedFirecracker,NestedProxmox:return true}
 return false
}
// ProfileBootCompatible says what operator-facing profile can use which
// substrate. Cluster membership is distinct from runtime substrate.
func ProfileBootCompatible(profile Profile,boot Boot)bool{
 switch profile{
 case ClusterNode:return boot==BareMetalSSD||boot==HypervisorSSD
 case DisposableBareMetal:return boot==BareMetalSSD
 case DisposableHosted:return boot==HypervisorSSD
 case RecoveryOnly,MaintenanceOnly:return boot==RecoveryEMMC||boot==RescueUSB
 }
 return false
}
func lifecycleNext(from Enrollment,action string)(Enrollment,bool){
 switch from{
 case Expected:
  if action=="discover"{return Discovered,true}
 case Discovered:
  if action=="request_claim"{return ClaimPending,true}
 case ClaimPending:
  if action=="confirm_identity"{return Enrolled,true}
  if action=="cancel_claim"{return Discovered,true}
 case Enrolled:
  if action=="disenroll"{return Disenrolled,true}
 case Disenrolled:
  if action=="reclaim_with_fresh_proof"{return ClaimPending,true}
  if action=="retire"{return Retired,true}
 }
 return "",false
}
// AdvanceEnrollment is a PURE planner. "confirm_identity" is only legal when
// proof was independently validated by the authenticated caller. It cannot
// create a certificate or remove an identity grant itself.
func AdvanceEnrollment(n Node,action string,freshWitness bool,revoked bool)(Node,error){
 dest,ok:=lifecycleNext(n.Enrollment,action)
 if !ok{return n,fmt.Errorf("forbidden lifecycle transition %s/%s",n.Enrollment,action)}
 if n.ID==""{return n,errors.New("missing inventory identity")}
 if action=="discover"&&n.Presence!=Present{return n,errors.New("discovery requires observed physical device")}
 if action=="request_claim"&&n.Presence!=Present{return n,errors.New("claim requires present device")}
 if action=="confirm_identity"&&(!freshWitness||n.Presence!=Present){return n,errors.New("independent fresh witnessed identity proof required")}
 if action=="disenroll" {
  if n.ActiveLeases!=0||n.ActiveGuests!=0{return n,errors.New("drain all workloads before disenrollment")}
  if n.Admission!=Drained&&n.Admission!=Quarantined{return n,errors.New("drain or quarantine before disenrollment")}
  if !revoked{return n,errors.New("external credential revocation receipt required")}
 }
 if action=="reclaim_with_fresh_proof"&&!revoked{return n,errors.New("old credentials must remain revoked before re-claim")}
 if action=="retire"&&!revoked{return n,errors.New("revocation receipt required before retirement")}
 n.Enrollment=dest;n.Revision++
 if dest==Disenrolled||dest==Retired {
  n.TrustVerified=false;n.Admission=Quarantined
 }
 if dest==ClaimPending {n.TrustVerified=false;n.Admission=Commissioning}
 if dest==Enrolled {n.TrustVerified=true;n.Admission=Commissioning}
 return n,nil
}
func (n Node) validateCommon() []string {
 var fail []string
 if n.Enrollment!=Enrolled{fail=append(fail,"NOT_ENROLLED")}
 if !n.TrustVerified{fail=append(fail,"DEVICE_TRUST_MISSING")}
 if n.Presence!=Present{fail=append(fail,"DEVICE_NOT_PRESENT")}
 if n.Power!=PowerOn{fail=append(fail,"NOT_POWERED_ON")}
 if n.Admission!=Drained&&n.Admission!=Maintenance{fail=append(fail,"HOST_MUST_BE_DRAINED_FOR_INSTALL")}
 if n.ActiveLeases!=0||n.ActiveGuests!=0{fail=append(fail,"WORKLOADS_NOT_DRAINED")}
 if !n.RecoveryVerified{fail=append(fail,"RECOVERY_NOT_VERIFIED")}
 if !n.BackupCustodyVerified{fail=append(fail,"BACKUP_CUSTODY_MISSING")}
 if n.Network!=OverlayOnline&&n.Network!=LANSSHOnly{fail=append(fail,"TRUSTED_MANAGEMENT_UNREACHABLE")}
 return fail
}
func validSSD(ident,emmc string)bool{
 return ident!=""&&emmc!=""&&ident!=emmc&&
  !strings.ContainsAny(ident," \t\r\n")&&!strings.ContainsAny(emmc," \t\r\n")
}
// HostPreflight is non-mutating. A successful result does NOT authorize a
// flash or BootNext: a separate signed, scoped mutation gate is required.
func HostPreflight(n Node,p Plan) []string {
 fail:=n.validateCommon()
 if n.ID!=p.DeviceID {fail=append(fail,"DEVICE_ID_MISMATCH")}
 if n.Revision!=p.ExpectedRevision {fail=append(fail,"STALE_REVISION")}
 if !knownProfile(p.TargetProfile)||!knownBoot(p.TargetBoot)||!ProfileBootCompatible(p.TargetProfile,p.TargetBoot){fail=append(fail,"PROFILE_BOOT_MISMATCH")}
 if p.TargetProfile==RecoveryOnly||p.TargetProfile==MaintenanceOnly {fail=append(fail,"NO_SSD_INSTALL_IN_SAFETY_PROFILE")}
 if !validSSD(p.SSDDeviceIdentity,p.EMMCDeviceIdentity){fail=append(fail,"UNSAFE_OR_UNKNOWN_SSD_TARGET")}
 if !digest(p.ArtifactSHA256){fail=append(fail,"INVALID_ARTIFACT_DIGEST")}
 if !p.ArtifactSigned{fail=append(fail,"ARTIFACT_UNSIGNED")}
 if !p.RightToInstall{fail=append(fail,"RIGHTS_NOT_VERIFIED")}
 if !knownNested(p.NestedRequirement){fail=append(fail,"UNKNOWN_NESTED_KIND")}
 if p.TargetBoot==BareMetalSSD&&p.NestedRequirement!=NoNested{fail=append(fail,"NESTED_REQUIREMENT_NEEDS_HYPERVISOR")}
 if p.NestedRequirement!=NoNested&&!n.HardwareNestedVerified{fail=append(fail,"NESTED_HARDWARE_NOT_QUALIFIED")}
 return fail
}
func AdvanceInstall(n Node,p Plan,next Stage) (Plan,[]string){
 if p.Stage==RolledBack||p.Stage==Failed||p.Stage==Committed{return p,[]string{"PLAN_TERMINAL"}}
 if p.Stage==Proposed&&next==Preflighted{
  if err:=HostPreflight(n,p);len(err)!=0{return p,err}
 }else{
  allowed:=map[Stage]Stage{Preflighted:Staged,Staged:Verified,Verified:Armed,Armed:BootProbing,BootProbing:Healthy,Healthy:Committed}
  if next==RolledBack&&p.Stage!=Proposed {
   p.Stage=RolledBack;return p,nil
  }
  if next==Failed {
   p.Stage=Failed;return p,nil
  }
  if allowed[p.Stage]!=next{return p,[]string{"INVALID_INSTALL_PHASE"}}
  if n.Revision!=p.ExpectedRevision{return p,[]string{"STALE_REVISION"}}
 }
 if next==Armed {
  if p.ApprovedChangeID==""||!p.SignedMutationGate{return p,[]string{"SIGNED_CHANGE_GATE_REQUIRED"}}
 }
 if next==Healthy {
  if n.ObservedBoot!=p.TargetBoot||!n.HostHealthy{return p,[]string{"SIGNED_HOST_HEALTH_OR_BOOT_MISMATCH"}}
 }
 p.Stage=next
 return p,nil
}
// GuestPreflight checks a separate guest transaction. The parent hypervisor
// must already be installed, healthy, attested and isolated from recovery.
func GuestPreflight(n Node,g Guest) []string {
 var fail []string
 if n.Enrollment!=Enrolled||!n.TrustVerified||n.Presence!=Present{fail=append(fail,"DEVICE_NOT_ADMITTED")}
 if n.Admission!=Ready||n.GARMHold{fail=append(fail,"SCHEDULING_OR_GARM_HOLD")}
 if n.DesiredBoot!=HypervisorSSD||n.ObservedBoot!=HypervisorSSD||!n.ActualHypervisorInstalled||!n.HostHealthy{fail=append(fail,"HYPERVISOR_NOT_HEALTHY")}
 if n.DesiredProfile!=DisposableHosted&&n.DesiredProfile!=ClusterNode{fail=append(fail,"WRONG_HOSTED_PROFILE")}
 if g.GuestID==""||!digest(g.ImageSHA256)||!g.ImageSigned||!g.RightToInstall{fail=append(fail,"GUEST_ARTIFACT_UNQUALIFIED")}
 if !g.IsolatedStorage||!g.IsolatedNetwork||!g.NoPhysicalTPM||!g.NoRecoveryDisk{fail=append(fail,"GUEST_ISOLATION_NOT_PROVEN")}
 if !g.ResourceBudgetVerified{fail=append(fail,"GUEST_RESOURCE_BUDGET_MISSING")}
 if !knownNested(g.NestedRequirement){fail=append(fail,"UNKNOWN_NESTED_KIND")}
 if g.NestedRequirement!=NoNested&&(!n.HardwareNestedVerified||!n.HostNestedVerified){fail=append(fail,"NESTED_L2_NOT_QUALIFIED")}
 return fail
}
// Admission to the existing GARM/Agent Dispatch provider is separate from
// successful guest provisioning and is explicitly disabled by a live hold.
func RunnerAdmission(n Node,g Guest) []string {
 return GuestPreflight(n,g)
}
