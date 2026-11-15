package modeplan

import (
 "reflect"
 "strings"
 "testing"
)

func mkNode() Node {
 return Node{
  ID:"synthetic-wyse-01",Revision:8,Enrollment:Enrolled,Presence:Present,
  Admission:Drained,DesiredProfile:DisposableHosted,
  DesiredBoot:HypervisorSSD,ObservedBoot:RecoveryEMMC,
  Power:PowerOn,Network:LANSSHOnly,TrustVerified:true,
  RecoveryVerified:true,BackupCustodyVerified:true,
  HardwareNestedVerified:true,ActiveLeases:0,ActiveGuests:0,
  GARMHold:true,
 }
}
func mkPlan(n Node)Plan{
 return Plan{DeviceID:n.ID,ExpectedRevision:n.Revision,
  TargetProfile:DisposableHosted,TargetBoot:HypervisorSSD,Stage:Proposed,
  SSDDeviceIdentity:"synthetic-ssd-nvme-01",EMMCDeviceIdentity:"synthetic-emmc-01",
  ArtifactSHA256:strings.Repeat("a",64),ArtifactSigned:true,RightToInstall:true,
  NestedRequirement:NestedKVM,ApprovedChangeID:"synthetic-approval-001",
  SignedMutationGate:true}
}
func guest() Guest{
 return Guest{GuestID:"synthetic-vm01",ImageSHA256:strings.Repeat("f",64),
  ImageSigned:true,RightToInstall:true,IsolatedStorage:true,
  IsolatedNetwork:true,NoPhysicalTPM:true,NoRecoveryDisk:true,
  VirtualTPM:true,ResourceBudgetVerified:true,NestedRequirement:NestedKVM}
}
func has(values []string,want string)bool{for _,v:=range values{if v==want{return true}};return false}
func TestLifecycleExpectedDiscoveredEnrolledDisenrolledRetired(t *testing.T){
 n:=Node{ID:"synthetic-expected-01",Revision:0,Enrollment:Expected,Presence:NotPresent,Admission:Commissioning}
 if _,err:=AdvanceEnrollment(n,"discover",false,false);err==nil{t.Fatal("expected absent enrolled")}
 n.Presence=Present
 var err error
 n,err=AdvanceEnrollment(n,"discover",false,false);if err!=nil||n.Enrollment!=Discovered{t.Fatal(err)}
 n,err=AdvanceEnrollment(n,"request_claim",false,false);if err!=nil||n.Enrollment!=ClaimPending{t.Fatal(err)}
 if _,err=AdvanceEnrollment(n,"confirm_identity",false,false);err==nil{t.Fatal("unwitnessed trusted")}
 n,err=AdvanceEnrollment(n,"confirm_identity",true,false);if err!=nil||n.Enrollment!=Enrolled||!n.TrustVerified{t.Fatal(err)}
 // Offline is observation and must not de-enroll; only explicit revocation can.
 n.Presence=Offline
 if n.Enrollment!=Enrolled{t.Fatal("offline node lost enrollment")}
 n.Presence=Present
 n.Admission=Drained
 if _,err=AdvanceEnrollment(n,"disenroll",false,false);err==nil{t.Fatal("not revoked")}
 n,err=AdvanceEnrollment(n,"disenroll",false,true)
 if err!=nil||n.Enrollment!=Disenrolled||n.TrustVerified{t.Fatal(err)}
 if _,err=AdvanceEnrollment(n,"confirm_identity",true,true);err==nil{t.Fatal("disenrolled node bypassed claim")}
 n,err=AdvanceEnrollment(n,"retire",false,true);if err!=nil||n.Enrollment!=Retired{t.Fatal(err)}
 if _,err=AdvanceEnrollment(n,"reclaim_with_fresh_proof",true,true);err==nil{t.Fatal("retired resurrected")}
}
func TestDisenrollmentRequiresDrainAndWorkloadZero(t *testing.T){
 n:=mkNode()
 n.ActiveLeases=1
 if _,err:=AdvanceEnrollment(n,"disenroll",false,true);err==nil{t.Fatal("active lease accepted")}
 n.ActiveLeases=0;n.ActiveGuests=2
 if _,err:=AdvanceEnrollment(n,"disenroll",false,true);err==nil{t.Fatal("active guest accepted")}
 n.ActiveGuests=0;n.Admission=Ready
 if _,err:=AdvanceEnrollment(n,"disenroll",false,true);err==nil{t.Fatal("un-drained retire")}
}
func TestProfileBootMatrix(t *testing.T){
 cases:=[]struct{p Profile;b Boot;ok bool}{
  {ClusterNode,BareMetalSSD,true},{ClusterNode,HypervisorSSD,true},
  {DisposableBareMetal,BareMetalSSD,true},{DisposableBareMetal,HypervisorSSD,false},
  {DisposableHosted,HypervisorSSD,true},{DisposableHosted,BareMetalSSD,false},
  {RecoveryOnly,RecoveryEMMC,true},{RecoveryOnly,RescueUSB,true},
  {MaintenanceOnly,RecoveryEMMC,true},{RecoveryOnly,HypervisorSSD,false},
  {Profile("unknown"),HypervisorSSD,false},
 }
 for _,x:=range cases{if ProfileBootCompatible(x.p,x.b)!=x.ok{t.Errorf("profile %s boot %s",x.p,x.b)}}
}
func TestRemoteHostInstallStageGates(t *testing.T){
 n:=mkNode();p:=mkPlan(n)
 var failures []string
 p,failures=AdvanceInstall(n,p,Preflighted);if len(failures)!=0{t.Fatal(failures)}
 p,failures=AdvanceInstall(n,p,Staged);if len(failures)!=0{t.Fatal(failures)}
 p,failures=AdvanceInstall(n,p,Verified);if len(failures)!=0{t.Fatal(failures)}
 unsigned:=p;unsigned.SignedMutationGate=false
 if _,v:=AdvanceInstall(n,unsigned,Armed);!has(v,"SIGNED_CHANGE_GATE_REQUIRED"){t.Fatal("mutation without authorization")}
 p,failures=AdvanceInstall(n,p,Armed);if len(failures)!=0{t.Fatal(failures)}
 p,failures=AdvanceInstall(n,p,BootProbing);if len(failures)!=0{t.Fatal(failures)}
 if _,v:=AdvanceInstall(n,p,Healthy);!has(v,"SIGNED_HOST_HEALTH_OR_BOOT_MISMATCH"){t.Fatal("accepted unhealthy host")}
 n.ObservedBoot=HypervisorSSD;n.HostHealthy=true
 p,failures=AdvanceInstall(n,p,Healthy);if len(failures)!=0{t.Fatal(failures)}
 p,failures=AdvanceInstall(n,p,Committed);if len(failures)!=0{t.Fatal(failures)}
 if _,v:=AdvanceInstall(n,p,Staged);!has(v,"PLAN_TERMINAL"){t.Fatal("committed plan reopened")}
}
func TestRemoteHostPreflightRejectsWrongDiskRecoveryAndNested(t *testing.T){
 n:=mkNode();p:=mkPlan(n)
 cases:=[]struct{name string;mutate func(*Node,*Plan);must string}{
  {"wrong-disk",func(_ *Node,p *Plan){p.SSDDeviceIdentity=p.EMMCDeviceIdentity},"UNSAFE_OR_UNKNOWN_SSD_TARGET"},
  {"invalid-sha",func(_ *Node,p *Plan){p.ArtifactSHA256="bad"},"INVALID_ARTIFACT_DIGEST"},
  {"unsigned",func(_ *Node,p *Plan){p.ArtifactSigned=false},"ARTIFACT_UNSIGNED"},
  {"unlicensed",func(_ *Node,p *Plan){p.RightToInstall=false},"RIGHTS_NOT_VERIFIED"},
  {"backup",func(n *Node,_ *Plan){n.BackupCustodyVerified=false},"BACKUP_CUSTODY_MISSING"},
  {"recovery",func(n *Node,_ *Plan){n.RecoveryVerified=false},"RECOVERY_NOT_VERIFIED"},
  {"untrusted",func(n *Node,_ *Plan){n.TrustVerified=false},"DEVICE_TRUST_MISSING"},
  {"disenrolled",func(n *Node,_ *Plan){n.Enrollment=Disenrolled},"NOT_ENROLLED"},
  {"missing",func(n *Node,_ *Plan){n.Presence=NotPresent},"DEVICE_NOT_PRESENT"},
  {"off",func(n *Node,_ *Plan){n.Power=PowerWOL},"NOT_POWERED_ON"},
  {"offline",func(n *Node,_ *Plan){n.Network=LinkOffline},"TRUSTED_MANAGEMENT_UNREACHABLE"},
  {"running",func(n *Node,_ *Plan){n.ActiveGuests=1},"WORKLOADS_NOT_DRAINED"},
  {"not-drained",func(n *Node,_ *Plan){n.Admission=Ready},"HOST_MUST_BE_DRAINED_FOR_INSTALL"},
  {"wrong-profile",func(_ *Node,p *Plan){p.TargetBoot=BareMetalSSD},"PROFILE_BOOT_MISMATCH"},
  {"no-nested",func(n *Node,_ *Plan){n.HardwareNestedVerified=false},"NESTED_HARDWARE_NOT_QUALIFIED"},
  {"stale",func(n *Node,_ *Plan){n.Revision++},"STALE_REVISION"},
 }
 for _,x:=range cases{
  nn,pp:=n,p;x.mutate(&nn,&pp)
  fail:=HostPreflight(nn,pp)
  if !has(fail,x.must){t.Errorf("%s: expected %s got %v",x.name,x.must,fail)}
 }
 if fail:=HostPreflight(n,p);len(fail)!=0{t.Fatalf("legitimate host plan rejected %v",fail)}
}
func TestRemoteGuestStandaloneVersusGARMAdmission(t *testing.T){
 n:=mkNode()
 n.Admission=Ready;n.ObservedBoot=HypervisorSSD;n.HostHealthy=true;n.ActualHypervisorInstalled=true;n.HostNestedVerified=true
 g:=guest()
 if r:=GuestPreflight(n,g);len(r)!=0{t.Fatalf("standalone guest incorrectly gated on GARM hold %v",r)}
 if r:=RunnerAdmission(n,g);!has(r,"GARM_LIVE_HOLD"){t.Fatalf("live hold bypass %v",r)}
 n.GARMHold=false
 if r:=RunnerAdmission(n,g);len(r)!=0{t.Fatal(r)}
 tests:=[]struct{name string;mutate func(*Node,*Guest);code string}{
  {"guest-physical-tpm",func(_ *Node,g *Guest){g.NoPhysicalTPM=false},"GUEST_ISOLATION_NOT_PROVEN"},
  {"guest-emmc",func(_ *Node,g *Guest){g.NoRecoveryDisk=false},"GUEST_ISOLATION_NOT_PROVEN"},
  {"network",func(_ *Node,g *Guest){g.IsolatedNetwork=false},"GUEST_ISOLATION_NOT_PROVEN"},
  {"disk",func(_ *Node,g *Guest){g.IsolatedStorage=false},"GUEST_ISOLATION_NOT_PROVEN"},
  {"budget",func(_ *Node,g *Guest){g.ResourceBudgetVerified=false},"GUEST_RESOURCE_BUDGET_MISSING"},
  {"nested",func(n *Node,_ *Guest){n.HostNestedVerified=false},"NESTED_L2_NOT_QUALIFIED"},
  {"host",func(n *Node,_ *Guest){n.HostHealthy=false},"HYPERVISOR_NOT_HEALTHY"},
  {"uninstalled",func(n *Node,_ *Guest){n.ActualHypervisorInstalled=false},"HYPERVISOR_NOT_HEALTHY"},
  {"baremetal",func(n *Node,_ *Guest){n.DesiredBoot=BareMetalSSD},"HYPERVISOR_NOT_HEALTHY"},
  {"quarantine",func(n *Node,_ *Guest){n.Admission=Quarantined},"HOST_NOT_READY"},
  {"license",func(_ *Node,g *Guest){g.RightToInstall=false},"GUEST_ARTIFACT_UNQUALIFIED"},
  {"not-powered",func(n *Node,_ *Guest){n.Power=PowerWOL},"HOST_NOT_POWERED"},
  {"remote-offline",func(n *Node,_ *Guest){n.Network=LinkOffline},"TRUSTED_MANAGEMENT_UNREACHABLE"},
  {"no-recovery",func(n *Node,_ *Guest){n.RecoveryVerified=false},"RECOVERY_NOT_VERIFIED"},
  {"guest-vtpm",func(_ *Node,g *Guest){g.RequiresVTPM=true;g.VirtualTPM=false},"REQUIRED_GUEST_VTPM_MISSING"},
 }
 for _,x:=range tests{nn,gg:=n,g;x.mutate(&nn,&gg);if !has(GuestPreflight(nn,gg),x.code){t.Errorf("%s fail-open",x.name)}}
}
func TestNoHostToBaremetalFallbackAndNoSideEffects(t *testing.T){
 n:=mkNode();p:=mkPlan(n)
 n.HardwareNestedVerified=false
 beforeN,beforeP:=n,p
 if _,errors:=AdvanceInstall(n,p,Preflighted);!has(errors,"NESTED_HARDWARE_NOT_QUALIFIED"){t.Fatal("nonnested rejected?")}
 if !reflect.DeepEqual(n,beforeN)||!reflect.DeepEqual(p,beforeP){t.Fatal("validator mutated source records")}
 if ProfileBootCompatible(DisposableHosted,BareMetalSSD){t.Fatal("hosted auto fell back to baremetal")}
 if !ProfileBootCompatible(ClusterNode,BareMetalSSD)||!ProfileBootCompatible(ClusterNode,HypervisorSSD){t.Fatal("cluster substrate should be independent")}
}


func TestBareMetalRunnerSeparateFromHostedGuest(t *testing.T){
 n:=mkNode()
 n.DesiredProfile=DisposableBareMetal;n.DesiredBoot=BareMetalSSD
 n.ObservedBoot=BareMetalSSD;n.Admission=Ready;n.HostHealthy=true;n.GARMHold=false
 if v:=BareMetalRunnerAdmission(n);len(v)!=0{t.Fatalf("healthy baremetal runner refused: %v",v)}
 if v:=GuestPreflight(n,guest());!has(v,"HYPERVISOR_NOT_HEALTHY"){t.Fatal("baremetal node misclassified as VM host")}
 n.GARMHold=true
 if v:=BareMetalRunnerAdmission(n);!has(v,"GARM_LIVE_HOLD"){t.Fatal("GARM hold ignored on baremetal")}
 n.GARMHold=false;n.DesiredProfile=ClusterNode
 if v:=BareMetalRunnerAdmission(n);len(v)!=0{t.Fatalf("cluster-managed baremetal runner rejected %v",v)}
 cases:=[]struct{fn func(*Node);code string}{
  {func(n *Node){n.Admission=Quarantined},"HOST_NOT_READY"},
  {func(n *Node){n.Network=LinkOffline},"TRUSTED_MANAGEMENT_UNREACHABLE"},
  {func(n *Node){n.Power=PowerNoWOL},"HOST_NOT_POWERED"},
  {func(n *Node){n.RecoveryVerified=false},"RECOVERY_NOT_VERIFIED"},
  {func(n *Node){n.ObservedBoot=RecoveryEMMC},"BAREMETAL_OS_NOT_HEALTHY"},
  {func(n *Node){n.ActiveGuests=1},"ACTIVE_GUESTS_ON_BAREMETAL_PROFILE"},
  {func(n *Node){n.Enrollment=Disenrolled},"DEVICE_NOT_ADMITTED"},
 }
 for _,x:=range cases{nn:=n;x.fn(&nn);if !has(BareMetalRunnerAdmission(nn),x.code){t.Errorf("%s not rejected",x.code)}}
}
