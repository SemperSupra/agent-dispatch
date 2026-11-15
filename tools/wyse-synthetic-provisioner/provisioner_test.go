package provisioner

import (
 "context"
 "errors"
 "os"
 "strings"
 "testing"
)
func fixture()Plan{
 h:=[]byte("synthetic signed hypervisor fixture")
 g:=[]byte("synthetic signed guest fixture")
 return Plan{DeviceID:"synthetic-node-01",Revision:5,ExpectedRevision:5,SSDIdentity:"synthetic-sata-01",EMMCIdentity:"synthetic-emmc-01",HostImage:h,HostSHA256:digest(h),GuestImage:g,GuestSHA256:digest(g),HostSigned:true,GuestSigned:true,InstallRights:true,BackupCustody:true,IndependentRecovery:true,ApprovedChangeID:"synthetic-only",SignedGate:true,HostHealthProof:true,GuestHealthProof:true,GuestIsolatedStorage:true,GuestIsolatedNetwork:true,GuestNoPhysicalTPM:true,GuestNoRecoveryDisk:true,GuestVTPM:true,RequiresNested:true,NestedQualified:true,GARMHold:true}
}
func TestSyntheticHostGuestAndZeroResidue(t *testing.T){
 r,err:=Run(context.Background(),fixture());if err!=nil{t.Fatal(err)}
 if r.Verdict!="SYNTHETIC_PASS"||len(r.Phases)!=5||!r.EMMCPreserved||!r.CleanupVerified||r.GARMAdmission!="HOLD"{t.Fatalf("bad receipt: %+v",r)}
 if _,err:=os.Stat(r.SandboxPath);!errors.Is(err,os.ErrNotExist){t.Fatalf("residue %v",err)}
}
func TestPreflightFailClosedMatrix(t *testing.T){
 tests:=[]struct{name string;f func(*Plan)}{
  {"stale",func(p *Plan){p.Revision++}},
  {"raw-disk",func(p *Plan){p.SSDIdentity="/dev/sda"}},
  {"mmc-swap",func(p *Plan){p.SSDIdentity="/dev/mmcblk0"}},
  {"untrusted-host-hash",func(p *Plan){p.HostSHA256=strings.Repeat("0",64)}},
  {"untrusted-guest-hash",func(p *Plan){p.GuestSHA256=strings.Repeat("0",64)}},
  {"unsigned",func(p *Plan){p.HostSigned=false}},
  {"rights",func(p *Plan){p.InstallRights=false}},
  {"custody",func(p *Plan){p.BackupCustody=false}},
  {"recovery",func(p *Plan){p.IndependentRecovery=false}},
  {"mutation-approval",func(p *Plan){p.SignedGate=false}},
  {"no-vtpm",func(p *Plan){p.GuestVTPM=false}},
  {"physical-tpm",func(p *Plan){p.GuestNoPhysicalTPM=false}},
  {"guest-emmc",func(p *Plan){p.GuestNoRecoveryDisk=false}},
  {"guest-net",func(p *Plan){p.GuestIsolatedNetwork=false}},
  {"guest-storage",func(p *Plan){p.GuestIsolatedStorage=false}},
  {"nested",func(p *Plan){p.NestedQualified=false}},
  {"garm-hold",func(p *Plan){p.GARMHold=false}},
 }
 for _,x:=range tests {t.Run(x.name,func(t *testing.T){p:=fixture();x.f(&p);r,err:=Run(context.Background(),p);if err==nil||r.Verdict!="REFUSED_PREFLIGHT"||r.SandboxPath!=""{t.Fatalf("fail-open: %+v %v",r,err)}})}
}
func TestInjectedFaultCleanup(t *testing.T){
 for _,phase:=range []string{"write","verify","boot","guest"}{t.Run(phase,func(t *testing.T){p:=fixture();p.FailAfter=phase;r,err:=Run(context.Background(),p);if err==nil||r.Verdict!="FAULT_INJECTED"||!r.CleanupVerified{t.Fatalf("fault accepted %+v %v",r,err)};if _,err:=os.Stat(r.SandboxPath);!errors.Is(err,os.ErrNotExist){t.Fatal("sandbox residue")}})}
}
func TestMissingHealthAndCancelled(t *testing.T){
 for _,host:=range []bool{true,false} {p:=fixture();if host{p.HostHealthProof=false}else{p.GuestHealthProof=false};r,err:=Run(context.Background(),p);if err==nil||!r.CleanupVerified||r.Verdict=="SYNTHETIC_PASS"{t.Fatalf("health accepted %+v",r)}}
 ctx,cancel:=context.WithCancel(context.Background());cancel();r,err:=Run(ctx,fixture());if !errors.Is(err,context.Canceled)||!r.CleanupVerified{t.Fatalf("cancel %+v %v",r,err)}
}
func TestOversizeReject(t *testing.T){p:=fixture();p.GuestImage=make([]byte,maxFixtureBytes+1);p.GuestSHA256=digest(p.GuestImage);if err:=Preflight(p);err==nil{t.Fatal("oversize accepted")}}
