package planner

import (
 "strings"
 "testing"
)

func hw()Hardware{return Hardware{
 Generation:strings.Repeat("a",64),Arch:"amd64",CPUThreads:4,RAMMiB:8192,
 HostReserveMiB:2048,RecoveryVerified:true,KVMGuestBootQualified:true,
 RenderGuestQualified:false,USBGuestQualified:false,
}}
func work()Workload{return Workload{ID:"cli-job",Kind:"cli",VCpus:2,MemoryMiB:2048,RequireIsolation:true}}
func plan(h Hardware,w Workload,p string)Candidate{return Candidate{
 Profile:p,VCpus:w.VCpus,MemoryMiB:w.MemoryMiB,
 HardwareGeneration:h.Generation,WorkloadID:w.ID,Qualification:"SYNTHETIC_PLAN_ONLY",
}}
func TestTrustedRecoveryAndHardwareConstraints(t *testing.T){
 h,w:=hw(),work()
 candidates:=Propose(h,w)
 if len(candidates)!=1||candidates[0].Profile!="kvm-virtio"{
  t.Fatalf("expected one synthetic KVM plan, got %+v",candidates)
 }
 if !strings.Contains(Verdict(candidates[0]),"REAL_WATTS_THERMALS_AND_HARDWARE=NOT_TESTED"){
  t.Fatal("false physical optimization claim")
 }
}
func TestFailClosedPlanMutations(t *testing.T){
 fixtures:=[]struct{
  name string; bad func(*Hardware,*Workload,*Candidate)
 }{
  {"missing-recovery",func(h *Hardware,_ *Workload,_ *Candidate){h.RecoveryVerified=false}},
  {"invalid-generation",func(h *Hardware,_ *Workload,_ *Candidate){h.Generation="unknown"}},
  {"stale-hardware-generation",func(_ *Hardware,_ *Workload,c *Candidate){c.HardwareGeneration=strings.Repeat("b",64)}},
  {"model-skips-qualification",func(_ *Hardware,_ *Workload,c *Candidate){c.Qualification="PRODUCTION_READY"}},
  {"fewer-cpu-threads",func(h *Hardware,_ *Workload,_ *Candidate){h.CPUThreads=1}},
  {"ram-insufficient",func(h *Hardware,_ *Workload,_ *Candidate){h.RAMMiB=3072}},
  {"host-reserve-too-small",func(h *Hardware,_ *Workload,_ *Candidate){h.HostReserveMiB=1}},
  {"kvm-not-qualified",func(h *Hardware,_ *Workload,_ *Candidate){h.KVMGuestBootQualified=false}},
  {"native-disallowed-with-isolation",func(_ *Hardware,_ *Workload,c *Candidate){c.Profile="native"}},
  {"unknown-device-profile",func(_ *Hardware,_ *Workload,c *Candidate){c.Profile="vfio-auto-pass-through"}},
  {"altered-guest-memory",func(_ *Hardware,_ *Workload,c *Candidate){c.MemoryMiB=8192}},
  {"guest-mismatch",func(_ *Hardware,_ *Workload,c *Candidate){c.WorkloadID="other-job"}},
  {"fake-usb",func(_ *Hardware,w *Workload,c *Candidate){w.Kind="usb";c.Profile="kvm-usb"}},
  {"fake-gpu",func(_ *Hardware,w *Workload,c *Candidate){w.Kind="media";c.Profile="kvm-render"}},
  {"ARM-unsupported-synthetic",func(h *Hardware,_ *Workload,_ *Candidate){h.Arch="mips64"}},
 }
 for _,tc:=range fixtures{
  t.Run(tc.name,func(t *testing.T){
   h,w:=hw(),work();c:=plan(h,w,"kvm-virtio")
   tc.bad(&h,&w,&c)
   if err:=Validate(h,w,c);err==nil{t.Fatalf("fail-open: %s",tc.name)}
  })
 }
}
func TestHypotheticalHardwareProfilesDoNotInventCapabilities(t *testing.T){
 h,w:=hw(),work()
 h.CPUThreads=4;h.RAMMiB=4096;h.RecoveryVerified=false // unknown J4105 4GB
 if len(Propose(h,w))!=0{t.Fatal("unverified recovery treated as deployable")}
 h.RecoveryVerified=true;h.KVMGuestBootQualified=false // CPU flag is not guest boot
 if len(Propose(h,w))!=0{t.Fatal("KVM invented from CPU feature")}
 h.RAMMiB=8192;h.KVMGuestBootQualified=true;w.Kind="media";w.ID="media-job"
 if len(Propose(h,w))!=0{t.Fatal("iGPU render support invented")}
 h.RenderGuestQualified=true
 c:=Propose(h,w)
 if len(c)!=1||c[0].Profile!="kvm-render"{t.Fatalf("render admission incorrect %+v",c)}
 w.Kind="usb";w.ID="usb-job"
 if len(Propose(h,w))!=0{t.Fatal("USB pass-through invented")}
 h.USBGuestQualified=true
 if a:=Propose(h,w);len(a)!=1||a[0].Profile!="kvm-usb"{t.Fatalf("USB qualification incorrect %+v",a)}
}
func TestMeasuredEvidenceMandatoryForPareto(t *testing.T){
 h,w:=hw(),work();w.RequireIsolation=false
 c:=Propose(h,w)
 if len(c)!=2{t.Fatalf("expected native and KVM feasible profiles %+v",c)}
 _,err:=ParetoQualified(c,nil)
 if err==nil{t.Fatal("unmeasured candidate falsely optimized")}
 a:=[]Measurement{
  {Profile:"native",Generation:h.Generation,WorkloadID:w.ID,Throughput:120,LatencyMs:20,EnergyJoulesPerJob:10,ActualCanaryQualified:true},
  {Profile:"kvm-virtio",Generation:h.Generation,WorkloadID:w.ID,Throughput:100,LatencyMs:25,EnergyJoulesPerJob:13,ActualCanaryQualified:true},
 }
 if _,err:=ParetoQualified(c,append([]Measurement(nil),a[0]));err==nil{t.Fatal("missing competing measurement accepted")}
 if _,err:=ParetoQualified(c,append(a, a[0]));err==nil{t.Fatal("duplicate measurement accepted")}
 bad:=append([]Measurement(nil),a...)
 bad[1].ActualCanaryQualified=false
 if _,err:=ParetoQualified(c,bad);err==nil{t.Fatal("unqualified cloud timing treated as real measurement")}
 bad=append([]Measurement(nil),a...)
 bad[1].Generation=strings.Repeat("c",64)
 if _,err:=ParetoQualified(c,bad);err==nil{t.Fatal("stale hardware gen measurement accepted")}
 front,err:=ParetoQualified(c,a)
 if err!=nil||len(front)!=1||front[0].Profile!="native"{t.Fatalf("Pareto frontier incorrect %+v %v",front,err)}
}
