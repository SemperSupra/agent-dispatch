// Package planner is a synthetic plan-only host/guest configuration
// evaluator. It has no authority to provision, enroll, sign or start guests.
// Hardware inputs and benchmark receipts are untrusted until independently
// qualified by the existing fleet controller and Agent Dispatch.
package planner

import (
 "errors"
 "fmt"
 "regexp"
 "sort"
)

type Hardware struct {
 Generation string `json:"generation"`
 Arch string `json:"arch"`
 CPUThreads int `json:"cpu_threads"`
 RAMMiB int `json:"ram_mib"`
 HostReserveMiB int `json:"host_reserve_mib"`
 RecoveryVerified bool `json:"recovery_verified"`
 KVMGuestBootQualified bool `json:"kvm_guest_boot_qualified"`
 RenderGuestQualified bool `json:"render_guest_qualified"`
 USBGuestQualified bool `json:"usb_guest_qualified"`
}
type Workload struct {
 ID string `json:"id"`
 Kind string `json:"kind"` // cli, browser, media, usb
 VCpus int `json:"vcpus"`
 MemoryMiB int `json:"memory_mib"`
 RequireIsolation bool `json:"require_isolation"`
}
type Candidate struct {
 Profile string `json:"profile"` // native, kvm-virtio, kvm-render, kvm-usb
 VCpus int `json:"vcpus"`
 MemoryMiB int `json:"memory_mib"`
 HardwareGeneration string `json:"hardware_generation"`
 WorkloadID string `json:"workload_id"`
 Qualification string `json:"qualification"`
}
type Measurement struct {
 Profile string `json:"profile"`
 Generation string `json:"generation"`
 WorkloadID string `json:"workload_id"`
 Throughput float64 `json:"throughput"`
 LatencyMs float64 `json:"latency_ms"`
 EnergyJoulesPerJob float64 `json:"energy_joules_per_job"`
 ActualCanaryQualified bool `json:"actual_canary_qualified"`
}
var genRE=regexp.MustCompile("^[a-f0-9]{64}$")
var idRE=regexp.MustCompile("^[a-z][a-z0-9_-]{2,47}$")
func deny(code string)error{return errors.New("DENIED:"+code)}
func Validate(h Hardware,w Workload,c Candidate)error{
 if !genRE.MatchString(h.Generation)||h.CPUThreads<1||h.RAMMiB<=0||h.HostReserveMiB<512||
    (h.Arch!="amd64"&&h.Arch!="arm64") {
  return deny("UNVERIFIED_HARDWARE_PROFILE")
 }
 if !h.RecoveryVerified{return deny("TRUSTED_RECOVERY_UNQUALIFIED")}
 if !idRE.MatchString(w.ID)||w.VCpus<1||w.MemoryMiB<128||w.Kind=="" {
  return deny("INVALID_WORKLOAD")
 }
 if c.WorkloadID!=w.ID||c.HardwareGeneration!=h.Generation||
    c.VCpus!=w.VCpus||c.MemoryMiB!=w.MemoryMiB {
  return deny("STALE_OR_ALTERED_PLAN")
 }
 if c.VCpus>h.CPUThreads||c.MemoryMiB+h.HostReserveMiB>h.RAMMiB {
  return deny("CPU_OR_MEMORY_OVERCOMMIT")
 }
 if c.Qualification!="SYNTHETIC_PLAN_ONLY" {return deny("FALSE_DEPLOYMENT_QUALIFICATION")}
 switch c.Profile{
 case "native":
  if w.RequireIsolation||w.Kind!="cli" {return deny("NATIVE_GUEST_ISOLATION_OR_CLASS")}
 case "kvm-virtio":
  if !h.KVMGuestBootQualified||w.Kind!="cli"&&w.Kind!="browser" {
   return deny("KVM_OR_WORKLOAD_UNQUALIFIED")
  }
 case "kvm-render":
  if !h.KVMGuestBootQualified||!h.RenderGuestQualified||w.Kind!="media"&&w.Kind!="browser" {
   return deny("GUEST_GPU_RENDER_UNQUALIFIED")
  }
 case "kvm-usb":
  if !h.KVMGuestBootQualified||!h.USBGuestQualified||w.Kind!="usb" {
   return deny("GUEST_USB_ASSIGNMENT_UNQUALIFIED")
  }
 default:return deny("UNKNOWN_EXECUTION_PROFILE")
 }
 if w.RequireIsolation&&c.Profile=="native" {return deny("ISOLATION_REQUIRED")}
 return nil
}
// Propose does not invent capabilities. It offers independently validated
// variants, without ranking or calling any external system.
func Propose(h Hardware,w Workload) []Candidate{
 profiles:=[]string{"native","kvm-virtio","kvm-render","kvm-usb"}
 out:=make([]Candidate,0,len(profiles))
 for _,p:=range profiles {
  c:=Candidate{Profile:p,VCpus:w.VCpus,MemoryMiB:w.MemoryMiB,
   HardwareGeneration:h.Generation,WorkloadID:w.ID,
   Qualification:"SYNTHETIC_PLAN_ONLY"}
  if Validate(h,w,c)==nil {out=append(out,c)}
 }
 return out
}
// ParetoQualified requires matching source generation, workload and full
// measured-canary evidence; no fixed heuristic ranking of cloud/unknown data.
func ParetoQualified(candidates []Candidate,measurements []Measurement)([]Candidate,error){
 if len(candidates)==0{return nil,deny("NO_FEASIBLE_CANDIDATE")}
 indexed:=map[string]Measurement{}
 for _,m:=range measurements{
  if !m.ActualCanaryQualified||m.Throughput<=0||m.EnergyJoulesPerJob<=0||m.LatencyMs<=0 {
   return nil,deny("MEASUREMENT_NOT_HARDWARE_QUALIFIED")
  }
  if _,ok:=indexed[m.Profile];ok{return nil,deny("DUPLICATE_MEASUREMENT")}
  indexed[m.Profile]=m
 }
 if len(indexed)!=len(candidates){return nil,deny("INCOMPLETE_MEASURED_COMPARISON")}
 for _,c:=range candidates{
  m,ok:=indexed[c.Profile]
  if !ok||m.Generation!=c.HardwareGeneration||m.WorkloadID!=c.WorkloadID{
   return nil,deny("MISMATCHED_MEASUREMENT_PROVENANCE")
  }
 }
 front:=[]Candidate{}
 for _,a:=range candidates{
  x:=indexed[a.Profile];dominated:=false
  for _,b:=range candidates{
   if a.Profile==b.Profile{continue}
   y:=indexed[b.Profile]
   if y.Throughput>=x.Throughput&&y.EnergyJoulesPerJob<=x.EnergyJoulesPerJob&&y.LatencyMs<=x.LatencyMs&&
     (y.Throughput>x.Throughput||y.EnergyJoulesPerJob<x.EnergyJoulesPerJob||y.LatencyMs<x.LatencyMs){
    dominated=true;break
   }
  }
  if !dominated{front=append(front,a)}
 }
 sort.Slice(front,func(i,j int)bool{return front[i].Profile<front[j].Profile})
 return front,nil
}
func Verdict(c Candidate)string {
 return fmt.Sprintf("R47_SYNTHETIC_PROFILE=%s;REAL_WATTS_THERMALS_AND_HARDWARE=NOT_TESTED",c.Profile)
}
