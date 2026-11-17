package profiles

import (
 "strings"
 "testing"
)

func base(family,arch,boot,model string) Hardware {
 return Hardware{
  Family:family,Architecture:arch,Boot:boot,Model:model,
  HardwareGeneration:strings.Repeat("a",64),
  LinuxCompatible:true,RecoveryQualified:true,
 }
}
func native() Intent {return Intent{Role:"native_agent"}}
func TestSafeArchitectureAndPlatformCandidates(t *testing.T){
 cases:=[]struct{name string;hardware Hardware; intent Intent; hostMode string}{
  {"pi5-native",base("rpi5","arm64","sd","Raspberry Pi 5"),native(),"NATIVE_LINUX_CANDIDATE"},
  {"pi4-native",base("rpi4","arm64","network","Raspberry Pi 4"),native(),"NATIVE_LINUX_CANDIDATE"},
  {"pi-cm5-native",base("rpi-cm5","arm64","sd","Compute Module 5"),native(),"NATIVE_LINUX_CANDIDATE"},
  {"amd64-pc",base("pc","amd64","uefi","Generic UEFI PC"),native(),"NATIVE_LINUX_CANDIDATE"},
  {"amd64-server",base("server","amd64","legacy_bios","Server BIOS Node"),native(),"NATIVE_LINUX_CANDIDATE"},
  {"generic-arm64",base("generic-arm64","arm64","vendor_qualified","Generic Arm64"),native(),"NATIVE_LINUX_CANDIDATE"},
  {"arm64-server",base("server","arm64","uefi","ARM64 UEFI Server"),native(),"NATIVE_LINUX_CANDIDATE"},
  {"arm64-laptop",base("laptop","arm64","uefi","ARM64 UEFI Laptop"),native(),"NATIVE_LINUX_CANDIDATE"},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   x,e:=Validate(tc.hardware,tc.intent);if e!=nil{t.Fatal(e)}
   if x.HostMode!=tc.hostMode||x.Qualification!="SYNTHETIC_ONLY_NOT_PHYSICAL_HIL"{
    t.Fatalf("false qualification %+v",x)
   }
  })
 }
}
func TestPlatformSpecificGates(t *testing.T){
 pi5:=base("rpi5","arm64","nvme","Raspberry Pi 5")
 if _,e:=Validate(pi5,native());e==nil{t.Fatal("Pi5 NVMe without observed adapter accepted")}
 pi5.NVMeAdapterObserved=true
 if _,e:=Validate(pi5,native());e!=nil{t.Fatalf("Pi5 known adapter still rejected %v",e)}
 pi4:=base("rpi4","arm64","nvme","Raspberry Pi 4")
 pi4.NVMeAdapterObserved=true
 if _,e:=Validate(pi4,native());e==nil{t.Fatal("Pi4 native PCIe NVMe boot invented")}
 j:=base("jetson-orin","arm64","jetson_vendor_bsp_uefi","NVIDIA Jetson Orin Nano")
 j.VendorBSPQualified=true
 j.JetPackMajor=7
 j.NativeGPUQualified=true
 cuda:=Intent{Role:"cuda_inference",NeedGPU:true}
 if p,e:=Validate(j,cuda);e!=nil||p.HostMode!="NATIVE_LINUX_CANDIDATE"{t.Fatalf("Jetson native host GPU refused %+v %v",p,e)}
 j.JetPackMajor=4
 if _,e:=Validate(j,cuda);e==nil{t.Fatal("unsupported legacy JetPack accepted for Orin")}
 j.JetPackMajor=6;j.VendorBSPQualified=false
 if _,e:=Validate(j,cuda);e==nil{t.Fatal("unqualified vendor BSP accepted")}
 j.VendorBSPQualified=true
 if _,e:=Validate(j,Intent{Role:"cuda_inference",NeedGPU:true,NeedVM:true,NeedGuestGPU:true});e==nil{
  t.Fatal("CUDA guest passthrough claimed")
 }
 thor:=base("jetson-thor","arm64","jetson_vendor_bsp_uefi","Jetson AGX Thor")
 thor.VendorBSPQualified=true;thor.JetPackMajor=6
 if _,e:=Validate(thor,native());e==nil{t.Fatal("Thor unsupported JetPack 6 accepted")}
 thor.JetPackMajor=7
 if _,e:=Validate(thor,native());e!=nil{t.Fatal(e)}
}
func TestGenericHostAndLaptopReliability(t *testing.T){
 laptop:=base("laptop","amd64","uefi","Generic Mobile Workstation")
 always:=Intent{Role:"edge_service",AlwaysOn:true}
 if _,e:=Validate(laptop,always);e==nil{t.Fatal("battery/lid unreliable laptop admitted")}
 laptop.PermanentAC=true
 if _,e:=Validate(laptop,always);e==nil{t.Fatal("laptop without suspend policy admitted")}
 laptop.SuspendInhibited=true
 if _,e:=Validate(laptop,always);e!=nil{t.Fatal(e)}
 pc:=base("pc","amd64","uefi","Generic Tower PC")
 isolated:=Intent{Role:"isolated_guest",NeedVM:true}
 if _,e:=Validate(pc,isolated);e==nil{t.Fatal("KVM invented")}
 pc.KVMGuestBootQualified=true
 if p,e:=Validate(pc,isolated);e!=nil||p.HostMode!="KVM_CANDIDATE_NO_GUEST_STARTED"{t.Fatalf("known KVM guest boot refused %+v %v",p,e)}
 arm:=base("generic-arm64","arm64","uefi","Unknown SBC")
 if _,e:=Validate(arm,native());e==nil{t.Fatal("unknown ARM boot chain accepted")}
}
func TestUntrustedModelClaimsAndCrossArchitectureDenied(t *testing.T){
 tests:=[]struct{name string;h Hardware;i Intent}{
  {"amd64-pi",base("rpi5","amd64","sd","Pi 5"),native()},
  {"foreign-jetpack-on-pi",func()Hardware{h:=base("rpi5","arm64","sd","Pi 5");h.JetPackMajor=7;return h}(),native()},
  {"jetson-without-bsp",base("jetson-orin","arm64","jetson_vendor_bsp_uefi","Jetson Orin"),native()},
  {"arm64-pc-legacy-bios",base("pc","arm64","legacy_bios","ARM64 Legacy BIOS"),native()},
  {"generic-unknown-model",base("random","arm64","vendor_qualified","Random SBC"),native()},
  {"no-recovery",func()Hardware{h:=base("rpi5","arm64","sd","Pi 5");h.RecoveryQualified=false;return h}(),native()},
  {"stale-hardware-generation",func()Hardware{h:=base("rpi5","arm64","sd","Pi 5");h.HardwareGeneration="old";return h}(),native()},
  {"pi-cuda",func()Hardware{h:=base("rpi5","arm64","sd","Pi 5");h.NativeGPUQualified=true;return h}(),Intent{Role:"cuda_inference",NeedGPU:true}},
  {"unqualified-gpu",base("rpi5","arm64","sd","Pi 5"),Intent{Role:"edge_service",NeedGPU:true}},
  {"guest-gpu-without-VM",base("pc","amd64","uefi","Generic PC"),Intent{Role:"edge_service",NeedGuestGPU:true}},
  {"unsupported-workload",base("pc","amd64","uefi","Generic PC"),Intent{Role:"vfio_all"}},
 }
 for _,tc:=range tests{t.Run(tc.name,func(t *testing.T){
  if p,e:=Validate(tc.h,tc.i);e==nil{t.Fatalf("unsafe plan accepted %+v",p)}
 })}
}
