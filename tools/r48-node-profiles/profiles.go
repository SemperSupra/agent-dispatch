// Package profiles admits architecture- and board-specific synthetic node
// plans. Device telemetry, real signing, firmware, CUDA and KVM are NOT
// validated here. Model input and every bool are untrusted until verified
// by the single existing fleet controller on physical hardware.
package profiles

import (
 "errors"
 "regexp"
 "strings"
)

type Hardware struct {
 Architecture string `json:"architecture"`
 Family string `json:"family"`
 Model string `json:"model"`
 HardwareGeneration string `json:"hardware_generation"`
 LinuxCompatible bool `json:"linux_compatible"`
 RecoveryQualified bool `json:"recovery_qualified"`
 Boot string `json:"boot"`
 NVMeAdapterObserved bool `json:"nvme_adapter_observed"`
 JetPackMajor int `json:"jetpack_major"`
 VendorBSPQualified bool `json:"vendor_bsp_qualified"`
 NativeGPUQualified bool `json:"native_gpu_qualified"`
 KVMGuestBootQualified bool `json:"kvm_guest_boot_qualified"`
 GPUGuestQualified bool `json:"gpu_guest_qualified"`
 PermanentAC bool `json:"permanent_ac"`
 SuspendInhibited bool `json:"suspend_inhibited"`
}
type Intent struct {
 Role string `json:"role"`
 AlwaysOn bool `json:"always_on"`
 NeedGPU bool `json:"need_gpu"`
 NeedVM bool `json:"need_vm"`
 NeedGuestGPU bool `json:"need_guest_gpu"`
}
type Plan struct {
 HardwareGeneration string `json:"hardware_generation"`
 Architecture string `json:"architecture"`
 Family string `json:"family"`
 Role string `json:"role"`
 HostMode string `json:"host_mode"`
 Qualification string `json:"qualification"`
}
var shaRE=regexp.MustCompile("^[a-f0-9]{64}$")
var modelRE=regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9 _+.-]{2,80}$")
func denied(s string)error{return errors.New("DENIED:"+s)}
func Validate(h Hardware,i Intent)(Plan,error){
 p:=Plan{HardwareGeneration:h.HardwareGeneration,Architecture:h.Architecture,Family:h.Family,Role:i.Role,
  Qualification:"SYNTHETIC_ONLY_NOT_PHYSICAL_HIL"}
 if !shaRE.MatchString(h.HardwareGeneration)||!modelRE.MatchString(h.Model)||
  !h.LinuxCompatible||!h.RecoveryQualified {return Plan{},denied("UNATTESTED_LINUX_RECOVERY_OR_HARDWARE_GENERATION")}
 if h.Architecture!="amd64"&&h.Architecture!="arm64"{return Plan{},denied("UNSUPPORTED_ARCH")}
 if i.NeedGuestGPU&&!i.NeedVM{return Plan{},denied("GUEST_GPU_REQUIRES_VM")}
 if i.NeedVM&&!h.KVMGuestBootQualified{return Plan{},denied("KVM_GUEST_NOT_PROVEN")}
 if i.NeedGuestGPU&&!h.GPUGuestQualified{return Plan{},denied("GUEST_GPU_NOT_PROVEN")}
 if i.NeedGPU&&!h.NativeGPUQualified&&!i.NeedGuestGPU{return Plan{},denied("NATIVE_GPU_NOT_PROVEN")}
 if h.Family=="laptop"&&i.AlwaysOn&&(!h.PermanentAC||!h.SuspendInhibited) {
  return Plan{},denied("LAPTOP_POWER_OR_SUSPEND_UNQUALIFIED")
 }
 switch h.Family{
 case "rpi4","rpi5","rpi-cm4","rpi-cm5":
  if h.Architecture!="arm64" {return Plan{},denied("RASPBERRY_PI_ARCH_MISMATCH")}
  if h.JetPackMajor!=0||h.VendorBSPQualified {return Plan{},denied("FOREIGN_JETSON_BSP_ON_PI")}
  switch h.Boot{
  case "sd","usb","network":
  case "nvme":
   if h.Family=="rpi4" || h.Family=="rpi5"&& !h.NVMeAdapterObserved ||
      h.Family=="rpi-cm4"&&!h.NVMeAdapterObserved{
    return Plan{},denied("NVME_BOOT_HARDWARE_NOT_OBSERVED")
   }
  default:return Plan{},denied("PI_FIRMWARE_BOOT_UNQUALIFIED")
  }
  if i.NeedGPU&&i.Role=="cuda_inference"{return Plan{},denied("PI_CUDA_NOT_SUPPORTED")}
  if i.NeedGuestGPU{return Plan{},denied("PI_GPU_GUEST_NOT_QUALIFIED")}
 case "jetson-orin","jetson-thor":
  if h.Architecture!="arm64" {return Plan{},denied("JETSON_ARCH_MISMATCH")}
  if h.Boot!="jetson_vendor_bsp_uefi"||!h.VendorBSPQualified {
   return Plan{},denied("JETSON_VENDOR_BOOT_OR_BSP_NOT_QUALIFIED")
  }
  if h.Family=="jetson-thor" && h.JetPackMajor!=7 ||
    h.Family=="jetson-orin" && h.JetPackMajor!=6&&h.JetPackMajor!=7 {
   return Plan{},denied("JETPACK_BOARD_FAMILY_MISMATCH")
  }
  if i.NeedGuestGPU{return Plan{},denied("JETSON_GPU_GUEST_PASSTHROUGH_NOT_ADMITTED")}
 case "pc","server","laptop":
  if h.Architecture!="amd64" {return Plan{},denied("X86_HARDWARE_ARCH_MISMATCH")}
  if h.Boot!="uefi"&&h.Boot!="legacy_bios" {return Plan{},denied("X86_BOOT_NOT_QUALIFIED")}
  if h.JetPackMajor!=0||h.VendorBSPQualified {return Plan{},denied("FOREIGN_BSP_ON_PC")}
 case "generic-arm64":
  if h.Architecture!="arm64"||h.Boot!="vendor_qualified" {
   return Plan{},denied("UNKNOWN_ARM_BOOT_NOT_QUALIFIED")
  }
  if h.JetPackMajor!=0 {return Plan{},denied("UNKNOWN_ARM_JETPACK_NOT_ADMITTED")}
 default:return Plan{},denied("UNKNOWN_HARDWARE_FAMILY")
 }
 switch i.Role{
 case "native_agent","edge_service","isolated_guest","cuda_inference":
 default:return Plan{},denied("UNKNOWN_WORKLOAD_ROLE")
 }
 if i.Role=="isolated_guest"&&!i.NeedVM {return Plan{},denied("ISOLATED_ROLE_REQUIRES_PROVEN_VM")}
 if i.Role=="cuda_inference" {
  if h.Family!="jetson-orin"&&h.Family!="jetson-thor"||
   !i.NeedGPU||i.NeedVM||!h.NativeGPUQualified {
   return Plan{},denied("CUDA_HOST_VENDOR_RUNTIME_NOT_PROVEN")
  }
 }
 if i.NeedVM {p.HostMode="KVM_CANDIDATE_NO_GUEST_STARTED"} else {p.HostMode="NATIVE_LINUX_CANDIDATE"}
 if strings.Contains(p.HostMode,"KVM")&&!h.KVMGuestBootQualified {return Plan{},denied("FALSE_KVM_ADMISSION")}
 return p,nil
}
