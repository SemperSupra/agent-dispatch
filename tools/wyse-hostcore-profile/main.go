// wyse-hostcore validates the minimal, read-only recovery host release profile.
// It performs no device discovery, mounts, partition writes or firmware actions.
package main

import (
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "os"
 "sort"
)

var mandatory = []string{
 "signed-boot-policy", "root-integrity", "busybox-init-console",
 "mmc-ahci-usb-nic", "key-only-lan-ssh", "recoverd-go",
 "offline-usb-recovery", "safe-boot-mode", "device-identity",
}
var knownOptional = map[string]bool{
 "vm-host":true,"vm-observer":true,"ssd-overlay":true,
 "overlay-network":true,"diagnostics":true,"garm-runner":true,
 "hardware-watchdog":true,"gpu-telemetry":true,"tpm-sealing":true,
}
type Profile struct {
 Schema string `json:"schema"`
 Buildroot string `json:"buildroot"`
 Core []string `json:"core"`
 Optional []string `json:"optional"`
 Mode string `json:"mode"`
 Rootfs string `json:"rootfs"`
 Storage struct{
  EMMC string `json:"emmc"`
  RuntimeWrites string `json:"runtime_writes"`
  SSD string `json:"ssd"`
  SSDPrepared bool `json:"ssd_prepared"`
  HostReserveProtectedFromBareMetal bool `json:"host_reserve_protected_from_baremetal"`
  RawDiskChanges bool `json:"raw_disk_changes"`
 } `json:"storage"`
 Network struct{
  SSH string `json:"ssh"`
  Web string `json:"web"`
  OfflineRescue bool `json:"offline_rescue"`
 } `json:"network"`
 Hardware struct{
  Watchdog string `json:"watchdog"`
  WatchdogVerified bool `json:"watchdog_verified"`
  WatchdogArmed bool `json:"watchdog_armed"`
  BIOSMetadataWrite bool `json:"bios_metadata_write"`
  TPMVerified bool `json:"tpm_verified"`
 } `json:"hardware"`
 Guest struct{
  Devices []string `json:"devices"`
  RecoveryDiskVisible bool `json:"recovery_disk_visible"`
  HostPhysicalTPMVisible bool `json:"host_physical_tpm_visible"`
  HostFirmwareVisible bool `json:"host_firmware_visible"`
 } `json:"guest"`
 Observability struct{
  LiveHost bool `json:"live_host"`
  ExternalOnly bool `json:"external_only"`
 } `json:"observability"`
 Audience []string `json:"audiences"`
}
type Outcome struct{
 Valid bool `json:"valid"`
 Errors []string `json:"errors"`
 Disabled []string `json:"disabled_optional"`
 Boundaries []string `json:"boundaries"`
}
func Validate(p Profile) Outcome{
 var out Outcome
 fail:=func(s string){out.Errors=append(out.Errors,s)}
 if p.Schema!="wyse-recovery-host/v1"{fail("schema invalid")}
 if p.Buildroot!="2026.08.1"{fail("Buildroot stable release must be pinned to 2026.08.1")}
 selected:=map[string]bool{}
 for _,c:=range p.Core{if selected[c]{fail("duplicate core "+c)};selected[c]=true}
 for _,c:=range mandatory{if !selected[c]{fail("missing mandatory core "+c)}}
 if len(p.Core)!=len(mandatory){fail("unknown or redundant mandatory core")}
 optional:=map[string]bool{}
 for _,o:=range p.Optional {
  if !knownOptional[o]{fail("unknown optional module "+o)}
  if optional[o]{fail("duplicate optional module "+o)}
  optional[o]=true
 }
 if p.Rootfs!="read-only-verity"{fail("recovery rootfs must be immutable and verified")}
 if p.Storage.EMMC!="read-only-ab-authorized-updates"{fail("eMMC may not be routine writable state")}
 if p.Storage.RuntimeWrites!="tmpfs"{fail("routine logs and state must be tmpfs")}
 if p.Storage.SSD!="optional-discovered"{fail("SSD must be optional and verified before use")}
 if p.Storage.RawDiskChanges{fail("raw disk changes cannot be part of source-only plan")}
 if p.Storage.HostReserveProtectedFromBareMetal{fail("SSD partition cannot be protected from unrestricted bare-metal root")}
 if p.Network.SSH!="trusted-lan-public-key"{fail("independent trusted LAN SSH mandatory")}
 if p.Network.Web!="headscale-overlay-only"{fail("Web/API must be overlay-only")}
 if !p.Network.OfflineRescue{fail("offline recovery must be available without SSD/TrueNAS")}
 if p.Hardware.BIOSMetadataWrite{fail("BIOS metadata writes prohibited outside separate hardware gate")}
 if p.Hardware.WatchdogArmed{fail("hardware watchdog cannot be armed in RDTE inventory")}
 if p.Hardware.Watchdog=="hardware" && !p.Hardware.WatchdogVerified{fail("hardware watchdog unverified")}
 if p.Hardware.Watchdog!="hardware"&&p.Hardware.Watchdog!="unqualified"{fail("watchdog mode invalid")}
 if optional["hardware-watchdog"]&&!p.Hardware.WatchdogVerified{out.Disabled=append(out.Disabled,"hardware-watchdog:unqualified")}
 if optional["tpm-sealing"]&&!p.Hardware.TPMVerified{out.Disabled=append(out.Disabled,"tpm-sealing:unqualified")}
 if optional["ssd-overlay"]&&!p.Storage.SSDPrepared{out.Disabled=append(out.Disabled,"ssd-overlay:ssd-not-ready")}
 if optional["garm-runner"]&&!optional["vm-host"]{fail("GARM runner requires VM host profile")}
 if optional["vm-observer"]&&!optional["vm-host"]{fail("VM observation requires VM host profile")}
 switch p.Mode{
 case "hosted":
  if !optional["vm-host"]{fail("hosted mode requires vm-host module")}
  if !p.Observability.LiveHost||p.Observability.ExternalOnly{fail("hosted mode must have real live host observer")}
  if p.Guest.RecoveryDiskVisible||p.Guest.HostPhysicalTPMVisible||p.Guest.HostFirmwareVisible{fail("guest may not see recovery disk, physical TPM, or firmware")}
  allow:=map[string]bool{"guest-ssd-image":true,"virtio-net":true,"virtual-tpm":true,"virtual-gpu":true,"virtual-console":true}
  for _,d:=range p.Guest.Devices{if !allow[d]{fail("unqualified guest device "+d)}}
  out.Boundaries=append(out.Boundaries,"HOST_OBSERVABLE_QMP_CGROUP_TAP_BLOCK;NO_GUEST_SECRETS")
 case "baremetal":
  if p.Observability.LiveHost||!p.Observability.ExternalOnly{fail("bare-metal runtime cannot have simultaneous live local host observer")}
  if optional["vm-host"]||optional["vm-observer"]{out.Disabled=append(out.Disabled,"vm-host:inactive-baremetal")}
  out.Boundaries=append(out.Boundaries,"BAREMETAL_ROOT_CAN_OVERWRITE_SSD;EXTERNAL_TELEMETRY_ONLY")
 case "recovery":
  if p.Observability.LiveHost||p.Observability.ExternalOnly{fail("recovery is not a VM/baremetal observer mode")}
  out.Boundaries=append(out.Boundaries,"RECOVERY_CORE_WITHOUT_SSD_TRUE_NAS_OR_HEADSCALE")
 default:fail("unknown runtime mode")
 }
 audience:=map[string]bool{}
 for _,v:=range p.Audience{if audience[v]{fail("duplicate audience "+v)};audience[v]=true}
 for _,v:=range []string{"human","automation","agent"}{if !audience[v]{fail("missing audience "+v)}}
 if len(audience)!=3{fail("unknown audience")}
 sort.Strings(out.Errors);sort.Strings(out.Disabled);sort.Strings(out.Boundaries)
 out.Valid=len(out.Errors)==0
 return out
}
func main(){
 path:=flag.String("profile","","JSON profile manifest")
 flag.Parse()
 if *path==""{fmt.Fprintln(os.Stderr,"usage: wyse-hostcore -profile manifest.json");os.Exit(2)}
 f,err:=os.Open(*path);if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
 defer f.Close()
 d:=json.NewDecoder(io.LimitReader(f,65537));d.DisallowUnknownFields()
 var p Profile
 if err=d.Decode(&p);err!=nil{fmt.Fprintln(os.Stderr,"decode:",err);os.Exit(2)}
 var extra any
 if err=d.Decode(&extra);!errors.Is(err,io.EOF){fmt.Fprintln(os.Stderr,"trailing or overlarge JSON");os.Exit(2)}
 result:=Validate(p)
 _=json.NewEncoder(os.Stdout).Encode(result)
 if !result.Valid{os.Exit(1)}
}
