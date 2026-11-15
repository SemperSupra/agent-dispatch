// wyse-probe reads a virtual or real sysfs/DMI view without opening any
// block/TPM/watchdog devices. Service Tags and other identifiers are redacted.
package main

import(
 "encoding/json"
 "flag"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "sort"
)
type Report struct {
 Schema string `json:"schema"`
 Mode string `json:"mode"`
 BIOSVersion string `json:"bios_version"`
 AssetTagPresent bool `json:"asset_tag_present"`
 ServiceTagPresent bool `json:"service_tag_present"`
 OwnershipTag string `json:"ownership_tag"`
 Watchdogs []WD `json:"watchdogs"`
 EMMC []MMC `json:"emmc"`
 PhysicalMutation bool `json:"physical_mutation"`
}
type WD struct {
 Driver string `json:"driver"`
 Category string `json:"category"`
 UsableHardwareWatchdog bool `json:"usable_hardware_watchdog"`
}
type MMC struct {
 Name string `json:"name"`
 UserRO string `json:"user_ro"`
 Boot0RO string `json:"boot0_ro"`
 Boot1RO string `json:"boot1_ro"`
 PreEOL string `json:"pre_eol_info"`
 WearA string `json:"lifetime_a"`
 WearB string `json:"lifetime_b"`
}
func read(root,path string)string {
 b,err:=os.ReadFile(filepath.Join(root,path))
 if err!=nil{return "unknown"}
 s:=strings.TrimSpace(string(b))
 if len(s)>96{return "oversize"}
 return s
}
func present(s string)bool{return s!=""&&s!="unknown"&&s!="Not Specified"&&s!="None"&&s!="To be filled by O.E.M."}
func classifyWD(s string)string{
 if s=="unknown"||s==""{return "unknown"}
 if strings.Contains(strings.ToLower(s),"softdog"){return "software-only"}
 return "hardware-driver-candidate-not-qualified"
}
func Probe(root string)Report{
 r:=Report{Schema:"wyse-readonly-inventory/v1",Mode:"read-only",Watchdogs:[]WD{},EMMC:[]MMC{},OwnershipTag:"OEM_SPECIFIC_NOT_IN_GENERIC_SYSFS",PhysicalMutation:false}
 r.BIOSVersion=read(root,"sys/class/dmi/id/bios_version")
 r.AssetTagPresent=present(read(root,"sys/class/dmi/id/chassis_asset_tag"))
 r.ServiceTagPresent=present(read(root,"sys/class/dmi/id/product_serial"))
 w,err:=os.ReadDir(filepath.Join(root,"sys/class/watchdog"))
 if err==nil{
  for _,entry:=range w{
   if !strings.HasPrefix(entry.Name(),"watchdog"){continue}
   driver:=read(root,"sys/class/watchdog/"+entry.Name()+"/identity")
   r.Watchdogs=append(r.Watchdogs,WD{Driver:driver,Category:classifyWD(driver),UsableHardwareWatchdog:false})
  }
 }
 sort.Slice(r.Watchdogs,func(i,j int)bool{return r.Watchdogs[i].Driver<r.Watchdogs[j].Driver})
 blocks,err:=os.ReadDir(filepath.Join(root,"sys/block"))
 if err==nil{
  for _,entry:=range blocks{
   name:=entry.Name()
   if !strings.HasPrefix(name,"mmcblk") || strings.Contains(name,"boot") || strings.Contains(name,"rpmb"){continue}
   m:=MMC{
    Name:name,UserRO:read(root,"sys/block/"+name+"/ro"),
    Boot0RO:read(root,"sys/block/"+name+"boot0/ro"),
    Boot1RO:read(root,"sys/block/"+name+"boot1/ro"),
    PreEOL:read(root,"sys/block/"+name+"/device/pre_eol_info"),
    WearA:"unknown",WearB:"unknown",
   }
   wear:=read(root,"sys/block/"+name+"/device/life_time")
   fields:=strings.Fields(wear)
   if len(fields)>0{m.WearA=fields[0]}
   if len(fields)>1{m.WearB=fields[1]}
   r.EMMC=append(r.EMMC,m)
  }
 }
 sort.Slice(r.EMMC,func(i,j int)bool{return r.EMMC[i].Name<r.EMMC[j].Name})
 return r
}
func main(){
 root:=flag.String("sysroot","/","read-only sysfs root; replace with synthetic fixture to test")
 flag.Parse()
 data:=Probe(*root)
 if err:=json.NewEncoder(os.Stdout).Encode(data);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
