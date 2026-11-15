package main
import(
 "os"
 "path/filepath"
 "encoding/json"
 "strings"
 "testing"
)
func put(t *testing.T,root,path,value string){
 t.Helper()
 p:=filepath.Join(root,path)
 if err:=os.MkdirAll(filepath.Dir(p),0700);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(p,[]byte(value),0600);err!=nil{t.Fatal(err)}
}
func TestEmptySysfsNeverAssumesHardware(t *testing.T){
 r:=Probe(t.TempDir())
 if r.PhysicalMutation||r.AssetTagPresent||r.ServiceTagPresent||len(r.Watchdogs)!=0{t.Fatal(r)}
 if r.OwnershipTag!="OEM_SPECIFIC_NOT_IN_GENERIC_SYSFS"{t.Fatal(r.OwnershipTag)}
}
func TestRedactDellIdentityAndClassifyTCO(t *testing.T){
 root:=t.TempDir()
 put(t,root,"sys/class/dmi/id/product_serial","SUPER_SECRET_SERVICE_TAG")
 put(t,root,"sys/class/dmi/id/chassis_asset_tag","INVENTORY1")
 put(t,root,"sys/class/dmi/id/bios_version","1.36.0")
 put(t,root,"sys/class/watchdog/watchdog0/identity","iTCO_wdt")
 put(t,root,"sys/class/watchdog/watchdog1/identity","softdog")
 put(t,root,"sys/block/mmcblk0/ro","0")
 put(t,root,"sys/block/mmcblk0boot0/ro","1")
 put(t,root,"sys/block/mmcblk0boot1/ro","1")
 put(t,root,"sys/block/mmcblk0/device/pre_eol_info","0x01")
 put(t,root,"sys/block/mmcblk0/device/life_time","0x03 0x04")
 r:=Probe(root)
 if !r.AssetTagPresent||!r.ServiceTagPresent||r.BIOSVersion!="1.36.0"{t.Fatal(r)}
 if len(r.Watchdogs)!=2||r.Watchdogs[0].Category!="hardware-driver-candidate-not-qualified"||r.Watchdogs[0].UsableHardwareWatchdog {t.Fatal(r.Watchdogs)}
 if r.Watchdogs[1].Category!="software-only" {t.Fatal(r.Watchdogs)}
 if len(r.EMMC)!=1||r.EMMC[0].UserRO!="0"||r.EMMC[0].Boot0RO!="1"||r.EMMC[0].WearB!="0x04"{t.Fatal(r.EMMC)}
 b,_:=json.Marshal(r)
 if strings.Contains(string(b),"SUPER_SECRET_SERVICE_TAG")||strings.Contains(string(b),"INVENTORY1"){t.Fatal("leaked DMI identifier")}
}
func TestWatchdogUnknownNotAssumed(t *testing.T){
 root:=t.TempDir()
 put(t,root,"sys/class/watchdog/watchdog0/identity","")
 r:=Probe(root)
 if len(r.Watchdogs)!=1||r.Watchdogs[0].UsableHardwareWatchdog{t.Fatal(r)}
}
