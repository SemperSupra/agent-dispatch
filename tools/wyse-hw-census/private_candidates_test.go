package census

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func fullFixture(t *testing.T)string{
 t.Helper()
 r:=fixture(t) // Reuse R43 baseline fixtures; no second CPU/PCI collector.
 // The synthetic iGPU and management NIC remain protected.
 dir(t,r,"sys/kernel/iommu_groups/4")
 gpu:="sys/bus/pci/devices/0000:03:00.0"
 write(t,r,gpu+"/vendor","0x1002\n")
 write(t,r,gpu+"/device","0x67ff\n")
 write(t,r,gpu+"/class","0x030000\n")
 link(t,r,gpu+"/driver","../../drivers/amdgpu")
 link(t,r,gpu+"/iommu_group","../../../../kernel/iommu_groups/4")
 write(t,r,gpu+"/sriov_totalvfs","0\n")
 for _,spec:=range []struct{name,vendor,product,cls string}{
  {"1-2","1a2b","3c4d","03"}, // physical HID
  {"1-3","aaaa","bbbb","08"}, // physical storage
  {"1-4","1111","2222","00"}, // composite with CCID interface
  {"1-0","8086","0001","09"}, // hub must never pass
 }{
  p:="sys/bus/usb/devices/"+spec.name
  write(t,r,p+"/idVendor",spec.vendor+"\n")
  write(t,r,p+"/idProduct",spec.product+"\n")
  write(t,r,p+"/bDeviceClass",spec.cls+"\n")
 }
 write(t,r,"sys/bus/usb/devices/1-4:1.0/bInterfaceClass","0b\n")
 dir(t,r,"sys/class/hidraw/hidraw0")
 dir(t,r,"sys/class/tty/ttyUSB0")
 dir(t,r,"sys/class/video4linux/video0")
 dir(t,r,"sys/class/sound/card0")
 dir(t,r,"sys/class/bluetooth/hci0")
 dir(t,r,"sys/class/input/event1")
 dir(t,r,"sys/class/i2c-dev/i2c-0")
 write(t,r,"sys/class/dmi/id/product_serial","SECRET-DELL-SERVICE-TAG-DO-NOT-PUBLISH\n")
 write(t,r,"sys/bus/usb/devices/1-2/serial","SECRET-USB-SERIAL-NO-PUBLIC\n")
 write(t,r,"sys/class/net/eth0/address","SECRET-MAC-NO-PUBLIC\n")
 return r
}
func find(devices []Candidate,kind,path string)(Candidate,bool){
 for _,d:=range devices{if d.Kind==kind&&d.HostPath==path{return d,true}}
 return Candidate{},false
}
func TestHostPrivateReadOnlyEnumerationAndProtectedDevices(t *testing.T){
 r:=fullFixture(t)
 v,e:=CollectHostCandidates(r);if e!=nil{t.Fatal(e)}
 if v.Scope!="PRIVATE_LOCAL_READ_ONLY_UNATTESTED_NO_GUEST_ATTACH"||len(v.Generation)!=64{
  t.Fatal("false capability acceptance")
 }
 igd,found:=find(v.Devices,"pci","0000:00:02.0")
 if !found||igd.Disposition!="blocked"||igd.Reason!="INTEGRATED_PRIMARY_GRAPHICS_HOST_GUARD" {t.Fatalf("iGPU unsafe: %+v",igd)}
 nic,found:=find(v.Devices,"pci","0000:01:00.0")
 if !found||nic.Disposition!="blocked"||nic.Reason!="MANAGEMENT_NIC_GUARD" {t.Fatalf("management nic unsafe: %+v",nic)}
 amd,found:=find(v.Devices,"pci","0000:03:00.0")
 if !found||amd.Disposition!="unqualified_candidate" {t.Fatalf("separate PCI gpu missed: %+v",amd)}
 usb,found:=find(v.Devices,"usb","1-2")
 if !found||usb.Function!="hid"||usb.Disposition!="unqualified_candidate"{t.Fatalf("USB HID missed: %+v",usb)}
 disk,found:=find(v.Devices,"usb","1-3")
 if !found||disk.Disposition!="blocked" {t.Fatalf("USB storage unguarded: %+v",disk)}
 ccid,found:=find(v.Devices,"usb_interface","1-4:1.0")
 if !found||ccid.Function!="smart_card_ccid"||ccid.Disposition!="blocked" {t.Fatalf("CAC interface unguarded: %+v",ccid)}
 hub,found:=find(v.Devices,"usb","1-0")
 if !found||hub.Disposition!="blocked"{t.Fatal("hub unguarded")}
 mmc,found:=find(v.Devices,"block","mmcblk0")
 if !found||mmc.Disposition!="blocked" {t.Fatal("eMMC available for destructive pass-through")}
 if _,ok:=find(v.Devices,"render","renderD128");!ok {t.Fatal("DRM render candidate missing")}
 if _,ok:=find(v.Devices,"hidraw","hidraw0");!ok {t.Fatal("hidraw missing")}
 if _,ok:=find(v.Devices,"serial","ttyUSB0");!ok {t.Fatal("USB serial missing")}
 b,e:=json.Marshal(v);if e!=nil{t.Fatal(e)}
 for _,leak:=range []string{"SECRET-DELL-SERVICE-TAG","SECRET-USB-SERIAL","SECRET-MAC"}{
  if strings.Contains(string(b),leak) {t.Fatalf("read forbidden identity: %s",leak)}
 }
}
func TestSharedIOMMUBlocksOptionalDiscreteGPU(t *testing.T){
 r:=fullFixture(t)
 // A second PCI function sharing group 4 disqualifies exclusive assignment.
 p:="sys/bus/pci/devices/0000:03:00.1"
 write(t,r,p+"/vendor","0x1002\n")
 write(t,r,p+"/device","0xaaf0\n")
 write(t,r,p+"/class","0x040300\n")
 link(t,r,p+"/iommu_group","../../../../kernel/iommu_groups/4")
 v,e:=CollectHostCandidates(r);if e!=nil{t.Fatal(e)}
 d,ok:=find(v.Devices,"pci","0000:03:00.0")
 if !ok||d.Disposition!="blocked"||d.Reason!="IOMMU_GROUP_SHARED"{t.Fatalf("shared group safety gate failed: %+v",d)}
}
func TestStaleHotplugAndCandidateNeverAuthorizeDirectAttach(t *testing.T){
 r:=fullFixture(t)
 v,e:=CollectHostCandidates(r);if e!=nil{t.Fatal(e)}
 if e:=IsCandidateCurrent(v,v.Generation,"pci","0000:03:00.0");e==nil||
  !strings.Contains(e.Error(),"HIL_APPROVAL"){t.Fatalf("qualified without owner approval: %v",e)}
 if e:=IsCandidateCurrent(v,v.Generation,"block","mmcblk0");e==nil||
  !strings.Contains(e.Error(),"PROTECTED"){t.Fatalf("protected disk passed: %v",e)}
 write(t,r,"sys/bus/usb/devices/1-5/idVendor","face\n")
 write(t,r,"sys/bus/usb/devices/1-5/idProduct","0001\n")
 write(t,r,"sys/bus/usb/devices/1-5/bDeviceClass","03\n")
 fresh,e:=CollectHostCandidates(r);if e!=nil{t.Fatal(e)}
 if fresh.Generation==v.Generation{t.Fatal("hotplug failed generation fencing")}
 if e:=IsCandidateCurrent(fresh,v.Generation,"usb","1-2");e==nil||
  !strings.Contains(e.Error(),"STALE"){t.Fatalf("stale lease accepted: %v",e)}
 if e:=IsCandidateCurrent(fresh,fresh.Generation,"usb","1-7");e==nil||
  !strings.Contains(e.Error(),"UNKNOWN"){t.Fatalf("unknown device accepted: %v",e)}
}
func TestNeverDiscloseHostInventoryToRemoteOrGuest(t *testing.T){
 r:=fullFixture(t)
 v,e:=CollectHostCandidates(r);if e!=nil{t.Fatal(e)}
 for _,caller:=range []struct{role,channel string}{
  {"guest","lan"},{"operator","overlay"},{"owner","overlay"},{"owner","lan"},{"agent","local_unix_verified"},
 }{
  _,err:=PrivateOwnerInventory(v,caller.role,caller.channel)
  if err==nil||err.Error()!="DENIED:PRIVATE_INVENTORY" {t.Fatalf("remote host inventory exposure: %+v",caller)}
 }
 allowed,e:=PrivateOwnerInventory(v,"owner","local_unix_verified")
 if e!=nil||len(allowed.Devices)==0 {t.Fatal("privileged local inventory missing")}
 gv:=ProjectGuestView([]AssignedVirtualDevice{
  {GuestHandle:"virt_kbd_001",VirtualClass:"virtual_keyboard"},
  {GuestHandle:"0000:03:00.0",VirtualClass:"virtual_display"}, // reject raw PCI topology
  {GuestHandle:"owner_host_gpu",VirtualClass:"pci"}, // reject raw device class
 })
 b,e:=json.Marshal(gv);if e!=nil{t.Fatal(e)}
 if len(gv.Attached)!=1 {t.Fatalf("guest device projection fail-open: %+v",gv)}
 for _,s:=range []string{"0000:","iommu","usb_interface","device","blocked","pci","candidate","host_path","3c4d","SECRET-"}{
  if strings.Contains(strings.ToLower(string(b)),strings.ToLower(s)){t.Fatalf("host fact visible to remote user: %s",s)}
 }
 // Confidential hardware data is never part of the guest projection API
 // shape, regardless of the content of an owner-local inventory.
 if _,ok:=find(v.Devices,"pci","0000:03:00.0");!ok{t.Fatal("test precondition")}
}
func TestMissingBaselineDenied(t *testing.T) {
 _,err:=CollectHostCandidates(t.TempDir())
 if err==nil{t.Fatal("empty/sysfs-incomplete host treated as enumerated")}
}
func TestDoesNotReadRealBlockDeviceNodes(t *testing.T){
 r:=fullFixture(t)
 // Even a synthetic read/write trap at a block node is never opened: only
 // sysfs metadata is inspected, and source must not gain os.OpenFile calls.
 p:=filepath.Join(r,"dev","sda")
 if err:=os.MkdirAll(filepath.Dir(p),0755);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(p,[]byte("DO_NOT_TOUCH"),0000);err!=nil{t.Fatal(err)}
 if _,err:=CollectHostCandidates(r);err!=nil{t.Fatal(err)}
 if err:=os.Chmod(p,0600);err!=nil{t.Fatal(err)}
 b,err:=os.ReadFile(p)
 if err!=nil||string(b)!="DO_NOT_TOUCH"{t.Fatal("block node mutated")}
}
