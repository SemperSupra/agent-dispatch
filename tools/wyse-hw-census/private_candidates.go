package census

// R45-B: PRIVATE, read-only candidate inventory on top of R43 capability probe.
// Enumerating a candidate is NOT a permission to bind VFIO, attach USB, expose
// a device remotely, or use an IOMMU group. No device nodes are opened.
import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "sort"
 "strconv"
 "strings"
)
type Candidate struct {
 Kind string `json:"kind"`
 HostPath string `json:"host_path"` // owner-local only; NEVER in remote JSON
 Function string `json:"function"`
 Vendor string `json:"vendor,omitempty"`
 Device string `json:"device,omitempty"`
 Driver string `json:"driver,omitempty"`
 IOMMUGroup string `json:"iommu_group,omitempty"`
 IOMMUMembers int `json:"iommu_members,omitempty"`
 Disposition string `json:"disposition"` // blocked or unqualified_candidate
 Reason string `json:"reason"`
}
type HostInventory struct {
 Scope string `json:"scope"`
 Generation string `json:"generation"` // used only by private controller
 Devices []Candidate `json:"devices"`
}
type AssignedVirtualDevice struct {
 GuestHandle string `json:"guest_handle"`
 VirtualClass string `json:"virtual_class"`
}
type GuestView struct {
 Attached []AssignedVirtualDevice `json:"attached"`
}
func candidate(kind,path,function,reason string) Candidate{
 return Candidate{Kind:kind,HostPath:path,Function:function,Disposition:"blocked",Reason:reason}
}
func readID(p string) string{
 v:=strings.ToLower(trimmed(p))
 if len(v)>64{return ""}
 return v
}
func readPositive(p string) int{
 n,e:=strconv.Atoi(trimmed(p))
 if e!=nil||n<0||n>65535{return 0}
 return n
}
func pciFunction(class string) string{
 switch {
 case strings.HasPrefix(class,"0x03"):return "graphics"
 case strings.HasPrefix(class,"0x02"):return "network"
 case strings.HasPrefix(class,"0x01"):return "storage_controller"
 case strings.HasPrefix(class,"0x0c03"):return "usb_host_controller"
 case strings.HasPrefix(class,"0x04"):return "multimedia"
 case strings.HasPrefix(class,"0x07"):return "serial_bus"
 default:return "other_pci"
 }
}
func usbFunction(class string) string{
 switch class{
 case "03":return "hid"
 case "08":return "mass_storage"
 case "0b":return "smart_card_ccid"
 case "09":return "hub"
 case "01":return "audio"
 case "0e":return "video"
 case "02":return "communications"
 case "ff":return "vendor_specific"
 default:return "unclassified"
 }
}
func CollectHostCandidates(root string)(HostInventory,error){
 root,e:=filepath.Abs(root);if e!=nil{return HostInventory{},e}
 if _,e=Collect(root);e!=nil{return HostInventory{},errors.New("DENIED:INCOMPLETE_BASELINE_CENSUS")}
 v:=HostInventory{Scope:"PRIVATE_LOCAL_READ_ONLY_UNATTESTED_NO_GUEST_ATTACH",Devices:[]Candidate{}}
 // PCI: enumerate functions, IOMMU graph, driver and SR-IOV/mdev flags. An
 // isolated group is a *candidate requirement*, not an ability assertion.
 pci:=glob(join(root,"sys","bus","pci","devices","*"))
 groups:=map[string]int{}
 for _,p:=range pci{g:=groupInfo(p);if g!=""&&readID(filepath.Join(p,"class"))!=""{groups[g]++}}
 for _,p:=range pci{
  class:=readID(filepath.Join(p,"class"))
  if class==""{continue}
  fn:=pciFunction(class);g:=groupInfo(p)
  d:=candidate("pci",filepath.Base(p),fn,"NO_ACTUATION_OR_UNVERIFIED_TOPOLOGY")
  d.Vendor=readID(filepath.Join(p,"vendor"))
  d.Device=readID(filepath.Join(p,"device"))
  d.Driver=linkBase(filepath.Join(p,"driver"))
  d.IOMMUGroup=g;d.IOMMUMembers=groups[g]
  if g=="" {d.Reason="IOMMU_GROUP_UNOBSERVED"}
  if g!=""&&groups[g]>1 {d.Reason="IOMMU_GROUP_SHARED"}
  switch fn{
  case "network":d.Reason="MANAGEMENT_NIC_GUARD"
  case "storage_controller":d.Reason="BOOT_OR_STORAGE_CONTROLLER_GUARD"
  case "usb_host_controller":d.Reason="WHOLE_USB_CONTROLLER_REQUIRES_ISOLATION_AND_MANAGEMENT_GUARD"
  case "graphics":
   if d.Vendor=="0x8086" {d.Reason="INTEGRATED_PRIMARY_GRAPHICS_HOST_GUARD"}
   if d.Vendor!="0x8086" && g!="" && groups[g]==1 {
    d.Disposition="unqualified_candidate";d.Reason="EXCLUSIVE_PCI_GPU_REQUIRES_HIL"
   }
  case "multimedia","other_pci":
   if g!=""&&groups[g]==1{d.Disposition="unqualified_candidate";d.Reason="EXCLUSIVE_PCI_REQUIRES_HIL"}
  }
  // Highest-priority group guard applies even to discrete graphics.
  if g==""||groups[g]!=1{
   d.Disposition="blocked"
   if g==""{d.Reason="IOMMU_GROUP_UNOBSERVED"}else{d.Reason="IOMMU_GROUP_SHARED"}
  }
  if readPositive(filepath.Join(p,"sriov_totalvfs"))>0 {
   d.Reason+=":SRIOV_PF_ADVERTISED_NOT_QUALIFIED"
  }
  if len(glob(filepath.Join(p,"mdev_supported_types","*")))>0 {
   d.Reason+=":MDEV_TYPE_ADVERTISED_NOT_QUALIFIED"
  }
  v.Devices=append(v.Devices,d)
 }
 // USB root devices and USB interfaces; USB serials, HID values and raw
 // descriptors are deliberately NOT read. Composite CCID appears via iface.
 for _,p:=range glob(join(root,"sys","bus","usb","devices","*")){
  name:=filepath.Base(p)
  vendor:=readID(filepath.Join(p,"idVendor"))
  product:=readID(filepath.Join(p,"idProduct"))
  cls:=readID(filepath.Join(p,"bDeviceClass"))
  if vendor!=""&&product!="" {
   fn:=usbFunction(cls);if fn=="unclassified"&&cls=="00"{fn="composite"}
   d:=candidate("usb",name,fn,"USB_DEVICE_NEEDS_PHYSICAL_AND_HOTPLUG_REVIEW")
   d.Vendor=vendor;d.Device=product
   // USB mass storage, smart cards and hubs always require extra owner
   // safeguards: inventory is never authorization to move them.
   if fn=="hub"||fn=="mass_storage"||fn=="smart_card_ccid"{d.Reason="PROTECTED_USB_CLASS_OWNER_GATE"}
   if fn=="hid"||fn=="audio"||fn=="video"||fn=="communications"||fn=="vendor_specific"||fn=="composite" {
    d.Disposition="unqualified_candidate"
   }
   v.Devices=append(v.Devices,d)
  }
  iface:=readID(filepath.Join(p,"bInterfaceClass"))
  if iface!="" {
   d:=candidate("usb_interface",name,usbFunction(iface),"USB_INTERFACE_NEEDS_OWNER_GATE")
   if d.Function=="hid"||d.Function=="audio"||d.Function=="video"{d.Disposition="unqualified_candidate"}
   if d.Function=="smart_card_ccid"||d.Function=="mass_storage"{d.Reason="PROTECTED_USB_INTERFACE_OWNER_GATE"}
   v.Devices=append(v.Devices,d)
  }
 }
 // Block devices are ALWAYS protected from direct host disk pass-through in
 // this experimental catalog. Guest filesystems should use ephemeral images.
 for _,pattern:=range []string{"mmcblk*","sd*","nvme*n*","vd*"} {
  for _,p:=range glob(join(root,"sys","block",pattern)){
   name:=filepath.Base(p)
   if strings.Contains(name,"boot")||strings.Contains(name,"rpmb"){continue}
   v.Devices=append(v.Devices,candidate("block",name,"raw_disk","HOST_BOOT_OR_DATA_INTEGRITY_GUARD"))
  }
 }
 for _,spec:=range []struct{pattern,kind,fn string}{
  {join(root,"sys","class","drm","renderD*"),"render","drm_render","RENDER_NODE_NOT_PROOF_OF_VIRGL_OR_VAAPI"},
  {join(root,"sys","class","video4linux","video*"),"video","v4l2","VIDEO_DEVICE_UNVERIFIED"},
  {join(root,"sys","class","hidraw","hidraw*"),"hidraw","hid_raw","MANAGEMENT_HID_NEEDS_OWNER_REVIEW"},
  {join(root,"sys","class","tty","ttyUSB*"),"serial","usb_serial","SERIAL_OWNER_GATE"},
  {join(root,"sys","class","tty","ttyACM*"),"serial","usb_acm","SERIAL_OWNER_GATE"},
  {join(root,"sys","class","sound","card*"),"audio","alsa","AUDIO_OWNER_GATE"},
 }{
  for _,p:=range glob(spec.pattern){
   d:=candidate(spec.kind,filepath.Base(p),spec.fn,spec.fn)
   d.Reason=spec.fn+":UNQUALIFIED_READ_ONLY"
   if spec.kind=="render"||spec.kind=="video"||spec.kind=="audio" {d.Disposition="unqualified_candidate"}
   v.Devices=append(v.Devices,d)
  }
 }
 sort.Slice(v.Devices,func(i,j int)bool{
  a,b:=v.Devices[i],v.Devices[j]
  if a.Kind!=b.Kind{return a.Kind<b.Kind}
  return a.HostPath<b.HostPath
 })
 raw,_:=json.Marshal(v.Devices)
 h:=sha256.Sum256(raw)
 v.Generation=hex.EncodeToString(h[:])
 return v,nil
}
// PrivateOwnerInventory is never called from an ordinary remote/tailnet/LAN
// handler. Verify Unix socket peer credentials in the actual controller;
// these input strings are synthetic policy test fixtures, NOT authentication.
func PrivateOwnerInventory(v HostInventory,role,channel string)(HostInventory,error){
 if role!="owner"||channel!="local_unix_verified"{
  return HostInventory{},errors.New("DENIED:PRIVATE_INVENTORY")
 }
 return v,nil
}
func IsCandidateCurrent(v HostInventory,generation,kind,hostPath string) error{
 if generation==""||generation!=v.Generation{return errors.New("DENIED:STALE_INVENTORY")}
 for _,d:=range v.Devices{
  if d.Kind==kind&&d.HostPath==hostPath{
   if d.Disposition=="blocked"{return errors.New("DENIED:PROTECTED_HOST_DEVICE")}
   // A candidate requires a *separate* owner-authorized live attach,
   // guest-observed verification and teardown receipt. Always stop here.
   return errors.New("DENIED:OWNER_HIL_APPROVAL_AND_LEASE_REQUIRED")
  }
 }
 return errors.New("DENIED:UNKNOWN_HOST_DEVICE")
}
// ProjectGuestView deliberately has NO HostInventory argument. It can only
// display independent guest-virtual handles issued by a future trusted actor.
func ProjectGuestView(assigned []AssignedVirtualDevice)GuestView{
 out:=GuestView{Attached:[]AssignedVirtualDevice{}}
 for _,x:=range assigned{
  if len(x.GuestHandle)<3||len(x.GuestHandle)>40||strings.ContainsAny(x.GuestHandle,"/:. ") {continue}
  switch x.VirtualClass{
  case "virtual_disk","virtual_nic","virtual_keyboard","virtual_mouse","virtual_display","virtual_audio":
  default:continue
  }
  out.Attached=append(out.Attached,x)
 }
 return out
}
