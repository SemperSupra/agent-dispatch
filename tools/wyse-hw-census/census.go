// Package census makes a nonprivileged, read-only capability inventory.
// It deliberately NEVER reads service tags, MAC addresses, DMI UUIDs,
// disk serials, SSH/TPM secrets or raw firmware variables. Physical identity
// association is a separate private owner-controlled operation.
package census

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type PCI struct {
	BDF             string `json:"bdf"`
	Vendor          string `json:"vendor"`
	Device          string `json:"device"`
	Driver          string `json:"driver,omitempty"`
	IOMMUGroup      string `json:"iommu_group,omitempty"`
	GroupMembers    int    `json:"group_members"`
	MdevTypes       int    `json:"mdev_types"`
}
type Snapshot struct {
	Scope           string `json:"scope"`
	Privacy         string `json:"privacy"`
	HostMode        string `json:"host_mode"`
	CPUModel        string `json:"cpu_model"`
	CPUs            int    `json:"logical_cpus_observed"`
	VMXFlag         bool   `json:"cpu_vmx_flag"`
	MemoryMiB       int    `json:"memory_mib"`
	IOMMUGroups     int    `json:"iommu_groups_observed"`
	KVMDevice       string `json:"kvm_device"`
	RenderNodes     int    `json:"render_nodes"`
	CPUFreqGovernor string `json:"cpu_governor,omitempty"`
	MaxThermalC     int    `json:"max_reported_thermal_c,omitempty"`
	EMMCBlockCount  int    `json:"emmc_block_count"`
	SATACandidates  int    `json:"sata_candidate_count"`
	USBScsiCount    int    `json:"usb_scsi_count"`
	UnknownScsi     int    `json:"unknown_scsi_count"`
	GPUs            []PCI  `json:"gpus"`
	NICs            []PCI  `json:"network_controllers"`
	KVMProfile      string `json:"kvm_profile"`
	VCPUSuggested   int    `json:"unqualified_guest_vcpu_suggestion"`
	MemorySuggested int    `json:"unqualified_guest_ram_mib_suggestion"`
	IGDPolicy       string `json:"igd_vfio_policy"`
	SharingPolicy   string `json:"gpu_sharing_policy"`
}
func trimmed(path string) string {
	b,err:=os.ReadFile(path);if err!=nil{return ""}
	return strings.TrimSpace(string(b))
}
func join(root string, paths ...string) string {
	p:=append([]string{root},paths...)
	return filepath.Join(p...)
}
func glob(pattern string) []string {
	a,err:=filepath.Glob(pattern);if err!=nil{return nil};return a
}
func parseCPU(data string) (string,int,bool) {
	model, count, vmx := "",0,false
	sc:=bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		x:=strings.SplitN(sc.Text(),":",2)
		if len(x)!=2 {continue}
		k,v:=strings.TrimSpace(x[0]),strings.TrimSpace(x[1])
		switch k {
		case "processor": count++
		case "model name": if model=="" {model=v}
		case "flags": if strings.Contains(" "+v+" "," vmx ") {vmx=true}
		}
	}
	return model,count,vmx
}
func parseRAM(data string) int {
	sc:=bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(),"MemTotal:") {
			f:=strings.Fields(sc.Text())
			if len(f)>=2 {n,_:=strconv.Atoi(f[1]);return n/1024}
		}
	}
	return 0
}
func linkBase(path string) string {
	l,err:=os.Readlink(path);if err!=nil{return ""}
	return filepath.Base(l)
}
func groupInfo(devicePath string) string {
	g:=linkBase(filepath.Join(devicePath,"iommu_group"))
	if g=="" || g=="." {return ""}
	return g
}
func KVMStatus(root string) string {
	// G0 is strict metadata-only. Even opening /dev/kvm with O_RDWR is a
	// capability exercise, not a passive inspection. Defer to a separate
	// owner-approved on-host KVM guest-boot test.
	p:=join(root,"dev","kvm")
	info,err:=os.Stat(p)
	if err!=nil{return "NOT_OBSERVED"}
	if info.Mode()&os.ModeCharDevice==0 {return "NOT_A_CHARACTER_DEVICE"}
	return "CHAR_DEVICE_PRESENT_NOT_OPENED"
}
func Collect(root string) (Snapshot,error) {
	root,err:=filepath.Abs(root);if err!=nil{return Snapshot{},err}
	cpu,num,vmx:=parseCPU(trimmed(join(root,"proc","cpuinfo")))
	mem:=parseRAM(trimmed(join(root,"proc","meminfo")))
	if num==0||mem==0{return Snapshot{},fmt.Errorf("incomplete CPU/RAM observation: FAIL_CLOSED")}
	s:=Snapshot{
		Scope:"READ_ONLY_CAPABILITY_PROBE_NOT_PHYSICAL_ATTESTATION",
		Privacy:"NO_SERIAL_MAC_UUID_OR_SECRET_READS",
		HostMode:"FIXTURE_NOT_HARDWARE" ,CPUModel:cpu,CPUs:num,VMXFlag:vmx,
		MemoryMiB:mem,KVMDevice:KVMStatus(root),
		GPUs:[]PCI{},NICs:[]PCI{},
		KVMProfile:"NATIVE_OR_CONTAINER_FIRST",
		IGDPolicy:"NOT_QUALIFIED_NO_HOST_GPU_REBINDING",
		SharingPolicy:"NOT_QUALIFIED",
	}
	if root=="/"{s.HostMode="LOCAL_READ_ONLY_UNATTESTED"}
	s.CPUFreqGovernor=trimmed(join(root,"sys","devices","system","cpu","cpu0","cpufreq","scaling_governor"))
	for _,x:=range glob(join(root,"sys","class","thermal","thermal_zone*","temp")) {
		k,err:=strconv.Atoi(trimmed(x));if err==nil && k>0 && k<125000 && k/1000>s.MaxThermalC {s.MaxThermalC=k/1000}
	}
	s.IOMMUGroups=len(glob(join(root,"sys","kernel","iommu_groups","*")))
	s.RenderNodes=len(glob(join(root,"sys","class","drm","renderD*")))
	for _,x:=range glob(join(root,"sys","block","mmcblk*")) {
		if !strings.Contains(filepath.Base(x),"boot") && !strings.Contains(filepath.Base(x),"rpmb") {s.EMMCBlockCount++}
	}
	for _,x:=range glob(join(root,"sys","block","sd*")) {
		ln,err:=os.Readlink(filepath.Join(x,"device"))
		if err!=nil{s.UnknownScsi++;continue}
		switch {
		case strings.Contains(ln,"/ata"):s.SATACandidates++
		case strings.Contains(ln,"/usb"):s.USBScsiCount++
		default:s.UnknownScsi++
		}
	}
	pciPaths:=glob(join(root,"sys","bus","pci","devices","*"))
	groups:=map[string]int{}
	for _,p:=range pciPaths {
		if trimmed(filepath.Join(p,"vendor"))=="" {continue}
		if g:=groupInfo(p);g!="" {groups[g]++}
	}
	for _,p:=range pciPaths {
		vendor:=strings.ToLower(trimmed(filepath.Join(p,"vendor")))
		class:=strings.ToLower(trimmed(filepath.Join(p,"class")))
		if vendor==""{continue}
		if !strings.HasPrefix(class,"0x03") && !strings.HasPrefix(class,"0x02"){continue}
		pci:=PCI{
			BDF:filepath.Base(p),Vendor:vendor,Device:strings.ToLower(trimmed(filepath.Join(p,"device"))),
			Driver:linkBase(filepath.Join(p,"driver")),IOMMUGroup:groupInfo(p),
			MdevTypes:len(glob(filepath.Join(p,"mdev_supported_types","*"))),
		}
		if pci.IOMMUGroup!="" {pci.GroupMembers=groups[pci.IOMMUGroup]}
		if strings.HasPrefix(class,"0x03"){s.GPUs=append(s.GPUs,pci)}else{s.NICs=append(s.NICs,pci)}
	}
	if root=="/" && vmx && s.KVMDevice=="CHAR_DEVICE_PRESENT_NOT_OPENED" && mem>=6144 {
		s.KVMProfile="KVM_TOPOLOGY_CANDIDATE_REQUIRES_GUEST_BOOT"
		s.VCPUSuggested=2
		s.MemorySuggested=mem-2048
		if s.MemorySuggested>8192{s.MemorySuggested=8192}
	}
	for _,gpu:=range s.GPUs {
		if gpu.Vendor=="0x8086"{
			if s.RenderNodes>0 {
				s.SharingPolicy="RENDER_NODE_PRESENT_VIRGL_VAAPI_REQUIRE_SEPARATE_TEST"
			}
			if gpu.MdevTypes>0 {
				s.SharingPolicy="MDEV_TYPES_ADVERTISED_REQUIRES_EXACT_GPU_TEST"
			}
			if s.IOMMUGroups>0 && gpu.IOMMUGroup!="" && gpu.GroupMembers==1 {
				s.IGDPolicy="EXCLUSIVE_VFIO_TOPOLOGY_CANDIDATE_NO_BINDING_OR_VBT_PROOF"
			}
		}
	}
	return s,nil
}
