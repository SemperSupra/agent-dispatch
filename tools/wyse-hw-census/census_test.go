package census

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T,root,path,contents string) {
	t.Helper()
	p:=filepath.Join(root,path)
	if err:=os.MkdirAll(filepath.Dir(p),0755);err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(p,[]byte(contents),0600);err!=nil{t.Fatal(err)}
}
func dir(t *testing.T,root,path string) {
	t.Helper(); if err:=os.MkdirAll(filepath.Join(root,path),0755);err!=nil{t.Fatal(err)}
}
func link(t *testing.T,root,path,target string) {
	t.Helper()
	p:=filepath.Join(root,path)
	if err:=os.MkdirAll(filepath.Dir(p),0755);err!=nil{t.Fatal(err)}
	if err:=os.Symlink(target,p);err!=nil{t.Fatal(err)}
}
func fixture(t *testing.T) string {
	t.Helper()
	r:=t.TempDir()
	write(t,r,"proc/cpuinfo",strings.Repeat("processor : 0\nmodel name : Intel Celeron J4105\nflags : fpu sse4_2 vmx\n",4))
	write(t,r,"proc/meminfo","MemTotal:        8388608 kB\n")
	write(t,r,"sys/devices/system/cpu/cpu0/cpufreq/scaling_governor","schedutil\n")
	write(t,r,"sys/class/thermal/thermal_zone0/temp","42000\n")
	dir(t,r,"sys/kernel/iommu_groups/2")
	dir(t,r,"sys/kernel/iommu_groups/3")
	gpu:="sys/bus/pci/devices/0000:00:02.0"
	write(t,r,gpu+"/vendor","0x8086\n")
	write(t,r,gpu+"/device","0x3185\n")
	write(t,r,gpu+"/class","0x030000\n")
	link(t,r,gpu+"/driver","../../drivers/i915")
	link(t,r,gpu+"/iommu_group","../../../../kernel/iommu_groups/2")
	nic:="sys/bus/pci/devices/0000:01:00.0"
	write(t,r,nic+"/vendor","0x10ec\n")
	write(t,r,nic+"/device","0x8168\n")
	write(t,r,nic+"/class","0x020000\n")
	link(t,r,nic+"/driver","../../drivers/r8169")
	link(t,r,nic+"/iommu_group","../../../../kernel/iommu_groups/3")
	dir(t,r,"sys/class/drm/renderD128")
	dir(t,r,"sys/block/mmcblk0")
	dir(t,r,"sys/block/sda")
	link(t,r,"sys/block/sda/device","../../devices/pci0000:00/ata1/host1")
	write(t,r,"sys/class/dmi/id/product_serial","PRIVATE-SERVICE-TAG-LEAK\n")
	write(t,r,"sys/class/net/eth0/address","PRIVATE-NIC-MAC-LEAK\n")
	write(t,r,"sys/class/dmi/id/product_uuid","PRIVATE-DMI-UUID-LEAK\n")
	write(t,r,"sys/block/sda/device_serial","PRIVATE-DISK-SERIAL-LEAK\n")
	// Regular file in a fixture must not be mistaken for usable /dev/kvm.
	write(t,r,"dev/kvm","NOT_ACTUAL_KVM\n")
	return r
}
func TestSyntheticWyseNoIdentityDisclosure(t *testing.T) {
	r:=fixture(t)
	s,err:=Collect(r)
	if err!=nil {t.Fatal(err)}
	if s.CPUs!=4||s.MemoryMiB!=8192||!s.VMXFlag {t.Fatalf("cpu/ram not parsed: %+v",s)}
	if len(s.GPUs)!=1||s.GPUs[0].Device!="0x3185"||s.GPUs[0].Driver!="i915" {t.Fatalf("gpu incorrect: %+v",s.GPUs)}
	if len(s.NICs)!=1||s.NICs[0].Device!="0x8168"||s.NICs[0].Driver!="r8169" {t.Fatalf("NIC incorrect: %+v",s.NICs)}
	if s.IOMMUGroups!=2||s.GPUs[0].GroupMembers!=1 {t.Fatalf("IOMMU topology incorrect: %+v",s)}
	if s.IGDPolicy!="EXCLUSIVE_VFIO_TOPOLOGY_CANDIDATE_NO_BINDING_OR_VBT_PROOF" {t.Fatal(s.IGDPolicy)}
	if s.SharingPolicy!="RENDER_NODE_PRESENT_VIRGL_VAAPI_REQUIRE_SEPARATE_TEST" {t.Fatal(s.SharingPolicy)}
	if s.EMMCBlockCount!=1||s.SATACandidates!=1 {t.Fatalf("storage incorrect: %+v",s)}
	if s.KVMDevice!="NOT_A_CHARACTER_DEVICE"||s.KVMProfile!="NATIVE_OR_CONTAINER_FIRST" {t.Fatal("fixture incorrectly passed KVM")}
	if s.MaxThermalC!=42||s.CPUFreqGovernor!="schedutil" {t.Fatal("perf sensors not parsed")}
	b,err:=json.Marshal(s);if err!=nil{t.Fatal(err)}
	for _,secret:=range []string{"PRIVATE-SERVICE-TAG-LEAK","PRIVATE-NIC-MAC-LEAK","PRIVATE-DMI-UUID-LEAK","PRIVATE-DISK-SERIAL-LEAK"} {
		if strings.Contains(string(b),secret) {t.Fatalf("identity disclosed: %s",secret)}
	}
	if s.HostMode!="FIXTURE_NOT_HARDWARE" {t.Fatal("false HIL claim")}
}
func TestIOMMUGroupWithOtherDeviceCannotBeStandalone(t *testing.T) {
	r:=fixture(t)
	// A network controller sharing the same group disqualifies an isolated
	// GPU VFIO candidate, even though VT-d/IOMMU groups are observed.
	p:=filepath.Join(r,"sys/bus/pci/devices/0000:01:00.0/iommu_group")
	if err:=os.Remove(p);err!=nil{t.Fatal(err)}
	link(t,r,"sys/bus/pci/devices/0000:01:00.0/iommu_group","../../../../kernel/iommu_groups/2")
	s,err:=Collect(r);if err!=nil{t.Fatal(err)}
	if s.GPUs[0].GroupMembers!=2||s.IGDPolicy!="NOT_QUALIFIED_NO_HOST_GPU_REBINDING" {
		t.Fatalf("unsafe VFIO eligibility: %+v",s)
	}
}
func TestMdevIsNotQualifiedJustBecauseAdvertised(t *testing.T) {
	r:=fixture(t)
	dir(t,r,"sys/bus/pci/devices/0000:00:02.0/mdev_supported_types/i915-GVTg_V5_4")
	s,err:=Collect(r);if err!=nil{t.Fatal(err)}
	if s.GPUs[0].MdevTypes!=1||s.SharingPolicy!="MDEV_TYPES_ADVERTISED_REQUIRES_EXACT_GPU_TEST" {t.Fatal("mdev falsely qualified")}
}
func TestMissingRequiredObservationFailsClosed(t *testing.T) {
	r:=t.TempDir()
	write(t,r,"proc/meminfo","MemTotal: 8388608 kB\n")
	if _,err:=Collect(r);err==nil{t.Fatal("missing CPU accepted")}
}
