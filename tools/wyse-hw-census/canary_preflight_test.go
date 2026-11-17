package census

import (
 "encoding/json"
 "strings"
 "testing"
)

func TestMVPPreflightNeverGrantsPhysicalOrGuestAdmission(t *testing.T){
 root:=fixture(t)
 s,err:=Collect(root);if err!=nil{t.Fatal(err)}
 p:=Preflight(s)
 if p.Admission!="HOLD_NOT_PHYSICAL_RELEASE_AUTHORITY"{
  t.Fatalf("synthetic Wyse topology accepted as HIL: %+v",p)
 }
 if p.KVMStatus!="KVM_GUEST_UNQUALIFIED_NO_AUTOMATIC_VM_ADMISSION"{
  t.Fatal("fake /dev/kvm fixture admitted as real KVM")
 }
 if len(p.TopologyBlockers)!=0{
  t.Fatalf("known synthetic J4105 topology unexpectedly unparseable %+v",p.TopologyBlockers)
 }
 if len(p.OwnerGates)<6 {t.Fatal("owner signer, Dell physical boot, SSH, Foundry gates omitted")}
 b,err:=json.Marshal(p);if err!=nil{t.Fatal(err)}
 for _,secret:=range []string{"PRIVATE-SERVICE-TAG-LEAK","PRIVATE-NIC-MAC-LEAK","PRIVATE-DMI-UUID-LEAK","PRIVATE-DISK-SERIAL-LEAK","0000:00:02.0","0x3185","r8169"}{
  if strings.Contains(string(b),secret) {t.Fatalf("coarse G0 preflight leaked private or chipset fact: %s",secret)}
 }
}
func TestG0StorageAndNetworkAmbiguityHolds(t *testing.T){
 s,_:=Collect(fixture(t))
 variants:=[]struct{
  name string
  change func(*Snapshot)
  expect string
 }{
  {"missing-emmc",func(s *Snapshot){s.EMMCBlockCount=0},"EMMC_CANDIDATES_AMBIGUOUS_OR_MISSING"},
  {"two-emmc",func(s *Snapshot){s.EMMCBlockCount=2},"EMMC_CANDIDATES_AMBIGUOUS_OR_MISSING"},
  {"two-sata",func(s *Snapshot){s.SATACandidates=2},"MULTIPLE_SATA_CANDIDATES_REQUIRE_PRIVATE_BY_ID"},
  {"unknown-sata-usb",func(s *Snapshot){s.UnknownScsi=1},"UNKNOWN_SCSI_TRANSPORT_REQUIRES_OWNER_REVIEW"},
  {"missing-nic",func(s *Snapshot){s.NICs=nil},"NO_OBSERVED_NETWORK_CONTROLLER"},
  {"wrong-mode",func(s *Snapshot){s.HostMode="PHYSICAL_READY"},"UNTRUSTED_OR_INVALID_CENSUS_SOURCE"},
  {"source-spoof",func(s *Snapshot){s.Scope="CANARY_PASSED"},"UNTRUSTED_OR_INVALID_CENSUS_SOURCE"},
  {"identity-privacy-invalid",func(s *Snapshot){s.Privacy=""},"UNTRUSTED_OR_INVALID_CENSUS_SOURCE"},
  {"missing-memory",func(s *Snapshot){s.MemoryMiB=0},"CPU_OR_RAM_NOT_OBSERVED"},
 }
 for _,tc:=range variants {
  t.Run(tc.name,func(t *testing.T) {
   x:=s;tc.change(&x)
   p:=Preflight(x)
   if p.Admission!="HOLD_NOT_PHYSICAL_RELEASE_AUTHORITY" {
    t.Fatal("unknown source or disk auto-admitted")
   }
   joined:=strings.Join(p.TopologyBlockers,";")
   if !strings.Contains(joined,tc.expect){
    t.Fatalf("missing expected fail-closed reason %s: %+v",tc.expect,p.TopologyBlockers)
   }
  })
 }
}
func TestEvenRealLookingKVMDeviceIsOnlyCandidate(t *testing.T) {
 s,_:=Collect(fixture(t))
 s.HostMode="LOCAL_READ_ONLY_UNATTESTED"
 s.KVMDevice="CHAR_DEVICE_PRESENT_NOT_OPENED"
 p:=Preflight(s)
 if p.Admission!="HOLD_NOT_PHYSICAL_RELEASE_AUTHORITY"||
    p.KVMStatus!="KVM_CANDIDATE_ONLY_GUEST_BOOT_REQUIRED"{
  t.Fatalf("KVM device fabricated guest boot proof: %+v",p)
 }
}
