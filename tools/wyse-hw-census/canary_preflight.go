package census

// CanaryPreflight is an intentionally NON-admitting coarse summary of one
// previously collected *read-only* local capability census. It cannot verify
// Dell chassis identity, disk by-id, signer custody, key-only SSH or physical
// boot. Even a passing synthetic topology must stay HOLD pending G0.
type CanaryPreflight struct {
 Schema string `json:"schema"`
 Admission string `json:"admission"`
 ObservedMode string `json:"observed_mode"`
 TopologyBlockers []string `json:"topology_blockers"`
 OwnerGates []string `json:"owner_gates"`
 KVMStatus string `json:"kvm_status"`
}
func Preflight(s Snapshot) CanaryPreflight {
 out:=CanaryPreflight{
  Schema:"wyse-mvp1-read-only-preflight/v1",
  Admission:"HOLD_NOT_PHYSICAL_RELEASE_AUTHORITY",
  ObservedMode:s.HostMode,
  TopologyBlockers:[]string{},
  OwnerGates:[]string{
   "PRIVATE_G0_CHASSIS_IDENTITY_BINDING_NOT_TESTED",
   "EXACT_EMMC_AND_SATA_BY_ID_OWNER_REVIEW_NOT_TESTED",
   "CANONICAL_OWNER_SIGNED_RECOVERY_AND_USB_FALLBACK_NOT_TESTED",
   "PHYSICAL_DELL_EMMC_BOOT_WITH_SATA_ABSENT_NOT_TESTED",
   "OFFLINE_KEY_ONLY_TRUSTED_LAN_SSH_NOT_TESTED",
   "FOUNDRY_TRUE_NAS_AND_DISPATCH_REAL_HOST_ADMISSION_NOT_TESTED",
  },
  KVMStatus:"GUEST_BOOT_NOT_TESTED",
 }
 if s.Scope!="READ_ONLY_CAPABILITY_PROBE_NOT_PHYSICAL_ATTESTATION"||
    s.Privacy!="NO_SERIAL_MAC_UUID_OR_SECRET_READS" ||
    (s.HostMode!="FIXTURE_NOT_HARDWARE"&&s.HostMode!="LOCAL_READ_ONLY_UNATTESTED") {
  out.TopologyBlockers=append(out.TopologyBlockers,"UNTRUSTED_OR_INVALID_CENSUS_SOURCE")
 }
 if s.CPUs<1||s.MemoryMiB<1024 {
  out.TopologyBlockers=append(out.TopologyBlockers,"CPU_OR_RAM_NOT_OBSERVED")
 }
 if s.EMMCBlockCount!=1 {
  out.TopologyBlockers=append(out.TopologyBlockers,"EMMC_CANDIDATES_AMBIGUOUS_OR_MISSING")
 }
 if s.SATACandidates>1 {
  out.TopologyBlockers=append(out.TopologyBlockers,"MULTIPLE_SATA_CANDIDATES_REQUIRE_PRIVATE_BY_ID")
 }
 if s.UnknownScsi!=0 {
  out.TopologyBlockers=append(out.TopologyBlockers,"UNKNOWN_SCSI_TRANSPORT_REQUIRES_OWNER_REVIEW")
 }
 if len(s.NICs)==0 {
  out.TopologyBlockers=append(out.TopologyBlockers,"NO_OBSERVED_NETWORK_CONTROLLER")
 }
 if !s.VMXFlag||s.KVMDevice!="CHAR_DEVICE_PRESENT_NOT_OPENED" {
  out.KVMStatus="KVM_GUEST_UNQUALIFIED_NO_AUTOMATIC_VM_ADMISSION"
 }else{
  out.KVMStatus="KVM_CANDIDATE_ONLY_GUEST_BOOT_REQUIRED"
 }
 // No data in Snapshot establishes disk writability, real SATA placement,
 // signer trust, BIOS configuration or an executable VM on a Dell Wyse.
 return out
}
