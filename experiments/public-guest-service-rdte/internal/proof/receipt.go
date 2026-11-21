package proof

import (
 "errors"
 "fmt"
 "regexp"
 "strings"
)
var shaPat=regexp.MustCompile("^[a-f0-9]{40}$")
var digestPat=regexp.MustCompile("^[a-f0-9]{64}$")
const IsoHash="bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38"
type Receipt struct {
 Schema string `json:"schema"`
 RunID string `json:"run_id"`
 SourceSHA string `json:"source_sha"`
 Runner string `json:"runner"`
 OfficialISOHashMatched bool `json:"official_iso_hash_matched"`
 WimlibHashMatched bool `json:"wimlib_hash_matched"`
 ExactOwnedDisk bool `json:"exact_owned_disk"`
 EFINTFSFormatted bool `json:"efi_ntfs_formatted"`
 WindowsImageApplied bool `json:"windows_image_applied"`
 UEFIBoot bool `json:"uefi_bcdboot_complete"`
 OwnedVM bool `json:"owned_vm_registered"`
 GuestStarted bool `json:"guest_vm_started"`
 GuestHeartbeat bool `json:"windows_heartbeat_observed"`
 FirstLogon bool `json:"first_logon_marker_observed"`
 PowerShellDirect bool `json:"powershell_direct_observed"`
 OOBEStaged bool `json:"oobe_unattend_staged"`
 GuestNetworkAttached bool `json:"guest_network_attached"`
 PublicBinaryPrepared bool `json:"public_binary_prepared"`
 ServiceBinarySHA string `json:"service_binary_sha256"`
 GuestServiceCleanup bool `json:"guest_service_cleanup"`
 Events []Event `json:"guest_service_events"`
 CleanupComplete bool `json:"cleanup_complete"`
 ProductInstalled bool `json:"actual_remote_access_product_installed"`
 FirstFailure *string `json:"first_failure"`
 GuestServiceFailure *string `json:"guest_service_failure"`
 }
func VerifyReceipt(r Receipt,run,source string) error{
 if r.Schema!="public-guest-service-rdte/v1" ||r.RunID!=run || !shaPat.MatchString(source) || strings.ToLower(source)!=r.SourceSHA || r.Runner!="windows-2025"{
  return errors.New("runner, source or receipt provenance mismatch")
 }
 if !r.OfficialISOHashMatched||!r.WimlibHashMatched||!r.ExactOwnedDisk||!r.EFINTFSFormatted||!r.WindowsImageApplied||!r.UEFIBoot||
 !r.OwnedVM||!r.GuestStarted||!r.GuestHeartbeat||!r.FirstLogon||!r.PowerShellDirect||!r.OOBEStaged||!r.PublicBinaryPrepared{
  return errors.New("Windows image, boot or public service provenance unqualified")
 }
 if r.GuestNetworkAttached||r.ProductInstalled{return errors.New("forbidden network/product effect")}
 if !digestPat.MatchString(r.ServiceBinarySHA) ||r.GuestServiceFailure!=nil||r.FirstFailure!=nil{return errors.New("binary hash or guest service failure")}
 if !r.GuestServiceCleanup||!r.CleanupComplete{return errors.New("guest service or VM teardown not verified")}
 if e:=Verify(r.Events);e!=nil{return fmt.Errorf("independent service lifecycle oracle: %w",e)}
 return nil
}
