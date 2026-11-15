package main

import (
 "encoding/json"
 "os"
 "strings"
 "testing"
)
func base() Profile{
 var p Profile
 p.Schema="wyse-recovery-host/v1";p.Buildroot="2026.08.1"
 p.Core=append([]string(nil),mandatory...)
 p.Optional=[]string{"ssd-overlay","tpm-sealing","hardware-watchdog"}
 p.Mode="recovery";p.Rootfs="read-only-verity"
 p.Storage.EMMC="read-only-ab-authorized-updates"
 p.Storage.RuntimeWrites="tmpfs";p.Storage.SSD="optional-discovered"
 p.Network.SSH="trusted-lan-public-key";p.Network.Web="headscale-overlay-only";p.Network.OfflineRescue=true
 p.Hardware.Watchdog="unqualified"
 p.Audience=[]string{"human","automation","agent"}
 return p
}
func assertValid(t *testing.T,p Profile){t.Helper();r:=Validate(p);if !r.Valid{t.Fatal(r.Errors)}}
func assertDenied(t *testing.T,p Profile,part string){t.Helper();r:=Validate(p);if r.Valid{t.Fatalf("accepted %s",part)};if !strings.Contains(strings.Join(r.Errors,"|"),part){t.Fatalf("reason %q absent from %v",part,r.Errors)}}
func TestMinimalRescueWithoutSSDTPMWatchdog(t *testing.T){
 p:=base();r:=Validate(p)
 if !r.Valid{t.Fatal(r.Errors)}
 if len(r.Disabled)!=3{t.Fatalf("expected disabled optional without hardware, got %v",r.Disabled)}
 if len(r.Boundaries)!=1{t.Fatal(r.Boundaries)}
}
func TestHostedRequiresIsolatedDevicesAndLiveHost(t *testing.T){
 p:=base();p.Mode="hosted";p.Optional=append(p.Optional,"vm-host","vm-observer")
 p.Storage.SSDPrepared=true;p.Observability.LiveHost=true
 p.Guest.Devices=[]string{"guest-ssd-image","virtio-net","virtual-tpm"}
 assertValid(t,p)
 p.Guest.RecoveryDiskVisible=true;assertDenied(t,p,"guest may not see")
 p.Guest.RecoveryDiskVisible=false;p.Guest.Devices=append(p.Guest.Devices,"physical-tpm");assertDenied(t,p,"unqualified guest device")
}
func TestBaremetalCannotMisstateSSDOrTelemetry(t *testing.T){
 p:=base();p.Mode="baremetal";p.Observability.ExternalOnly=true;assertValid(t,p)
 p.Observability.LiveHost=true;assertDenied(t,p,"simultaneous live local host")
 p.Observability.LiveHost=false;p.Storage.HostReserveProtectedFromBareMetal=true
 assertDenied(t,p,"cannot be protected")
}
func TestCoreMandatoryAndVersion(t *testing.T){
 p:=base();p.Core=p.Core[1:];assertDenied(t,p,"missing mandatory core")
 p=base();p.Buildroot="2026.11-rc1";assertDenied(t,p,"stable release")
 p=base();p.Rootfs="ext4-rw";assertDenied(t,p,"immutable")
}
func TestWearAndOfflineService(t *testing.T){
 p:=base();p.Storage.EMMC="rw";assertDenied(t,p,"routine writable")
 p=base();p.Storage.RuntimeWrites="emmc-journal";assertDenied(t,p,"tmpfs")
 p=base();p.Network.OfflineRescue=false;assertDenied(t,p,"offline recovery")
 p=base();p.Storage.SSD="required";assertDenied(t,p,"SSD must be optional")
}
func TestHardwareWatchdogAndBIOSNeverAssumed(t *testing.T){
 p:=base();p.Hardware.Watchdog="hardware";assertDenied(t,p,"watchdog unverified")
 p=base();p.Hardware.WatchdogArmed=true;assertDenied(t,p,"cannot be armed")
 p=base();p.Hardware.BIOSMetadataWrite=true;assertDenied(t,p,"BIOS metadata")
 p=base();p.Hardware.Watchdog="hardware";p.Hardware.WatchdogVerified=true;assertValid(t,p)
}
func TestGuestHostPrivilegeProhibition(t *testing.T){
 p:=base();p.Mode="hosted";p.Optional=append(p.Optional,"vm-host")
 p.Storage.SSDPrepared=true;p.Observability.LiveHost=true
 p.Guest.HostPhysicalTPMVisible=true;assertDenied(t,p,"guest may not see")
 p.Guest.HostPhysicalTPMVisible=false;p.Guest.HostFirmwareVisible=true;assertDenied(t,p,"guest may not see")
}
func TestThreeAudiencesRequired(t *testing.T){
 p:=base();p.Audience=[]string{"human","automation"};assertDenied(t,p,"missing audience agent")
 p=base();p.Audience=append(p.Audience,"superuser");assertDenied(t,p,"unknown audience")
}
func TestNoUnqualifiedRunnerCapability(t *testing.T){
 p:=base();p.Optional=[]string{"garm-runner"};assertDenied(t,p,"requires VM host")
 p=base();p.Optional=[]string{"vm-observer"};assertDenied(t,p,"requires VM host")
}
func TestPlanCannotRequestDiskChanges(t *testing.T){
 p:=base();p.Storage.RawDiskChanges=true;assertDenied(t,p,"raw disk changes")
 p=base();p.Network.Web="private-lan";assertDenied(t,p,"overlay-only")
}
func TestNoUnexpectedFieldsInExample(t *testing.T){
 b,err:=os.ReadFile("profile-recovery.json");if err!=nil{t.Fatal(err)}
 var p Profile
 if err=json.Unmarshal(b,&p);err!=nil{t.Fatal(err)}
 assertValid(t,p)
}
