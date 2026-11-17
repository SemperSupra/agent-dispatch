package mobile

import (
 "strings"
 "testing"
)
func device(os string)Device{
 return Device{OS:os,VersionMajor:18,EnrollmentVerified:true,AppSignatureVerified:true,
  UserConsented:true,DeviceGeneration:strings.Repeat("a",64),BatteryPct:80,
  Charging:true,WifiUnmetered:true,ThermalState:"nominal",Foreground:true,
  BackgroundAuthorized:true}
}
func TestThreeOSFamiliesHaveOnlyConsentedAppTasks(t *testing.T){
 for _,os:=range []string{"android","ios","ipados"}{
  d:=device(os)
  for _,task:=range []Task{
   {Role:"interactive_assist"},
   {Role:"sensor_capture",NeedsCamera:true,CameraPermission:true},
   {Role:"local_inference"},
   {Role:"notification"},
   {Role:"background_sync"},
  }{
   p,e:=Admit(d,task)
   if e!=nil||p.Scope!="SYNTHETIC_POLICY_ONLY_NO_REAL_MOBILE_APP_ATTESTATION"{
    t.Fatalf("%s %s: %+v %v",os,task.Role,p,e)
   }
  }
 }
}
func TestFailClosedMobileBackgroundPrivacyAndHardware(t *testing.T){
 cases:=[]struct{name string;mut func(*Device,*Task)}{
  {"no-app-signature",func(d *Device,_ *Task){d.AppSignatureVerified=false}},
  {"unpaired",func(d *Device,_ *Task){d.EnrollmentVerified=false}},
  {"consent-revoked",func(d *Device,_ *Task){d.UserConsented=false}},
  {"stale-generation",func(d *Device,_ *Task){d.DeviceGeneration=""}},
  {"unsupported-os",func(d *Device,_ *Task){d.OS="watchos"}},
  {"unknown-api",func(d *Device,_ *Task){d.VersionMajor=0}},
  {"battery-unknown",func(d *Device,_ *Task){d.BatteryPct=-1}},
  {"thermal-unknown-enum",func(d *Device,_ *Task){d.ThermalState="impossibly_cool"}},
  {"thermal-serious",func(d *Device,_ *Task){d.ThermalState="serious"}},
  {"thermal-critical",func(d *Device,_ *Task){d.ThermalState="critical"}},
  {"guest-hypervisor",func(_ *Device,t *Task){t.Role="kvm_host"}},
  {"host-usb-passthrough",func(_ *Device,t *Task){t.Role="usb_passthrough"}},
  {"host-root-ssh",func(_ *Device,t *Task){t.Role="root_ssh"}},
  {"guaranteed-24h-host",func(_ *Device,t *Task){t.RequireAlwaysOn=true}},
  {"background-no-grant",func(d *Device,t *Task){d.BackgroundAuthorized=false;t.Role="background_sync"}},
  {"background-low-battery",func(d *Device,t *Task){d.Charging=false;d.BatteryPct=12;t.Role="background_sync"}},
  {"urgent-background",func(_ *Device,t *Task){t.Urgent=true;t.Role="background_sync"}},
  {"urgent-notification",func(_ *Device,t *Task){t.Urgent=true;t.Role="notification"}},
  {"infer-not-present",func(d *Device,t *Task){d.Foreground=false;t.Role="local_inference"}},
  {"infer-low-battery",func(d *Device,t *Task){d.Charging=false;d.BatteryPct=25;t.Role="local_inference"}},
  {"infer-not-cooled",func(d *Device,t *Task){d.ThermalState="fair";t.Role="local_inference"}},
  {"camera-consent-missing",func(_ *Device,t *Task){t.NeedsCamera=true;t.Role="sensor_capture"}},
  {"mic-consent-missing",func(_ *Device,t *Task){t.NeedsMicrophone=true;t.Role="sensor_capture"}},
  {"metered-network",func(d *Device,t *Task){d.WifiUnmetered=false;t.NeedsNetwork=true}},
  {"not-foreground",func(d *Device,_ *Task){d.Foreground=false}},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   d,q:=device("android"),Task{Role:"interactive_assist"}
   tc.mut(&d,&q)
   if _,e:=Admit(d,q);e==nil{t.Fatalf("unsafe mobile state accepted %s",tc.name)}
  })
 }
}
func TestIOSBackgroundNeverGuaranteedOnDemand(t *testing.T){
 d:=device("ios");d.Foreground=false
 if out,e:=Admit(d,Task{Role:"background_sync"});e!=nil||out.Execution!="OS_SCHEDULED_OPPORTUNISTIC_NO_SLA"{
  t.Fatalf("incorrect background admission %+v %v",out,e)
 }
}
